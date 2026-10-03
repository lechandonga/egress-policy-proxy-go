package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Action is the verdict a rule emits when it wins conflict resolution.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// PortRange is an inclusive TCP/UDP port interval.
type PortRange struct {
	Lo uint16
	Hi uint16
}

func (p PortRange) contains(port uint16) bool { return port >= p.Lo && port <= p.Hi }

// Rule is one policy statement. All set constraints must match simultaneously.
// Unset constraints match everything (no ports constraint => any port).
type Rule struct {
	ID       string      `json:"id"`
	Action   Action      `json:"action"`
	Domains  []string    `json:"domains,omitempty"`
	CIDRs    []string    `json:"cidrs,omitempty"`
	Ports    []PortRange `json:"ports,omitempty"`
	Priority int         `json:"priority,omitempty"`

	domains  []domainPattern
	prefixes []netip.Prefix
}

// domainPattern is either an exact name ("example.com") or a wildcard
// matching the name and any depth of subdomains ("*.example.com").
type domainPattern struct {
	suffix   string // lower-cased, no leading dot
	wildcard bool   // leading "*." present
}

func (d domainPattern) matches(host string) bool {
	if d.wildcard {
		return host == d.suffix || strings.HasSuffix(host, "."+d.suffix)
	}
	return host == d.suffix
}

// Config is the on-disk JSON representation of a policy.
type Config struct {
	Rules []Rule `json:"rules"`
}

// ErrorKind classifies why a reload failed so callers (and the reload
// history) can distinguish failure categories programmatically.
type ErrorKind string

const (
	KindIO            ErrorKind = "io"             // file could not be read
	KindInvalidJSON   ErrorKind = "invalid_json"   // document is not valid JSON
	KindEmptyPolicy   ErrorKind = "empty_policy"   // zero rules
	KindInvalidID     ErrorKind = "invalid_id"     // missing/duplicate rule id
	KindInvalidAction ErrorKind = "invalid_action" // action not allow/deny
	KindConstraint    ErrorKind = "missing_constraint"
	KindInvalidDomain ErrorKind = "invalid_domain"
	KindInvalidCIDR   ErrorKind = "invalid_cidr"
	KindInvalidPort   ErrorKind = "invalid_port"
)

// LoadError is a malformed or illegal policy document (as opposed to an I/O
// error while reading the file).
type LoadError struct {
	kind   ErrorKind
	reason string
}

func (e *LoadError) Error() string { return e.reason }

// Kind returns the machine-readable failure category.
func (e *LoadError) Kind() ErrorKind { return e.kind }

func loadErr(kind ErrorKind, format string, args ...any) error {
	return &LoadError{kind: kind, reason: fmt.Sprintf(format, args...)}
}

// ErrorKindOf reports the failure category. Validation failures return one
// of the Kind* constants; anything else (including I/O errors) returns
// KindIO.
func ErrorKindOf(err error) ErrorKind {
	var le *LoadError
	if errors.As(err, &le) {
		return le.kind
	}
	return KindIO
}

// IsLoadError reports whether err is a policy validation error.
func IsLoadError(err error) bool {
	var le *LoadError
	return errors.As(err, &le)
}

// Policy is an immutable, compiled snapshot.
type Policy struct {
	Rules   []*Rule
	Version string
}

// Decode parses, validates and compiles a JSON policy document.
// Any malformed or illegal rule aborts the whole load with a LoadError;
// nothing is silently ignored.
func Decode(data []byte) (*Policy, error) {
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		var le *LoadError
		if errors.As(err, &le) {
			return nil, err // field-level validation (e.g. bad port) keeps its kind
		}
		return nil, loadErr(KindInvalidJSON, "policy is not valid JSON: %v", err)
	}
	if dec.More() {
		return nil, loadErr(KindInvalidJSON, "policy document contains trailing JSON values")
	}
	return Build(cfg.Rules, "")
}

// Build validates and compiles rules into an immutable snapshot.
func Build(rules []Rule, version string) (*Policy, error) {
	if len(rules) == 0 {
		return nil, loadErr(KindEmptyPolicy, "policy must contain at least one rule; an empty policy would deny everything and is rejected to avoid accidental lockout")
	}

	seenIDs := make(map[string]bool, len(rules))
	p := &Policy{Version: version, Rules: make([]*Rule, 0, len(rules))}

	for i := range rules {
		r := rules[i]
		idx := i + 1

		if strings.TrimSpace(r.ID) == "" {
			return nil, loadErr(KindInvalidID, "rule #%d: missing id", idx)
		}
		if seenIDs[r.ID] {
			return nil, loadErr(KindInvalidID, "rule %q: duplicate rule id", r.ID)
		}
		seenIDs[r.ID] = true

		switch r.Action {
		case ActionAllow, ActionDeny:
		default:
			return nil, loadErr(KindInvalidAction, "rule %q: action must be %q or %q, got %q", r.ID, ActionAllow, ActionDeny, r.Action)
		}

		if len(r.Domains) == 0 && len(r.CIDRs) == 0 {
			return nil, loadErr(KindConstraint, "rule %q: at least one domain or cidr constraint is required (a rule matching all traffic is rejected for safety)", r.ID)
		}

		for _, d := range r.Domains {
			pat, err := compileDomain(r.ID, d)
			if err != nil {
				return nil, err
			}
			r.domains = append(r.domains, pat)
		}

		for _, c := range r.CIDRs {
			prefix, perr := compilePrefix(r.ID, c)
			if perr != nil {
				return nil, perr
			}
			r.prefixes = append(r.prefixes, prefix)
		}

		for _, pr := range r.Ports {
			if pr.Lo == 0 || pr.Hi == 0 {
				return nil, loadErr(KindInvalidPort, "rule %q: port 0 is not allowed", r.ID)
			}
			if pr.Lo > pr.Hi {
				return nil, loadErr(KindInvalidPort, "rule %q: invalid port range %d-%d (low > high)", r.ID, pr.Lo, pr.Hi)
			}
		}

		p.Rules = append(p.Rules, &r)
	}

	return p, nil
}

// compilePrefix accepts exactly one bare IP (127.0.0.1, ::1) or one
// canonical "addr/bits" CIDR. Nothing is corrected or defaulted: a host
// address with a mask, a non-32/128 bit length, an out-of-range prefix
// length, a zone suffix or a catch-all prefix all fail the whole load.
func compilePrefix(ruleID, c string) (netip.Prefix, error) {
	if strings.TrimSpace(c) == "" {
		return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: empty cidr/ip", ruleID)
	}
	if c != strings.TrimSpace(c) || strings.ContainsAny(c, " \t") {
		return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: invalid cidr/ip %q: whitespace not allowed", ruleID, c)
	}
	raw := c

	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: invalid cidr %q: %v", ruleID, c, err)
		}
		if prefix.Addr().Zone() != "" {
			return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: cidr %q must not carry a zone", ruleID, c)
		}
		// ParsePrefix accepts host bits ("10.0.0.5/24"); reject instead of
		// silently masking them.
		if prefix.Bits() != prefix.Addr().BitLen() && prefix.Masked() != prefix {
			return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: cidr %q has non-zero host bits; write %q", ruleID, c, prefix.Masked().String())
		}
		if prefix.Addr().IsUnspecified() {
			return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: cidr %q matches every address and is rejected for safety", ruleID, c)
		}
		return prefix, nil
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: invalid cidr/ip %q: %v", ruleID, c, err)
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: address %q must not carry a zone", ruleID, c)
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	if addr.IsUnspecified() {
		return netip.Prefix{}, loadErr(KindInvalidCIDR, "rule %q: address %q matches every address and is rejected for safety", ruleID, c)
	}
	return prefix, nil
}

func compileDomain(ruleID, d string) (domainPattern, error) {
	name := strings.ToLower(d)
	if name == "" || strings.TrimSpace(name) == "" {
		return domainPattern{}, loadErr(KindInvalidDomain, "rule %q: empty domain pattern", ruleID)
	}
	if strings.ContainsAny(name, " \t/") {
		return domainPattern{}, loadErr(KindInvalidDomain, "rule %q: invalid domain %q: whitespace not allowed", ruleID, d)
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return domainPattern{}, loadErr(KindInvalidDomain, "rule %q: invalid domain %q: empty or leading dot label", ruleID, d)
	}
	wild := false
	if strings.HasPrefix(name, "*.") {
		wild = true
		name = strings.TrimPrefix(name, "*.")
	}
	if strings.Contains(name, "*") {
		return domainPattern{}, loadErr(KindInvalidDomain, "rule %q: wildcard only allowed as leading %q, got %q", ruleID, "*.", d)
	}
	if name == "" {
		return domainPattern{}, loadErr(KindInvalidDomain, "rule %q: invalid domain %q: name missing after wildcard", ruleID, d)
	}
	for _, label := range strings.Split(name, ".") {
		if !validLabel(label) {
			return domainPattern{}, loadErr(KindInvalidDomain, "rule %q: invalid domain %q: illegal label %q (labels need 1-63 letters, digits or hyphens, no leading/trailing hyphen)", ruleID, d, label)
		}
	}
	return domainPattern{suffix: name, wildcard: wild}, nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		b := label[i]
		switch {
		case b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-':
		default:
			return false
		}
	}
	return true
}

// UnmarshalJSON accepts a number (8080) or an inclusive range ("8000-9000").
func (p *PortRange) UnmarshalJSON(raw []byte) error {
	var single uint16
	if err := json.Unmarshal(raw, &single); err == nil {
		p.Lo, p.Hi = single, single
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return loadErr(KindInvalidPort, "port must be a number or \"lo-hi\" range, got %s", string(raw))
	}
	loStr, hiStr, ok := strings.Cut(s, "-")
	if !ok {
		return loadErr(KindInvalidPort, "invalid port range %q: use a number or \"lo-hi\"", s)
	}
	lo, err := parsePortNumber(loStr)
	if err != nil {
		return loadErr(KindInvalidPort, "invalid port range %q: %v", s, err)
	}
	hi, err := parsePortNumber(hiStr)
	if err != nil {
		return loadErr(KindInvalidPort, "invalid port range %q: %v", s, err)
	}
	p.Lo, p.Hi = uint16(lo), uint16(hi)
	return nil
}

func parsePortNumber(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty port value")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("port %q must contain digits only", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", n)
	}
	return n, nil
}

// MarshalJSON renders single-port ranges as numbers.
func (p PortRange) MarshalJSON() ([]byte, error) {
	if p.Lo == p.Hi {
		return json.Marshal(p.Lo)
	}
	return json.Marshal(fmt.Sprintf("%d-%d", p.Lo, p.Hi))
}

// specificity describes how constrained a rule is; it deterministically
// breaks ties between rules at the same priority with the same action.
type specificity struct {
	domain int // 2 exact > 1 wildcard > 0 unset
	ip     int // prefix length, -1 when unset
	port   int // 2 single port > 1 range > 0 unset
	total  int
}

func (p *Policy) specificityOf(r *Rule) specificity {
	s := specificity{ip: -1}
	for _, d := range r.domains {
		v := 1
		if !d.wildcard {
			v = 2
		}
		if v > s.domain {
			s.domain = v
		}
	}
	for _, pref := range r.prefixes {
		if v := pref.Bits(); v > s.ip {
			s.ip = v
		}
	}
	switch {
	case len(r.Ports) == 0:
	case len(r.Ports) == 1 && r.Ports[0].Lo == r.Ports[0].Hi:
		s.port = 2
	default:
		s.port = 1
	}
	s.total = s.domain
	if s.ip > 0 {
		s.total += s.ip
	}
	s.total += s.port
	return s
}

// Match is the evaluated request tuple.
type Match struct {
	Host string // lower-cased domain name, empty for literal-IP requests
	IP   netip.Addr
	Port uint16
}

// Decision is the unique verdict plus a full explanation.
type Decision struct {
	Allowed      bool
	Action       Action
	WinningRule  string
	Reason       string
	MatchedRules []string
}

// Evaluate applies the snapshot. Conflicts are resolved by total order:
// priority desc, then specificity desc (the more specific rule wins, so a
// broad deny cannot shadow a narrow allow), then deny wins among equally
// specific rules, then rule id asc. The verdict is unique and the winning
// rule is always named. Requests matching no rule are denied by default:
// the policy fails closed.
func (p *Policy) Evaluate(m Match) Decision {
	type cand struct {
		r *Rule
		s specificity
	}
	cands := make([]cand, 0, len(p.Rules))
	for _, r := range p.Rules {
		if ruleMatches(r, m) {
			cands = append(cands, cand{r: r, s: p.specificityOf(r)})
		}
	}

	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.r.Priority != b.r.Priority {
			return a.r.Priority > b.r.Priority
		}
		if a.s.total != b.s.total {
			return a.s.total > b.s.total
		}
		if a.s.domain != b.s.domain {
			return a.s.domain > b.s.domain
		}
		if a.s.ip != b.s.ip {
			return a.s.ip > b.s.ip
		}
		if a.s.port != b.s.port {
			return a.s.port > b.s.port
		}
		if a.r.Action != b.r.Action {
			return a.r.Action == ActionDeny
		}
		return a.r.ID < b.r.ID
	})

	ids := make([]string, len(cands))
	for i, c := range cands {
		ids[i] = c.r.ID
	}

	if len(cands) == 0 {
		return Decision{
			Action:      ActionDeny,
			WinningRule: "",
			Reason:      fmt.Sprintf("default deny: no rule matches host=%q ip=%s port=%d (policy fails closed)", displayHost(m.Host), m.IP, m.Port),
		}
	}

	winner := cands[0].r
	return Decision{
		Allowed:      winner.Action == ActionAllow,
		Action:       winner.Action,
		WinningRule:  winner.ID,
		Reason:       fmt.Sprintf("rule %q (%s, priority=%d) wins among %v for host=%q ip=%s port=%d", winner.ID, winner.Action, winner.Priority, ids, displayHost(m.Host), m.IP, m.Port),
		MatchedRules: ids,
	}
}

func displayHost(h string) string {
	if h == "" {
		return "-"
	}
	return h
}

// AddressVerdict is the Decision for one evaluated address together with
// that address.
type AddressVerdict struct {
	IP       netip.Addr `json:"ip"`
	Decision Decision   `json:"decision"`
}

// Adjudication is the combined verdict for one (host, port, address-set)
// tuple. It is the single, shared semantics used both by real forwarding
// (after resolution) and by dry-run trial evaluation.
type Adjudication struct {
	Allowed     bool             `json:"allowed"`
	Action      Action           `json:"action"`
	WinningRule string           `json:"winning_rule"`
	Reason      string           `json:"reason"`
	Host        string           `json:"host"`
	Port        uint16           `json:"port"`
	Addresses   []AddressVerdict `json:"addresses"`
	DefaultDeny bool             `json:"default_deny"`
}

// Adjudicate evaluates one host (lower-cased; empty for literal-IP
// requests), one port, against every address in the given order. The
// semantics match real forwarding exactly:

//   - with no addresses, the policy is evaluated on host+port alone (a
//     rule matching only by CIDR cannot apply, just like an unresolved
//     name);
//   - otherwise every address is evaluated as part of the same tuple;
//   - the FIRST denied address decides the whole result (in address
//     order), so "name allowed but one resolved address falls in a deny
//     range" is an overall denial;
//   - when every address is allowed, the first address's verdict is the
//     overall verdict (real forwarding dials the first resolved address).
func (p *Policy) Adjudicate(host string, port uint16, ips []netip.Addr) Adjudication {
	lhost := strings.ToLower(host)
	adj := Adjudication{Host: lhost, Port: port, Action: ActionDeny}

	if len(ips) == 0 {
		d := p.Evaluate(Match{Host: lhost, Port: port})
		adj.reasonFor(d, lhost, port, nil)
		return adj
	}

	for _, ip := range ips {
		d := p.Evaluate(Match{Host: lhost, IP: ip.Unmap(), Port: port})
		adj.Addresses = append(adj.Addresses, AddressVerdict{IP: ip.Unmap(), Decision: d})
	}

	for _, av := range adj.Addresses {
		if !av.Decision.Allowed {
			adj.reasonFor(av.Decision, lhost, port, adj.Addresses)
			return adj
		}
	}
	adj.reasonFor(adj.Addresses[0].Decision, lhost, port, adj.Addresses)
	return adj
}

func (a *Adjudication) reasonFor(d Decision, host string, port uint16, all []AddressVerdict) {
	a.Allowed = d.Allowed
	a.Action = d.Action
	a.WinningRule = d.WinningRule
	a.DefaultDeny = len(d.MatchedRules) == 0
	if a.DefaultDeny {
		a.Reason = fmt.Sprintf("default deny: no rule matches host=%q port=%d across %d address(es); policy fails closed", displayHost(host), port, len(all))
		return
	}
	if !a.Allowed && len(all) > 1 {
		a.Reason = fmt.Sprintf("denied by rule %q: at least one evaluated address is rejected (first denial wins); underlying: %s", d.WinningRule, d.Reason)
		return
	}
	a.Reason = d.Reason
}

func ruleMatches(r *Rule, m Match) bool {
	if len(r.Ports) > 0 {
		ok := false
		for _, pr := range r.Ports {
			if pr.contains(m.Port) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	domainRelevant := len(r.domains) > 0
	ipRelevant := len(r.prefixes) > 0

	domainOK := !domainRelevant
	if domainRelevant && m.Host != "" {
		for _, d := range r.domains {
			if d.matches(m.Host) {
				domainOK = true
				break
			}
		}
	}

	ipOK := !ipRelevant
	if ipRelevant && m.IP.IsValid() {
		for _, pref := range r.prefixes {
			if pref.Contains(m.IP) {
				ipOK = true
				break
			}
		}
	}

	// A name-only rule never matches a literal-IP request, and an
	// IP-only rule never matches an unresolved name.
	if domainRelevant && m.Host == "" {
		domainOK = false
	}
	if ipRelevant && !m.IP.IsValid() {
		ipOK = false
	}

	return domainOK && ipOK
}
