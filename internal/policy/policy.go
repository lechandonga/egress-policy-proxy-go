package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
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

// LoadError is a malformed or illegal policy document (as opposed to an I/O
// error while reading the file).
type LoadError struct{ reason string }

func (e *LoadError) Error() string { return e.reason }

func loadErr(format string, args ...any) error {
	return &LoadError{reason: fmt.Sprintf(format, args...)}
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
		return nil, loadErr("policy is not valid JSON: %v", err)
	}
	if dec.More() {
		return nil, loadErr("policy document contains trailing JSON values")
	}
	return Build(cfg.Rules, "")
}

// Build validates and compiles rules into an immutable snapshot.
func Build(rules []Rule, version string) (*Policy, error) {
	if len(rules) == 0 {
		return nil, loadErr("policy must contain at least one rule; an empty policy would deny everything and is rejected to avoid accidental lockout")
	}

	seenIDs := make(map[string]bool, len(rules))
	p := &Policy{Version: version, Rules: make([]*Rule, 0, len(rules))}

	for i := range rules {
		r := rules[i]
		idx := i + 1

		if strings.TrimSpace(r.ID) == "" {
			return nil, loadErr("rule #%d: missing id", idx)
		}
		if seenIDs[r.ID] {
			return nil, loadErr("rule %q: duplicate rule id", r.ID)
		}
		seenIDs[r.ID] = true

		switch r.Action {
		case ActionAllow, ActionDeny:
		default:
			return nil, loadErr("rule %q: action must be %q or %q, got %q", r.ID, ActionAllow, ActionDeny, r.Action)
		}

		if len(r.Domains) == 0 && len(r.CIDRs) == 0 {
			return nil, loadErr("rule %q: at least one domain or cidr constraint is required (a rule matching all traffic is rejected for safety)", r.ID)
		}

		for _, d := range r.Domains {
			pat, err := compileDomain(r.ID, d)
			if err != nil {
				return nil, err
			}
			r.domains = append(r.domains, pat)
		}

		for _, c := range r.CIDRs {
			prefix, err := netip.ParsePrefix(c)
			if err != nil {
				addr, addrErr := netip.ParseAddr(c)
				if addrErr != nil {
					return nil, loadErr("rule %q: invalid cidr/ip %q: %v", r.ID, c, err)
				}
				if addr.Zone() != "" {
					return nil, loadErr("rule %q: address %q must not carry a zone", r.ID, c)
				}
				if addr.Is4In6() {
					return nil, loadErr("rule %q: address %q must be written in canonical IPv4 form", r.ID, c)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if prefix.Addr().Zone() != "" {
				return nil, loadErr("rule %q: cidr %q must not carry a zone", r.ID, c)
			}
			if prefix.Addr().Is4In6() {
				return nil, loadErr("rule %q: cidr %q must be written in canonical IPv4 form", r.ID, c)
			}
			if prefix.Addr().IsUnspecified() {
				return nil, loadErr("rule %q: cidr %q matches every address and is rejected for safety", r.ID, c)
			}
			if prefix != prefix.Masked() {
				return nil, loadErr("rule %q: cidr %q has host bits set; write the canonical network address %q instead", r.ID, c, prefix.Masked())
			}
			r.prefixes = append(r.prefixes, prefix)
		}

		for _, pr := range r.Ports {
			if pr.Lo == 0 || pr.Hi == 0 {
				return nil, loadErr("rule %q: port 0 is not allowed", r.ID)
			}
			if pr.Lo > pr.Hi {
				return nil, loadErr("rule %q: invalid port range %d-%d (low > high)", r.ID, pr.Lo, pr.Hi)
			}
			if pr.Lo > 65535 || pr.Hi > 65535 {
				return nil, loadErr("rule %q: port out of range: %d-%d", r.ID, pr.Lo, pr.Hi)
			}
		}

		p.Rules = append(p.Rules, &r)
	}

	return p, nil
}

func compileDomain(ruleID, d string) (domainPattern, error) {
	name := strings.ToLower(strings.TrimSpace(d))
	if name == "" {
		return domainPattern{}, loadErr("rule %q: empty domain pattern", ruleID)
	}
	if strings.ContainsAny(name, " /:_") || strings.HasSuffix(name, ".") {
		return domainPattern{}, loadErr("rule %q: invalid domain %q", ruleID, d)
	}
	wild := false
	if strings.HasPrefix(name, "*.") {
		wild = true
		name = strings.TrimPrefix(name, "*.")
	}
	if strings.Contains(name, "*") {
		return domainPattern{}, loadErr("rule %q: wildcard only allowed as leading %q, got %q", ruleID, "*.", d)
	}
	if len(name) > 253 {
		return domainPattern{}, loadErr("rule %q: domain %q exceeds 253 characters", ruleID, d)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return domainPattern{}, loadErr("rule %q: invalid domain label in %q", ruleID, d)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return domainPattern{}, loadErr("rule %q: domain label in %q must not start or end with '-'", ruleID, d)
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return domainPattern{}, loadErr("rule %q: invalid character %q in domain %q", ruleID, string(ch), d)
			}
		}
	}
	return domainPattern{suffix: name, wildcard: wild}, nil
}

// UnmarshalJSON accepts a number (8080) or an inclusive range ("8000-9000").
// Malformed spellings are rejected outright; nothing is silently repaired.
func (p *PortRange) UnmarshalJSON(raw []byte) error {
	var single uint16
	if err := json.Unmarshal(raw, &single); err == nil {
		p.Lo, p.Hi = single, single
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("port must be a number or \"lo-hi\" range, got %s", string(raw))
	}
	lo, hi, ok := parsePortRange(s)
	if !ok {
		return fmt.Errorf("invalid port range %q: use a number or \"lo-hi\"", s)
	}
	p.Lo, p.Hi = uint16(lo), uint16(hi)
	return nil
}

// parsePortRange strictly parses "lo-hi": exactly two all-digit parts, no
// signs, spaces or trailing garbage, each within 0-65535.
func parsePortRange(s string) (lo, hi int, ok bool) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	vals := [2]int{}
	for i, part := range parts {
		if part == "" {
			return 0, 0, false
		}
		n := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return 0, 0, false
			}
			n = n*10 + int(ch-'0')
			if n > 65535 {
				return 0, 0, false
			}
		}
		vals[i] = n
	}
	return vals[0], vals[1], true
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
