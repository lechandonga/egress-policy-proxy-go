package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/resolver"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Reason codes returned to clients. They are the contract for
// distinguishing policy denials from infrastructure failures.
const (
	ReasonPolicyDeny      = "policy_deny"
	ReasonResolveNXDOMAIN = "resolve_nxdomain"
	ReasonResolveFailure  = "resolve_failure"
	ReasonUpstreamDial    = "upstream_unreachable"
	ReasonUpstreamTimeout = "upstream_timeout"
	ReasonNoPolicy        = "policy_unavailable"
	ReasonBadRequest      = "bad_request"
)

// Config configures a Proxy.
type Config struct {
	Resolver       resolver.Resolver
	RequestTimeout time.Duration // total budget for one proxied request
	DialTimeout    time.Duration // TCP connect budget
	IOIdleTimeout  time.Duration // idle deadline while bridging CONNECT tunnels
	// Dialer, if set, performs the upstream TCP dial. The address is always
	// "ip:port". Defaults to net.Dialer.DialContext.
	Dialer func(ctx context.Context, network, address string) (net.Conn, error)
}

// Proxy is an HTTP/HTTPS forward proxy that enforces a policy.Store.
type Proxy struct {
	store   *policy.Store
	counter *stats.Counters
	cfg     Config
}

func New(store *policy.Store, counter *stats.Counters, cfg Config) *Proxy {
	if cfg.Resolver == nil {
		cfg.Resolver = resolver.Std{}
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 15 * time.Second
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.IOIdleTimeout == 0 {
		cfg.IOIdleTimeout = 30 * time.Second
	}
	if cfg.Dialer == nil {
		d := &net.Dialer{}
		cfg.Dialer = d.DialContext
	}
	return &Proxy{store: store, counter: counter, cfg: cfg}
}

// verdict bundles the evaluated decision with the IP it applies to.
type verdict struct {
	decision policy.Decision
	ip       netip.Addr
}

// authorize resolves host (when needed) and evaluates the policy against
// the domain together with EVERY resolved address, so an allowed name that
// resolves into a denied CIDR cannot bypass the policy.
func (p *Proxy) authorize(ctx context.Context, host string, port uint16) ([]verdict, string, error) {
	_, verdicts, reason, err := evaluate(ctx, p.store, p.cfg.Resolver, host, port, nil)
	return verdicts, reason, err
}

// evaluate is the single decision core shared by real forwarding and the
// admin dry-run: same snapshot handling, same resolution rules, same
// per-address evaluation and the same "any denied address denies the whole
// request" collapse. assumed, when non-empty, replaces live resolution.
// The returned snapshot is the one the verdicts were computed from, so
// callers can report exactly which policy version decided.
func evaluate(ctx context.Context, store *policy.Store, res resolver.Resolver, host string, port uint16, assumed []netip.Addr) (*policy.Policy, []verdict, string, error) {
	snap, ok := store.Current()
	if !ok {
		return nil, nil, ReasonNoPolicy, errors.New("no policy loaded; proxy fails closed")
	}

	var ips []netip.Addr
	switch {
	case len(assumed) > 0:
		for _, a := range assumed {
			ips = append(ips, a.Unmap())
		}
	default:
		if addr, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{addr.Unmap()}
			host = ""
		} else {
			addrs, err := res.LookupNetIP(ctx, "ip", host)
			if err != nil {
				var rerr *resolver.Error
				if errors.As(err, &rerr) && rerr.Class == resolver.ClassNXDOMAIN {
					return nil, nil, ReasonResolveNXDOMAIN, err
				}
				return nil, nil, ReasonResolveFailure, err
			}
			if len(addrs) == 0 {
				return nil, nil, ReasonResolveFailure, errors.New("resolver returned no addresses for " + host)
			}
			for _, a := range addrs {
				ips = append(ips, a.Unmap())
			}
		}
	}

	verdicts := make([]verdict, 0, len(ips))
	for _, ip := range ips {
		d := snap.Evaluate(policy.Match{Host: strings.ToLower(host), IP: ip, Port: port})
		verdicts = append(verdicts, verdict{decision: d, ip: ip})
	}

	// If any resolved address is denied, the whole request is denied:
	// a mixed answer set must not let a denied address be reached.
	for _, v := range verdicts {
		if !v.decision.Allowed {
			return snap, []verdict{v}, "", nil
		}
	}
	return snap, verdicts, "", nil
}

// DryRunResult is the outcome of a what-if policy evaluation. Nothing is
// forwarded and nothing is counted in the traffic statistics.
type DryRunResult struct {
	Allowed      bool     `json:"allowed"`
	Action       string   `json:"action"`
	WinningRule  string   `json:"winning_rule,omitempty"`
	Reason       string   `json:"reason"`
	MatchedRules []string `json:"matched_rules,omitempty"`
	IPs          []string `json:"ips"`
	Version      string   `json:"version"`
}

// DryRun evaluates host/port (optionally against assumed resolved
// addresses) against exactly one policy snapshot and reports the verdict,
// the winning rule and the version that decided. It shares evaluate() with
// real forwarding, so identical inputs always yield identical conclusions.
func DryRun(ctx context.Context, store *policy.Store, res resolver.Resolver, host string, port uint16, assumed []netip.Addr) (DryRunResult, string, error) {
	snap, verdicts, reason, err := evaluate(ctx, store, res, host, port, assumed)
	if err != nil {
		return DryRunResult{}, reason, err
	}
	chosen := verdicts[0]
	res2 := DryRunResult{
		Allowed:      chosen.decision.Allowed,
		Action:       string(chosen.decision.Action),
		WinningRule:  chosen.decision.WinningRule,
		Reason:       chosen.decision.Reason,
		MatchedRules: chosen.decision.MatchedRules,
		Version:      snap.Version,
	}
	seen := map[string]bool{}
	for _, v := range verdicts {
		s := v.ip.String()
		if !seen[s] {
			seen[s] = true
			res2.IPs = append(res2.IPs, s)
		}
	}
	return res2, "", nil
}

func (p *Proxy) count(o stats.Outcome, rule string) { p.counter.Record(o, rule) }

type reject struct {
	status int
	reason string
	rule   string
	detail string
}

func (p *Proxy) rejectResponse(w http.ResponseWriter, rj reject) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Egress-Reason", rj.reason)
	if rj.rule != "" {
		h.Set("X-Egress-Rule", rj.rule)
	}
	w.WriteHeader(rj.status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"allowed": false,
		"reason":  rj.reason,
		"rule":    rj.rule,
		"detail":  rj.detail,
	})
}

func splitHostPort(hostport string) (string, uint16, error) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	port, err := parsePort(ps)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}

func parsePort(ps string) (uint16, error) {
	n, err := net.LookupPort("tcp", ps) // accepts numeric and service names
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", ps, err)
	}
	return uint16(n), nil
}

// Handler returns the http.Handler implementing the forward proxy.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.serveHTTP)
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleForward(w, r)
}

func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request) {
	// Forward-proxy style: absolute-form request target.
	if r.URL == nil || r.URL.Host == "" {
		p.count(stats.OutcomeClientError, "")
		p.rejectResponse(w, reject{
			status: http.StatusBadRequest,
			reason: ReasonBadRequest,
			detail: "plain HTTP proxy requests must use an absolute URL (http://host/path)",
		})
		return
	}

	host := r.URL.Hostname()
	ps := r.URL.Port()
	if ps == "" {
		ps = "80"
	}
	port, err := parsePort(ps)
	if err != nil {
		p.count(stats.OutcomeClientError, "")
		p.rejectResponse(w, reject{status: http.StatusBadRequest, reason: ReasonBadRequest, detail: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.cfg.RequestTimeout)
	defer cancel()

	verdicts, reason, err := p.authorize(ctx, host, port)
	if err != nil {
		p.writeAuthzError(w, reason, err)
		return
	}
	chosen := verdicts[0]
	if !chosen.decision.Allowed {
		p.count(stats.OutcomeDeniedPolicy, chosen.decision.WinningRule)
		p.rejectResponse(w, reject{
			status: http.StatusForbidden,
			reason: ReasonPolicyDeny,
			rule:   chosen.decision.WinningRule,
			detail: chosen.decision.Reason,
		})
		return
	}

	conn, rj := p.dialUpstream(ctx, chosen.ip, port)
	if rj != nil {
		p.count(dialOutcome(rj.reason), "")
		p.rejectResponse(w, *rj)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.cfg.RequestTimeout))

	// Speak HTTP/1.x to the upstream over the already-established connection.
	upReq := r.Clone(ctx)
	upReq.RequestURI = ""
	upReq.URL.Scheme = "http"
	// Keep the target's authority in Host; drop hop-by-hop proxy headers.
	upReq.Header.Del("Proxy-Connection")
	upReq.Header.Del("Proxy-Authorization")

	tr := &oneShotTransport{conn: conn}
	resp, err := tr.RoundTrip(upReq)
	if err != nil {
		outcome, reason := classifyUpstreamErr(err)
		p.count(outcome, "")
		p.rejectResponse(w, reject{status: http.StatusBadGateway, reason: reason, detail: err.Error()})
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_ = copyWithIdle(w, resp.Body, p.cfg.IOIdleTimeout, conn)
	p.count(stats.OutcomeAllowed, chosen.decision.WinningRule)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host)
	if err != nil {
		p.count(stats.OutcomeClientError, "")
		p.rejectResponse(w, reject{status: http.StatusBadRequest, reason: ReasonBadRequest, detail: err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.cfg.RequestTimeout)
	defer cancel()

	verdicts, reason, err := p.authorize(ctx, host, port)
	if err != nil {
		p.writeAuthzError(w, reason, err)
		return
	}
	chosen := verdicts[0]
	if !chosen.decision.Allowed {
		p.count(stats.OutcomeDeniedPolicy, chosen.decision.WinningRule)
		p.rejectResponse(w, reject{
			status: http.StatusForbidden,
			reason: ReasonPolicyDeny,
			rule:   chosen.decision.WinningRule,
			detail: chosen.decision.Reason,
		})
		return
	}

	conn, rj := p.dialUpstream(ctx, chosen.ip, port)
	if rj != nil {
		p.count(dialOutcome(rj.reason), "")
		p.rejectResponse(w, *rj)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = conn.Close()
		p.rejectResponse(w, reject{status: http.StatusInternalServerError, reason: "bad_request", detail: "server does not support hijacking"})
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = conn.Close()
		p.rejectResponse(w, reject{status: http.StatusBadGateway, reason: ReasonUpstreamDial, detail: err.Error()})
		return
	}

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = conn.Close()
		p.count(stats.OutcomeClientError, "")
		return
	}

	// Tunnel until either side closes or goes idle. Both conns are always
	// closed here, which guarantees no goroutine/connection leak.
	done := make(chan struct{}, 2)
	go func() { bridge(client, conn, p.cfg.IOIdleTimeout); done <- struct{}{} }()
	go func() { bridge(conn, client, p.cfg.IOIdleTimeout); done <- struct{}{} }()
	<-done // first half-close ends the tunnel
	_ = client.Close()
	_ = conn.Close()
	<-done
	p.count(stats.OutcomeAllowed, chosen.decision.WinningRule)
}

func (p *Proxy) writeAuthzError(w http.ResponseWriter, reason string, err error) {
	switch reason {
	case ReasonNoPolicy:
		p.count(stats.OutcomeClientError, "")
		p.rejectResponse(w, reject{status: http.StatusServiceUnavailable, reason: reason, detail: err.Error()})
	case ReasonResolveNXDOMAIN:
		p.count(stats.OutcomeResolveFailed, "")
		p.rejectResponse(w, reject{status: http.StatusBadGateway, reason: reason, detail: err.Error()})
	case ReasonResolveFailure:
		p.count(stats.OutcomeResolveFailed, "")
		p.rejectResponse(w, reject{status: http.StatusBadGateway, reason: reason, detail: err.Error()})
	default:
		p.rejectResponse(w, reject{status: http.StatusInternalServerError, reason: reason, detail: err.Error()})
	}
}

func (p *Proxy) dialUpstream(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, *reject) {
	dialCtx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := p.cfg.Dialer(dialCtx, "tcp", address)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &reject{status: http.StatusGatewayTimeout, reason: ReasonUpstreamTimeout, detail: err.Error()}
		}
		return nil, &reject{status: http.StatusBadGateway, reason: ReasonUpstreamDial, detail: err.Error()}
	}
	return conn, nil
}

func dialOutcome(reason string) stats.Outcome {
	if reason == ReasonUpstreamTimeout {
		return stats.OutcomeUpstreamIOTimeout
	}
	return stats.OutcomeUpstreamDial
}

func classifyUpstreamErr(err error) (stats.Outcome, string) {
	if errors.Is(err, context.DeadlineExceeded) || isNetTimeout(err) {
		return stats.OutcomeUpstreamIOTimeout, ReasonUpstreamTimeout
	}
	return stats.OutcomeUpstreamDial, ReasonUpstreamDial
}

func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// bridge copies between two conns with an idle deadline; any EOF/error/timeout
// returns so the caller can close both sides.
func bridge(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idle))
		n, rerr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func copyWithIdle(w http.ResponseWriter, body io.Reader, idle time.Duration, conn net.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return rerr
		}
	}
}

// oneShotTransport issues one HTTP request over a pre-dialed connection.
type oneShotTransport struct{ conn net.Conn }

func (t *oneShotTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Write(t.conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(t.conn)
	return http.ReadResponse(br, req)
}
