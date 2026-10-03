package proxy

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func portOfURL(t *testing.T, u *url.URL) uint16 {
	t.Helper()
	ps := u.Port()
	if ps == "" {
		ps = "80"
	}
	p, err := parsePort(ps)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// trial runs exactly the evaluation half of authorize without dialing or
// counting: snapshot the store, resolve, and call the same Adjudicate the
// proxy uses internally.
func (p *Proxy) trial(ctx context.Context, host string, port uint16) policy.Adjudication {
	snap, ok := p.store.Current()
	if !ok {
		t := policy.Adjudication{Action: policy.ActionDeny, Reason: "no policy"}
		return t
	}
	var ips []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{addr.Unmap()}
		return snap.Adjudicate("", port, ips)
	}
	addrs, err := p.cfg.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		// Resolution failure is out of scope for policy parity.
		return policy.Adjudication{Action: policy.ActionDeny, Reason: "resolve:" + err.Error()}
	}
	for _, a := range addrs {
		ips = append(ips, a.Unmap())
	}
	return snap.Adjudicate(host, port, ips)
}

// trialWithAddrs evaluates with caller-assumed addresses (the /evaluate
// feature) against the same snapshot semantics.
func (p *Proxy) trialWithAddrs(host string, port uint16, ips []netip.Addr) (policy.Adjudication, string) {
	snap, ok := p.store.Current()
	if !ok {
		return policy.Adjudication{}, ""
	}
	return snap.Adjudicate(host, port, ips), snap.Version
}

// For every (host, port) pair the dry-run verdict must equal the verdict a
// real forwarded request gets, including "name allowed but a resolved
// address hits a deny range".
func TestDryRunMatchesRealForwarding(t *testing.T) {
	h := newHarness(t, `{
	  "rules": [
	    {"id":"allow-upstream","action":"allow","domains":["upstream.test"]},
	    {"id":"allow-tls","action":"allow","domains":["tls.test"]},
	    {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]},
	    {"id":"deny-domain","action":"deny","domains":["forbidden.test"]}
	  ]
	}`)

	cases := []struct {
		name       string
		target     string
		wantAllow  bool
		wantRule   string
		wantStatus int
	}{
		{"allowed", "http://upstream.test:" + h.portOf(h.upstream) + "/", true, "allow-upstream", 200},
		{"denied by domain", "http://forbidden.test:" + h.portOf(h.upstream) + "/", false, "deny-domain", 403},
		{"denied via resolved ip", "http://rebind.test:443/", false, "deny-203", 403},
		{"default deny resolvable host", "http://slow.test:80/", false, "", 403},
	}

	px := New(h.store, h.counters, Config{
		Resolver:       h.resolver,
		RequestTimeout: 5 * time.Second,
		DialTimeout:    2 * time.Second,
		IOIdleTimeout:  2 * time.Second,
	})

	before := h.counters.Snapshot().Total
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := mustURL(t, tc.target)
			port := portOfURL(t, u)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			trial := px.trial(ctx, u.Hostname(), port)

			status, hdr, _ := proxyGet(t, h.proxyClient(), tc.target)
			if status != tc.wantStatus {
				t.Fatalf("real status=%d want %d", status, tc.wantStatus)
			}

			if trial.Allowed != tc.wantAllow {
				t.Fatalf("trial allowed=%v want %v (adj=%+v)", trial.Allowed, tc.wantAllow, trial)
			}
			if trial.WinningRule != tc.wantRule {
				t.Fatalf("trial rule=%q real=%q", trial.WinningRule, tc.wantRule)
			}
			if tc.wantRule == "" && !trial.DefaultDeny {
				t.Fatalf("default-deny case must set DefaultDeny")
			}
			if realRule := hdr.Get("X-Egress-Rule"); !tc.wantAllow && realRule != tc.wantRule {
				t.Fatalf("real X-Egress-Rule=%q want %q", realRule, tc.wantRule)
			}
		})
	}

	// Trials do not touch counters: only the real requests were counted
	// (every real request lands in exactly one bucket, including NXDOMAIN).
	after := h.counters.Snapshot().Total
	if after-before != uint64(len(cases)) {
		t.Fatalf("trial polluted counters: before=%d after=%d", before, after)
	}
}

// Assumed-address semantics: the same deny CIDR rule that a real request
// hits via DNS must be hit by the dry-run when that address is supplied via
// addr=; any one bad address among several denies, and the version is bound.
func TestDryRunAssumedAddressesParity(t *testing.T) {
	h := newHarness(t, `{
	  "rules": [
	    {"id":"allow-names","action":"allow","domains":["*.test"]},
	    {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]}
	  ]
	}`)

	px := New(h.store, h.counters, Config{Resolver: h.resolver})

	// Baseline: real request to rebind.test (resolves to 203.0.113.7).
	status, hdr, _ := proxyGet(t, h.proxyClient(), "http://rebind.test:443/")
	if status != http.StatusForbidden || hdr.Get("X-Egress-Rule") != "deny-203" {
		t.Fatalf("real request must be denied by deny-203, got %d", status)
	}

	// Dry-run WITHOUT the bad address: the name alone is allowed, exactly
	// like a hypothetical resolution that only returned a clean IP.
	adj, _ := px.trialWithAddrs("rebind.test", 443, []netip.Addr{netip.MustParseAddr("198.51.100.1")})
	if !adj.Allowed || adj.WinningRule != "allow-names" {
		t.Fatalf("clean addresses should allow: %+v", adj)
	}

	// Dry-run WITH the bad assumed address: same verdict as the real request.
	adj, _ = px.trialWithAddrs("rebind.test", 443, []netip.Addr{
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("203.0.113.7"),
	})
	if adj.Allowed || adj.WinningRule != "deny-203" {
		t.Fatalf("one bad assumed address must deny like real traffic: %+v", adj)
	}

	// Order independent for the final verdict: bad address first.
	adj, _ = px.trialWithAddrs("rebind.test", 443, []netip.Addr{
		netip.MustParseAddr("203.0.113.7"),
		netip.MustParseAddr("198.51.100.1"),
	})
	if adj.Allowed || adj.WinningRule != "deny-203" {
		t.Fatalf("bad-first ordering must also deny: %+v", adj)
	}

	// No counters consumed by trials.
	snap := h.counters.Snapshot()
	if snap.Total != 1 {
		t.Fatalf("only the one real request must be counted, got %d", snap.Total)
	}
}
