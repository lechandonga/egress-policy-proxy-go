package policy

import (
	"net/netip"
	"testing"
)

func mustBuild(t *testing.T, rules []Rule) *Policy {
	t.Helper()
	p, err := Build(rules, "test")
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	return p
}

func addr(s string) netip.Addr {
	a := netip.MustParseAddr(s)
	return a.Unmap()
}

func TestDomainPatterns(t *testing.T) {
	tests := []struct {
		name string
		pat  string
		host string
		want bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"exact rejects subdomain", "example.com", "api.example.com", false},
		{"wildcard matches apex", "*.example.com", "example.com", true},
		{"wildcard matches one level", "*.example.com", "api.example.com", true},
		{"wildcard matches deep levels", "*.example.com", "a.b.example.com", true},
		{"wildcard does not match suffix attack", "*.example.com", "evilexample.com", false},
		{"wildcard does not match other domain", "*.example.com", "example.org", false},
		{"case insensitive", "Example.COM", "example.com", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pat, err := compileDomain("r1", tc.pat)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := pat.matches(tc.host); got != tc.want {
				t.Fatalf("matches(%q under %q) = %v, want %v", tc.host, tc.pat, got, tc.want)
			}
		})
	}
}

func TestDefaultDenyFailsClosed(t *testing.T) {
	p := mustBuild(t, []Rule{{
		ID: "allow-httpbin", Action: ActionAllow,
		Domains: []string{"allowed.test"}, Ports: []PortRange{{80, 80}},
	}})
	d := p.Evaluate(Match{Host: "unknown.test", IP: addr("10.0.0.1"), Port: 80})
	if d.Allowed || d.Action != ActionDeny {
		t.Fatalf("want default deny, got %+v", d)
	}
	if d.WinningRule != "" {
		t.Fatalf("default deny must name no winning rule, got %q", d.WinningRule)
	}
}

func TestConflictDenyWinsAtSamePriority(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "allow-wild", Action: ActionAllow, Domains: []string{"*.example.com"}, Ports: []PortRange{{443, 443}}},
		{ID: "deny-secret", Action: ActionDeny, Domains: []string{"secret.example.com"}, Ports: []PortRange{{443, 443}}},
	})
	d := p.Evaluate(Match{Host: "secret.example.com", IP: addr("1.2.3.4"), Port: 443})
	if d.Allowed {
		t.Fatalf("deny must win, got %+v", d)
	}
	if d.WinningRule != "deny-secret" {
		t.Fatalf("want deny-secret, got rule %q (matched %v)", d.WinningRule, d.MatchedRules)
	}

	d2 := p.Evaluate(Match{Host: "other.example.com", IP: addr("1.2.3.4"), Port: 443})
	if !d2.Allowed || d2.WinningRule != "allow-wild" {
		t.Fatalf("wildcard allow should apply: %+v", d2)
	}
}

func TestConflictExplicitPriorityBeatsAction(t *testing.T) {
	// Even though deny wins ties, a higher-priority allow overrides.
	p := mustBuild(t, []Rule{
		{ID: "deny-all", Action: ActionDeny, CIDRs: []string{"10.0.0.0/8"}, Priority: 1},
		{ID: "allow-exception", Action: ActionAllow, CIDRs: []string{"10.1.2.3/32"}, Priority: 100},
	})
	d := p.Evaluate(Match{IP: addr("10.1.2.3"), Port: 443})
	if !d.Allowed || d.WinningRule != "allow-exception" {
		t.Fatalf("priority must win: %+v", d)
	}
}

func TestConflictSpecificityThenID(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "allow-cidr-broad", Action: ActionAllow, CIDRs: []string{"10.0.0.0/8"}},
		{ID: "allow-cidr-narrow", Action: ActionAllow, CIDRs: []string{"10.0.0.0/24"}},
	})
	d := p.Evaluate(Match{IP: addr("10.0.0.9"), Port: 8080})
	if d.WinningRule != "allow-cidr-narrow" {
		t.Fatalf("more specific prefix must win, got %q", d.WinningRule)
	}

	// Same specificity -> lexicographic rule id is the documented final tie-break.
	p2 := mustBuild(t, []Rule{
		{ID: "zzz", Action: ActionAllow, Domains: []string{"a.test"}},
		{ID: "aaa", Action: ActionAllow, Domains: []string{"a.test"}},
	})
	d2 := p2.Evaluate(Match{Host: "a.test", IP: addr("1.1.1.1"), Port: 80})
	if d2.WinningRule != "aaa" {
		t.Fatalf("lexicographic tie-break expected aaa, got %q", d2.WinningRule)
	}
}

func TestDomainAndResolvedIPBothEnforced(t *testing.T) {
	// Name allowed, but IP explicitly denied by a same-priority deny rule.
	p := mustBuild(t, []Rule{
		{ID: "allow-name", Action: ActionAllow, Domains: []string{"good.test"}, Ports: []PortRange{{443, 443}}},
		{ID: "deny-ip", Action: ActionDeny, CIDRs: []string{"203.0.113.0/24"}, Ports: []PortRange{{443, 443}}},
	})
	// Request tuple evaluated with BOTH name and resolved IP.
	d := p.Evaluate(Match{Host: "good.test", IP: addr("203.0.113.5"), Port: 443})
	if d.Allowed || d.WinningRule != "deny-ip" {
		t.Fatalf("resolved IP in denied CIDR must reject even with allowed name: %+v", d)
	}
}

func TestPorts(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "allow-80", Action: ActionAllow, Domains: []string{"a.test"}, Ports: []PortRange{{80, 80}}},
		{ID: "deny-other", Action: ActionDeny, Domains: []string{"a.test"}},
	})
	if d := p.Evaluate(Match{Host: "a.test", IP: addr("1.1.1.1"), Port: 80}); !d.Allowed {
		t.Fatalf("port 80 allowed: %+v", d)
	}
	d := p.Evaluate(Match{Host: "a.test", IP: addr("1.1.1.1"), Port: 8080})
	if d.Allowed || d.WinningRule != "deny-other" {
		t.Fatalf("port 8080 must hit deny-other: %+v", d)
	}

	// Range semantics.
	p2 := mustBuild(t, []Rule{
		{ID: "allow-range", Action: ActionAllow, Domains: []string{"b.test"}, Ports: []PortRange{{8000, 8010}}},
	})
	for _, port := range []uint16{7999, 8011} {
		if d := p2.Evaluate(Match{Host: "b.test", IP: addr("2.2.2.2"), Port: port}); d.Allowed {
			t.Fatalf("port %d outside range must default-deny", port)
		}
	}
	if d := p2.Evaluate(Match{Host: "b.test", IP: addr("2.2.2.2"), Port: 8005}); !d.Allowed {
		t.Fatalf("port 8005 in range must allow: %+v", d)
	}
}
