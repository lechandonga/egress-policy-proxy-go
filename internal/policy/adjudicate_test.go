package policy

import (
	"net/netip"
	"os"
	"testing"
)

// Adjudicate is the single function shared by real forwarding and dry-run
// trial evaluation; these tests pin down its shared semantics.

func TestAdjudicateAllow(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "allow-name", Action: ActionAllow, Domains: []string{"good.test"}, Ports: []PortRange{{443, 443}}},
	})
	adj := p.Adjudicate("good.test", 443, []netip.Addr{addr("198.51.100.7")})
	if !adj.Allowed || adj.WinningRule != "allow-name" || adj.DefaultDeny {
		t.Fatalf("want allow by allow-name, got %+v", adj)
	}
}

func TestAdjudicateDefaultDenyNamesRule(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "allow-name", Action: ActionAllow, Domains: []string{"good.test"}, Ports: []PortRange{{443, 443}}},
	})
	adj := p.Adjudicate("other.test", 443, []netip.Addr{addr("198.51.100.7")})
	if adj.Allowed {
		t.Fatalf("must deny: %+v", adj)
	}
	if !adj.DefaultDeny || adj.WinningRule != "" || adj.Action != ActionDeny {
		t.Fatalf("must be an explicit default deny with no winning rule: %+v", adj)
	}
}

func TestAdjudicateDefaultDenyWithoutAddresses(t *testing.T) {
	// Name-only trial without assumed addresses: an IP-only rule can't match.
	p := mustBuild(t, []Rule{
		{ID: "deny-ip", Action: ActionDeny, CIDRs: []string{"203.0.113.0/24"}},
	})
	adj := p.Adjudicate("anything.test", 443, nil)
	if adj.Allowed || !adj.DefaultDeny {
		t.Fatalf("name-only trial must default deny, got %+v", adj)
	}
}

func TestAdjudicateAnyDeniedAddressRejectsAll(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "allow-name", Action: ActionAllow, Domains: []string{"good.test"}, Ports: []PortRange{{443, 443}}},
		{ID: "deny-net", Action: ActionDeny, CIDRs: []string{"203.0.113.0/24"}, Ports: []PortRange{{443, 443}}},
	})

	// Two assumed addresses; the second lands in the denied range.
	adj := p.Adjudicate("good.test", 443, []netip.Addr{
		addr("198.51.100.1"),
		addr("203.0.113.9"),
	})
	if adj.Allowed || adj.WinningRule != "deny-net" {
		t.Fatalf("one denied address must deny the whole trial, got %+v", adj)
	}

	// Order matters for "first denial wins": a denied first address must
	// surface its own winning rule too.
	adj2 := p.Adjudicate("good.test", 443, []netip.Addr{
		addr("203.0.113.9"),
		addr("198.51.100.1"),
	})
	if adj2.Allowed || adj2.WinningRule != "deny-net" {
		t.Fatalf("first address denied must deny, got %+v", adj2)
	}

	// Both addresses outside the deny range: allowed.
	adj3 := p.Adjudicate("good.test", 443, []netip.Addr{
		addr("198.51.100.1"),
		addr("198.51.100.2"),
	})
	if !adj3.Allowed || adj3.WinningRule != "allow-name" {
		t.Fatalf("all addresses allowed must allow, got %+v", adj3)
	}
}

func TestAdjudicateLowercasesHost(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "a", Action: ActionAllow, Domains: []string{"good.test"}},
	})
	adj := p.Adjudicate("GOOD.Test", 443, []netip.Addr{addr("1.1.1.1")})
	if !adj.Allowed || adj.Host != "good.test" {
		t.Fatalf("host must be normalized: %+v", adj)
	}
}

// Strict validation matrix: every illegal spelling must fail the whole
// load with a specific error kind; nothing is corrected or defaulted.

func TestStrictValidationMatrix(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		kind ErrorKind
	}{
		// ports
		{"port float", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":[4.5]}]}`, KindInvalidPort},
		{"port negative", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":[-1]}]}`, KindInvalidPort},
		{"port huge", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":[99999]}]}`, KindInvalidPort},
		{"port string single", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["443"]}]}`, KindInvalidPort},
		{"port range garbage", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["80-abc"]}]}`, KindInvalidPort},
		{"port range three", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["80-90-100"]}]}`, KindInvalidPort},
		{"port range trailing", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["80-90x"]}]}`, KindInvalidPort},
		{"port range zero", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["0-80"]}]}`, KindInvalidPort},
		{"port range inverted", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["90-80"]}]}`, KindInvalidPort},
		{"port range huge", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["1-99999"]}]}`, KindInvalidPort},
		{"port bool", `{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":[true]}]}`, KindInvalidPort},

		// cidrs
		{"cidr bad", `{"rules":[{"id":"r","action":"allow","cidrs":["1.2.3.4/99"]}]}`, KindInvalidCIDR},
		{"cidr host bits", `{"rules":[{"id":"r","action":"allow","cidrs":["10.0.0.5/24"]}]}`, KindInvalidCIDR},
		{"cidr space", `{"rules":[{"id":"r","action":"allow","cidrs":[" 10.0.0.0/24"]}]}`, KindInvalidCIDR},
		{"cidr garbage", `{"rules":[{"id":"r","action":"allow","cidrs":["not-an-ip"]}]}`, KindInvalidCIDR},
		{"cidr v4prefix v6", `{"rules":[{"id":"r","action":"allow","cidrs":["2001:db8::/200"]}]}`, KindInvalidCIDR},
		{"bare zero v4", `{"rules":[{"id":"r","action":"allow","cidrs":["0.0.0.0"]}]}`, KindInvalidCIDR},
		{"bare zero v6", `{"rules":[{"id":"r","action":"allow","cidrs":["::"]}]}`, KindInvalidCIDR},
		{"cidr zone", `{"rules":[{"id":"r","action":"allow","cidrs":["fe80::1%eth0"]}]}`, KindInvalidCIDR},

		// domains / wildcards
		{"domain empty", `{"rules":[{"id":"r","action":"allow","domains":[""]}]}`, KindInvalidDomain},
		{"domain bare wildcard", `{"rules":[{"id":"r","action":"allow","domains":["*."]}]}`, KindInvalidDomain},
		{"domain mid wildcard", `{"rules":[{"id":"r","action":"allow","domains":["a.*.test"]}]}`, KindInvalidDomain},
		{"domain trailing dot", `{"rules":[{"id":"r","action":"allow","domains":["a.test."]}]}`, KindInvalidDomain},
		{"domain leading dot", `{"rules":[{"id":"r","action":"allow","domains":[".a.test"]}]}`, KindInvalidDomain},
		{"domain double dot", `{"rules":[{"id":"r","action":"allow","domains":["a..test"]}]}`, KindInvalidDomain},
		{"domain bad char", `{"rules":[{"id":"r","action":"allow","domains":["a!.test"]}]}`, KindInvalidDomain},
		{"domain unicode", `{"rules":[{"id":"r","action":"allow","domains":["é.test"]}]}`, KindInvalidDomain},
		{"domain space", `{"rules":[{"id":"r","action":"allow","domains":["a .test"]}]}`, KindInvalidDomain},
		{"domain long label", `{"rules":[{"id":"r","action":"allow","domains":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test"]}]}`, KindInvalidDomain},
		{"domain leading hyphen", `{"rules":[{"id":"r","action":"allow","domains":["-a.test"]}]}`, KindInvalidDomain},

		// other
		{"bad action", `{"rules":[{"id":"r","action":"maybe","domains":["a.test"]}]}`, KindInvalidAction},
		{"missing id", `{"rules":[{"action":"allow","domains":["a.test"]}]}`, KindInvalidID},
		{"dup id", `{"rules":[{"id":"r","action":"allow","domains":["a.test"]},{"id":"r","action":"deny","domains":["b.test"]}]}`, KindInvalidID},
		{"no constraints", `{"rules":[{"id":"r","action":"allow"}]}`, KindConstraint},
		{"empty rules", `{"rules":[]}`, KindEmptyPolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.doc))
			if err == nil {
				t.Fatalf("expected %s rejection, got nil", tc.kind)
			}
			var le *LoadError
			if !AsLoadError(err, &le) {
				t.Fatalf("want LoadError, got %T %v", err, err)
			}
			if le.Kind() != tc.kind {
				t.Fatalf("kind=%s want %s (err=%v)", le.Kind(), tc.kind, err)
			}
		})
	}
}

func AsLoadError(err error, target **LoadError) bool {
	if le, ok := err.(*LoadError); ok {
		*target = le
		return true
	}
	return false
}

// Previously-valid documents must remain valid after validation tightening.
func TestExamplePolicyStillValid(t *testing.T) {
	data, err := os.ReadFile("../../policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(data)
	if err != nil {
		t.Fatalf("example policy must load: %v", err)
	}
	if len(p.Rules) != 4 {
		t.Fatalf("want 4 rules, got %d", len(p.Rules))
	}
}

func TestStrictValidationKeepsBareIPsAndWildcards(t *testing.T) {
	p, err := Decode([]byte(`{"rules":[
	  {"id":"ip","action":"allow","cidrs":["127.0.0.1","::1","10.0.0.0/24","2001:db8::/32"]},
	  {"id":"dom","action":"deny","domains":["*.a.test","x-y.io"]}
	]}`))
	if err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(p.Rules))
	}
}
