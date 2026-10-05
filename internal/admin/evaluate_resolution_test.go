package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/resolver"
)

// newEvaluateServer wires an admin server with an injectable offline
// resolver so dry-run evaluation without addr exercises the exact
// resolve+adjudicate path real forwarding uses, with no external network.
func newEvaluateServer(t *testing.T, rules string, res policy.NameResolver) (*httptest.Server, *policy.Store) {
	t.Helper()
	store := policy.NewStore()
	p, err := policy.Decode([]byte(rules))
	if err != nil {
		t.Fatal(err)
	}
	store.Swap(p)
	ts := httptest.NewServer((&Server{Store: store, Resolver: res}).Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

// TestEvaluateWithoutAddrResolvesLikeForwarding is the core regression:
// a domain allowed by name but resolving into a deny CIDR must be denied
// by the dry-run just like a real forwarded request, and the reported
// winning rule/version must match the policy actually used.
func TestEvaluateWithoutAddrResolvesLikeForwarding(t *testing.T) {
	rules := `{"rules":[
	  {"id":"allow-names","action":"allow","domains":["*.test"]},
	  {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]}
	]}`
	res := resolver.Map{
		"clean.test":  []netip.Addr{netip.MustParseAddr("198.51.100.1")},
		"rebind.test": []netip.Addr{netip.MustParseAddr("203.0.113.7")},
		"multi.test": {
			netip.MustParseAddr("198.51.100.2"),
			netip.MustParseAddr("203.0.113.9"),
		},
	}
	ts, store := newEvaluateServer(t, rules, res)
	cur, _ := store.Current()

	get := func(q string) (int, map[string]any) {
		t.Helper()
		resp, err := http.Get(ts.URL + "/evaluate?" + q)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	t.Run("allowed name resolves to clean address", func(t *testing.T) {
		status, m := get("host=clean.test&port=443")
		if status != 200 || m["allowed"] != true || m["winning_rule"] != "allow-names" {
			t.Fatalf("got %d %+v", status, m)
		}
		if m["version"] != cur.Version {
			t.Fatalf("version %v want %q", m["version"], cur.Version)
		}
		// Resolution path must still populate per-address detail.
		addrs, _ := m["addresses"].([]any)
		if len(addrs) != 1 {
			t.Fatalf("addresses detail missing: %+v", m["addresses"])
		}
	})

	t.Run("allowed name but resolved IP in deny range", func(t *testing.T) {
		status, m := get("host=rebind.test&port=443")
		if status != 200 || m["allowed"] != false || m["winning_rule"] != "deny-203" {
			t.Fatalf("dry-run must match real forwarding denial: got %d %+v", status, m)
		}
		if m["version"] != cur.Version {
			t.Fatalf("version %v want %q", m["version"], cur.Version)
		}
	})

	t.Run("several resolved addresses one denied denies the whole", func(t *testing.T) {
		status, m := get("host=multi.test&port=443")
		if status != 200 || m["allowed"] != false || m["winning_rule"] != "deny-203" {
			t.Fatalf("one bad resolved address must deny: got %d %+v", status, m)
		}
		addrs, _ := m["addresses"].([]any)
		if len(addrs) != 2 {
			t.Fatalf("both resolved addresses must be detailed: %+v", m["addresses"])
		}
	})

	t.Run("explicit addr overrides resolution", func(t *testing.T) {
		// rebind.test resolves into the deny range, but an explicitly
		// assumed clean address must be used (resolver never consulted).
		status, m := get("host=rebind.test&port=443&addr=198.51.100.50")
		if status != 200 || m["allowed"] != true || m["winning_rule"] != "allow-names" {
			t.Fatalf("assumed addr must stand in for resolution: got %d %+v", status, m)
		}
	})

	t.Run("NXDOMAIN is a definite 502 not a verdict", func(t *testing.T) {
		status, m := get("host=nope.test&port=443")
		if status != http.StatusBadGateway || m["reason"] != "resolve_nxdomain" {
			t.Fatalf("nxdomain: got %d %+v", status, m)
		}
		if _, ok := m["allowed"]; ok {
			t.Fatalf("resolution failure must not return a verdict: %+v", m)
		}
	})

	t.Run("resolver failure is a definite 502", func(t *testing.T) {
		failing := resolver.Func(func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, &resolver.Error{
				Class: resolver.ClassFailure,
				Host:  "broken.test",
				Err:   errors.New("upstream resolver timeout"),
			}
		})
		store2 := policy.NewStore()
		store2.Swap(cur)
		ts2 := httptest.NewServer((&Server{Store: store2, Resolver: failing}).Handler())
		t.Cleanup(ts2.Close)
		resp, err := http.Get(ts2.URL + "/evaluate?host=broken.test&port=443")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		if resp.StatusCode != http.StatusBadGateway || m["reason"] != "resolve_failure" {
			t.Fatalf("resolver failure: got %d %+v", resp.StatusCode, m)
		}
	})
}

// TestEvaluateResolutionUsesActiveVersion re-snapshots on every request, so
// the version returned is always the one that produced the verdict even
// while swaps happen.
func TestEvaluateResolutionVersionBound(t *testing.T) {
	rules := `{"rules":[{"id":"allow-a","action":"allow","domains":["a.test"]}]}`
	res := resolver.Map{"a.test": []netip.Addr{netip.MustParseAddr("198.51.100.1")}}
	ts, store := newEvaluateServer(t, rules, res)
	v1, _ := store.Current()
	v1.Version = "v1"
	store.Swap(v1)

	p2, err := policy.Decode([]byte(`{"rules":[{"id":"deny-all-ip","action":"deny","cidrs":["198.51.100.0/24"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p2.Version = "v2"

	const rounds = 200
	allowedV1, deniedV2 := 0, 0
	for i := 0; i < rounds; i++ {
		if i%2 == 0 {
			store.Swap(p2)
		} else {
			store.Swap(v1)
		}
		resp, err := http.Get(ts.URL + "/evaluate?host=a.test&port=443")
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
		// The handler snapshots once per request: its verdict must always
		// belong to exactly one of the two versions, never a mix.
		switch m["version"] {
		case v1.Version:
			if m["allowed"] != true || m["winning_rule"] != "allow-a" {
				t.Fatalf("v1 verdict mismatch: %+v", m)
			}
			allowedV1++
		case p2.Version:
			if m["allowed"] != false || m["winning_rule"] != "deny-all-ip" {
				t.Fatalf("v2 verdict mismatch: %+v", m)
			}
			deniedV2++
		default:
			t.Fatalf("unknown version %v", m["version"])
		}
	}
	if allowedV1 == 0 || deniedV2 == 0 {
		t.Fatalf("expected both versions to be observed, got v1=%d v2=%d", allowedV1, deniedV2)
	}
}
