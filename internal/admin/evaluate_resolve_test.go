package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/resolver"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

func newResolveServer(t *testing.T, rules string, rs resolver.Resolver) (*httptest.Server, *policy.Store, *stats.Counters) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore()
	rl := policy.NewReloader(store, path)
	if _, err := rl.Reload(); err != nil {
		t.Fatal(err)
	}
	c := stats.New()
	srv := &Server{Store: store, Counters: c, Reload: rl.Reload, History: rl.History, Resolver: rs}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, store, c
}

func getEvaluate(t *testing.T, ts *httptest.Server, q string) (int, map[string]any) {
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

// Dry-run WITHOUT addr= must resolve the name (via the injected offline
// resolver) and adjudicate every resolved address — the same path real
// forwarding takes — so "name allowed but resolved IP denied" is a denial
// in the trial too.
func TestEvaluateWithoutAddrResolvesLikeRealForwarding(t *testing.T) {
	rules := `{"rules":[
	  {"id":"allow-names","action":"allow","domains":["*.test"]},
	  {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]}
	]}`
	rs := resolver.Map{
		"clean.test":  []netip.Addr{netip.MustParseAddr("198.51.100.1")},
		"rebind.test": []netip.Addr{netip.MustParseAddr("203.0.113.7")},
		"mixed.test": []netip.Addr{
			netip.MustParseAddr("198.51.100.1"),
			netip.MustParseAddr("203.0.113.9"),
		},
	}
	ts, store, c := newResolveServer(t, rules, rs)
	cur, _ := store.Current()

	// Name allowed, clean resolution -> allow.
	status, m := getEvaluate(t, ts, "host=clean.test&port=443")
	if status != 200 || m["allowed"] != true || m["winning_rule"] != "allow-names" {
		t.Fatalf("clean resolution must allow: %d %+v", status, m)
	}
	if m["version"] != cur.Version {
		t.Fatalf("version %v want %q", m["version"], cur.Version)
	}

	// Name allowed, resolved IP in deny range -> deny with the deny rule,
	// exactly what a real request gets.
	status, m = getEvaluate(t, ts, "host=rebind.test&port=443")
	if status != 200 || m["allowed"] != false || m["winning_rule"] != "deny-203" {
		t.Fatalf("rebinding resolution must deny via deny-203: %d %+v", status, m)
	}

	// Any one denied address among several denies the whole request.
	status, m = getEvaluate(t, ts, "host=mixed.test&port=443")
	if status != 200 || m["allowed"] != false || m["winning_rule"] != "deny-203" {
		t.Fatalf("one bad resolved address must deny: %d %+v", status, m)
	}

	// NXDOMAIN is reported as a resolution failure, never as a verdict.
	status, m = getEvaluate(t, ts, "host=missing.test&port=443")
	if status != http.StatusBadGateway || m["reason"] != "resolve_nxdomain" {
		t.Fatalf("nxdomain: want 502 resolve_nxdomain, got %d %+v", status, m)
	}
	if _, ok := m["allowed"]; ok {
		t.Fatalf("resolution failure must not return a verdict: %+v", m)
	}

	// Dry-run never touches traffic counters.
	if total := c.Snapshot().Total; total != 0 {
		t.Fatalf("dry-run polluted traffic counters: %d", total)
	}
}

// With addr= given, no resolution happens: the assumed addresses decide,
// and the verdict matches adjudicating exactly those addresses.
func TestEvaluateWithAddrSkipsResolution(t *testing.T) {
	rules := `{"rules":[
	  {"id":"allow-names","action":"allow","domains":["*.test"]},
	  {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]}
	]}`
	// rebind.test WOULD resolve to a denied address, but assumed clean
	// addresses must still allow: addr= replaces resolution entirely.
	rs := resolver.Map{
		"rebind.test": []netip.Addr{netip.MustParseAddr("203.0.113.7")},
	}
	ts, store, c := newResolveServer(t, rules, rs)
	cur, _ := store.Current()

	status, m := getEvaluate(t, ts, "host=rebind.test&port=443&addr=198.51.100.1")
	if status != 200 || m["allowed"] != true || m["winning_rule"] != "allow-names" {
		t.Fatalf("assumed clean address must allow regardless of DNS: %d %+v", status, m)
	}
	if m["version"] != cur.Version {
		t.Fatalf("version %v want %q", m["version"], cur.Version)
	}

	status, m = getEvaluate(t, ts, "host=rebind.test&port=443&addr=198.51.100.1&addr=203.0.113.7")
	if status != 200 || m["allowed"] != false || m["winning_rule"] != "deny-203" {
		t.Fatalf("one bad assumed address must deny: %d %+v", status, m)
	}

	if total := c.Snapshot().Total; total != 0 {
		t.Fatalf("dry-run polluted traffic counters: %d", total)
	}
}
