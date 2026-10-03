package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/resolver"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

func TestReloadEndpointKeepsOldPolicyOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	store := policy.NewStore()
	v1, err := store.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		Store:    store,
		Counters: stats.New(),
		Reload:   func() (*policy.Policy, error) { return store.LoadFile(path) },
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Broken policy: reload endpoint must report validation failure and
	// confirm the old version stays active.
	if err := os.WriteFile(path, []byte(`{bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error_kind"] != "validation" {
		t.Fatalf("error_kind=%q want validation", body["error_kind"])
	}
	if body["active_version"] != v1.Version {
		t.Fatalf("old version %q not retained, got %q", v1.Version, body["active_version"])
	}

	// Valid policy reloads and activates.
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"v2","action":"allow","domains":["b.test"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.Post(ts.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || !strings.Contains(readBody(resp2), `"reloaded":"true"`) {
		t.Fatalf("reload failed: %d %s", resp2.StatusCode, readBody(resp2))
	}
}

func TestStatsEndpoint(t *testing.T) {
	c := stats.New()
	c.Record(stats.OutcomeAllowed, "r1")
	srv := &Server{Store: policy.NewStore(), Counters: c}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	body := readBody(resp)
	if !strings.Contains(body, `"allowed":1`) || !strings.Contains(body, `"rule":"r1"`) {
		t.Fatalf("stats body missing data: %s", body)
	}
}

func readBody(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// --- Dry-run endpoint ---------------------------------------------------

func newDryRunServer(t *testing.T, rulesJSON string) (*httptest.Server, *stats.Counters) {
	t.Helper()
	p, err := policy.Decode([]byte(rulesJSON))
	if err != nil {
		t.Fatalf("bad test policy: %v", err)
	}
	p.Version = "test-v1"
	store := policy.NewStore()
	store.Swap(p)
	c := stats.New()
	srv := &Server{
		Store:    store,
		Counters: c,
		Resolver: resolver.Map{
			"app.test":   []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			"other.test": []netip.Addr{netip.MustParseAddr("198.51.100.7")},
		},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, c
}

const dryRunRules = `{"rules":[
  {"id":"allow-app","action":"allow","domains":["app.test"]},
  {"id":"deny-net","action":"deny","cidrs":["203.0.113.0/24"]}
]}`

func dryRunGet(t *testing.T, ts *httptest.Server, query string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(ts.URL + "/dryrun?" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.StatusCode, body
}

// Business: dry-run allows what the policy allows and reports rule+version.
func TestDryRunEndpointAllow(t *testing.T) {
	ts, _ := newDryRunServer(t, dryRunRules)
	code, body := dryRunGet(t, ts, "host=app.test&port=443")
	if code != 200 {
		t.Fatalf("status=%d body=%v", code, body)
	}
	if body["allowed"] != true || body["winning_rule"] != "allow-app" {
		t.Fatalf("unexpected verdict: %v", body)
	}
	if body["version"] != "test-v1" {
		t.Fatalf("version=%v want test-v1", body["version"])
	}
}

// Business: assumed address inside a denied CIDR denies the whole query
// even though the name itself is allowed.
func TestDryRunEndpointAssumedIPDenied(t *testing.T) {
	ts, _ := newDryRunServer(t, dryRunRules)
	code, body := dryRunGet(t, ts, "host=app.test&port=443&ip=192.0.2.10&ip=203.0.113.5")
	if code != 200 {
		t.Fatalf("status=%d body=%v", code, body)
	}
	if body["allowed"] != false || body["winning_rule"] != "deny-net" {
		t.Fatalf("assumed denied address must deny: %v", body)
	}
}

// Business: no matching rule -> explicit default deny in the response.
func TestDryRunEndpointDefaultDeny(t *testing.T) {
	ts, _ := newDryRunServer(t, dryRunRules)
	code, body := dryRunGet(t, ts, "host=other.test&port=443")
	if code != 200 {
		t.Fatalf("status=%d", code)
	}
	if body["allowed"] != false || body["winning_rule"] != nil && body["winning_rule"] != "" {
		t.Fatalf("want default deny: %v", body)
	}
	if reason, _ := body["reason"].(string); !strings.Contains(reason, "default deny") {
		t.Fatalf("reason must state default deny: %v", body)
	}
}

// Business: malformed dry-run parameters are 400 errors, never an allow.
func TestDryRunEndpointBadParams(t *testing.T) {
	ts, c := newDryRunServer(t, dryRunRules)
	for _, q := range []string{
		"port=443",                            // missing host
		"host=app.test",                       // missing port
		"host=app.test&port=0",                // port out of range
		"host=app.test&port=65536",            // port out of range
		"host=app.test&port=abc",              // port not a number
		"host=app.test&port=443&ip=not-an-ip", // bad assumed address
		"host=bad%20host&port=443",            // illegal host characters
	} {
		code, body := dryRunGet(t, ts, q)
		if code != http.StatusBadRequest {
			t.Fatalf("query %q: want 400, got %d (%v)", q, code, body)
		}
		if body["error"] == nil || body["error"] == "" {
			t.Fatalf("query %q: error message required: %v", q, body)
		}
	}
	if snap := c.Snapshot(); snap.Total != 0 {
		t.Fatalf("invalid dry-runs must not be counted: %+v", snap)
	}
}

// Business: dry-runs never pollute forwarding statistics.
func TestDryRunEndpointNotCounted(t *testing.T) {
	ts, c := newDryRunServer(t, dryRunRules)
	for i := 0; i < 10; i++ {
		dryRunGet(t, ts, "host=app.test&port=443")
		dryRunGet(t, ts, "host=app.test&port=443&ip=203.0.113.5")
	}
	if snap := c.Snapshot(); snap.Total != 0 {
		t.Fatalf("dry-run counted as traffic: %+v", snap)
	}
}

// --- Windowed stats endpoint -------------------------------------------

// Business: ?window= returns a conserving window next to the unchanged
// cumulative fields; bad windows are 400.
func TestStatsWindowEndpoint(t *testing.T) {
	c := stats.New()
	c.Record(stats.OutcomeAllowed, "r1")
	c.Record(stats.OutcomeDeniedPolicy, "r2")
	srv := &Server{Store: policy.NewStore(), Counters: c}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/stats?window=5m")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body struct {
		Total  uint64            `json:"total"`
		Counts map[string]uint64 `json:"counts"`
		Window struct {
			Total  uint64            `json:"total"`
			Counts map[string]uint64 `json:"counts"`
			Rules  []struct {
				Rule string `json:"rule"`
				Hits uint64 `json:"hits"`
			} `json:"rules"`
		} `json:"window"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 || body.Counts["allowed"] != 1 {
		t.Fatalf("cumulative fields changed: %+v", body)
	}
	if body.Window.Total != 2 {
		t.Fatalf("window total=%d want 2", body.Window.Total)
	}
	var sum uint64
	for _, n := range body.Window.Counts {
		sum += n
	}
	if sum != body.Window.Total {
		t.Fatalf("window not conserving: %v vs %d", body.Window.Counts, body.Window.Total)
	}
	if len(body.Window.Rules) != 2 {
		t.Fatalf("window rules=%v", body.Window.Rules)
	}

	for _, q := range []string{"window=abc", "window=0s", "window=-5m", "window=2h"} {
		resp, err := http.Get(ts.URL + "/stats?" + q)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", q, resp.StatusCode)
		}
	}
}

// --- Reload history endpoint -------------------------------------------

// Business: /reloads reports time, result, failure kind and version for
// both success and failure, newest first; success versions match /version.
func TestReloadsEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore()
	if _, err := store.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	r := policy.NewReloader(store, path)
	srv := &Server{
		Store:         store,
		Counters:      stats.New(),
		Reload:        r.Reload,
		ReloadHistory: r.History,
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// One failure, then one success.
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"bad","action":"allow","cidrs":["0.0.0.0/0"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("broken policy reload: want 400, got %d", resp.StatusCode)
	}
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"v2","action":"allow","domains":["b.test"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err = http.Post(ts.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("valid reload failed: %d", resp.StatusCode)
	}

	resp, err = http.Get(ts.URL + "/reloads")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Reloads []struct {
			Time    string `json:"time"`
			Success bool   `json:"success"`
			Kind    string `json:"error_kind"`
			Version string `json:"version"`
		} `json:"reloads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Reloads) != 2 {
		t.Fatalf("records=%v", body.Reloads)
	}
	newest, older := body.Reloads[0], body.Reloads[1]
	if !newest.Success {
		t.Fatalf("newest record must be the success: %+v", newest)
	}
	if older.Success || older.Kind != "validation" {
		t.Fatalf("older record must be the validation failure: %+v", older)
	}
	if newest.Time == "" || older.Time == "" {
		t.Fatalf("timestamps required: %+v", body.Reloads)
	}
	// The successful version must match the currently active version.
	vresp, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer vresp.Body.Close()
	var vbody map[string]string
	if err := json.NewDecoder(vresp.Body).Decode(&vbody); err != nil {
		t.Fatal(err)
	}
	if newest.Version != vbody["version"] {
		t.Fatalf("success version %q != active version %q", newest.Version, vbody["version"])
	}
	if older.Version == "" {
		t.Fatal("failure record must still name the retained version")
	}
}

// Business: dense concurrent reloads through the admin endpoint — every
// trigger gets a definitive answer, the process keeps serving, and the
// final active version corresponds to a recorded success.
func TestConcurrentReloadsViaEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore()
	if _, err := store.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	r := policy.NewReloader(store, path)
	srv := &Server{Store: store, Counters: stats.New(), Reload: r.Reload, ReloadHistory: r.History}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const n = 40
	var wg sync.WaitGroup
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(ts.URL+"/reload", "application/json", nil)
			if err != nil {
				codes <- -1
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	ok := 0
	for code := range codes {
		if code != 200 {
			t.Fatalf("reload of a valid file must succeed, got %d", code)
		}
		ok++
	}
	if ok != n {
		t.Fatalf("only %d/%d reloads answered", ok, n)
	}

	hist := r.History(0)
	if len(hist) != n {
		t.Fatalf("history=%d want %d (one record per trigger)", len(hist), n)
	}
	cur, _ := store.Current()
	matched := false
	for _, rec := range hist {
		if rec.Version == cur.Version && rec.Success {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("active version %q matches no recorded success", cur.Version)
	}
}
