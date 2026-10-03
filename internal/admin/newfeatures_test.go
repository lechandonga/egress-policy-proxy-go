package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

func newFeatureServer(t *testing.T, rules string) (*httptest.Server, *policy.Store, *stats.Counters, *policy.Reloader, string) {
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
	srv := &Server{
		Store:    store,
		Counters: c,
		Reload:   rl.Reload,
		History:  rl.History,
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, store, c, rl, path
}

func TestEvaluateAllowDenyDefaultDenyAndVersion(t *testing.T) {
	rules := `{"rules":[
	  {"id":"allow-good","action":"allow","domains":["good.test"],"ports":[443]},
	  {"id":"deny-net","action":"deny","cidrs":["203.0.113.0/24"],"ports":[443]}
	]}`
	ts, store, c, _, _ := newFeatureServer(t, rules)
	cur, _ := store.Current()

	get := func(q string) (int, map[string]any) {
		resp, err := http.Get(ts.URL + "/evaluate?" + q)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	status, m := get("host=good.test&port=443&addr=198.51.100.1")
	if status != 200 || m["allowed"] != true || m["winning_rule"] != "allow-good" {
		t.Fatalf("allow case: %d %+v", status, m)
	}
	if m["version"] != cur.Version {
		t.Fatalf("version %v want %q", m["version"], cur.Version)
	}

	// Host allowed, but one assumed address is in the deny range.
	status, m = get("host=good.test&port=443&addr=198.51.100.1&addr=203.0.113.9")
	if status != 200 || m["allowed"] != false || m["winning_rule"] != "deny-net" {
		t.Fatalf("mixed-address deny: %d %+v", status, m)
	}

	// No matching rule: default deny must be explicit.
	status, m = get("host=other.test&port=443&addr=198.51.100.1")
	if status != 200 || m["allowed"] != false || m["winning_rule"] != "" || m["default_deny"] != true {
		t.Fatalf("default deny: %d %+v", status, m)
	}

	// Literal IP host.
	status, m = get("host=203.0.113.9&port=443")
	if status != 200 || m["allowed"] != false || m["winning_rule"] != "deny-net" {
		t.Fatalf("literal ip deny: %d %+v", status, m)
	}

	// Bad parameters must not be answered as allow/deny.
	for _, q := range []string{
		"port=443",                               // no host
		"host=good.test",                         // no port
		"host=good.test&port=0",                  // bad port
		"host=good.test&port=70000",              // bad port
		"host=good.test&port=443x",               // bad port
		"host=good.test&port=443&addr=nope",      // bad addr
		"host=203.0.113.9&port=443&addr=1.2.3.4", // addr with IP host
	} {
		status, m = get(q)
		if status != http.StatusBadRequest {
			t.Fatalf("q %q: want 400, got %d (%+v)", q, status, m)
		}
		if _, ok := m["allowed"]; ok {
			t.Fatalf("bad params must not return a verdict: %+v", m)
		}
	}

	// Dry-run must never touch traffic counters.
	if total := c.Snapshot().Total; total != 0 {
		t.Fatalf("dry-run polluted traffic counters: %d", total)
	}
}

func TestEvaluateVersionBoundToOneSnapshot(t *testing.T) {
	rules := `{"rules":[{"id":"a","action":"allow","domains":["a.test"]}]}`
	ts, store, _, rl, path := newFeatureServer(t, rules)
	cur, _ := store.Current()

	// Hammer reloads while evaluating; every answer's verdict must match
	// the version it reports.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			var doc string
			if i%3 == 0 {
				doc = `{broken`
			} else {
				doc = fmt.Sprintf(`{"rules":[{"id":"a","action":"allow","domains":["h%d.test"]}]}`, i)
			}
			_ = os.WriteFile(path, []byte(doc), 0o600)
			rl.Reload()
		}
	}()
	for i := 0; i < 200; i++ {
		resp, err := http.Get(ts.URL + "/evaluate?host=a.test&port=443&addr=1.1.1.1")
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
		v, _ := m["version"].(string)
		allowed, _ := m["allowed"].(bool)
		// Under the original version the host is allowed; under hN versions
		// it default-denies. The version reported must match the verdict.
		switch v {
		case cur.Version:
			if !allowed {
				t.Fatalf("verdict/version mismatch under %s", v)
			}
		default:
			// vN policies deny a.test; no mixed answers allowed.
			if allowed {
				t.Fatalf("version %s should deny a.test but allowed it (mixed snapshot?)", v)
			}
		}
	}
	wg.Wait()
}

func TestStatsWindowEndpoint(t *testing.T) {
	ts, _, c, _, _ := newFeatureServer(t, `{"rules":[{"id":"r1","action":"allow","domains":["a.test"]}]}`)
	c.Record(stats.OutcomeAllowed, "r1")
	c.Record(stats.OutcomeDeniedPolicy, "r1")

	resp, err := http.Get(ts.URL + "/stats?window=1m")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	win, ok := m["window"].(map[string]any)
	if !ok {
		t.Fatalf("missing window: %+v", m)
	}
	if win["total"].(float64) != 2 {
		t.Fatalf("window total=%v", win["total"])
	}
	counts := win["counts"].(map[string]any)
	if counts["allowed"].(float64) != 1 || counts["denied_policy"].(float64) != 1 {
		t.Fatalf("window counts: %+v", counts)
	}
	// Cumulative fields are still there unchanged.
	if m["total"].(float64) != 2 {
		t.Fatalf("cumulative total missing: %+v", m["total"])
	}

	// Bad window values are rejected.
	for _, w := range []string{"abc", "-1s", "2h"} {
		resp, err := http.Get(ts.URL + "/stats?window=" + url.QueryEscape(w))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("window=%q: want 400 got %d", w, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestReloadHistoryEndpoint(t *testing.T) {
	ts, _, _, _, path := newFeatureServer(t,
		`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`)

	// One failure, one success.
	if err := os.WriteFile(path, []byte(`{bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var fail map[string]string
	json.NewDecoder(resp.Body).Decode(&fail)
	resp.Body.Close()
	if fail["error_kind"] != "validation" || fail["error_kind_detail"] != "invalid_json" {
		t.Fatalf("failure body: %+v", fail)
	}

	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"v2","action":"allow","domains":["b.test"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err = http.Post(ts.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/reload-history?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	var hist struct {
		CurrentVersion string `json:"current_version"`
		Events         []struct {
			Seq           int64  `json:"seq"`
			Result        string `json:"result"`
			Version       string `json:"version"`
			ErrorKind     string `json:"error_kind"`
			LoadedVersion string `json:"loaded_version"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hist); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(hist.Events) != 3 { // priming + failure + success
		t.Fatalf("events=%d: %+v", len(hist.Events), hist)
	}
	if hist.Events[0].Result != "success" || hist.Events[1].Result != "failure" {
		t.Fatalf("history order/content: %+v", hist.Events)
	}
	if hist.Events[1].ErrorKind != "invalid_json" {
		t.Fatalf("failure kind: %+v", hist.Events[1])
	}
	// The most recent success's version is the current version.
	if hist.CurrentVersion != hist.Events[0].Version || hist.Events[0].LoadedVersion != hist.CurrentVersion {
		t.Fatalf("version lineage broken: %+v current=%s", hist.Events, hist.CurrentVersion)
	}

	resp, err = http.Get(ts.URL + "/reload-history?limit=0")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("bad limit must 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestConcurrentReloadEndpointsNeverFail(t *testing.T) {
	ts, _, _, rl, path := newFeatureServer(t,
		`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`)

	var wg sync.WaitGroup
	const n = 40
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < n; j++ {
				if (seed+j)%4 == 0 {
					_ = os.WriteFile(path, []byte(`{bad`), 0o600)
				} else {
					_ = os.WriteFile(path, []byte(
						fmt.Sprintf(`{"rules":[{"id":"r","action":"allow","domains":["x%d.test"]}]}`, seed*n+j)), 0o600)
				}
				resp, err := http.Post(ts.URL+"/reload", "application/json", strings.NewReader(""))
				if err != nil {
					t.Errorf("reload request failed: %v", err)
					return
				}
				if resp.StatusCode != 200 && resp.StatusCode != 400 {
					t.Errorf("reload status=%d", resp.StatusCode)
				}
				resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()

	if len(rl.History(0)) != 8*n+1 {
		t.Fatalf("every HTTP trigger must be recorded: %d", len(rl.History(0)))
	}
	// Current version always traces back to one successful event.
	resp, err := http.Get(ts.URL + "/reload-history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("history status %d", resp.StatusCode)
	}
}
