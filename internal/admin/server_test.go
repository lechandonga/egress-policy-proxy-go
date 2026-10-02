package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
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
