package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
)

// Both trigger paths (POST /reload and the SIGHUP-equivalent direct
// Reloader call) firing densely while the policy file changes: every
// trigger gets a definite result, nothing is lost, and at rest the active
// version, the newest successful history event and /version all agree.
func TestReloadDeterminismAcrossBothTriggerPaths(t *testing.T) {
	ts, store, _, rl, path := newFeatureServer(t,
		`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`)

	// Sequential determinism first: a successful POST's active_version is
	// exactly what GET /version reports right after.
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"v2","action":"allow","domains":["b.test"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var okBody map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&okBody)
	resp.Body.Close()
	if resp.StatusCode != 200 || okBody["reloaded"] != "true" {
		t.Fatalf("reload failed: %d %+v", resp.StatusCode, okBody)
	}
	vresp, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	var vbody map[string]string
	_ = json.NewDecoder(vresp.Body).Decode(&vbody)
	vresp.Body.Close()
	if okBody["active_version"] == "" || okBody["active_version"] != vbody["version"] {
		t.Fatalf("success returned %q but /version says %q", okBody["active_version"], vbody["version"])
	}

	// Concurrent storm across both paths with changing content.
	const httpWorkers, directWorkers, perWorker = 4, 4, 30
	var wg sync.WaitGroup
	for w := 0; w < httpWorkers+directWorkers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if (seed+i)%5 == 0 {
					_ = os.WriteFile(path, []byte(`{broken`), 0o600)
				} else {
					_ = os.WriteFile(path, []byte(fmt.Sprintf(
						`{"rules":[{"id":"r","action":"allow","domains":["s%dn%d.test"]}]}`, seed, i)), 0o600)
				}
				if seed < httpWorkers {
					resp, err := http.Post(ts.URL+"/reload", "application/json", nil)
					if err != nil {
						t.Errorf("reload request failed: %v", err)
						return
					}
					if resp.StatusCode != 200 && resp.StatusCode != 400 {
						t.Errorf("reload status=%d", resp.StatusCode)
					}
					resp.Body.Close()
				} else {
					// SIGHUP path: same serialized Reloader, no HTTP.
					_, _ = rl.Reload()
				}
			}
		}(w)
	}
	wg.Wait()

	triggers := (httpWorkers + directWorkers) * perWorker
	hist := rl.History(0)
	if len(hist) != triggers+2 { // priming + sequential + storm
		t.Fatalf("history=%d want %d: every trigger on both paths recorded", len(hist), triggers+2)
	}

	// Version lineage: current version == newest successful event, and the
	// /reload-history endpoint agrees.
	cur, ok := store.Current()
	if !ok {
		t.Fatal("no active policy after storm")
	}
	for _, ev := range hist {
		if ev.Result == "success" {
			if ev.Version != cur.Version {
				t.Fatalf("newest success %s != active %s", ev.Version, cur.Version)
			}
			break
		}
	}

	resp, err = http.Get(ts.URL + "/reload-history?limit=128")
	if err != nil {
		t.Fatal(err)
	}
	var hbody struct {
		CurrentVersion string `json:"current_version"`
		Events         []struct {
			Result  string `json:"result"`
			Version string `json:"version"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hbody); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hbody.CurrentVersion != cur.Version {
		t.Fatalf("endpoint current_version %s != store %s", hbody.CurrentVersion, cur.Version)
	}
	for _, ev := range hbody.Events {
		if ev.Result == "success" {
			if ev.Version != hbody.CurrentVersion {
				t.Fatalf("endpoint newest success %s != current %s", ev.Version, hbody.CurrentVersion)
			}
			break
		}
	}
}
