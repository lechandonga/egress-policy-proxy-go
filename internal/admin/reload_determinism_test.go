package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// postReload drives one HTTP reload and returns (status, activeVersion in
// response, loaded flag).
func postReload(t *testing.T, ts string) (int, string) {
	t.Helper()
	resp, err := http.Post(ts+"/reload", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("reload transport failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m struct {
		ActiveVersion string `json:"active_version"`
	}
	_ = json.Unmarshal(body, &m)
	return resp.StatusCode, m.ActiveVersion
}

// TestReloadDeterminismSequential covers both trigger paths (HTTP handler
// and the reloader directly) back to back: every success's reported
// version is already active at return time, every failure keeps the old
// version, and the history's latest successful event always owns the
// current version — even when the file changes while triggers are
// landing.
func TestReloadDeterminismSequential(t *testing.T) {
	t.Run("http path", func(t *testing.T) {
		ts, _, _, rl, path := newFeatureServer(t,
			`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`)

		assertLineage := func(stage string) {
			t.Helper()
			cur, _ := rl.Store().Current()
			hist := rl.History(0)
			var latestSuccess string
			for _, ev := range hist {
				if ev.Result == "success" {
					latestSuccess = ev.Version
					break
				}
			}
			if latestSuccess != cur.Version {
				t.Fatalf("%s: latest success %s != active %s", stage, latestSuccess, cur.Version)
			}
		}

		for i := 0; i < 60; i++ {
			var doc string
			switch i % 5 {
			case 0:
				doc = `{broken json`
			default:
				doc = fmt.Sprintf(`{"rules":[{"id":"r","action":"allow","domains":["h%d.test"]}]}`, i)
			}
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			before, _ := rl.Store().Current()
			status, reported := postReload(t, ts.URL)
			cur, _ := rl.Store().Current()
			if doc == `{broken json` {
				if status != http.StatusBadRequest {
					t.Fatalf("trigger %d: want 400 got %d", i, status)
				}
				if cur.Version != before.Version {
					t.Fatalf("trigger %d: failure changed version %s -> %s", i, before.Version, cur.Version)
				}
			} else {
				if status != http.StatusOK {
					t.Fatalf("trigger %d: want 200 got %d", i, status)
				}
				if reported != cur.Version {
					t.Fatalf("trigger %d: success reported %s but active is %s", i, reported, cur.Version)
				}
			}
			assertLineage(fmt.Sprintf("trigger %d", i))
		}
	})

	t.Run("direct reloader path (signal)", func(t *testing.T) {
		// The SIGHUP path in main calls reloader.Reload directly; exercise
		// that same call to prove determinism independent of HTTP.
		ts, _, _, rl, path := newFeatureServer(t,
			`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`)
		_ = ts
		for i := 0; i < 60; i++ {
			if i%4 == 0 {
				_ = os.WriteFile(path, []byte(`{bad`), 0o600)
			} else {
				_ = os.WriteFile(path, []byte(
					fmt.Sprintf(`{"rules":[{"id":"s","action":"allow","domains":["s%d.test"]}]}`, i)), 0o600)
			}
			before, _ := rl.Store().Current()
			p, err := rl.Reload()
			cur, _ := rl.Store().Current()
			if err != nil {
				if cur.Version != before.Version {
					t.Fatalf("trigger %d: failure changed version", i)
				}
			} else {
				if p.Version != cur.Version {
					t.Fatalf("trigger %d: caller got %s active is %s", i, p.Version, cur.Version)
				}
			}
		}
		cur, _ := rl.Store().Current()
		for _, ev := range rl.History(0) {
			if ev.Result == "success" {
				if ev.Version != cur.Version {
					t.Fatalf("latest success %s != active %s", ev.Version, cur.Version)
				}
				break
			}
		}
	})
}

// TestReloadDeterminismConcurrentFileChurn hammers BOTH trigger paths at
// once while a third goroutine keeps rewriting the policy file (content may
// therefore change while a reload is in flight). Every trigger gets one
// definite, recorded result; every reported success is already active; the
// final active version traces to the latest successful event; serving never
// stops and no trigger is lost.
func TestReloadDeterminismConcurrentFileChurn(t *testing.T) {
	ts, _, _, rl, path := newFeatureServer(t,
		`{"rules":[{"id":"v1","action":"allow","domains":["a.test"]}]}`)

	const writers, httpWorkers, signalWorkers, perWorker = 2, 6, 6, 30
	var wg sync.WaitGroup
	var triggerCount atomic.Int64
	stop := make(chan struct{})

	// Every successful response reports a version captured inside the
	// reloader's serialized section at the instant it installed the
	// snapshot. After the storm we correlate each reported version with the
	// history event recorded under the same lock: each one must exist as a
	// success, and the latest one must own the active snapshot. Checking
	// Store.Current() directly after each concurrent return would itself
	// race with the next serialized trigger completing.
	var reportedMu sync.Mutex
	reportedSuccess := map[string]int{}
	recordSuccess := func(reported string) {
		reportedMu.Lock()
		reportedSuccess[reported]++
		reportedMu.Unlock()
	}

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < httpWorkers*perWorker; i++ {
				select {
				case <-stop:
					return
				default:
				}
				doc := fmt.Sprintf(`{"rules":[{"id":"c","action":"allow","domains":["w%d-%d.test"]}]}`, id, i)
				if i%9 == 0 {
					doc = `{broken`
				}
				_ = os.WriteFile(path, []byte(doc), 0o600)
			}
		}(w)
	}

	for w := 0; w < httpWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				status, reported := postReload(t, ts.URL)
				if status != http.StatusOK && status != http.StatusBadRequest {
					t.Errorf("unexpected reload status %d", status)
					return
				}
				triggerCount.Add(1)
				if status == http.StatusOK {
					recordSuccess(reported)
				}
			}
		}()
	}
	for w := 0; w < signalWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				p, err := rl.Reload()
				if err == nil {
					triggerCount.Add(1)
					recordSuccess(p.Version)
				} else {
					triggerCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()
	close(stop)

	// Every one of the (httpWorkers+signalWorkers)*perWorker triggers plus
	// the priming reload must be present in history: no trigger lost.
	wantTriggers := int64((httpWorkers+signalWorkers)*perWorker) + 1
	if got := int64(len(rl.History(0))); got != wantTriggers {
		t.Fatalf("history %d want %d", got, wantTriggers)
	}
	if triggerCount.Load() != wantTriggers-1 {
		t.Fatalf("observed results %d want %d", triggerCount.Load(), wantTriggers-1)
	}

	// Latest successful event must match the current active version.
	cur, _ := rl.Store().Current()
	if cur == nil {
		t.Fatal("no active policy after storm")
	}
	hist := rl.History(0)
	histSuccess := map[string]int{}
	var latestSuccess string
	for _, ev := range hist {
		if ev.Result == "success" {
			histSuccess[ev.Version]++
			if latestSuccess == "" {
				latestSuccess = ev.Version
			}
		}
	}
	if latestSuccess != cur.Version {
		t.Fatalf("latest success %s != active %s", latestSuccess, cur.Version)
	}
	// Each version reported as a success must be a recorded success event,
	// proving the response came from the serialized install section.
	for v, n := range reportedSuccess {
		if histSuccess[v] < n {
			t.Fatalf("reported success %s x%d but history has %d matching events", v, n, histSuccess[v])
		}
	}

	// With all trigger goroutines finished and no more file writers, a
	// successful reload's returned version must be the active version
	// immediately at return (linearizability without concurrent movers).
	_ = os.WriteFile(path, []byte(`{"rules":[{"id":"final","action":"allow","domains":["final.test"]}]}`), 0o600)
	finalPolicy, ferr := rl.Reload()
	if ferr != nil {
		t.Fatal(ferr)
	}
	activeNow, _ := rl.Store().Current()
	if finalPolicy.Version != activeNow.Version {
		t.Fatalf("post-storm success returned %s but active is %s", finalPolicy.Version, activeNow.Version)
	}

	// Service is still answering normally.
	resp, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatalf("admin stopped serving: %v", err)
	}
	var vm map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&vm)
	resp.Body.Close()
	if resp.StatusCode != 200 || vm["version"] != activeNow.Version {
		t.Fatalf("version endpoint %d %+v want %s", resp.StatusCode, vm, activeNow.Version)
	}
}
