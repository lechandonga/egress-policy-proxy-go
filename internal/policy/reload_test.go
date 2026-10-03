package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writePolicy(t *testing.T, path, doc string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func allowDoc(id string) string {
	return fmt.Sprintf(`{"rules":[{"id":%q,"action":"allow","domains":["%s.test"]}]}`, id, id)
}

// Business: dense sequential reloads — every trigger is processed and
// recorded; successes swap the version, failures keep the old one.
func TestReloaderSequentialBurst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, allowDoc("v1"))

	store := NewStore()
	if _, err := store.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	r := NewReloader(store, path)

	const n = 30
	for i := 0; i < n; i++ {
		writePolicy(t, path, allowDoc(fmt.Sprintf("v%d", i+2)))
		if _, err := r.Reload(); err != nil {
			t.Fatalf("reload %d failed: %v", i, err)
		}
	}
	// Failures interleave: broken file keeps the last good version.
	good, _ := store.Current()
	writePolicy(t, path, `{"rules":[{"id":"x","action":"allow","cidrs":["0.0.0.0/0"]}]}`)
	if _, err := r.Reload(); err == nil {
		t.Fatal("invalid policy must fail the reload")
	} else if !IsLoadError(err) {
		t.Fatalf("want validation error, got %v", err)
	}
	cur, _ := store.Current()
	if cur.Version != good.Version {
		t.Fatalf("failed reload changed active version: %q -> %q", good.Version, cur.Version)
	}

	hist := r.History(0)
	if len(hist) != n+1 {
		t.Fatalf("history has %d records, want %d (one per trigger)", len(hist), n+1)
	}
	if hist[0].Success || hist[0].Kind != "validation" {
		t.Fatalf("newest record should be the validation failure: %+v", hist[0])
	}
	if hist[0].Version != good.Version {
		t.Fatalf("failure record version %q, want retained %q", hist[0].Version, good.Version)
	}
	if !hist[1].Success || hist[1].Version != good.Version {
		t.Fatalf("last success must name the active version: %+v", hist[1])
	}
}

// Business: concurrent triggers never lose a record, never corrupt the
// store, and the final active version corresponds to one recorded success.
func TestReloaderConcurrentDeterministic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, allowDoc("v1"))

	store := NewStore()
	if _, err := store.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	r := NewReloader(store, path)

	const triggers = 64
	var wg sync.WaitGroup
	errs := make(chan error, triggers)
	for i := 0; i < triggers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Half the triggers write a distinct valid policy first; all
			// of them must get a definitive result.
			if id%2 == 0 {
				// Deploys replace the policy atomically (write+rename);
				// mirror that so a reload never reads a half-written file.
				tmp := filepath.Join(dir, fmt.Sprintf("tmp-%d.json", id))
				if err := os.WriteFile(tmp, []byte(allowDoc(fmt.Sprintf("w%d", id))), 0o600); err == nil {
					_ = os.Rename(tmp, path)
				}
			}
			_, err := r.Reload()
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("reload of a valid file must succeed: %v", err)
		}
	}

	hist := r.History(0)
	if len(hist) != triggers {
		t.Fatalf("history=%d want exactly %d records", len(hist), triggers)
	}
	cur, ok := store.Current()
	if !ok {
		t.Fatal("no active policy after reloads")
	}
	matched := false
	for _, rec := range hist {
		if !rec.Success {
			t.Fatalf("unexpected failed record: %+v", rec)
		}
		if rec.Version == cur.Version {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("active version %q matches no recorded success", cur.Version)
	}
}

// Business: history is capped so reload-happy deploys cannot grow memory.
func TestReloaderHistoryCapped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, allowDoc("v1"))
	store := NewStore()
	if _, err := store.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	r := NewReloader(store, path)
	for i := 0; i < historyCap+50; i++ {
		if _, err := r.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(r.History(0)); got != historyCap {
		t.Fatalf("history len=%d want cap %d", got, historyCap)
	}
	if got := len(r.History(5)); got != 5 {
		t.Fatalf("limited history len=%d want 5", got)
	}
}
