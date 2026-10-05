package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writePolicy(t *testing.T, path, dom string) {
	t.Helper()
	doc := fmt.Sprintf(`{"rules":[{"id":"r","action":"allow","domains":["%s"]}]}`, dom)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloaderEveryTriggerHasAResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, "a.test")

	store := NewStore()
	rl := NewReloader(store, path)
	if _, err := rl.Reload(); err != nil {
		t.Fatal(err)
	}
	activeVersion, _ := store.Current()
	activeVer := activeVersion.Version

	// 50 dense sequential triggers, mixing valid and invalid contents.
	const n = 50
	var successes, failures int
	for i := 0; i < n; i++ {
		if i%7 == 0 {
			if err := os.WriteFile(path, []byte(`{broken`), 0o600); err != nil {
				t.Fatal(err)
			}
		} else {
			writePolicy(t, path, fmt.Sprintf("h%d.test", i))
		}
		p, err := rl.Reload()
		if err != nil {
			failures++
			if ErrorKindOf(err) != KindInvalidJSON {
				t.Fatalf("trigger %d: want invalid_json, got %s", i, ErrorKindOf(err))
			}
			cur, ok := store.Current()
			if !ok {
				t.Fatalf("trigger %d: failure must leave a policy active", i)
			}
			if cur.Version != activeVer {
				t.Fatalf("trigger %d: failure changed active version", i)
			}
		} else {
			successes++
			activeVer = p.Version
			if cur, _ := store.Current(); cur.Version != p.Version {
				t.Fatalf("trigger %d: success reported %s but active is %s", i, p.Version, cur.Version)
			}
		}
	}
	if successes+failures != n {
		t.Fatalf("counted %d results, want %d", successes+failures, n)
	}
	hist := rl.History(0)
	if len(hist) != n+1 { // +1 for the priming reload
		t.Fatalf("history len=%d want %d (every trigger recorded)", len(hist), n+1)
	}
	// History is newest-first with monotonic seq.
	for i, ev := range hist {
		if ev.Seq != int64(n+1-i) {
			t.Fatalf("history not ordered: pos %d seq %d", i, ev.Seq)
		}
	}
	// Last successful event's version is the active version.
	var lastSuccess string
	for _, ev := range hist {
		if ev.Result == ReloadSuccess {
			lastSuccess = ev.Version
			break
		}
	}
	cur, _ := store.Current()
	if lastSuccess != cur.Version {
		t.Fatalf("active %s != last successful reload %s", cur.Version, lastSuccess)
	}
}

func TestReloaderConcurrentTriggersDeterministic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, "a.test")

	store := NewStore()
	rl := NewReloader(store, path)
	if _, err := rl.Reload(); err != nil {
		t.Fatal(err)
	}

	const workers, perWorker = 12, 25
	var wg sync.WaitGroup
	var successCount, failureCount atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				p, err := rl.Reload()
				if err != nil {
					failureCount.Add(1)
				} else {
					successCount.Add(1)
					cur, _ := store.Current()
					if cur.Version != p.Version {
						t.Errorf("caller saw success %s but active is %s", p.Version, cur.Version)
					}
				}
			}
		}()
	}
	wg.Wait()

	total := int64(workers*perWorker + 1)
	hist := rl.History(0)
	if int64(len(hist)) != total {
		t.Fatalf("history %d want %d: no trigger may be lost", len(hist), total)
	}
	if successCount.Load()+failureCount.Load() != workers*perWorker {
		t.Fatalf("results=%d want %d", successCount.Load()+failureCount.Load(), workers*perWorker)
	}
	// The active version must correspond to one specific successful event.
	cur, _ := store.Current()
	found := false
	for _, ev := range hist {
		if ev.Result == ReloadSuccess && ev.Version == cur.Version {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("active version %s corresponds to no recorded success", cur.Version)
	}
	// Sequential seqs, no duplicates/gaps.
	for i := range hist {
		if hist[i].Seq != total-int64(i) {
			t.Fatalf("seq gap at %d: %d", i, hist[i].Seq)
		}
	}
}

// Concurrent triggers WHILE the policy file keeps changing: every trigger
// gets a definite result, and at rest the active version is exactly the
// version of the newest successful history event — a stale snapshot can
// never be installed after a newer one completed.
func TestReloaderConcurrentTriggersWithChangingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, "a.test")

	store := NewStore()
	rl := NewReloader(store, path)
	if _, err := rl.Reload(); err != nil {
		t.Fatal(err)
	}

	// A wide policy document makes each load take measurable time, which is
	// what exposes unsynchronized load/swap interleavings under contention.
	writeWide := func(tag string) {
		var b strings.Builder
		b.WriteString(`{"rules":[`)
		for i := 0; i < 400; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"%s-%d","action":"allow","domains":["%s-%d.test"]}`, tag, i, tag, i)
		}
		b.WriteString(`]}`)
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			t.Errorf("write policy: %v", err)
		}
	}

	const workers, perWorker = 16, 25
	var wg sync.WaitGroup
	var successes, failures atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if (seed+i)%6 == 0 {
					_ = os.WriteFile(path, []byte(`{broken`), 0o600)
				} else {
					writeWide(fmt.Sprintf("w%dn%d", seed, i))
				}
				p, err := rl.Reload()
				if err != nil {
					failures.Add(1)
					continue
				}
				successes.Add(1)
				// The returned policy must be a fully compiled snapshot.
				if p == nil || p.Version == "" || len(p.Rules) == 0 {
					t.Errorf("success returned an unusable policy: %+v", p)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	total := int64(workers*perWorker + 1)
	hist := rl.History(0)
	if int64(len(hist)) != total {
		t.Fatalf("history %d want %d: no trigger may be lost", len(hist), total)
	}
	if successes.Load()+failures.Load() != workers*perWorker {
		t.Fatalf("results=%d want %d", successes.Load()+failures.Load(), workers*perWorker)
	}
	for i := range hist {
		if hist[i].Seq != total-int64(i) {
			t.Fatalf("seq gap at %d: %d", i, hist[i].Seq)
		}
		if hist[i].Result == ReloadSuccess && hist[i].Version != hist[i].LoadedVersion {
			t.Fatalf("success event %d: version %q != loaded %q", hist[i].Seq, hist[i].Version, hist[i].LoadedVersion)
		}
	}

	// The determinism contract: the newest successful event names the
	// currently active version.
	cur, ok := store.Current()
	if !ok {
		t.Fatal("no active policy after reload storm")
	}
	for _, ev := range hist {
		if ev.Result == ReloadSuccess {
			if ev.Version != cur.Version {
				t.Fatalf("newest success %s != active %s", ev.Version, cur.Version)
			}
			break
		}
	}
}

// Deterministic serialization proof: while one trigger is mid-reload
// (inside the afterLoad hook, lock held), a second trigger cannot complete;
// once released, both complete in trigger order and each success's version
// is the active version at its own completion.
func TestReloaderTriggersAreFullySerialized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, "one.test")

	store := NewStore()
	rl := NewReloader(store, path)
	p1, err := rl.Reload()
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var hookCalls atomic.Int64
	rl.afterLoad = func() {
		if hookCalls.Add(1) == 1 {
			close(entered)
			<-release // hold the reload lock: nothing else may proceed
		}
	}

	writePolicy(t, path, "two.test")
	type outcome struct {
		p   *Policy
		err error
	}
	first := make(chan outcome, 1)
	go func() {
		p, err := rl.Reload()
		first <- outcome{p, err}
	}()
	<-entered // first reload is now mid-flight, holding the lock

	writePolicy(t, path, "three.test")
	second := make(chan outcome, 1)
	go func() {
		p, err := rl.Reload()
		second <- outcome{p, err}
	}()

	// The second trigger must not complete while the first is mid-reload.
	select {
	case o := <-second:
		t.Fatalf("second reload completed concurrently: %+v", o)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	o1 := <-first
	if o1.err != nil {
		t.Fatal(o1.err)
	}
	if cur, _ := store.Current(); cur.Version != o1.p.Version {
		t.Fatalf("first success %s not active at completion (active %s)", o1.p.Version, cur.Version)
	}
	o2 := <-second
	if o2.err != nil {
		t.Fatal(o2.err)
	}
	if cur, _ := store.Current(); cur.Version != o2.p.Version {
		t.Fatalf("second success %s not active at completion (active %s)", o2.p.Version, cur.Version)
	}
	if o1.p.Version == p1.Version || o2.p.Version == o1.p.Version {
		t.Fatalf("expected three distinct versions: %s %s %s", p1.Version, o1.p.Version, o2.p.Version)
	}

	// Newest successful history event names the active version.
	hist := rl.History(0)
	if len(hist) != 3 || hist[0].Result != ReloadSuccess || hist[0].Version != o2.p.Version {
		t.Fatalf("history lineage broken: %+v", hist)
	}
}

func TestReloaderHistoryBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, "a.test")
	rl := NewReloader(NewStore(), path)
	for i := 0; i < maxHistoryEntries+30; i++ {
		writePolicy(t, path, fmt.Sprintf("h%d.test", i))
		if _, err := rl.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(rl.History(0)); got != maxHistoryEntries {
		t.Fatalf("history must be bounded, got %d", got)
	}
	if got := len(rl.History(5)); got != 5 {
		t.Fatalf("limit not honored: %d", got)
	}
}

func TestReloaderFailureKeepsOldPolicyIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePolicy(t, path, "first.test")
	store := NewStore()
	rl := NewReloader(store, path)
	p1, err := rl.Reload()
	if err != nil {
		t.Fatal(err)
	}

	// One invalid file per validation category: old policy survives all.
	bad := []string{
		`{"rules":[{"id":"r","action":"allow","ports":[99999]}]}`,
		`{"rules":[{"id":"r","action":"allow","cidrs":["1.2.3.4/99"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a..b"]}]}`,
		`{not json`,
	}
	for i, doc := range bad {
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := rl.Reload(); err == nil {
			t.Fatalf("bad doc #%d must fail", i)
		}
		cur, ok := store.Current()
		if !ok || cur != p1 {
			t.Fatalf("bad doc #%d replaced the active policy", i)
		}
		d := cur.Evaluate(Match{Host: "first.test", IP: addr("1.1.1.1"), Port: 80})
		if !d.Allowed {
			t.Fatalf("old policy semantics changed after failed reload #%d", i)
		}
	}
}
