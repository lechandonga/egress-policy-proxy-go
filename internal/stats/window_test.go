package stats

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowConservation(t *testing.T) {
	c := New()
	c.Record(OutcomeAllowed, "r1")
	c.Record(OutcomeAllowed, "r2")
	c.Record(OutcomeDeniedPolicy, "r3")
	c.Record(OutcomeDeniedPolicy, "r2")
	c.Record(OutcomeResolveFailed, "")
	c.Record(OutcomeUpstreamDial, "")
	c.Record(OutcomeClientError, "")

	win, err := c.Window(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if win.Total != 7 {
		t.Fatalf("window total=%d want 7", win.Total)
	}
	var sum uint64
	for _, n := range win.Counts {
		sum += n
	}
	if sum != win.Total {
		t.Fatalf("category sum %d != total %d", sum, win.Total)
	}
	if win.Counts["allowed"] != 2 || win.Counts["denied_policy"] != 2 {
		t.Fatalf("window counts wrong: %+v", win.Counts)
	}
	var hits uint64
	for _, rs := range win.Rules {
		hits += rs.Hits
		var sub uint64 = rs.Allowed + rs.Denied
		if sub != rs.Hits {
			t.Fatalf("rule %s splits %d != hits %d", rs.Rule, sub, rs.Hits)
		}
	}
	if hits != 4 {
		t.Fatalf("window rule hits=%d want 4", hits)
	}

	// Cumulative counters are unaffected by window queries.
	cum := c.Snapshot()
	if cum.Total != 7 {
		t.Fatalf("cumulative total changed: %d", cum.Total)
	}
}

func TestWindowBoundsAndExclusions(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New()
	c.SetClock(func() time.Time { return now })

	c.Record(OutcomeAllowed, "old")
	now = now.Add(10 * time.Second)
	c.Record(OutcomeDeniedPolicy, "new")
	c.Record(OutcomeDeniedPolicy, "new")

	win, err := c.Window(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if win.Total != 2 {
		t.Fatalf("window must exclude the old event, got %d", win.Total)
	}
	for _, rs := range win.Rules {
		if rs.Rule == "old" {
			t.Fatal("old rule must not appear in window")
		}
	}

	if _, err := c.Window(0); err == nil {
		t.Fatal("zero window must error")
	}
	if _, err := c.Window(-time.Second); err == nil {
		t.Fatal("negative window must error")
	}
	if _, err := c.Window(MaxWindow + time.Second); err == nil {
		t.Fatal("oversized window must error, not be truncated")
	}
	if _, err := c.Window(MaxWindow); err != nil {
		t.Fatalf("exact MaxWindow must be allowed: %v", err)
	}
}

// Long-running traffic + frequent, concurrent window queries: no failures,
// every snapshot self-consistent, and retained bucket count stays bounded.
func TestWindowConcurrentTrafficAndQueriesBoundedMemory(t *testing.T) {
	c := New()

	var records atomic.Uint64
	var recWG sync.WaitGroup
	stop := make(chan struct{})
	var queryWG sync.WaitGroup

	for w := 0; w < 8; w++ {
		recWG.Add(1)
		go func(id int) {
			defer recWG.Done()
			rules := []string{"a", "b", "c", ""}
			outs := []Outcome{OutcomeAllowed, OutcomeDeniedPolicy, OutcomeResolveFailed, OutcomeClientError}
			for i := 0; i < 4000; i++ {
				c.Record(outs[(i+id)%len(outs)], rules[(i+id)%len(rules)])
				records.Add(1)
			}
		}(w)
	}
	for w := 0; w < 4; w++ {
		queryWG.Add(1)
		go func() {
			defer queryWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				win, err := c.Window(time.Second)
				if err != nil {
					t.Errorf("window query failed: %v", err)
					return
				}
				var sum uint64
				for _, n := range win.Counts {
					sum += n
				}
				if sum != win.Total {
					t.Errorf("inconsistent snapshot: %d != %d", sum, win.Total)
					return
				}
			}
		}()
	}

	recWG.Wait()
	close(stop)
	queryWG.Wait()

	if got := c.Snapshot().Total; got != records.Load() {
		t.Fatalf("cumulative total=%d records=%d", got, records.Load())
	}

	// Ring size is fixed regardless of event volume.
	if len(c.win.ring.buckets) != ringBuckets {
		t.Fatalf("ring grew beyond fixed size: %d", len(c.win.ring.buckets))
	}
	live := 0
	for i := range c.win.ring.buckets {
		if c.win.ring.buckets[i].sec != 0 {
			live++
		}
	}
	if live > ringBuckets {
		t.Fatalf("live buckets exceed cap: %d", live)
	}
}
