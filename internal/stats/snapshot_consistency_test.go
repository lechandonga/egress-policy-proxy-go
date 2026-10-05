package stats

import (
	"sync"
	"testing"
	"time"
)

// Concurrent recording + cumulative/window snapshots: every snapshot must
// be a self-consistent point-in-time view (category sum == total) and no
// query may ever fail or panic, no matter the recording rate.
func TestSnapshotConsistentUnderConcurrentLoad(t *testing.T) {
	c := New()

	const recorders, snapshots = 8, 4
	const perRecorder = 20000

	var wg sync.WaitGroup
	for i := 0; i < recorders; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for n := 0; n < perRecorder; n++ {
				o := outcomes[(seed+n)%len(outcomes)]
				c.Record(o, "rule-x")
			}
		}(i)
	}

	stop := make(chan struct{})
	var swg sync.WaitGroup
	for i := 0; i < snapshots; i++ {
		swg.Add(1)
		go func(seed int) {
			defer swg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap := c.Snapshot()
				var sum uint64
				for _, n := range snap.Counts {
					sum += n
				}
				if sum != snap.Total {
					t.Errorf("cumulative snapshot inconsistent: sum=%d total=%d", sum, snap.Total)
					return
				}
				var ruleHits uint64
				for _, rs := range snap.Rules {
					ruleHits += rs.Hits
					if rs.Allowed+rs.Denied > rs.Hits {
						t.Errorf("rule %s: allowed+denied > hits", rs.Rule)
						return
					}
				}
				// Every record in this test carries a rule, so rule hits
				// must equal the total of the SAME snapshot.
				if ruleHits != snap.Total {
					t.Errorf("rule hits %d != total %d in one snapshot", ruleHits, snap.Total)
					return
				}

				win, err := c.Window(time.Duration(seed+1) * 10 * time.Second)
				if err != nil {
					t.Errorf("window query failed: %v", err)
					return
				}
				var wsum uint64
				for _, n := range win.Counts {
					wsum += n
				}
				if wsum != win.Total {
					t.Errorf("window snapshot inconsistent: sum=%d total=%d", wsum, win.Total)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(stop)
	swg.Wait()

	// At rest the totals are exact.
	snap := c.Snapshot()
	if want := uint64(recorders * perRecorder); snap.Total != want {
		t.Fatalf("total=%d want %d", snap.Total, want)
	}
	var sum uint64
	for _, n := range snap.Counts {
		sum += n
	}
	if sum != snap.Total {
		t.Fatalf("final snapshot inconsistent: sum=%d total=%d", sum, snap.Total)
	}
}

// Illegal window parameters are errors, never panics or silent defaults.
func TestWindowInvalidParameters(t *testing.T) {
	c := New()
	for _, d := range []time.Duration{0, -time.Second, MaxWindow + time.Second, 2 * time.Hour} {
		if _, err := c.Window(d); err == nil {
			t.Fatalf("window %v must be rejected", d)
		}
	}
	if _, err := c.Window(time.Minute); err != nil {
		t.Fatalf("valid window rejected: %v", err)
	}
}
