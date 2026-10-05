package stats

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSnapshotAlwaysSelfConsistentUnderContention is the regression test
// for torn snapshots: while many goroutines record outcomes (each record
// is a total increment plus one bucket increment plus rule attribution),
// other goroutines take cumulative and window snapshots at maximum
// frequency. Every single query must succeed and every returned snapshot
// must satisfy bucket-sum == total; with the race detector enabled this
// also proves the shared state has no data race.
func TestSnapshotAlwaysSelfConsistentUnderContention(t *testing.T) {
	c := New()

	var recorded atomic.Uint64
	stop := make(chan struct{})
	var recWG, queryWG sync.WaitGroup

	outs := []Outcome{
		OutcomeAllowed,
		OutcomeDeniedPolicy,
		OutcomeResolveFailed,
		OutcomeUpstreamDial,
		OutcomeUpstreamIOTimeout,
		OutcomeClientError,
	}
	rules := []string{"allow-a", "deny-b", ""}

	// Recorders.
	for w := 0; w < 10; w++ {
		recWG.Add(1)
		go func(id int) {
			defer recWG.Done()
			for i := 0; i < 5000; i++ {
				o := outs[(i+id)%len(outs)]
				c.Record(o, rules[(i+id)%len(rules)])
				recorded.Add(1)
			}
		}(w)
	}

	// High-frequency cumulative + window queries. A failure or panic here
	// aborts the whole test.
	for q := 0; q < 4; q++ {
		queryWG.Add(1)
		go func(seed int) {
			defer queryWG.Done()
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
					t.Errorf("cumulative snapshot torn: sum=%d total=%d", sum, snap.Total)
					return
				}
				for _, rs := range snap.Rules {
					if rs.Allowed+rs.Denied > rs.Hits {
						t.Errorf("rule attribution inconsistent: %+v", rs)
						return
					}
				}
				win, err := c.Window(time.Duration(1+seed%30) * time.Second)
				if err != nil {
					t.Errorf("window query failed: %v", err)
					return
				}
				var wsum uint64
				for _, n := range win.Counts {
					wsum += n
				}
				if wsum != win.Total {
					t.Errorf("window snapshot torn: sum=%d total=%d", wsum, win.Total)
					return
				}
			}
		}(q)
	}

	recWG.Wait()
	close(stop)
	queryWG.Wait()

	final := c.Snapshot()
	if final.Total != recorded.Load() {
		t.Fatalf("final total=%d recorded=%d", final.Total, recorded.Load())
	}
	var sum uint64
	for _, n := range final.Counts {
		sum += n
	}
	if sum != final.Total {
		t.Fatalf("final snapshot inconsistent: %d != %d", sum, final.Total)
	}
}
