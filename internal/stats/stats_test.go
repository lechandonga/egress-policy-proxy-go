package stats

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Business: windowed stats conserve — per-bucket counts sum to the window
// total on every snapshot, and rule attribution never exceeds the total.
func TestWindowConservation(t *testing.T) {
	c := New()
	c.Record(OutcomeAllowed, "r1")
	c.Record(OutcomeAllowed, "r1")
	c.Record(OutcomeDeniedPolicy, "r2")
	c.Record(OutcomeResolveFailed, "")
	c.Record(OutcomeClientError, "")

	ws := c.Window(time.Minute)
	if ws.Total != 5 {
		t.Fatalf("window total=%d want 5", ws.Total)
	}
	var sum uint64
	for _, n := range ws.Counts {
		sum += n
	}
	if sum != ws.Total {
		t.Fatalf("bucket sum %d != window total %d (%v)", sum, ws.Total, ws.Counts)
	}
	if ws.Counts[string(OutcomeAllowed)] != 2 || ws.Counts[string(OutcomeDeniedPolicy)] != 1 {
		t.Fatalf("counts=%v", ws.Counts)
	}
	var hits uint64
	for _, rs := range ws.Rules {
		hits += rs.Hits
	}
	if hits != 3 {
		t.Fatalf("window rule hits=%d want 3 (%v)", hits, ws.Rules)
	}
	for _, rs := range ws.Rules {
		if rs.Rule == "r1" && rs.Allowed != 2 {
			t.Fatalf("r1 allowed=%d want 2", rs.Allowed)
		}
		if rs.Rule == "r2" && rs.Denied != 1 {
			t.Fatalf("r2 denied=%d want 1", rs.Denied)
		}
	}
}

// Business: events older than the window fall out; cumulative totals are
// unaffected.
func TestWindowExcludesOldEvents(t *testing.T) {
	c := New()
	c.Record(OutcomeAllowed, "r1")

	// Pretend "now" is 10 minutes later: a 5m window must be empty while
	// the cumulative snapshot still shows the request.
	ws := c.WindowAt(5*time.Minute, time.Now().Add(10*time.Minute))
	if ws.Total != 0 {
		t.Fatalf("stale event leaked into window: %+v", ws)
	}
	if snap := c.Snapshot(); snap.Total != 1 {
		t.Fatalf("cumulative total=%d want 1", snap.Total)
	}
}

// Business: the event ring is bounded — memory stays flat under unbounded
// load, and the window reports at most ring-capacity events.
func TestWindowRingIsBounded(t *testing.T) {
	c := NewWithCapacity(4)
	for i := 0; i < 1000; i++ {
		c.Record(OutcomeAllowed, "r1")
	}
	ws := c.Window(time.Hour)
	if ws.Total != 4 {
		t.Fatalf("ring must cap retained events at 4, got %d", ws.Total)
	}
	if snap := c.Snapshot(); snap.Total != 1000 {
		t.Fatalf("cumulative total=%d want 1000", snap.Total)
	}
}

// Business: concurrent recording and window queries never fail and every
// snapshot is self-consistent.
func TestWindowConcurrentRecordAndQuery(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if (i+id)%3 == 0 {
					c.Record(OutcomeDeniedPolicy, "deny-rule")
				} else {
					c.Record(OutcomeAllowed, "allow-rule")
				}
			}
		}(w)
	}

	errCh := make(chan error, 4)
	for q := 0; q < 4; q++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				ws := c.Window(time.Minute)
				var sum uint64
				for _, n := range ws.Counts {
					sum += n
				}
				if sum != ws.Total {
					errCh <- fmt.Errorf("inconsistent window: sum=%d total=%d", sum, ws.Total)
					return
				}
			}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
