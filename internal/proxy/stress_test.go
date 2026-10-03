package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Business: sustained forwarding traffic plus high-frequency windowed
// stats queries — queries never fail, every snapshot is self-consistent,
// and the process stays healthy (run with -race).
func TestStatsQueriesUnderSustainedTraffic(t *testing.T) {
	h := newHarness(t, baseRules)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errCh := make(chan error, 16)

	// Traffic: mixed allow / policy-deny / resolve-failure.
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c := h.proxyClient()
			targets := []string{
				"http://upstream.test:" + h.portOf(h.upstream) + "/",
				"http://forbidden.test:" + h.portOf(h.upstream) + "/",
				"http://nope-nxdomain.test:80/",
			}
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				proxyGet(t, c, targets[(i+id)%len(targets)])
			}
		}(w)
	}

	// High-frequency window queries: every snapshot must conserve.
	for q := 0; q < 6; q++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ws := h.counters.Window(5 * time.Minute)
				var sum uint64
				for _, n := range ws.Counts {
					sum += n
				}
				if sum != ws.Total {
					errCh <- fmt.Errorf("window not self-consistent: sum=%d total=%d", sum, ws.Total)
					return
				}
				snap := h.counters.Snapshot()
				var csum uint64
				for _, n := range snap.Counts {
					csum += n
				}
				if csum != snap.Total {
					errCh <- fmt.Errorf("cumulative not self-consistent: sum=%d total=%d", csum, snap.Total)
					return
				}
			}
		}()
	}

	time.Sleep(2 * time.Second)
	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// The final in-flight requests may still be recording; wait for the
	// counters to settle, then the 1h window must cover the whole run.
	var snap stats.Snapshot
	var ws stats.WindowSnapshot
	deadline := time.Now().Add(3 * time.Second)
	for {
		snap = h.counters.Snapshot()
		ws = h.counters.Window(time.Hour)
		if snap.Total > 0 && snap.Total == ws.Total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("window/cumulative never converged: window=%d cumulative=%d", ws.Total, snap.Total)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("processed %d requests; window total=%d rules=%v", snap.Total, ws.Total, ws.Rules)
}

// Business: cumulative counters keep their exact semantics while windowed
// stats exist — every request counted exactly once.
func TestCumulativeUnaffectedByWindowQueries(t *testing.T) {
	h := newHarness(t, baseRules)
	c := h.proxyClient()
	const n = 50
	for i := 0; i < n; i++ {
		proxyGet(t, c, "http://upstream.test:"+h.portOf(h.upstream)+"/")
		_ = h.counters.Window(time.Minute)
	}
	snap := h.counters.Snapshot()
	if snap.Total != n || snap.Counts[string(stats.OutcomeAllowed)] != n {
		t.Fatalf("cumulative counts wrong: %+v", snap)
	}
}
