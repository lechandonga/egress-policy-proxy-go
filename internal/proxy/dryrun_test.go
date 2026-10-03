package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Business: dry-run and real forwarding reach the same conclusion and name
// the same winning rule for identical inputs.
func TestDryRunMatchesRealForwarding(t *testing.T) {
	h := newHarness(t, baseRules)
	ctx := context.Background()

	upPort := h.portOf(h.upstream)
	portOf := func(p string) uint16 {
		var n int
		fmt.Sscanf(p, "%d", &n)
		return uint16(n)
	}
	cases := []struct {
		host string
		port uint16
	}{
		{"upstream.test", portOf(upPort)},
		{"forbidden.test", portOf(upPort)},
		{"rebind.test", 443},
	}

	for _, tc := range cases {
		dr, reason, err := DryRun(ctx, h.store, h.resolver, tc.host, tc.port, nil)
		if err != nil {
			t.Fatalf("dryrun %s:%d: %v (%s)", tc.host, tc.port, err, reason)
		}
		target := fmt.Sprintf("http://%s:%d/", tc.host, tc.port)
		status, hdr, _ := proxyGet(t, h.proxyClient(), target)
		realAllowed := status == http.StatusOK
		if dr.Allowed != realAllowed {
			t.Fatalf("%s:%d dryrun allowed=%v but real status=%d", tc.host, tc.port, dr.Allowed, status)
		}
		if !realAllowed {
			realRule := hdr.Get("X-Egress-Rule")
			if dr.WinningRule != realRule {
				t.Fatalf("%s:%d dryrun rule=%q real rule=%q", tc.host, tc.port, dr.WinningRule, realRule)
			}
		}
	}
}

// Business: dry-run with assumed addresses — the name itself is allowed,
// but an assumed address inside a denied CIDR denies the whole query, and
// the deny rule is named.
func TestDryRunAssumedAddressDenied(t *testing.T) {
	h := newHarness(t, baseRules)
	dr, _, err := DryRun(context.Background(), h.store, h.resolver,
		"upstream.test", 80, []netip.Addr{netip.MustParseAddr("203.0.113.7")})
	if err != nil {
		t.Fatal(err)
	}
	if dr.Allowed {
		t.Fatalf("assumed denied address must deny the query: %+v", dr)
	}
	if dr.WinningRule != "deny-203" {
		t.Fatalf("winning rule=%q want deny-203", dr.WinningRule)
	}
}

// Business: with several assumed addresses, ANY single denied address
// denies the whole query — same as real multi-A-record handling.
func TestDryRunAnyAssumedAddressDenied(t *testing.T) {
	h := newHarness(t, baseRules)
	good := addrsOf(h.upstream.Listener.Addr())[0]
	bad := netip.MustParseAddr("203.0.113.9")

	dr, _, err := DryRun(context.Background(), h.store, h.resolver,
		"upstream.test", 80, []netip.Addr{good, bad})
	if err != nil {
		t.Fatal(err)
	}
	if dr.Allowed || dr.WinningRule != "deny-203" {
		t.Fatalf("one denied address out of two must deny all: %+v", dr)
	}

	dr2, _, err := DryRun(context.Background(), h.store, h.resolver,
		"upstream.test", 80, []netip.Addr{good})
	if err != nil {
		t.Fatal(err)
	}
	if !dr2.Allowed || dr2.WinningRule != "allow-upstream" {
		t.Fatalf("all-good assumed set must allow: %+v", dr2)
	}
}

// Business: no matching rule -> explicit default deny, empty winning rule.
func TestDryRunDefaultDenyIsExplicit(t *testing.T) {
	h := newHarness(t, `{"rules":[{"id":"only-a","action":"allow","domains":["a.test"]}]}`)
	dr, _, err := DryRun(context.Background(), h.store, h.resolver, "upstream.test", 80, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dr.Allowed || dr.WinningRule != "" {
		t.Fatalf("default deny must be explicit: %+v", dr)
	}
	if dr.Action != string(policy.ActionDeny) {
		t.Fatalf("action=%q want deny", dr.Action)
	}
	if !strings.Contains(dr.Reason, "default deny") {
		t.Fatalf("reason must state default deny, got %q", dr.Reason)
	}
}

// Business: a dry-run colliding with a reload belongs entirely to ONE
// version — the reported version always matches the verdict it produced.
func TestDryRunVersionBindingUnderReload(t *testing.T) {
	store := policy.NewStore()
	counters := stats.New()
	_ = counters

	mk := func(id, version string) *policy.Policy {
		p, err := policy.Build([]policy.Rule{
			{ID: id, Action: policy.ActionAllow, Domains: []string{"x.test"}},
		}, version)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	store.Swap(mk("allow-v1", "v1"))

	res := h0resolver{ip: netip.MustParseAddr("192.0.2.1")}
	ctx := context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errCh := make(chan error, 128)

	// Flip versions v1<->v2 with different winning rule ids.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				store.Swap(mk("allow-v1", "v1"))
			} else {
				store.Swap(mk("allow-v2", "v2"))
			}
		}
	}()

	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				dr, _, err := DryRun(ctx, store, res, "x.test", 443, nil)
				if err != nil {
					errCh <- err
					return
				}
				wantRule := "allow-" + dr.Version
				if dr.WinningRule != wantRule {
					errCh <- fmt.Errorf("version %q but rule %q: mixed snapshot", dr.Version, dr.WinningRule)
					return
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// Business: dry-runs never touch the forwarding statistics.
func TestDryRunNotCountedInStats(t *testing.T) {
	h := newHarness(t, baseRules)
	before := h.counters.Snapshot()
	for i := 0; i < 20; i++ {
		if _, _, err := DryRun(context.Background(), h.store, h.resolver, "upstream.test", 80, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := DryRun(context.Background(), h.store, h.resolver, "forbidden.test", 80, nil); err != nil {
			t.Fatal(err)
		}
	}
	after := h.counters.Snapshot()
	if after.Total != before.Total {
		t.Fatalf("dry-run polluted stats: total %d -> %d", before.Total, after.Total)
	}
	if ws := h.counters.Window(time.Hour); ws.Total != 0 {
		t.Fatalf("dry-run leaked into window stats: %+v", ws)
	}
}

type h0resolver struct{ ip netip.Addr }

func (r h0resolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}
