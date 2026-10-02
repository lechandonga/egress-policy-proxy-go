package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/resolver"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Business: HTTP forward proxy allow / deny.

func TestHTTPForwardAllowed(t *testing.T) {
	h := newHarness(t, baseRules)
	status, hdr, body := proxyGet(t, h.proxyClient(),
		"http://upstream.test:"+h.portOf(h.upstream)+"/path")
	if status != 200 || body != "hello-from-upstream" {
		t.Fatalf("status=%d body=%q", status, body)
	}
	if hdr.Get("X-Upstream") != "ok" {
		t.Fatal("upstream header missing")
	}
}

func TestHTTPForwardDeniedByDomain(t *testing.T) {
	h := newHarness(t, baseRules)
	status, hdr, _ := proxyGet(t, h.proxyClient(),
		"http://forbidden.test:"+h.portOf(h.upstream)+"/")
	if status != http.StatusForbidden {
		t.Fatalf("want 403, got %d", status)
	}
	if hdr.Get("X-Egress-Reason") != ReasonPolicyDeny {
		t.Fatalf("reason=%q", hdr.Get("X-Egress-Reason"))
	}
	if hdr.Get("X-Egress-Rule") != "deny-domain" {
		t.Fatalf("rule=%q", hdr.Get("X-Egress-Rule"))
	}
}

// Business: DNS rebinding — allowed name, denied resolved IP.

func TestAllowedNameButDeniedResolvedIP(t *testing.T) {
	h := newHarness(t, `{
	  "rules": [
	    {"id":"allow-all-names","action":"allow","domains":["*.test"]},
	    {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]}
	  ]
	}`)
	status, hdr, _ := proxyGet(t, h.proxyClient(), "http://rebind.test:443/")
	if status != http.StatusForbidden {
		t.Fatalf("want 403, got %d", status)
	}
	if hdr.Get("X-Egress-Rule") != "deny-203" {
		t.Fatalf("deny-203 must win over allowed name, got %q", hdr.Get("X-Egress-Rule"))
	}
}

// Business: resolution failure classifications.

func TestResolveNXDOMAIN(t *testing.T) {
	h := newHarness(t, `{"rules":[{"id":"a","action":"allow","domains":["missing.test"]}]}`)
	status, hdr, _ := proxyGet(t, h.proxyClient(), "http://missing.test:80/")
	if status != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", status)
	}
	if hdr.Get("X-Egress-Reason") != ReasonResolveNXDOMAIN {
		t.Fatalf("reason=%q", hdr.Get("X-Egress-Reason"))
	}
}

func TestResolveFailureDistinctFromNXDOMAIN(t *testing.T) {
	h := newHarness(t, baseRules)
	h.resolver = resolver.Func(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		return nil, &resolver.Error{Class: resolver.ClassFailure, Host: host,
			Err: errors.New("resolver timeout in test")}
	})
	h.start()
	status, hdr, _ := proxyGet(t, h.proxyClient(),
		"http://upstream.test:"+h.portOf(h.upstream)+"/")
	if status != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", status)
	}
	if hdr.Get("X-Egress-Reason") != ReasonResolveFailure {
		t.Fatalf("reason=%q want %q", hdr.Get("X-Egress-Reason"), ReasonResolveFailure)
	}
}

// Business: upstream unreachable vs timeout.

func TestUpstreamConnectionRefused(t *testing.T) {
	h := newHarness(t, `{"rules":[{"id":"allow-refused","action":"allow","domains":["refused.test"]}]}`)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
	_ = ln.Close()

	status, hdr, _ := proxyGet(t, h.proxyClient(), "http://refused.test:"+deadPort+"/")
	if status != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", status)
	}
	if hdr.Get("X-Egress-Reason") != ReasonUpstreamDial {
		t.Fatalf("reason=%q", hdr.Get("X-Egress-Reason"))
	}
}

func TestUpstreamDialTimeout(t *testing.T) {
	h := newHarness(t, `{"rules":[{"id":"allow-slow","action":"allow","domains":["slow.test"]}]}`)
	h.dialer = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	h.timeouts.DialTimeout = 300 * time.Millisecond
	h.start()

	start := time.Now()
	status, hdr, _ := proxyGet(t, h.proxyClient(), "http://slow.test:443/")
	if status != http.StatusGatewayTimeout {
		t.Fatalf("want 504, got %d", status)
	}
	if hdr.Get("X-Egress-Reason") != ReasonUpstreamTimeout {
		t.Fatalf("reason=%q", hdr.Get("X-Egress-Reason"))
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("request hung: %v", d)
	}
}

// Business: HTTPS via CONNECT — allow, deny, tunnel idle timeout.

func TestHTTPSConnectAllowed(t *testing.T) {
	h := newHarness(t, baseRules)
	status, _, body := proxyGet(t, h.proxyClient(),
		"https://tls.test:"+h.portOf(h.tlsSrv)+"/")
	if status != 200 || body != "hello-over-tls" {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestHTTPSConnectDenied(t *testing.T) {
	h := newHarness(t, baseRules)
	status, _, _ := proxyGet(t, h.proxyClient(),
		"https://forbidden.test:"+h.portOf(h.tlsSrv)+"/")
	if status != http.StatusForbidden && status != -1 {
		t.Fatalf("want 403 (CONNECT denial), got %d", status)
	}
}

func TestConnectTunnelIdleTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	port := strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")

	h := newHarness(t, fmt.Sprintf(
		`{"rules":[{"id":"allow-hang","action":"allow","domains":["slow.test"],"ports":[%s]}]}`, port))
	h.resolver = resolver.Func(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	h.timeouts.IOIdleTimeout = 300 * time.Millisecond
	h.start()

	conn, err := net.Dial("tcp", strings.TrimPrefix(h.proxyURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT slow.test:%s HTTP/1.1\r\nHost: slow.test:%s\r\n\r\n", port, port)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT want 200, got %d", resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "slow.test"})
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tlsConn.Handshake(); err != nil {
		// Proxy idle timeout can close the tunnel during handshake too,
		// which is acceptable; here the handshake itself sends bytes.
		t.Logf("handshake ended: %v", err)
	}
	// After silence, the idle deadline must terminate the tunnel.
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("tunnel stayed open past idle timeout (leak/hang)")
	}
}

// Business: fail closed when no policy is loaded.

func TestNoPolicyFailsClosed(t *testing.T) {
	h := newHarness(t, "")
	status, hdr, _ := proxyGet(t, h.proxyClient(),
		"http://upstream.test:"+h.portOf(h.upstream)+"/")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", status)
	}
	if hdr.Get("X-Egress-Reason") != ReasonNoPolicy {
		t.Fatalf("reason=%q", hdr.Get("X-Egress-Reason"))
	}
}

// Business: concurrent reloads and requests use consistent snapshots and
// counters never double-count or lose requests.

func TestConcurrentReloadAndTraffic(t *testing.T) {
	h := newHarness(t, baseRules)

	allowPolicy := func(domain string) string {
		return fmt.Sprintf(`{"rules":[{"id":"r","action":"allow","domains":["%s"]}]}`, domain)
	}

	const workers = 16
	const perWorker = 60
	var wg sync.WaitGroup
	var reloads atomic.Int64

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				dom := "upstream.test"
				if (seed+i)%2 == 0 {
					dom = "other.test"
				}
				p, err := policy.Decode([]byte(allowPolicy(dom)))
				if err != nil {
					t.Errorf("reload decode: %v", err)
					return
				}
				h.store.Swap(p)
				reloads.Add(1)
			}
		}(w)
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c := h.proxyClient()
			for i := 0; i < perWorker; i++ {
				target := "http://upstream.test:" + h.portOf(h.upstream) + "/"
				_, _, _ = proxyGet(t, c, target)
			}
		}(w)
	}

	wg.Wait()

	snap := h.counters.Snapshot()
	var total uint64
	for _, n := range snap.Counts {
		total += n
	}
	want := uint64(workers * perWorker)
	if total != want {
		t.Fatalf("counted %d requests, want exactly %d (counts=%v)", total, want, snap.Counts)
	}
	if snap.Total != want {
		t.Fatalf("snapshot total=%d want %d", snap.Total, want)
	}

	// In-flight requests must see one coherent version; either an allow
	// rule named upstream.test exists or the default deny fires, but the
	// sum of attributions is internally consistent.
	var attributed uint64
	for _, rs := range snap.Rules {
		attributed += rs.Hits
	}
	if attributed > snap.Total {
		t.Fatalf("rule hits %d exceed total requests %d", attributed, snap.Total)
	}
	t.Logf("reloads=%d stats=%+v", reloads.Load(), snap)
}

// Business: stats distinguish each error class and attribution sums up.

func TestStatsBucketPerOutcome(t *testing.T) {
	h := newHarness(t, baseRules)
	c := h.proxyClient()

	one := func(target string) { proxyGet(t, c, target) }
	one("http://upstream.test:" + h.portOf(h.upstream) + "/")  // allowed
	one("http://forbidden.test:" + h.portOf(h.upstream) + "/") // policy deny
	one("http://rebind.test:443/")                             // policy deny via IP
	one("http://nope-nxdomain.test:80/")                       // resolve failed

	snap := h.counters.Snapshot()
	if snap.Counts[string(stats.OutcomeAllowed)] != 1 {
		t.Fatalf("allowed=%d want 1 (%v)", snap.Counts[string(stats.OutcomeAllowed)], snap.Counts)
	}
	if snap.Counts[string(stats.OutcomeDeniedPolicy)] != 2 {
		t.Fatalf("denied=%d want 2", snap.Counts[string(stats.OutcomeDeniedPolicy)])
	}
	if snap.Counts[string(stats.OutcomeResolveFailed)] != 1 {
		t.Fatalf("resolve_failed=%d want 1", snap.Counts[string(stats.OutcomeResolveFailed)])
	}

	var hits uint64
	for _, rs := range snap.Rules {
		hits += rs.Hits
	}
	if hits != 3 {
		t.Fatalf("attributed rule hits=%d want 3", hits)
	}
}
