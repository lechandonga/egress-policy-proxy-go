package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/resolver"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

type harness struct {
	t        *testing.T
	store    *policy.Store
	counters *stats.Counters
	resolver resolver.Resolver
	dialer   func(ctx context.Context, network, address string) (net.Conn, error)
	proxyURL string
	httpSrv  *httptest.Server
	upstream *httptest.Server
	tlsSrv   *httptest.Server
	timeouts Config
}

func newHarness(t *testing.T, rulesJSON string) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		store:    policy.NewStore(),
		counters: stats.New(),
	}
	if rulesJSON != "" {
		h.load(rulesJSON)
	}

	h.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Upstream", "ok")
		fmt.Fprint(w, "hello-from-upstream")
	}))
	t.Cleanup(h.upstream.Close)

	h.tlsSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello-over-tls")
	}))
	t.Cleanup(h.tlsSrv.Close)

	h.resolver = resolver.Map{
		"upstream.test":  addrsOf(h.upstream.Listener.Addr()),
		"tls.test":       addrsOf(h.tlsSrv.Listener.Addr()),
		"forbidden.test": addrsOf(h.upstream.Listener.Addr()),
		"rebind.test":    []netip.Addr{netip.MustParseAddr("203.0.113.7")},
		"slow.test":      []netip.Addr{netip.MustParseAddr("198.51.100.9")},
		"refused.test":   []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}

	h.timeouts = Config{
		RequestTimeout: 5 * time.Second,
		DialTimeout:    2 * time.Second,
		IOIdleTimeout:  2 * time.Second,
	}

	h.start()
	return h
}

func addrsOf(a net.Addr) []netip.Addr {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		panic(err)
	}
	return []netip.Addr{netip.MustParseAddr(host)}
}

func (h *harness) load(rulesJSON string) {
	p, err := policy.Decode([]byte(rulesJSON))
	if err != nil {
		h.t.Fatalf("bad test policy: %v", err)
	}
	h.store.Swap(p)
}

func (h *harness) start() {
	cfg := h.timeouts
	cfg.Resolver = h.resolver
	cfg.Dialer = h.dialer
	px := New(h.store, h.counters, cfg)
	h.httpSrv = httptest.NewServer(px.Handler())
	h.t.Cleanup(h.httpSrv.Close)
	u, _ := url.Parse(h.httpSrv.URL)
	h.proxyURL = u.String()
}

func (h *harness) proxyClient() *http.Client {
	pu, _ := url.Parse(h.proxyURL)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 6 * time.Second,
	}
}

func (h *harness) portOf(srv *httptest.Server) string {
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return p
}

func proxyGet(t *testing.T, c *http.Client, target string) (int, http.Header, string) {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		return -1, nil, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

const baseRules = `{
  "rules": [
    {"id":"allow-upstream","action":"allow","domains":["upstream.test"]},
    {"id":"allow-tls","action":"allow","domains":["tls.test"]},
    {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]},
    {"id":"deny-domain","action":"deny","domains":["forbidden.test"]}
  ]
}`
