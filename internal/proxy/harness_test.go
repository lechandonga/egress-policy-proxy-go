package proxy

import (
	"bufio"
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
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

type harness struct {
	t        *testing.T
	store    *policy.Store
	st       *stats.Stats
	pxy      *Proxy
	srv      *httptest.Server
	resolver *staticResolver
	proxyURL *url.URL
	dialFn   func(ctx context.Context, network, address string) (net.Conn, error)
}

func newHarness(t *testing.T, policyJSON string, hosts map[string][]netip.Addr) *harness {
	t.Helper()
	pol, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatalf("策略不合法: %v", err)
	}
	store, err := policy.NewStore(pol)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	st := &stats.Stats{}
	h := &harness{
		t:        t,
		store:    store,
		st:       st,
		resolver: &staticResolver{hosts: hosts},
	}
	h.pxy = New(store, st, Config{
		Resolver:       h.resolver,
		DialTimeout:    2 * time.Second,
		RequestTimeout: 3 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if h.dialFn != nil {
				return h.dialFn(ctx, network, address)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	})
	h.srv = httptest.NewServer(h.pxy.Handler())
	t.Cleanup(h.srv.Close)
	h.proxyURL, _ = url.Parse(h.srv.URL)
	return h
}

func (h *harness) plainClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(h.proxyURL)},
		Timeout:   5 * time.Second,
	}
}

// startOrigin 启动一个本地 HTTP 源站，并把其 127.0.0.1:port 作为解析结果登记到 host。
func (h *harness) startOrigin(host string, handler http.HandlerFunc) (*httptest.Server, []netip.Addr, uint16) {
	srv := httptest.NewServer(handler)
	h.t.Cleanup(srv.Close)
	addr := netip.MustParseAddr("127.0.0.1")
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	if h.resolver.hosts == nil {
		h.resolver.hosts = map[string][]netip.Addr{}
	}
	h.resolver.hosts[host] = []netip.Addr{addr}
	return srv, []netip.Addr{addr}, port
}

// startTLSOrigin 启动本地 HTTPS 源站，端口固定 443 无法在 127.0.0.1 直接监听，
// 因此 CONNECT 测试用 host:port 形式，策略按实际端口放行。
func (h *harness) startTLSOrigin(host string, handler http.HandlerFunc) (*httptest.Server, []netip.Addr, uint16) {
	srv := httptest.NewTLSServer(handler)
	h.t.Cleanup(srv.Close)
	addr := netip.MustParseAddr("127.0.0.1")
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	if h.resolver.hosts == nil {
		h.resolver.hosts = map[string][]netip.Addr{}
	}
	h.resolver.hosts[host] = []netip.Addr{addr}
	return srv, []netip.Addr{addr}, port
}

// rawConnect 手工发送 CONNECT，返回隧道内 TLS 响应或错误状态。
func (h *harness) rawConnectAndTLS(host string, port uint16, tlsSrv *httptest.Server, path string) (*http.Response, error) {
	conn, err := net.Dial("tcp", h.srv.Listener.Addr().String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("CONNECT 未建立: %s", resp.Status)
	}
	tlsConn := tls.Client(&bufferedConn{Conn: conn, r: br}, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return nil, err
	}
	fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", path, host, port)
	tbr := bufio.NewReader(tlsConn)
	return http.ReadResponse(tbr, nil)
}

// bufferedConn 把 CONNECT 响应后可能缓冲在 bufio.Reader 里的数据接回连接。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("读 body 失败: %v", err)
	}
	return string(b)
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func newBufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

func dialTCP(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }

func waitActiveConns(h *harness, want int64) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.pxy.ActiveConns() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
