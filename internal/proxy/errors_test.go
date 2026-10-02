package proxy

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// 业务三：解析失败、上游不可达、上游超时、畸形请求必须返回可区分结果。
func TestErrorClassification(t *testing.T) {
	policyJSON := `{
		"version":1,"default_action":"deny",
		"rules":[
			{"id":"allow-all-domains","action":"allow","domains":["a.example.com","dead.example.com","slow.example.com","nx.example.com"]}
		]}`
	h := newHarness(t, policyJSON, map[string][]netip.Addr{
		"a.example.com":    {mustAddr("127.0.0.1")},
		"dead.example.com": {mustAddr("127.0.0.1")},
		"slow.example.com": {mustAddr("127.0.0.1")},
		// nx.example.com 不登记 -> staticResolver 返回解析失败
	})

	t.Run("解析失败->502 dns_failed", func(t *testing.T) {
		resp, err := h.plainClient().Get("http://nx.example.com/")
		if err != nil {
			t.Fatalf("应得到响应: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway ||
			resp.Header.Get("X-Egress-Reason") != "dns_failed" {
			t.Fatalf("DNS 错误分类错误: %d %q", resp.StatusCode, resp.Header.Get("X-Egress-Reason"))
		}
		if h.st.Snapshot().ByOutcome["dns_failed"] != 1 {
			t.Fatalf("dns_failed 计数错误")
		}
	})

	t.Run("上游不可达->502 upstream_unreachable", func(t *testing.T) {
		// 找一个必然没有监听的本地端口
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := ln.Addr().String()
		ln.Close()
		_, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		resp, err := h.plainClient().Get("http://dead.example.com:" + strconv.Itoa(port) + "/")
		if err != nil {
			t.Fatalf("应得到响应: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway ||
			resp.Header.Get("X-Egress-Reason") != "upstream_unreachable" {
			t.Fatalf("上游故障分类错误: %d %q", resp.StatusCode, resp.Header.Get("X-Egress-Reason"))
		}
		if h.st.Snapshot().ByOutcome["upstream_fail"] != 1 {
			t.Fatalf("upstream_fail 计数错误")
		}
	})

	t.Run("上游超时->504 upstream_timeout 且不卡死", func(t *testing.T) {
		// 拨号阶段挂起：DialContext 阻塞直到 ctx 超时
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); time.Sleep(time.Hour) }()
			}
		}()

		hSlow := newHarness(t, policyJSON, map[string][]netip.Addr{
			"slow.example.com": {mustAddr("127.0.0.1")},
		})
		// 让“读响应”超时：接受连接后永不回响应；拨号成功但 ReadResponse 卡住。
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portStr)

		start := time.Now()
		resp, err := hSlow.plainClient().Get("http://slow.example.com:" + strconv.Itoa(port) + "/")
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("应得到 504 而非客户端错误: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusGatewayTimeout ||
			resp.Header.Get("X-Egress-Reason") != "upstream_timeout" {
			t.Fatalf("超时分类错误: %d %q", resp.StatusCode, resp.Header.Get("X-Egress-Reason"))
		}
		if elapsed > 6*time.Second {
			t.Fatalf("请求卡死，耗时 %v", elapsed)
		}
		t.Logf("超时请求在 %v 内被明确终止", elapsed)
		if hSlow.st.Snapshot().ByOutcome["upstream_timeout"] != 1 {
			t.Fatalf("upstream_timeout 计数错误")
		}
	})

	t.Run("拨号超时同样归类为 upstream_timeout", func(t *testing.T) {
		h2 := newHarness(t, policyJSON, map[string][]netip.Addr{
			"slow.example.com": {mustAddr("127.0.0.1")},
		})
		h2.dialFn = func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
		}
		resp, err := h2.plainClient().Get("http://slow.example.com:9/")
		if err != nil {
			t.Fatalf("应得到响应: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusGatewayTimeout {
			t.Fatalf("拨号超时应为 504，实际 %d", resp.StatusCode)
		}
	})

	t.Run("畸形代理请求->400 bad_request", func(t *testing.T) {
		conn, err := net.Dial("tcp", h.srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		// origin-form 且无 Host 端口，无法确定目标
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: /bad host\r\n\r\n"))
		br := newBufioReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("读响应失败: %v", err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("畸形请求应 400，实际 %d", resp.StatusCode)
		}
	})
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
