package proxy

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
)

// 业务四：HTTPS CONNECT 隧道同样执行「解析 + 策略」判定，策略拒绝时隧道不建立。
func TestHTTPSConnectPolicy(t *testing.T) {
	policyJSON := `{
		"version":1,"default_action":"deny",
		"rules":[
			{"id":"allow-secure","action":"allow","domains":["secure.example.com"]},
			{"id":"deny-evil","action":"deny","domains":["evil.example.com"]},
			{"id":"deny-cidr","action":"deny","ips":["10.0.0.0/8"]}
		]}`
	h := newHarness(t, policyJSON, nil)

	tlsSrv, _, port := h.startTLSOrigin("secure.example.com", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls-ok"))
	})
	_ = tlsSrv

	t.Run("CONNECT放行并完成TLS往返", func(t *testing.T) {
		resp, err := h.rawConnectAndTLS("secure.example.com", port, tlsSrv, "/hello")
		if err != nil {
			t.Fatalf("CONNECT/TLS 失败: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("源站状态异常: %d", resp.StatusCode)
		}
		if readAll(t, resp.Body) != "tls-ok" {
			t.Fatalf("TLS body 异常")
		}
		waitActiveConns(h, 0)
		snap := h.st.Snapshot()
		if snap.ByOutcome["allowed"] != 1 || snap.RuleHits["allow-secure"] != 1 {
			t.Fatalf("CONNECT 放行统计错误: %+v %+v", snap.ByOutcome, snap.RuleHits)
		}
	})

	t.Run("CONNECT被策略拒绝返回403且隧道不建立", func(t *testing.T) {
		h.resolver.hosts["evil.example.com"] = []netip.Addr{mustAddr("127.0.0.1")}
		conn, err := dialTCP(h.srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("CONNECT evil.example.com:" + strconv.Itoa(int(port)) + " HTTP/1.1\r\nHost: evil.example.com\r\n\r\n"))
		br := newBufioReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("读响应失败: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden ||
			resp.Header.Get("X-Egress-Reason") != "policy_denied" {
			t.Fatalf("CONNECT 拒绝分类错误: %d", resp.StatusCode)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		winner, _ := body["winner"].(map[string]any)
		if winner["rule_id"] != "deny-evil" {
			t.Fatalf("生效规则应为 deny-evil: %v", body)
		}
	})

	t.Run("CONNECT域名允许但解析到拒绝CIDR仍拒绝", func(t *testing.T) {
		h.resolver.hosts["secure.example.com"] = []netip.Addr{mustAddr("10.9.9.9")}
		conn, err := dialTCP(h.srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("CONNECT secure.example.com:443 HTTP/1.1\r\nHost: secure.example.com\r\n\r\n"))
		br := newBufioReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("读响应失败: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("解析到 10/8 时 CONNECT 必须拒绝，实际 %d", resp.StatusCode)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		winner, _ := body["winner"].(map[string]any)
		if winner["rule_id"] != "deny-cidr" {
			t.Fatalf("生效规则应为 deny-cidr: %v", body["winner"])
		}
		t.Logf("HTTPS 防绕过: %s", body["explanation"])
	})
}
