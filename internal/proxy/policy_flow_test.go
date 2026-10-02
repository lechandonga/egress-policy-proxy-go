package proxy

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
)

// 业务一：HTTP 明文转发——放行与拒绝走同一套判定，并给出可解释的生效规则。
func TestHTTPPlainAllowAndDeny(t *testing.T) {
	policyJSON := `{
		"version":1,"default_action":"deny",
		"rules":[
			{"id":"allow-ok","action":"allow","domains":["ok.example.com"]},
			{"id":"deny-bad","action":"deny","domains":["bad.example.com"]}
		]}`
	h := newHarness(t, policyJSON, nil)
	_, _, okPort := h.startOrigin("ok.example.com", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("origin-ok"))
	})
	badSrv, _, badPort := h.startOrigin("bad.example.com", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("被拒绝的请求绝不能到达上游")
	})
	defer badSrv.Close()

	t.Run("允许域名转发成功并计入放行", func(t *testing.T) {
		resp, err := h.plainClient().Get("http://ok.example.com:" + strconv.Itoa(int(okPort)) + "/")
		if err != nil {
			t.Fatalf("放行请求失败: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusTeapot || readAll(t, resp.Body) != "origin-ok" {
			t.Fatalf("源站响应异常: %d", resp.StatusCode)
		}
		snap := h.st.Snapshot()
		if snap.ByOutcome["allowed"] != 1 || snap.RuleHits["allow-ok"] != 1 {
			t.Fatalf("放行统计错误: %+v %+v", snap.ByOutcome, snap.RuleHits)
		}
	})

	t.Run("拒绝域名返回403且说明生效规则", func(t *testing.T) {
		resp, err := h.plainClient().Get("http://bad.example.com:" + strconv.Itoa(int(badPort)) + "/")
		if err != nil {
			t.Fatalf("拒绝应返回响应而非传输错误: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden ||
			resp.Header.Get("X-Egress-Reason") != "policy_denied" {
			t.Fatalf("状态/reason 错误: %d %q", resp.StatusCode, resp.Header.Get("X-Egress-Reason"))
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		winner, _ := body["winner"].(map[string]any)
		if winner["rule_id"] != "deny-bad" {
			t.Fatalf("生效规则应为 deny-bad，body=%v", body)
		}
		t.Logf("拒绝解释: %s", body["explanation"])
		snap := h.st.Snapshot()
		if snap.ByOutcome["denied_policy"] != 1 {
			t.Fatalf("策略拒绝计数错误: %+v", snap.ByOutcome)
		}
	})
}

// 业务二：域名允许但实际解析地址落在拒绝 CIDR —— 必须拒绝，防解析差异绕过。
func TestDomainAllowedButResolvedIPDenied(t *testing.T) {
	policyJSON := `{
		"version":1,"default_action":"deny",
		"rules":[
			{"id":"allow-trick","action":"allow","domains":["trick.example.com"]},
			{"id":"deny-internal","action":"deny","ips":["10.0.0.0/8"]}
		]}`
	h := newHarness(t, policyJSON, map[string][]netip.Addr{
		"trick.example.com": {mustAddr("10.2.3.4")},
	})

	resp, err := h.plainClient().Get("http://trick.example.com/secret")
	if err != nil {
		t.Fatalf("应返回 403 响应而非传输错误: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("解析到 10/8 必须拒绝，实际 %d", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	winner, _ := body["winner"].(map[string]any)
	if winner["rule_id"] != "deny-internal" {
		t.Fatalf("生效规则应为 deny-internal，实际 %v", body["winner"])
	}
	if winner["ip_hit"] == "" {
		t.Fatalf("应给出 IP 命中说明: %v", winner)
	}
	t.Logf("防绕过判定: %s | %s", body["explanation"], winner["ip_hit"])
}

// IP 字面量直连也必须经过同样判定。
func TestIPLiteralDeny(t *testing.T) {
	policyJSON := `{
		"version":1,"default_action":"allow",
		"rules":[{"id":"block-metadata","action":"deny","ips":["169.254.169.254"]}]}`
	h := newHarness(t, policyJSON, nil)
	resp, err := h.plainClient().Get("http://169.254.169.254/latest/meta-data")
	if err != nil {
		t.Fatalf("应返回 403: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("元数据地址必须拒绝，实际 %d", resp.StatusCode)
	}
}
