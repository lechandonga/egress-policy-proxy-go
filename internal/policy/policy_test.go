package policy

import (
	"net/netip"
	"strings"
	"testing"
)

// 业务一：策略格式校验——畸形/非法规则必须逐条报错，绝不静默忽略。
func TestParseMalformedPolicy(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantSub []string
	}{
		{
			"JSON 语法错误",
			`{ broken`,
			[]string{"JSON 语法/字段错误"},
		},
		{
			"未知字段被拒绝",
			`{"version":1,"default_action":"deny","rules":[],"hack":true}`,
			[]string{"unknown field"},
		},
		{
			"不支持的版本",
			`{"version":9,"default_action":"deny","rules":[]}`,
			[]string{"version"},
		},
		{
			"非法默认动作",
			`{"version":1,"default_action":"maybe","rules":[]}`,
			[]string{"default_action"},
		},
		{
			"规则 id 为空且重复",
			`{"version":1,"default_action":"deny","rules":[
				{"id":"r1","action":"allow","domains":["a.com"]},
				{"id":"r1","action":"allow","domains":["b.com"]},
				{"id":"","action":"allow","domains":["c.com"]}
			]}`,
			[]string{"重复", "id 不能为空"},
		},
		{
			"非法 action",
			`{"version":1,"default_action":"deny","rules":[{"id":"r","action":"permit","domains":["a.com"]}]}`,
			[]string{"action"},
		},
		{
			"域名、IP、端口全为空",
			`{"version":1,"default_action":"deny","rules":[{"id":"r","action":"allow"}]}`,
			[]string{"不能同时为空"},
		},
		{
			"畸形域名与通配位置",
			`{"version":1,"default_action":"deny","rules":[{"id":"r","action":"allow","domains":["a..com","foo.*.com",".", "bad name.com"]}]}`,
			[]string{"domains[0]", "domains[1]", "domains[2]", "domains[3]"},
		},
		{
			"非法 IP/CIDR 与端口区间",
			`{"version":1,"default_action":"deny","rules":[
				{"id":"r","action":"allow","ips":["999.1.1.1","10.0.0.0/400"],"ports":[0,"9000-8000",70000]}
			]}`,
			[]string{"ips[0]", "ips[1]", "ports[0]", "ports[1]", "ports[2]"},
		},
		{
			"重复域名/IP/端口均报错",
			`{"version":1,"default_action":"deny","rules":[
				{"id":"r","action":"allow","domains":["a.com","a.com"],"ips":["10.0.0.1","10.0.0.1"],"ports":[80,80]}
			]}`,
			[]string{"domains[1]", "ips[1]", "ports[1]"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.json))
			if err == nil {
				t.Fatalf("期望加载失败，却成功了")
			}
			le, ok := err.(*LoadError)
			if !ok {
				t.Fatalf("期望 *LoadError，实际 %T: %v", err, err)
			}
			msg := le.Error()
			for _, sub := range tc.wantSub {
				if !strings.Contains(msg, sub) {
					t.Errorf("错误原因缺少 %q；完整错误:\n%s", sub, msg)
				}
			}
			t.Logf("如预期被整体拒绝，共 %d 处可区分原因", len(le.Reasons))
		})
	}
}

func TestParseValidPolicy(t *testing.T) {
	p, err := Parse([]byte(`{
		"version":1,"default_action":"deny",
		"rules":[
			{"id":"a","action":"allow","domains":["example.com","*.example.org",".cdn.net"],"ips":["10.0.0.0/8","1.2.3.4"],"ports":[443,"8000-9000"]}
		]}`))
	if err != nil {
		t.Fatalf("合法策略被拒绝: %v", err)
	}
	if got := p.Rules[0].Ports; len(got) != 2 || got[1].Start != 8000 || got[1].End != 9000 {
		t.Fatalf("端口区间解析错误: %+v", got)
	}
}

// 业务二：域名语法的匹配语义（精确/子域/单层通配/点前缀仅子域）。
func TestDomainMatching(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "a.example.com", true},
		{"example.com", "a.b.example.com", true},
		{"example.com", "notexample.com", false},
		{"*.example.org", "a.example.org", true},
		{"*.example.org", "a.b.example.org", false},
		{"*.example.org", "example.org", false},
		{".cdn.net", "cdn.net", false},
		{".cdn.net", "x.cdn.net", true},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"->"+tc.host, func(t *testing.T) {
			m, err := compileDomain(tc.pattern)
			if err != nil {
				t.Fatalf("编译 %q 失败: %v", tc.pattern, err)
			}
			got, _ := m.matches(tc.host)
			if got != tc.want {
				t.Errorf("%s 匹配 %s = %v，期望 %v", tc.pattern, tc.host, got, tc.want)
			}
		})
	}
}

func mustPolicy(t *testing.T, j string) *Policy {
	t.Helper()
	p, err := Parse([]byte(j))
	if err != nil {
		t.Fatalf("策略不合法: %v", err)
	}
	return p
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// 业务三：规则冲突——判定必须唯一，且能说明生效规则。
func TestConflictResolution(t *testing.T) {
	const base = `{"version":1,"default_action":"deny","rules":[
		{"id":"allow-domain","action":"allow","domains":["app.example.com"],"ports":[443]},
		{"id":"deny-cidr","action":"deny","ips":["203.0.113.0/24"]},
		{"id":"deny-port","action":"deny","domains":["app.example.com"],"ports":[8443]}
	]}`
	p := mustPolicy(t, base)

	// 域名允许，但解析地址落入拒绝 CIDR：IP 优先级高于域名，必须拒绝。
	d := p.Evaluate(EvalRequest{Host: "app.example.com", Port: 443, IPs: []netip.Addr{addr("203.0.113.9")}})
	if d.Allowed {
		t.Fatalf("解析地址命中 deny CIDR 时必须拒绝")
	}
	if d.Winner == nil || d.Winner.RuleID != "deny-cidr" {
		t.Fatalf("生效规则应为 deny-cidr，实际 %+v", d.Winner)
	}
	if len(d.AllMatched) != 2 {
		t.Fatalf("应有 2 条规则参与匹配，实际 %d；说明: %s", len(d.AllMatched), d.Explanation)
	}
	t.Logf("域名允许但 IP 拒绝 -> %s", d.Explanation)

	// 解析到允许范围外的地址：域名规则放行。
	d = p.Evaluate(EvalRequest{Host: "app.example.com", Port: 443, IPs: []netip.Addr{addr("198.51.100.7")}})
	if !d.Allowed || d.Winner.RuleID != "allow-domain" {
		t.Fatalf("应被 allow-domain 放行，实际 %+v", d.Winner)
	}

	// 端口冲突：同域名不同端口规则，8443 被专门拒绝。
	d = p.Evaluate(EvalRequest{Host: "app.example.com", Port: 8443, IPs: []netip.Addr{addr("198.51.100.7")}})
	if d.Allowed || d.Winner.RuleID != "deny-port" {
		t.Fatalf("8443 应被 deny-port 拒绝，实际 %+v", d.Winner)
	}
}

// 同优先级冲突：声明顺序靠前的唯一胜出（first-match-wins），结论确定。
func TestConflictSamePrecedenceFirstWins(t *testing.T) {
	p := mustPolicy(t, `{"version":1,"default_action":"deny","rules":[
		{"id":"first-deny","action":"deny","domains":["x.com"]},
		{"id":"second-allow","action":"allow","domains":["x.com"]}
	]}`)
	d := p.Evaluate(EvalRequest{Host: "x.com", Port: 443, IPs: []netip.Addr{addr("1.1.1.1")}})
	if d.Allowed || d.Winner.RuleID != "first-deny" {
		t.Fatalf("同优先级时先声明规则应唯一胜出，实际 %+v", d.Winner)
	}

	// 调换声明顺序后结论应相反，证明判定确定且可复现。
	p2 := mustPolicy(t, `{"version":1,"default_action":"deny","rules":[
		{"id":"first-allow","action":"allow","domains":["x.com"]},
		{"id":"second-deny","action":"deny","domains":["x.com"]}
	]}`)
	d2 := p2.Evaluate(EvalRequest{Host: "x.com", Port: 443, IPs: []netip.Addr{addr("1.1.1.1")}})
	if !d2.Allowed || d2.Winner.RuleID != "first-allow" {
		t.Fatalf("调换顺序后应放行，实际 %+v", d2.Winner)
	}
}

func TestDefaultActionAndPorts(t *testing.T) {
	// 默认放行 + 端口精确拒绝
	p := mustPolicy(t, `{"version":1,"default_action":"allow","rules":[
		{"id":"block-22","action":"deny","ports":[22]}
	]}`)
	d := p.Evaluate(EvalRequest{Host: "anything", Port: 22, IPs: []netip.Addr{addr("8.8.8.8")}})
	if d.Allowed || d.Winner.RuleID != "block-22" {
		t.Fatalf("22 端口应被拒绝")
	}
	d = p.Evaluate(EvalRequest{Host: "anything", Port: 80, IPs: []netip.Addr{addr("8.8.8.8")}})
	if !d.Allowed || d.Winner != nil {
		t.Fatalf("80 端口应走默认 allow")
	}
}
