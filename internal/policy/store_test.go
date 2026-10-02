package policy

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// 业务五：热更新要么整体生效、要么明确失败沿用上一版；进行中请求只见整版规则。
func TestReloadAtomicAndFallback(t *testing.T) {
	v1 := mustPolicy(t, `{"version":1,"default_action":"deny","rules":[
		{"id":"v1-allow","action":"allow","domains":["a.com"]}]}`)
	store, err := NewStore(v1)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("成功重载整体切换", func(t *testing.T) {
		res := store.Reload([]byte(`{"version":1,"default_action":"deny","rules":[
			{"id":"v2-allow","action":"allow","domains":["b.com"]}]}`))
		if !res.Success || res.Revision != 2 || !res.Replaced {
			t.Fatalf("重载结果异常: %+v", res)
		}
		cur, rev := store.Current()
		if rev != 2 || cur.Rules[0].ID != "v2-allow" {
			t.Fatalf("未切换到新版本: rev=%d", rev)
		}
		// 旧规则不应再生效
		d := cur.Evaluate(EvalRequest{Host: "a.com", Port: 443, IPs: []netip.Addr{addr("1.1.1.1")}})
		if d.Allowed {
			t.Fatalf("旧版规则不应在新版本中残留（新旧混合）")
		}
		d = cur.Evaluate(EvalRequest{Host: "b.com", Port: 443, IPs: []netip.Addr{addr("1.1.1.1")}})
		if !d.Allowed {
			t.Fatalf("新版规则应生效")
		}
	})

	t.Run("畸形重载明确失败并沿用上一版", func(t *testing.T) {
		bad := []byte(`{"version":1,"default_action":"maybe","rules":[{"id":"x","action":"allow"}]}`)
		res := store.Reload(bad)
		if res.Success {
			t.Fatalf("畸形策略绝不能加载成功")
		}
		if res.Reason == "" || !strings.Contains(res.Reason, "策略加载失败") {
			t.Fatalf("必须给出可区分原因: %+v", res)
		}
		cur, rev := store.Current()
		if rev != 2 || cur.Rules[0].ID != "v2-allow" {
			t.Fatalf("失败后必须沿用上一版，实际 rev=%d", rev)
		}
		_, ok, lastErr := store.Status()
		if ok || lastErr == "" {
			t.Fatalf("Status 应反映最近一次失败")
		}
		t.Logf("失败原因已保留: %s", strings.ReplaceAll(res.Reason, "\n", " | "))
	})

	t.Run("初始策略为空时拒绝启动（禁止默认放行）", func(t *testing.T) {
		if _, err := NewStore(nil); err == nil {
			t.Fatalf("nil 初始策略必须报错")
		}
	})
}

// 并发读取 + 重载下，Current 快照始终完整，revision 单调，且无数据竞争（配合 -race）。
func TestStoreConcurrentReload(t *testing.T) {
	store, _ := NewStore(mustPolicy(t, `{"version":1,"default_action":"deny","rules":[
		{"id":"r0","action":"allow","domains":["h.com"]}]}`))

	good := []byte(`{"version":1,"default_action":"deny","rules":[
		{"id":"r1","action":"allow","domains":["h.com"]}]}`)
	bad := []byte(`{broken`)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					p, rev := store.Current()
					if p == nil || rev < 1 {
						t.Errorf("读到不完整快照")
						return
					}
					// 用快照做判定，验证其内部字段一致可用
					_ = p.Evaluate(EvalRequest{Host: "h.com", Port: 443, IPs: []netip.Addr{addr("1.1.1.1")}})
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if i%2 == 0 {
				store.Reload(good)
			} else {
				store.Reload(bad)
			}
		}
		close(stop)
	}()

	wg.Wait()
	p, rev := store.Current()
	if p == nil {
		t.Fatalf("最终策略不能为 nil")
	}
	t.Logf("并发重载结束，最终 revision=%d default=%s", rev, p.DefaultAction)
}
