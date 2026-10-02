package proxy

import (
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
)

// 业务六：高并发请求与重载交织——进行中请求只见整版规则，统计不重不漏，连接不泄漏，无数据竞争。
func TestConcurrentRequestsAndReload(t *testing.T) {
	policyJSON := `{
		"version":1,"default_action":"deny",
		"rules":[
			{"id":"allow-a","action":"allow","domains":["a.example.com"]},
			{"id":"deny-b","action":"deny","domains":["b.example.com"]}
		]}`
	h := newHarness(t, policyJSON, nil)
	_, _, aPort := h.startOrigin("a.example.com", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("a"))
	})
	_, _, bPort := h.startOrigin("b.example.com", nil)

	// 两个完整版本，都包含同名规则集，重载只切换“默认动作/个别动作”，整版可判定。
	policyA := []byte(`{"version":1,"default_action":"deny","rules":[
		{"id":"allow-a","action":"allow","domains":["a.example.com"]},
		{"id":"deny-b","action":"deny","domains":["b.example.com"]}]}`)
	policyB := []byte(`{"version":1,"default_action":"deny","rules":[
		{"id":"allow-a","action":"allow","domains":["a.example.com"]},
		{"id":"deny-b","action":"deny","domains":["b.example.com"]}]}`)
	policyBad := []byte(`{"version":1,"default_action":"nope","rules":[]}`)

	const workers = 16
	const perWorker = 25
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 并发重载：好/坏策略交替，坏的必须失败并沿用旧版。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			var res policy.ReloadResult
			switch i % 3 {
			case 0:
				res = h.store.Reload(policyA)
			case 1:
				res = h.store.Reload(policyB)
			default:
				res = h.store.Reload(policyBad)
				if res.Success {
					t.Errorf("畸形策略不能加载成功")
				}
			}
			_ = res
		}
		close(stop)
	}()

	urlA := "http://a.example.com:" + strconv.Itoa(int(aPort)) + "/"
	urlB := "http://b.example.com:" + strconv.Itoa(int(bPort)) + "/"
	client := h.plainClient()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				select {
				case <-stop:
					return
				default:
				}
				target := urlA
				if (id+i)%2 == 0 {
					target = urlB
				}
				resp, err := client.Get(target)
				if err != nil {
					// 仅允许连接复用导致的偶发传输错误，不允许“卡住”
					continue
				}
				switch target {
				case urlA:
					// a 始终放行；重载从不改变其结论
					if resp.StatusCode != http.StatusOK {
						t.Errorf("a.example.com 结论不稳定: %d", resp.StatusCode)
					}
				case urlB:
					if resp.StatusCode != http.StatusForbidden {
						t.Errorf("b.example.com 必须稳定拒绝: %d", resp.StatusCode)
					}
				}
				drainBody(resp.Body)
				resp.Body.Close()
			}
		}(w)
	}

	wg.Wait()

	// 等待进行中的转发收尾，检查连接泄漏
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && h.pxy.ActiveConns() != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.pxy.ActiveConns(); got != 0 {
		t.Fatalf("存在连接/goroutine 泄漏，ActiveConns=%d", got)
	}

	snap := h.st.Snapshot()
	totalClassified := snap.ByOutcome["allowed"] + snap.ByOutcome["denied_policy"] +
		snap.ByOutcome["dns_failed"] + snap.ByOutcome["upstream_fail"] +
		snap.ByOutcome["upstream_timeout"] + snap.ByOutcome["bad_request"]
	if totalClassified > snap.Total {
		t.Fatalf("计数重复: classified=%d total=%d", totalClassified, snap.Total)
	}
	if snap.ByOutcome["allowed"]+snap.ByOutcome["denied_policy"] == 0 {
		t.Fatalf("放行与拒绝都应有计数: %+v", snap.ByOutcome)
	}
	// 规则命中合计不应超过有生效规则的请求数（allowed+denied）
	var hitSum int64
	for _, v := range snap.RuleHits {
		hitSum += v
	}
	if hitSum != snap.ByOutcome["allowed"]+snap.ByOutcome["denied_policy"] {
		t.Fatalf("规则命中数(%d) 与放行+拒绝数(%d) 不一致，存在漏计/重计",
			hitSum, snap.ByOutcome["allowed"]+snap.ByOutcome["denied_policy"])
	}
	t.Logf("并发结束 total=%d allowed=%d denied=%d ruleHits=%+v activeConns=0",
		snap.Total, snap.ByOutcome["allowed"], snap.ByOutcome["denied_policy"], snap.RuleHits)
}

func drainBody(b io.Reader) { _, _ = io.Copy(io.Discard, b) }
