package stats

import (
	"sync"
	"testing"
)

// 业务七：统计互斥分类、并发安全、规则命中不重不漏。
func TestStatsConcurrent(t *testing.T) {
	st := &Stats{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				switch (id + j) % 4 {
				case 0:
					st.Record(OutcomeAllowed, "r-allow")
				case 1:
					st.Record(OutcomeDeniedPolicy, "r-deny")
				case 2:
					st.Record(OutcomeDNSFailed, "")
				default:
					st.Record(OutcomeAllowed, "r-allow")
				}
			}
		}(i)
	}
	wg.Wait()

	snap := st.Snapshot()
	if snap.Total != 5000 {
		t.Fatalf("total=%d，期望 5000（存在漏计或重计）", snap.Total)
	}
	sum := int64(0)
	for _, v := range snap.ByOutcome {
		sum += v
	}
	// client_gone 未使用，其余互斥分类之和应等于总数
	if sum != snap.Total {
		t.Fatalf("互斥分类之和 %d != total %d", sum, snap.Total)
	}
	if snap.RuleHits["r-allow"] != 2500 || snap.RuleHits["r-deny"] != 1250 {
		t.Fatalf("规则命中统计错误: %+v", snap.RuleHits)
	}
}
