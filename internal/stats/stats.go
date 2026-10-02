package stats

import (
	"sync"
	"sync/atomic"
)

// Outcome 是请求的终态分类，彼此互斥。
type Outcome string

const (
	OutcomeAllowed      Outcome = "allowed"          // 策略放行且转发成功
	OutcomeDeniedPolicy Outcome = "denied_policy"    // 策略拒绝
	OutcomeDNSFailed    Outcome = "dns_failed"       // 域名解析失败
	OutcomeUpstreamFail Outcome = "upstream_fail"    // 上游不可达（连接被拒/重置）
	OutcomeUpstreamTO   Outcome = "upstream_timeout" // 上游超时
	OutcomeBadRequest   Outcome = "bad_request"      // 请求本身畸形（无法取得 host/port）
	OutcomeClientGone   Outcome = "client_gone"      // 客户端中途断开（不计入放行/拒绝）
)

type counters struct {
	total atomic.Int64
	by    [6]atomic.Int64
	hits  sync.Map // ruleID(string) -> *atomic.Int64
}

// Stats 是并发安全的统计器。每个请求终态只计入一个互斥分类，
// 因此不会重复计数；统计与判定在同一终态路径完成，不会漏计。
type Stats struct {
	c counters
}

var outcomes = []Outcome{
	OutcomeAllowed,
	OutcomeDeniedPolicy,
	OutcomeDNSFailed,
	OutcomeUpstreamFail,
	OutcomeUpstreamTO,
	OutcomeBadRequest,
}

// Record 记录一次终态。ruleID 为空表示无生效规则（默认动作/错误类）。
func (s *Stats) Record(o Outcome, ruleID string) {
	s.c.total.Add(1)
	for i, x := range outcomes {
		if x == o {
			s.c.by[i].Add(1)
			break
		}
	}
	if ruleID != "" {
		v, _ := s.c.hits.LoadOrStore(ruleID, new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
	}
}

// Snapshot 是某一时刻的一致快照。
type Snapshot struct {
	Total     int64            `json:"total"`
	ByOutcome map[string]int64 `json:"by_outcome"`
	RuleHits  map[string]int64 `json:"rule_hits"`
	Allowed   int64            `json:"allowed"`
	Denied    int64            `json:"denied"`
}

func (s *Stats) Snapshot() Snapshot {
	snap := Snapshot{
		Total:     s.c.total.Load(),
		ByOutcome: map[string]int64{},
		RuleHits:  map[string]int64{},
	}
	for i, o := range outcomes {
		v := s.c.by[i].Load()
		snap.ByOutcome[string(o)] = v
	}
	s.c.hits.Range(func(k, v any) bool {
		snap.RuleHits[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	snap.Allowed = snap.ByOutcome[string(OutcomeAllowed)]
	snap.Denied = snap.Total - snap.Allowed - snap.ByOutcome[string(OutcomeClientGone)]

	// 稳定输出
	return snap
}
