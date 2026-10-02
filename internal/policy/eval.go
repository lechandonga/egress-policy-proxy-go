package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// EvalRequest 是一次出口连接的判定输入。
// Host 为规范化后的小写域名或 IP 字面量；IPs 为解析得到的全部地址（IP 字面量时为其自身）。
type EvalRequest struct {
	Host string
	Port uint16
	IPs  []netip.Addr
	IsIP bool
}

// MatchedRule 描述一条参与匹配的规则及其命中细节。
type MatchedRule struct {
	RuleID     string
	Action     Action
	DomainHit  string
	IPHit      string
	Precidence string
	rank       rank
	order      int
}

// Decision 是唯一判定结果。
type Decision struct {
	Allowed     bool
	Action      Action
	Winner      *MatchedRule
	AllMatched  []MatchedRule
	Explanation string
}

// rank 是规则冲突时的优先级：IP/CIDR 命中 > 域名命中 > 仅端口；
// 同优先级下，声明顺序靠前的规则唯一胜出（first-match-wins）。
type rank struct {
	ipRank     int // 3=IP 精确, 2=CIDR, 0=未命中 IP
	domainRank int // 2=精确, 1=子域/通配, 0=未命中域名
	portRank   int // 1=端口命中（规则声明了 ports 且命中）, 0 也合法（规则未限定端口）
	order      int
}

// better 报告 a 是否唯一优先于 b。
func (a rank) betterThan(b rank) bool {
	if a.ipRank != b.ipRank {
		return a.ipRank > b.ipRank
	}
	if a.domainRank != b.domainRank {
		return a.domainRank > b.domainRank
	}
	if a.portRank != b.portRank {
		return a.portRank > b.portRank
	}
	return a.order < b.order
}

func rankLabel(r rank) string {
	return fmt.Sprintf("ip=%d/domain=%d/port=%d/index=%d", r.ipRank, r.domainRank, r.portRank, r.order)
}

// Evaluate 对一次连接请求执行唯一判定。
func (p *Policy) Evaluate(req EvalRequest) *Decision {
	var matched []MatchedRule

	for _, r := range p.Rules {
		hit, ok := r.evalRule(req)
		if !ok {
			continue
		}
		matched = append(matched, hit)
	}

	// 稳定排序仅用于解释输出；胜出者用 rank.betterThan 唯一确定。
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].rank.betterThan(matched[j].rank)
	})

	d := &Decision{AllMatched: matched}
	if len(matched) == 0 {
		d.Action = p.DefaultAction
		d.Allowed = p.DefaultAction == Allow
		d.Explanation = fmt.Sprintf("无任何规则匹配 host=%s port=%d，采用默认动作 %s",
			req.Host, req.Port, p.DefaultAction)
		return d
	}

	winner := matched[0]
	d.Winner = &winner
	d.Action = winner.Action
	d.Allowed = winner.Action == Allow
	d.Explanation = fmt.Sprintf("host=%s port=%d 共 %d 条规则匹配；生效规则 %s（动作 %s，优先级 %s）",
		req.Host, req.Port, len(matched), winner.RuleID, winner.Action, winner.Precidence)
	return d
}

func (r *Rule) evalRule(req EvalRequest) (MatchedRule, bool) {
	m := MatchedRule{RuleID: r.ID, Action: r.Action, order: r.Index}

	domainMatched := len(r.matchers) == 0
	for _, dm := range r.matchers {
		if ok, why := dm.matches(req.Host); ok {
			domainMatched = true
			m.DomainHit = why
			m.rank.domainRank = domainRankOf(why)
			break
		}
	}

	ipMatched := len(r.prefixes) == 0
	for _, pref := range r.prefixes {
		for _, addr := range req.IPs {
			u := addr.Unmap()
			if pref.Contains(u) {
				ipMatched = true
				m.IPHit = fmt.Sprintf("解析地址 %s 命中 %s", u, pref.String())
				if pref.IsSingleIP() {
					m.rank.ipRank = 3
				} else {
					m.rank.ipRank = 2
				}
				break
			}
		}
		if ipMatched && len(r.prefixes) > 0 {
			break
		}
	}

	portMatched := true
	if len(r.Ports) > 0 {
		portMatched = false
		for _, ps := range r.Ports {
			if ps.contains(req.Port) {
				portMatched = true
				m.rank.portRank = 1
				break
			}
		}
	}

	// 规则同时声明了域名与 IP 时，二者都必须命中（AND 语义）。
	needDomain := len(r.matchers) > 0
	needIP := len(r.prefixes) > 0
	if (needDomain && !domainMatched) || (needIP && !ipMatched) || !portMatched {
		return m, false
	}
	m.rank.order = r.Index
	m.Precidence = rankLabel(m.rank)
	return m, true
}

func domainRankOf(why string) int {
	if strings.Contains(why, "精确") {
		return 2
	}
	return 1
}
