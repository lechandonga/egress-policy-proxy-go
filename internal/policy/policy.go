package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Action 是规则或默认动作。
type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// PortSpec 表示一个端口选择器：单端口或闭区间 [Start, End]。
type PortSpec struct {
	Start uint16
	End   uint16
	raw   string
}

func (p PortSpec) contains(port uint16) bool {
	return port >= p.Start && port <= p.End
}

func (p PortSpec) String() string {
	if p.Start == p.End {
		return fmt.Sprintf("%d", p.Start)
	}
	return fmt.Sprintf("%d-%d", p.Start, p.End)
}

// Rule 是一条出口策略规则。
type Rule struct {
	Index   int        `json:"-"`
	ID      string     `json:"id"`
	Action  Action     `json:"action"`
	Domains []string   `json:"domains,omitempty"`
	IPs     []string   `json:"ips,omitempty"`
	Ports   []PortSpec `json:"ports,omitempty"`

	matchers domainMatchers
	prefixes []netip.Prefix
}

// Policy 是一份完整策略。
type Policy struct {
	Version       int     `json:"version"`
	DefaultAction Action  `json:"default_action"`
	Rules         []*Rule `json:"rules"`
}

// LoadError 汇总一次策略加载中所有可区分的错误原因。
type LoadError struct {
	Reasons []string
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("策略加载失败（共 %d 处错误）:\n  - %s",
		len(e.Reasons), strings.Join(e.Reasons, "\n  - "))
}

func loadError(format string, args ...any) error {
	return &LoadError{Reasons: []string{fmt.Sprintf(format, args...)}}
}

func appendReason(err error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if le, ok := err.(*LoadError); ok {
		le.Reasons = append(le.Reasons, msg)
		return le
	}
	return &LoadError{Reasons: []string{msg}}
}

// LoadFile 从文件读取并整体校验策略；任何一处非法都返回 *LoadError。
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取策略文件失败: %w", err)
	}
	return Parse(data)
}

// Parse 解析并整体校验策略 JSON。未知字段、畸形值都会显式报错，绝不静默忽略。
func Parse(data []byte) (*Policy, error) {
	var p Policy
	var loadErr error

	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, loadError("JSON 语法/字段错误: %v", err)
	}
	if dec.More() {
		loadErr = appendReason(loadErr, "策略文件在单个 JSON 对象后还存在多余内容")
	}

	if p.Version != 1 {
		loadErr = appendReason(loadErr, "不支持的策略版本 version=%d（当前仅支持 1）", p.Version)
	}
	switch p.DefaultAction {
	case Allow, Deny:
	default:
		loadErr = appendReason(loadErr, "default_action 必须是 allow 或 deny，实际为 %q", p.DefaultAction)
	}

	seenIDs := make(map[string]int)
	for i, r := range p.Rules {
		if r == nil {
			loadErr = appendReason(loadErr, "rules[%d] 不能为空", i)
			continue
		}
		r.Index = i
		where := fmt.Sprintf("rules[%d]", i)

		if strings.TrimSpace(r.ID) == "" {
			loadErr = appendReason(loadErr, "%s.id 不能为空", where)
		} else if prev, ok := seenIDs[r.ID]; ok {
			loadErr = appendReason(loadErr, "%s.id=%q 与 rules[%d] 重复，规则 id 必须唯一", where, r.ID, prev)
		} else {
			seenIDs[r.ID] = i
		}

		switch r.Action {
		case Allow, Deny:
		default:
			loadErr = appendReason(loadErr, "%s(%s).action 必须是 allow 或 deny，实际为 %q", where, r.ID, r.Action)
		}

		if len(r.Domains) == 0 && len(r.IPs) == 0 && len(r.Ports) == 0 {
			loadErr = appendReason(loadErr, "%s(%s) domains、ips、ports 不能同时为空，规则必须有匹配对象", where, r.ID)
		}

		domSeen := make(map[string]int)
		for j, d := range r.Domains {
			m, err := compileDomain(d)
			if err != nil {
				loadErr = appendReason(loadErr, "%s(%s).domains[%d] %q 非法: %v", where, r.ID, j, d, err)
				continue
			}
			if prev, ok := domSeen[d]; ok {
				loadErr = appendReason(loadErr, "%s(%s).domains[%d] %q 与 domains[%d] 重复", where, r.ID, j, d, prev)
			} else {
				domSeen[d] = j
			}
			r.matchers = append(r.matchers, m)
		}

		ipSeen := make(map[string]int)
		for j, raw := range r.IPs {
			addr, err := netip.ParseAddr(raw)
			var pref netip.Prefix
			if err == nil {
				pref = netip.PrefixFrom(addr.Unmap(), addr.BitLen())
			} else {
				pref, err = netip.ParsePrefix(raw)
				if err != nil {
					loadErr = appendReason(loadErr, "%s(%s).ips[%d] %q 既不是合法 IP 也不是合法 CIDR: %v",
						where, r.ID, j, raw, firstLine(err))
					continue
				}
				pref = pref.Masked()
			}
			key := pref.String()
			if prev, ok := ipSeen[key]; ok {
				loadErr = appendReason(loadErr, "%s(%s).ips[%d] %s 与 ips[%d] 重复", where, r.ID, j, key, prev)
			} else {
				ipSeen[key] = j
			}
			r.prefixes = append(r.prefixes, pref)
		}

		portSeen := make(map[string]int)
		for j, ps := range r.Ports {
			if ps.Start == 0 || ps.End == 0 {
				loadErr = appendReason(loadErr, "%s(%s).ports[%d] %q 端口必须在 1-65535 之间",
					where, r.ID, j, ps.raw)
				continue
			}
			if ps.Start > ps.End {
				loadErr = appendReason(loadErr, "%s(%s).ports[%d] %q 区间起点不能大于终点",
					where, r.ID, j, ps.raw)
				continue
			}
			key := ps.String()
			if prev, ok := portSeen[key]; ok {
				loadErr = appendReason(loadErr, "%s(%s).ports[%d] %s 与 ports[%d] 重复",
					where, r.ID, j, key, prev)
			} else {
				portSeen[key] = j
			}
		}
	}

	if loadErr != nil {
		return nil, loadErr
	}
	return &p, nil
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// UnmarshalJSON 让端口同时支持数字（443）与字符串区间（"8000-9000"）。
func (p *PortSpec) UnmarshalJSON(data []byte) error {
	p.raw = strings.Trim(string(data), `"`)
	var single uint64
	if err := json.Unmarshal(data, &single); err == nil {
		if single > 65535 {
			// 保留零值与原始文本，交由整体校验报告，避免单条畸形值中断整份解析。
			return nil
		}
		p.Start = uint16(single)
		p.End = p.Start
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New("端口必须是数字或形如 \"8000-9000\" 的字符串")
	}
	p.raw = s
	parts := strings.Split(s, "-")
	switch len(parts) {
	case 1:
		v, err := parsePortToken(parts[0])
		if err != nil {
			return err
		}
		p.Start, p.End = v, v
	case 2:
		start, err := parsePortToken(parts[0])
		if err != nil {
			return nil
		}
		end, err := parsePortToken(parts[1])
		if err != nil {
			return nil
		}
		p.Start, p.End = start, end
	default:
		return fmt.Errorf("端口区间 %q 格式非法，应为 起始-结束", s)
	}
	return nil
}

func parsePortToken(t string) (uint16, error) {
	var v uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &v); err != nil {
		return 0, fmt.Errorf("端口 %q 不是数字", t)
	}
	if v == 0 || v > 65535 {
		return 0, fmt.Errorf("端口 %d 超出 1-65535", v)
	}
	return uint16(v), nil
}

// SortedRules 仅用于稳定输出。
func (p *Policy) SortedRules() []*Rule {
	out := make([]*Rule, len(p.Rules))
	copy(out, p.Rules)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}
