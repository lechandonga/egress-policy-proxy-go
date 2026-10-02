package policy

import (
	"fmt"
	"strings"
)

type domainMatcher interface {
	matches(host string) (bool, string)
}

type domainMatchers []domainMatcher

// exactMatcher: 精确域名，如 example.com
type exactMatcher struct{ domain string }

func (m exactMatcher) matches(host string) (bool, string) {
	if host == m.domain {
		return true, fmt.Sprintf("域名精确匹配 %q", m.domain)
	}
	return false, ""
}

// subMatcher: 域及其全部子域，如 .example.com 或 example.com（子域语义）
type subMatcher struct {
	suffix string // 形如 ".example.com"
	raw    string
}

func (m subMatcher) matches(host string) (bool, string) {
	if strings.HasSuffix(host, m.suffix) {
		return true, fmt.Sprintf("域名子域匹配 %q", m.raw)
	}
	return false, ""
}

// wildcardMatcher: 单层通配，如 *.example.com（只匹配 a.example.com，不匹配 a.b.example.com）
type wildcardMatcher struct {
	suffix string // 形如 ".example.com"
	raw    string
}

func (m wildcardMatcher) matches(host string) (bool, string) {
	if !strings.HasSuffix(host, m.suffix) {
		return false, ""
	}
	left := host[:len(host)-len(m.suffix)]
	// 单层标签：不能再含点，且不能为空
	if left != "" && !strings.Contains(left, ".") {
		return true, fmt.Sprintf("域名单层通配匹配 %q", m.raw)
	}
	return false, ""
}

// compileDomain 编译域名字符串。
// 语法：
//   - example.com      ：精确匹配，同时匹配所有子域（含子域与通配需求）
//   - *.example.com    ：单层通配（只匹配一级子域）
//   - .example.com     ：仅子域（不含 example.com 自身）
func compileDomain(d string) (domainMatcher, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return nil, fmt.Errorf("域名不能为空")
	}
	if strings.ContainsAny(d, " /") {
		return nil, fmt.Errorf("域名不能包含空格")
	}
	if strings.HasPrefix(d, "*.") {
		rest := d[2:]
		if err := validatePlainDomain(rest); err != nil {
			return nil, err
		}
		return wildcardMatcher{suffix: "." + rest, raw: d}, nil
	}
	if strings.HasPrefix(d, ".") {
		rest := d[1:]
		if err := validatePlainDomain(rest); err != nil {
			return nil, err
		}
		return subMatcher{suffix: "." + rest, raw: d}, nil
	}
	if err := validatePlainDomain(d); err != nil {
		return nil, err
	}
	// 裸域名同时匹配自身和所有层级子域，用子域匹配器（后缀 .example.com）外加精确匹配。
	return exactAndSubMatcher{exact: exactMatcher{domain: d}, sub: subMatcher{suffix: "." + d, raw: d}}, nil
}

type exactAndSubMatcher struct {
	exact exactMatcher
	sub   subMatcher
}

func (m exactAndSubMatcher) matches(host string) (bool, string) {
	if ok, why := m.exact.matches(host); ok {
		return ok, why
	}
	return m.sub.matches(host)
}

func validatePlainDomain(d string) error {
	if d == "" || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return fmt.Errorf("域名 %q 标签结构非法", d)
	}
	if strings.Contains(d, "*") {
		return fmt.Errorf("域名 %q 中 * 只能作为最左侧单层标签（如 *.example.com）", d)
	}
	for i, label := range strings.Split(d, ".") {
		if label == "" {
			return fmt.Errorf("域名 %q 含空标签", d)
		}
		for _, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return fmt.Errorf("域名 %q 标签 %d 含非法字符 %q", d, i, c)
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("域名 %q 标签 %q 不能以 - 开头或结尾", d, label)
		}
	}
	return nil
}
