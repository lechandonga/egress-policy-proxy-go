package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// DNSError 把解析失败与其他错误区分开。
type DNSError struct {
	Host string
	Err  error
}

func (e *DNSError) Error() string { return "解析域名 " + e.Host + " 失败: " + e.Err.Error() }
func (e *DNSError) Unwrap() error { return e.Err }

// Resolver 抽象域名解析，便于在不依赖外部网络的情况下注入假解析结果。
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// netResolver 使用系统解析器，但带明确超时。
type netResolver struct{ timeout time.Duration }

func NewNetResolver(timeout time.Duration) Resolver {
	return &netResolver{timeout: timeout}
}

func (r *netResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, &DNSError{Host: host, Err: err}
	}
	if len(addrs) == 0 {
		return nil, &DNSError{Host: host, Err: errors.New("解析结果为空")}
	}
	return addrs, nil
}

// staticResolver 是测试用内存解析表。
type staticResolver struct {
	hosts map[string][]netip.Addr
	err   error
	delay time.Duration
}

func (s *staticResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, &DNSError{Host: host, Err: ctx.Err()}
		}
	}
	if s.err != nil {
		return nil, &DNSError{Host: host, Err: s.err}
	}
	addrs, ok := s.hosts[host]
	if !ok || len(addrs) == 0 {
		return nil, &DNSError{Host: host, Err: errors.New("no such host")}
	}
	out := make([]netip.Addr, len(addrs))
	copy(out, addrs)
	return out, nil
}
