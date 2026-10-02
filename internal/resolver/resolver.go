package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// ErrorClass categorizes resolution outcomes so callers can distinguish
// "name does not exist" from "resolver failed/timed out".
type ErrorClass string

const (
	ClassNXDOMAIN ErrorClass = "nxdomain"
	ClassFailure  ErrorClass = "resolver_failure"
)

// Error is a classified name-resolution failure.
type Error struct {
	Class ErrorClass
	Host  string
	Err   error
}

func (e *Error) Error() string { return "resolve " + e.Host + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Resolver resolves a name to addresses. It is an interface so tests can
// run fully offline and deterministically inject DNS rebinding/failures.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Std uses the net package resolver.
type Std struct{ R *net.Resolver }

func (s Std) resolver() *net.Resolver {
	if s.R != nil {
		return s.R
	}
	return net.DefaultResolver
}

func (s Std) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, err := s.resolver().LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, classify(host, err)
	}
	return addrs, nil
}

func classify(host string, err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return &Error{Class: ClassNXDOMAIN, Host: host, Err: err}
		}
		return &Error{Class: ClassFailure, Host: host, Err: err}
	}
	return &Error{Class: ClassFailure, Host: host, Err: err}
}

// Map is an offline, deterministic resolver for tests.
type Map map[string][]netip.Addr

func (m Map) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if addrs, ok := m[host]; ok {
		return append([]netip.Addr(nil), addrs...), nil
	}
	return nil, &Error{Class: ClassNXDOMAIN, Host: host, Err: errors.New("no such host (test map)")}
}

// Func adapts a function to the Resolver interface.
type Func func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f Func) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}
