package policy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

// ResolveError marks a name-resolution failure surfaced by
// AdjudicateRequest. Callers that need to distinguish NXDOMAIN from a
// resolver failure inspect their own resolver error type against the
// wrapped error (via errors.As/Unwrap).
type ResolveError struct {
	Host string
	Err  error
}

// Error renders as "resolve <host>: <detail>". When the wrapped resolver
// error already carries that exact prefix (the resolver package does), it
// is passed through unchanged instead of being doubled.
func (e *ResolveError) Error() string {
	msg := e.Err.Error()
	if strings.HasPrefix(msg, "resolve "+e.Host+":") {
		return msg
	}
	return "resolve " + e.Host + ": " + msg
}

func (e *ResolveError) Unwrap() error { return e.Err }

// AsResolveError reports whether err is (or wraps) a *ResolveError.
func AsResolveError(err error) (*ResolveError, bool) {
	var re *ResolveError
	if errors.As(err, &re) {
		return re, true
	}
	return nil, false
}

// NameResolver is the resolution capability AdjudicateRequest needs. The
// resolver package implements it, and so do the offline test doubles.
type NameResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// AdjudicateRequest resolves host the same way real forwarding does and
// evaluates the resulting tuple. It is the single shared entry point used
// by the proxy (before dialing) and by the dry-run /evaluate endpoint, so
// trial verdicts and real verdicts cannot drift:
//
//   - a literal-IP host is evaluated as an address-only request (host
//     becomes "", one address);
//   - when assumedIPs is empty host is resolved via res, so a domain
//     allowed by name but resolving into a deny CIDR is denied in a
//     dry-run exactly as it is when forwarding;
//   - when assumedIPs is non-empty it stands in for resolution ("suppose
//     the name resolved to these addresses") and res is never called;
//   - among several addresses the FIRST denied one decides the whole
//     result; a resolution failure or an empty answer is returned as
//     *ResolveError without evaluating the policy.
func AdjudicateRequest(ctx context.Context, snap *Policy, res NameResolver, host string, port uint16, assumedIPs []netip.Addr) (Adjudication, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return snap.Adjudicate("", port, []netip.Addr{addr.Unmap()}), nil
	}

	ips := make([]netip.Addr, 0, len(assumedIPs))
	for _, a := range assumedIPs {
		ips = append(ips, a.Unmap())
	}

	if len(ips) == 0 {
		addrs, err := res.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return Adjudication{}, &ResolveError{Host: host, Err: err}
		}
		if len(addrs) == 0 {
			return Adjudication{}, &ResolveError{
				Host: host,
				Err:  errors.New("resolver returned no addresses for " + host),
			}
		}
		for _, a := range addrs {
			ips = append(ips, a.Unmap())
		}
	}

	return snap.Adjudicate(host, port, ips), nil
}
