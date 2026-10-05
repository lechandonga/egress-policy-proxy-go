package policy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type stubResolver struct {
	addrs map[string][]netip.Addr
	err   error
	calls int
}

func (s *stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if a, ok := s.addrs[host]; ok {
		return append([]netip.Addr(nil), a...), nil
	}
	return nil, errors.New("no such host")
}

func adjPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := Decode([]byte(`{"rules":[
	  {"id":"allow-names","action":"allow","domains":["*.test"]},
	  {"id":"deny-203","action":"deny","cidrs":["203.0.113.0/24"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdjudicateRequestWithoutAssumedAddrsResolves(t *testing.T) {
	p := adjPolicy(t)
	res := &stubResolver{addrs: map[string][]netip.Addr{
		"clean.test":  {netip.MustParseAddr("198.51.100.1")},
		"rebind.test": {netip.MustParseAddr("203.0.113.7")},
		"multi.test": {
			netip.MustParseAddr("198.51.100.2"),
			netip.MustParseAddr("203.0.113.9"),
		},
	}}
	ctx := context.Background()

	adj, err := AdjudicateRequest(ctx, p, res, "clean.test", 443, nil)
	if err != nil || !adj.Allowed || adj.WinningRule != "allow-names" {
		t.Fatalf("clean: %+v err=%v", adj, err)
	}

	// Name allowed but the resolved address hits a deny range => denied.
	adj, err = AdjudicateRequest(ctx, p, res, "rebind.test", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	if adj.Allowed || adj.WinningRule != "deny-203" {
		t.Fatalf("rebind must be denied by resolved ip: %+v", adj)
	}

	// Any one of several resolved addresses denied => whole denied.
	adj, err = AdjudicateRequest(ctx, p, res, "multi.test", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	if adj.Allowed || adj.WinningRule != "deny-203" || len(adj.Addresses) != 2 {
		t.Fatalf("multi: %+v", adj)
	}
}

func TestAdjudicateRequestWithAssumedAddrsSkipsResolver(t *testing.T) {
	p := adjPolicy(t)
	res := &stubResolver{}
	ctx := context.Background()

	// Assumed clean address, even though no resolution exists.
	adj, err := AdjudicateRequest(ctx, p, res, "rebind.test", 443,
		[]netip.Addr{netip.MustParseAddr("198.51.100.5")})
	if err != nil || !adj.Allowed {
		t.Fatalf("assumed clean: %+v %v", adj, err)
	}

	// Any bad assumed address denies; first denied address wins.
	adj, err = AdjudicateRequest(ctx, p, res, "rebind.test", 443, []netip.Addr{
		netip.MustParseAddr("198.51.100.5"),
		netip.MustParseAddr("203.0.113.5"),
	})
	if err != nil || adj.Allowed || adj.WinningRule != "deny-203" {
		t.Fatalf("mixed assumed: %+v %v", adj, err)
	}

	if res.calls != 0 {
		t.Fatalf("resolver must not be consulted with assumed addrs, calls=%d", res.calls)
	}
}

func TestAdjudicateRequestLiteralIP(t *testing.T) {
	p := adjPolicy(t)
	res := &stubResolver{}

	adj, err := AdjudicateRequest(context.Background(), p, res, "203.0.113.9", 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	if adj.Allowed || adj.WinningRule != "deny-203" || adj.Host != "" {
		t.Fatalf("literal ip: %+v", adj)
	}
	if res.calls != 0 {
		t.Fatalf("literal ip must not be resolved")
	}
}

func TestAdjudicateRequestResolverFailures(t *testing.T) {
	p := adjPolicy(t)

	rerr := errors.New("boom")
	_, err := AdjudicateRequest(context.Background(), p, &stubResolver{err: rerr}, "nope.test", 443, nil)
	re, ok := AsResolveError(err)
	if !ok {
		t.Fatalf("want ResolveError, got %v", err)
	}
	if re.Host != "nope.test" || !errors.Is(err, rerr) {
		t.Fatalf("wrapped error wrong: %+v", re)
	}

	// Empty answer is also a resolution failure.
	_, err = AdjudicateRequest(context.Background(), p, &stubResolver{
		addrs: map[string][]netip.Addr{"empty.test": {}},
	}, "empty.test", 443, nil)
	if _, ok := AsResolveError(err); !ok {
		t.Fatalf("empty answer must be ResolveError, got %v", err)
	}
}
