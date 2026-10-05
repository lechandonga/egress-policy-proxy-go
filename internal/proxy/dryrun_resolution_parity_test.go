package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/lechandonga/egress-policy-proxy-go/internal/admin"
)

// TestDryRunWithoutAddrParity drives the REAL admin /evaluate handler with
// the same injected offline resolver the proxy uses. For every case the
// dry-run verdict (no addr => actual resolution) must match the real
// forwarded request; dry-runs must leave traffic counters untouched and
// must never dial the upstream.
func TestDryRunWithoutAddrParity(t *testing.T) {
	h := newHarness(t, baseRules)

	adminSrv := httptest.NewServer((&admin.Server{
		Store:    h.store,
		Counters: h.counters,
		Resolver: h.resolver,
	}).Handler())
	t.Cleanup(adminSrv.Close)

	cases := []struct {
		name       string
		target     string
		wantAllow  bool
		wantRule   string
		wantStatus int
	}{
		{"allowed", "http://upstream.test:" + h.portOf(h.upstream) + "/", true, "allow-upstream", 200},
		{"denied by domain", "http://forbidden.test:" + h.portOf(h.upstream) + "/", false, "deny-domain", 403},
		{"denied via resolved ip", "http://rebind.test:443/", false, "deny-203", 403},
		{"default deny resolvable host", "http://slow.test:80/", false, "", 403},
	}

	before := h.counters.Snapshot().Total

	for _, tc := range cases {
		t.Run(tc.name+" dry-run matches forwarding", func(t *testing.T) {
			u := mustURL(t, tc.target)
			port := portOfURL(t, u)

			resp, err := http.Get(adminSrv.URL + "/evaluate?host=" + u.Hostname() + "&port=" + strconv.Itoa(int(port)))
			if err != nil {
				t.Fatal(err)
			}
			var m struct {
				Allowed     bool   `json:"allowed"`
				WinningRule string `json:"winning_rule"`
				DefaultDeny bool   `json:"default_deny"`
				Version     string `json:"version"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
				t.Fatalf("decode: %v (status %d)", err, resp.StatusCode)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("dry-run status=%d", resp.StatusCode)
			}
			if m.Allowed != tc.wantAllow {
				t.Fatalf("dry-run allowed=%v real=%v", m.Allowed, tc.wantAllow)
			}
			if m.WinningRule != tc.wantRule {
				t.Fatalf("dry-run rule=%q real=%q", m.WinningRule, tc.wantRule)
			}

			// Now the real request through the proxy.
			status, hdr, _ := proxyGet(t, h.proxyClient(), tc.target)
			if status != tc.wantStatus {
				t.Fatalf("real status=%d want %d", status, tc.wantStatus)
			}
			if !tc.wantAllow && hdr.Get("X-Egress-Rule") != tc.wantRule {
				t.Fatalf("real rule header=%q want %q", hdr.Get("X-Egress-Rule"), tc.wantRule)
			}
		})
	}

	// NXDOMAIN: real forwarding records a resolve failure; the dry-run must
	// report a 502 with resolve_nxdomain rather than any allow/deny verdict.
	t.Run("nxdomain dry-run is 502", func(t *testing.T) {
		resp, err := http.Get(adminSrv.URL + "/evaluate?host=nxdomain.test&port=443")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("want 502, got %d: %s", resp.StatusCode, body)
		}
	})

	// Exactly one counted request per policy case; dry-runs added nothing.
	after := h.counters.Snapshot().Total
	if after-before != uint64(len(cases)) {
		t.Fatalf("dry-run polluted counters: before=%d after=%d", before, after)
	}
}
