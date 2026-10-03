package policy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMalformedPoliciesRejected(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string // expected substring in error
	}{
		{
			"not json", `{not json`, "not valid JSON",
		},
		{
			"unknown field",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"acton":"allow"}]}`,
			"unknown field",
		},
		{
			"missing id",
			`{"rules":[{"action":"allow","domains":["a.test"]}]}`,
			"missing id",
		},
		{
			"duplicate id",
			`{"rules":[{"id":"r","action":"allow","domains":["a.test"]},{"id":"r","action":"deny","domains":["b.test"]}]}`,
			"duplicate rule id",
		},
		{
			"bad action",
			`{"rules":[{"id":"r1","action":"permit","domains":["a.test"]}]}`,
			"action must",
		},
		{
			"empty rules",
			`{"rules":[]}`,
			"at least one rule",
		},
		{
			"rule without constraints",
			`{"rules":[{"id":"r1","action":"allow","ports":[80]}]}`,
			"at least one domain or cidr",
		},
		{
			"bad cidr",
			`{"rules":[{"id":"r1","action":"allow","cidrs":["999.1.1.0/24"]}]}`,
			"invalid cidr",
		},
		{
			"wildcard cidr 0.0.0.0/0 rejected",
			`{"rules":[{"id":"r1","action":"allow","cidrs":["0.0.0.0/0"]}]}`,
			"matches every address",
		},
		{
			"wildcard cidr ::/0 rejected",
			`{"rules":[{"id":"r1","action":"allow","cidrs":["::/0"]}]}`,
			"matches every address",
		},
		{
			"bad domain wildcard position",
			`{"rules":[{"id":"r1","action":"allow","domains":["api.*.com"]}]}`,
			"wildcard only allowed",
		},
		{
			"port zero",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":[0]}]}`,
			"port 0",
		},
		{
			"inverted port range",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":["9000-8000"]}]}`,
			"low > high",
		},
		{
			"port range with extra segment",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":["80-90-100"]}]}`,
			"invalid port range",
		},
		{
			"port range with trailing garbage",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":["80-90x"]}]}`,
			"invalid port range",
		},
		{
			"port range with spaces",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":["80 - 90"]}]}`,
			"invalid port range",
		},
		{
			"port range open ended",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":["80-"]}]}`,
			"invalid port range",
		},
		{
			"port range negative",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":["-5-10"]}]}`,
			"invalid port range",
		},
		{
			"port number too large",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":[70000]}]}`,
			"port must be a number",
		},
		{
			"port string range too large",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test"],"ports":["1-70000"]}]}`,
			"invalid port range",
		},
		{
			"cidr with host bits set is not auto-masked",
			`{"rules":[{"id":"r1","action":"allow","cidrs":["10.0.0.1/24"]}]}`,
			"host bits set",
		},
		{
			"ipv4-mapped ipv6 address rejected",
			`{"rules":[{"id":"r1","action":"allow","cidrs":["::ffff:10.0.0.1"]}]}`,
			"canonical IPv4",
		},
		{
			"ipv4-mapped ipv6 prefix rejected",
			`{"rules":[{"id":"r1","action":"allow","cidrs":["::ffff:10.0.0.0/104"]}]}`,
			"canonical IPv4",
		},
		{
			"zoned address rejected",
			`{"rules":[{"id":"r1","action":"allow","cidrs":["fe80::1%eth0"]}]}`,
			"zone",
		},
		{
			"domain label starts with dash",
			`{"rules":[{"id":"r1","action":"allow","domains":["-bad.test"]}]}`,
			"must not start or end",
		},
		{
			"domain label ends with dash",
			`{"rules":[{"id":"r1","action":"allow","domains":["bad-.test"]}]}`,
			"must not start or end",
		},
		{
			"domain empty label",
			`{"rules":[{"id":"r1","action":"allow","domains":["a..test"]}]}`,
			"invalid domain label",
		},
		{
			"domain underscore rejected",
			`{"rules":[{"id":"r1","action":"allow","domains":["a_b.test"]}]}`,
			"invalid domain",
		},
		{
			"domain with port rejected",
			`{"rules":[{"id":"r1","action":"allow","domains":["a.test:443"]}]}`,
			"invalid domain",
		},
		{
			"wildcard with empty suffix",
			`{"rules":[{"id":"r1","action":"allow","domains":["*."]}]}`,
			"invalid domain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.doc))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !IsLoadError(err) {
				t.Fatalf("expected LoadError classification, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidPolicyDecodesWithPorts(t *testing.T) {
	doc := `{
	  "rules": [
	    {"id":"deny-bad","action":"deny","domains":["*.bad.test"],"ports":[443, "8000-8999"]},
	    {"id":"allow-good","action":"allow","domains":["good.test"],"cidrs":["10.0.0.0/24"]}
	  ]
	}`
	p, err := Decode([]byte(doc))
	if err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(p.Rules))
	}
	r := p.Rules[0]
	if len(r.Ports) != 2 || r.Ports[0] != (PortRange{443, 443}) || r.Ports[1] != (PortRange{8000, 8999}) {
		t.Fatalf("port parsing wrong: %+v", r.Ports)
	}
}

func TestStoreReloadAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	v1 := `{"rules":[{"id":"v1-allow","action":"allow","domains":["v1.test"]}]}`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewStore()
	p1, err := store.LoadFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Broken v2: load must fail and leave v1 active.
	if err := os.WriteFile(path, []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadFile(path); err == nil {
		t.Fatal("broken policy must fail to load")
	} else if !IsLoadError(err) {
		t.Fatalf("want LoadError, got %v", err)
	}
	cur, ok := store.Current()
	if !ok || cur != p1 || cur.Version != p1.Version {
		t.Fatalf("previous policy must stay active after failed reload")
	}

	// Valid v2 swaps atomically.
	v2 := `{"rules":[{"id":"v2-allow","action":"allow","domains":["v2.test"]}]}`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	p2, err := store.LoadFile(path)
	if err != nil {
		t.Fatalf("v2 load: %v", err)
	}
	if p2.Version == p1.Version {
		t.Fatal("version must change after successful reload")
	}
	if cur, _ := store.Current(); cur != p2 {
		t.Fatal("new policy must be active")
	}
}

func TestMissingFileIsIOErrorNotLoadError(t *testing.T) {
	store := NewStore()
	_, err := store.LoadFile(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error")
	}
	if IsLoadError(err) {
		t.Fatalf("missing file must be I/O error, not validation error: %v", err)
	}
}

func TestConcurrentEvaluationNoRace(t *testing.T) {
	p := mustBuild(t, []Rule{
		{ID: "d1", Action: ActionAllow, Domains: []string{"*.a.test"}, Ports: []PortRange{{80, 80}}},
		{ID: "d2", Action: ActionDeny, CIDRs: []string{"10.0.0.0/8"}, Ports: []PortRange{{80, 80}}},
	})
	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "x.a.test"
			ip := addr("10.0.0.1")
			if i%2 == 0 {
				ip = addr("192.0.2.1")
			}
			if i%3 == 0 {
				host = "other.test"
			}
			p.Evaluate(Match{Host: host, IP: ip, Port: 80})
		}(i)
	}
	wg.Wait()
}

// Business: every malformed variant fails the WHOLE reload and the old
// policy keeps serving byte-for-byte; nothing is repaired or defaulted.
func TestInvalidReloadKeepsOldPolicyUntouched(t *testing.T) {
	bad := []string{
		`{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":[0]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["80-90-100"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["80-90x"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":["1-70000"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a.test"],"ports":[70000]}]}`,
		`{"rules":[{"id":"r","action":"allow","cidrs":["10.0.0.1/24"]}]}`,
		`{"rules":[{"id":"r","action":"allow","cidrs":["::ffff:10.0.0.1"]}]}`,
		`{"rules":[{"id":"r","action":"allow","cidrs":["fe80::1%eth0"]}]}`,
		`{"rules":[{"id":"r","action":"allow","cidrs":["0.0.0.0/0"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["-bad.test"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a..test"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a_b.test"]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["*."]}]}`,
		`{"rules":[{"id":"r","action":"allow","domains":["a.*.test"]}]}`,
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	good := `{"rules":[{"id":"good","action":"allow","domains":["good.test"]}]}`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	p0, err := store.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, doc := range bad {
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadFile(path); err == nil {
			t.Fatalf("case %d: invalid policy must fail to load: %s", i, doc)
		} else if !IsLoadError(err) {
			t.Fatalf("case %d: want LoadError, got %v", i, err)
		}
		cur, ok := store.Current()
		if !ok || cur != p0 || cur.Version != p0.Version {
			t.Fatalf("case %d: old policy must stay active and identical", i)
		}
		d := cur.Evaluate(Match{Host: "good.test", Port: 443})
		if !d.Allowed || d.WinningRule != "good" {
			t.Fatalf("case %d: old policy no longer decides correctly: %+v", i, d)
		}
	}
}
