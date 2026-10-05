package stats

import (
	"sort"
	"sync"
	"time"
)

// Outcome is the single bucket a request is counted in. Every proxied
// request is counted exactly once, in exactly one bucket.
type Outcome string

const (
	OutcomeAllowed           Outcome = "allowed"             // forwarded and the upstream exchange finished
	OutcomeDeniedPolicy      Outcome = "denied_policy"       // policy verdict deny (incl. default deny)
	OutcomeResolveFailed     Outcome = "resolve_failed"      // NXDOMAIN / resolver failure
	OutcomeUpstreamDial      Outcome = "upstream_dial"       // connection refused / network unreachable
	OutcomeUpstreamIOTimeout Outcome = "upstream_io_timeout" // deadline while talking to upstream
	OutcomeClientError       Outcome = "client_error"        // malformed proxy request
)

// Counters is a goroutine-safe set of request counters. Recording and
// snapshotting are mutually atomic: a Snapshot always reflects a single
// point in time, so the category buckets always sum to Total.
type Counters struct {
	mu        sync.Mutex
	total     uint64
	buckets   [6]uint64
	ruleHits  map[string]uint64 // rule id -> times that rule was the winner
	ruleAllow map[string]uint64
	ruleDeny  map[string]uint64

	win *windowState
}

func New() *Counters {
	return &Counters{
		ruleHits:  map[string]uint64{},
		ruleAllow: map[string]uint64{},
		ruleDeny:  map[string]uint64{},
		win:       newWindowState(),
	}
}

// SetClock overrides the clock used for rolling windows (tests only).
func (c *Counters) SetClock(now func() time.Time) {
	c.win.mu.Lock()
	c.win.now = now
	c.win.mu.Unlock()
}

var outcomes = []Outcome{
	OutcomeAllowed,
	OutcomeDeniedPolicy,
	OutcomeResolveFailed,
	OutcomeUpstreamDial,
	OutcomeUpstreamIOTimeout,
	OutcomeClientError,
}

// Record counts one request in exactly one bucket and, when a policy rule
// decided the verdict, attributes one hit to that rule.
func (c *Counters) Record(o Outcome, winningRule string) {
	idx := outcomeIndex(o)
	if idx < 0 {
		panic("unknown outcome: " + string(o))
	}
	c.mu.Lock()
	c.total++
	c.buckets[idx]++
	if winningRule != "" {
		c.ruleHits[winningRule]++
		if o == OutcomeAllowed {
			c.ruleAllow[winningRule]++
		} else if o == OutcomeDeniedPolicy {
			c.ruleDeny[winningRule]++
		}
	}
	c.mu.Unlock()
	c.win.record(idx, winningRule)
}

// RuleStat is the per-rule attribution in a snapshot.
type RuleStat struct {
	Rule    string `json:"rule"`
	Hits    uint64 `json:"hits"`
	Allowed uint64 `json:"allowed"`
	Denied  uint64 `json:"denied"`
}

// Snapshot is a consistent point-in-time view of all counters.
type Snapshot struct {
	Total  uint64            `json:"total"`
	Counts map[string]uint64 `json:"counts"`
	Rules  []RuleStat        `json:"rules"`
}

func (c *Counters) Snapshot() Snapshot {
	snap := Snapshot{Counts: map[string]uint64{}}
	c.mu.Lock()
	snap.Total = c.total
	for _, o := range outcomes {
		snap.Counts[string(o)] = c.buckets[outcomeIndex(o)]
	}
	ids := make([]string, 0, len(c.ruleHits))
	for id := range c.ruleHits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		snap.Rules = append(snap.Rules, RuleStat{
			Rule:    id,
			Hits:    c.ruleHits[id],
			Allowed: c.ruleAllow[id],
			Denied:  c.ruleDeny[id],
		})
	}
	c.mu.Unlock()
	return snap
}

// Window returns a coherent snapshot of requests recorded during the
// trailing d interval. d must be > 0 and <= MaxWindow. It does not change
// any cumulative counter.
func (c *Counters) Window(d time.Duration) (WindowSnapshot, error) {
	if d <= 0 {
		return WindowSnapshot{}, ErrInvalidWindow{"window must be > 0"}
	}
	if d > MaxWindow {
		return WindowSnapshot{}, ErrInvalidWindow{"window exceeds maximum " + MaxWindow.String()}
	}
	return c.win.snapshot(d), nil
}

// ErrInvalidWindow marks an illegal window parameter.
type ErrInvalidWindow struct{ Msg string }

func (e ErrInvalidWindow) Error() string { return e.Msg }

func outcomeIndex(o Outcome) int {
	for i, x := range outcomes {
		if x == o {
			return i
		}
	}
	return -1
}
