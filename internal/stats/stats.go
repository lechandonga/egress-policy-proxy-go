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

// Counters is a goroutine-safe set of request counters. Total, buckets and
// rule attribution are mutated and read under one mutex, so every Snapshot
// is a consistent cut (bucket sum always equals total) no matter how
// recording and querying overlap. The recent-event window uses a bounded
// ring so memory stays flat under indefinite load.
type Counters struct {
	mu        sync.Mutex // guards total, buckets and the rule maps
	total     uint64
	buckets   [6]uint64
	ruleHits  map[string]uint64 // rule id -> times that rule was the winner
	ruleAllow map[string]uint64
	ruleDeny  map[string]uint64

	evMu   sync.Mutex
	events []event // ring buffer, oldest overwritten when full
	head   int     // next write position
	count  int     // number of valid entries, <= cap
	evCap  int
}

// DefaultEventCap bounds the recent-event ring. At ~56 bytes per event
// this keeps the window memory in the low tens of MB worst case.
const DefaultEventCap = 1 << 18

type event struct {
	t    time.Time
	idx  int    // index into outcomes
	rule string // winning rule, "" when no rule decided
}

func New() *Counters {
	return NewWithCapacity(DefaultEventCap)
}

// NewWithCapacity is New with an explicit event-ring capacity (tests use
// small rings to exercise overflow).
func NewWithCapacity(eventCap int) *Counters {
	if eventCap <= 0 {
		eventCap = 1
	}
	return &Counters{
		ruleHits:  map[string]uint64{},
		ruleAllow: map[string]uint64{},
		ruleDeny:  map[string]uint64{},
		events:    make([]event, eventCap),
		evCap:     eventCap,
	}
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
	idx := -1
	for i, x := range outcomes {
		if x == o {
			idx = i
			break
		}
	}
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
	c.evMu.Lock()
	c.events[c.head] = event{t: time.Now(), idx: idx, rule: winningRule}
	c.head = (c.head + 1) % c.evCap
	if c.count < c.evCap {
		c.count++
	}
	c.evMu.Unlock()
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
	c.mu.Lock()
	snap := Snapshot{Counts: map[string]uint64{}}
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

	var sum uint64
	for _, n := range snap.Counts {
		sum += n
	}
	if sum != snap.Total {
		// Should never happen; Record always increments total and one bucket.
		panic("stats invariant violated: bucket sum != total")
	}
	return snap
}

// WindowSnapshot is a consistent view of the events recorded inside the
// trailing window ending at now. Counts always sum to Total.
type WindowSnapshot struct {
	Window string            `json:"window"`
	Since  time.Time         `json:"since"`
	Total  uint64            `json:"total"`
	Counts map[string]uint64 `json:"counts"`
	Rules  []RuleStat        `json:"rules"`
}

// Window returns the snapshot of the last d ending now. The snapshot is
// computed under the event lock, so every query observes one self-
// consistent cut: per-bucket counts always sum to Total, and per-rule
// attributions never exceed it.
func (c *Counters) Window(d time.Duration) WindowSnapshot {
	return c.WindowAt(d, time.Now())
}

// WindowAt is Window with an explicit "now" (deterministic tests).
func (c *Counters) WindowAt(d time.Duration, now time.Time) WindowSnapshot {
	cutoff := now.Add(-d)
	ws := WindowSnapshot{
		Window: d.String(),
		Since:  cutoff.UTC(),
		Counts: map[string]uint64{},
	}
	for _, o := range outcomes {
		ws.Counts[string(o)] = 0
	}
	ruleHits := map[string]uint64{}
	ruleAllow := map[string]uint64{}
	ruleDeny := map[string]uint64{}

	c.evMu.Lock()
	for i := 0; i < c.count; i++ {
		ev := c.events[i]
		if ev.t.Before(cutoff) {
			continue
		}
		ws.Total++
		ws.Counts[string(outcomes[ev.idx])]++
		if ev.rule != "" {
			ruleHits[ev.rule]++
			switch outcomes[ev.idx] {
			case OutcomeAllowed:
				ruleAllow[ev.rule]++
			case OutcomeDeniedPolicy:
				ruleDeny[ev.rule]++
			}
		}
	}
	c.evMu.Unlock()

	ids := make([]string, 0, len(ruleHits))
	for id := range ruleHits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ws.Rules = append(ws.Rules, RuleStat{
			Rule:    id,
			Hits:    ruleHits[id],
			Allowed: ruleAllow[id],
			Denied:  ruleDeny[id],
		})
	}
	return ws
}

func outcomeIndex(o Outcome) int {
	for i, x := range outcomes {
		if x == o {
			return i
		}
	}
	return -1
}
