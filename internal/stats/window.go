package stats

import (
	"sort"
	"time"
)

// MaxWindow is the server-side cap on observation-window length. Requests
// for a larger window are rejected by the caller instead of being silently
// truncated.
const MaxWindow = time.Hour

// windowResolution is the bucket granularity for the rolling ring.
const windowResolution = time.Second

const ringBuckets = int(MaxWindow / windowResolution) // 3600

type ruleAgg struct{ hits, allowed, denied uint64 }

type bucket struct {
	sec    int64 // unix seconds; 0 means unused
	total  uint64
	counts [6]uint64
	rules  map[string]ruleAgg
}

// ring is a fixed-size ring of one-second aggregation buckets. Its memory
// is bounded by ringBuckets regardless of process lifetime or event rate:
// a hot second only makes one existing map larger, and expired buckets are
// reset.
type ring struct {
	buckets []bucket
}

func newRing() *ring {
	return &ring{buckets: make([]bucket, ringBuckets)}
}

func (r *ring) add(now time.Time, outcomeIdx int, rule string) {
	sec := now.Unix()
	i := int(sec % int64(ringBuckets))
	b := &r.buckets[i]
	if b.sec != sec {
		// Slot belongs to an older second (or was never used): reset it.
		*b = bucket{sec: sec, rules: map[string]ruleAgg{}}
	}
	b.total++
	b.counts[outcomeIdx]++
	if rule != "" {
		a := b.rules[rule]
		a.hits++
		if outcomeIdx == 0 { // outcomeIndex(OutcomeAllowed)
			a.allowed++
		} else if outcomeIdx == 1 { // outcomeIndex(OutcomeDeniedPolicy)
			a.denied++
		}
		b.rules[rule] = a
	}
}

// WindowSnapshot is a self-consistent snapshot of one recent interval.
// Every request that ended inside the interval is counted exactly once, so
// the category counts always sum to Total.
type WindowSnapshot struct {
	WindowMS int64             `json:"window_ms"`
	Total    uint64            `json:"total"`
	Counts   map[string]uint64 `json:"counts"`
	Rules    []RuleStat        `json:"rules"`
}

// windowState holds the rolling ring and its clock. It has no lock of its
// own: every access happens while the owning Counters holds Counters.mu,
// which also serializes recording and cumulative snapshots.
type windowState struct {
	ring *ring
	now  func() time.Time
}

func newWindowState() *windowState {
	return &windowState{ring: newRing(), now: time.Now}
}

// snapshot aggregates the half-open interval (now-d, now] bucket-aligned:
// all one-second buckets whose timestamp satisfies nowSec*1s - d < t <= now.
// The caller must hold Counters.mu, so recording cannot interleave and the
// returned numbers are a single coherent point-in-time view.
func (w *windowState) snapshot(d time.Duration) WindowSnapshot {
	nowSec := w.now().Unix()
	startSec := nowSec - int64(d/windowResolution)

	snap := WindowSnapshot{
		WindowMS: d.Milliseconds(),
		Counts:   map[string]uint64{},
	}
	ruleTotals := map[string]*RuleStat{}

	for i := range w.ring.buckets {
		b := &w.ring.buckets[i]
		if b.sec == 0 || b.sec <= startSec || b.sec > nowSec {
			continue
		}
		snap.Total += b.total
		for j, n := range b.counts {
			snap.Counts[string(outcomes[j])] += n
		}
		for id, a := range b.rules {
			rs := ruleTotals[id]
			if rs == nil {
				rs = &RuleStat{Rule: id}
				ruleTotals[id] = rs
			}
			rs.Hits += a.hits
			rs.Allowed += a.allowed
			rs.Denied += a.denied
		}
	}

	for _, o := range outcomes {
		if _, ok := snap.Counts[string(o)]; !ok {
			snap.Counts[string(o)] = 0
		}
	}

	ids := make([]string, 0, len(ruleTotals))
	for id := range ruleTotals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		snap.Rules = append(snap.Rules, *ruleTotals[id])
	}
	return snap
}
