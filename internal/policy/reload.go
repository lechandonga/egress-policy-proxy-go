package policy

import (
	"sync"
	"time"
)

// ReloadRecord describes one reload trigger and its outcome.
type ReloadRecord struct {
	Time    time.Time `json:"time"`
	Success bool      `json:"success"`
	// Kind classifies failures: "validation" (policy content illegal) or
	// "io" (file unreadable). Empty on success.
	Kind  string `json:"error_kind,omitempty"`
	Error string `json:"error,omitempty"`
	// Version is the policy version active after this reload completed:
	// the freshly loaded version on success, the retained old version on
	// failure.
	Version string `json:"version"`
}

// historyCap bounds the retained reload history so memory stays flat no
// matter how often reloads fire.
const historyCap = 64

// Reloader serializes policy reloads and keeps an audit trail. Every
// trigger is processed to completion — either the store atomically swaps to
// a fully compiled new version, or the reload fails and the previous
// version keeps serving untouched. Concurrent triggers queue on the mutex,
// so the final active version always corresponds to exactly one recorded
// success, and a caller that observes success never raced a half-applied
// state.
type Reloader struct {
	store *Store
	path  string

	mu      sync.Mutex
	history []ReloadRecord // oldest first, capped at historyCap
}

func NewReloader(store *Store, path string) *Reloader {
	return &Reloader{store: store, path: path}
}

// Reload performs one full reload. It never panics and never disturbs the
// active policy on failure.
func (r *Reloader) Reload() (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, err := r.store.LoadFile(r.path)
	rec := ReloadRecord{Time: time.Now().UTC()}
	if err != nil {
		rec.Kind = "io"
		if IsLoadError(err) {
			rec.Kind = "validation"
		}
		rec.Error = err.Error()
		if cur, ok := r.store.Current(); ok {
			rec.Version = cur.Version
		}
		r.append(rec)
		return nil, err
	}
	rec.Success = true
	rec.Version = p.Version
	r.append(rec)
	return p, nil
}

// History returns the most recent reload records, newest first. limit <= 0
// returns everything retained.
func (r *Reloader) History(limit int) []ReloadRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.history)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]ReloadRecord, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, r.history[len(r.history)-1-i])
	}
	return out
}

func (r *Reloader) append(rec ReloadRecord) {
	r.history = append(r.history, rec)
	if len(r.history) > historyCap {
		r.history = append([]ReloadRecord(nil), r.history[len(r.history)-historyCap:]...)
	}
}
