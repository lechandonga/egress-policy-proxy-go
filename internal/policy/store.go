package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds one immutable Policy snapshot and swaps it atomically on
// reload. In-flight requests keep using the snapshot they started with, so
// they never observe a mix of old and new rules.
type Store struct {
	current atomic.Pointer[Policy]
}

// NewStore returns an empty store. Current reports false until the first
// successful Load, letting the caller fail closed at startup.
func NewStore() *Store { return &Store{} }

// Current returns the active snapshot and whether one has been loaded.
func (s *Store) Current() (*Policy, bool) {
	p := s.current.Load()
	if p == nil {
		return nil, false
	}
	return p, true
}

// LoadFile reads and fully compiles the file before swapping the snapshot.
// On any error (I/O or validation) the previous policy stays in effect and
// the error is returned; the caller can tell validation failures apart via
// IsLoadError.
func (s *Store) LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", path, err)
	}
	sum := sha256.Sum256(data)
	p, err := Decode(data)
	if err != nil {
		return nil, err
	}
	p.Version = fmt.Sprintf("%s@%s", path, hex.EncodeToString(sum[:8]))
	s.current.Store(p)
	return p, nil
}

// Swap installs an already-compiled snapshot (used in tests and embedders).
func (s *Store) Swap(p *Policy) { s.current.Store(p) }

// MaxHistoryEntries bounds the reload history memory; older events are
// evicted but every trigger still produced a definite result at the time.
const MaxHistoryEntries = 512

const maxHistoryEntries = MaxHistoryEntries

// ReloadResult is one recorded reload attempt.
type ReloadResult string

const (
	ReloadSuccess ReloadResult = "success"
	ReloadFailure ReloadResult = "failure"
)

// ReloadEvent records what happened for a single reload trigger.
type ReloadEvent struct {
	Seq           int64        `json:"seq"`
	Time          time.Time    `json:"time"`
	Result        ReloadResult `json:"result"`
	Version       string       `json:"version"`        // version active as a consequence of this reload
	LoadedVersion string       `json:"loaded_version"` // version successfully loaded; "" on failure
	ErrorKind     ErrorKind    `json:"error_kind,omitempty"`
	Error         string       `json:"error,omitempty"`
}

// Reloader serializes reload triggers against a Store and records a bounded
// history. Every trigger returns its own outcome: a success means the
// returned version is the active one at the moment the trigger completes
// (reloads are serialized, so the last completed successful reload always
// owns the active snapshot); a failure leaves the previous policy intact.
type Reloader struct {
	store *Store
	path  string

	mu      sync.Mutex
	seq     int64
	history []ReloadEvent // newest first, capped at maxHistoryEntries
}

// NewReloader returns a Reloader bound to store and policy file path.
func NewReloader(store *Store, path string) *Reloader {
	return &Reloader{store: store, path: path}
}

// Store returns the underlying store.
func (r *Reloader) Store() *Store { return r.store }

// Path returns the configured policy file path.
func (r *Reloader) Path() string { return r.path }

// Reload performs exactly one reload attempt. Concurrent calls are
// serialized end to end: the read, validation, atomic installation and
// history append for one trigger all happen while the same mutex is held,
// so a later trigger cannot install its snapshot between this trigger's
// installation and its return. Consequently a returned success means the
// returned version is already the active one, and the most recent
// successful event in history always owns the active snapshot. A failure
// leaves the previous policy in place. No trigger is dropped: every caller
// acquires the lock in turn and appends exactly one history event.
func (r *Reloader) Reload() (*Policy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, err := r.store.LoadFile(r.path)

	r.seq++
	ev := ReloadEvent{
		Seq:    r.seq,
		Time:   time.Now(),
		Result: ReloadSuccess,
	}
	if err != nil {
		ev.Result = ReloadFailure
		ev.ErrorKind = ErrorKindOf(err)
		ev.Error = err.Error()
		if cur, ok := r.store.Current(); ok {
			ev.Version = cur.Version
		}
	} else {
		ev.Version = p.Version
		ev.LoadedVersion = p.Version
	}
	r.history = append([]ReloadEvent{ev}, r.history...)
	if len(r.history) > maxHistoryEntries {
		r.history = r.history[:maxHistoryEntries]
	}

	return p, err
}

// History returns up to n recent reload events, newest first. n <= 0 (or
// larger than the cap) returns the retained history.
func (r *Reloader) History(n int) []ReloadEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.history) {
		n = len(r.history)
	}
	out := make([]ReloadEvent, n)
	copy(out, r.history[:n])
	return out
}
