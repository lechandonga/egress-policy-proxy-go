package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync/atomic"
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
