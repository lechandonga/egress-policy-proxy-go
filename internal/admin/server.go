package admin

import (
	"encoding/json"
	"net/http"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Server exposes the read-only operational API:
//
//	GET  /stats   - counter snapshot (totals + per-rule attribution)
//	POST /reload   - re-read the policy file; on failure keeps the old version
//	GET  /version  - active policy version
type Server struct {
	Store      *policy.Store
	Counters   *stats.Counters
	PolicyPath string
	Reload     func() (*policy.Policy, error)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/reload", s.handleReload)
	mux.HandleFunc("/version", s.handleVersion)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Counters.Snapshot())
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	p, ok := s.Store.Current()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"version": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"version": p.Version})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}
	before, _ := s.Store.Current()
	p, err := s.Reload()
	if err != nil {
		// Reload failed: old version is still active. Report a
		// distinguishable error kind (validation vs I/O).
		kind := "io"
		if policy.IsLoadError(err) {
			kind = "validation"
		}
		oldVersion := ""
		if before != nil {
			oldVersion = before.Version
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"reloaded":       "false",
			"error_kind":     kind,
			"error":          err.Error(),
			"active_version": oldVersion,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"reloaded":       "true",
		"active_version": p.Version,
	})
}
