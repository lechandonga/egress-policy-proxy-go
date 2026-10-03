package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Server exposes the read-only operational API:
//
//	GET  /stats   - counter snapshot (totals + per-rule attribution)
//	GET  /evaluate - dry-run trial verdict against a single policy version
//	POST /reload   - re-read the policy file; on failure keeps the old version
//	GET  /reload-history - recent reload attempts and their outcomes
//	GET  /version  - active policy version
type Server struct {
	Store      *policy.Store
	Counters   *stats.Counters
	PolicyPath string
	Reload     func() (*policy.Policy, error)
	History    func(n int) []policy.ReloadEvent
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/evaluate", s.handleEvaluate)
	mux.HandleFunc("/reload", s.handleReload)
	mux.HandleFunc("/reload-history", s.handleReloadHistory)
	mux.HandleFunc("/version", s.handleVersion)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// handleStats returns the cumulative snapshot (unchanged schema) and, when
// ?window= is given (e.g. "5m", "30s", "90s"), an additional self-consistent
// "window" snapshot for that trailing interval. Window length is capped at
// stats.MaxWindow; illegal values are rejected rather than defaulted.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	snap := s.Counters.Snapshot()
	raw := strings.TrimSpace(r.URL.Query().Get("window"))
	if raw == "" {
		writeJSON(w, http.StatusOK, snap)
		return
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid window: use a Go duration like 30s or 5m: " + err.Error(),
		})
		return
	}
	win, err := s.Counters.Window(d)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		stats.Snapshot
		Window stats.WindowSnapshot `json:"window"`
	}{Snapshot: snap, Window: win})
}

// evaluationResponse is the dry-run verdict. It intentionally mirrors the
// policy.Adjudication JSON and adds the exact policy version used.
type evaluationResponse struct {
	policy.Adjudication
	Version string `json:"version"`
}

// handleEvaluate answers "would this be allowed?" without forwarding
// anything and without touching any traffic counter:
//
//	GET /evaluate?host=api.example.com&port=443
//	GET /evaluate?host=api.example.com&port=443&addr=203.0.113.4&addr=10.0.0.1
//
// The snapshot is loaded once per request, so the verdict belongs to one
// policy version end to end, even if a reload lands mid-request. Invalid
// parameters produce a 400 rather than an allow/deny answer.
func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := strings.ToLower(strings.TrimSpace(q.Get("host")))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host: provide host=example.com"})
		return
	}

	portRaw := strings.TrimSpace(q.Get("port"))
	if portRaw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing port: provide port=443"})
		return
	}
	portN, err := strconv.Atoi(portRaw)
	if err != nil || portN < 1 || portN > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid port %q: integer 1-65535 required", portRaw)})
		return
	}

	var ips []netip.Addr
	for _, a := range q["addr"] {
		a = strings.TrimSpace(a)
		addr, err := netip.ParseAddr(a)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid addr %q: %v", a, err)})
			return
		}
		ips = append(ips, addr.Unmap())
	}

	snap, ok := s.Store.Current()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no policy loaded"})
		return
	}

	// A literal IP host is evaluated as an address-only request; extra
	// assumed addresses are meaningless in that case.
	evalHost := host
	if addr, err := netip.ParseAddr(host); err == nil {
		if len(ips) > 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "addr is not allowed when host itself is a literal IP"})
			return
		}
		evalHost = ""
		ips = []netip.Addr{addr.Unmap()}
	}

	adj := snap.Adjudicate(evalHost, uint16(portN), ips)
	writeJSON(w, http.StatusOK, evaluationResponse{Adjudication: adj, Version: snap.Version})
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
	p, err := s.Reload()
	if err != nil {
		// Reload failed: old version is still active. Report the
		// distinguishable failure category and the version still in effect.
		cur, _ := s.Store.Current()
		activeVersion := ""
		if cur != nil {
			activeVersion = cur.Version
		}
		// error_kind keeps the original two-value contract
		// ("validation" vs "io"); error_kind_detail adds the specific
		// category (invalid_json, invalid_port, ...).
		kind := "io"
		detail := string(policy.KindIO)
		if policy.IsLoadError(err) {
			kind = "validation"
			detail = string(policy.ErrorKindOf(err))
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"reloaded":          "false",
			"result":            string(policy.ReloadFailure),
			"error_kind":        kind,
			"error_kind_detail": detail,
			"error":             err.Error(),
			"active_version":    activeVersion,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"reloaded":       "true",
		"result":         string(policy.ReloadSuccess),
		"active_version": p.Version,
	})
}

// handleReloadHistory returns recent reload attempts, newest first:
//
//	GET /reload-history[?limit=20]
//
// Every successful entry's version matches the version that was active
// right after that reload; failures carry a category and the retained
// (older) version.
func (s *Server) handleReloadHistory(w http.ResponseWriter, r *http.Request) {
	if s.History == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "reload history is not configured"})
		return
	}
	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 128 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be an integer 1-128"})
			return
		}
		limit = n
	}
	current, _ := s.Store.Current()
	currentVersion := ""
	if current != nil {
		currentVersion = current.Version
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current_version": currentVersion,
		"events":          s.History(limit),
	})
}
