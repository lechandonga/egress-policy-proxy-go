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
	"github.com/lechandonga/egress-policy-proxy-go/internal/proxy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/resolver"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Server exposes the operational API:
//
//	GET  /stats[?window=5m]  - counter snapshot, optionally plus a recent window
//	POST /reload             - re-read the policy file; on failure keeps the old version
//	GET  /reloads            - recent reload history (time, result, kind, version)
//	GET  /version            - active policy version
//	GET  /dryrun?host=H&port=P[&ip=A...] - what-if evaluation, forwards nothing
type Server struct {
	Store      *policy.Store
	Counters   *stats.Counters
	PolicyPath string
	// Reload performs one serialized reload (see policy.Reloader).
	Reload func() (*policy.Policy, error)
	// ReloadHistory, when set, backs GET /reloads.
	ReloadHistory func(limit int) []policy.ReloadRecord
	// Resolver is used by /dryrun when no assumed addresses are given.
	// Defaults to the system resolver.
	Resolver resolver.Resolver
}

// MaxStatsWindow bounds the ?window= observation window.
const MaxStatsWindow = time.Hour

// maxReloadHistory bounds how many records one /reloads query returns.
const maxReloadHistory = 64

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/reload", s.handleReload)
	mux.HandleFunc("/reloads", s.handleReloads)
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/dryrun", s.handleDryRun)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	snap := s.Counters.Snapshot()
	q := r.URL.Query()
	if !q.Has("window") {
		writeJSON(w, http.StatusOK, snap)
		return
	}
	d, err := time.ParseDuration(q.Get("window"))
	if err != nil || d <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid window %q: use a positive Go duration like 30s, 5m, 1h", q.Get("window")),
		})
		return
	}
	if d > MaxStatsWindow {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("window %s exceeds the server maximum of %s", d, MaxStatsWindow),
		})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		stats.Snapshot
		Window stats.WindowSnapshot `json:"window"`
	}{Snapshot: snap, Window: s.Counters.Window(d)})
}

func (s *Server) handleReloads(w http.ResponseWriter, r *http.Request) {
	limit := maxReloadHistory
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		if n < limit {
			limit = n
		}
	}
	var records []policy.ReloadRecord
	if s.ReloadHistory != nil {
		records = s.ReloadHistory(limit)
	}
	if records == nil {
		records = []policy.ReloadRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloads": records})
}

func (s *Server) handleDryRun(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := strings.ToLower(strings.TrimSpace(q.Get("host")))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required query parameter: host"})
		return
	}
	if len(host) > 253 || strings.ContainsAny(host, " /\t\r\n") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid host %q", host)})
		return
	}
	portRaw := q.Get("port")
	if portRaw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required query parameter: port"})
		return
	}
	portNum, err := strconv.Atoi(portRaw)
	if err != nil || portNum < 1 || portNum > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid port %q: must be an integer between 1 and 65535", portRaw),
		})
		return
	}
	var assumed []netip.Addr
	for _, raw := range q["ip"] {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("invalid assumed address %q: %v", raw, err),
			})
			return
		}
		assumed = append(assumed, addr)
	}

	res := s.Resolver
	if res == nil {
		res = resolver.Std{}
	}
	result, reason, err := proxy.DryRun(r.Context(), s.Store, res, host, uint16(portNum), assumed)
	if err != nil {
		status := http.StatusBadGateway
		if reason == proxy.ReasonNoPolicy {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]string{
			"error":  err.Error(),
			"reason": reason,
		})
		return
	}
	writeJSON(w, http.StatusOK, result)
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
