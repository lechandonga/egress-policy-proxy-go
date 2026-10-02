package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/proxy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

// Server 装配代理与管理端点，并负责 SIGHUP/接口热更新。
type Server struct {
	Store      *policy.Store
	Stats      *stats.Stats
	Proxy      *proxy.Proxy
	PolicyPath string
	Logger     *log.Logger

	mu        sync.Mutex
	reloading bool
}

func New(policyPath string, pxy *proxy.Proxy, store *policy.Store, st *stats.Stats, logger *log.Logger) *Server {
	return &Server{Store: store, Stats: st, Proxy: pxy, PolicyPath: policyPath, Logger: logger}
}

func (s *Server) ProxyHandler() http.Handler { return s.Proxy.Handler() }

// AdminHandler:
//
//	GET  /admin/stats   查询统计
//	GET  /admin/status  当前策略修订号与最近重载结果
//	POST /admin/reload  从文件原子重载；失败明确返回原因且沿用旧策略
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, s.Stats.Snapshot())
	})
	mux.HandleFunc("/admin/status", func(w http.ResponseWriter, r *http.Request) {
		rev, ok, lastErr := s.Store.Status()
		writeJSON(w, http.StatusOK, map[string]any{
			"revision":        rev,
			"last_reload_ok":  ok,
			"last_reload_err": lastErr,
			"active_conns":    s.Proxy.ActiveConns(),
		})
	})
	mux.HandleFunc("/admin/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		res := s.Reload()
		status := http.StatusOK
		if !res.Success {
			status = http.StatusUnprocessableEntity
		}
		writeJSON(w, status, res)
	})
	return mux
}

func (s *Server) Reload() policy.ReloadResult {
	s.mu.Lock()
	if s.reloading {
		s.mu.Unlock()
		return policy.ReloadResult{Success: false, Reason: "另一次重载正在进行"}
	}
	s.reloading = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.reloading = false
		s.mu.Unlock()
	}()

	res := s.Store.ReloadFile(s.PolicyPath)
	if res.Success {
		s.Logger.Printf("[reload] 策略已整体切换到 revision=%d", res.Revision)
	} else {
		s.Logger.Printf("[reload] 重载失败，沿用 revision=%d；原因: %s", res.Revision, res.Reason)
	}
	return res
}

func (s *Server) WatchSIGHUP(ch <-chan os.Signal) {
	go func() {
		for range ch {
			s.Reload()
		}
	}()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Serve 启动代理与管理两个监听器，返回停止函数。
func Serve(proxyAddr, adminAddr string, srv *Server) (stop func(), err error) {
	proxyHTTP := &http.Server{
		Addr:              proxyAddr,
		Handler:           srv.ProxyHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	adminHTTP := &http.Server{
		Addr:              adminAddr,
		Handler:           srv.AdminHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 2)
	go func() { errCh <- proxyHTTP.ListenAndServe() }()
	go func() { errCh <- adminHTTP.ListenAndServe() }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-errCh:
			return nil, e
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = proxyHTTP.Shutdown(ctx)
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		_ = adminHTTP.Shutdown(ctx2)
	}, nil
}
