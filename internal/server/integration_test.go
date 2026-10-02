package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/proxy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

type mapResolver struct{ hosts map[string][]netip.Addr }

func (m *mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := m.hosts[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host")
}

// 端到端（不依赖外部网络）：本地源站 + 本地代理 + 内存解析器，
// 覆盖启动拦截、管理接口热更新失败回退/成功切换、统计查询。
func TestEndToEndReloadAndStats(t *testing.T) {
	var reached bool
	originMux := http.NewServeMux()
	originMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte("origin-body"))
	})
	ol, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = http.Serve(ol, originMux) }()
	_, oPortS, _ := net.SplitHostPort(ol.Addr().String())
	oPort, _ := strconv.Atoi(oPortS)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	mustWrite(t, policyPath, fmt.Sprintf(`{
		"version":1,"default_action":"deny",
		"rules":[{"id":"block-app","action":"deny","domains":["app.test"],"ports":[%d]}]
	}`, oPort))

	pol, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := policy.NewStore(pol)
	if err != nil {
		t.Fatal(err)
	}
	st := &stats.Stats{}
	resolver := &mapResolver{hosts: map[string][]netip.Addr{
		"app.test": {netip.MustParseAddr("127.0.0.1")},
	}}
	pxy := proxy.New(store, st, proxy.Config{
		Resolver:       resolver,
		DialTimeout:    2 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	srv := New(policyPath, pxy, store, st, log.New(io.Discard, "", 0))

	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = http.Serve(pl, srv.ProxyHandler()) }()
	al, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = http.Serve(al, srv.AdminHandler()) }()

	proxyURL, _ := url.Parse("http://" + pl.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	admin := "http://" + al.Addr().String()

	getApp := func() int {
		r, err := client.Get(fmt.Sprintf("http://app.test:%d/", oPort))
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return r.StatusCode
	}

	if code := getApp(); code != http.StatusForbidden {
		t.Fatalf("初始策略应拒绝，实际 %d", code)
	}
	if reached {
		t.Fatal("被拒绝请求不应到达源站")
	}

	// 畸形热更：明确失败、沿用旧版
	mustWrite(t, policyPath, `{"version":1,"default_action":"oops","rules":[]}`)
	rr := postReload(t, admin+"/admin/reload")
	if rr.Success || rr.Revision != 1 {
		t.Fatalf("畸形热更应失败并沿用 rev1，实际 %+v", rr)
	}
	if code := getApp(); code != http.StatusForbidden {
		t.Fatalf("热更失败后必须沿用旧策略，实际 %d", code)
	}

	// 合法热更：整体切换为放行
	mustWrite(t, policyPath, fmt.Sprintf(`{
		"version":1,"default_action":"deny",
		"rules":[{"id":"allow-app","action":"allow","domains":["app.test"],"ports":[%d]}]
	}`, oPort))
	rr = postReload(t, admin+"/admin/reload")
	if !rr.Success || rr.Revision != 2 {
		t.Fatalf("合法热更应切到 rev2，实际 %+v", rr)
	}
	r, err := client.Get(fmt.Sprintf("http://app.test:%d/", oPort))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || string(body) != "origin-body" || !reached {
		t.Fatalf("热更后未正确转发: status=%d body=%q reached=%v", r.StatusCode, string(body), reached)
	}

	// 统计查询：分类清晰守恒
	sresp, err := http.Get(admin + "/admin/stats")
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	_ = json.NewDecoder(sresp.Body).Decode(&snap)
	sresp.Body.Close()
	by := snap["by_outcome"].(map[string]any)
	if by["denied_policy"].(float64) != 2 || by["allowed"].(float64) != 1 {
		t.Fatalf("端到端统计不符: %v", by)
	}
	t.Logf("端到端统计: %v", by)
}

func TestStartupRejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	mustWrite(t, p, `{"version":1,"default_action":"deny","rules":[{"id":"","action":"allow"}]}`)
	if _, err := policy.LoadFile(p); err == nil {
		t.Fatal("非法初始策略必须加载失败，代理不得启动（安全默认 deny-all）")
	}
}

func postReload(t *testing.T, endpoint string) policy.ReloadResult {
	t.Helper()
	resp, err := http.Post(endpoint, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rr policy.ReloadResult
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		t.Fatal(err)
	}
	return rr
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
