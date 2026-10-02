package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/proxy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/server"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

func main() {
	var (
		policyPath = flag.String("policy", "configs/policy.json", "策略文件路径")
		listen     = flag.String("listen", "127.0.0.1:18080", "代理监听地址")
		admin      = flag.String("admin", "127.0.0.1:18081", "管理接口监听地址")
		dialTO     = flag.Duration("dial-timeout", 5*time.Second, "拨号上游超时")
		reqTO      = flag.Duration("request-timeout", 30*time.Second, "单次请求整体超时")
		dnsTO      = flag.Duration("dns-timeout", 5*time.Second, "域名解析超时")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "[egress] ", log.LstdFlags|log.Lmicroseconds)

	// 启动时策略必须有效；加载失败直接退出，绝不退化成全部放行。
	pol, err := policy.LoadFile(*policyPath)
	if err != nil {
		logger.Fatalf("初始策略加载失败，代理拒绝启动（安全默认 deny-all）:\n%v", err)
	}
	store, err := policy.NewStore(pol)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	st := &stats.Stats{}
	pxy := proxy.New(store, st, proxy.Config{
		Resolver:       proxy.NewNetResolver(*dnsTO),
		DialTimeout:    *dialTO,
		RequestTimeout: *reqTO,
	})
	srv := server.New(*policyPath, pxy, store, st, logger)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	srv.WatchSIGHUP(hup)

	logger.Printf("代理监听 %s（HTTP 正向代理 + HTTPS CONNECT），管理接口 %s", *listen, *admin)
	stop, err := server.Serve(*listen, *admin, srv)
	if err != nil {
		logger.Fatalf("启动失败: %v", err)
	}
	defer stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Printf("收到退出信号，关闭中…")
}
