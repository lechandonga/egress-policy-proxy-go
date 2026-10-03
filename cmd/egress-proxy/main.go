package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/admin"
	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/proxy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "proxy listen address")
	adminListen := flag.String("admin-listen", "127.0.0.1:8081", "admin API listen address")
	policyPath := flag.String("policy", "policy.json", "path to the policy JSON file")
	requestTimeout := flag.Duration("request-timeout", 15*time.Second, "total per-request timeout")
	dialTimeout := flag.Duration("dial-timeout", 5*time.Second, "upstream TCP dial timeout")
	idleTimeout := flag.Duration("idle-timeout", 30*time.Second, "idle timeout for CONNECT tunnels")
	flag.Parse()

	store := policy.NewStore()
	counters := stats.New()

	reloader := policy.NewReloader(store, *policyPath)

	// Startup fails closed: if the initial policy cannot be loaded the
	// process exits instead of running an allow-all proxy.
	p, err := reloader.Reload()
	if err != nil {
		log.Fatalf("initial policy load failed (%s): %v", policy.ErrorKindOf(err), err)
	}
	log.Printf("loaded policy %s with %d rules", p.Version, len(p.Rules))

	reload := func() (*policy.Policy, error) {
		np, err := reloader.Reload()
		if err != nil {
			log.Printf("reload failed (%s), keeping previous policy: %v", policy.ErrorKindOf(err), err)
			return nil, err
		}
		log.Printf("reloaded policy %s with %d rules", np.Version, len(np.Rules))
		return np, nil
	}

	px := proxy.New(store, counters, proxy.Config{
		RequestTimeout: *requestTimeout,
		DialTimeout:    *dialTimeout,
		IOIdleTimeout:  *idleTimeout,
	})

	proxySrv := &http.Server{
		Addr:              *listen,
		Handler:           px.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	adminSrv := &http.Server{
		Addr: *adminListen,
		Handler: (&admin.Server{
			Store:      store,
			Counters:   counters,
			PolicyPath: *policyPath,
			Reload:     reload,
			History:    reloader.History,
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Buffer heavily so a deploy script that fires several SIGHUPs in a row
	// cannot lose any trigger: each one becomes one reload result.
	sigCh := make(chan os.Signal, 64)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	// Separate channels let SIGHUP reloads happen in their own goroutine, so
	// signals keep draining while a reload is in flight: every delivered
	// SIGHUP (up to the channel buffer) becomes its own reload result, even
	// when a deploy script fires several in one burst. INT/TERM are routed
	// to the main loop for graceful shutdown.
	hupCh := make(chan os.Signal, 64)
	termCh := make(chan os.Signal, 4)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				hupCh <- sig
			default:
				termCh <- sig
			}
		}
	}()
	go func() {
		for range hupCh {
			if _, err := reload(); err != nil {
				log.Printf("SIGHUP reload failed: %v", err)
			}
		}
	}()

	go func() {
		log.Printf("proxy listening on %s", *listen)
		if err := proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("proxy server: %v", err)
		}
	}()
	go func() {
		log.Printf("admin API listening on %s", *adminListen)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("admin server: %v", err)
		}
	}()

	// Keep serving through arbitrarily many reloads. SIGHUP never exits the
	// process; the first INT/TERM initiates graceful shutdown.
	<-termCh

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxySrv.Shutdown(shutdownCtx)
	_ = adminSrv.Shutdown(shutdownCtx)
	log.Print("shutdown complete")
}
