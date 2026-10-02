package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lechandonga/egress-policy-proxy-go/internal/policy"
	"github.com/lechandonga/egress-policy-proxy-go/internal/stats"
)

const (
	ReasonPolicyDeny = "policy_denied"
	ReasonDNS        = "dns_failed"
	ReasonUpstream   = "upstream_unreachable"
	ReasonTimeout    = "upstream_timeout"
	ReasonBadRequest = "bad_request"
)

type Config struct {
	Resolver       Resolver
	DialTimeout    time.Duration
	RequestTimeout time.Duration
	DialContext    func(ctx context.Context, network, address string) (net.Conn, error)
}

type Proxy struct {
	store       *policy.Store
	stats       *stats.Stats
	cfg         Config
	activeConns atomic.Int64
}

func New(store *policy.Store, st *stats.Stats, cfg Config) *Proxy {
	if cfg.Resolver == nil {
		cfg.Resolver = NewNetResolver(5 * time.Second)
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	return &Proxy{store: store, stats: st, cfg: cfg}
}

func (p *Proxy) ActiveConns() int64 { return p.activeConns.Load() }

func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.serveHTTP)
}

type winnerInfo struct {
	RuleID    string `json:"rule_id"`
	Action    string `json:"action"`
	DomainHit string `json:"domain_hit,omitempty"`
	IPHit     string `json:"ip_hit,omitempty"`
}

type denyBody struct {
	Result      string       `json:"result"`
	Reason      string       `json:"reason"`
	Host        string       `json:"host"`
	Port        uint16       `json:"port"`
	Explanation string       `json:"explanation"`
	Winner      *winnerInfo  `json:"winner,omitempty"`
	AllMatched  []winnerInfo `json:"all_matched,omitempty"`
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlain(w, r)
}

func (p *Proxy) resolveAndDecide(ctx context.Context, host string, port uint16) (
	*policy.Decision, []netip.Addr, string,
) {
	host = strings.ToLower(strings.TrimSpace(host))
	var addrs []netip.Addr
	if ap, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ap.Unmap()}
	} else {
		got, err := p.cfg.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, nil, ReasonDNS
		}
		addrs = got
	}

	pol, _ := p.store.Current()
	dec := pol.Evaluate(policy.EvalRequest{Host: host, Port: port, IPs: addrs})
	return dec, addrs, ""
}

func (p *Proxy) writeDeny(w http.ResponseWriter, status int, reason string, host string, port uint16, dec *policy.Decision) {
	body := denyBody{Result: "denied", Reason: reason, Host: host, Port: port, Explanation: dec.Explanation}
	ruleID := ""
	if dec.Winner != nil {
		ruleID = dec.Winner.RuleID
		body.Winner = &winnerInfo{
			RuleID: dec.Winner.RuleID, Action: string(dec.Winner.Action),
			DomainHit: dec.Winner.DomainHit, IPHit: dec.Winner.IPHit,
		}
	}
	for _, m := range dec.AllMatched {
		body.AllMatched = append(body.AllMatched, winnerInfo{
			RuleID: m.RuleID, Action: string(m.Action),
			DomainHit: m.DomainHit, IPHit: m.IPHit,
		})
	}
	p.stats.Record(stats.OutcomeDeniedPolicy, ruleID)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Egress-Reason", reason)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (p *Proxy) writeError(w http.ResponseWriter, status int, reason, msg string, outcome stats.Outcome) {
	p.stats.Record(outcome, "")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Egress-Reason", reason)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"result": "error", "reason": reason, "message": msg})
}

func (p *Proxy) writeDialError(w http.ResponseWriter, err error, host string) {
	if isTimeout(err) {
		p.writeError(w, http.StatusGatewayTimeout, ReasonTimeout,
			"连接上游超时: "+host+": "+err.Error(), stats.OutcomeUpstreamTO)
		return
	}
	p.writeError(w, http.StatusBadGateway, ReasonUpstream,
		"上游不可达: "+host+": "+err.Error(), stats.OutcomeUpstreamFail)
}

func hostPortFromRequest(r *http.Request) (string, uint16, error) {
	if r.Method == http.MethodConnect {
		h, sp, err := net.SplitHostPort(r.Host)
		if err != nil {
			return "", 0, err
		}
		port, err := parsePort(sp)
		if err != nil {
			return "", 0, err
		}
		return h, port, nil
	}
	if !strings.Contains(r.Host, ":") {
		port := uint16(80)
		if r.URL != nil && r.URL.Scheme == "https" {
			port = 443
		}
		return r.Host, port, nil
	}
	h, sp, err := net.SplitHostPort(r.Host)
	if err != nil {
		return "", 0, err
	}
	port, err := parsePort(sp)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}

func parsePort(s string) (uint16, error) {
	var v int
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil || v < 1 || v > 65535 {
		return 0, fmt.Errorf("非法端口 %q", s)
	}
	return uint16(v), nil
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

type flushWriter struct{ w http.ResponseWriter }

func newFlushWriter(w http.ResponseWriter) io.Writer { return &flushWriter{w} }

func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (p *Proxy) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	if p.cfg.DialContext != nil {
		return p.cfg.DialContext(dialCtx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(dialCtx, "tcp", addr)
}

func (p *Proxy) dialAddrs(ctx context.Context, addrs []netip.Addr, port uint16) (net.Conn, error) {
	var lastErr error
	for _, a := range addrs {
		addr := net.JoinHostPort(a.String(), fmt.Sprintf("%d", port))
		conn, err := p.dial(ctx, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("没有可拨号的地址")
	}
	return nil, lastErr
}

func writeRequest(conn net.Conn, req *http.Request) error {
	return req.Write(conn)
}

// dialAndAuthorize 对 HTTP 与 CONNECT 执行完全相同的「解析 -> 判定 -> 拨号」路径。
func (p *Proxy) dialAndAuthorize(ctx context.Context, r *http.Request) (
	net.Conn, *policy.Decision, string, uint16, string,
) {
	host, port, err := hostPortFromRequest(r)
	if err != nil {
		return nil, nil, "", 0, ReasonBadRequest
	}
	dec, addrs, failReason := p.resolveAndDecide(ctx, host, port)
	if failReason != "" {
		return nil, nil, host, port, failReason
	}
	if !dec.Allowed {
		return nil, dec, host, port, ReasonPolicyDeny
	}
	conn, err := p.dialAddrs(ctx, addrs, port)
	if err != nil {
		if isTimeout(err) {
			return nil, dec, host, port, ReasonTimeout
		}
		return nil, dec, host, port, ReasonUpstream
	}
	return conn, dec, host, port, ""
}

func (p *Proxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), p.cfg.RequestTimeout)
	defer cancel()

	if r.URL == nil || r.URL.Host == "" {
		p.writeError(w, http.StatusBadRequest, ReasonBadRequest,
			"无法从请求确定目标（请使用绝对 URI 访问代理）", stats.OutcomeBadRequest)
		return
	}

	outConn, dec, host, port, failReason := p.dialAndAuthorize(ctx, r)
	switch failReason {
	case "":
	case ReasonBadRequest:
		p.writeError(w, http.StatusBadRequest, ReasonBadRequest, "无法确定目标 host/port", stats.OutcomeBadRequest)
		return
	case ReasonDNS:
		p.writeError(w, http.StatusBadGateway, ReasonDNS, "域名解析失败: "+host, stats.OutcomeDNSFailed)
		return
	case ReasonPolicyDeny:
		p.writeDeny(w, http.StatusForbidden, ReasonPolicyDeny, host, port, dec)
		return
	case ReasonUpstream:
		p.writeDialError(w, errors.New("connection refused"), host)
		return
	case ReasonTimeout:
		p.writeDialError(w, context.DeadlineExceeded, host)
		return
	}
	defer outConn.Close()
	p.activeConns.Add(1)
	defer p.activeConns.Add(-1)

	outReq := r.Clone(ctx)
	outReq.RequestURI = ""
	outReq.URL = &url.URL{Scheme: "http", Host: r.URL.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	removeHopHeaders(outReq.Header)
	if outReq.Header.Get("Host") == "" {
		outReq.Host = r.Host
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = outConn.SetDeadline(dl)
	}

	if err := writeRequest(outConn, outReq); err != nil {
		p.writeDialError(w, err, host)
		return
	}

	br := bufio.NewReader(outConn)
	// ReadResponse 本身不感知 ctx：放入 goroutine，ctx 取消时主动关闭上游连接以打断阻塞读，
	// 保证任何请求都不会卡死，也不会遗留 goroutine/连接。
	type readResult struct {
		resp *http.Response
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		rsp, rerr := http.ReadResponse(br, outReq)
		readCh <- readResult{rsp, rerr}
	}()
	var resp *http.Response
	select {
	case rr := <-readCh:
		if rr.err != nil {
			if isTimeout(ctx.Err()) {
				p.writeDialError(w, context.DeadlineExceeded, host)
			} else {
				p.writeDialError(w, rr.err, host)
			}
			return
		}
		resp = rr.resp
	case <-ctx.Done():
		_ = outConn.Close() // 打断 goroutine 中的阻塞读
		if isTimeout(ctx.Err()) {
			p.writeError(w, http.StatusGatewayTimeout, ReasonTimeout,
				"读取上游响应超时: "+host, stats.OutcomeUpstreamTO)
		} else {
			p.writeError(w, http.StatusBadGateway, ReasonUpstream,
				"读取上游响应时客户端断开: "+host, stats.OutcomeClientGone)
		}
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(newFlushWriter(w), io.LimitReader(resp.Body, 1<<40))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			p.stats.Record(stats.OutcomeUpstreamFail, dec.Winner.RuleID)
			return
		}
		p.stats.Record(stats.OutcomeAllowed, dec.Winner.RuleID)
	case <-ctx.Done():
		if isTimeout(ctx.Err()) {
			p.stats.Record(stats.OutcomeUpstreamTO, dec.Winner.RuleID)
		} else {
			p.stats.Record(stats.OutcomeClientGone, "")
		}
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), p.cfg.RequestTimeout)
	defer cancel()

	outConn, dec, host, port, failReason := p.dialAndAuthorize(ctx, r)
	switch failReason {
	case "":
	case ReasonBadRequest:
		p.writeError(w, http.StatusBadRequest, ReasonBadRequest, "CONNECT 目标必须是 host:port", stats.OutcomeBadRequest)
		return
	case ReasonDNS:
		p.writeError(w, http.StatusBadGateway, ReasonDNS, "域名解析失败: "+host, stats.OutcomeDNSFailed)
		return
	case ReasonPolicyDeny:
		p.writeDeny(w, http.StatusForbidden, ReasonPolicyDeny, host, port, dec)
		return
	case ReasonUpstream:
		p.writeDialError(w, errors.New("connection refused"), host)
		return
	case ReasonTimeout:
		p.writeDialError(w, context.DeadlineExceeded, host)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		outConn.Close()
		p.writeError(w, http.StatusInternalServerError, ReasonUpstream, "服务器不支持连接劫持", stats.OutcomeUpstreamFail)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		outConn.Close()
		p.writeError(w, http.StatusBadGateway, ReasonUpstream, "劫持客户端连接失败: "+err.Error(), stats.OutcomeUpstreamFail)
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		outConn.Close()
		p.stats.Record(stats.OutcomeClientGone, "")
		return
	}

	p.activeConns.Add(1)
	tErr := tunnel(ctx, clientBuf, clientConn, outConn)

	switch {
	case tErr == nil:
		p.stats.Record(stats.OutcomeAllowed, dec.Winner.RuleID)
	case isTimeout(tErr):
		p.stats.Record(stats.OutcomeUpstreamTO, dec.Winner.RuleID)
	default:
		p.stats.Record(stats.OutcomeUpstreamFail, dec.Winner.RuleID)
	}
	p.activeConns.Add(-1)
}

// tunnel 双向桥接客户端与上游；任一方向结束即整体结束，避免 goroutine/连接泄漏。
func tunnel(ctx context.Context, clientBuf *bufio.ReadWriter, client, server net.Conn) error {
	defer client.Close()
	defer server.Close()

	results := make(chan error, 2)

	go func() {
		if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
			if _, err := io.Copy(server, clientBuf); err != nil {
				results <- err
				return
			}
		}
		_, err := io.Copy(server, client)
		results <- err
	}()
	go func() {
		_, err := io.Copy(client, server)
		results <- err
	}()

	select {
	case err := <-results:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
