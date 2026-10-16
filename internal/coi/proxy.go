package coi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// egressToken is the bearer for one request. It is not logged.
type egressToken struct{}

// Egress is the host-side reverse proxy. The jail speaks plain HTTP to a
// loopback forwarder; this process dials TLS to the allowlisted host and
// sets Authorization. A CONNECT proxy would hide that header inside TLS,
// so it cannot inject the credential.
type Egress struct {
	dir         string
	sock        string
	ln          net.Listener
	srv         *http.Server
	token       string
	bearer      func() (string, error)
	hosts       map[string]bool
	first       string
	prefixes    []string
	requireGate bool
	gateMu      sync.Mutex
	gates       map[string]gateBinding
	// onAudit records one loopback request. It is not used for a unix socket.
	// The callback receives the bot, the run, the normalized path, and the status.
	onAudit func(botID, runID, path string, status int)
}

// gateBinding is the bot and run a placeholder bearer was admitted for.
type gateBinding struct {
	botID string
	runID string
}

// StartEgress listens on a unix socket in a private 0700 directory under parent.
// prefixes nil means policy.DefaultProxyPathPrefix (/v1). An empty non-nil
// list allows no path. trip, when set, replaces the outbound transport (tests).
func StartEgress(parent string, hosts, prefixes []string, token string, trip http.RoundTripper) (*Egress, error) {
	if token == "" || len(hosts) == 0 {
		return nil, ErrProxyUnavailable
	}
	resolved, err := resolvePrefixes(prefixes)
	if err != nil {
		return nil, ErrProxyUnavailable
	}
	parent = filepath.Clean(parent)
	if !filepath.IsAbs(parent) {
		return nil, ErrProxyUnavailable
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, ErrProxyUnavailable
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, ErrProxyUnavailable
	}
	dir, err := os.MkdirTemp(parent, "call-")
	if err != nil {
		return nil, ErrProxyUnavailable
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, ErrProxyUnavailable
	}
	allow := map[string]bool{}
	var first string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if first == "" {
			first = h
		}
		allow[h] = true
	}
	if first == "" || !allow[first] {
		_ = os.RemoveAll(dir)
		return nil, ErrProxyUnavailable
	}
	sock := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, ErrProxyUnavailable
	}
	_ = os.Chmod(sock, 0o600)
	eg := &Egress{dir: dir, sock: sock, ln: ln, token: token, hosts: allow, first: first, prefixes: resolved}
	eg.serve(trip)
	return eg, nil
}

// StartLoopback listens on 127.0.0.1 and serves the same reverse proxy as
// StartEgress. bearer is called per accepted request and is not logged.
// The listener injects that bearer only after Admit has registered the
// presented placeholder for this bot run. Any other client is rejected.
// The Grok CLI speaks HTTP, so the chat client needs a TCP origin. A unix
// socket is what the jailed COI forwarder uses; this listener is for a
// process that shares the host network namespace.
func StartLoopback(hosts, prefixes []string, bearer func() (string, error), trip http.RoundTripper) (*Egress, error) {
	if bearer == nil || len(hosts) == 0 {
		return nil, ErrProxyUnavailable
	}
	if _, err := bearer(); err != nil {
		return nil, ErrProxyUnavailable
	}
	resolved, err := resolvePrefixes(prefixes)
	if err != nil {
		return nil, ErrProxyUnavailable
	}
	allow := map[string]bool{}
	var first string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if first == "" {
			first = h
		}
		allow[h] = true
	}
	if first == "" || !allow[first] {
		return nil, ErrProxyUnavailable
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, ErrProxyUnavailable
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcp.IP == nil || !tcp.IP.IsLoopback() {
		_ = ln.Close()
		return nil, ErrProxyUnavailable
	}
	eg := &Egress{ln: ln, bearer: bearer, hosts: allow, first: first, prefixes: resolved, requireGate: true}
	eg.serve(trip)
	return eg, nil
}

// Admit registers one placeholder bearer for one bot and one run. The
// loopback proxy replaces that bearer only when the request names the same
// bot and run. Every other bearer is rejected, including the well-known
// placeholder. The returned function removes it and is safe to call more
// than once. A unix-socket proxy does not consult this set.
func (e *Egress) Admit(botID, runID, secret string) func() {
	if e == nil || !e.requireGate || !acceptableGate(secret) || !SafeRouteID(botID) || !SafeRouteID(runID) {
		return func() {}
	}
	e.gateMu.Lock()
	if e.gates == nil {
		e.gates = map[string]gateBinding{}
	}
	e.gates[secret] = gateBinding{botID: botID, runID: runID}
	e.gateMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			if e == nil {
				return
			}
			e.gateMu.Lock()
			delete(e.gates, secret)
			e.gateMu.Unlock()
		})
	}
}

// SetAudit registers the loopback request record. A nil function disables it.
// The callback must not expect headers, a body, or the presented bearer.
func (e *Egress) SetAudit(fn func(botID, runID, path string, status int)) {
	if e == nil {
		return
	}
	e.gateMu.Lock()
	e.onAudit = fn
	e.gateMu.Unlock()
}

func (e *Egress) note(botID, runID, path string, status int) {
	if e == nil || !e.requireGate {
		return
	}
	e.gateMu.Lock()
	fn := e.onAudit
	e.gateMu.Unlock()
	if fn == nil {
		return
	}
	fn(botID, runID, path, status)
}

func (e *Egress) admits(botID, runID, presented string) bool {
	if e == nil || presented == "" || botID == "" || runID == "" {
		return false
	}
	e.gateMu.Lock()
	defer e.gateMu.Unlock()
	ok := 0
	pb := []byte(presented)
	bb := []byte(botID)
	rb := []byte(runID)
	for secret, g := range e.gates {
		match := subtle.ConstantTimeCompare(pb, []byte(secret))
		botOK := subtle.ConstantTimeCompare(bb, []byte(g.botID))
		runOK := subtle.ConstantTimeCompare(rb, []byte(g.runID))
		ok |= match & botOK & runOK
	}
	return ok == 1
}

// SafeRouteID reports whether id can be one path segment of a proxy route.
func SafeRouteID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func acceptableGate(s string) bool {
	if len(s) < 16 || len(s) > 128 || s == PlaceholderToken {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func presentedBearer(r *http.Request) string {
	if r == nil {
		return ""
	}
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func (e *Egress) serve(trip http.RoundTripper) {
	var transport http.RoundTripper = allowTransport(e.hosts)
	if trip != nil {
		transport = trip
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "https", Host: e.first})
			pr.Out.Host = e.first
			keepForwardHeaders(pr.Out.Header)
			tok, _ := pr.In.Context().Value(egressToken{}).(string)
			if tok == "" {
				tok = e.token
			}
			if tok != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+tok)
			}
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	e.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			botID, runID, norm, fwd, ok := e.prepare(r)
			if !ok || fwd == nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				e.note(botID, runID, norm, http.StatusForbidden)
				return
			}
			if e.requireGate && !e.admits(botID, runID, presentedBearer(r)) {
				http.Error(w, "forbidden", http.StatusForbidden)
				e.note(botID, runID, norm, http.StatusForbidden)
				return
			}
			tok, err := e.currentToken()
			if err != nil || tok == "" {
				http.Error(w, "proxy is not available", http.StatusServiceUnavailable)
				e.note(botID, runID, norm, http.StatusServiceUnavailable)
				return
			}
			dst := w
			var sw *statusWriter
			if e.requireGate {
				sw = &statusWriter{ResponseWriter: w}
				dst = sw
			}
			proxy.ServeHTTP(dst, fwd.WithContext(context.WithValue(fwd.Context(), egressToken{}, tok)))
			if sw != nil {
				e.note(botID, runID, norm, sw.status())
			}
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = e.srv.Serve(e.ln) }()
}

// statusWriter records the response status. Unwrap lets the reverse proxy flush.
type statusWriter struct {
	http.ResponseWriter
	code int
	set  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if s.set {
		return
	}
	s.set = true
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if !s.set {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(p)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) status() int {
	if !s.set || s.code == 0 {
		return http.StatusOK
	}
	return s.code
}

func (e *Egress) currentToken() (string, error) {
	if e == nil {
		return "", ErrProxyUnavailable
	}
	if e.bearer != nil {
		tok, err := e.bearer()
		if err != nil || tok == "" {
			return "", ErrProxyUnavailable
		}
		return tok, nil
	}
	if e.token == "" {
		return "", ErrProxyUnavailable
	}
	return e.token, nil
}

// Base is the loopback origin, with no path. It is empty for a unix-socket proxy.
func (e *Egress) Base() string {
	if e == nil || e.ln == nil || e.ln.Addr() == nil || e.ln.Addr().Network() != "tcp" {
		return ""
	}
	return "http://" + e.ln.Addr().String()
}

func (e *Egress) Sock() string {
	if e == nil {
		return ""
	}
	return e.sock
}

func (e *Egress) Close() {
	if e == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e.srv != nil {
		_ = e.srv.Shutdown(ctx)
	}
	if e.ln != nil {
		_ = e.ln.Close()
	}
	if e.dir != "" {
		_ = os.RemoveAll(e.dir)
	}
}

func (e *Egress) prepare(r *http.Request) (botID, runID, path string, fwd *http.Request, ok bool) {
	if e == nil || r == nil {
		return "", "", "", nil, false
	}
	if !e.requireGate {
		if e.allowRequest(r) && e.allowPath(r) {
			p := ""
			if r.URL != nil {
				p, _ = normalizeProxyPath(r.URL.Path)
			}
			return "", "", p, r, true
		}
		return "", "", "", nil, false
	}
	if r.URL == nil {
		return "", "", "", nil, false
	}
	botID, runID, rest, split := splitBotRun(r.URL.Path)
	if !split {
		return "", "", "", nil, false
	}
	norm, normOK := normalizeProxyPath(rest)
	if !normOK {
		return botID, runID, "", nil, false
	}
	fwd = requestWithPath(r, norm)
	if !e.allowRequest(fwd) || !e.allowPath(fwd) {
		return botID, runID, norm, nil, false
	}
	return botID, runID, norm, fwd, true
}

func splitBotRun(p string) (botID, runID, rest string, ok bool) {
	const bots = "/bots/"
	if !strings.HasPrefix(p, bots) {
		return "", "", "", false
	}
	botID, after, found := strings.Cut(p[len(bots):], "/")
	if !found || !SafeRouteID(botID) {
		return "", "", "", false
	}
	const runs = "runs/"
	if !strings.HasPrefix(after, runs) {
		return "", "", "", false
	}
	runID, tail, found := strings.Cut(after[len(runs):], "/")
	if !found || !SafeRouteID(runID) || tail == "" {
		return "", "", "", false
	}
	return botID, runID, "/" + tail, true
}

func requestWithPath(r *http.Request, path string) *http.Request {
	c := r.Clone(r.Context())
	u := *c.URL
	u.Path = path
	u.RawPath = ""
	c.URL = &u
	if u.RawQuery == "" {
		c.RequestURI = path
	} else {
		c.RequestURI = path + "?" + u.RawQuery
	}
	return c
}

func (e *Egress) allowRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	hosts := []string{}
	if r.Host != "" {
		hosts = append(hosts, r.Host)
	}
	if r.URL != nil && r.URL.Host != "" && r.URL.Host != r.Host {
		hosts = append(hosts, r.URL.Host)
	}
	if len(hosts) == 0 {
		return e.hosts[e.first]
	}
	for _, host := range hosts {
		host = strings.ToLower(host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
			continue
		}
		if !e.hosts[host] {
			return false
		}
	}
	return e.hosts[e.first]
}

func resolvePrefixes(in []string) ([]string, error) {
	if in == nil {
		return []string{policy.DefaultProxyPathPrefix}, nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		n, ok := normalizeProxyPath(p)
		if !ok || n == "/" {
			return nil, ErrProxyUnavailable
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

func (e *Egress) allowPath(r *http.Request) bool {
	if e == nil || r == nil || queryTraversal(r) {
		return false
	}
	cands := pathCandidates(r)
	if len(cands) == 0 || len(e.prefixes) == 0 {
		return false
	}
	var norm string
	for i, c := range cands {
		n, ok := normalizeProxyPath(c)
		if !ok {
			return false
		}
		if i == 0 {
			norm = n
			continue
		}
		if n != norm {
			return false
		}
	}
	for _, p := range e.prefixes {
		if norm == p || strings.HasPrefix(norm, p+"/") {
			return true
		}
	}
	return false
}

func pathCandidates(r *http.Request) []string {
	var out []string
	if r.RequestURI != "" {
		out = append(out, r.RequestURI)
	}
	if r.URL != nil {
		if r.URL.RawPath != "" {
			out = append(out, r.URL.RawPath)
		}
		if r.URL.Path != "" {
			out = append(out, r.URL.Path)
		}
	}
	return out
}

// normalizeProxyPath returns a decoded absolute path with no dot segments,
// empty segments, or encoded separators. ok is false for traversal.
func normalizeProxyPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", false
		}
		if u.RawPath != "" {
			raw = u.RawPath
		} else if u.EscapedPath() != "" {
			raw = u.EscapedPath()
		} else {
			raw = u.Path
		}
	}
	cur := raw
	for i := 0; i < 4; i++ {
		if badProxyPath(cur) {
			return "", false
		}
		if !strings.Contains(cur, "%") {
			break
		}
		next, err := url.PathUnescape(cur)
		if err != nil || next == cur {
			if err != nil {
				return "", false
			}
			break
		}
		cur = next
	}
	if strings.Contains(cur, "%") || badProxyPath(cur) {
		return "", false
	}
	trimmed := strings.TrimRight(cur, "/")
	if trimmed == "" {
		trimmed = "/"
	}
	if path.Clean(trimmed) != trimmed {
		return "", false
	}
	return trimmed, true
}

// forwardHeaders are copied from the caller. Authorization is not one of
// them; the proxy sets that itself. Names match without regard to case.
var forwardHeaders = map[string]bool{
	"content-type":             true,
	"content-length":           true,
	"accept":                   true,
	"accept-encoding":          true,
	"user-agent":               true,
	"x-grok-model-override":    true,
	"x-grok-client-version":    true,
	"x-grok-client-mode":       true,
	"x-grok-client-identifier": true,
	"x-grok-experiments":       true,
	"x-grok-conv-id":           true,
	"x-grok-req-id":            true,
	"x-grok-session-id":        true,
	"x-grok-agent-id":          true,
	"x-grok-turn-id":           true,
	"x-grok-transient-retry":   true,
}

func keepForwardHeaders(h http.Header) {
	if len(h) == 0 {
		return
	}
	var drop []string
	for k := range h {
		if !forwardHeaders[strings.ToLower(strings.TrimSpace(k))] {
			drop = append(drop, k)
		}
	}
	for _, k := range drop {
		delete(h, k)
		h.Del(k)
	}
}

func queryTraversal(r *http.Request) bool {
	if r == nil {
		return false
	}
	var qs []string
	if r.URL != nil && r.URL.RawQuery != "" {
		qs = append(qs, r.URL.RawQuery)
	}
	if r.RequestURI != "" {
		if i := strings.IndexByte(r.RequestURI, '?'); i >= 0 {
			q := r.RequestURI[i+1:]
			if j := strings.IndexByte(q, '#'); j >= 0 {
				q = q[:j]
			}
			qs = append(qs, q)
		}
	}
	for _, q := range qs {
		if badQuery(q) {
			return true
		}
	}
	return false
}

func badQuery(q string) bool {
	cur := q
	for i := 0; i < 3; i++ {
		if strings.Contains(cur, "..") {
			return true
		}
		lower := strings.ToLower(cur)
		if strings.Contains(lower, "%2e%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			return true
		}
		next, err := url.QueryUnescape(cur)
		if err != nil || next == cur {
			return false
		}
		cur = next
		if strings.ContainsAny(cur, `/\`) {
			return true
		}
	}
	return strings.Contains(cur, "..")
}

func badProxyPath(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\\?#\x00") {
		return true
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return true
	}
	if strings.Contains(s, "//") {
		return true
	}
	for _, seg := range strings.Split(strings.TrimRight(s, "/"), "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

func allowTransport(allow map[string]bool) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	tr := base.Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialAllowlisted(ctx, network, addr, allow)
	}
	return tr
}

func dialAllowlisted(ctx context.Context, network, addr string, allow map[string]bool) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if !allow[strings.ToLower(host)] {
		return nil, errors.New("host is not allowlisted")
	}
	var d net.Dialer
	d.Timeout = 15 * time.Second
	return d.DialContext(ctx, network, addr)
}
