package github

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Audit is one proxy decision. It has no header, no body, and no token.
// Method is the request method. A non-GET is action github_write.
type Audit struct {
	Bot      string `json:"bot,omitempty"`
	Run      string `json:"run,omitempty"`
	Action   string `json:"action"`
	Owner    string `json:"owner,omitempty"`
	Repo     string `json:"repo,omitempty"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
}

// Access selects which routes a proxy instance forwards.
// The zero value is AccessRead.
type Access int

const (
	// AccessRead is the jail socket and host reads: upload-pack and the
	// listed GET API routes. It does not push or call a write API.
	AccessRead Access = iota
	// AccessWrite is opened on the host after an approval card. It is not
	// mounted in the jail and it does not listen on a unix socket.
	AccessWrite
)

// Config builds a credential proxy. Token is read on each forwarded request
// and is not logged. GitBase and APIBase default to https://github.com and
// https://api.github.com. Tests point them at an httptest server.
type Config struct {
	Repos   []string
	Token   func() (string, error)
	GitBase string
	APIBase string
	Audit   func(Audit)
	// Access defaults to AccessRead. AccessWrite is a second instance used
	// only for a push or create_pr after the card is approved.
	Access Access
}

// Proxy is a host-side reverse proxy. It adds Authorization only for an
// allowlisted owner/repo on github.com or api.github.com, and it drops any
// caller Authorization first. The jail reaches a read proxy through a unix
// socket. A TCP listener on 127.0.0.1 requires an unguessable path gate.
// A write proxy is a separate instance: TCP only, never the jail socket.
type Proxy struct {
	access  Access
	repos   map[string]bool
	token   func() (string, error)
	gitBase *url.URL
	apiBase *url.URL
	client  *http.Client
	audit   func(Audit)

	mu      sync.Mutex
	bot     string
	run     string
	gate    string
	dir     string
	sock    string
	unixLn  net.Listener
	tcpLn   net.Listener
	unixSrv *http.Server
	tcpSrv  *http.Server
}

// New checks the repository list and the upstream bases. An empty repository
// list is valid and refuses every request.
func New(cfg Config) (*Proxy, error) {
	if cfg.Token == nil {
		return nil, errors.New("github proxy is not available")
	}
	repos, err := NormalizeRepos(cfg.Repos)
	if err != nil {
		return nil, err
	}
	gitBase, err := parseBase(cfg.GitBase, "https://github.com")
	if err != nil {
		return nil, err
	}
	apiBase, err := parseBase(cfg.APIBase, "https://api.github.com")
	if err != nil {
		return nil, err
	}
	allow := map[string]bool{}
	for _, r := range repos {
		allow[r] = true
	}
	gate, err := newGate()
	if err != nil {
		return nil, errors.New("github proxy is not available")
	}
	if cfg.Access != AccessRead && cfg.Access != AccessWrite {
		return nil, errors.New("github proxy is not available")
	}
	p := &Proxy{
		access:  cfg.Access,
		repos:   allow,
		token:   cfg.Token,
		gitBase: gitBase,
		apiBase: apiBase,
		audit:   cfg.Audit,
		gate:    gate,
		client: &http.Client{
			Transport: lockedTransport(gitBase, apiBase),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return p, nil
}

func parseBase(raw, fallback string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		raw = fallback
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("github proxy is not available")
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, errors.New("github proxy is not available")
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("github proxy is not available")
	}
	u.Path = ""
	u.RawPath = ""
	return u, nil
}

func newGate() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func lockedTransport(bases ...*url.URL) http.RoundTripper {
	allow := map[string]bool{}
	for _, u := range bases {
		if u == nil {
			continue
		}
		allow[strings.ToLower(u.Hostname())] = true
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	tr := base.Clone()
	tr.Proxy = nil
	tr.ResponseHeaderTimeout = 60 * time.Second
	tr.TLSHandshakeTimeout = 15 * time.Second
	dial := tr.DialContext
	if dial == nil {
		var d net.Dialer
		d.Timeout = 15 * time.Second
		dial = d.DialContext
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, errors.New("host is not allowlisted")
		}
		if !allow[strings.ToLower(host)] {
			return nil, errors.New("host is not allowlisted")
		}
		return dial(ctx, network, addr)
	}
	return tr
}

// Bind records the bot and run copied into later audit rows.
func (p *Proxy) Bind(bot, run string) {
	if p == nil {
		return
	}
	if !safeID(bot) {
		bot = ""
	}
	if !safeID(run) {
		run = ""
	}
	p.mu.Lock()
	p.bot, p.run = bot, run
	p.mu.Unlock()
}

func safeID(s string) bool {
	if len(s) > 128 {
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

// Gate is the TCP path secret. The unix socket does not require it.
func (p *Proxy) Gate() string {
	if p == nil {
		return ""
	}
	return p.gate
}

// Sock is the unix socket path. It is empty until ListenUnix succeeds.
func (p *Proxy) Sock() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sock
}

// ServeHTTP forwards without the TCP gate. The unix listener and tests use it.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.serve(w, r, false)
}

// ListenUnix serves on a mode-0600 socket named sock in a 0700 directory
// under parent. The socket path does not require the TCP gate.
func (p *Proxy) ListenUnix(parent string) error {
	if p == nil || p.access == AccessWrite {
		return errors.New("github proxy is not available")
	}
	parent = filepath.Clean(parent)
	if !filepath.IsAbs(parent) {
		return errors.New("github proxy is not available")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return errors.New("github proxy is not available")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return errors.New("github proxy is not available")
	}
	dir, err := os.MkdirTemp(parent, "gh-")
	if err != nil {
		return errors.New("github proxy is not available")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return errors.New("github proxy is not available")
	}
	sock := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		return errors.New("github proxy is not available")
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(dir)
		return errors.New("github proxy is not available")
	}
	srv := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	p.mu.Lock()
	p.dir = dir
	p.sock = sock
	p.unixLn = ln
	p.unixSrv = srv
	p.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// ListenTCP serves on 127.0.0.1 and returns the origin including the gate
// prefix, for example http://127.0.0.1:1234/g/<gate>. Requests without that
// prefix are refused. The token is not part of the URL.
func (p *Proxy) ListenTCP() (string, error) {
	if p == nil {
		return "", errors.New("github proxy is not available")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", errors.New("github proxy is not available")
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.serve(w, r, true)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	p.mu.Lock()
	if p.tcpLn != nil {
		p.mu.Unlock()
		_ = ln.Close()
		return "", errors.New("github proxy is not available")
	}
	p.tcpLn = ln
	p.tcpSrv = srv
	p.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	return "http://" + ln.Addr().String() + "/g/" + p.gate, nil
}

// Close stops listeners and removes the socket directory.
func (p *Proxy) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	unixSrv, tcpSrv := p.unixSrv, p.tcpSrv
	dir := p.dir
	p.unixSrv, p.tcpSrv = nil, nil
	p.unixLn, p.tcpLn = nil, nil
	p.sock = ""
	p.dir = ""
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if unixSrv != nil {
		_ = unixSrv.Shutdown(ctx)
	}
	if tcpSrv != nil {
		_ = tcpSrv.Shutdown(ctx)
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	return nil
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request, requireGate bool) {
	if p == nil || r == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	method := ""
	if r.Method != "" {
		method = r.Method
	}
	if r.Method == http.MethodConnect || r.Method == "PRI" || r.URL == nil || r.URL.User != nil {
		p.finish(w, http.StatusForbidden, "", "", "", "method", method)
		return
	}
	path, ok := requestPath(r)
	if !ok {
		p.finish(w, http.StatusForbidden, clipPath(r.URL.Path), "", "", "path", method)
		return
	}
	if requireGate {
		path, ok = stripGate(path, p.gate)
		if !ok {
			p.finish(w, http.StatusForbidden, "/", "", "", "gate", method)
			return
		}
	}
	service, rest, ok := splitService(path)
	if !ok {
		p.finish(w, http.StatusForbidden, clipPath(path), "", "", "path", method)
		return
	}
	route, err := Classify(service, rest, r.URL.RawQuery, p.repos)
	if errors.Is(err, ErrNotAllowed) {
		p.finish(w, http.StatusForbidden, route.Path, route.Owner, route.Repo, "repo", method)
		return
	}
	if err != nil {
		p.finish(w, http.StatusForbidden, clipPath(path), "", "", "path", method)
		return
	}
	if !accessOK(p.access, route, r.Method) {
		reason := "method"
		if r.Method == http.MethodGet {
			reason = "route"
		}
		p.finish(w, http.StatusForbidden, route.Path, route.Owner, route.Repo, reason, method)
		return
	}
	tok, err := p.token()
	if err != nil || !TokenShape(tok) {
		p.finish(w, http.StatusServiceUnavailable, route.Path, route.Owner, route.Repo, "token", method)
		return
	}
	if strings.Contains(path, tok) || strings.Contains(r.URL.RawQuery, tok) {
		p.finish(w, http.StatusForbidden, "/", "", "", "path", method)
		return
	}
	base := p.gitBase
	if route.Service == "api" {
		base = p.apiBase
	}
	status, ferr := p.forward(w, r, base, route, tok)
	if ferr != nil {
		if status == 0 {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			status = http.StatusBadGateway
		}
		p.note(status, route.Path, route.Owner, route.Repo, "refuse", "upstream", method)
		return
	}
	p.note(status, route.Path, route.Owner, route.Repo, "allow", "", method)
}

func (p *Proxy) finish(w http.ResponseWriter, status int, path, owner, repo, reason, method string) {
	http.Error(w, http.StatusText(status), status)
	decision := "refuse"
	if status >= 200 && status < 300 {
		decision = "allow"
	}
	p.note(status, path, owner, repo, decision, reason, method)
}

func (p *Proxy) note(status int, path, owner, repo, decision, reason, method string) {
	if p == nil || p.audit == nil {
		return
	}
	p.mu.Lock()
	bot, run := p.bot, p.run
	p.mu.Unlock()
	p.audit(Audit{
		Bot: bot, Run: run, Action: auditAction(decision, method),
		Owner: owner, Repo: repo, Decision: decision, Reason: reason,
		Method: method, Path: clipPath(path), Status: status,
	})
}

func auditAction(decision, method string) string {
	if method != http.MethodGet {
		return "github_write"
	}
	if decision == "allow" {
		return "github_allow"
	}
	return "github_refuse"
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, base *url.URL, route Route, tok string) (int, error) {
	u := *base
	u.Path = route.Path
	u.RawQuery = route.Query
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		return 0, err
	}
	copyHeaders(req.Header, r.Header, requestHeaders)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Host = u.Host
	if r.ContentLength > 0 {
		req.ContentLength = r.ContentLength
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return 0, errors.New("redirect")
	}
	copyHeaders(w.Header(), resp.Header, responseHeaders)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, nil
}

var requestHeaders = map[string]bool{
	"content-type":    true,
	"accept":          true,
	"user-agent":      true,
	"git-protocol":    true,
	"accept-encoding": true,
}

var responseHeaders = map[string]bool{
	"content-type":  true,
	"cache-control": true,
	"pragma":        true,
	"expires":       true,
	"vary":          true,
}

func copyHeaders(dst, src http.Header, allow map[string]bool) {
	if src == nil {
		return
	}
	for k, vs := range src {
		if !allow[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			if strings.ContainsAny(v, "\r\n\x00") {
				continue
			}
			dst.Add(k, v)
		}
	}
}

func accessOK(access Access, route Route, method string) bool {
	if access == AccessWrite {
		return writeAccess(route, method)
	}
	return readAccess(route, method)
}

func readAccess(route Route, method string) bool {
	if route.Service == "github" {
		switch gitTail(route.Path) {
		case "info/refs":
			return method == http.MethodGet && route.Query == "service=git-upload-pack"
		case "git-upload-pack":
			return method == http.MethodPost && route.Query == ""
		default:
			return false
		}
	}
	if route.Service != "api" || method != http.MethodGet {
		return false
	}
	return apiReadPath(route.Path)
}

func writeAccess(route Route, method string) bool {
	if route.Service == "github" {
		switch gitTail(route.Path) {
		case "info/refs":
			return method == http.MethodGet && route.Query == "service=git-receive-pack"
		case "git-receive-pack":
			return method == http.MethodPost && route.Query == ""
		default:
			return false
		}
	}
	if route.Service != "api" || method != http.MethodPost {
		return false
	}
	return apiPullCreate(route.Path)
}

func gitTail(path string) string {
	parts := splitParts(path)
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[2:], "/")
}

func apiReadPath(path string) bool {
	parts := splitParts(path)
	if len(parts) < 3 || parts[0] != "repos" {
		return false
	}
	if len(parts) == 3 {
		return true
	}
	return len(parts) == 5 && parts[3] == "pulls" && pullNumber(parts[4])
}

func apiPullCreate(path string) bool {
	parts := splitParts(path)
	return len(parts) == 4 && parts[0] == "repos" && parts[3] == "pulls"
}

func pullNumber(s string) bool {
	if s == "" || len(s) > 10 || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func splitService(path string) (service, rest string, ok bool) {
	switch {
	case strings.HasPrefix(path, "/github/"):
		return "github", path[len("/github"):], true
	case strings.HasPrefix(path, "/api/"):
		return "api", path[len("/api"):], true
	default:
		return "", "", false
	}
}

func stripGate(path, gate string) (string, bool) {
	const prefix = "/g/"
	if !strings.HasPrefix(path, prefix) || gate == "" {
		return "", false
	}
	rest := path[len(prefix):]
	seg, tail, found := strings.Cut(rest, "/")
	if !found || !gateEqual(seg, gate) {
		return "", false
	}
	return "/" + tail, true
}

func gateEqual(got, want string) bool {
	if len(got) != len(want) || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func requestPath(r *http.Request) (string, bool) {
	var cands []string
	if r.URL != nil {
		if r.URL.RawPath != "" {
			cands = append(cands, r.URL.RawPath)
		}
		if r.URL.Path != "" {
			cands = append(cands, r.URL.Path)
		}
	}
	if r.RequestURI != "" && r.RequestURI != "*" {
		cands = append(cands, r.RequestURI)
	}
	if len(cands) == 0 {
		return "", false
	}
	var norm string
	for i, c := range cands {
		n, ok := normalizePath(c)
		if !ok {
			return "", false
		}
		if i == 0 {
			norm = n
			continue
		}
		if n != norm {
			return "", false
		}
	}
	return norm, true
}

func clipPath(s string) string {
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return "/"
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
