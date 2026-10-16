package coi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// Egress is the host-side reverse proxy. The jail speaks plain HTTP to a
// loopback forwarder; this process dials TLS to the allowlisted host and
// sets Authorization. A CONNECT proxy would hide that header inside TLS,
// so it cannot inject the credential.
type Egress struct {
	dir      string
	sock     string
	ln       net.Listener
	srv      *http.Server
	token    string
	hosts    map[string]bool
	first    string
	prefixes []string
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
	var transport http.RoundTripper = allowTransport(allow)
	if trip != nil {
		transport = trip
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "https", Host: eg.first})
			pr.Out.Host = eg.first
			keepForwardHeaders(pr.Out.Header)
			pr.Out.Header.Set("Authorization", "Bearer "+eg.token)
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	eg.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !eg.allowRequest(r) || !eg.allowPath(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = eg.srv.Serve(ln) }()
	return eg, nil
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
