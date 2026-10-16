package coi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Egress is the host-side reverse proxy. The jail speaks plain HTTP to a
// loopback forwarder; this process dials TLS to the allowlisted host and
// sets Authorization. A CONNECT proxy would hide that header inside TLS,
// so it cannot inject the credential.
type Egress struct {
	dir   string
	sock  string
	ln    net.Listener
	srv   *http.Server
	token string
	hosts map[string]bool
	first string
}

// StartEgress listens on a unix socket in a private 0700 directory under parent.
// trip, when set, replaces the outbound transport (tests).
func StartEgress(parent string, hosts []string, token string, trip http.RoundTripper) (*Egress, error) {
	if token == "" || len(hosts) == 0 {
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
	eg := &Egress{dir: dir, sock: sock, ln: ln, token: token, hosts: allow, first: first}
	var transport http.RoundTripper = allowTransport(allow)
	if trip != nil {
		transport = trip
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "https", Host: eg.first})
			pr.Out.Host = eg.first
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Set("Authorization", "Bearer "+eg.token)
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	eg.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !eg.allowRequest(r) {
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
