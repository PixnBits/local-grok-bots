package sandbox

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPAllow is an HTTP CONNECT and forward proxy. It dials only exact
// allowlisted hosts. Loopback, private, link-local, multicast, and
// unspecified addresses are refused even when the name is listed. An empty
// allowlist denies every request.
type HTTPAllow struct {
	dir    string
	sock   string
	ln     net.Listener
	allow  map[string]bool
	dial   func(context.Context, string, string) (net.Conn, error)
	ctx    context.Context
	cancel context.CancelFunc
}

// StartHTTPAllowProxy listens on a mode-0600 socket named sock in a 0700
// directory under parent. dial, when set, replaces the outbound dial (tests).
func StartHTTPAllowProxy(parent string, allow []string, dial func(context.Context, string, string) (net.Conn, error)) (*HTTPAllow, error) {
	parent = filepath.Clean(parent)
	if !filepath.IsAbs(parent) {
		return nil, errors.New("egress proxy is not available")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, errors.New("egress proxy is not available")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, errors.New("egress proxy is not available")
	}
	dir, err := os.MkdirTemp(parent, "egress-")
	if err != nil {
		return nil, errors.New("egress proxy is not available")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("egress proxy is not available")
	}
	sock := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("egress proxy is not available")
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(dir)
		return nil, errors.New("egress proxy is not available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &HTTPAllow{
		dir: dir, sock: sock, ln: ln, allow: setOf(allow), dial: dial,
		ctx: ctx, cancel: cancel,
	}
	go p.serve()
	return p, nil
}

func (p *HTTPAllow) Sock() string {
	if p == nil {
		return ""
	}
	return p.sock
}

func (p *HTTPAllow) Close() {
	if p == nil {
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	if p.ln != nil {
		_ = p.ln.Close()
	}
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
	}
}

func (p *HTTPAllow) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.serveConn(c)
	}
}

func (p *HTTPAllow) serveConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	host, port, ok := requestTarget(req)
	if !ok || !p.allowed(host) {
		writeDeny(conn)
		return
	}
	req.Host = net.JoinHostPort(host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	defer cancel()
	up, err := p.dialHost(ctx, host, port)
	if err != nil {
		writeDeny(conn)
		return
	}
	defer up.Close()
	if req.Method == http.MethodConnect {
		_ = conn.SetDeadline(time.Time{})
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		splice(bufferedConn{Reader: br, Conn: conn}, up)
		return
	}
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(up); err != nil {
		writeDeny(conn)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_, _ = io.Copy(conn, up)
}

func (p *HTTPAllow) allowed(host string) bool {
	if ip := net.ParseIP(host); ip != nil && forbiddenIP(ip) {
		return false
	}
	return p.allow[host]
}

func (p *HTTPAllow) dialHost(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if p.dial != nil {
		return p.dial(ctx, "tcp", addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if forbiddenIP(ip) {
			return nil, errDenied
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errDenied
	}
	var chosen net.IP
	for _, got := range ips {
		if forbiddenIP(got.IP) {
			return nil, errDenied
		}
		if chosen == nil {
			chosen = got.IP
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", net.JoinHostPort(chosen.String(), strconv.Itoa(port)))
}

func requestTarget(r *http.Request) (string, int, bool) {
	if r == nil || r.URL == nil || r.URL.User != nil {
		return "", 0, false
	}
	var hostport string
	switch {
	case r.Method == http.MethodConnect:
		hostport = r.Host
		if hostport == "" {
			hostport = r.URL.Host
		}
	case r.URL.IsAbs():
		hostport = r.URL.Host
	default:
		return "", 0, false
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		switch {
		case r.Method == http.MethodConnect:
			return "", 0, false
		case r.URL.Scheme == "https":
			portStr = "443"
		case r.URL.Scheme == "http":
			portStr = "80"
		default:
			return "", 0, false
		}
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, " \t/\\") || strings.Contains(host, "%") {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

func forbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast()
}

func writeDeny(conn net.Conn) {
	_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

type bufferedConn struct {
	*bufio.Reader
	net.Conn
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

func splice(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, _ = io.Copy(right, left)
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(left, right)
		wg.Done()
	}()
	wg.Wait()
}

var errDenied = errors.New("denied")
