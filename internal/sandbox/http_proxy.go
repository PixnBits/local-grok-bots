package sandbox

import (
	"bufio"
	"bytes"
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

// EgressConfig is an allowlisting HTTP CONNECT and forward proxy.
// Resolve, when set, replaces DNS. Dial, when set, replaces the TCP dial.
// Both receive the address after the forbidden-IP check. Ports nil means
// 443 and 80. An empty Ports list allows no port.
type EgressConfig struct {
	Allow   []string
	Ports   []int
	Resolve func(context.Context, string) ([]net.IP, error)
	Dial    func(context.Context, string, string) (net.Conn, error)
	Audit   func(EgressEvent)
}

// EgressEvent is one allow or deny. It has no header and no body.
type EgressEvent struct {
	Host   string
	Port   int
	Allow  bool
	Reason string
}

// HTTPAllow is an HTTP CONNECT and forward proxy. It dials only exact
// allowlisted hosts, and only on an allowed port. It resolves a name once,
// refuses a forbidden address, and dials that IP. An empty allowlist denies
// every request.
type HTTPAllow struct {
	dir     string
	sock    string
	ln      net.Listener
	allow   map[string]bool
	ports   []int
	resolve func(context.Context, string) ([]net.IP, error)
	dial    func(context.Context, string, string) (net.Conn, error)
	audit   func(EgressEvent)
	ctx     context.Context
	cancel  context.CancelFunc
}

// StartHTTPAllowProxy listens on a mode-0600 socket named sock in a 0700
// directory under parent.
func StartHTTPAllowProxy(parent string, cfg EgressConfig) (*HTTPAllow, error) {
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
		dir: dir, sock: sock, ln: ln, allow: setOf(cfg.Allow), ports: cfg.Ports,
		resolve: cfg.Resolve, dial: cfg.Dial, audit: cfg.Audit,
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
	if !ok {
		writeDeny(conn)
		return
	}
	decide := func(allow bool, reason string) {
		if p.audit == nil {
			return
		}
		p.audit(EgressEvent{Host: host, Port: port, Allow: allow, Reason: reason})
	}
	if !p.allowed(host) {
		reason := "host"
		if ip := net.ParseIP(host); ip != nil && forbiddenIP(ip) {
			reason = "address"
		}
		decide(false, reason)
		writeDeny(conn)
		return
	}
	if !p.portAllowed(port) {
		decide(false, "port")
		writeDeny(conn)
		return
	}
	req.Host = net.JoinHostPort(host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	defer cancel()
	up, err := p.dialHost(ctx, host, port)
	if err != nil {
		reason := "dial"
		if errors.Is(err, errAddress) {
			reason = "address"
		} else if errors.Is(err, errResolve) {
			reason = "resolve"
		}
		decide(false, reason)
		writeDeny(conn)
		return
	}
	defer up.Close()
	if req.Method == http.MethodConnect {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		hello, reason := readConnectSNI(br, host)
		_ = conn.SetDeadline(time.Time{})
		if reason != "" {
			decide(false, reason)
			return
		}
		decide(true, "ok")
		left := streamConn{Conn: conn, r: io.MultiReader(bytes.NewReader(hello), br)}
		splice(left, up)
		return
	}
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(up); err != nil {
		decide(false, "dial")
		writeDeny(conn)
		return
	}
	decide(true, "ok")
	_ = conn.SetDeadline(time.Time{})
	_, _ = io.Copy(conn, up)
}

func (p *HTTPAllow) allowed(host string) bool {
	if ip := net.ParseIP(host); ip != nil && forbiddenIP(ip) {
		return false
	}
	return p.allow[host]
}

func (p *HTTPAllow) portAllowed(port int) bool {
	list := p.ports
	if list == nil {
		list = []int{443, 80}
	}
	for _, n := range list {
		if n == port {
			return true
		}
	}
	return false
}

func (p *HTTPAllow) dialHost(ctx context.Context, host string, port int) (net.Conn, error) {
	ip, err := p.chooseIP(ctx, host)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	if p.dial != nil {
		return p.dial(ctx, "tcp", addr)
	}
	// The resolver refuses lookups. The address is already an IP, so a second
	// resolution cannot swap in a different answer.
	d := net.Dialer{Resolver: refuseDNS()}
	return d.DialContext(ctx, "tcp", addr)
}

func (p *HTTPAllow) chooseIP(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if forbiddenIP(ip) {
			return nil, errAddress
		}
		return append(net.IP(nil), ip...), nil
	}
	ips, err := p.lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errResolve
	}
	var chosen net.IP
	for _, ip := range ips {
		if ip == nil || forbiddenIP(ip) {
			return nil, errAddress
		}
		if chosen == nil {
			chosen = append(net.IP(nil), ip...)
		}
	}
	if chosen == nil {
		return nil, errResolve
	}
	return chosen, nil
}

func (p *HTTPAllow) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if p.resolve != nil {
		return p.resolve(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			out = append(out, append(net.IP(nil), addr.IP...))
		}
	}
	return out, nil
}

func refuseDNS() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dns disabled")
		},
	}
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
	// To4 unmaps an IPv4-mapped IPv6 address before the IPv4 checks.
	if v4 := ip.To4(); v4 != nil {
		return forbidden4(v4)
	}
	v6 := ip.To16()
	if v6 == nil {
		return true
	}
	return forbidden6(v6)
}

func forbidden4(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// This-network (the whole zero prefix), shared CGNAT space, and the
	// benchmarking range. Checked on the unmapped IPv4 address.
	if ip[0] == 0 {
		return true
	}
	if ip[0] == 100 && ip[1]&0xc0 == 0x40 {
		return true
	}
	if ip[0] == 198 && ip[1]&0xfe == 18 {
		return true
	}
	return false
}

func forbidden6(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// Well-known NAT64 prefix and 6to4. The whole prefix is refused.
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b && allZero(ip[4:12]) {
		return true
	}
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return true
	}
	return false
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func writeDeny(conn net.Conn) {
	_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

type streamConn struct {
	net.Conn
	r io.Reader
}

func (c streamConn) Read(p []byte) (int, error) { return c.r.Read(p) }

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

var (
	errAddress = errors.New("address")
	errResolve = errors.New("resolve")
)
