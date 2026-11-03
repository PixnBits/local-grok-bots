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
	"sync/atomic"
	"time"
)

// EgressConfig is an allowlisting HTTP CONNECT and forward proxy.
// Resolve, when set, replaces DNS. Dial, when set, replaces the TCP dial.
// Both receive the address after the forbidden-IP check. Ports nil means
// 443 and 80. An empty Ports list allows no port.
//
// Decide, when set, replaces the Allow-list host check. The bool is the
// policy decision and the Event is the sandbox record. Port limits,
// forbidden addresses, resolve-once, and CONNECT SNI still apply. Record
// receives that event at the same moments as the splice proxy: immediately
// on deny, after a failed dial, and when the request is allowed through.
// Nil Decide keeps the Allow list and Audit behaviour used by the CLI jail.
type EgressConfig struct {
	Allow   []string
	Ports   []int
	Resolve func(context.Context, string) ([]net.IP, error)
	Dial    func(context.Context, string, string) (net.Conn, error)
	Audit   func(EgressEvent)
	Decide  func(host string, port int) (bool, Event)
	Record  func(Event)
}

// EgressEvent is one allow or deny. It has no header and no body.
// Count is how many denials this emission stands for. Zero means one allow.
type EgressEvent struct {
	Host   string
	Port   int
	Allow  bool
	Reason string
	Count  int
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
	decide  func(string, int) (bool, Event)
	record  func(Event)
	ctx     context.Context
	cancel  context.CancelFunc
	slotMu  sync.Mutex
	slots   int
	busy    busyNote
	denies  reasonNote

	closeOnce sync.Once
	wg        sync.WaitGroup
	liveMu    sync.Mutex
	live      map[net.Conn]struct{}
	shut      bool
}

// upstreamIdle is how long a plain response may sit without progress.
const upstreamIdle = 60 * time.Second

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
		decide: cfg.Decide, record: cfg.Record,
		ctx: ctx, cancel: cancel,
	}
	p.start()
	return p, nil
}

// listenShellEgress serves cfg on an existing unix path. The socket is mode
// 0666 so the jail uid can connect. The directory is not removed on Close.
// The CLI jail keeps using StartHTTPAllowProxy.
func listenShellEgress(ctx context.Context, sock string, cfg EgressConfig) (*HTTPAllow, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := os.MkdirAll(filepathDir(sock), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	p := &HTTPAllow{
		sock: sock, ln: ln, allow: setOf(cfg.Allow), ports: cfg.Ports,
		resolve: cfg.Resolve, dial: cfg.Dial, audit: cfg.Audit,
		decide: cfg.Decide, record: cfg.Record,
		ctx: cctx, cancel: cancel,
	}
	p.start()
	return p, nil
}

func (p *HTTPAllow) Sock() string {
	if p == nil {
		return ""
	}
	return p.sock
}

func (p *HTTPAllow) start() {
	p.wg.Add(1)
	go p.serve()
	go p.watchParent()
}

func (p *HTTPAllow) watchParent() {
	if p == nil || p.ctx == nil {
		return
	}
	<-p.ctx.Done()
	p.Close()
}

func (p *HTTPAllow) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		if p.ln != nil {
			_ = p.ln.Close()
		}
		p.closeLive()
		p.wg.Wait()
		p.flushDenies()
		if p.dir != "" {
			_ = os.RemoveAll(p.dir)
		}
	})
}

func (p *HTTPAllow) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.slotMu.Lock()
		if p.slots >= connLimit {
			p.slotMu.Unlock()
			p.rejectBusy(c)
			continue
		}
		p.slots++
		p.slotMu.Unlock()
		p.wg.Add(1)
		go func(conn net.Conn) {
			defer p.wg.Done()
			defer p.releaseSlot()
			p.serveConn(conn)
		}(c)
	}
}

func (p *HTTPAllow) releaseSlot() {
	p.slotMu.Lock()
	if p.slots > 0 {
		p.slots--
	}
	p.slotMu.Unlock()
}

// rejectBusy answers 503 without starting a connection handler.
// The audit and record hooks are notified at most once per second.
func (p *HTTPAllow) rejectBusy(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	_ = conn.Close()
	emit, detail := p.busy.mark()
	if !emit {
		return
	}
	if p.record != nil {
		p.record(Event{Kind: "grant_denied", Detail: detail})
	}
	if p.audit != nil {
		p.audit(EgressEvent{Allow: false, Reason: "busy"})
	}
}

// httpHeaderMax is the cap on the request line plus headers. The limit is
// lifted after a successful parse so a CONNECT tunnel or a request body is
// not cut off by it.
const httpHeaderMax = 64 << 10

func (p *HTTPAllow) serveConn(conn net.Conn) {
	defer conn.Close()
	if !p.addLive(conn) {
		return
	}
	defer p.removeLive(conn)
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	lim := &byteCap{r: conn, max: httpHeaderMax}
	br := bufio.NewReader(lim)
	req, err := http.ReadRequest(br)
	if err != nil {
		if lim.over() {
			_, _ = io.WriteString(conn, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			ev := Event{Kind: "grant_denied", Detail: "header"}
			p.noteDeny("header", "", 0, &ev)
		}
		return
	}
	lim.lift()
	host, port, ok := requestTarget(req)
	if !ok {
		writeDeny(conn)
		return
	}
	audit := func(allow bool, reason string) {
		if allow {
			if p.audit != nil {
				p.audit(EgressEvent{Host: host, Port: port, Allow: true, Reason: reason})
			}
			return
		}
		p.noteDeny(reason, host, port, nil)
	}
	record := func(ev Event) {
		if p.record != nil {
			p.record(ev)
		}
	}
	var policy Event
	havePolicy := false
	if p.decide != nil {
		allow, ev := p.decide(host, port)
		if !allow {
			record(ev)
			audit(false, "host")
			writeDeny(conn)
			return
		}
		if ip := net.ParseIP(host); ip != nil && forbiddenIP(ip) {
			ev.Kind = "grant_denied"
			ev.Detail = "address"
			ev.Notice = ""
			record(ev)
			audit(false, "address")
			writeDeny(conn)
			return
		}
		policy = ev
		havePolicy = true
	} else if !p.allowed(host) {
		reason := "host"
		if ip := net.ParseIP(host); ip != nil && forbiddenIP(ip) {
			reason = "address"
		}
		audit(false, reason)
		writeDeny(conn)
		return
	}
	if !p.portAllowed(port) {
		if havePolicy {
			ev := policy
			ev.Kind = "grant_denied"
			ev.Detail = "port"
			ev.Notice = ""
			record(ev)
		}
		audit(false, "port")
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
		if havePolicy {
			ev := policy
			if reason == "address" {
				ev.Kind = "grant_denied"
				ev.Detail = "address"
				ev.Notice = ""
			} else {
				ev.Notice = ""
				ev.Detail = "dial failed"
			}
			record(ev)
		}
		audit(false, reason)
		writeDeny(conn)
		return
	}
	if !p.addLive(up) {
		_ = up.Close()
		return
	}
	defer p.removeLive(up)
	defer up.Close()
	if req.Method == http.MethodConnect {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		hello, reason := readConnectSNI(br, host)
		_ = conn.SetDeadline(time.Time{})
		if reason != "" {
			if havePolicy {
				ev := policy
				ev.Kind = "grant_denied"
				ev.Detail = reason
				ev.Notice = ""
				record(ev)
			}
			audit(false, reason)
			return
		}
		if havePolicy {
			record(policy)
		}
		audit(true, "ok")
		left := streamConn{Conn: conn, r: io.MultiReader(bytes.NewReader(hello), br)}
		splice(left, up)
		return
	}
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Connection")
	// The body is written with the request, and one response is read.
	// Leave Expect off so the upstream does not send 100 Continue first.
	req.Header.Del("Expect")
	req.Close = true
	_ = up.SetWriteDeadline(time.Now().Add(upstreamIdle))
	if err := req.Write(up); err != nil {
		if havePolicy {
			ev := policy
			ev.Notice = ""
			ev.Detail = "dial failed"
			record(ev)
		}
		audit(false, "dial")
		writeDeny(conn)
		return
	}
	_ = up.SetWriteDeadline(time.Time{})
	if havePolicy {
		record(policy)
	}
	audit(true, "ok")
	_ = conn.SetDeadline(time.Time{})
	p.copyResponse(conn, up, req)
}

// copyResponse reads one upstream response and writes it to the client.
// Both connections are closed before it returns. A client close closes upstream.
func (p *HTTPAllow) copyResponse(conn, up net.Conn, req *http.Request) {
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		var one [1]byte
		_, err := conn.Read(one[:])
		if stop.Load() || err == nil {
			return
		}
		_ = up.Close()
	}()
	defer func() {
		stop.Store(true)
		_ = up.Close()
		_ = conn.Close()
		<-done
	}()
	resp, err := http.ReadResponse(bufio.NewReader(idleConn{Conn: up, idle: upstreamIdle}), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	resp.Header.Del("Connection")
	resp.Close = true
	_ = resp.Write(idleConn{Conn: conn, idle: upstreamIdle})
}

func (p *HTTPAllow) noteDeny(reason, host string, port int, rec *Event) {
	em, ok := p.denies.mark(reason, host, port, rec)
	if !ok {
		return
	}
	p.emitDeny(em)
}

func (p *HTTPAllow) flushDenies() {
	for _, em := range p.denies.flush() {
		p.emitDeny(em)
	}
}

func (p *HTTPAllow) emitDeny(em reasonEmit) {
	if em.count < 1 {
		return
	}
	if em.doRec && p.record != nil {
		ev := em.record
		ev.Count = em.count
		p.record(ev)
	}
	if p.audit != nil {
		p.audit(EgressEvent{
			Host: em.host, Port: em.port, Allow: false, Reason: em.reason, Count: em.count,
		})
	}
}

func (p *HTTPAllow) addLive(c net.Conn) bool {
	if c == nil {
		return false
	}
	p.liveMu.Lock()
	shut := p.shut
	if !shut {
		if p.live == nil {
			p.live = map[net.Conn]struct{}{}
		}
		p.live[c] = struct{}{}
	}
	p.liveMu.Unlock()
	if shut {
		_ = c.Close()
		return false
	}
	return true
}

func (p *HTTPAllow) removeLive(c net.Conn) {
	if c == nil {
		return
	}
	p.liveMu.Lock()
	delete(p.live, c)
	p.liveMu.Unlock()
}

func (p *HTTPAllow) closeLive() {
	p.liveMu.Lock()
	p.shut = true
	conns := make([]net.Conn, 0, len(p.live))
	for c := range p.live {
		conns = append(conns, c)
	}
	p.live = nil
	p.liveMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
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

// byteCap counts bytes from r. max > 0 stops further reads at that many
// bytes. max 0 is unlimited. lift clears the cap without discarding bytes
// already buffered by the caller.
type byteCap struct {
	r   io.Reader
	n   int
	max int
}

func (b *byteCap) Read(p []byte) (int, error) {
	if b.max > 0 && b.n >= b.max {
		return 0, io.ErrUnexpectedEOF
	}
	if b.max > 0 && len(p) > b.max-b.n {
		p = p[:b.max-b.n]
	}
	n, err := b.r.Read(p)
	b.n += n
	return n, err
}

func (b *byteCap) lift() { b.max = 0 }

func (b *byteCap) over() bool { return b != nil && b.max > 0 && b.n >= b.max }

// idleConn refreshes the read and write deadlines on each call.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(p)
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
