package sandbox

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is one grant use, denial, domain request, or thread notice.
type Event struct {
	Kind   string `json:"kind"`
	Grant  string `json:"grant,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	Detail string `json:"detail,omitempty"`
	Notice string `json:"notice,omitempty"`
}

type proxy struct {
	ln       net.Listener
	ctx      context.Context
	grants   map[string]bool
	netAllow map[string]bool
	sshAllow map[string]bool
	dial     func(context.Context, string, string) (net.Conn, error)
	upstream Upstream
	onEvent  func(Event)
	mu       sync.Mutex
	events   []Event
}

// NetProxy is the allowlist proxy used by a CLI turn.
type NetProxy struct {
	p *proxy
}

// Close stops the proxy listener.
func (n *NetProxy) Close() {
	if n != nil {
		n.p.close()
	}
}

// UseUpstream dials later connections through up. Credentials stay in the
// daemon. A disabled upstream leaves the dial unchanged.
func (n *NetProxy) UseUpstream(up Upstream) {
	if n == nil || n.p == nil || !up.Enabled() {
		return
	}
	n.p.upstream = up
	n.p.dial = up.Wrap(n.p.dial)
}

// SetObserver receives every allow and deny. The callback must not retain
// secrets; events name hosts and the upstream host only.
func (n *NetProxy) SetObserver(fn func(Event)) {
	if n == nil || n.p == nil {
		return
	}
	n.p.onEvent = fn
}

// ListenNetProxy serves the shell proxy protocol on sock.
// The net grant is on. SSH is not. An empty allowlist denies every host.
func ListenNetProxy(ctx context.Context, sock string, allow []string, dial func(context.Context, string, string) (net.Conn, error)) (*NetProxy, error) {
	p, err := startProxy(ctx, sock, []string{"net"}, allow, nil, dial)
	if err != nil {
		return nil, err
	}
	return &NetProxy{p: p}, nil
}

func startProxy(ctx context.Context, sock string, grants, netAllow, sshAllow []string, dial func(context.Context, string, string) (net.Conn, error)) (*proxy, error) {
	if err := os.MkdirAll(filepathDir(sock), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o666)
	p := &proxy{
		ln: ln, ctx: ctx, dial: dial,
		grants:   setOf(grants),
		netAllow: setOf(netAllow),
		sshAllow: setOf(sshAllow),
	}
	go p.serve()
	return p, nil
}

func filepathDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "."
	}
	return p[:i]
}

func setOf(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range xs {
		s = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(s, ".")))
		if s != "" {
			m[s] = true
		}
	}
	return m
}

func (p *proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *proxy) close() {
	if p != nil && p.ln != nil {
		_ = p.ln.Close()
	}
}

func (p *proxy) drain() []Event {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.events
	p.events = nil
	return out
}

func (p *proxy) add(ev Event) {
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
}

func (p *proxy) emit(ev Event) {
	p.add(ev)
	if p.onEvent != nil {
		p.onEvent(ev)
	}
}

func (p *proxy) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := readLine(conn)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	host, port, ok := parseConnect(line)
	if !ok {
		_, _ = conn.Write([]byte("DENY\n"))
		return
	}
	allowed, ev := p.decide(host, port)
	if allowed && p.upstream.Enabled() {
		ev.Detail = p.upstream.Label(host, port)
	}
	if !allowed {
		p.emit(ev)
		_, _ = conn.Write([]byte("DENY\n"))
		return
	}
	dial := p.dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	up, err := dial(p.ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		ev.Notice = ""
		label := ev.Detail
		ev.Detail = "dial failed"
		if label != "" && label != "direct" {
			ev.Detail = "dial failed; " + label
		}
		p.emit(ev)
		_, _ = conn.Write([]byte("DENY\n"))
		return
	}
	defer up.Close()
	p.emit(ev)
	if _, err := conn.Write([]byte("OK\n")); err != nil {
		return
	}
	errc := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, conn); errc <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, up); errc <- struct{}{} }()
	<-errc
	_ = up.Close()
	_ = conn.Close()
	<-errc
}

func (p *proxy) decide(host string, port int) (bool, Event) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if port == 22 {
		if !p.grants["ssh"] {
			return false, Event{Kind: "grant_denied", Grant: "ssh", Host: host, Port: port, Detail: "missing ssh grant"}
		}
		if !p.sshAllow[host] {
			return false, Event{Kind: "grant_denied", Grant: "ssh", Host: host, Port: port, Detail: "not allowlisted"}
		}
		return true, Event{Kind: "grant_use", Grant: "ssh", Host: host, Port: port, Notice: "SSH to " + host}
	}
	if !p.grants["net"] {
		return false, Event{Kind: "grant_denied", Grant: "net", Host: host, Port: port, Detail: "missing net grant"}
	}
	if !p.netAllow[host] {
		return false, Event{Kind: "net_request", Grant: "net", Host: host, Port: port, Detail: "not allowlisted"}
	}
	return true, Event{Kind: "grant_use", Grant: "net", Host: host, Port: port}
}

func readLine(conn net.Conn) (string, error) {
	var b [320]byte
	n := 0
	for n < len(b) {
		var one [1]byte
		_, err := conn.Read(one[:])
		if err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return string(b[:n]), nil
		}
		b[n] = one[0]
		n++
	}
	return "", io.ErrShortBuffer
}

func parseConnect(line string) (string, int, bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "CONNECT" {
		return "", 0, false
	}
	host := fields[1]
	if host == "" || strings.ContainsAny(host, " \t/\\") {
		return "", 0, false
	}
	port, err := strconv.Atoi(fields[2])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}
