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
// Untrusted events are lines the jail wrote. Reported is the kind that line
// claimed. A jailed process can write anything, so those fields are not a
// grant decision and are not a sandbox_block.
// Count is how many identical events this entry stands for. Zero means one.
type Event struct {
	Kind      string `json:"kind"`
	Grant     string `json:"grant,omitempty"`
	Host      string `json:"host,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Notice    string `json:"notice,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Untrusted bool   `json:"untrusted,omitempty"`
	Reported  string `json:"reported,omitempty"`
	Count     int    `json:"count,omitempty"`
}

// eventCap is the most distinct events kept for one run.
const eventCap = 256

type proxy struct {
	ln       net.Listener
	ctx      context.Context
	grants   map[string]bool
	netAllow map[string]bool
	sshAllow map[string]bool
	dial     func(context.Context, string, string) (net.Conn, error)
	mu       sync.Mutex
	events   []Event
	dropped  int
	slotMu   sync.Mutex
	slots    int
	busy     busyNote
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
		p.slotMu.Lock()
		if p.slots >= connLimit {
			p.slotMu.Unlock()
			p.rejectBusy(c)
			continue
		}
		p.slots++
		p.slotMu.Unlock()
		go func(conn net.Conn) {
			defer p.releaseSlot()
			p.handle(conn)
		}(c)
	}
}

func (p *proxy) releaseSlot() {
	p.slotMu.Lock()
	if p.slots > 0 {
		p.slots--
	}
	p.slotMu.Unlock()
}

// rejectBusy closes a connection that is not HTTP. The busy event is
// recorded at most once per second.
func (p *proxy) rejectBusy(conn net.Conn) {
	_ = conn.Close()
	emit, detail := p.busy.mark()
	if !emit {
		return
	}
	p.add(Event{Kind: "grant_denied", Detail: detail})
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
	dropped := p.dropped
	p.events = nil
	p.dropped = 0
	if dropped > 0 {
		out = append(out, Event{Kind: "grant_denied", Detail: "events dropped", Count: dropped})
	}
	return out
}

func (p *proxy) add(ev Event) {
	n := ev.Count
	if n < 1 {
		n = 1
	}
	ev.Count = n
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.events {
		if sameEvent(p.events[i], ev) {
			p.events[i].Count += n
			return
		}
	}
	if len(p.events) >= eventCap {
		p.dropped += n
		return
	}
	p.events = append(p.events, ev)
}

func sameEvent(a, b Event) bool {
	return a.Kind == b.Kind && a.Grant == b.Grant && a.Host == b.Host && a.Detail == b.Detail &&
		a.Notice == b.Notice && a.Owner == b.Owner && a.Repo == b.Repo &&
		a.Untrusted == b.Untrusted && a.Reported == b.Reported
}

// dialUpstream bounds every dial, including a test dial, at 10s.
// Close of the returned connection releases the dial context. The context
// is not cancelled when the dial succeeds, so a dialer that follows ctx
// does not drop a live connection. The timer is stopped on success.
func (p *proxy) dialUpstream(host string, port int) (net.Conn, error) {
	dial := p.dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	ctx, cancel := context.WithCancel(p.ctx)
	stop := time.AfterFunc(10*time.Second, cancel)
	up, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		stop.Stop()
		cancel()
		return nil, err
	}
	if !stop.Stop() {
		_ = up.Close()
		cancel()
		return nil, context.DeadlineExceeded
	}
	return &cancelOnClose{Conn: up, cancel: cancel}, nil
}

type cancelOnClose struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.Conn.Close()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	return err
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
	if !allowed {
		p.add(ev)
		_, _ = conn.Write([]byte("DENY\n"))
		return
	}
	up, err := p.dialUpstream(host, port)
	if err != nil {
		ev.Notice = ""
		ev.Detail = "dial failed"
		p.add(ev)
		_, _ = conn.Write([]byte("DENY\n"))
		return
	}
	defer up.Close()
	p.add(ev)
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

// GitHubNetworkDenied is the splice-proxy detail for github.com and
// api.github.com. GitHubProxyDenied is the detail when the credential
// bridge cannot be built. Both are host-side and the daemon audits them.
// GitHubAllowlistDenied is the detail a jail wrapper writes for a remote
// outside the allowlist. That line is an untrusted jail report. The host
// GitHub proxy audits a request that actually reaches it.
const (
	GitHubNetworkDenied   = "github is not on the network grant"
	GitHubProxyDenied     = "github proxy unavailable"
	GitHubAllowlistDenied = "allowlist"
)

func (p *proxy) decide(host string, port int) (bool, Event) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// GitHub is never reached tokenless. A net grant cannot carry it, even
	// when the name is on net_allow. Clone and fetch use the credential proxy.
	if host == "github.com" || host == "api.github.com" {
		return false, Event{Kind: "grant_denied", Grant: "github", Host: host, Detail: GitHubNetworkDenied}
	}
	if port == 22 {
		if !p.grants["ssh"] {
			return false, Event{Kind: "grant_denied", Grant: "ssh", Host: host, Detail: "missing ssh grant"}
		}
		if !p.sshAllow[host] {
			return false, Event{Kind: "grant_denied", Grant: "ssh", Host: host, Detail: "not allowlisted"}
		}
		return true, Event{Kind: "grant_use", Grant: "ssh", Host: host, Notice: "SSH to " + host}
	}
	if !p.grants["net"] {
		return false, Event{Kind: "grant_denied", Grant: "net", Host: host, Detail: "missing net grant"}
	}
	if !p.netAllow[host] {
		return false, Event{Kind: "net_request", Grant: "net", Host: host, Detail: "not allowlisted"}
	}
	return true, Event{Kind: "grant_use", Grant: "net", Host: host}
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
