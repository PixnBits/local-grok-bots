package sandbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Upstream is the corporate proxy a CLI allowlist proxy dials through.
// Empty values mean a direct dial. Credentials stay in this value and are
// not copied into the CLI child.
type Upstream struct {
	HTTPProxy  string
	HTTPSProxy string
	NoProxy    string
}

// Enabled reports whether an upstream proxy URL is set.
func (u Upstream) Enabled() bool {
	return strings.TrimSpace(u.HTTPProxy) != "" || strings.TrimSpace(u.HTTPSProxy) != ""
}

// Label is the log text for one destination. It names the proxy host and
// port, never a username or password.
func (u Upstream) Label(host string, port int) string {
	if !u.Enabled() || bypass(u.NoProxy, host, port) {
		return "direct"
	}
	raw := u.pick(port)
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return "via upstream"
	}
	return "via " + net.JoinHostPort(parsed.Hostname(), proxyPort(parsed))
}

// Wrap returns a dial function that sends non-exempt destinations through
// the upstream proxy with HTTP CONNECT. A disabled upstream returns base.
func (u Upstream) Wrap(base func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if !u.Enabled() {
		return base
	}
	if base == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		base = d.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		if bypass(u.NoProxy, host, port) {
			return base(ctx, network, addr)
		}
		proxyRaw := u.pick(port)
		parsed, err := url.Parse(proxyRaw)
		if err != nil || parsed.Hostname() == "" {
			return nil, fmt.Errorf("upstream proxy URL is invalid")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("upstream proxy scheme is not supported")
		}
		tcp, err := base(ctx, network, net.JoinHostPort(parsed.Hostname(), proxyPort(parsed)))
		if err != nil {
			return nil, fmt.Errorf("upstream proxy dial failed")
		}
		out, err := connectVia(ctx, tcp, parsed, host, port)
		if err != nil {
			_ = tcp.Close()
			return nil, err
		}
		return out, nil
	}
}

func (u Upstream) pick(port int) string {
	httpProxy := strings.TrimSpace(u.HTTPProxy)
	httpsProxy := strings.TrimSpace(u.HTTPSProxy)
	if port == 443 && httpsProxy != "" {
		return httpsProxy
	}
	if port != 443 && httpProxy != "" {
		return httpProxy
	}
	if httpsProxy != "" {
		return httpsProxy
	}
	return httpProxy
}

func proxyPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func bypass(noProxy, host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, raw := range strings.Split(noProxy, ",") {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		if h, portStr, err := net.SplitHostPort(p); err == nil {
			if strconv.Itoa(port) != portStr {
				continue
			}
			p = h
		}
		if strings.HasPrefix(p, ".") {
			bare := strings.TrimPrefix(p, ".")
			if host == bare || strings.HasSuffix(host, p) {
				return true
			}
			continue
		}
		if p == host {
			return true
		}
	}
	return false
}

func connectVia(ctx context.Context, raw net.Conn, proxy *url.URL, host string, port int) (net.Conn, error) {
	conn := raw
	if proxy.Scheme == "https" {
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName: proxy.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("upstream proxy tls failed")
		}
		conn = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxy.User != nil {
		user := proxy.User.Username()
		pass, _ := proxy.User.Password()
		if strings.ContainsAny(user, "\r\n\x00") || strings.ContainsAny(pass, "\r\n\x00") {
			return nil, fmt.Errorf("upstream proxy credentials are not safe")
		}
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", token)
	}
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		return nil, fmt.Errorf("upstream proxy connect failed")
	}
	status, err := readProxyStatus(conn)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("upstream proxy rejected the connect")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func readProxyStatus(conn net.Conn) (int, error) {
	var buf []byte
	one := []byte{0}
	for len(buf) < 8192 {
		n, err := conn.Read(one)
		if n == 1 {
			buf = append(buf, one[0])
			if bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
				line := string(buf)
				if i := strings.Index(line, "\r\n"); i >= 0 {
					line = line[:i]
				}
				fields := strings.Fields(line)
				if len(fields) < 2 {
					return 0, fmt.Errorf("upstream proxy rejected the connect")
				}
				code, conv := strconv.Atoi(fields[1])
				if conv != nil {
					return 0, fmt.Errorf("upstream proxy rejected the connect")
				}
				return code, nil
			}
		}
		if err != nil {
			return 0, fmt.Errorf("upstream proxy connect failed")
		}
	}
	return 0, fmt.Errorf("upstream proxy header is too large")
}
