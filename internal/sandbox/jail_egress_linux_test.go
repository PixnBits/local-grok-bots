//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func skipIfMissing(t *testing.T, bins ...string) {
	t.Helper()
	for _, name := range bins {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " unavailable")
		}
	}
}

func buildStaticClient(t *testing.T) string {
	t.Helper()
	skipIfMissing(t, "go")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module jailclient\n\ngo 1.24.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `package main
import (
  "fmt"
  "net/http"
  "os"
  "time"
)
func main() {
  fmt.Println("PROXY", os.Getenv("HTTP_PROXY"))
  c := &http.Client{Timeout: 8 * time.Second}
  resp, err := c.Get(os.Args[1])
  if err != nil {
    fmt.Println("ERR", err.Error())
    os.Exit(1)
  }
  defer resp.Body.Close()
  fmt.Printf("STATUS %s %d\n", os.Args[1], resp.StatusCode)
  if resp.StatusCode != 200 {
    os.Exit(1)
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "client")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build static client: %v\n%s", err, out)
	}
	ldd, err := exec.Command("ldd", bin).CombinedOutput()
	text := string(ldd)
	if err == nil && !strings.Contains(text, "not a dynamic executable") && !strings.Contains(text, "statically linked") {
		t.Fatalf("client must be statically linked:\n%s", text)
	}
	return bin
}

func copyClient(t *testing.T, ws, bin string) {
	t.Helper()
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "client"), b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func httpUpstream(t *testing.T) (net.Listener, func(context.Context, string, string) (net.Conn, error), func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	var mu sync.Mutex
	var got []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		got = append(got, addr)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
	return ln, dial, snapshot
}

func TestJailNetProxyEnvStaticGo(t *testing.T) {
	skipIfMissing(t, "bwrap", "go", "gcc")
	bin := buildStaticClient(t)
	ws := t.TempDir()
	copyClient(t, ws, bin)
	_, dial, got := httpUpstream(t)
	res, err := runCmd(t, Request{
		Workspace: ws,
		Command:   "/work/client http://allowed.test/a; /work/client http://nope.test/a; /work/client http://github.com/; true",
		Grants:    []string{"net"},
		NetAllow:  []string{"allowed.test"},
		Dial:      dial,
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
	})
	if err != nil && !strings.Contains(res.Stdout, "STATUS") {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(res.Stdout, "PROXY "+shellProxyURL()) {
		t.Fatalf("proxy env missing:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "STATUS http://allowed.test/a 200") {
		t.Fatalf("allowlisted request failed:\n%s\n%s", res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "STATUS http://nope.test/a 403") {
		t.Fatalf("non-allowlisted request was not denied:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "STATUS http://github.com/ 403") {
		t.Fatalf("github.com was not refused:\n%s", res.Stdout)
	}
	if ev, ok := findEvent(res.Events, "grant_use", "net", "allowed.test"); !ok || ev.Detail != "" {
		t.Fatalf("grant_use: %+v", res.Events)
	}
	if ev, ok := findEvent(res.Events, "net_request", "net", "nope.test"); !ok || ev.Detail != "not allowlisted" {
		t.Fatalf("net_request: %+v", res.Events)
	}
	if ev, ok := findEvent(res.Events, "grant_denied", "github", "github.com"); !ok || ev.Detail != GitHubNetworkDenied {
		t.Fatalf("github denial: %+v", res.Events)
	}
	if dialed := got(); len(dialed) != 1 || dialed[0] != "203.0.113.10:80" {
		t.Fatalf("dialed %#v", dialed)
	}
}

func TestJailNetOffNoProxyEnv(t *testing.T) {
	skipIfMissing(t, "bwrap", "python3")
	script := `python3 - <<'PY'
import os, socket
keys = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy"]
for k in keys:
    print("ENV", k, os.environ.get(k, "<absent>"))
s = socket.socket()
s.settimeout(0.3)
try:
    s.connect(("127.0.0.1", ` + strconv.Itoa(jailHTTPProxyPort) + `))
    print("LISTEN")
except OSError:
    print("CLOSED")
PY`
	res := mustRun(t, Request{Workspace: t.TempDir(), Command: script})
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy"} {
		if !strings.Contains(res.Stdout, "ENV "+k+" <absent>") {
			t.Fatalf("env leaked:\n%s", res.Stdout)
		}
	}
	if strings.Contains(res.Stdout, "LISTEN") || !strings.Contains(res.Stdout, "CLOSED") {
		t.Fatalf("proxy port:\n%s", res.Stdout)
	}
}

func TestJailEgressProxyAllowlist(t *testing.T) {
	skipIfMissing(t, "bwrap", "go", "gcc")
	bin := buildStaticClient(t)
	ws := t.TempDir()
	copyClient(t, ws, bin)
	_, dial, got := httpUpstream(t)
	res, err := runCmd(t, Request{
		Workspace: ws,
		Command:   "/work/client http://allowed.test/a; /work/client http://github.com/; true",
		Grants:    []string{"net"},
		NetAllow:  []string{"allowed.test", "github.com"},
		Dial:      dial,
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
	})
	if err != nil && !strings.Contains(res.Stdout, "STATUS") {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(res.Stdout, "STATUS http://allowed.test/a 200") {
		t.Fatalf("allowlisted host failed:\n%s\n%s", res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "STATUS http://github.com/ 403") {
		t.Fatalf("github.com on net_allow was proxied:\n%s", res.Stdout)
	}
	if ev, ok := findEvent(res.Events, "grant_denied", "github", "github.com"); !ok || ev.Detail != GitHubNetworkDenied {
		t.Fatalf("missing decide() denial: %+v", res.Events)
	}
	if dialed := got(); len(dialed) != 1 || dialed[0] != "203.0.113.10:80" {
		t.Fatalf("dialed %#v, decide() was skipped if github.com was dialed", dialed)
	}
}

func TestJailCurlMaxTimeHonored(t *testing.T) {
	skipIfMissing(t, "bwrap", "curl", "python3", "gcc")
	t.Run("denied", func(t *testing.T) {
		var n int
		var mu sync.Mutex
		assertCurlMaxTime(t, "https://denied.test/", func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			n++
			mu.Unlock()
			return nil, fmt.Errorf("dialed %s", addr)
		})
		mu.Lock()
		got := n
		mu.Unlock()
		if got != 0 {
			t.Fatalf("denied host was dialed %d times", got)
		}
	})
	t.Run("dial-stalls", func(t *testing.T) {
		assertCurlMaxTime(t, "https://allowed.test/", func(ctx context.Context, network, addr string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
	})
	t.Run("accepted-silent", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		hold, stop := context.WithCancel(context.Background())
		t.Cleanup(stop)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					<-hold.Done()
				}(c)
			}
		}()
		assertCurlMaxTime(t, "https://allowed.test/", func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		})
	})
}

func assertCurlMaxTime(t *testing.T, rawURL string, dial func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	script := fmt.Sprintf(`python3 - <<'PY'
import subprocess, time
url = %q
t0 = time.monotonic()
p = subprocess.run(["curl", "--max-time", "3", "--noproxy", "*", "-sS", "-o", "/dev/null", url])
print("elapsed %%.3f" %% (time.monotonic() - t0))
print("code", p.returncode)
PY`, rawURL)
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command:   script,
		Grants:    []string{"net"},
		NetAllow:  []string{"allowed.test"},
		Dial:      dial,
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
	})
	if err != nil && !strings.Contains(res.Stdout, "elapsed") {
		t.Fatalf("run: %v\n%s", err, res.Stderr)
	}
	elapsed, code := parseCurlTiming(t, res.Stdout)
	if code == 0 {
		t.Fatalf("curl succeeded\n%s\n%s", res.Stdout, res.Stderr)
	}
	if elapsed >= 6 {
		t.Fatalf("curl ignored --max-time: elapsed %.3f\n%s\n%s", elapsed, res.Stdout, res.Stderr)
	}
}

func parseCurlTiming(t *testing.T, stdout string) (float64, int) {
	t.Helper()
	var elapsed float64
	var code int
	var sawE, sawC bool
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, "elapsed ") {
			v, err := strconv.ParseFloat(strings.TrimPrefix(line, "elapsed "), 64)
			if err != nil {
				t.Fatalf("elapsed %q: %v", line, err)
			}
			elapsed = v
			sawE = true
		}
		if strings.HasPrefix(line, "code ") {
			v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "code ")))
			if err != nil {
				t.Fatalf("code %q: %v", line, err)
			}
			code = v
			sawC = true
		}
	}
	if !sawE || !sawC {
		t.Fatalf("timing missing:\n%s", stdout)
	}
	return elapsed, code
}

func TestPreloadKeepsNonblock(t *testing.T) {
	skipIfMissing(t, "bwrap", "python3", "gcc")
	_, dial, _ := httpUpstream(t)
	script := `python3 - <<'PY'
import errno, fcntl, os, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setblocking(False)
fd = s.fileno()
fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.fcntl(fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
err = 0
try:
    s.connect(("allowed.test", 80))
except OSError as e:
    err = e.errno
fl = fcntl.fcntl(fd, fcntl.F_GETFL)
fdfl = fcntl.fcntl(fd, fcntl.F_GETFD)
print("errno", err)
print("nonblock", 1 if (fl & os.O_NONBLOCK) else 0)
print("cloexec", 1 if (fdfl & fcntl.FD_CLOEXEC) else 0)
print("einprogress", errno.EINPROGRESS)
PY`
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command:   script,
		Grants:    []string{"net"},
		NetAllow:  []string{"allowed.test"},
		Dial:      dial,
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
	})
	if err != nil && !strings.Contains(res.Stdout, "nonblock") {
		t.Fatalf("run: %v\n%s", err, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "nonblock 1") || !strings.Contains(res.Stdout, "cloexec 1") {
		t.Fatalf("flags lost:\n%s\n%s", res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "errno 0\n") && !strings.Contains(res.Stdout, "errno 115\n") {
		// EINPROGRESS is the async path. 0 means the handshake finished
		// before connect returned. Either keeps the caller's flags.
		ein := ""
		for _, line := range strings.Split(res.Stdout, "\n") {
			if strings.HasPrefix(line, "einprogress ") {
				ein = strings.TrimPrefix(line, "einprogress ")
			}
		}
		if !strings.Contains(res.Stdout, "errno "+ein+"\n") {
			t.Fatalf("unexpected connect errno:\n%s", res.Stdout)
		}
	}
}
