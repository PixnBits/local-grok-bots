//go:build linux

package clisession

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestGrokJailHidesHostNetwork(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip(err)
	}
	absName := "lgb" + strconv.FormatInt(time.Now().UnixNano(), 36)
	absLn, err := net.Listen("unix", "@"+absName)
	if err != nil {
		t.Fatal(err)
	}
	defer absLn.Close()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("open"))
			_ = c.Close()
		}
	}()
	port := tcpLn.Addr().(*net.TCPAddr).Port
	ws := t.TempDir()
	home := t.TempDir()
	out := filepath.Join(ws, "probe.out")
	probe := filepath.Join(ws, "probe.sh")
	body := "#!/bin/sh\n" +
		"python3 - <<'PY' > \"$HOST_PROBE_OUT\"\n" +
		"import os, socket\n" +
		"name = os.environ['HOST_ABS_NAME']\n" +
		"s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n" +
		"s.settimeout(1)\n" +
		"try:\n" +
		"    s.connect('\\0' + name)\n" +
		"    print('ABSTRACT=reachable')\n" +
		"except Exception:\n" +
		"    print('ABSTRACT=unreachable')\n" +
		"PY\n" +
		"if timeout 1 bash -c 'echo >/dev/tcp/127.0.0.1/" + strconv.Itoa(port) + "'; then echo LOOP=reachable; else echo LOOP=unreachable; fi >> \"$HOST_PROBE_OUT\"\n" +
		"if timeout 1 bash -c 'echo >/dev/tcp/203.0.113.1/9'; then echo LAN=reachable; else echo LAN=unreachable; fi >> \"$HOST_PROBE_OUT\"\n" +
		"if [ -n \"$HTTP_PROXY$HTTPS_PROXY$http_proxy$https_proxy\" ]; then echo EGRESS=set; else echo EGRESS=unset; fi >> \"$HOST_PROBE_OUT\"\n" +
		acpShellTail()
	if err := os.WriteFile(probe, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var pgidOK bool
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: probe, Prompt: "hi", Workspace: ws,
		PermissionMode: "always-allow",
		ACP:            quietACP(),
		OnStart: func(pid int) {
			pgid, gerr := syscall.Getpgid(pid)
			pgidOK = gerr == nil && pgid == pid
		},
		Isolate: &Isolation{
			Home:        home,
			GrokSandbox: GrokProfile,
			Env: []string{
				"PATH=/usr/bin:/bin",
				"HOME=" + home,
				"HOST_PROBE_OUT=" + out,
				"HOST_ABS_NAME=" + absName,
				"HTTP_PROXY=http://127.0.0.1:9",
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("run: %v res %+v", err, res)
	}
	if !pgidOK {
		t.Fatal("bwrap was not the process group leader")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"ABSTRACT=unreachable", "LOOP=unreachable", "LAN=unreachable", "EGRESS=unset"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s:\n%s", want, text)
		}
	}
	for _, bad := range []string{"ABSTRACT=reachable", "LOOP=reachable", "LAN=reachable", "EGRESS=set"} {
		if strings.Contains(text, bad) {
			t.Fatalf("leaked %s:\n%s", bad, text)
		}
	}
}

func TestGrokJailNetGrantAllowlistsEgress(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip(err)
	}
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 512)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			_ = c.Close()
		}
	}()
	proxy, err := sandbox.StartHTTPAllowProxy(t.TempDir(), sandbox.EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.10")}, nil
		},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			if addr != "192.0.2.10:80" {
				return nil, fmt.Errorf("denied")
			}
			return net.Dial("tcp", up.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	fwd := forwarderBin(t)
	ws := t.TempDir()
	home := t.TempDir()
	out := filepath.Join(ws, "probe.out")
	probe := filepath.Join(ws, "probe.sh")
	body := "#!/bin/sh\n" +
		"python3 - <<'PY' > \"$HOST_PROBE_OUT\"\n" +
		"import os, urllib.request\n" +
		"print('PROXY=' + ('set' if os.environ.get('HTTP_PROXY') and os.environ.get('HTTPS_PROXY') else 'unset'))\n" +
		"print('NO_PROXY=' + os.environ.get('NO_PROXY', ''))\n" +
		"def hit(url):\n" +
		"    try:\n" +
		"        r = urllib.request.urlopen(url, timeout=2)\n" +
		"        print(url.split('/')[2].split(':')[0] + '=' + str(r.status))\n" +
		"    except Exception as e:\n" +
		"        code = getattr(e, 'code', None)\n" +
		"        print(url.split('/')[2].split(':')[0] + '=' + (str(code) if code else 'fail'))\n" +
		"hit('http://allowed.test/ok')\n" +
		"hit('http://other.test/no')\n" +
		"os.environ.pop('NO_PROXY', None)\n" +
		"os.environ.pop('no_proxy', None)\n" +
		"hit('http://127.0.0.1:9/no')\n" +
		"PY\n" +
		acpShellTail()
	if err := os.WriteFile(probe, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: probe, Prompt: "hi", Workspace: ws,
		PermissionMode: "always-allow",
		ACP:            quietACP(),
		Isolate: &Isolation{
			Home:        home,
			GrokSandbox: GrokProfile,
			Env: []string{
				"PATH=/usr/bin:/bin",
				"HOME=" + home,
				"HOST_PROBE_OUT=" + out,
			},
			ForwardBin:  fwd,
			ForwardArgs: []string{"--coi-forward", "--http-sock", JailEgressSock},
			ExtraBinds:  [][2]string{{proxy.Sock(), JailEgressSock}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("run: %v res %+v", err, res)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"PROXY=set", "NO_PROXY=127.0.0.1,localhost,::1", "allowed.test=204", "other.test=403", "127.0.0.1=403"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s:\n%s", want, text)
		}
	}
}

func TestGrokJailReachesCredentialProxy(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip(err)
	}
	const gate = "unit-jail-gate-value1"
	proxyDir := t.TempDir()
	sockPath := filepath.Join(proxyDir, "sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}(c)
		}
	}()
	fwd := forwarderBin(t)
	ws := t.TempDir()
	home := t.TempDir()
	out := filepath.Join(ws, "probe.out")
	probe := filepath.Join(ws, "probe.sh")
	body := "#!/bin/sh\n" +
		"python3 - <<'PY' > \"$HOST_PROBE_OUT\"\n" +
		"import os, urllib.request\n" +
		"url = os.environ['GROK_CLI_CHAT_PROXY_BASE_URL'] + '/ping'\n" +
		"req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + os.environ['XAI_API_KEY']})\n" +
		"try:\n" +
		"    r = urllib.request.urlopen(req, timeout=2)\n" +
		"    print('CRED=' + str(r.status))\n" +
		"except Exception as e:\n" +
		"    print('CRED=fail')\n" +
		"print('KEY_KEPT=' + ('yes' if os.environ.get('XAI_API_KEY') == os.environ.get('HOST_GATE') else 'no'))\n" +
		"PY\n" +
		acpShellTail()
	if err := os.WriteFile(probe, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: probe, Prompt: "hi", Workspace: ws,
		PermissionMode: "always-allow",
		ACP:            quietACP(),
		Isolate: &Isolation{
			Home:        home,
			GrokSandbox: GrokProfile,
			Env: []string{
				"PATH=/usr/bin:/bin",
				"HOME=" + home,
				"HOST_PROBE_OUT=" + out,
				"HOST_GATE=" + gate,
				"XAI_API_KEY=" + gate,
				"GROK_CLI_CHAT_PROXY_BASE_URL=http://127.0.0.1:9/v1",
			},
			ForwardBin: fwd,
			ForwardArgs: []string{
				"--coi-forward", "--sock", JailProxySock, "--keep-key",
				"--env", "GROK_CLI_CHAT_PROXY_BASE_URL",
				"--prefix", "/bots/b1/runs/run-1/v1",
			},
			ExtraBinds: [][2]string{{sockPath, JailProxySock}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("run: %v res %+v", err, res)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.Contains(text, "CRED=204") || !strings.Contains(text, "KEY_KEPT=yes") {
		t.Fatalf("probe:\n%s", text)
	}
}

var (
	fwdOnce sync.Once
	fwdBin  string
	fwdErr  error
)

func forwarderBin(t *testing.T) string {
	t.Helper()
	fwdOnce.Do(func() {
		mod, err := exec.Command("go", "env", "GOMOD").Output()
		if err != nil {
			fwdErr = err
			return
		}
		root := filepath.Dir(strings.TrimSpace(string(mod)))
		dir, err := os.MkdirTemp("", "lgb-fwd-")
		if err != nil {
			fwdErr = err
			return
		}
		fwdBin = filepath.Join(dir, "lgb")
		cmd := exec.Command("go", "build", "-o", fwdBin, "./cmd/local-grok-bots")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			fwdErr = fmt.Errorf("%v\n%s", err, out)
		}
	})
	if fwdErr != nil {
		t.Fatal(fwdErr)
	}
	return fwdBin
}
