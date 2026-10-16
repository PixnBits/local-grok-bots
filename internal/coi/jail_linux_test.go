//go:build linux

package coi

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLinuxBwrapArgsBindBinaryNotHome(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	home := filepath.Join(root, "home")
	bin := filepath.Join(root, "bin", "tool")
	cred := filepath.Join(root, "cred")
	for _, d := range []string{ws, home, filepath.Dir(bin), cred} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	spool, dev, ino := makeSpool(t, ws)
	args, err := linuxBwrapArgs(jailSpec{
		Bin: bin, Args: []string{"--version"}, Workspace: ws, Home: home,
		Env:      []string{"HOME=" + home, "PATH=/usr/bin:/bin", "GROK_HOME=" + filepath.Join(home, ".grok")},
		Spool:    spool,
		SpoolDev: dev, SpoolIno: ino,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, bin) || !strings.Contains(joined, ws) {
		t.Fatalf("missing binds:\n%s", joined)
	}
	if strings.Contains(joined, cred) {
		t.Fatalf("credential home bound:\n%s", joined)
	}
	if strings.Contains(joined, "--disable-userns") {
		t.Fatal("user namespaces disabled")
	}
	for _, flag := range []string{"--unshare-net", "--unshare-ipc", "--new-session"} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("missing %s:\n%s", flag, joined)
		}
	}
	if strings.Contains(joined, "resolv.conf") {
		t.Fatalf("resolv bind:\n%s", joined)
	}
	assertNoSockMounts(t, args, "")
	if !hasArgPair(args, "--tmpfs", spool) {
		t.Fatalf("spool not covered:\n%s", joined)
	}
	if strings.Contains(joined, ".lgb") {
		t.Fatalf("args name a fixed spool directory:\n%s", joined)
	}
	wantHome := false
	for i, a := range args {
		if a == "--setenv" && i+1 < len(args) && args[i+1] == "HOME" {
			if i+2 >= len(args) || args[i+2] != jailHomeInside {
				t.Fatalf("HOME %v", args[i+2])
			}
			wantHome = true
		}
	}
	if !wantHome {
		t.Fatal("HOME not remapped")
	}
}

func TestLinuxBwrapArgsProxySocketOnly(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	home := filepath.Join(root, "home")
	bin := filepath.Join(root, "bin", "tool")
	fwd := filepath.Join(root, "bin", "lgb")
	sock := filepath.Join(root, "proxy", "id", "sock")
	for _, d := range []string{ws, home, filepath.Dir(bin), filepath.Dir(sock)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{bin, fwd, sock} {
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	args, err := linuxBwrapArgs(jailSpec{
		Bin: bin, Args: []string{"--version"}, Workspace: ws, Home: home,
		Forwarder: fwd, ProxySock: sock,
		BaseEnvs: []string{"GROK_CLI_CHAT_PROXY_BASE_URL"}, BasePrefix: "/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSockMounts(t, args, jailProxySock)
	if !hasBind(args, sock, jailProxySock) {
		t.Fatalf("proxy bind missing:\n%s", strings.Join(args, "\n"))
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--coi-forward") || !strings.Contains(joined, "--sock") || !strings.Contains(joined, jailProxySock) {
		t.Fatalf("forwarder args:\n%s", joined)
	}
	if strings.Contains(joined, "/run") || strings.Contains(joined, "resolv.conf") {
		t.Fatalf("host run leaked into args:\n%s", joined)
	}
}

func TestLinuxJailHidesHostRunAndNet(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal(ln.Addr())
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("open"))
			_ = c.Close()
		}
	}()
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil || os.MkdirAll(filepath.Join(ws, ".lgb"), 0o755) != nil {
		t.Fatal(err)
	}
	spool, dev, ino := makeSpool(t, ws)
	if err := os.WriteFile(filepath.Join(spool, "tok"), []byte("host-spool-marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".lgb", "decoy"), []byte("decoy-marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "probe")
	body := "#!/bin/sh\n" +
		"if [ -d /run ] || [ -d /var/run ] || [ -e /run/docker.sock ]; then echo RUN; else echo NO_RUN; fi\n" +
		"if [ -f run-spool/tok ]; then echo SPOOL; else echo NO_SPOOL; fi\n" +
		"if [ -f .lgb/decoy ]; then echo DECOY; else echo NO_DECOY; fi\n" +
		"if timeout 1 bash -c 'echo >/dev/tcp/127.0.0.1/" + strconv.Itoa(tcp.Port) + "'; then echo LOOP; else echo NO_LOOP; fi\n" +
		"if timeout 1 bash -c 'echo >/dev/tcp/192.0.2.1/80'; then echo LAN; else echo NO_LAN; fi\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	args, err := linuxBwrapArgs(jailSpec{
		Bin: script, Workspace: ws, Home: home,
		Env:   []string{"PATH=/usr/bin:/bin"},
		Spool: spool, SpoolDev: dev, SpoolIno: ino,
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bwrap, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bwrap: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{"NO_RUN", "NO_SPOOL", "DECOY", "NO_LOOP", "NO_LAN"} {
		if !strings.Contains(text, want) {
			t.Fatalf("probe missing %s:\n%s", want, text)
		}
	}
	for _, bad := range []string{"\nRUN\n", "\nSPOOL\n", "\nLOOP\n", "\nLAN\n", "open", "host-spool-marker"} {
		if strings.Contains(text, bad) {
			t.Fatalf("probe leaked %q:\n%s", bad, text)
		}
	}
	if b, err := os.ReadFile(filepath.Join(spool, "tok")); err != nil || string(b) != "host-spool-marker\n" {
		t.Fatal("host spool file changed")
	}
}

func makeSpool(t *testing.T, ws string) (string, uint64, uint64) {
	t.Helper()
	spool := filepath.Join(ws, "run-spool")
	if err := os.MkdirAll(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	dev, ino, err := DirIdentity(spool)
	if err != nil {
		t.Fatal(err)
	}
	return spool, dev, ino
}

func hasBind(args []string, src, dst string) bool {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--bind" && args[i+1] == src && args[i+2] == dst {
			return true
		}
	}
	return false
}

func hasArgPair(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

func assertNoSockMounts(t *testing.T, args []string, allowSock string) {
	t.Helper()
	mounts := map[string]bool{
		"--bind": true, "--ro-bind": true, "--ro-bind-try": true, "--dev-bind": true, "--tmpfs": true,
	}
	for i := 0; i < len(args); i++ {
		if !mounts[args[i]] {
			if strings.HasSuffix(args[i], ".sock") && args[i] != allowSock {
				t.Fatalf("sock path %s", args[i])
			}
			continue
		}
		if args[i] == "--tmpfs" {
			if i+1 < len(args) && forbiddenMount(args[i+1], allowSock) {
				t.Fatalf("forbidden mount %s", args[i+1])
			}
			continue
		}
		if i+2 >= len(args) {
			continue
		}
		for _, p := range []string{args[i+1], args[i+2]} {
			if forbiddenMount(p, allowSock) {
				t.Fatalf("forbidden mount %s\n%s", p, strings.Join(args, "\n"))
			}
		}
	}
}

func forbiddenMount(p, allowSock string) bool {
	if p == allowSock {
		return false
	}
	clean := filepath.Clean(p)
	if clean == "/run" || clean == "/var/run" || strings.HasPrefix(clean, "/run/") || strings.HasPrefix(clean, "/var/run/") {
		return true
	}
	return strings.HasSuffix(clean, ".sock")
}
