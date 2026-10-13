package clisession

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestPlaceBinaryRewritesLoginDir(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	ws := filepath.Join(root, "ws")
	binDir := filepath.Join(home, ".grok", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	argv0, mounts, err := placeBinary(bin, ws, home)
	if err != nil {
		t.Fatal(err)
	}
	if argv0 != "/lgb-home/.grok/bin/grok" {
		t.Fatalf("argv0 %s", argv0)
	}
	if len(mounts) != 0 {
		t.Fatalf("mounts %+v", mounts)
	}
}

func TestPlaceBinaryBindsForeignDir(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	opt := filepath.Join(root, "opt")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(opt, "grok")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	argv0, mounts, err := placeBinary(bin, ws, filepath.Join(root, "home"))
	if err != nil {
		t.Fatal(err)
	}
	if argv0 != bin {
		t.Fatalf("argv0 %s", argv0)
	}
	if len(mounts) != 1 || mounts[0].src != opt || !mounts[0].ro {
		t.Fatalf("mounts %+v", mounts)
	}
}

func TestConfinedCommandEnvIsMinimal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XAI_API_KEY", "supersecret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	cmd, cleanup, err := confinedCommand("/bin/true", []string{"-p", "x"}, dir)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.Join(cmd.Env, "\n")
	if strings.Contains(blob, "supersecret") || strings.Contains(blob, "SSH_AUTH_SOCK") || strings.Contains(blob, "XAI_API_KEY") {
		t.Fatal(cmd.Env)
	}
	if len(cmd.Env) == 0 || !strings.HasPrefix(cmd.Env[0], "PATH=") {
		t.Fatalf("env %v", cmd.Env)
	}
}

func TestEnvAllowlistIsAddedAndSecretsStayOut(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("REVIEW_NOTE", "visible-note")
	t.Setenv("XAI_API_KEY", "supersecret")
	t.Setenv("ANTHROPIC_API_KEY", "supersecret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	pol := policy.Default()
	pol.EnvAllowlist = []string{"REVIEW_NOTE"}
	extra, err := pol.ExtraEnv(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	args, err := confineArgsPlan(filepath.Join(dir, "missing"), nil, dir, confinePlan{ExtraEnv: extra})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--setenv\x00REVIEW_NOTE\x00visible-note") {
		t.Fatal("allowlisted variable was not set")
	}
	for _, bad := range []string{"supersecret", "SSH_AUTH_SOCK", "XAI_API_KEY", "ANTHROPIC_API_KEY"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("args contain %s", bad)
		}
	}
	pol.EnvAllowlist = []string{"XAI_API_KEY"}
	if _, err := pol.ExtraEnv(os.LookupEnv); err == nil {
		t.Fatal("secret env was accepted")
	}
}

func TestProxyAndNoneNetworkFlags(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "missing")
	none, err := confineArgsPlan(bin, nil, dir, confinePlan{UnshareNet: true})
	if err != nil {
		t.Fatal(err)
	}
	noneJoined := strings.Join(none, "\x00")
	if !strings.Contains(noneJoined, "--unshare-net") || strings.Contains(noneJoined, "LGB_PROXY_SOCK") || strings.Contains(noneJoined, "--disable-userns") {
		t.Fatalf("none args %v", none)
	}
	proxy, err := confineArgsPlan(bin, nil, dir, confinePlan{
		UnshareNet: true,
		PreloadSrc: "/tmp/preload.so",
		ProxyDir:   "/tmp/proxydir",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyJoined := strings.Join(proxy, "\x00")
	for _, want := range []string{"--unshare-net", "--bind\x00/tmp/proxydir\x00/lgb-proxy/run", "--ro-bind\x00/tmp/preload.so\x00" + cliPreloadJail, "LGB_PROXY_SOCK\x00" + cliProxySockJail, "LD_PRELOAD\x00" + cliPreloadJail} {
		if !strings.Contains(proxyJoined, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(proxyJoined, "--disable-userns") {
		t.Fatal("proxy mode disabled user namespaces")
	}
}

func TestProxyEnvStaysOutOfTheChild(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HTTP_PROXY", "http://user:s3cret@proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "http://user:s3cret@proxy.example:8443")
	t.Setenv("NO_PROXY", "localhost")
	t.Setenv("XAI_API_KEY", "supersecret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("REVIEW_NOTE", "visible-note")

	open := policy.Default()
	if open.UsesUpstream() {
		t.Fatal("open policy uses the corporate proxy")
	}
	openExtra, err := open.ExtraEnv(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	openArgs, err := confineArgsPlan(filepath.Join(dir, "missing"), nil, dir, confinePlan{ExtraEnv: openExtra})
	if err != nil {
		t.Fatal(err)
	}
	openJoined := strings.Join(openArgs, "\x00")
	if strings.Contains(openJoined, "--unshare-net") || strings.Contains(openJoined, "s3cret") || strings.Contains(openJoined, "HTTP_PROXY") {
		t.Fatal("open mode applied the proxy environment")
	}

	pol := policy.Default()
	pol.CLINetwork = policy.NetExplicit
	pol.HTTPProxy = "http://user:s3cret@proxy.example:8080"
	pol.HTTPSProxy = "http://user:s3cret@proxy.example:8443"
	pol.NoProxy = "localhost"
	pol.EnvAllowlist = []string{"REVIEW_NOTE"}
	if !pol.UsesUpstream() {
		t.Fatal("explicit-proxy did not use the corporate proxy")
	}
	extra, err := pol.ExtraEnv(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	args, err := confineArgsPlan(filepath.Join(dir, "missing"), nil, dir, confinePlan{
		UnshareNet: true,
		PreloadSrc: "/tmp/preload.so",
		ProxyDir:   "/tmp/proxydir",
		ExtraEnv:   extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--unshare-net") || !strings.Contains(joined, "--setenv\x00REVIEW_NOTE\x00visible-note") {
		t.Fatal("explicit-proxy jail was not built")
	}
	for _, bad := range []string{"s3cret", "supersecret", "HTTP_PROXY", "HTTPS_PROXY", "SSH_AUTH_SOCK", "XAI_API_KEY"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("child env contains %s", bad)
		}
	}

	bare := launch{Policy: policy.Policy{CLINetwork: policy.NetExplicit}}
	if _, _, err := bare.command(context.Background(), "/bin/true", nil, dir); err == nil || !strings.Contains(err.Error(), "explicit-proxy") {
		t.Fatalf("missing proxy URL: %v", err)
	}
}

func TestLaunchProxyProducesUnsharedNet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap flags")
	}
	dir := t.TempDir()
	pol := policy.Default()
	pol.CLINetwork = policy.NetProxy
	pol.CLINetAllow = []string{"allowed.test"}
	l := launch{Policy: pol, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, net.ErrClosed
	}}
	cmd, cleanup, err := l.command(context.Background(), "/bin/true", nil, dir)
	if err != nil {
		if strings.Contains(err.Error(), "unavailable") {
			t.Skip(err.Error())
		}
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	joined := strings.Join(cmd.Args, "\x00")
	if !strings.Contains(joined, "--unshare-net") || !strings.Contains(joined, cliProxySockJail) {
		t.Fatalf("args missing proxy jail: %s", strings.Join(cmd.Args, " "))
	}
}

func TestCLIWorkspaceReadonlyArgv(t *testing.T) {
	ws := t.TempDir()
	plain, err := confineArgsPlan("/bin/true", nil, ws, confinePlan{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plain, "\x00"), "--bind\x00"+ws+"\x00"+ws) {
		t.Fatal("default workspace is not writable")
	}
	args, err := confineArgsPlan("/bin/true", nil, ws, confinePlan{WorkspaceReadonly: true})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--ro-bind\x00"+ws+"\x00"+ws) || strings.Contains(joined, "--bind\x00"+ws+"\x00") {
		t.Fatalf("workspace mount:\n%s", strings.Join(args, " "))
	}
}

func TestCLIRlimitArgv(t *testing.T) {
	ws := t.TempDir()
	plain, err := confineArgsPlan("/bin/true", nil, ws, confinePlan{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(plain, "\x00"), "--rlimit") {
		t.Fatal("zero rlimits changed the argv")
	}
	args, err := confineArgsPlan("/bin/true", nil, ws, confinePlan{Rlimits: sandbox.Rlimits{Nofile: 1024, Nproc: 64, CPUSeconds: 15}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--rlimit\x00NOFILE\x001024\x001024",
		"--rlimit\x00NPROC\x0064\x0064",
		"--rlimit\x00CPU\x0015\x0015",
	} {
		at := strings.Index(joined, want)
		sep := strings.Index(joined, "\x00--\x00")
		if at < 0 || sep < 0 || at > sep {
			t.Fatalf("missing %q before command:\n%s", want, strings.Join(args, " "))
		}
	}
}

func TestCLIROBindArgv(t *testing.T) {
	ws := t.TempDir()
	shared := filepath.Join(t.TempDir(), "shared")
	plain, err := confineArgsPlan("/bin/true", nil, ws, confinePlan{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(plain, "\x00"), shared) {
		t.Fatal("empty plan added a bind")
	}
	args, err := confineArgsPlan("/bin/true", nil, ws, confinePlan{ROBinds: []policy.CLIROBind{{Src: shared, Dst: shared}}})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	want := "--ro-bind\x00" + shared + "\x00" + shared
	ro := strings.Index(joined, want)
	wsBind := strings.Index(joined, "--bind\x00"+ws+"\x00"+ws)
	if ro < 0 || wsBind < 0 || ro > wsBind {
		t.Fatalf("bind order:\n%s", strings.Join(args, " "))
	}
	if strings.Contains(joined, "--bind\x00"+shared+"\x00") {
		t.Fatal("cli ro bind is writable")
	}
	if _, err := confineArgsPlan("/bin/true", nil, ws, confinePlan{ROBinds: []policy.CLIROBind{{Src: "/usr", Dst: "/usr"}}}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatal(err)
	}
}

func TestCLIROBindIsReadOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip(err)
	}
	touch, err := exec.LookPath("touch")
	if err != nil {
		t.Skip(err)
	}
	ws := t.TempDir()
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(shared, "marker")
	if err := os.WriteFile(marker, []byte("shared-ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args, err := confineArgsPlan(cat, []string{marker}, ws, confinePlan{ROBinds: []policy.CLIROBind{{Src: shared, Dst: shared}}})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "shared-ok\n" {
		t.Fatalf("read %v %s", err, out)
	}
	created := filepath.Join(shared, "newfile")
	args, err = confineArgsPlan(touch, []string{created}, ws, confinePlan{ROBinds: []policy.CLIROBind{{Src: shared, Dst: shared}}})
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("write succeeded: %s", out)
	}
	if _, statErr := os.Stat(created); !os.IsNotExist(statErr) {
		t.Fatalf("read-only bind created %s (%v)", created, statErr)
	}
}

func TestCLIROBindIsLogged(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	ws := t.TempDir()
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	var got []sandbox.Event
	l := launch{
		Policy:  policy.Policy{CLINetwork: policy.NetOpen, CLIROBinds: []policy.CLIROBind{{Src: shared, Dst: shared}}},
		BindLog: func(ev sandbox.Event) { got = append(got, ev) },
	}
	cmd, cleanup, err := l.command(context.Background(), "/bin/true", nil, ws)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	joined := strings.Join(cmd.Args, "\x00")
	if !strings.Contains(joined, "--ro-bind\x00"+shared+"\x00"+shared) {
		t.Fatalf("args %s", strings.Join(cmd.Args, " "))
	}
	if len(got) != 1 || got[0].Kind != "grant_use" || got[0].Grant != "cli_ro_bind" || got[0].Detail != shared+" read-only" {
		t.Fatalf("%+v", got)
	}
}
