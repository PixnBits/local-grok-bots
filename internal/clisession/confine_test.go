package clisession

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
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
