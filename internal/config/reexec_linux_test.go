//go:build linux

package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunningDaemonEnvironOmitsSecrets(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "lgb")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(root, "cmd", "local-grok-bots")
	build.Env = append(os.Environ(), "GOWORK=off")
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(policyPath, []byte("[backend]\nbackend = \"ollama\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	const (
		token      = "unit-auth-token-canary"
		canaryName = "LGB_CANARY_PROC"
		canaryVal  = "unit-canary-proc-value"
	)
	cmd := exec.Command(bin)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"LANG=C",
		"DATA_DIR=" + data,
		"BIND_ADDR=" + addr,
		"POLICY_PATH=" + policyPath,
		"AUTH_TOKEN=" + token,
		canaryName + "=" + canaryVal,
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
			_, _ = cmd.Process.Wait()
		}
	})
	ready := make(chan struct{})
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 512)
		for {
			n, err := stderr.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if bytes.Contains(buf, []byte("listening on")) {
					close(ready)
					io.Copy(io.Discard, stderr)
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not start")
	}
	pid := cmd.Process.Pid
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		t.Fatal(err)
	}
	env := string(raw)
	for _, name := range []string{"AUTH_TOKEN", canaryName, "XAI_API_KEY"} {
		if strings.Contains(env, name+"=") || bytes.Contains(raw, []byte(name+"=")) {
			t.Fatalf("environ still has %s", name)
		}
	}
	for _, val := range []string{token, canaryVal} {
		if strings.Contains(env, val) {
			t.Fatal("environ still has a secret value")
		}
	}
	health, err := http.Get("http://" + addr + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	health.Body.Close()
	if health.StatusCode != 200 {
		t.Fatalf("health %d", health.StatusCode)
	}
	unauth, err := http.Get("http://" + addr + "/api/bots")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != 401 {
		t.Fatalf("unauth %d", unauth.StatusCode)
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/api/bots", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	auth, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	auth.Body.Close()
	if auth.StatusCode != 200 {
		t.Fatalf("auth %d", auth.StatusCode)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
