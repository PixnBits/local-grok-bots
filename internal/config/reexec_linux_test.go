//go:build linux

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRunningDaemonEnvironOmitsSecrets(t *testing.T) {
	dir := t.TempDir()
	bin := buildDaemon(t)
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
		named      = "named-token-reexec-value-0000001"
		canaryName = "LGB_CANARY_PROC"
		canaryVal  = "unit-canary-proc-value"
	)
	if len(named) < 32 {
		t.Fatalf("named token length %d", len(named))
	}
	tokensPath := filepath.Join(dir, "tokens")
	if err := os.WriteFile(tokensPath, []byte("reexec:"+named+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokensPath, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"LANG=C",
		"DATA_DIR=" + data,
		"BIND_ADDR=" + addr,
		"POLICY_PATH=" + policyPath,
		"AUTH_TOKEN=" + token,
		"AUTH_TOKENS_FILE=" + tokensPath,
		canaryName + "=" + canaryVal,
		"DB_PASS=unit-pass",
		"GPG_TTY=/dev/pts/1",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
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
	marker := environValue(raw, readyKey)
	if marker == "" || marker == readyVal || !strings.Contains(marker, ".") {
		t.Fatalf("ready marker %q", marker)
	}
	for _, name := range []string{"AUTH_TOKEN", "AUTH_TOKENS_FILE", canaryName, "XAI_API_KEY", "DB_PASS"} {
		if strings.Contains(env, name+"=") || bytes.Contains(raw, []byte(name+"=")) {
			t.Fatalf("environ still has %s", name)
		}
	}
	for _, val := range []string{token, named, canaryVal, tokensPath} {
		if strings.Contains(env, val) {
			t.Fatal("environ still has a secret value")
		}
	}
	var health *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		health, err = http.Get("http://" + addr + "/api/health")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
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
	namedReq, err := http.NewRequest(http.MethodGet, "http://"+addr+"/api/bots", nil)
	if err != nil {
		t.Fatal(err)
	}
	namedReq.Header.Set("Authorization", "Bearer "+named)
	namedRes, err := http.DefaultClient.Do(namedReq)
	if err != nil {
		t.Fatal(err)
	}
	namedRes.Body.Close()
	if namedRes.StatusCode != 200 {
		t.Fatalf("named auth %d", namedRes.StatusCode)
	}
	envText := strings.ReplaceAll(env, "\x00", "\n")
	if !strings.Contains(envText, "GPG_TTY=/dev/pts/1") || !strings.Contains(envText, "SSH_AUTH_SOCK=/tmp/agent.sock") {
		t.Fatal("non-secret names were dropped")
	}
}

func TestPresetReadyMarkerExits(t *testing.T) {
	bin := buildDaemon(t)
	cmd := exec.Command(bin)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"LGB_ENV_READY=1",
		"AUTH_TOKEN=preset-should-not-start",
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("preset marker started: %s", out)
	}
	if strings.Contains(string(out), "preset-should-not-start") {
		t.Fatal("preset token was printed")
	}
}

func TestReadReadyAuthChecksPipeAndNonce(t *testing.T) {
	const nonce = "0123456789abcdef0123456789abcdef"
	tok := "unit-token"
	tokensFile := "/tmp/lgb-tokens"
	r, w := mustPipe(t)
	if err := json.NewEncoder(w).Encode(secretPayload{AuthToken: &tok, TokensFile: &tokensFile, Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	fd := int(r.Fd())
	got, file, err := readReadyAuth(nonce + "." + strconv.Itoa(fd))
	if err != nil || got != tok || file != tokensFile {
		t.Fatalf("read %q %q %v", got, file, err)
	}
	_ = r.Close()

	r, w = mustPipe(t)
	defer r.Close()
	if err := json.NewEncoder(w).Encode(secretPayload{AuthToken: &tok, Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if _, _, err := readReadyAuth("fedcba9876543210fedcba9876543210." + strconv.Itoa(int(r.Fd()))); err == nil {
		t.Fatal("nonce mismatch was accepted")
	}

	r, w = mustPipe(t)
	defer r.Close()
	if _, err := w.Write([]byte(`{"n":"` + nonce + `"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if _, _, err := readReadyAuth(nonce + "." + strconv.Itoa(int(r.Fd()))); err == nil {
		t.Fatal("missing token was accepted")
	}

	empty := ""
	r, w = mustPipe(t)
	defer r.Close()
	if err := json.NewEncoder(w).Encode(secretPayload{AuthToken: &empty, Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got, file, err = readReadyAuth(nonce + "." + strconv.Itoa(int(r.Fd())))
	if err != nil || got != "" || file != "" {
		t.Fatalf("empty token %q %q %v", got, file, err)
	}

	f, err := os.CreateTemp(t.TempDir(), "reg")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := readReadyAuth(nonce + "." + strconv.Itoa(int(f.Fd()))); err == nil {
		t.Fatal("regular file was accepted")
	}
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uf, ok := c.(*net.UnixConn)
	if !ok {
		t.Fatal("unix conn")
	}
	raw, err := uf.File()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, _, err := readReadyAuth(nonce + "." + strconv.Itoa(int(raw.Fd()))); err == nil {
		t.Fatal("socket was accepted")
	}

	mem, err := unix.MemfdCreate("lgb", 0)
	if err != nil {
		t.Fatal(err)
	}
	mf := os.NewFile(uintptr(mem), "mem")
	defer mf.Close()
	if err := json.NewEncoder(mf).Encode(secretPayload{AuthToken: &tok, Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	if _, err := mf.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	got, file, err = readReadyAuth(nonce + "." + strconv.Itoa(mem))
	if err != nil || got != tok || file != "" {
		t.Fatalf("memfd %q %q %v", got, file, err)
	}

	if _, _, err := readReadyAuth("1"); err == nil {
		t.Fatal("preset marker was accepted")
	}
	if _, _, err := readReadyAuth(nonce + ".1"); err == nil {
		t.Fatal("stdio fd was accepted")
	}
}

func TestReadyAuthHoldsTLSKey(t *testing.T) {
	prev := heldTLSKey
	t.Cleanup(func() { heldTLSKey = prev })
	heldTLSKey = ""
	const nonce = "0123456789abcdef0123456789abcdef"
	const key = "/var/lib/lgb/from-pipe.key"
	tok := "unit-token"
	r, w := mustPipe(t)
	defer r.Close()
	tlsKey := key
	if err := json.NewEncoder(w).Encode(secretPayload{AuthToken: &tok, TLSKey: &tlsKey, Nonce: nonce}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if _, _, err := readReadyAuth(nonce + "." + strconv.Itoa(int(r.Fd()))); err != nil {
		t.Fatal(err)
	}
	if heldTLSKey != key || CurrentTLSKey() != key {
		t.Fatalf("held %q", heldTLSKey)
	}
	t.Setenv("TLS_KEY", "")
	if FromEnv().TLSKey != key {
		t.Fatalf("config %q", FromEnv().TLSKey)
	}
}

func mustPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	return r, w
}

func environValue(raw []byte, key string) string {
	prefix := key + "="
	for _, ent := range bytes.Split(raw, []byte{0}) {
		if bytes.HasPrefix(ent, []byte(prefix)) {
			return string(ent[len(prefix):])
		}
	}
	return ""
}

func buildDaemon(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "lgb")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(root, "cmd", "local-grok-bots")
	build.Env = append(os.Environ(), "GOWORK=off")
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
