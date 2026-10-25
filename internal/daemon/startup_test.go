package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
)

type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureStartup(t *testing.T) *safeBuf {
	t.Helper()
	buf := &safeBuf{}
	prev := logOut
	logOut = buf
	t.Cleanup(func() { logOut = prev })
	return buf
}

func TestLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"0.0.0.0:8080", false},
		{":8080", false},
		{"[::]:8080", false},
		{"192.168.1.5:8080", false},
	}
	for _, tc := range cases {
		if got := loopbackBind(tc.addr); got != tc.ok {
			t.Errorf("%s loopback %v", tc.addr, got)
		}
	}
}

func TestRunLogsPolicyBind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte("[daemon]\nbind = \"127.0.0.1:0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const envBind = "192.0.2.1:9"
	t.Setenv("BIND_ADDR", envBind)
	t.Setenv("MANAGED_POLICY", "")
	buf := captureStartup(t)
	cfg := config.Config{
		DataDir:    filepath.Join(dir, "data"),
		BindAddr:   envBind,
		OllamaURL:  "http://127.0.0.1:9",
		Model:      "test-model",
		Version:    "0.1.0",
		PolicyPath: path,
	}
	app, err := New(cfg, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.cfg.BindAddr != "127.0.0.1:0" {
		t.Fatalf("bind %s", app.cfg.BindAddr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var runErr error
	go func() {
		runErr = app.Run(ctx)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
		}
	})

	var logged string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out := buf.String()
		if addr, ok := loggedAddr(out); ok {
			logged = addr
			if strings.Count(out, "listening on ") != 1 {
				t.Fatalf("startup log:\n%s", out)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if logged == "" {
		t.Fatalf("startup log:\n%s", buf.String())
	}
	if logged == envBind || logged == "127.0.0.1:0" || !strings.HasPrefix(logged, "127.0.0.1:") {
		t.Fatalf("logged %s", logged)
	}
	conn, err := net.Dial("tcp", logged)
	if err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr().String() != logged {
		conn.Close()
		t.Fatalf("listener %s logged %s", conn.RemoteAddr(), logged)
	}
	conn.Close()
	client := &http.Client{Timeout: time.Second}
	var res *http.Response
	deadline = time.Now().Add(3 * time.Second)
	for {
		res, err = client.Get("http://" + logged + "/api/health")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("health %d %s", res.StatusCode, body)
	}
	var health struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatal(err)
	}
	if health.Version != "0.1.0" {
		t.Fatalf("health %+v", health)
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown")
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
}

func loggedAddr(out string) (string, bool) {
	const prefix = "local-grok-bots 0.1.0 listening on "
	i := strings.Index(out, prefix)
	if i < 0 {
		return "", false
	}
	rest := out[i+len(prefix):]
	line, _, _ := strings.Cut(rest, "\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	return line, true
}

func TestStartupWarn(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")

	open := func(t *testing.T, bind, token, policy, tokensFile string) (*App, string) {
		t.Helper()
		dir := t.TempDir()
		cfg := config.Config{
			DataDir:        filepath.Join(dir, "data"),
			BindAddr:       bind,
			OllamaURL:      "http://127.0.0.1:9",
			Model:          "test-model",
			Version:        "0.1.0",
			AuthToken:      token,
			AuthTokensFile: tokensFile,
		}
		if policy != "" {
			path := filepath.Join(dir, "policy.toml")
			if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg.PolicyPath = path
		}
		buf := captureStartup(t)
		app, err := New(cfg, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{}, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(app.Shutdown)
		return app, buf.String()
	}

	t.Run("non-loopback", func(t *testing.T) {
		_, out := open(t, "192.168.1.5:9", "", "", "")
		if out != bindWarn || strings.Count(out, "local-grok-bots: WARN:") != 1 {
			t.Fatalf("log:\n%s", out)
		}
	})
	t.Run("loopback", func(t *testing.T) {
		_, out := open(t, "127.0.0.1:0", "", "", "")
		if strings.Contains(out, "local-grok-bots: WARN:") {
			t.Fatalf("log:\n%s", out)
		}
	})
	t.Run("token", func(t *testing.T) {
		_, out := open(t, "192.168.1.5:9", "unit-token", "", "")
		if strings.Contains(out, "local-grok-bots: WARN:") {
			t.Fatalf("log:\n%s", out)
		}
	})
	t.Run("policy bind", func(t *testing.T) {
		app, out := open(t, "127.0.0.1:0", "", "[daemon]\nbind = \"192.168.1.5:9\"\n", "")
		if app.cfg.BindAddr != "192.168.1.5:9" || out != bindWarn {
			t.Fatalf("bind %s log:\n%s", app.cfg.BindAddr, out)
		}
	})
	t.Run("policy loopback", func(t *testing.T) {
		app, out := open(t, "192.168.1.5:9", "", "[daemon]\nbind = \"127.0.0.1:0\"\n", "")
		if app.cfg.BindAddr != "127.0.0.1:0" || strings.Contains(out, "local-grok-bots: WARN:") {
			t.Fatalf("bind %s log:\n%s", app.cfg.BindAddr, out)
		}
	})
	t.Run("generated token", func(t *testing.T) {
		app, out := open(t, "192.168.1.5:9", "", "[daemon]\nbind = \"192.168.1.5:9\"\n\n[backend]\nbackend = \"claude\"\n", "")
		if app.cfg.AuthToken == "" || strings.Contains(out, "local-grok-bots: WARN:") {
			t.Fatalf("token %q log:\n%s", app.cfg.AuthToken, out)
		}
	})
	t.Run("file tokens", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "tokens")
		tok := strings.Repeat("a", 32)
		if err := os.WriteFile(path, []byte("alice:"+tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		_, out := open(t, "192.168.1.5:9", "", "", path)
		if strings.Contains(out, "local-grok-bots: WARN:") || strings.Contains(out, tok) {
			t.Fatalf("log:\n%s", out)
		}
	})
	t.Run("empty tokens file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "tokens")
		if err := os.WriteFile(path, []byte("# none\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		_, out := open(t, "192.168.1.5:9", "", "", path)
		if out != bindWarn {
			t.Fatalf("log:\n%s", out)
		}
	})
}
