package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestProdShapedSnapshotAllowsBind(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("bwrap is required")
	}
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	t.Setenv("SANDBOX_BUILD_BINDS", "")
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(data, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	bind := filepath.Join(root, "bind")
	if err := os.MkdirAll(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bind, "marker"), []byte("PROD-BIND\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(data, "audit.log")
	policyPath := filepath.Join(root, "policy.toml")
	body := "[backend]\nbackend = \"ollama\"\n[security]\naudit_log = \"" + auditPath + "\"\n[[tools.cli]]\nname = \"grok\"\npath = \"/usr/bin/grok\"\ncredential_home = \"" + home + "\"\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir:    data,
		PolicyPath: policyPath,
		BindAddr:   "127.0.0.1:0",
		OllamaURL:  "http://127.0.0.1:9",
		Model:      "test-model",
		Version:    "0.1.0",
		BuildBinds: []string{bind},
	}, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
	}
	before := app.protectInodes()
	buf := &safeBuf{}
	hup := make(chan os.Signal, 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		WatchSIGHUP(ctx, hup, "", nil, buf)
		close(done)
	}()
	for i := 0; i < 5; i++ {
		hup <- syscall.SIGHUP
	}
	want := strings.Repeat(sighupIgnoreLine+"\n", 5)
	deadline := time.Now().Add(2 * time.Second)
	for buf.String() != want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not return")
	}
	if buf.String() != want {
		t.Fatalf("log %q", buf.String())
	}
	after := app.protectInodes()
	if len(before) == 0 || len(before) != len(after) {
		t.Fatalf("snapshot %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("snapshot changed")
		}
	}
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
	}
	out := runBuildShell(t, app, "cat "+shellQuote(filepath.Join(bind, "marker")))
	if !strings.Contains(out, "PROD-BIND") {
		t.Fatalf("bind not mounted:\n%s", out)
	}
	raw := readAudit(t, auditPath)
	if strings.Contains(raw, "protect_snapshot_tripped") || strings.Contains(raw, "sandbox_block") {
		t.Fatalf("audit:\n%s", raw)
	}
}

func TestProtectTokensDirMoveTrips(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("bwrap is required")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := chmodDataDir(data); err != nil {
		t.Fatal(err)
	}
	tokenDir := filepath.Join(root, "tokend")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := writeTokenFile(t, tokenDir, "alice:"+aliceTok+"\n", 0o600)
	const canary = "TOKEN-CANARY-BYTES"
	if err := os.WriteFile(filepath.Join(tokenDir, "canary"), []byte(canary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bind := filepath.Join(root, "bind")
	if err := os.MkdirAll(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bind, "marker"), []byte("BIND-MARKER\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(root, "audit.log")
	app := newProtectApp(t, data, auditPath, "", []string{bind}, tokenPath)
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
	}
	out := runBuildShell(t, app, "cat "+shellQuote(filepath.Join(bind, "marker")))
	if !strings.Contains(out, "BIND-MARKER") {
		t.Fatalf("first bind:\n%s", out)
	}
	away := bind + "-away"
	if err := os.Rename(bind, away); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tokenDir, bind); err != nil {
		t.Fatal(err)
	}
	reloadLog := &safeBuf{}
	app.logw = reloadLog
	signalProtect(t, app, tokenPath)
	if !strings.Contains(reloadLog.String(), "reload failed") {
		t.Fatalf("reload log %q", reloadLog.String())
	}
	out = runBuildShell(t, app, "cat "+shellQuote(filepath.Join(bind, "canary"))+" || true")
	if strings.Contains(out, canary) {
		t.Fatalf("read the token dir:\n%s", out)
	}
	raw := readAudit(t, auditPath)
	if !strings.Contains(raw, `"action":"sandbox_block"`) || !strings.Contains(raw, "protected path changed (restart required)") {
		t.Fatalf("refusal:\n%s\naudit:\n%s", out, raw)
	}
	if strings.Count(raw, `"action":"protect_snapshot_tripped"`) != 1 {
		t.Fatalf("audit:\n%s", raw)
	}
	if err := os.Rename(bind, tokenDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(away, bind); err != nil {
		t.Fatal(err)
	}
	reloadLog = &safeBuf{}
	app.logw = reloadLog
	signalProtect(t, app, tokenPath)
	out = runBuildShell(t, app, "cat "+shellQuote(filepath.Join(bind, "marker"))+" || true")
	if strings.Contains(out, "BIND-MARKER") || strings.Contains(out, canary) {
		t.Fatalf("sticky allowed a read:\n%s", out)
	}
	raw = readAudit(t, auditPath)
	if !strings.Contains(raw, "protected path changed (restart required)") {
		t.Fatalf("sticky refusal:\n%s\naudit:\n%s", out, raw)
	}
	if strings.Count(readAudit(t, auditPath), `"action":"protect_snapshot_tripped"`) != 1 {
		t.Fatalf("trip was not sticky:\n%s", readAudit(t, auditPath))
	}
}

func TestProtectGitHubTokenMissingAtStart(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("bwrap is required")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := chmodDataDir(data); err != nil {
		t.Fatal(err)
	}
	tokenDir := filepath.Join(root, "ghtok")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(tokenDir, "github.token")
	const canary = "GH-TOKEN-CANARY"
	if err := os.WriteFile(tokenPath, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bind := filepath.Join(root, "bind")
	if err := os.MkdirAll(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(bind); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tokenDir, bind); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(root, "audit.log")
	policyPath := filepath.Join(root, "policy.toml")
	body := "[backend]\nbackend = \"ollama\"\n[security]\naudit_log = \"" + auditPath + "\"\n[github]\ntoken_file = \"" + tokenPath + "\"\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: data, PolicyPath: policyPath, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		BuildBinds: []string{bind},
	}, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if !strings.Contains(app.protectBlockReason(), "missing") {
		t.Fatalf("reason %q", app.protectBlockReason())
	}
	out := runBuildShell(t, app, "cat "+shellQuote(filepath.Join(bind, "github.token"))+" || true")
	if strings.Contains(out, canary) {
		t.Fatalf("read the token:\n%s", out)
	}
	raw := readAudit(t, auditPath)
	if !strings.Contains(raw, `"action":"sandbox_block"`) || !strings.Contains(raw, "protected path missing (restart required)") {
		t.Fatalf("refusal:\n%s\naudit:\n%s", out, raw)
	}
	if strings.Count(raw, `"action":"protect_snapshot_tripped"`) != 1 || !strings.Contains(raw, "protected path missing:") {
		t.Fatalf("audit:\n%s", raw)
	}
}

func TestProtectRequiredMissingAtStart(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("bwrap is required")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := chmodDataDir(data); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "missing-home")
	bind := filepath.Join(root, "bind")
	if err := os.MkdirAll(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bind, "marker"), []byte("SHOULD-NOT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(root, "audit.log")
	policyPath := filepath.Join(root, "policy.toml")
	body := "[backend]\nbackend = \"ollama\"\n[security]\naudit_log = \"" + auditPath + "\"\n[[tools.cli]]\nname = \"grok\"\npath = \"/usr/bin/grok\"\ncredential_home = \"" + home + "\"\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: data, PolicyPath: policyPath, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		BuildBinds: []string{bind},
	}, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if !strings.Contains(app.protectBlockReason(), "missing") || !strings.Contains(app.protectBlockReason(), "restart required") {
		t.Fatalf("reason %q", app.protectBlockReason())
	}
	out := runBuildShell(t, app, "cat "+shellQuote(filepath.Join(bind, "marker"))+" || true")
	if strings.Contains(out, "SHOULD-NOT") {
		t.Fatalf("mounted:\n%s", out)
	}
	raw := readAudit(t, auditPath)
	if !strings.Contains(raw, `"action":"sandbox_block"`) || !strings.Contains(raw, "protected path missing (restart required)") {
		t.Fatalf("refusal:\n%s\naudit:\n%s", out, raw)
	}
}

func TestProtectTokenRotateDoesNotTrip(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("bwrap is required")
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := chmodDataDir(data); err != nil {
		t.Fatal(err)
	}
	tokenDir := filepath.Join(root, "tokend")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := writeTokenFile(t, tokenDir, "alice:"+aliceTok+"\n", 0o600)
	bind := filepath.Join(root, "bind")
	if err := os.MkdirAll(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bind, "marker"), []byte("STILL-BOUND\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(root, "audit.log")
	app := newProtectApp(t, data, auditPath, "", []string{bind}, tokenPath)
	srv := serve(t, app)
	bot := createGrantedBotToken(t, srv.URL, "BindRotate", []string{"build"}, aliceTok)
	before := inodeAt(t, app.protectInodes(), tokenDir)
	next := filepath.Join(tokenDir, "tokens.new")
	if err := os.WriteFile(next, []byte("bob:"+bobTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(next, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, tokenPath); err != nil {
		t.Fatal(err)
	}
	reloadLog := &safeBuf{}
	app.logw = reloadLog
	signalProtect(t, app, tokenPath)
	if !strings.Contains(reloadLog.String(), "reloaded AUTH_TOKENS_FILE") {
		t.Fatalf("reload %q", reloadLog.String())
	}
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
	}
	after := inodeAt(t, app.protectInodes(), tokenDir)
	if after != before {
		t.Fatalf("dir inode changed %+v -> %+v", before, after)
	}
	out, err := app.dispatchTool(context.Background(), bot, "run_shell", map[string]any{
		"command": "cat " + shellQuote(filepath.Join(bind, "marker")),
	})
	if err != nil && !strings.Contains(out, "stdout:") {
		t.Fatalf("shell: %v\n%s", err, out)
	}
	if !strings.Contains(out, "STILL-BOUND") {
		t.Fatalf("bind:\n%s", out)
	}
	if strings.Contains(readAudit(t, auditPath), "protect_snapshot_tripped") {
		t.Fatalf("tripped:\n%s", readAudit(t, auditPath))
	}
}

func TestProtectOptionalMissingDoesNotTrip(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("bwrap is required")
	}
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	wal := filepath.Join(app.cfg.DataDir, "state.db-wal")
	shm := filepath.Join(app.cfg.DataDir, "state.db-shm")
	cli := filepath.Join(app.cfg.DataDir, "cli")
	_ = os.Remove(wal)
	_ = os.Remove(shm)
	if _, err := os.Lstat(wal); err == nil {
		t.Fatal("wal exists")
	}
	if _, err := os.Lstat(cli); err == nil {
		t.Fatal("cli exists")
	}
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
	}
	bind := t.TempDir()
	if err := os.WriteFile(filepath.Join(bind, "marker"), []byte("OPTIONAL-OK\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app.cfg.BuildBinds = []string{bind}
	app.observeProtectBaseline()
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
	}
	out := runBuildShell(t, app, "cat "+shellQuote(filepath.Join(bind, "marker")))
	if !strings.Contains(out, "OPTIONAL-OK") {
		t.Fatalf("bind:\n%s", out)
	}
	if _, err := os.Lstat(cli); err != nil {
		t.Fatal(err)
	}
	if app.protectBlockReason() != "" {
		t.Fatal(app.protectBlockReason())
	}
}

func newProtectApp(t *testing.T, data, auditPath, extraPolicy string, binds []string, tokensFile string) *App {
	t.Helper()
	policyPath := filepath.Join(t.TempDir(), "policy.toml")
	body := "[backend]\nbackend = \"ollama\"\n[security]\naudit_log = \"" + auditPath + "\"\n" + extraPolicy
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: data, PolicyPath: policyPath, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		AuthTokensFile: tokensFile, BuildBinds: binds,
	}, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if _, err := os.Stat(auditPath); err != nil {
		t.Fatal(err)
	}
	return app
}

func signalProtect(t *testing.T, app *App, tokensFile string) {
	t.Helper()
	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		WatchSIGHUP(ctx, hup, tokensFile, app.ReloadAuthTokens, app.logw)
		close(done)
	}()
	hup <- syscall.SIGHUP
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(app.logw.(*safeBuf).String(), "AUTH_TOKENS_FILE") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not return")
	}
}

var buildShellBots atomic.Int64

func runBuildShell(t *testing.T, app *App, command string) string {
	t.Helper()
	srv := serve(t, app)
	token := ""
	if app.tokensConfigured() {
		token = aliceTok
	}
	name := "Bind" + strconv.FormatInt(buildShellBots.Add(1), 10)
	bot := createGrantedBotToken(t, srv.URL, name, []string{"build"}, token)
	out, err := app.dispatchTool(context.Background(), bot, "run_shell", map[string]any{"command": command})
	if err != nil && !strings.Contains(out, "stdout:") {
		t.Fatalf("shell: %v\n%s", err, out)
	}
	return out
}

func createGrantedBotToken(t *testing.T, base, name string, grants []string, token string) store.Bot {
	t.Helper()
	res, b := do(t, "POST", base+"/api/bots", map[string]any{"name": name, "description": "stay"}, token)
	if res.StatusCode != 200 && res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if bot.Name != name {
		t.Fatalf("name stored as %q", bot.Name)
	}
	res, b = do(t, "PATCH", base+"/api/bots/"+bot.ID, map[string]any{"grants": grants}, token)
	if res.StatusCode != 200 {
		t.Fatalf("grant %d %s", res.StatusCode, b)
	}
	return bot
}
