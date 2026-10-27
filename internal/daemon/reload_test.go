package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func clearPolicyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AUTH_TOKEN", "AUTH_TOKENS_FILE", "MANAGED_POLICY", "BIND_ADDR",
		"WHISPER_BIN", "WHISPER_MODEL", "TLS_CERT", "TLS_KEY", "TLS_SELF_SIGNED",
		"PERM_CALLBACK_ADDR", "OLLAMA_URL", "OLLAMA_MODEL",
	} {
		t.Setenv(k, "")
	}
}

func writePolicyFile(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func waitModel(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("model was not called")
	}
}

func TestPolicyStartupFixed(t *testing.T) {
	clearPolicyEnv(t)
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	policyPath := filepath.Join(dir, "policy.toml")
	ollama := "[security]\naudit_log = \"" + auditPath + "\"\n[backend]\nbackend = \"ollama\"\n"
	claude := "[security]\naudit_log = \"" + auditPath + "\"\n[backend]\nbackend = \"claude\"\n"
	writePolicyFile(t, policyPath, ollama)
	binDir := t.TempDir()
	invocations := filepath.Join(dir, "cli-invocations")
	script := "#!/bin/sh\necho invoked >> " + shQuote(invocations) + "\nexit 0\n"
	for _, name := range []string{"claude", "grok"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	started := make(chan struct{}, 8)
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: policyPath,
	}, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		started <- struct{}{}
		return model.ChatResponse{Content: "ok"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if app.tokensConfigured() || app.pol().UsesCLI() || app.pol().EffectiveBackend() != "ollama" {
		t.Fatalf("startup tokens %v cli %v backend %s", app.tokensConfigured(), app.pol().UsesCLI(), app.pol().EffectiveBackend())
	}
	if _, err := os.Stat(filepath.Join(dir, adminTokenFile)); !os.IsNotExist(err) {
		t.Fatalf("admin token %v", err)
	}
	writePolicyFile(t, policyPath, claude)
	check := func() {
		t.Helper()
		if _, err := app.policyNow(); err != nil {
			t.Fatal(err)
		}
		_ = app.daemonSecrets()
		_ = app.shellProtect()
		pol := app.pol()
		if pol.EffectiveBackend() != "ollama" || pol.UsesCLI() || app.tokensConfigured() {
			t.Fatalf("backend %s cli %v tokens %v", pol.EffectiveBackend(), pol.UsesCLI(), app.tokensConfigured())
		}
	}
	check()
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "description": "brief"}, "")
	if res.StatusCode != 200 && res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	for i := 0; i < 3; i++ {
		res, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "ping"}, "")
		if res.StatusCode != 200 {
			t.Fatalf("post %d %s", res.StatusCode, b)
		}
		waitModel(t, started)
		waitIdle(t, srv.URL, bot.ID, "")
		check()
	}
	raw, err := os.ReadFile(invocations)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(raw))) != 0 {
		t.Fatalf("cli invocations %s", raw)
	}
	n, err := app.st.LogCount("policy_restart_required")
	if err != nil || n != 1 {
		t.Fatalf("log count %d %v", n, err)
	}
	evs, err := app.st.ListLog("", "policy_restart_required", "", 10)
	if err != nil || len(evs) != 1 || !strings.Contains(string(evs[0].Detail), `"backend"`) || strings.Contains(string(evs[0].Detail), "claude") {
		t.Fatalf("log %v %v", evs, err)
	}
	auditRaw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(auditRaw), `"action":"policy_restart_required"`) != 1 || strings.Contains(string(auditRaw), "claude") {
		t.Fatalf("audit %s", auditRaw)
	}
	writePolicyFile(t, policyPath, ollama)
	check()
	if n, err = app.st.LogCount("policy_restart_required"); err != nil || n != 1 {
		t.Fatalf("after restore %d %v", n, err)
	}
	writePolicyFile(t, policyPath, claude)
	check()
	if n, err = app.st.LogCount("policy_restart_required"); err != nil || n != 2 {
		t.Fatalf("after second change %d %v", n, err)
	}
}

func TestPolicyInstallGeneration(t *testing.T) {
	app := newApp(t, "", nil)
	app.startPol = policy.Policy{Backend: "ollama", CLIPermitted: true, Loaded: true, ClaudeTransport: policy.TransportMCP}
	app.setPol(app.startPol)
	newer := policy.Policy{Loaded: true, VoiceEnabled: true, ClaudeTransport: policy.TransportMCP}
	older := policy.Policy{Loaded: true, VoiceEnabled: false, ClaudeTransport: policy.TransportStreamControl}
	app.consider(5, newer)
	app.consider(3, older)
	app.noteGen(4)
	got := app.pol()
	if !got.VoiceEnabled || got.ClaudeTransport != policy.TransportMCP || got.EffectiveBackend() != "ollama" {
		t.Fatalf("stale generation applied: %#v", got)
	}
	if app.installedGeneration() != 5 {
		t.Fatalf("generation %d", app.installedGeneration())
	}
	app.consider(6, older)
	got = app.pol()
	if got.VoiceEnabled || got.ClaudeTransport != policy.TransportStreamControl {
		t.Fatalf("newer generation: %#v", got)
	}
	if app.installedGeneration() != 6 {
		t.Fatalf("generation %d", app.installedGeneration())
	}
}

func TestPolicyConcurrentReaders(t *testing.T) {
	clearPolicyEnv(t)
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	writePolicyFile(t, path, "[backend]\nbackend = \"ollama\"\n")
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: path,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			id := "bot-" + string(rune('a'+i))
			for n := 0; n < 40; n++ {
				_ = app.daemonSecrets()
				_ = app.egressPorts()
				_ = app.protectSpecs()
				_ = app.pol()
				end := app.holdTurn(id)
				_ = app.effPol(id)
				_ = app.secretList(id)
				_ = app.egressFor(id)
				end()
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if app.pol().EffectiveBackend() != "ollama" {
		t.Fatalf("backend %s", app.pol().EffectiveBackend())
	}
}

func TestPolicyReloadConverges(t *testing.T) {
	clearPolicyEnv(t)
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	voiceDir := t.TempDir()
	if err := os.Chmod(voiceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, model := writeWhisperScript(t, voiceDir)
	path := filepath.Join(dir, "policy.toml")
	off := "[backend]\nbackend = \"ollama\"\n[voice]\nenabled = false\n[cli.permission]\nclaude_transport = \"stream_control\"\n"
	on := "[backend]\nbackend = \"ollama\"\n[voice]\nenabled = true\nbin = \"" + bin + "\"\nmodel = \"" + model + "\"\n[cli.permission]\nclaude_transport = \"mcp\"\n"
	writePolicyFile(t, path, off)
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: path,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 24; n++ {
			body := off
			if n%2 == 0 {
				body = on
			}
			writePolicyFile(t, path, body)
			_, _ = app.policyNow()
		}
	}()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "bot-" + string(rune('a'+i))
			for n := 0; n < 24; n++ {
				end := app.holdTurn(id)
				_ = app.effPol(id)
				_ = app.secretList(id)
				_ = app.egressFor(id)
				end()
				if n < 2 {
					callSTT(app, nil, bytesReader(make([]byte, 3200)), nil)
				}
			}
		}(i)
	}
	wg.Wait()
	writePolicyFile(t, path, on)
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	pol := app.pol()
	snap := app.voicePolicy()
	if pol.EffectiveBackend() != "ollama" || !pol.VoiceEnabled || pol.ClaudeTransport != policy.TransportMCP || !snap.enabled || snap.stt == nil {
		t.Fatalf("final backend %s voice %v transport %s stt %v", pol.EffectiveBackend(), pol.VoiceEnabled, pol.ClaudeTransport, snap.stt != nil)
	}
	stale := policy.Policy{Loaded: true, VoiceEnabled: false, ClaudeTransport: policy.TransportStreamControl}
	app.consider(app.installedGeneration(), stale)
	after := app.pol()
	if after.VoiceEnabled != pol.VoiceEnabled || after.ClaudeTransport != pol.ClaudeTransport {
		t.Fatalf("stale generation replaced final policy")
	}
}

func TestPolicyReloadFailure(t *testing.T) {
	clearPolicyEnv(t)
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	voiceDir := t.TempDir()
	if err := os.Chmod(voiceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, model := writeWhisperScript(t, voiceDir)
	path := filepath.Join(dir, "policy.toml")
	good := "[backend]\nbackend = \"ollama\"\n[voice]\nenabled = true\nbin = \"" + bin + "\"\nmodel = \"" + model + "\"\n"
	writePolicyFile(t, path, good)
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: path,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if !app.pol().VoiceEnabled || !app.pol().CLIPermitted || app.voicePolicy().stt == nil {
		t.Fatal("voice did not start")
	}
	writePolicyFile(t, path, "[[[")
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	if app.pol().VoiceEnabled || app.pol().EffectiveBackend() != "ollama" || !app.pol().CLIPermitted || app.voicePolicy().stt != nil {
		t.Fatalf("bad file pol %#v stt %v", app.pol(), app.voicePolicy().stt != nil)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	if app.pol().VoiceEnabled || app.voicePolicy().stt != nil || app.pol().EffectiveBackend() != "ollama" {
		t.Fatal("deleted file kept voice")
	}
	writePolicyFile(t, path, good)
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	if !app.pol().VoiceEnabled || app.voicePolicy().stt == nil || app.pol().EffectiveBackend() != "ollama" {
		t.Fatal("voice did not return")
	}
}

func TestPolicyEmptyPathKeepsSnapshot(t *testing.T) {
	app := newApp(t, "", nil)
	app.editPol(func(p *policy.Policy) {
		p.Backend = "grok"
		p.CLIPermitted = true
		p.VoiceEnabled = true
	})
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	pol := app.pol()
	if pol.EffectiveBackend() != "grok" || !pol.VoiceEnabled {
		t.Fatalf("empty path reset policy: %#v", pol)
	}
}

func TestPolicyOverlapVoiceOff(t *testing.T) {
	clearPolicyEnv(t)
	dir := t.TempDir()
	home := t.TempDir()
	path := writeHomePolicy(t, dir, home)
	app, err := overlapOpen(t, config.Config{DataDir: dir, PolicyPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	app.editPol(func(p *policy.Policy) { p.VoiceEnabled = true })
	target := filepath.Join(dir, adminTokenFile)
	if err := os.WriteFile(target, []byte("placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(homePolicy(link)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := app.policyNow(); err == nil || err.Error() != dataDirHomeErr(link) {
		t.Fatalf("reload %v", err)
	}
	if app.pol().VoiceEnabled || app.pol().EffectiveBackend() != "ollama" {
		t.Fatalf("overlap kept voice %#v", app.pol())
	}
}

func TestPolicyVoiceDrop(t *testing.T) {
	clearPolicyEnv(t)
	voiceDir := t.TempDir()
	if err := os.Chmod(voiceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, model := writeWhisperScript(t, voiceDir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	if app.voicePolicy().stt == nil {
		t.Fatal("missing transcriber")
	}
	writePolicyFile(t, app.cfg.PolicyPath, "[voice]\nenabled = true\n")
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	if app.voicePolicy().stt != nil || !app.pol().VoiceEnabled {
		t.Fatal("cleared paths kept the transcriber")
	}
	code, out, _ := callSTT(app, nil, bytesReader(make([]byte, 3200)), nil)
	if code != 503 || out["error"] != errSTTUnavailable.Error() {
		t.Fatalf("missing %d %v", code, out)
	}
	writePolicyFile(t, app.cfg.PolicyPath, "[voice]\nenabled = false\n")
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	code, out, _ = callSTT(app, nil, bytesReader(make([]byte, 3200)), nil)
	if code != 403 || out["error"] != "speech recognition is disabled" || app.voicePolicy().stt != nil {
		t.Fatalf("disabled %d %v stt %v", code, out, app.voicePolicy().stt != nil)
	}
}

func TestPolicyWhisperSecrets(t *testing.T) {
	clearPolicyEnv(t)
	voiceDir := t.TempDir()
	if err := os.Chmod(voiceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, model := writeWhisperScript(t, voiceDir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	secrets := app.daemonSecrets()
	if !coiListed(secrets, bin) || !coiListed(secrets, model) {
		t.Fatalf("secrets %v", secrets)
	}
	writePolicyFile(t, app.cfg.PolicyPath, "[voice]\nenabled = false\nbin = \""+bin+"\"\nmodel = \""+model+"\"\n")
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	secrets = app.daemonSecrets()
	if coiListed(secrets, bin) || coiListed(secrets, model) {
		t.Fatalf("disabled secrets %v", secrets)
	}

	envDir := t.TempDir()
	if err := chmodDataDir(envDir); err != nil {
		t.Fatal(err)
	}
	envBin := filepath.Join(voiceDir, "env-whisper")
	envModel := filepath.Join(voiceDir, "env-model")
	if err := os.WriteFile(envBin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envModel, []byte("m"), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(envDir, "policy.toml")
	writePolicyFile(t, envPath, "[voice]\nenabled = true\n")
	envApp, err := New(config.Config{
		DataDir: envDir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: envPath, AuthToken: "voice-test-token",
		WhisperBin: envBin, WhisperModel: envModel,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	envApp.noGrokProxy = true
	t.Cleanup(envApp.Shutdown)
	secrets = envApp.daemonSecrets()
	if !coiListed(secrets, envBin) || !coiListed(secrets, envModel) {
		t.Fatalf("env secrets %v", secrets)
	}
}
