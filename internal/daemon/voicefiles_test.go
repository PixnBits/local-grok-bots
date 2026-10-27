package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"golang.org/x/sys/unix"
)

func voiceWarnings(t *testing.T, app *App) string {
	t.Helper()
	ev, err := app.st.ListLog("", "voice_path", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range ev {
		b.Write(e.Detail)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestJudgeVoiceOwner(t *testing.T) {
	regular := voiceStat{mode: unix.S_IFREG | 0o644, uid: 2}
	if msg := judgeVoice("voice.bin", regular, 1, true); !strings.Contains(msg, "voice.bin") || !strings.Contains(msg, "owner") {
		t.Fatalf("owner %q", msg)
	}
	if msg := judgeVoice("WHISPER_MODEL", regular, 1, true); !strings.Contains(msg, "WHISPER_MODEL") {
		t.Fatalf("key %q", msg)
	}
	if judgeVoice("voice.bin", voiceStat{mode: unix.S_IFREG | 0o644, uid: 0}, 1, true) != "" {
		t.Fatal("root owner rejected")
	}
	if judgeVoice("voice.bin", voiceStat{mode: unix.S_IFREG | 0o644, uid: 1}, 1, true) != "" {
		t.Fatal("daemon owner rejected")
	}
	if msg := judgeVoice("voice.model", voiceStat{mode: unix.S_IFREG | 0o664, uid: 1}, 1, true); !strings.Contains(msg, "voice.model") || !strings.Contains(msg, "writable") {
		t.Fatalf("mode %q", msg)
	}
}

func TestVoicePathsAcceptedAndProtected(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(model, 0o644); err != nil {
		t.Fatal(err)
	}
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	if app.voicePolicy().enabled != true {
		t.Fatalf("blocked %q", app.voiceBlock)
	}
	inodeAt(t, app.protectInodes(), bin)
	inodeAt(t, app.protectInodes(), model)
	inodeAt(t, app.protectInodes(), filepath.Dir(bin))
	inodeAt(t, app.protectInodes(), filepath.Dir(model))
	srv := serve(t, app)
	res, out := postSTT(t, srv.URL, "voice-test-token", make([]byte, 3200))
	if res.StatusCode != 200 || out["text"] != sttPhrase {
		t.Fatalf("status %d %v", res.StatusCode, out)
	}
}

func TestVoicePathRefused(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	goodDir := filepath.Join(base, "good")
	if err := os.Mkdir(goodDir, 0o700); err != nil {
		t.Fatal(err)
	}
	goodBin, goodModel := writeWhisperScript(t, goodDir)

	t.Run("symlink file", func(t *testing.T) {
		dir := filepath.Join(base, "sym")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "whisper-cli")
		if err := os.Symlink(goodBin, link); err != nil {
			t.Fatal(err)
		}
		expectVoiceBlocked(t, link, goodModel, "voice.bin", "symlink")
	})
	t.Run("directory", func(t *testing.T) {
		dir := filepath.Join(base, "dirbin")
		if err := os.MkdirAll(filepath.Join(dir, "whisper-cli"), 0o700); err != nil {
			t.Fatal(err)
		}
		expectVoiceBlocked(t, filepath.Join(dir, "whisper-cli"), goodModel, "voice.bin", "not a regular file")
	})
	t.Run("fifo", func(t *testing.T) {
		dir := filepath.Join(base, "fifo")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		fifo := filepath.Join(dir, "model.bin")
		if err := unix.Mkfifo(fifo, 0o644); err != nil {
			t.Fatal(err)
		}
		expectVoiceBlocked(t, goodBin, fifo, "voice.model", "not a regular file")
	})
	t.Run("group writable", func(t *testing.T) {
		dir := filepath.Join(base, "group")
		bin, model := writeWhisperScript(t, dir)
		if err := os.Chmod(bin, 0o664); err != nil {
			t.Fatal(err)
		}
		expectVoiceBlocked(t, bin, model, "voice.bin", "writable")
	})
	t.Run("other writable", func(t *testing.T) {
		dir := filepath.Join(base, "other")
		bin, model := writeWhisperScript(t, dir)
		if err := os.Chmod(model, 0o606); err != nil {
			t.Fatal(err)
		}
		expectVoiceBlocked(t, bin, model, "voice.model", "writable")
	})
	t.Run("parent writable", func(t *testing.T) {
		dir := filepath.Join(base, "pwrite")
		bin, model := writeWhisperScript(t, dir)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		expectVoiceBlocked(t, bin, model, "voice.bin parent", "writable")
	})
	t.Run("parent symlink", func(t *testing.T) {
		link := filepath.Join(base, "plink")
		if err := os.Symlink(goodDir, link); err != nil {
			t.Fatal(err)
		}
		expectVoiceBlocked(t, filepath.Join(link, "whisper-cli"), filepath.Join(link, "model.bin"), "voice.bin parent", "symlink")
	})
}

func expectVoiceBlocked(t *testing.T, bin, model, key, why string) {
	t.Helper()
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	if app.voicePolicy().enabled {
		t.Fatal("voice stayed on")
	}
	warn := voiceWarnings(t, app)
	if !strings.Contains(warn, key) || !strings.Contains(warn, why) {
		t.Fatalf("warning %q want %s %s", warn, key, why)
	}
	srv := serve(t, app)
	res, out := postSTT(t, srv.URL, "voice-test-token", make([]byte, 3200))
	if res.StatusCode != 403 {
		t.Fatalf("status %d %v", res.StatusCode, out)
	}
	logs := sttLogText(t, app)
	if !strings.Contains(logs, `"code":403`) || strings.Contains(logs, sttPhrase) {
		t.Fatalf("audit %s", logs)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(bin), "called")); err == nil {
		t.Fatal("whisper ran")
	}
}

func TestVoiceEnvPathRefused(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(dir, "model.bin")
	if err := os.WriteFile(model, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real-whisper")
	if err := os.WriteFile(real, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "whisper-cli")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte("[voice]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: path, AuthToken: "voice-test-token",
		WhisperBin: link, WhisperModel: model,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	if app.voicePolicy().enabled {
		t.Fatal("voice stayed on")
	}
	warn := voiceWarnings(t, app)
	if !strings.Contains(warn, "WHISPER_BIN") || !strings.Contains(warn, "symlink") {
		t.Fatalf("warning %q", warn)
	}
	srv := serve(t, app)
	res, out := postSTT(t, srv.URL, "voice-test-token", make([]byte, 3200))
	if res.StatusCode != 403 {
		t.Fatalf("status %d %v", res.StatusCode, out)
	}
}
