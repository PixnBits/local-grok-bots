package daemon

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVoiceExecRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 30))
	pcm := make([]byte, 3200)

	if err := os.Chmod(bin, 0o666); err != nil {
		t.Fatal(err)
	}
	code, out, raw := callSTT(app, nil, bytes.NewReader(pcm), nil)
	if code != http.StatusForbidden || out["error"] != "speech recognition is disabled" {
		t.Fatalf("mode %d %v", code, out)
	}
	if strings.Contains(raw, bin) || strings.Contains(raw, dir) {
		t.Fatalf("path in body %s", raw)
	}
	if !strings.Contains(voiceWarnings(t, app), bin) {
		t.Fatalf("log %s", voiceWarnings(t, app))
	}
	if n := len(app.voiceHits.hits["default"]); n != 0 {
		t.Fatalf("counted %d", n)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), nil)
	if code != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("after mode %d %v", code, out)
	}

	t.Run("library", func(t *testing.T) {
		lib := filepath.Join(dir, "libbad.so")
		if err := os.WriteFile(lib, []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lib, 0o666); err != nil {
			t.Fatal(err)
		}
		code, out, raw := callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusForbidden || out["error"] != "speech recognition is disabled" || strings.Contains(raw, lib) {
			t.Fatalf("lib %d %v %s", code, out, raw)
		}
		if !strings.Contains(voiceWarnings(t, app), lib) {
			t.Fatalf("lib log %s", voiceWarnings(t, app))
		}
		if err := os.Remove(lib); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "libtarget")
		if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "libout.so")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		code, out, raw = callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusForbidden || strings.Contains(raw, outside) {
			t.Fatalf("symlink %d %v %s", code, out, raw)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		inner := filepath.Join(dir, "libin.so.1")
		if err := os.WriteFile(inner, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(inner, filepath.Join(dir, "libin.so")); err != nil {
			t.Fatal(err)
		}
		code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusOK || out["text"] != sttPhrase {
			t.Fatalf("inner lib %d %v", code, out)
		}
	})

	t.Run("protect", func(t *testing.T) {
		app.latchProtect(filepath.Join(dir, "marker"), "protected path changed: marker")
		before := len(app.voiceHits.hits["default"])
		code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusForbidden || out["error"] != "speech recognition is disabled" {
			t.Fatalf("protect %d %v", code, out)
		}
		if len(app.voiceHits.hits["default"]) != before {
			t.Fatalf("protect counted %d", len(app.voiceHits.hits["default"]))
		}
	})
}

func TestVoiceExecProtectBeforeTranscribe(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 1))
	app.sttBodyHold = func() {
		app.latchProtect(filepath.Join(dir, "marker"), "protected path changed: marker")
	}
	code, out, _ := callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), nil)
	if code != http.StatusForbidden || out["error"] != "speech recognition is disabled" {
		t.Fatalf("mid %d %v", code, out)
	}
	if len(app.voiceHits.hits["default"]) != 0 {
		t.Fatalf("counted %d", len(app.voiceHits.hits["default"]))
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "called")); err == nil && len(raw) != 0 {
		t.Fatalf("whisper ran %s", raw)
	}
}

func TestVoiceExecMissingThenCreated(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(dir, "model.bin")
	if err := os.WriteFile(model, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "whisper-cli")
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 4))
	pcm := make([]byte, 3200)
	code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), nil)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("missing %d %v", code, out)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o666); err != nil {
		t.Fatal(err)
	}
	code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), nil)
	if code != http.StatusForbidden || out["error"] != "speech recognition is disabled" {
		t.Fatalf("created bad %d %v", code, out)
	}
	script := "#!/bin/sh\n" +
		"out=\nprev=\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = \"-of\" ]; then out=$arg; fi\n" +
		"  prev=$arg\n" +
		"done\n" +
		"printf '%s\\n' '" + sttPhrase + "' > \"$out.txt\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), nil)
	if code != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("created good %d %v", code, out)
	}
}

func TestSTTOriginAllowlist(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin, model := writeWhisperScript(t, dir)
	body := voicePolicy(true, bin, model, 240, 1<<20, 60) + "[daemon]\nallowed_hosts = [\"voice.example\"]\n"
	app := newVoiceApp(t, body)
	pcm := make([]byte, 3200)
	ok := func(host, origin string, tlsOn bool) {
		t.Helper()
		code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), func(r *http.Request) {
			r.Host = host
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			if tlsOn {
				r.TLS = &tls.ConnectionState{}
			}
		})
		if code != http.StatusOK || out["text"] != sttPhrase {
			t.Fatalf("%s origin %s tls %v -> %d %v", host, origin, tlsOn, code, out)
		}
	}
	ok("127.0.0.1:8787", "http://localhost:8787", false)
	ok("localhost:8787", "http://127.0.0.1:8787", false)
	ok("voice.example:8787", "http://voice.example:8787", false)
	ok("[::1]:8787", "", false)
	deny := func(host, origin string, tlsOn bool) {
		t.Helper()
		code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), func(r *http.Request) {
			r.Host = host
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			if tlsOn {
				r.TLS = &tls.ConnectionState{}
			}
		})
		if code != http.StatusForbidden || out["error"] != "forbidden" {
			t.Fatalf("%s origin %s tls %v -> %d %v", host, origin, tlsOn, code, out)
		}
	}
	deny("evil.example:8787", "http://evil.example:8787", false)
	deny("voice.example:8787", "http://voice.example:9", false)
	deny("voice.example:8787", "https://voice.example:8787", false)
	deny("voice.example:8787", "http://voice.example:8787", true)
	deny("voice.example:8787", "http://evil.example:8787", false)
	code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), func(r *http.Request) {
		r.Host = "voice.example:8787"
		r.Header.Set("Origin", "http://voice.example:8787")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	if code != http.StatusForbidden || out["error"] != "forbidden" {
		t.Fatalf("fetch %d %v", code, out)
	}
}

func TestSTTOutputCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "whisper-cli")
	model := filepath.Join(dir, "model.bin")
	script := "#!/bin/sh\n" +
		"out=\nprev=\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = \"-of\" ]; then out=$arg; fi\n" +
		"  prev=$arg\n" +
		"done\n" +
		"dd if=/dev/zero bs=" + itoa(sttOutputCap+1) + " count=1 of=\"$out.txt\" status=none\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	code, out, raw := callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), nil)
	if code != http.StatusBadGateway || out["error"] != "speech recognition failed" || len(raw) > 200 {
		t.Fatalf("over %d %s", code, raw)
	}
	exact := "#!/bin/sh\n" +
		"out=\nprev=\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$prev\" = \"-of\" ]; then out=$arg; fi\n" +
		"  prev=$arg\n" +
		"done\n" +
		"dd if=/dev/zero bs=" + itoa(sttOutputCap) + " count=1 of=\"$out.txt\" status=none\n"
	if err := os.WriteFile(bin, []byte(exact), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, _ = callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), nil)
	text, _ := out["text"].(string)
	if code != http.StatusOK || len(text) != sttOutputCap {
		t.Fatalf("exact %d len %d", code, len(text))
	}
}
