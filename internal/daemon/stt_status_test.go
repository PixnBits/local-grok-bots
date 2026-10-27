package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func getSTTStatus(t *testing.T, url, token string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+"/api/stt/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header, b
}

func assertSTTStatus(t *testing.T, code int, hdr http.Header, raw []byte, enabled, available bool, hidden ...string) {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status %d %s", code, raw)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache %q", hdr.Get("Cache-Control"))
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %v %s", err, raw)
	}
	if len(body) != 2 {
		t.Fatalf("keys %v", body)
	}
	for _, key := range []string{"enabled", "available"} {
		v, ok := body[key]
		if !ok {
			t.Fatalf("missing %s in %s", key, raw)
		}
		if _, ok := v.(bool); !ok {
			t.Fatalf("%s is %T in %s", key, v, raw)
		}
	}
	if body["enabled"] != enabled || body["available"] != available {
		t.Fatalf("got enabled %v available %v, want %v %v (%s)", body["enabled"], body["available"], enabled, available, raw)
	}
	text := string(raw)
	if strings.Contains(strings.ToLower(text), "whisper") {
		t.Fatalf("body names the engine: %s", text)
	}
	for _, part := range hidden {
		if part != "" && strings.Contains(text, part) {
			t.Fatalf("body contains %q: %s", part, text)
		}
	}
}

func TestSTTStatusSnapshot(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	policyText := voicePolicy(true, bin, model, 240, 1<<20, 60)
	app := newVoiceApp(t, policyText)
	if app.voicePolicy().stt == nil || !app.pol().VoiceEnabled {
		t.Fatal("voice did not start")
	}
	srv := serve(t, app)
	hidden := []string{bin, model, app.cfg.Version}

	code, _, raw := getSTTStatus(t, srv.URL, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("missing token %d %s", code, raw)
	}
	code, _, raw = getSTTStatus(t, srv.URL, "not-the-token")
	if code != http.StatusUnauthorized {
		t.Fatalf("bad token %d %s", code, raw)
	}

	code, hdr, raw := getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, true, true, hidden...)

	off := app.pol()
	off.VoiceEnabled = false
	app.setPol(off)
	code, hdr, raw = getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, false, false, hidden...)

	on := app.pol()
	on.VoiceEnabled = true
	app.setPol(on)
	code, hdr, raw = getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, true, true, hidden...)

	app.installMu.Lock()
	app.voiceBlock = bin + " whisper " + app.cfg.Version + " " + model
	app.installMu.Unlock()
	code, hdr, raw = getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, false, false, hidden...)

	app.installMu.Lock()
	app.voiceBlock = ""
	app.installMu.Unlock()
	code, hdr, raw = getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, true, true, hidden...)

	writePolicyFile(t, app.cfg.PolicyPath, "[voice]\nenabled = true\n")
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	code, hdr, raw = getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, true, false, hidden...)

	writePolicyFile(t, app.cfg.PolicyPath, policyText)
	if _, err := app.policyNow(); err != nil {
		t.Fatal(err)
	}
	code, hdr, raw = getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, true, true, hidden...)

	marker := bin + "-protect-marker"
	app.latchProtect(marker, "protected path changed: "+marker)
	code, hdr, raw = getSTTStatus(t, srv.URL, "voice-test-token")
	assertSTTStatus(t, code, hdr, raw, true, false, append(hidden, marker)...)
}
