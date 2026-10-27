package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/config"
)

const sttPhrase = "super-secret-transcript"

func writeWhisperScript(t *testing.T, dir string) (bin, model string) {
	t.Helper()
	bin = filepath.Join(dir, "whisper-cli")
	model = filepath.Join(dir, "model.bin")
	script := `#!/bin/sh
dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
echo called >> "$dir/called"
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-of" ]; then
    out=$arg
  fi
  prev=$arg
done
if [ -z "$out" ]; then
  echo missing output >&2
  exit 1
fi
printf '%s\n' '` + sttPhrase + `' > "$out.txt"
`
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bin, model
}

func voicePolicy(enabled bool, bin, model string, audio, body, rate int) string {
	en := "false"
	if enabled {
		en = "true"
	}
	return strings.TrimSpace(`
[voice]
enabled = `+en+`
bin = "`+bin+`"
model = "`+model+`"
max_audio_seconds = `+itoa(audio)+`
max_body_bytes = `+itoa(body)+`
max_requests_per_hour = `+itoa(rate)+`
`) + "\n"
}

func itoa(n int) string {
	return strconvItoa(n)
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func newVoiceApp(t *testing.T, policyBody string) *App {
	t.Helper()
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: path, AuthToken: "voice-test-token",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	return app
}

func postSTT(t *testing.T, url, token string, body []byte) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/api/stt", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func sttLogText(t *testing.T, app *App) string {
	t.Helper()
	ev, err := app.st.ListLog("", "stt", "", 50)
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

func TestSTTDisabledByDefault(t *testing.T) {
	app := newVoiceApp(t, "[backend]\nbackend = \"ollama\"\n")
	srv := serve(t, app)
	res, out := postSTT(t, srv.URL, "voice-test-token", make([]byte, 3200))
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d %v", res.StatusCode, out)
	}
	logs := sttLogText(t, app)
	if !strings.Contains(logs, `"code":403`) || !strings.Contains(logs, `"who":"default"`) {
		t.Fatalf("audit %s", logs)
	}
	if n, err := app.st.LogCount("stt"); err != nil || n != 1 {
		t.Fatalf("count %d %v", n, err)
	}
}

func TestSTTUnauthenticated(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 8<<20, 60))
	srv := serve(t, app)
	res, _ := postSTT(t, srv.URL, "", make([]byte, 3200))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", res.StatusCode)
	}
	if n, err := app.st.LogCount("stt"); err != nil || n != 0 {
		t.Fatalf("unauthenticated wrote %d logs %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "called")); !os.IsNotExist(err) {
		t.Fatal("whisper ran without auth")
	}
}

func TestSTTCapsRateAndMissing(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	cases := []struct {
		name   string
		policy string
		body   int
		want   int
		called bool
	}{
		{"over body", voicePolicy(true, bin, model, 240, 64, 60), 128, http.StatusRequestEntityTooLarge, false},
		{"over audio", voicePolicy(true, bin, model, 1, 1<<20, 60), 32002, http.StatusRequestEntityTooLarge, false},
		{"missing binary", voicePolicy(true, filepath.Join(dir, "missing-bin"), model, 240, 1<<20, 60), 3200, http.StatusServiceUnavailable, false},
		{"missing model", voicePolicy(true, bin, filepath.Join(dir, "missing-model"), 240, 1<<20, 60), 3200, http.StatusServiceUnavailable, false},
		{"unconfigured", "[voice]\nenabled = true\n", 3200, http.StatusServiceUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(filepath.Join(dir, "called"))
			app := newVoiceApp(t, tc.policy)
			srv := serve(t, app)
			res, out := postSTT(t, srv.URL, "voice-test-token", make([]byte, tc.body))
			if res.StatusCode != tc.want {
				t.Fatalf("status %d %v", res.StatusCode, out)
			}
			msg, _ := out["error"].(string)
			if msg == "" || strings.Contains(msg, sttPhrase) {
				t.Fatalf("error %q", msg)
			}
			if tc.name == "missing binary" || tc.name == "missing model" || tc.name == "unconfigured" {
				if !strings.Contains(strings.ToLower(msg), "not") {
					t.Fatalf("unclear error %q", msg)
				}
			}
			logs := sttLogText(t, app)
			if strings.Contains(logs, sttPhrase) || !strings.Contains(logs, `"who":"default"`) {
				t.Fatalf("audit %s", logs)
			}
			_, err := os.Stat(filepath.Join(dir, "called"))
			ran := err == nil
			if ran != tc.called {
				t.Fatalf("whisper ran=%v err=%v", ran, err)
			}
		})
	}
}

func TestSTTRateLimitPerUser(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 2))
	srv := serve(t, app)
	pcm := make([]byte, 3200)
	for i := 0; i < 2; i++ {
		res, out := postSTT(t, srv.URL, "voice-test-token", pcm)
		if res.StatusCode != http.StatusOK || out["text"] != sttPhrase {
			t.Fatalf("call %d: %d %v", i, res.StatusCode, out)
		}
	}
	res, out := postSTT(t, srv.URL, "voice-test-token", pcm)
	if res.StatusCode != http.StatusTooManyRequests || out["error"] != "speech recognition rate limit exceeded" {
		t.Fatalf("third %d %v", res.StatusCode, out)
	}
	logs := sttLogText(t, app)
	if strings.Contains(logs, sttPhrase) {
		t.Fatalf("audit contains transcript: %s", logs)
	}
	if !strings.Contains(logs, `"code":429`) {
		t.Fatalf("audit %s", logs)
	}
}

func TestSTTAuditOmitsTranscript(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	srv := serve(t, app)
	res, out := postSTT(t, srv.URL, "voice-test-token", make([]byte, 3200))
	if res.StatusCode != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("%d %v", res.StatusCode, out)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logs := sttLogText(t, app)
	blob := logs + "\n" + string(raw)
	if strings.Contains(blob, sttPhrase) || strings.Contains(blob, "transcript") {
		t.Fatalf("audit leaked transcript: %s", blob)
	}
	for _, needle := range []string{`"who":"default"`, `"bytes":3200`, `"code":200`, `"duration_ms":`} {
		if !strings.Contains(blob, needle) {
			t.Fatalf("missing %s in %s", needle, blob)
		}
	}
}

// blockingSTT holds the first Transcribe on hold and counts every call.
type blockingSTT struct {
	calls   atomic.Int32
	entered chan struct{}
	hold    chan struct{}
	text    string
}

func (b *blockingSTT) Transcribe(ctx context.Context, pcm []byte) (string, error) {
	if b.calls.Add(1) == 1 {
		close(b.entered)
		select {
		case <-b.hold:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return b.text, nil
}

func newBlockingVoice(t *testing.T) (*App, *blockingSTT, func()) {
	t.Helper()
	app := newVoiceApp(t, voicePolicy(true, "/whisper/whisper-cli", "/whisper/model.bin", 240, 1<<20, 60))
	fake := &blockingSTT{
		entered: make(chan struct{}),
		hold:    make(chan struct{}),
		text:    "slot-hold-transcript",
	}
	app.stt = fake
	var once sync.Once
	release := func() { once.Do(func() { close(fake.hold) }) }
	return app, fake, release
}

func callHandleSTT(app *App, ctx context.Context, pcm []byte) (int, map[string]any) {
	if ctx == nil {
		ctx = context.Background()
	}
	req := httptest.NewRequest(http.MethodPost, "/api/stt", bytes.NewReader(pcm))
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer voice-test-token")
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	app.handleSTT(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func firedSTTWait() <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	return ch
}

func TestSTTBusyReturns429(t *testing.T) {
	app, fake, release := newBlockingVoice(t)
	var arms atomic.Int32
	idle := make(chan time.Time)
	fired := firedSTTWait()
	app.sttBusyTimer = func(time.Duration) (<-chan time.Time, func()) {
		if arms.Add(1) == 1 {
			return idle, func() {}
		}
		return fired, func() {}
	}
	pcm := make([]byte, 3200)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		callHandleSTT(app, context.Background(), pcm)
	}()
	defer func() {
		release()
		wg.Wait()
	}()
	<-fake.entered

	code, out := callHandleSTT(app, context.Background(), pcm)
	if code != http.StatusTooManyRequests || out["error"] != sttBusyMsg {
		t.Fatalf("status %d %v", code, out)
	}
	if out["error"] == "speech recognition rate limit exceeded" {
		t.Fatal("busy 429 uses the rate-limit message")
	}
	if text, ok := out["text"].(string); ok && text != "" {
		t.Fatalf("transcript in response %q", text)
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("whisper calls %d", fake.calls.Load())
	}
	logs := sttLogText(t, app)
	if strings.Contains(logs, fake.text) || strings.Contains(logs, "transcript") {
		t.Fatalf("audit leaked transcript: %s", logs)
	}
	for _, needle := range []string{`"who":"default"`, `"bytes":3200`, `"code":429`, `"duration_ms":`} {
		if !strings.Contains(logs, needle) {
			t.Fatalf("missing %s in %s", needle, logs)
		}
	}
}

func TestSTTCancelWhileWaiting(t *testing.T) {
	app, fake, release := newBlockingVoice(t)
	waiting := make(chan struct{})
	var arms atomic.Int32
	app.sttBusyTimer = func(time.Duration) (<-chan time.Time, func()) {
		if arms.Add(1) == 2 {
			close(waiting)
		}
		return make(chan time.Time), func() {}
	}
	pcm := make([]byte, 3200)

	firstDone := make(chan struct{})
	var firstCode int
	var firstOut map[string]any
	go func() {
		defer close(firstDone)
		firstCode, firstOut = callHandleSTT(app, context.Background(), pcm)
	}()
	defer func() {
		release()
		<-firstDone
	}()
	<-fake.entered

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secondDone := make(chan struct{})
	var secondCode int
	var secondOut map[string]any
	go func() {
		defer close(secondDone)
		secondCode, secondOut = callHandleSTT(app, ctx, pcm)
	}()
	<-waiting
	cancel()
	<-secondDone

	if secondCode != http.StatusRequestTimeout || secondOut["error"] != sttWaitEndedMsg {
		t.Fatalf("cancel %d %v", secondCode, secondOut)
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("whisper calls %d", fake.calls.Load())
	}
	logs := sttLogText(t, app)
	if strings.Contains(logs, fake.text) || strings.Contains(logs, "transcript") {
		t.Fatalf("audit leaked transcript: %s", logs)
	}
	for _, needle := range []string{`"who":"default"`, `"bytes":3200`, `"code":408`, `"duration_ms":100`} {
		if !strings.Contains(logs, needle) {
			t.Fatalf("missing %s in %s", needle, logs)
		}
	}

	release()
	<-firstDone
	if firstCode != http.StatusOK || firstOut["text"] != fake.text {
		t.Fatalf("holder %d %v", firstCode, firstOut)
	}

	thirdCode, thirdOut := callHandleSTT(app, context.Background(), pcm)
	if thirdCode != http.StatusOK || thirdOut["text"] != fake.text {
		t.Fatalf("third %d %v", thirdCode, thirdOut)
	}
	if fake.calls.Load() != 2 {
		t.Fatalf("whisper calls %d", fake.calls.Load())
	}
}

func TestVoiceGateIsPerUser(t *testing.T) {
	var g voiceGate
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	if !g.allow("ada", 1, now) || g.allow("ada", 1, now.Add(time.Second)) {
		t.Fatal("ada limit")
	}
	if !g.allow("bea", 1, now.Add(time.Second)) {
		t.Fatal("bea should have her own window")
	}
	if g.allow("ada", 1, now.Add(time.Hour)) == false && g.allow("ada", 1, now.Add(time.Hour+time.Second)) == false {
		t.Fatal("window did not slide")
	}
}

func TestWhisperHalfConfigRefusesStart(t *testing.T) {
	_, err := New(config.Config{
		DataDir: t.TempDir(), BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", WhisperBin: "/opt/whisper-cli",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "WHISPER_BIN") {
		t.Fatalf("err %v", err)
	}
}

func TestPolicyOverridesVoiceAndTLSOnApp(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.toml")
	body := `
[daemon]
tls_self_signed = false

[voice]
enabled = true
bin = "/policy/whisper-cli"
model = "/policy/model.bin"
max_audio_seconds = 15
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLS_SELF_SIGNED", "1")
	t.Setenv("TLS_CERT", "/env/cert.pem")
	t.Setenv("TLS_KEY", "/env/key.pem")
	t.Setenv("WHISPER_BIN", "/env/whisper")
	t.Setenv("WHISPER_MODEL", "/env/model")
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: path,
		TLSCert: "/env/cert.pem", TLSKey: "/env/key.pem", TLSSelfSigned: true,
		WhisperBin: "/env/whisper", WhisperModel: "/env/model",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.cfg.TLSSelfSigned || app.cfg.TLSCert != "" || app.cfg.WhisperBin != "/policy/whisper-cli" || app.cfg.WhisperModel != "/policy/model.bin" {
		t.Fatalf("cfg tls %v %s whisper %s", app.cfg.TLSSelfSigned, app.cfg.TLSCert, app.cfg.WhisperBin)
	}
	if !app.policy.VoiceEnabled || app.policy.EffectiveVoiceMaxAudio() != 15 {
		t.Fatalf("voice %+v", app.policy.VoiceEnabled)
	}
}

func TestManagedTLSConflictRefusesStart(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(dir, "policy.toml")
	managed := filepath.Join(dir, "managed.toml")
	if err := os.WriteFile(local, []byte("[backend]\nbackend = \"ollama\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte("[daemon]\ntls_cert = \"/managed/cert.pem\"\ntls_key = \"/managed/key.pem\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MANAGED_POLICY", managed)
	t.Setenv("TLS_CERT", "/env/cert.pem")
	t.Setenv("TLS_KEY", "/env/key.pem")
	_, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0", OllamaURL: "http://127.0.0.1:9",
		Model: "test-model", Version: "0.1.0", PolicyPath: local,
		TLSCert: "/env/cert.pem", TLSKey: "/env/key.pem",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "TLS_CERT") {
		t.Fatalf("err %v", err)
	}
}
