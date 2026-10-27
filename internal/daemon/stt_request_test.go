package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func callSTT(app *App, ctx context.Context, body io.Reader, hdr func(*http.Request)) (int, map[string]any, string) {
	if ctx == nil {
		ctx = context.Background()
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/stt", body)
	req = req.WithContext(ctx)
	req.Host = "127.0.0.1:8787"
	req.Header.Set("Authorization", "Bearer voice-test-token")
	req.Header.Set("Content-Type", "application/octet-stream")
	if hdr != nil {
		hdr(req)
	}
	rec := httptest.NewRecorder()
	app.handleSTT(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func TestSTTContentTypeAndSite(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	pcm := bytes.NewReader(make([]byte, 3200))

	code, out, raw := callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), func(r *http.Request) {
		r.Header.Del("Content-Type")
	})
	if code != http.StatusUnsupportedMediaType {
		t.Fatalf("type %d %v", code, out)
	}
	logs := sttLogText(t, app)
	if !strings.Contains(logs, `"code":415`) || !strings.Contains(logs, `"who":"default"`) || strings.Contains(logs, sttPhrase) {
		t.Fatalf("audit %s", logs)
	}

	code, out, raw = callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	})
	if code != http.StatusForbidden || out["error"] != "forbidden" {
		t.Fatalf("site %d %v", code, out)
	}
	if strings.Contains(raw, dir) {
		t.Fatalf("path in body %s", raw)
	}
	logs = sttLogText(t, app)
	if !strings.Contains(logs, `"code":403`) || strings.Contains(logs, sttPhrase) {
		t.Fatalf("audit %s", logs)
	}

	code, out, _ = callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), func(r *http.Request) {
		r.Header.Set("Origin", "http://127.0.0.2:8787")
	})
	if code != http.StatusForbidden || out["error"] != "forbidden" {
		t.Fatalf("origin %d %v", code, out)
	}

	code, out, _ = callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), func(r *http.Request) {
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Origin", "http://127.0.0.1:8787")
	})
	if code != http.StatusForbidden || out["error"] != "forbidden" {
		t.Fatalf("scheme %d %v", code, out)
	}

	code, out, _ = callSTT(app, nil, pcm, func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Origin", "http://127.0.0.1:8787")
	})
	if code != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("same origin %d %v", code, out)
	}

	code, out, _ = callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "none")
	})
	if code != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("none %d %v", code, out)
	}
}

func TestSTTMissingPathStaysOutOfResponse(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(dir, "model.bin")
	if err := os.WriteFile(model, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing-bin")
	app := newVoiceApp(t, voicePolicy(true, missing, model, 240, 1<<20, 60))
	code, out, raw := callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), nil)
	if code != http.StatusServiceUnavailable || out["error"] != errSTTUnavailable.Error() {
		t.Fatalf("status %d %v", code, out)
	}
	if strings.Contains(raw, missing) || strings.Contains(raw, "missing-bin") || strings.Contains(raw, dir) {
		t.Fatalf("path in body %s", raw)
	}
	warn := voiceWarnings(t, app)
	if !strings.Contains(warn, missing) || !strings.Contains(warn, "voice.bin") {
		t.Fatalf("log %q", warn)
	}
}

func TestSTTPartialSkipsQuota(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 1))
	pcm := make([]byte, 3200)
	partial := func(r *http.Request) { r.Header.Set("X-STT-Partial", "1") }
	for i := 0; i < 3; i++ {
		code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), partial)
		if code != http.StatusOK || out["text"] != sttPhrase {
			t.Fatalf("partial %d %v", code, out)
		}
	}
	if n := len(app.voiceHits.hits["default"]); n != 0 {
		t.Fatalf("partials counted %d", n)
	}
	code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), nil)
	if code != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("final %d %v", code, out)
	}
	if n := len(app.voiceHits.hits["default"]); n != 1 {
		t.Fatalf("final counted %d", n)
	}
	code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), nil)
	if code != http.StatusTooManyRequests || out["error"] != "speech recognition rate limit exceeded" || out["reason"] != "limit" {
		t.Fatalf("limit %d %v", code, out)
	}
	code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), partial)
	if code != http.StatusTooManyRequests || out["reason"] != "limit" {
		t.Fatalf("partial over limit %d %v", code, out)
	}
	if n := len(app.voiceHits.hits["default"]); n != 1 {
		t.Fatalf("over-limit counted %d", n)
	}

	busy := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	busy.sttSlot = make(chan struct{}, 1)
	busy.sttSlot <- struct{}{}
	busy.sttBusyTimer = func(time.Duration) (<-chan time.Time, func()) {
		ch := make(chan time.Time)
		close(ch)
		return ch, func() {}
	}
	code, out, _ = callSTT(busy, nil, bytes.NewReader(pcm), partial)
	if code != http.StatusTooManyRequests || out["reason"] != "busy" {
		t.Fatalf("busy %d %v", code, out)
	}
}

func TestSTTQuotaSkipsRejected(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	pcm := make([]byte, 3200)

	t.Run("bad body", func(t *testing.T) {
		app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 2))
		for i := 0; i < 2; i++ {
			code, _, _ := callSTT(app, nil, bytes.NewReader([]byte{1}), nil)
			if code != http.StatusBadRequest {
				t.Fatalf("bad %d", code)
			}
		}
		for i := 0; i < 2; i++ {
			code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), nil)
			if code != http.StatusOK || out["text"] != sttPhrase {
				t.Fatalf("ok %d %v", code, out)
			}
		}
		code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusTooManyRequests || out["error"] != "speech recognition rate limit exceeded" {
			t.Fatalf("limit %d %v", code, out)
		}
	})

	t.Run("too large", func(t *testing.T) {
		app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 64, 2))
		for i := 0; i < 2; i++ {
			code, _, _ := callSTT(app, nil, bytes.NewReader(make([]byte, 128)), nil)
			if code != http.StatusRequestEntityTooLarge {
				t.Fatalf("large %d", code)
			}
		}
		small := make([]byte, 32)
		for i := 0; i < 2; i++ {
			code, out, _ := callSTT(app, nil, bytes.NewReader(small), nil)
			if code != http.StatusOK || out["text"] != sttPhrase {
				t.Fatalf("after large %d %v", code, out)
			}
		}
	})

	t.Run("type and site", func(t *testing.T) {
		app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 2))
		for i := 0; i < 2; i++ {
			code, _, _ := callSTT(app, nil, bytes.NewReader(pcm), func(r *http.Request) {
				r.Header.Del("Content-Type")
			})
			if code != http.StatusUnsupportedMediaType {
				t.Fatalf("type %d", code)
			}
			code, _, _ = callSTT(app, nil, bytes.NewReader(pcm), func(r *http.Request) {
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			})
			if code != http.StatusForbidden {
				t.Fatalf("site %d", code)
			}
		}
		for i := 0; i < 2; i++ {
			code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), nil)
			if code != http.StatusOK {
				t.Fatalf("ok %d %v", code, out)
			}
		}
	})

	t.Run("busy", func(t *testing.T) {
		app, fake, release := newBlockingVoice(t)
		app.rtMu.Lock()
		app.editPol(func(p *policy.Policy) { p.VoiceMaxPerHour = 2 })
		app.editPol(func(p *policy.Policy) { p.VoiceMaxPerHourSet = true })
		app.rtMu.Unlock()
		var arms atomic.Int32
		idle := make(chan time.Time)
		fired := firedSTTWait()
		app.sttBusyTimer = func(time.Duration) (<-chan time.Time, func()) {
			if arms.Add(1) == 1 {
				return idle, func() {}
			}
			return fired, func() {}
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			callSTT(app, nil, bytes.NewReader(pcm), nil)
		}()
		defer func() {
			release()
			wg.Wait()
		}()
		<-fake.entered
		code, out, _ := callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusTooManyRequests || out["error"] != sttBusyMsg {
			t.Fatalf("busy %d %v", code, out)
		}
		release()
		wg.Wait()
		code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusOK {
			t.Fatalf("after busy %d %v", code, out)
		}
		code, out, _ = callSTT(app, nil, bytes.NewReader(pcm), nil)
		if code != http.StatusTooManyRequests || out["error"] != "speech recognition rate limit exceeded" {
			t.Fatalf("limit %d %v", code, out)
		}
	})
}

func TestSTTReadDeadline(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 1))
	app.sttReadTimeout = 50 * time.Millisecond
	srv := serve(t, app)
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/stt", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer voice-test-token")
	req.Header.Set("Content-Type", "application/octet-stream")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status %d %s", res.StatusCode, raw)
	}
	logs := sttLogText(t, app)
	if !strings.Contains(logs, `"code":408`) || !strings.Contains(logs, `"who":"default"`) || strings.Contains(logs, sttPhrase) {
		t.Fatalf("audit %s", logs)
	}
	ok, out := postSTT(t, srv.URL, "voice-test-token", make([]byte, 3200))
	if ok.StatusCode != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("after deadline %d %v", ok.StatusCode, out)
	}
}

func TestSTTBodyReadBound(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	var n atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	app.sttBodyHold = func() {
		if n.Add(1) == 2 {
			close(entered)
		}
		<-release
	}
	pcm := make([]byte, 3200)
	var wg sync.WaitGroup
	wg.Add(3)
	for i := 0; i < 3; i++ {
		go func() {
			defer wg.Done()
			callSTT(app, nil, bytes.NewReader(pcm), nil)
		}()
	}
	<-entered
	if got := n.Load(); got != 2 {
		t.Fatalf("holders %d", got)
	}
	close(release)
	wg.Wait()
	if got := n.Load(); got != 3 {
		t.Fatalf("readers %d", got)
	}
}

func TestSTTRateLimitDoesNotReadBody(t *testing.T) {
	dir := t.TempDir()
	bin, model := writeWhisperScript(t, dir)
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 1))
	code, out, _ := callSTT(app, nil, bytes.NewReader(make([]byte, 3200)), nil)
	if code != http.StatusOK || out["text"] != sttPhrase {
		t.Fatalf("first %d %v", code, out)
	}
	var saw atomic.Bool
	body := readFlag{saw: &saw}
	code, out, _ = callSTT(app, nil, &body, nil)
	if code != http.StatusTooManyRequests || out["error"] != "speech recognition rate limit exceeded" {
		t.Fatalf("limit %d %v", code, out)
	}
	if saw.Load() {
		t.Fatal("rate limit read the body")
	}
}

type readFlag struct {
	saw *atomic.Bool
}

func (r *readFlag) Read(p []byte) (int, error) {
	r.saw.Store(true)
	return 0, io.EOF
}
