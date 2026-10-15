package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type fakeSTT struct{ got int }

func (f *fakeSTT) Transcribe(_ context.Context, pcm []byte) (string, error) {
	f.got = len(pcm)
	return "hello world", nil
}

func postPCM(t *testing.T, url, token string, body []byte) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/api/stt", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func TestSTTFailsClosedWhenUnconfigured(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	res, out := postPCM(t, srv.URL, "", make([]byte, 3200))
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(out["error"].(string), "not available") {
		t.Fatalf("%d %v", res.StatusCode, out)
	}
	if _, err := sttFromConfig("/bin/whisper", ""); err == nil {
		t.Fatal("half config must error")
	}
}

func TestSTTTranscribesAuditsAndCaps(t *testing.T) {
	app := newApp(t, "", nil)
	f := &fakeSTT{}
	app.stt = f
	app.cfg.AuthToken = "tok"
	srv := serve(t, app)
	if res, _ := postPCM(t, srv.URL, "", make([]byte, 3200)); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", res.StatusCode)
	}
	res, out := postPCM(t, srv.URL, "tok", make([]byte, 32000))
	if res.StatusCode != 200 || out["text"] != "hello world" || f.got != 32000 {
		t.Fatalf("%d %v %d", res.StatusCode, out, f.got)
	}
	if res, _ := postPCM(t, srv.URL, "tok", make([]byte, 3)); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("odd bytes: %d", res.StatusCode)
	}
	if res, _ := postPCM(t, srv.URL, "tok", make([]byte, sttMaxBytes+2)); res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("too big: %d", res.StatusCode)
	}
	n, err := app.st.LogCount("stt")
	if err != nil || n != 1 {
		t.Fatalf("stt audit count %d %v", n, err)
	}
}

func TestSTTPartialDoesNotQueue(t *testing.T) {
	app := newApp(t, "", nil)
	app.stt = &fakeSTT{}
	srv := serve(t, app)
	sttQ <- struct{}{}
	defer func() { <-sttQ }()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/stt", bytes.NewReader(make([]byte, 3200)))
	req.Header.Set("X-STT-Partial", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("partial while busy = %d", res.StatusCode)
	}
}
