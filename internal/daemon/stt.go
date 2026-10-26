package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const sttSampleRate = 16000

// sttBusyWait is how long a request waits for the single transcription
// before the handler returns 429. It is not the 60s transcription deadline.
const sttBusyWait = 2 * time.Second

// sttBusyMsg is the 429 when that wait elapses. The hourly cap uses a
// different sentence, speech recognition rate limit exceeded.
const sttBusyMsg = "speech recognition is busy"

// sttWaitEndedMsg is the body for a wait aborted by the request context.
// The status is 408 Request Timeout. 499 is not a registered code, so a
// client disconnect and the 60s deadline use 408 while the request is queued.
const sttWaitEndedMsg = "speech recognition request ended"

// errSTTUnavailable is a missing binary, a missing model, or no configuration.
// The handler answers 503. It is never a reason to call another service.
var errSTTUnavailable = errors.New("speech recognition is not available")

// STT transcribes 16 kHz mono 16-bit little-endian PCM with a local whisper.cpp.
type STT interface {
	Transcribe(ctx context.Context, pcm []byte) (string, error)
}

// WhisperCLI shells out to a local whisper-cli. A missing binary or model
// is an error. There is no remote fallback.
type WhisperCLI struct {
	Bin   string
	Model string
}

func (w WhisperCLI) Transcribe(ctx context.Context, pcm []byte) (string, error) {
	if w.Bin == "" || w.Model == "" {
		return "", fmt.Errorf("%w (WHISPER_BIN and WHISPER_MODEL are not set)", errSTTUnavailable)
	}
	if _, err := os.Stat(w.Bin); err != nil {
		return "", fmt.Errorf("%w: whisper binary not found at %s", errSTTUnavailable, w.Bin)
	}
	if _, err := os.Stat(w.Model); err != nil {
		return "", fmt.Errorf("%w: whisper model not found at %s", errSTTUnavailable, w.Model)
	}
	dir, err := os.MkdirTemp("", "lgb-stt-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	wav := filepath.Join(dir, "in.wav")
	if err := writeWAV(wav, pcm, sttSampleRate); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "out")
	cmd := exec.CommandContext(ctx, w.Bin,
		"-m", w.Model, "-f", wav, "-l", "en",
		"-np", "-nt", "--no-timestamps", "-of", out, "-otxt")
	if _, err := cmd.CombinedOutput(); err != nil {
		return "", errors.New("speech recognition failed")
	}
	b, err := os.ReadFile(out + ".txt")
	if err != nil {
		return "", errors.New("speech recognition failed")
	}
	return strings.TrimSpace(string(b)), nil
}

func writeWAV(path string, pcm []byte, rate int) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	h := make([]byte, 44)
	copy(h[0:], "RIFF")
	binary.LittleEndian.PutUint32(h[4:], uint32(36+len(pcm)))
	copy(h[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(h[16:], 16)
	binary.LittleEndian.PutUint16(h[20:], 1)
	binary.LittleEndian.PutUint16(h[22:], 1)
	binary.LittleEndian.PutUint32(h[24:], uint32(rate))
	binary.LittleEndian.PutUint32(h[28:], uint32(rate*2))
	binary.LittleEndian.PutUint16(h[32:], 2)
	binary.LittleEndian.PutUint16(h[34:], 16)
	copy(h[36:], "data")
	binary.LittleEndian.PutUint32(h[40:], uint32(len(pcm)))
	if _, err := f.Write(h); err != nil {
		return err
	}
	_, err = f.Write(pcm)
	return err
}

// sttFromConfig builds the transcriber from WHISPER_BIN and WHISPER_MODEL.
// Both empty is unconfigured. One set refuses to start.
func sttFromConfig(bin, model string) (STT, error) {
	if bin == "" && model == "" {
		return nil, nil
	}
	if bin == "" || model == "" {
		return nil, errors.New("WHISPER_BIN and WHISPER_MODEL must be set together")
	}
	return WhisperCLI{Bin: bin, Model: model}, nil
}

// voiceGate is a per-user sliding window of one hour.
type voiceGate struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (g *voiceGate) allow(user string, limit int, now time.Time) bool {
	if limit <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hits == nil {
		g.hits = map[string][]time.Time{}
	}
	cut := now.Add(-time.Hour)
	var kept []time.Time
	for _, ts := range g.hits[user] {
		if ts.After(cut) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= limit {
		g.hits[user] = kept
		return false
	}
	g.hits[user] = append(kept, now)
	return true
}

func (a *App) voiceNow() time.Time { return time.Now() }

func pcmDuration(n int) time.Duration {
	return time.Duration(n/2) * time.Second / sttSampleRate
}

func (a *App) requestActor(r *http.Request) string {
	presented, ok := presentedAuth(r)
	if !ok || !a.tokensConfigured() {
		if !a.tokensConfigured() {
			return "anonymous"
		}
		return ""
	}
	name, match := matchNamedToken(presented, a.configuredTokens())
	if !match {
		return ""
	}
	return name
}

// auditSTT records who, size, duration, and the HTTP result. It never records
// the transcript or the audio.
func (a *App) auditSTT(who string, n int, dur time.Duration, code int, haveDur bool) {
	detail := map[string]any{
		"who":   who,
		"bytes": n,
		"code":  code,
	}
	if haveDur {
		detail["duration_ms"] = dur.Milliseconds()
	}
	a.log("", "stt", detail)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"action": "stt"}
		for k, v := range detail {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
}

func (a *App) handleSTT(w http.ResponseWriter, r *http.Request) {
	pol := a.voicePolicy()
	who := a.requestActor(r)
	if !pol.enabled {
		a.auditSTT(who, 0, 0, http.StatusForbidden, false)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "speech recognition is disabled"})
		return
	}
	if !a.voiceHits.allow(who, pol.perHour, a.voiceNow()) {
		a.auditSTT(who, 0, 0, http.StatusTooManyRequests, false)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "speech recognition rate limit exceeded"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, pol.body)
	pcm, err := io.ReadAll(r.Body)
	if err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			a.auditSTT(who, len(pcm), 0, http.StatusRequestEntityTooLarge, false)
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "audio too large"})
			return
		}
		a.auditSTT(who, len(pcm), 0, http.StatusBadRequest, false)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not read audio"})
		return
	}
	if len(pcm) < 2 || len(pcm)%2 != 0 {
		a.auditSTT(who, len(pcm), 0, http.StatusBadRequest, false)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be 16 kHz mono 16-bit PCM"})
		return
	}
	dur := pcmDuration(len(pcm))
	maxDur := time.Duration(pol.audio) * time.Second
	if dur > maxDur {
		a.auditSTT(who, len(pcm), dur, http.StatusRequestEntityTooLarge, true)
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "audio longer than the configured limit"})
		return
	}
	if a.stt == nil {
		a.auditSTT(who, len(pcm), dur, http.StatusServiceUnavailable, true)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "speech recognition is not available on this daemon (WHISPER_BIN and WHISPER_MODEL are not set)",
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	release, waitCode := a.acquireSTT(ctx)
	if release == nil {
		msg := sttBusyMsg
		if waitCode == http.StatusRequestTimeout {
			msg = sttWaitEndedMsg
		}
		a.auditSTT(who, len(pcm), dur, waitCode, true)
		writeJSON(w, waitCode, map[string]string{"error": msg})
		return
	}
	defer release()
	text, err := a.stt.Transcribe(ctx, pcm)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, errSTTUnavailable) {
			code = http.StatusServiceUnavailable
		}
		a.auditSTT(who, len(pcm), dur, code, true)
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	a.auditSTT(who, len(pcm), dur, http.StatusOK, true)
	writeJSON(w, http.StatusOK, map[string]any{"text": text})
}

// sttSem returns the capacity-1 transcription slot.
func (a *App) sttSem() chan struct{} {
	a.sttSlotOnce.Do(func() {
		if a.sttSlot == nil {
			a.sttSlot = make(chan struct{}, 1)
		}
	})
	return a.sttSlot
}

// armSTTBusy starts the busy-wait timer. Tests set sttBusyTimer so the
// channel is already fired, or so the test closes it, without sleeping.
func (a *App) armSTTBusy() (<-chan time.Time, func()) {
	if a != nil && a.sttBusyTimer != nil {
		return a.sttBusyTimer(sttBusyWait)
	}
	t := time.NewTimer(sttBusyWait)
	return t.C, func() { t.Stop() }
}

// acquireSTT takes the single transcription slot.
// release is nil when the slot was not taken: 429 if the busy wait elapsed
// while another transcription held it, or 408 if ctx ended first.
// A nil release means the caller must not call whisper and must not release.
func (a *App) acquireSTT(ctx context.Context) (release func(), code int) {
	slot := a.sttSem()
	wait, stop := a.armSTTBusy()
	if stop == nil {
		stop = func() {}
	}
	select {
	case slot <- struct{}{}:
		stop()
		return func() { <-slot }, 0
	case <-ctx.Done():
		stop()
		return nil, http.StatusRequestTimeout
	case <-wait:
		stop()
		return nil, http.StatusTooManyRequests
	}
}

func (a *App) voicePolicy() policySnap {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	return policySnap{
		enabled: a.policy.VoiceEnabled,
		audio:   a.policy.EffectiveVoiceMaxAudio(),
		body:    a.policy.EffectiveVoiceMaxBody(),
		perHour: a.policy.EffectiveVoiceMaxPerHour(),
	}
}

// policySnap is the voice limits for one request. It is a copy so the
// handler does not hold the policy lock while whisper runs.
type policySnap struct {
	enabled bool
	audio   int
	body    int64
	perHour int
}
