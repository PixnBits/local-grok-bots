package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
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
// before the handler returns 429. It is not the transcription deadline.
const sttBusyWait = 2 * time.Second

const (
	sttTranscribeTimeout = 60 * time.Second
	sttReadTimeout       = 30 * time.Second
	sttWaitDelay         = 2 * time.Second
	sttBodySlots         = 2
)

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

// sttMissingError is a missing binary or model. Error text stays generic.
// Path is for the daemon log.
type sttMissingError struct {
	Key  string
	Path string
}

func (e *sttMissingError) Error() string { return errSTTUnavailable.Error() }

func (e *sttMissingError) Unwrap() error { return errSTTUnavailable }

// WhisperCLI shells out to a local whisper-cli. A missing binary or model
// is an error. There is no remote fallback.
type WhisperCLI struct {
	Bin       string
	Model     string
	BinKey    string
	ModelKey  string
	WaitDelay time.Duration
}

func (w WhisperCLI) binKey() string {
	if w.BinKey != "" {
		return w.BinKey
	}
	return "WHISPER_BIN"
}

func (w WhisperCLI) modelKey() string {
	if w.ModelKey != "" {
		return w.ModelKey
	}
	return "WHISPER_MODEL"
}

func (w WhisperCLI) waitDelay() time.Duration {
	if w.WaitDelay > 0 {
		return w.WaitDelay
	}
	return sttWaitDelay
}

func (w WhisperCLI) Transcribe(ctx context.Context, pcm []byte) (string, error) {
	if w.Bin == "" || w.Model == "" {
		return "", errSTTUnavailable
	}
	if _, err := os.Lstat(w.Bin); err != nil {
		return "", &sttMissingError{Key: w.binKey(), Path: w.Bin}
	}
	if _, err := os.Lstat(w.Model); err != nil {
		return "", &sttMissingError{Key: w.modelKey(), Path: w.Model}
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
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.WaitDelay = w.waitDelay()
	configureWhisperProc(cmd)
	if err := cmd.Run(); err != nil {
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

// voiceHit is one provisional or accepted request in the rolling hour.
type voiceHit struct {
	at time.Time
	id uint64
}

// voiceGate is a per-user sliding window of one hour.
// begin reserves a slot. finish drops it when the request is not accepted.
type voiceGate struct {
	mu   sync.Mutex
	hits map[string][]voiceHit
	next uint64
}

func (g *voiceGate) allow(user string, limit int, now time.Time) bool {
	_, ok := g.begin(user, limit, now)
	return ok
}

func (g *voiceGate) begin(user string, limit int, now time.Time) (uint64, bool) {
	if limit <= 0 {
		return 0, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hits == nil {
		g.hits = map[string][]voiceHit{}
	}
	kept := g.kept(user, now)
	if len(kept) >= limit {
		g.hits[user] = kept
		return 0, false
	}
	g.next++
	id := g.next
	g.hits[user] = append(kept, voiceHit{at: now, id: id})
	return id, true
}

func (g *voiceGate) finish(user string, id uint64, accept bool) {
	if accept || id == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	src := g.hits[user]
	kept := make([]voiceHit, 0, len(src))
	for _, h := range src {
		if h.id != id {
			kept = append(kept, h)
		}
	}
	g.hits[user] = kept
}

func (g *voiceGate) kept(user string, now time.Time) []voiceHit {
	cut := now.Add(-time.Hour)
	var kept []voiceHit
	for _, h := range g.hits[user] {
		if h.at.After(cut) {
			kept = append(kept, h)
		}
	}
	return kept
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

func sttContentTypeOK(r *http.Request) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && strings.EqualFold(media, "application/octet-stream")
}

// sttCrossSite is true when the browser says the request came from another
// site, or when Origin is not this listener's own scheme and host.
func sttCrossSite(r *http.Request) bool {
	if site := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); site != "" {
		if !strings.EqualFold(site, "same-origin") && !strings.EqualFold(site, "none") {
			return true
		}
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return origin != scheme+"://"+host
}

func sttTimedOut(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (a *App) readTimeout() time.Duration {
	if a != nil && a.sttReadTimeout > 0 {
		return a.sttReadTimeout
	}
	return sttReadTimeout
}

func (a *App) transcribeTimeout() time.Duration {
	if a != nil && a.sttTranscribeTimeout > 0 {
		return a.sttTranscribeTimeout
	}
	return sttTranscribeTimeout
}

func (a *App) handleSTT(w http.ResponseWriter, r *http.Request) {
	pol := a.voicePolicy()
	who := a.requestActor(r)
	if !pol.enabled {
		a.auditSTT(who, 0, 0, http.StatusForbidden, false)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "speech recognition is disabled"})
		return
	}
	if !sttContentTypeOK(r) {
		a.auditSTT(who, 0, 0, http.StatusUnsupportedMediaType, false)
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content type must be application/octet-stream"})
		return
	}
	if sttCrossSite(r) {
		a.auditSTT(who, 0, 0, http.StatusForbidden, false)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	id, ok := a.voiceHits.begin(who, pol.perHour, a.voiceNow())
	if !ok {
		a.auditSTT(who, 0, 0, http.StatusTooManyRequests, false)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "speech recognition rate limit exceeded"})
		return
	}
	accepted := false
	defer func() { a.voiceHits.finish(who, id, accepted) }()

	releaseBody, waitCode := a.acquireBody(r.Context())
	if releaseBody == nil {
		a.auditSTT(who, 0, 0, waitCode, false)
		writeJSON(w, waitCode, map[string]string{"error": sttWaitEndedMsg})
		return
	}
	defer releaseBody()
	if a.sttBodyHold != nil {
		a.sttBodyHold()
	}
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(a.readTimeout())); err != nil && !errors.Is(err, http.ErrNotSupported) {
		a.auditSTT(who, 0, 0, http.StatusRequestTimeout, false)
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": sttWaitEndedMsg})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, pol.body)
	pcm, err := io.ReadAll(r.Body)
	releaseBody()
	if err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			a.auditSTT(who, len(pcm), 0, http.StatusRequestEntityTooLarge, false)
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "audio too large"})
			return
		}
		if sttTimedOut(err) {
			a.auditSTT(who, len(pcm), 0, http.StatusRequestTimeout, false)
			writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": sttWaitEndedMsg})
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
	a.rtMu.Lock()
	stt := a.stt
	a.rtMu.Unlock()
	if stt == nil {
		accepted = true
		a.auditSTT(who, len(pcm), dur, http.StatusServiceUnavailable, true)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": errSTTUnavailable.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.transcribeTimeout())
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
	accepted = true
	text, err := stt.Transcribe(ctx, pcm)
	if err != nil {
		code := http.StatusBadGateway
		msg := "speech recognition failed"
		if errors.Is(err, errSTTUnavailable) {
			code = http.StatusServiceUnavailable
			msg = errSTTUnavailable.Error()
		}
		var miss *sttMissingError
		if errors.As(err, &miss) && miss.Path != "" {
			a.log("", "voice_path", map[string]any{"warning": miss.Key + " " + miss.Path})
		}
		a.auditSTT(who, len(pcm), dur, code, true)
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	a.auditSTT(who, len(pcm), dur, http.StatusOK, true)
	writeJSON(w, http.StatusOK, map[string]any{"text": text})
}

// sttBodySem is the body-read bound. The buffer starts empty.
func (a *App) sttBodySem() chan struct{} {
	a.sttBodyOnce.Do(func() {
		if a.sttBody == nil {
			a.sttBody = make(chan struct{}, sttBodySlots)
		}
	})
	return a.sttBody
}

// acquireBody takes one body-read slot.
// release is nil when ctx ended first. The status is then 408.
func (a *App) acquireBody(ctx context.Context) (release func(), code int) {
	slot := a.sttBodySem()
	select {
	case slot <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-slot }) }, 0
	case <-ctx.Done():
		return nil, http.StatusRequestTimeout
	}
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
		enabled: a.policy.VoiceEnabled && a.voiceBlock == "",
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
