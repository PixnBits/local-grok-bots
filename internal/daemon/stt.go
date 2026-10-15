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
	"time"
)

// STT limits. Audio is transcribed and discarded; nothing is written to disk.
const (
	sttMaxBytes    = 8 << 20 // ~4 min of 16 kHz mono 16-bit PCM
	sttMaxDuration = 4 * time.Minute
	sttSampleRate  = 16000
	sttTimeout     = 60 * time.Second
)

// STT transcribes 16 kHz mono 16-bit little-endian PCM with a local whisper.cpp.
type STT interface {
	Transcribe(ctx context.Context, pcm []byte) (string, error)
}

// WhisperCLI shells out to whisper-cli. Fail closed: a missing binary or model
// is an error the caller reports, never a silent empty result.
type WhisperCLI struct {
	Bin   string
	Model string
}

func (w WhisperCLI) Transcribe(ctx context.Context, pcm []byte) (string, error) {
	if w.Bin == "" || w.Model == "" {
		return "", errors.New("speech recognition not configured (set WHISPER_BIN and WHISPER_MODEL)")
	}
	if _, err := os.Stat(w.Bin); err != nil {
		return "", fmt.Errorf("whisper binary not found at %s", w.Bin)
	}
	if _, err := os.Stat(w.Model); err != nil {
		return "", fmt.Errorf("whisper model not found at %s", w.Model)
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
	if b, err := cmd.CombinedOutput(); err != nil {
		tail := string(b)
		if len(tail) > 300 {
			tail = tail[len(tail)-300:]
		}
		return "", fmt.Errorf("whisper failed: %v: %s", err, strings.TrimSpace(tail))
	}
	b, err := os.ReadFile(out + ".txt")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeWAV(path string, pcm []byte, rate int) error {
	f, err := os.Create(path)
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
// Both empty disables the endpoint with a clear message; one set is an error
// so a half-configured daemon fails closed instead of serving HTTP 200 blanks.
func sttFromConfig(bin, model string) (STT, error) {
	if bin == "" && model == "" {
		return nil, nil
	}
	if bin == "" || model == "" {
		return nil, errors.New("WHISPER_BIN and WHISPER_MODEL must be set together")
	}
	return WhisperCLI{Bin: bin, Model: model}, nil
}

var (
	sttQ = make(chan struct{}, 1) // one transcription at a time; the GPU is shared
)

func (a *App) handleSTTStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"available": a.stt != nil, "engine": sttEngine(a.stt)})
}

func sttEngine(s STT) string {
	if s == nil {
		return "none"
	}
	if w, ok := s.(WhisperCLI); ok {
		return "whisper.cpp " + filepath.Base(w.Model)
	}
	return "whisper"
}

// handleSTT transcribes one utterance. Body is raw PCM s16le 16 kHz mono.
// The audio is not stored; the audit log records only sizes and the outcome.
func (a *App) handleSTT(w http.ResponseWriter, r *http.Request) {
	if a.stt == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "speech recognition is not available on this daemon (WHISPER_BIN and WHISPER_MODEL are not set)"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, sttMaxBytes+1)
	pcm, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "audio too large (max 8 MB, about 4 minutes)"})
		return
	}
	if len(pcm) < 2 || len(pcm)%2 != 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be 16 kHz mono 16-bit PCM"})
		return
	}
	dur := time.Duration(len(pcm)/2) * time.Second / sttSampleRate
	if dur > sttMaxDuration {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "audio longer than 4 minutes"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sttTimeout)
	defer cancel()
	// Partial (live preview) requests never queue behind real work.
	if r.Header.Get("X-STT-Partial") == "1" {
		select {
		case sttQ <- struct{}{}:
			defer func() { <-sttQ }()
		default:
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "busy"})
			return
		}
	} else {
		select {
		case sttQ <- struct{}{}:
			defer func() { <-sttQ }()
		case <-ctx.Done():
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "speech recognition is busy"})
			return
		}
	}
	start := time.Now()
	text, err := a.stt.Transcribe(ctx, pcm)
	took := time.Since(start).Milliseconds()
	detail := map[string]any{"partial": r.Header.Get("X-STT-Partial") == "1", "bytes": len(pcm), "duration_ms": dur.Milliseconds(), "took_ms": took, "ok": err == nil}
	if err != nil {
		detail["error"] = err.Error()
	} else {
		detail["chars"] = len(text)
	}
	_ = a.st.AddLog("", "stt", detail)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "stt"}
		for k, v := range detail {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"text": text, "took_ms": took})
}
