//go:build unix

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWhisperProcessGroupEnds(t *testing.T) {
	t.Run("deadline releases slot", func(t *testing.T) {
		app, child := blockingWhisperApp(t)
		w := app.stt.(WhisperCLI)
		w.WaitDelay = 150 * time.Millisecond
		app.rtMu.Lock()
		app.stt = w
		app.rtMu.Unlock()
		app.sttTranscribeTimeout = 150 * time.Millisecond
		start := time.Now()
		code, _, _ := callSTT(app, context.Background(), bytesReader(make([]byte, 3200)), nil)
		elapsed := time.Since(start)
		if code == 0 {
			t.Fatal("no status")
		}
		limit := app.transcribeTimeout() + w.waitDelay() + 3*time.Second
		if elapsed > limit {
			t.Fatalf("returned in %s, limit %s, code %d", elapsed, limit, code)
		}
		if pid := readPID(child); pid > 1 && !waitESRCH(pid, 2*time.Second) {
			t.Fatalf("child %d still running", pid)
		}
		app.sttBusyTimer = func(time.Duration) (<-chan time.Time, func()) {
			return make(chan time.Time), func() {}
		}
		slotCtx, slotCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer slotCancel()
		rel, waitCode := app.acquireSTT(slotCtx)
		if rel == nil {
			t.Fatalf("slot busy %d", waitCode)
		}
		rel()
	})

	t.Run("cancel stops child", func(t *testing.T) {
		app, child := blockingWhisperApp(t)
		w := app.stt.(WhisperCLI)
		w.WaitDelay = 200 * time.Millisecond
		app.rtMu.Lock()
		app.stt = w
		app.rtMu.Unlock()
		app.sttTranscribeTimeout = 5 * time.Second
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		done := make(chan struct{})
		go func() {
			defer close(done)
			callSTT(app, ctx, bytesReader(make([]byte, 3200)), nil)
		}()
		pid := waitPIDFile(t, child, 2*time.Second)
		cancel()
		if !waitESRCH(pid, 2*time.Second) {
			t.Fatalf("child %d still running", pid)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("request still running")
		}
	})
}

func blockingWhisperApp(t *testing.T) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "child.pid")
	parent := filepath.Join(dir, "parent.pid")
	bin := filepath.Join(dir, "whisper-cli")
	model := filepath.Join(dir, "model.bin")
	script := "#!/bin/sh\necho $$ > " + shQuote(parent) + "\nsleep 300 &\necho $! > " + shQuote(child) + "\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(model, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { killOwned(parent, true); killOwned(child, false) })
	app := newVoiceApp(t, voicePolicy(true, bin, model, 240, 1<<20, 60))
	return app, child
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func bytesReader(b []byte) *strings.Reader {
	return strings.NewReader(string(b))
}

func readPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0
	}
	return pid
}

func waitPIDFile(t *testing.T, path string, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if pid := readPID(path); pid > 1 {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid file %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitESRCH(pid int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func ownedProc(pid int) bool {
	if pid <= 1 {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "whisper-cli") || strings.Contains(s, "sleep")
}

func killOwned(path string, group bool) {
	pid := readPID(path)
	if !ownedProc(pid) {
		return
	}
	if group {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
