package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestShellPushThenSleepIsCapped(t *testing.T) {
	for _, bin := range []string{"git", "bwrap", "gcc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is required")
		}
	}
	prevCap := shellRunCap
	prevHook := gitPushHook
	t.Cleanup(func() {
		shellRunCap = prevCap
		gitPushHook = prevHook
	})

	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
	var hits atomic.Int32
	gitPushHook = func(context.Context, store.Bot, string, []string) sandbox.PushResult {
		hits.Add(1)
		return sandbox.PushResult{Code: 0, Stdout: "git push sent\n"}
	}
	// The first jail in this process compiles the cached bridges. That work
	// shares the shell cap, so warm it before the shortened cap is installed.
	shellRunCap = 120 * time.Second
	warmCtx, warmCancel := context.WithTimeout(t.Context(), 3*time.Minute)
	out, err := app.dispatchTool(warmCtx, bot, "run_shell", map[string]any{
		"command": "git push https://github.com/acme/widgets.git feature; true",
	})
	warmCancel()
	if err != nil || hits.Load() != 1 || !strings.Contains(out, "git push sent") {
		t.Fatalf("warm: hits=%d err=%v\n%s", hits.Load(), err, out)
	}

	const capD = 15 * time.Second
	shellRunCap = capD
	const sleepFor = 50 * time.Second
	pushCmd := "git push https://github.com/acme/widgets.git feature"

	run := func(t *testing.T, command string) (string, error, time.Duration) {
		t.Helper()
		hits.Store(0)
		start := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
		defer cancel()
		got, runErr := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": command})
		return got, runErr, time.Since(start)
	}

	t.Run("success then sleep", func(t *testing.T) {
		gitPushHook = func(context.Context, store.Bot, string, []string) sandbox.PushResult {
			hits.Add(1)
			return sandbox.PushResult{Code: 0, Stdout: "git push sent\n"}
		}
		got, runErr, elapsed := run(t, pushCmd+"; sleep 50; echo SLEPT")
		if hits.Load() != 1 {
			t.Fatalf("push hook calls=%d elapsed=%s\n%s", hits.Load(), elapsed, got)
		}
		if runErr == nil || !(strings.Contains(runErr.Error(), "shell timed out") || strings.Contains(runErr.Error(), "stopped after")) {
			t.Fatalf("err=%v elapsed=%s\n%s", runErr, elapsed, got)
		}
		if strings.Contains(got, "SLEPT") || strings.Contains(runErr.Error(), "SLEPT") {
			t.Fatalf("sleep finished after the push: elapsed=%s\n%s", elapsed, got)
		}
		if !strings.Contains(got, "git push sent") {
			t.Fatalf("push output missing: %s", got)
		}
		if elapsed >= capD+12*time.Second || elapsed >= sleepFor {
			t.Fatalf("slept for %s, cap %s", elapsed, capD)
		}
	})

	t.Run("denied then sleep", func(t *testing.T) {
		gitPushHook = func(context.Context, store.Bot, string, []string) sandbox.PushResult {
			hits.Add(1)
			return sandbox.PushResult{Code: 1, Stderr: "git push denied: no\n"}
		}
		got, runErr, elapsed := run(t, pushCmd+"; sleep 50; echo SLEPT")
		if hits.Load() != 1 {
			t.Fatalf("push hook calls=%d elapsed=%s\n%s", hits.Load(), elapsed, got)
		}
		if runErr == nil || !(strings.Contains(runErr.Error(), "shell timed out") || strings.Contains(runErr.Error(), "stopped after")) {
			t.Fatalf("err=%v elapsed=%s\n%s", runErr, elapsed, got)
		}
		if strings.Contains(got, "SLEPT") || !strings.Contains(got, "git push denied: no") {
			t.Fatalf("denied-then-sleep output elapsed=%s\n%s", elapsed, got)
		}
		if elapsed >= capD+12*time.Second || elapsed >= sleepFor {
			t.Fatalf("slept for %s, cap %s", elapsed, capD)
		}
	})

	t.Run("slow push is not capped", func(t *testing.T) {
		slow := capD + 8*time.Second
		var cancelled atomic.Bool
		gitPushHook = func(ctx context.Context, _ store.Bot, _ string, _ []string) sandbox.PushResult {
			hits.Add(1)
			select {
			case <-time.After(slow):
				return sandbox.PushResult{Code: 0, Stdout: "git push sent\n"}
			case <-ctx.Done():
				cancelled.Store(true)
				return sandbox.PushResult{Code: 1, Stderr: "git push denied: cancelled\n"}
			}
		}
		got, runErr, elapsed := run(t, pushCmd+"; echo AFTER_PUSH")
		if cancelled.Load() || hits.Load() != 1 {
			t.Fatalf("push cancelled=%v hits=%d elapsed=%s\n%s", cancelled.Load(), hits.Load(), elapsed, got)
		}
		if runErr != nil || strings.Contains(got, "shell timed out") || strings.Contains(got, "stopped after") || strings.Contains(got, "cancelled") {
			t.Fatalf("err=%v elapsed=%s\n%s", runErr, elapsed, got)
		}
		if !strings.Contains(got, "git push sent") || !strings.Contains(got, "AFTER_PUSH") {
			t.Fatalf("slow push output elapsed=%s\n%s", elapsed, got)
		}
		if elapsed < slow-time.Second {
			t.Fatalf("push returned early: %s", elapsed)
		}
	})

	t.Run("slow push then sleep is capped", func(t *testing.T) {
		slow := capD + 8*time.Second
		var cancelled atomic.Bool
		gitPushHook = func(ctx context.Context, _ store.Bot, _ string, _ []string) sandbox.PushResult {
			hits.Add(1)
			select {
			case <-time.After(slow):
				return sandbox.PushResult{Code: 0, Stdout: "git push sent\n"}
			case <-ctx.Done():
				cancelled.Store(true)
				return sandbox.PushResult{Code: 1, Stderr: "git push denied: cancelled\n"}
			}
		}
		got, runErr, elapsed := run(t, pushCmd+"; sleep 50; echo SLEPT")
		if hits.Load() != 1 || cancelled.Load() {
			t.Fatalf("push cancelled=%v hits=%d elapsed=%s\n%s", cancelled.Load(), hits.Load(), elapsed, got)
		}
		if runErr == nil || !(strings.Contains(runErr.Error(), "shell timed out") || strings.Contains(runErr.Error(), "stopped after")) {
			t.Fatalf("err=%v elapsed=%s\n%s", runErr, elapsed, got)
		}
		if !strings.Contains(got, "git push sent") {
			t.Fatalf("push output missing: elapsed=%s\n%s", elapsed, got)
		}
		if strings.Contains(got, "SLEPT") || strings.Contains(runErr.Error(), "SLEPT") {
			t.Fatalf("sleep finished after the push: elapsed=%s\n%s", elapsed, got)
		}
		if elapsed >= slow+capD+12*time.Second || elapsed >= sleepFor+slow {
			t.Fatalf("slept for %s, cap %s slow %s", elapsed, capD, slow)
		}
	})

	t.Run("background push does not extend the shell", func(t *testing.T) {
		slow := capD + 8*time.Second
		var cancelled atomic.Bool
		gitPushHook = func(ctx context.Context, _ store.Bot, _ string, _ []string) sandbox.PushResult {
			hits.Add(1)
			select {
			case <-time.After(slow):
				return sandbox.PushResult{Code: 0, Stdout: "git push sent\n"}
			case <-ctx.Done():
				cancelled.Store(true)
				return sandbox.PushResult{Code: 1, Stderr: "git push denied: cancelled\n"}
			}
		}
		// One tick per second in the bot workspace. Trim has to stop this loop
		// at the shell cap while the push is still pending. The post-push
		// re-arm would otherwise keep writing until about slow+capD.
		got, runErr, elapsed := run(t, pushCmd+" & i=0; while [ $i -lt 50 ]; do i=$((i+1)); echo $i > bgtick; sleep 1; done; echo SLEPT")
		if cancelled.Load() || hits.Load() != 1 {
			t.Fatalf("push cancelled=%v hits=%d elapsed=%s\n%s\n%v", cancelled.Load(), hits.Load(), elapsed, got, runErr)
		}
		if strings.Contains(got, "SLEPT") || (runErr != nil && strings.Contains(runErr.Error(), "SLEPT")) {
			t.Fatalf("sleep finished: elapsed=%s err=%v\n%s", elapsed, runErr, got)
		}
		if elapsed >= 40*time.Second || elapsed >= sleepFor {
			t.Fatalf("ran for %s, cap %s", elapsed, capD)
		}
		raw, err := os.ReadFile(filepath.Join(app.botWorkspace(bot.ID), "bgtick"))
		if err != nil {
			t.Fatalf("bgtick: %v elapsed=%s", err, elapsed)
		}
		tick, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatalf("bgtick %q: %v", raw, err)
		}
		if time.Duration(tick)*time.Second > capD+3*time.Second {
			t.Fatalf("background work ran past the cap: tick=%d elapsed=%s cap=%s", tick, elapsed, capD)
		}
		if elapsed >= slow+5*time.Second {
			t.Fatalf("shell outlived the push: elapsed=%s slow=%s cap=%s", elapsed, slow, capD)
		}
	})
}
