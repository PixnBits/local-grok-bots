package daemon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func quietModel() fakeModel {
	return fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "ok"}, nil
	}}
}

func jobBot(t *testing.T, app *App, name string) store.Bot {
	t.Helper()
	bot, err := app.st.CreateBot(name, "stay", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	return bot
}

func jobIDFrom(out string) string {
	const prefix = "job_id: "
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func jobLogPath(app *App, botID, id string) string {
	return filepath.Join(app.botWorkspace(botID), ".lgb", "jobs", id+".log")
}

func readJobLog(t *testing.T, app *App, botID, id string) string {
	t.Helper()
	b, err := os.ReadFile(jobLogPath(app, botID, id))
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	return string(b)
}

func waitJobDone(t *testing.T, app *App, id string) store.Job {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var job store.Job
	var err error
	for time.Now().Before(deadline) {
		job, err = app.st.GetJob(id)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status != store.JobRunning {
			return job
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s still %s", id, job.Status)
	return job
}

func stopJobAndWait(t *testing.T, app *App, bot store.Bot, id string) store.Job {
	t.Helper()
	out, err := app.dispatchTool(context.Background(), bot, "stop_job", map[string]any{"id": id})
	if err != nil {
		t.Fatalf("stop: %v %s", err, out)
	}
	if !strings.Contains(out, "stopped") || !strings.Contains(out, id) {
		t.Fatalf("stop output %q", out)
	}
	return waitJobDone(t, app, id)
}

func stopIfRunning(app *App, bot store.Bot, id string) {
	if app == nil || app.st == nil || id == "" {
		return
	}
	job, err := app.st.GetJob(id)
	if err != nil || job.Status != store.JobRunning {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = app.dispatchTool(ctx, bot, "stop_job", map[string]any{"id": id})
}

func warmShell(t *testing.T, app *App, bot store.Bot) {
	t.Helper()
	prev := shellRunCap
	shellRunCap = 120 * time.Second
	defer func() { shellRunCap = prev }()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	out, err := app.dispatchTool(ctx, bot, "run_shell", map[string]any{"command": "true"})
	if err != nil || strings.Contains(out, "running in the background") || strings.Contains(out, "job_id:") {
		t.Fatalf("warm: %v\n%s", err, out)
	}
}

func runShell(t *testing.T, app *App, bot store.Bot, args map[string]any) (string, error, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	start := time.Now()
	out, err := app.dispatchTool(ctx, bot, "run_shell", args)
	return out, err, time.Since(start)
}

func waitLog(t *testing.T, app *App, botID, id, needle string) string {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last string
	var err error
	for time.Now().Before(deadline) {
		var b []byte
		b, err = os.ReadFile(jobLogPath(app, botID, id))
		if err == nil {
			last = string(b)
			if strings.Contains(last, needle) {
				return last
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("log missing %q: %v\n%s", needle, err, last)
	return last
}

func userJobLine(t *testing.T, app *App, botID, id string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		msgs, err := app.st.ListMessages(botID, "user", "", 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range msgs {
			if m.Role == "system" && strings.HasPrefix(m.Content, "[job] ") && strings.Contains(m.Content, id) {
				return m.Content
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no [job] message for %s", id)
	return ""
}

func waitJobCard(t *testing.T, app *App, botID, id string) permbroker.Pending {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	want := "job:" + id
	for time.Now().Before(deadline) {
		for _, item := range app.broker.ListPending() {
			if item.SessionID == want {
				return item
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	log := ""
	if b, err := os.ReadFile(jobLogPath(app, botID, id)); err == nil {
		log = string(b)
	}
	job, _ := app.st.GetJob(id)
	t.Fatalf("no card for %s status %s\n%s", id, job.Status, log)
	return permbroker.Pending{}
}

func TestJobBookkeeping(t *testing.T) {
	msg := store.Message{Role: "system", Content: "[job] abc exited 0\nThe log is at .lgb/jobs/abc.log"}
	got := mapHist(msg, nil)
	if got.Role != "user" || got.Content != msg.Content {
		t.Fatalf("mapHist %+v", got)
	}
	plain := mapHist(store.Message{Role: "system", Content: "check the oven"}, nil)
	if plain.Role != "user" || plain.Content != "[scheduled] check the oven" {
		t.Fatalf("scheduled %+v", plain)
	}

	app := newApp(t, "", quietModel())
	bot := jobBot(t, app, "Book")
	_, err := app.dispatchTool(context.Background(), bot, "run_shell", map[string]any{
		"command": "true", "background": "yes",
	})
	if err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("background type: %v", err)
	}
	_, err = app.dispatchTool(context.Background(), bot, "stop_job", map[string]any{"id": "missing-job"})
	if err == nil || !strings.Contains(err.Error(), "unknown job") {
		t.Fatalf("unknown: %v", err)
	}

	other := jobBot(t, app, "Other")
	if err := app.st.InsertRunningJob(store.Job{
		ID: "other-job", BotID: other.ID, Command: "sleep 1",
		LogPath: jobLogRel("other-job"), Status: store.JobRunning,
	}, maxJobsPerBot, maxJobsTotal); err != nil {
		t.Fatal(err)
	}
	_, err = app.dispatchTool(context.Background(), bot, "stop_job", map[string]any{"id": "other-job"})
	if err == nil || !strings.Contains(err.Error(), "another bot") {
		t.Fatalf("other bot: %v", err)
	}

	if err := app.st.InsertRunningJob(store.Job{
		ID: "book-job", BotID: bot.ID, Command: "sleep 1",
		LogPath: jobLogRel("book-job"), Status: store.JobRunning,
	}, maxJobsPerBot, maxJobsTotal); err != nil {
		t.Fatal(err)
	}
	_, err = app.dispatchTool(context.Background(), bot, "stop_job", map[string]any{"id": "book-job"})
	if err == nil || !strings.Contains(err.Error(), "is not running") {
		t.Fatalf("not running: %v", err)
	}
	if _, err := app.st.FinishJob("book-job", store.JobExited, nil, ""); err != nil {
		t.Fatal(err)
	}
	_, err = app.dispatchTool(context.Background(), bot, "stop_job", map[string]any{"id": "book-job"})
	if err == nil || !strings.Contains(err.Error(), "is exited") {
		t.Fatalf("finished: %v", err)
	}

	root := t.TempDir()
	if err := os.Symlink("real", filepath.Join(root, ".lgb")); err != nil {
		t.Fatal(err)
	}
	if _, err := openJobLog(root, "abc"); err == nil {
		t.Fatal("symlink log was created")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "job.log")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	sink := &jobSink{}
	chunk := make([]byte, 1<<20)
	for i := 0; i < 65; i++ {
		n, werr := sink.Write(chunk)
		if n != len(chunk) || werr != nil {
			t.Fatalf("write %d: %d %v", i, n, werr)
		}
	}
	sink.Adopt(f)
	if !sink.truncatedNow() {
		t.Fatal("pending past the cap was kept")
	}
	n, werr := sink.Write(chunk)
	if n != len(chunk) || werr != nil {
		t.Fatalf("after adopt: %d %v", n, werr)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != maxJobLog {
		t.Fatalf("size %d want %d", st.Size(), maxJobLog)
	}
	sink.close()
}

func TestJobForegroundStillReturnsOutput(t *testing.T) {
	app := newApp(t, "", quietModel())
	bot := jobBot(t, app, "Fg")
	warmShell(t, app, bot)
	out, err, elapsed := runShell(t, app, bot, map[string]any{"command": "echo hello-fg"})
	if err != nil || !strings.Contains(out, "hello-fg") {
		t.Fatalf("err=%v elapsed=%s\n%s", err, elapsed, out)
	}
	if strings.Contains(out, "running in the background") || strings.Contains(out, "job_id:") {
		t.Fatalf("foreground became a job\n%s", out)
	}
}

func TestJobAutoBackgroundOnShellTimeout(t *testing.T) {
	app := newApp(t, "", quietModel())
	bot := jobBot(t, app, "Auto")
	warmShell(t, app, bot)
	prev := shellRunCap
	t.Cleanup(func() { shellRunCap = prev })
	shellRunCap = time.Second
	var id string
	t.Cleanup(func() { stopIfRunning(app, bot, id) })
	out, err, elapsed := runShell(t, app, bot, map[string]any{"command": "echo START; sleep 15; echo DONE"})
	if err != nil || !strings.Contains(out, "running in the background") {
		t.Fatalf("err=%v elapsed=%s\n%s", err, elapsed, out)
	}
	if elapsed >= 12*time.Second {
		t.Fatalf("waited %s for a 15s command", elapsed)
	}
	id = jobIDFrom(out)
	if id == "" || !strings.Contains(out, jobLogRel(id)) {
		t.Fatalf("output %q", out)
	}
	job, err := app.st.GetJob(id)
	if err != nil || job.Status != store.JobRunning {
		t.Fatalf("job %+v err %v", job, err)
	}
	if !strings.Contains(waitLog(t, app, bot.ID, id, "DONE"), "START") {
		t.Fatal("log missing START")
	}
	done := waitJobDone(t, app, id)
	if done.Status != store.JobExited || done.ExitCode == nil || *done.ExitCode != 0 {
		t.Fatalf("finish %+v", done)
	}
	line := userJobLine(t, app, bot.ID, id)
	if !strings.Contains(line, "exited 0") || !strings.Contains(line, jobLogRel(id)) {
		t.Fatalf("wake %q", line)
	}
	mapped := mapHist(store.Message{Role: "system", Content: line}, nil)
	if mapped.Role != "user" || mapped.Content != line || strings.Contains(mapped.Content, "[scheduled]") {
		t.Fatalf("mapped %+v", mapped)
	}
}

func TestJobBackgroundFlag(t *testing.T) {
	app := newApp(t, "", quietModel())
	bot := jobBot(t, app, "Imm")
	warmShell(t, app, bot)
	var id string
	t.Cleanup(func() { stopIfRunning(app, bot, id) })
	out, err, elapsed := runShell(t, app, bot, map[string]any{
		"command": "sleep 8; echo DONE", "background": true,
	})
	if err != nil || !strings.Contains(out, "running in the background") {
		t.Fatalf("err=%v elapsed=%s\n%s", err, elapsed, out)
	}
	if elapsed >= 6*time.Second {
		t.Fatalf("waited %s", elapsed)
	}
	id = jobIDFrom(out)
	job, err := app.st.GetJob(id)
	if err != nil || job.Status != store.JobRunning {
		t.Fatalf("job %+v err %v", job, err)
	}
	waitLog(t, app, bot.ID, id, "DONE")
	done := waitJobDone(t, app, id)
	if done.Status != store.JobExited || done.ExitCode == nil || *done.ExitCode != 0 {
		t.Fatalf("finish %+v", done)
	}
	st, err := os.Stat(jobLogPath(app, bot.ID, id))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&^os.FileMode(0o640) != 0 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	body, err := app.dispatchTool(context.Background(), bot, "read_file", map[string]any{"path": jobLogRel(id)})
	if err != nil || !strings.Contains(body, "DONE") {
		t.Fatalf("read_file %v\n%s", err, body)
	}
	line := userJobLine(t, app, bot.ID, id)
	if !strings.Contains(line, "exited 0") || !strings.Contains(line, jobLogRel(id)) {
		t.Fatalf("wake %q", line)
	}
}

func TestJobStopWakesStopped(t *testing.T) {
	app := newApp(t, "", quietModel())
	bot := jobBot(t, app, "Stop")
	warmShell(t, app, bot)
	var id string
	t.Cleanup(func() { stopIfRunning(app, bot, id) })
	out, err, _ := runShell(t, app, bot, map[string]any{"command": "sleep 30", "background": true})
	if err != nil || !strings.Contains(out, "running in the background") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	id = jobIDFrom(out)
	job := stopJobAndWait(t, app, bot, id)
	if job.Status != store.JobStopped {
		t.Fatalf("status %s", job.Status)
	}
	line := userJobLine(t, app, bot.ID, id)
	if !strings.Contains(line, "stopped") || !strings.Contains(line, jobLogRel(id)) {
		t.Fatalf("wake %q", line)
	}
}

func TestJobSlotLimits(t *testing.T) {
	app := newApp(t, "", quietModel())
	a := jobBot(t, app, "SlotA")
	b := jobBot(t, app, "SlotB")
	c := jobBot(t, app, "SlotC")
	warmShell(t, app, a)
	var running []struct {
		bot store.Bot
		id  string
	}
	t.Cleanup(func() {
		for _, item := range running {
			stopIfRunning(app, item.bot, item.id)
		}
	})
	start := func(bot store.Bot) (string, error) {
		t.Helper()
		out, err, _ := runShell(t, app, bot, map[string]any{"command": "sleep 120", "background": true})
		if err != nil {
			return out, err
		}
		id := jobIDFrom(out)
		if id == "" || !strings.Contains(out, "running in the background") {
			t.Fatalf("start %q", out)
		}
		running = append(running, struct {
			bot store.Bot
			id  string
		}{bot, id})
		return out, nil
	}
	if _, err := start(a); err != nil {
		t.Fatal(err)
	}
	if _, err := start(a); err != nil {
		t.Fatal(err)
	}
	if _, err := start(a); err == nil || !strings.Contains(err.Error(), "the limit is 2") {
		t.Fatalf("third: %v", err)
	}
	if _, err := start(b); err != nil {
		t.Fatal(err)
	}
	if _, err := start(b); err != nil {
		t.Fatal(err)
	}
	if _, err := start(c); err == nil || !strings.Contains(err.Error(), "the limit is 4") {
		t.Fatalf("fifth: %v", err)
	}
}

func TestJobLogCapInJail(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap is required")
	}
	app := newApp(t, "", quietModel())
	bot := jobBot(t, app, "Cap")
	warmShell(t, app, bot)
	var id string
	t.Cleanup(func() { stopIfRunning(app, bot, id) })
	out, err, _ := runShell(t, app, bot, map[string]any{
		"command": "head -c 68157440 /dev/zero", "background": true,
	})
	if err != nil || !strings.Contains(out, "running in the background") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	id = jobIDFrom(out)
	done := waitJobDone(t, app, id)
	st, serr := os.Stat(jobLogPath(app, bot.ID, id))
	if serr != nil {
		t.Fatal(serr)
	}
	if st.Size() != maxJobLog {
		t.Fatalf("size %d status %s", st.Size(), done.Status)
	}
	if done.Status != store.JobExited {
		t.Fatalf("status %s", done.Status)
	}
	line := userJobLine(t, app, bot.ID, id)
	if !strings.Contains(line, "truncated") {
		t.Fatalf("wake %q", line)
	}
}

func TestJobRestartMarksLost(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, quietModel())
	bot := jobBot(t, app, "Lost")
	id := "restartjob1"
	if err := app.st.InsertRunningJob(store.Job{
		ID: id, BotID: bot.ID, Command: "sleep 30",
		LogPath: jobLogRel(id), Status: store.JobRunning,
	}, maxJobsPerBot, maxJobsTotal); err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
	app2 := newApp(t, dir, quietModel())
	job, err := app2.st.GetJob(id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.JobLost || job.Reason != "daemon_restart" {
		t.Fatalf("%+v", job)
	}
	line := userJobLine(t, app2, bot.ID, id)
	if !strings.Contains(line, "job_lost") || !strings.Contains(line, jobLogRel(id)) {
		t.Fatalf("wake %q", line)
	}
}

func TestJobLifetimeExpires(t *testing.T) {
	prev := jobLifetimeOverride
	t.Cleanup(func() { jobLifetimeOverride = prev })
	jobLifetimeOverride = 2 * time.Second
	app := newApp(t, "", quietModel())
	bot := jobBot(t, app, "Life")
	warmShell(t, app, bot)
	var id string
	t.Cleanup(func() { stopIfRunning(app, bot, id) })
	start := time.Now()
	out, err, elapsed := runShell(t, app, bot, map[string]any{
		"command": "sleep 30", "background": true,
	})
	if err != nil || !strings.Contains(out, "running in the background") {
		t.Fatalf("err=%v elapsed=%s\n%s", err, elapsed, out)
	}
	id = jobIDFrom(out)
	done := waitJobDone(t, app, id)
	if done.Status != store.JobExpired {
		t.Fatalf("status %s", done.Status)
	}
	if time.Since(start) >= 20*time.Second {
		t.Fatalf("lifetime waited %s", time.Since(start))
	}
	line := userJobLine(t, app, bot.ID, id)
	if !strings.Contains(line, "expired") || !strings.Contains(line, jobLogRel(id)) {
		t.Fatalf("wake %q", line)
	}
}

func TestJobStepCardOutlivesApprovalTTL(t *testing.T) {
	for _, bin := range []string{"git", "bwrap", "gcc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is required")
		}
	}
	prevHook := gitPushHook
	t.Cleanup(func() { gitPushHook = prevHook })
	app := newApp(t, "", quietModel())
	srv := serve(t, app)
	bot := createGrantedBot(t, srv.URL, "Ada", []string{"git", "github"})
	warmShell(t, app, bot)

	start := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	var nano atomic.Int64
	nano.Store(start.UnixNano())
	app.broker.SetClock(func() time.Time { return time.Unix(0, nano.Load()).UTC() })
	t.Cleanup(func() { app.broker.SetClock(time.Now) })
	raw := json.RawMessage(`{"command":"git push"}`)
	gitPushHook = func(ctx context.Context, b store.Bot, _ string, _ []string) sandbox.PushResult {
		id, ok := app.shellIsJob(ctx)
		if !ok {
			return sandbox.PushResult{Code: 1, Stderr: "not a job\n"}
		}
		if err := app.askJobStep(ctx, b, id, "git_push", raw); err != nil {
			return sandbox.PushResult{Code: 1, Stderr: "git push denied: " + err.Error() + "\n"}
		}
		return sandbox.PushResult{Code: 0, Stdout: "git push sent\n"}
	}

	decide := func(t *testing.T, id, pending, decision string) {
		t.Helper()
		if err := app.broker.Decide(pending, decision, permbroker.ScopeOnce); err != nil {
			t.Fatal(err)
		}
		app.afterBrokerDecision(pending, decision, permbroker.PendingSnapshot{SessionID: "job:" + id})
	}

	t.Run("approve", func(t *testing.T) {
		var id string
		t.Cleanup(func() { stopIfRunning(app, bot, id) })
		out, err, _ := runShell(t, app, bot, map[string]any{
			"command":    "git push https://github.com/acme/widgets.git feature; echo AFTER_OK",
			"background": true,
		})
		if err != nil || !strings.Contains(out, "running in the background") {
			t.Fatalf("start: %v\n%s", err, out)
		}
		id = jobIDFrom(out)
		card := waitJobCard(t, app, bot.ID, id)
		nano.Store(start.Add(permbroker.DefaultApprovalTTL + time.Second).UnixNano())
		still := false
		for _, item := range app.broker.ListPending() {
			if item.ID == card.ID {
				still = true
			}
		}
		if !still {
			t.Fatal("card dropped after the approval ttl")
		}
		decide(t, id, card.ID, "approve")
		done := waitJobDone(t, app, id)
		log := readJobLog(t, app, bot.ID, id)
		if done.Status != store.JobExited || done.ExitCode == nil || *done.ExitCode != 0 || !strings.Contains(log, "git push sent") || !strings.Contains(log, "AFTER_OK") {
			t.Fatalf("job %+v\n%s", done, log)
		}
		fresh, err := app.st.GetBot(bot.ID)
		if err != nil {
			t.Fatal(err)
		}
		ws := app.botWorkspace(fresh.ID)
		again := app.broker.Evaluate(context.Background(), permbroker.Request{
			BotID: fresh.ID, SessionID: "job:" + id,
			Cwd: ws, Workspace: ws,
			Repos:     app.effPol(fresh.ID).EffectiveGitHubRepos(fresh.GitHubAllow),
			ToolName:  "git_push",
			ToolInput: raw,
			Origin:    permbroker.OriginNative,
			Sticky:    true,
		})
		if again.Verdict == permbroker.VerdictAllow || again.PendingID == "" {
			t.Fatalf("once token %+v", again)
		}
		if err := app.broker.Decide(again.PendingID, "deny", ""); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("deny", func(t *testing.T) {
		var id string
		t.Cleanup(func() { stopIfRunning(app, bot, id) })
		out, err, _ := runShell(t, app, bot, map[string]any{
			"command":    "git push https://github.com/acme/widgets.git feature; echo AFTER_DENY",
			"background": true,
		})
		if err != nil || !strings.Contains(out, "running in the background") {
			t.Fatalf("start: %v\n%s", err, out)
		}
		id = jobIDFrom(out)
		card := waitJobCard(t, app, bot.ID, id)
		nano.Store(time.Unix(0, nano.Load()).Add(permbroker.DefaultApprovalTTL + time.Second).UnixNano())
		still := false
		for _, item := range app.broker.ListPending() {
			if item.ID == card.ID {
				still = true
			}
		}
		if !still {
			t.Fatal("card dropped after the approval ttl")
		}
		decide(t, id, card.ID, "deny")
		done := waitJobDone(t, app, id)
		log := readJobLog(t, app, bot.ID, id)
		if done.Status != store.JobExited || done.ExitCode == nil || *done.ExitCode != 0 || !strings.Contains(log, "git push denied") || !strings.Contains(log, "AFTER_DENY") {
			t.Fatalf("job %+v\n%s", done, log)
		}
	})
}

func TestJobLogRefusesSymlinkToRealDir(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, ".lgb")); err != nil {
		t.Fatal(err)
	}
	if _, err := openJobLog(root, "abc"); err == nil {
		t.Fatal("log opened through a symlinked .lgb")
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatalf("wrote through the symlink: %v", ents)
	}
	root2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root2, ".lgb"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root2, ".lgb", "jobs")); err != nil {
		t.Fatal(err)
	}
	if _, err := openJobLog(root2, "abc"); err == nil {
		t.Fatal("log opened through a symlinked jobs dir")
	}
}
