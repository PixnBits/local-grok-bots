package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
	"golang.org/x/sys/unix"
)

const (
	maxJobsPerBot = 2
	maxJobsTotal  = 4
	// maxJobLog is the background log cap. Further bytes are discarded.
	maxJobLog = 64 << 20
)

// jobLifetimeOverride replaces the policy lifetime in tests. Zero uses policy.
var jobLifetimeOverride time.Duration

func (a *App) jobLifetime(bot store.Bot) time.Duration {
	if jobLifetimeOverride > 0 {
		return jobLifetimeOverride
	}
	if a == nil {
		return policy.DefaultJobLifetime
	}
	d := a.effPol(bot.ID).EffectiveJobLifetime()
	if d <= 0 {
		return policy.DefaultJobLifetime
	}
	return d
}

// jobSink buffers shell output until the command is adopted, then appends
// to the log file up to maxJobLog. Write never returns an error, so a full
// log does not stall the process.
type jobSink struct {
	mu        sync.Mutex
	pending   []byte
	file      *os.File
	written   int64
	truncated bool
	adopted   bool
}

func (s *jobSink) Write(p []byte) (int, error) {
	if s == nil || len(p) == 0 {
		return len(p), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.adopted {
		room := maxJobLog - int64(len(s.pending))
		if room > 0 {
			n := int(room)
			if n > len(p) {
				n = len(p)
			}
			s.pending = append(s.pending, p[:n]...)
			if n < len(p) {
				s.truncated = true
			}
		} else {
			s.truncated = true
		}
		return len(p), nil
	}
	s.writeFile(p)
	return len(p), nil
}

func (s *jobSink) writeFile(p []byte) {
	if s.file == nil {
		s.truncated = true
		return
	}
	for len(p) > 0 && s.written < maxJobLog {
		room := maxJobLog - s.written
		chunk := p
		if int64(len(chunk)) > room {
			chunk = chunk[:room]
		}
		n, err := s.file.Write(chunk)
		if n > 0 {
			s.written += int64(n)
			p = p[n:]
		}
		if err != nil || n == 0 {
			s.truncated = true
			return
		}
	}
	if len(p) > 0 {
		s.truncated = true
	}
}

// Adopt flushes the buffered prefix into f and switches later writes to it.
func (s *jobSink) Adopt(f *os.File) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.file = f
	s.adopted = true
	if len(s.pending) > 0 {
		buf := s.pending
		s.pending = nil
		s.writeFile(buf)
	}
}

func (s *jobSink) truncatedNow() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.truncated
}

func (s *jobSink) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}

func jobLogRel(id string) string {
	return ".lgb/jobs/" + id + ".log"
}

func jobRunningText(id, logPath string) string {
	return fmt.Sprintf("running in the background\njob_id: %s\nlog: %s\n", id, logPath)
}

func jobWakeLine(id, status, logPath string, exit *int, truncated bool) string {
	head := fmt.Sprintf("[job] %s %s", id, status)
	if status == store.JobExited && exit != nil {
		head = fmt.Sprintf("[job] %s exited %d", id, *exit)
	}
	line := head + "\nThe log is at " + logPath
	if truncated {
		line += "\nThe log was truncated."
	}
	return line
}

// openJobLog creates .lgb/jobs/<id>.log inside the bot workspace.
// Symlink path components are refused. The file mode is 0640.
func openJobLog(root, id string) (*os.File, error) {
	if root == "" || id == "" || strings.Contains(id, "/") || strings.Contains(id, `\`) || strings.Contains(id, "..") {
		return nil, errors.New("invalid job log")
	}
	if err := mkdirDurable(root, ".lgb"); err != nil {
		return nil, err
	}
	if err := mkdirDurable(filepath.Join(root, ".lgb"), "jobs"); err != nil {
		return nil, err
	}
	full := filepath.Join(root, ".lgb", "jobs", id+".log")
	fd, err := unix.Open(full, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o640)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), full)
	if err := f.Chmod(0o640); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func mkdirDurable(parent, name string) error {
	st, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("refusing %s", parent)
	}
	dir := filepath.Join(parent, name)
	st, err = os.Lstat(dir)
	if err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("refusing %s", dir)
		}
		return os.Chmod(dir, 0o750)
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		return err
	}
	return os.Chmod(dir, 0o750)
}

// shellJobCtx is stored on the shell context. adopted is set once the
// command is a background job, so a later broker ask does not use the
// foreground prompt timeout.
type shellJobCtx struct {
	id      string
	adopted atomic.Bool
}

type shellJobKey struct{}

func withShellJob(ctx context.Context, job *shellJobCtx) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, shellJobKey{}, job)
}

func shellJobFrom(ctx context.Context) *shellJobCtx {
	if ctx == nil {
		return nil
	}
	job, _ := ctx.Value(shellJobKey{}).(*shellJobCtx)
	return job
}

func (a *App) shellIsJob(ctx context.Context) (string, bool) {
	job := shellJobFrom(ctx)
	if job == nil || !job.adopted.Load() || job.id == "" {
		return "", false
	}
	return job.id, true
}

type liveJob struct {
	id      string
	botID   string
	pgid    int
	logPath string
	shellWS string
	sink    *jobSink
	lease   *shellLease
	timer   *time.Timer
	cancel  context.CancelFunc

	mu  sync.Mutex
	why string
}

func (j *liveJob) claim(why string) bool {
	if j == nil || why == "" {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.why != "" {
		return false
	}
	j.why = why
	return true
}

func (j *liveJob) reason() string {
	if j == nil {
		return ""
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.why
}

func (a *App) addLive(j *liveJob) {
	a.jobsMu.Lock()
	if a.jobs == nil {
		a.jobs = map[string]*liveJob{}
	}
	a.jobs[j.id] = j
	a.jobsMu.Unlock()
}

func (a *App) takeLive(id string) *liveJob {
	a.jobsMu.Lock()
	defer a.jobsMu.Unlock()
	return a.jobs[id]
}

func (a *App) dropLive(id string) {
	a.jobsMu.Lock()
	delete(a.jobs, id)
	a.jobsMu.Unlock()
}

func (a *App) reconcileLostJobs() error {
	if a == nil || a.st == nil {
		return nil
	}
	lost, err := a.st.MarkLostJobs(func(j store.Job) string {
		return jobWakeLine(j.ID, j.Status, j.LogPath, j.ExitCode, false)
	})
	if err != nil {
		return err
	}
	for _, j := range lost {
		a.noteScheduledTurn(j.BotID)
	}
	return nil
}

func (a *App) reserveJob(bot store.Bot, id, command, logPath string) error {
	return a.st.InsertRunningJob(store.Job{
		ID: id, BotID: bot.ID, Command: command, LogPath: logPath, Status: store.JobRunning,
	}, maxJobsPerBot, maxJobsTotal)
}

func (a *App) dropReserved(reserved bool, id string, err error) {
	if !reserved || a == nil || a.st == nil || id == "" {
		return
	}
	if err != nil && strings.Contains(err.Error(), "shell sandbox:") {
		_, _ = a.st.FinishJob(id, store.JobError, nil, "start")
		return
	}
	_ = a.st.DeleteRunningJob(id)
}

func (a *App) finishJob(j *liveJob, out shellOut) {
	if j == nil {
		return
	}
	if j.timer != nil {
		j.timer.Stop()
	}
	why := j.reason()
	status := store.JobExited
	var code *int
	switch why {
	case store.JobStopped:
		status = store.JobStopped
	case store.JobExpired:
		status = store.JobExpired
	default:
		if a.isClosing() || (a.ctx != nil && a.ctx.Err() != nil) {
			status = store.JobLost
			why = store.JobLost
		} else {
			n := 0
			if out.err != nil {
				if parsed, ok := exitFromShell(out.err); ok {
					n = parsed
				} else {
					status = store.JobError
					why = "error"
				}
			}
			if status == store.JobExited {
				code = &n
			}
		}
	}
	truncated := j.sink.truncatedNow()
	j.sink.close()
	if a.st != nil {
		_, _ = a.st.FinishJob(j.id, status, code, why)
	}
	a.recordSandboxEvents(j.botID, out.res.Events)
	if out.err == nil && status == store.JobExited {
		a.commitShellPlan(j.botID, j.shellWS)
	} else {
		a.clearShellPlan(j.botID)
	}
	a.dropLive(j.id)
	if a.st != nil && status != store.JobError {
		_, _ = a.st.AddMessage(store.Message{
			BotID: j.botID, Thread: "user", Role: "system",
			Content: jobWakeLine(j.id, status, j.logPath, code, truncated),
		})
		if !a.isClosing() {
			a.noteScheduledTurn(j.botID)
			a.kick(j.botID)
		}
	}
	if j.lease != nil {
		j.lease.release()
	}
}

func exitFromShell(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "exit ") {
		return 0, false
	}
	var code int
	n, conv := fmt.Sscanf(msg, "exit %d", &code)
	if conv != nil || n != 1 {
		return 0, false
	}
	return code, true
}

func (a *App) isClosing() bool {
	if a == nil {
		return false
	}
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	return a.closing
}

func (a *App) toolStopJob(bot store.Bot, args map[string]any) (string, error) {
	raw, exists := args["id"]
	if !exists || raw == nil {
		return "", errors.New("stop_job: missing required \"id\" field")
	}
	id, ok := raw.(string)
	if !ok {
		return "", errors.New("stop_job: \"id\" must be a string")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", errors.New("stop_job: missing required \"id\" field")
	}
	job, err := a.st.GetJob(id)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("stop_job: unknown job %s", id)
	}
	if err != nil {
		return "", err
	}
	if job.BotID != bot.ID {
		return "", fmt.Errorf("stop_job: job %s belongs to another bot", id)
	}
	if job.Status != store.JobRunning {
		return "", fmt.Errorf("stop_job: job %s is %s", id, job.Status)
	}
	live := a.takeLive(id)
	if live == nil {
		return "", fmt.Errorf("stop_job: job %s is not running", id)
	}
	if !live.claim(store.JobStopped) {
		return "", fmt.Errorf("stop_job: job %s is %s", id, live.reason())
	}
	if live.timer != nil {
		live.timer.Stop()
	}
	if live.pgid > 0 {
		_ = syscall.Kill(-live.pgid, syscall.SIGKILL)
	}
	if live.cancel != nil {
		live.cancel()
	}
	return "stopped\njob_id: " + id + "\n", nil
}

// askJobStep blocks on a native approval card that does not expire with the
// approval TTL. Approve returns nil. Deny, or the job context ending,
// returns an error the command can handle.
func (a *App) askJobStep(ctx context.Context, bot store.Bot, jobID, tool string, input json.RawMessage) error {
	if a == nil || a.broker == nil {
		return errors.New("denied")
	}
	if jobID == "" {
		return errors.New("denied")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ws := a.botWorkspace(bot.ID)
	repos := a.effPol(bot.ID).EffectiveGitHubRepos(bot.GitHubAllow)
	a.broker.SetBotContext(bot.ID, ws, repos)
	userHome, _ := os.UserHomeDir()
	cliHome := ""
	if a.ws != "" {
		cliHome = filepath.Join(filepath.Dir(a.ws), "cli", bot.ID, "home")
	}
	a.broker.EnsureBotHomes(bot.ID, cliHome, userHome)
	a.broker.SnapshotBot(bot.ID)
	d := a.broker.Evaluate(ctx, permbroker.Request{
		BotID:     bot.ID,
		SessionID: "job:" + jobID,
		RunID:     a.loopRunID(bot.ID),
		Cwd:       ws,
		Workspace: ws,
		Repos:     repos,
		ToolName:  tool,
		ToolInput: input,
		Origin:    permbroker.OriginNative,
		Sticky:    true,
	})
	if d.Verdict == permbroker.VerdictAllow {
		return nil
	}
	if d.PendingID == "" {
		if d.Reason == "" {
			return errors.New("denied")
		}
		return errors.New(d.Reason)
	}
	ch := make(chan error, 1)
	a.jobsMu.Lock()
	if early, ok := a.jobEarly[d.PendingID]; ok {
		delete(a.jobEarly, d.PendingID)
		a.jobsMu.Unlock()
		return early
	}
	if a.jobWait == nil {
		a.jobWait = map[string]chan error{}
	}
	a.jobWait[d.PendingID] = ch
	a.jobsMu.Unlock()
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		a.jobsMu.Lock()
		delete(a.jobWait, d.PendingID)
		a.jobsMu.Unlock()
		_ = a.broker.Decide(d.PendingID, "deny", "")
		return errors.New("denied")
	}
}

// deliverJobDecision unblocks askJobStep. A pending id that is not a job
// step returns false so the checkpoint resume path still runs.
func (a *App) deliverJobDecision(id, decision string) bool {
	return a.finishJobDecision(id, decision, false)
}

// finishJobDecision delivers decision to a waiting job step. When remember
// is set and the waiter is not published yet, the decision is kept until
// askJobStep looks for it. A nil stored error is an approval.
func (a *App) finishJobDecision(id, decision string, remember bool) bool {
	if a == nil || id == "" {
		return false
	}
	var err error
	if decision != "approve" {
		err = errors.New("denied")
	}
	a.jobsMu.Lock()
	ch := a.jobWait[id]
	if ch != nil {
		delete(a.jobWait, id)
		a.jobsMu.Unlock()
		select {
		case ch <- err:
		default:
		}
		return true
	}
	if !remember {
		a.jobsMu.Unlock()
		return false
	}
	if a.jobEarly == nil {
		a.jobEarly = map[string]error{}
	}
	a.jobEarly[id] = err
	a.jobsMu.Unlock()
	return true
}
