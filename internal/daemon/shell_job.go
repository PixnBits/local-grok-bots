package daemon

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/id"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// shellLease owns the resources a background shell must keep after the tool
// call returns: the github proxy, the shell guard, and the job context.
type shellLease struct {
	app        *App
	botID      string
	sock       string
	px         *github.Proxy
	guard      *sandbox.ShellGuard
	cancel     context.CancelFunc
	stopTimers func()
}

func (l *shellLease) release() {
	if l == nil {
		return
	}
	if l.stopTimers != nil {
		l.stopTimers()
		l.stopTimers = nil
	}
	if l.px != nil {
		l.px.Close()
		l.px = nil
	}
	if l.app != nil && l.sock != "" {
		l.app.clearGitHubSock(l.botID, l.sock)
		l.sock = ""
	}
	if l.guard != nil {
		l.guard.Close()
		l.guard = nil
	}
	if l.cancel != nil {
		l.cancel()
		l.cancel = nil
	}
}

type shellOut struct {
	res sandbox.Result
	err error
}

func shellBackgroundArg(args map[string]any) (bool, error) {
	v, ok := args["background"]
	if !ok || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("run_shell: \"background\" must be a boolean")
	}
	return b, nil
}

// execRunShell runs a jailed command. A short command returns its output.
// background true, or the shell cap with no push in flight, keeps the
// process as a daemon child and returns a job id. The job context is the
// app context, so the tool returning does not kill it.
func (a *App) execRunShell(ctx context.Context, bot store.Bot, args map[string]any) (string, error) {
	command, err := shellCommandArg(args)
	if err != nil {
		return "", err
	}
	immediate, err := shellBackgroundArg(args)
	if err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current := bot
	if fresh, err := a.st.GetBot(bot.ID); err == nil {
		current = fresh
	}
	turnPol := a.effPol(current.ID)
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	runCtx, runCancel := context.WithCancel(parent)
	marker := &shellJobCtx{id: id.New()}
	runCtx = withShellJob(runCtx, marker)
	var state atomic.Int32
	adopted := make(chan struct{})
	var adoptedOnce sync.Once
	notifyAdopted := func() { adoptedOnce.Do(func() { close(adopted) }) }
	go func() {
		select {
		case <-ctx.Done():
			if state.CompareAndSwap(0, 2) {
				runCancel()
			}
		case <-adopted:
		case <-runCtx.Done():
		}
	}()
	shellCancel := func() {
		if state.Load() == 1 || marker.adopted.Load() {
			return
		}
		runCancel()
	}
	lease := &shellLease{app: a, botID: current.ID, cancel: runCancel}
	handed := false
	defer func() {
		if !handed {
			lease.release()
		}
	}()

	guard := &sandbox.ShellGuard{}
	lease.guard = guard
	guard.OnRefused = func(pid int, reason string) {
		a.noteShellSignalRefused(current, pid, reason)
	}
	var timerMu sync.Mutex
	var shellTimer *time.Timer
	var pushTimer *time.Timer
	var timerFired bool
	var capHeld bool
	var capMissed bool
	// capSpent means the shell cap already fired while a push was in
	// flight. The rest of the command is still capped: a later timer
	// kills it instead of adopting a background job.
	var capSpent bool
	var pushDepth int
	var pushSnips []string
	var shellStart time.Time
	var shellBudget time.Duration
	var shellLeft time.Duration
	var resumeShell func(time.Duration)
	detach := make(chan struct{})
	var detachOnce sync.Once
	signalDetach := func() { detachOnce.Do(func() { close(detach) }) }
	armShell := func(d time.Duration) {
		if shellTimer != nil {
			shellTimer.Stop()
		}
		shellStart = time.Now()
		shellBudget = d
		shellTimer = time.AfterFunc(d, func() {
			timerMu.Lock()
			timerFired = true
			depth := pushDepth
			spent := capSpent
			if depth > 0 {
				capSpent = true
			}
			timerMu.Unlock()
			if depth == 0 {
				if spent {
					shellCancel()
					return
				}
				signalDetach()
				return
			}
			if guard.Trim() {
				timerMu.Lock()
				capHeld = true
				timerMu.Unlock()
				return
			}
			timerMu.Lock()
			left := shellLeft
			ended := pushDepth == 0
			if !ended {
				capMissed = true
			}
			timerMu.Unlock()
			if ended {
				resumeShell(left)
			}
		})
	}
	resumeShell = func(left time.Duration) {
		if marker.adopted.Load() {
			return
		}
		if left <= 0 {
			shellCancel()
			return
		}
		if left < time.Second {
			left = time.Second
		}
		timerMu.Lock()
		armShell(left)
		timerMu.Unlock()
	}
	cap := a.shellCap(current)
	if !immediate {
		timerMu.Lock()
		armShell(cap)
		timerMu.Unlock()
	}
	lease.stopTimers = func() {
		timerMu.Lock()
		if shellTimer != nil {
			shellTimer.Stop()
			shellTimer = nil
		}
		if pushTimer != nil {
			pushTimer.Stop()
			pushTimer = nil
		}
		timerMu.Unlock()
	}

	ghSock := ""
	ghRepos := turnPol.EffectiveGitHubRepos(current.GitHubAllow)
	author, email, aerr := github.CommitAuthor(current.Name, turnPol.GitHub.AuthorName, turnPol.GitHub.AuthorEmail)
	if aerr != nil {
		author, email = "", ""
	}
	if granted(current.Grants, "github") {
		opened, perr := a.openGitHubProxy(current)
		if perr != nil || opened == nil {
			a.auditGitHubDecision(current, "github_proxy_denied", "", "", "deny", "proxy unavailable")
		} else {
			lease.px = opened
			ghSock = opened.Sock()
			lease.sock = ghSock
			a.noteGitHubSock(current.ID, ghSock)
		}
	}
	gate := &gitHubGate{px: lease.px}
	a.observeProtectBaseline()
	protect := a.shellProtectBot(current.ID)
	binds := a.cfg.BuildBinds
	if granted(current.Grants, "build") {
		var blocked []sandbox.Event
		binds, blocked = guardBuildBinds(protect, binds)
		for _, ev := range blocked {
			a.recordSandbox(current.ID, ev)
		}
	}
	cleanBash, gerr := a.gateShell(ctx, current, command)
	if gerr != nil {
		return "", gerr
	}
	shellWS, werr := a.shellWorkspace(current.ID)
	if werr != nil {
		a.clearShellPlan(current.ID)
		return "", werr
	}
	rel, rerr := a.shellExecRel(current.ID, shellWS)
	if rerr != nil {
		a.clearShellPlan(current.ID)
		return "", rerr
	}

	logRel := jobLogRel(marker.id)
	reserved := false
	if immediate {
		if err := a.reserveJob(current, marker.id, command, logRel); err != nil {
			return "", err
		}
		reserved = true
	}
	sink := &jobSink{}
	started := make(chan int, 1)
	done := make(chan shellOut, 1)
	goEnv := turnPol.EffectiveGoEnv()
	go func() {
		res, runErr := sandbox.Run(runCtx, sandbox.Request{
			Workspace:       shellWS,
			Command:         command,
			Chdir:           rel,
			CleanBash:       cleanBash,
			Grants:          current.Grants,
			NetAllow:        current.NetAllow,
			SSHAllow:        current.SSHAllow,
			BuildBinds:      binds,
			Protect:         protect,
			ProtectInodes:   a.protectInodes(),
			ProtectTripped:  a.protectBlockReason(),
			SSHKey:          a.sshKeyPath(),
			GitHubSock:      ghSock,
			GitHubRepos:     ghRepos,
			GitAuthor:       author,
			GitAuthorEmail:  email,
			GitAuthorRefuse: aerr != nil,
			BotGoRoot:       goRootForBot(a.cfg.DataDir, current.ID),
			GoProxy:         goEnv.Proxy,
			GoToolchain:     goEnv.Toolchain,
			GoFlags:         goEnv.Flags,
			GoSumDB:         goEnv.SumDB,
			Guard:           guard,
			Output:          sink,
			OnStart: func(pgid int) {
				if immediate {
					if state.CompareAndSwap(0, 1) {
						marker.adopted.Store(true)
					}
				}
				select {
				case started <- pgid:
				default:
				}
			},
			OnPushStart: func() {
				timerMu.Lock()
				defer timerMu.Unlock()
				if marker.adopted.Load() {
					pushDepth++
					return
				}
				if pushDepth == 0 {
					if pushTimer != nil {
						pushTimer.Stop()
					}
					d := turnPol.EffectivePromptTimeout() + 15*time.Second
					pushTimer = time.AfterFunc(d, func() {
						timerMu.Lock()
						timerFired = true
						timerMu.Unlock()
						shellCancel()
					})
					shellLeft = shellBudget - time.Since(shellStart)
				}
				pushDepth++
			},
			OnPushEnd: func() {
				timerMu.Lock()
				if pushDepth > 0 {
					pushDepth--
				}
				if pushDepth == 0 && pushTimer != nil {
					pushTimer.Stop()
					pushTimer = nil
				}
				held := capHeld && pushDepth == 0
				missed := capMissed && pushDepth == 0
				left := shellLeft
				if pushDepth == 0 {
					capMissed = false
				}
				timerMu.Unlock()
				if marker.adopted.Load() {
					return
				}
				if held {
					shellCancel()
					return
				}
				if missed {
					resumeShell(left)
				}
			},
			OnPush: func(pctx context.Context, cwd string, pushArgs []string) sandbox.PushResult {
				var res sandbox.PushResult
				if gitPushHook != nil {
					res = gitPushHook(pctx, current, cwd, pushArgs)
				} else {
					res = a.handleGitPush(pctx, ctx, current, gate, cwd, pushArgs)
				}
				if res.Stdout != "" || res.Stderr != "" {
					timerMu.Lock()
					pushSnips = append(pushSnips, res.Stdout, res.Stderr)
					timerMu.Unlock()
					if res.Stdout != "" {
						_, _ = sink.Write([]byte(res.Stdout))
					}
					if res.Stderr != "" {
						_, _ = sink.Write([]byte(res.Stderr))
					}
				}
				return res
			},
			Dial: a.shellDial,
		})
		done <- shellOut{res: res, err: runErr}
	}()

	finish := func(out shellOut) (string, error) {
		a.dropReserved(reserved, marker.id, out.err)
		timerMu.Lock()
		fired := timerFired
		snips := append([]string{}, pushSnips...)
		timerMu.Unlock()
		return a.finishShell(ctx, current, shellWS, cap, fired, snips, out.res, out.err)
	}

	var pgid int
	select {
	case pgid = <-started:
	case out := <-done:
		return finish(out)
	case <-ctx.Done():
		runCancel()
		return finish(<-done)
	}
	if immediate && state.Load() != 1 {
		runCancel()
		return finish(<-done)
	}
	if !immediate {
		select {
		case out := <-done:
			return finish(out)
		case <-detach:
			select {
			case out := <-done:
				return finish(out)
			default:
			}
		case <-ctx.Done():
			runCancel()
			return finish(<-done)
		}
		if !state.CompareAndSwap(0, 1) {
			runCancel()
			return finish(<-done)
		}
		marker.adopted.Store(true)
	}
	select {
	case out := <-done:
		return finish(out)
	default:
	}
	if !reserved {
		if err := a.reserveJob(current, marker.id, command, logRel); err != nil {
			runCancel()
			<-done
			return "", err
		}
		reserved = true
	}
	logFile, lerr := openJobLog(shellWS, marker.id)
	if lerr != nil {
		runCancel()
		<-done
		_, _ = a.st.FinishJob(marker.id, store.JobError, nil, "log")
		reserved = false
		return "", lerr
	}
	sink.Adopt(logFile)
	notifyAdopted()
	_ = a.st.SetJobPGID(marker.id, pgid)
	live := &liveJob{
		id: marker.id, botID: current.ID, pgid: pgid, logPath: logRel,
		shellWS: shellWS, sink: sink, lease: lease, cancel: runCancel,
	}
	life := a.jobLifetime(current)
	live.timer = time.AfterFunc(life, func() {
		if !live.claim(store.JobExpired) {
			return
		}
		if pgid > 0 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		runCancel()
	})
	a.addLive(live)
	handed = true
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.finishJob(live, <-done)
	}()
	return jobRunningText(marker.id, logRel), nil
}

func (a *App) finishShell(ctx context.Context, bot store.Bot, shellWS string, cap time.Duration, timerFired bool, snips []string, res sandbox.Result, err error) (string, error) {
	a.recordSandboxEvents(bot.ID, res.Events)
	summary := formatShell(res.Stdout, res.Stderr)
	for _, snip := range snips {
		if snip == "" || strings.Contains(summary, snip) {
			continue
		}
		summary += snip
		if !strings.HasSuffix(snip, "\n") {
			summary += "\n"
		}
	}
	err = adjustShellStop(ctx, timerFired, err)
	if err != nil {
		a.clearShellPlan(bot.ID)
		msg := err.Error()
		if msg == "shell timed out" {
			msg = a.shellCapMessage(bot, cap)
		}
		return summary, fmt.Errorf("%s\n%s", msg, summary)
	}
	a.commitShellPlan(bot.ID, shellWS)
	return summary, nil
}
