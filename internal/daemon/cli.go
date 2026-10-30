package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/coi"
	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/dlp"
	"github.com/PixnBits/local-grok-bots/internal/id"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func (a *App) executeCLI(ctx context.Context, bot store.Bot, runID string) {
	turnPol := a.effPol(bot.ID)
	// A previous turn must not leave the broker armed for this one.
	a.setBrokerOn(bot.ID, false)

	backend := turnPol.EffectiveBackend()
	a.takePending(runID)
	a.dropResume(bot.ID)
	defer a.clearCLIPID(bot.ID, runID)
	defer a.forgetRunPerms(runID)
	if !turnPol.AllowsBackend(backend) {
		a.failCLI(bot.ID, runID, backend, fmt.Errorf("cli backend %q is not allowed by policy", backend))
		return
	}
	// Empty is mcp. An unknown value is the same config error Load fail-closes on.
	transport, err := policy.NormClaudeTransport(turnPol.ClaudeTransport)
	if err != nil {
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	inputs, err := a.st.TurnInputs(bot.ID, runID)
	if err != nil {
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	fresh := strings.TrimSpace(bot.SessionID) == ""
	sessionID := bot.SessionID
	if fresh {
		sessionID = id.New()
		if err := a.st.SetBotSession(bot.ID, sessionID); err != nil {
			a.failCLI(bot.ID, runID, backend, err)
			return
		}
	}
	prompt, err := a.cliPrompt(bot, fresh, inputs)
	if err != nil {
		if errors.Is(err, clisession.ErrSlash) {
			a.recordACPHostFail(bot.ID, runID, "acp", nil, err.Error())
		}
		if fresh {
			a.clearBotSession(bot.ID, sessionID)
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	if err := a.screenDLP(ctx, bot.ID, runID, backend, prompt); err != nil {
		if fresh {
			a.clearBotSession(bot.ID, sessionID)
		}
		return
	}
	ws, err := cliWorkspace(a.ws, bot.ID)
	if err != nil {
		if fresh {
			a.clearBotSession(bot.ID, sessionID)
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	iso, err := a.cliIsolation(bot, backend, ws, runID)
	if err != nil {
		if fresh {
			a.clearBotSession(bot.ID, sessionID)
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	if iso != nil && iso.ReleaseGate != nil {
		defer iso.ReleaseGate()
	}
	lgb, lgbEnv, lerr := a.startLGB(ctx, bot, runID, ws)
	if lerr != nil {
		a.log(bot.ID, "lgb_unavailable", map[string]any{"run_id": runID, "error": clip(lerr.Error(), 300)})
	}
	defer lgb.stop()
	if lgbEnv != nil {
		iso.Env = withLGBEnv(iso.Env, filepath.Join(ws, lgbDirName, "bin"), lgbEnv)
	}
	turnTimeout := turnPol.EffectiveTurnTimeout()
	turnCtx, turnCancel := context.WithTimeout(ctx, turnTimeout)
	defer turnCancel()
	a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
	var runner clisession.Runner = clisession.ExecRunner{
		Policy: turnPol,
		HasTTY: a.cliTTY,
		PinLog: func(backend, path, result string) {
			a.log(bot.ID, "cli_pin", map[string]any{"backend": backend, "path": path, "result": result})
		},
	}
	if a.runner != nil {
		runner = a.runner
	}
	var streamed bool
	var redactStream audit.Stream
	var pid int
	mode := turnPol.PermissionMode
	if policy.IsBypassMode(mode) && !turnPol.ManagedBypass {
		mode = ""
	}
	spec := clisession.Spec{
		Backend: backend, SessionID: sessionID, Fresh: fresh,
		Prompt: prompt, Workspace: ws, PermissionMode: mode,
		AllowRules: append(append([]string(nil), turnPol.ToolAllow...), lgbAllow(lgbEnv)...),
		DenyRules:  append([]string(nil), turnPol.ToolDeny...),
		Isolate:    iso,
		Marker:     runID,
		OnStart: func(child int) {
			if child <= 0 {
				return
			}
			pid = child
			a.setCLIPID(bot.ID, child)
			a.noteCLIProc(bot.ID, child, runID, "")
			a.auditCLI("cli_start", backend, sessionID, child, "")
		},
	}
	if bot.Model != nil {
		spec.Model = strings.TrimSpace(*bot.Model)
	}
	// mcp attaches the HTTP prompt tool only when a UI is allowed and the
	// daemon has an HTTP base. stream_control is the host on stdin even
	// when that UI is absent; the broker still denies residual asks.
	// none, and mcp with no host, pass --permission-prompts none.
	cliDenySource := "cli"
	eventTransport := ""
	var cardDenied atomic.Bool
	permOrigin := a.mcpHostBase()
	host := strings.TrimSpace(permOrigin) != ""
	switch {
	case strings.EqualFold(backend, "grok"):
		eventTransport = policy.TransportACP
		botID := bot.ID
		spec.ACP = &clisession.ACPHooks{
			Decide: func(ctx context.Context, ask clisession.ACPAsk) (clisession.ACPDecision, error) {
				dec, err := a.decideGrokACP(ctx, botID, runID, sessionID, ask, envField(iso.Env, "GROK_HOME"))
				if dec.UserDenied {
					cardDenied.Store(true)
				}
				return dec, err
			},
			Fail: func(tool string, args map[string]any, reason string) {
				a.recordACPHostFail(botID, runID, tool, args, reason)
			},
			Note: func(kind, tool string, args map[string]any, reason string) {
				a.recordACPNote(botID, runID, kind, tool, args, reason)
			},
		}
	case !strings.EqualFold(backend, "claude"):
	case transport == policy.TransportStreamControl:
		eventTransport = policy.TransportStreamControl
		spec.StreamControl = true
		botID := bot.ID
		spec.Control = &clisession.ControlHooks{
			Decide: func(ctx context.Context, ask clisession.ControlAsk) clisession.ControlDecision {
				return a.decideStreamControl(ctx, botID, runID, sessionID, ask)
			},
			Deny: func(tool string, args map[string]any, rule string) {
				a.recordControlDeny(botID, runID, tool, args, rule)
			},
		}
	case transport == policy.TransportNone:
		spec.PermissionPrompts = "none"
		eventTransport = policy.TransportNone
		cliDenySource = cliNoHostSource(turnPol.UIPrompts)
	case turnPol.UIPrompts && host && !a.brokerHooksOn(bot.ID):
		tok := a.registerPerm(bot.ID, runID, sessionID)
		defer a.unregisterPerm(tok)
		cfgPath, werr := a.writePermMCP(bot.ID, runID, permOrigin, tok)
		if werr != nil {
			a.failCLI(bot.ID, runID, backend, werr)
			return
		}
		defer a.removePermMCP(bot.ID, runID)
		spec.MCPConfig = cfgPath
		spec.PermissionTool = permissionToolName
		eventTransport = policy.TransportMCP
		// The permission tool call blocks until the user answers. Claude's
		// MCP client must not give up before the daemon's prompt timeout.
		if iso != nil {
			ms := (turnPol.EffectivePromptTimeout() + time.Minute).Milliseconds()
			iso.Env = append(iso.Env, fmt.Sprintf("MCP_TOOL_TIMEOUT=%d", ms))
		}
	default:
		spec.PermissionPrompts = "none"
		eventTransport = policy.TransportNone
		cliDenySource = cliNoHostSource(turnPol.UIPrompts)
	}
	if err := a.armBrokerSpec(bot.ID, sessionID, runID, inputs, &spec); err != nil {
		if fresh {
			a.clearBotSession(bot.ID, sessionID)
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	a.warnGrokDarwinNetwork(bot, runID, backend)
	trace := &cliTrace{a: a, botID: bot.ID, runID: runID}
	res, err := runner.Run(turnCtx, spec, func(ev clisession.Event) {
		// Output is activity: a long turn that keeps working is not idle.
		a.touchActivity(bot.ID)
		switch ev.Kind {
		case "token":
			if ev.Text == "" {
				return
			}
			safe := redactStream.Push(ev.Text)
			if safe == "" {
				return
			}
			streamed = true
			trace.token(safe)
			a.bus.Publish(runID, "token", map[string]string{"text": safe})
		case "tool":
			name := ev.ToolName
			if name == "" {
				name = "tool"
			}
			args := ev.ToolArgs
			if args == nil {
				args = map[string]any{}
			}
			redacted := redactValue(args)
			trace.tool(name, redacted)
			a.bus.Publish(runID, "status", map[string]any{"state": name, "text": name})
			a.bus.Publish(runID, "tool_call", map[string]any{"name": name, "arguments": redacted})
			a.log(bot.ID, "tool_start", map[string]any{"name": name, "arguments": redacted})
		case "tool_result":
			name := ev.ToolName
			if name == "" {
				name = "tool"
			}
			ok := !ev.Denied && !ev.Failed
			body := ev.Text
			if ev.Denied && strings.TrimSpace(body) == "" {
				body = "denied"
			}
			trace.result(name, body, ok)
			shown := clip(audit.RedactText(body), 4000)
			payload := map[string]any{"name": name, "ok": ok, "result_or_error": shown}
			if ev.Denied {
				payload["status"] = "denied"
			} else if ev.Failed {
				payload["status"] = "error"
			}
			a.bus.Publish(runID, "tool_result", payload)
			a.log(bot.ID, "tool_end", map[string]any{"name": name, "ok": ok})
		case "permission_decision":
			a.noteCLIPermission(bot.ID, runID, ev.ToolName, ev.ToolArgs, "", cliDenySource, eventTransport)
		case "end":
			for _, d := range ev.Denials {
				a.noteCLIPermission(bot.ID, runID, d.Tool, d.Args, d.UseID, cliDenySource, eventTransport)
			}
		}
	})
	if tail := redactStream.Flush(); tail != "" {
		streamed = true
		trace.token(tail)
		a.bus.Publish(runID, "token", map[string]string{"text": tail})
	}
	if pid > 0 {
		result := "ok"
		if err != nil {
			result = "error"
			a.rtMu.Lock()
			idle := a.loops[bot.ID] != nil && a.loops[bot.ID].idleKill
			a.rtMu.Unlock()
			if idle || ctx.Err() != nil || turnCtx.Err() != nil {
				result = "interrupted"
			}
		}
		a.auditCLI("cli_stop", backend, sessionID, pid, result)
	}
	if res.SessionID != "" && res.SessionID != sessionID {
		old := sessionID
		_ = a.st.SetBotSession(bot.ID, res.SessionID)
		if a.broker != nil && old != "" {
			a.broker.CancelSession(bot.ID, old)
		}
		sessionID = res.SessionID
		a.noteBrokerTurn(bot.ID, sessionID, runID, inputs)
	}
	trace.finish()
	text := strings.TrimSpace(trace.reply(audit.RedactText(res.Text)))
	if text == "" && (err != nil || turnCtx.Err() != nil) {
		// A turn that failed or timed out has no result text. What it
		// streamed after its last tool call is still the reply so far.
		text = trace.tail()
	}
	if text != "" && !streamed {
		a.bus.Publish(runID, "token", map[string]string{"text": text})
	}
	a.log(bot.ID, "model_call", map[string]any{"model": backend, "ok": err == nil, "session_id": sessionID})
	switch {
	case a.consumeIdleKill(bot.ID):
		a.finishCLIInterrupted(bot.ID, runID, text)
	case turnCtx.Err() != nil && ctx.Err() == nil && errors.Is(turnCtx.Err(), context.DeadlineExceeded):
		if text != "" {
			a.persistBotText(bot.ID, runID, text, false)
		}
		_, _ = a.finishRun(runID, "error", "turn_timeout")
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": "turn_timeout"})
	case ctx.Err() != nil:
		if a.ctx.Err() != nil {
			a.finishCLIInterrupted(bot.ID, runID, text)
			break
		}
		if text != "" {
			a.persistBotText(bot.ID, runID, text, false)
		}
		a.finishInterrupted(bot.ID, runID, ctx)
	case errors.Is(err, clisession.ErrTruncated) || res.Interrupted:
		a.finishCLIInterrupted(bot.ID, runID, text)
	case err != nil:
		var untrusted *clisession.UntrustedConfigError
		if errors.As(err, &untrusted) {
			a.auditUntrustedConfig(bot.ID, runID, backend, "grok_home", untrusted.Names)
		}
		var refused *clisession.VersionError
		if errors.As(err, &refused) {
			a.auditVersionRefused(bot.ID, runID, backend, refused.Version)
		}
		if fresh && strings.TrimSpace(res.SessionID) == "" {
			a.clearBotSession(bot.ID, sessionID)
		}
		// A bridge that cannot be applied must not continue. A sandbox that
		// cannot be applied must not continue either. Claude's
		// failIfUnavailable exits at startup. Grok does the same for a custom
		// profile, and a built-in profile is refused before the process starts.
		var bridge *clisession.BridgeError
		if errors.As(err, &bridge) {
			a.recordBridge(bot.ID)
		} else if iso != nil && strings.TrimSpace(res.Text) == "" && cliSandboxFailed(backend, iso, err) {
			why := audit.RedactText(err.Error())
			a.recordSandboxRefusal(bot.ID, backend, why)
			if strings.EqualFold(backend, "grok") {
				err = fmt.Errorf("Grok's sandbox is required but can't run here (%s), so the turn was refused", why)
			} else {
				err = fmt.Errorf("Claude's sandbox is required but can't run here (%s), so the turn was refused. Install bubblewrap and socat on Linux, or a managed policy can set [cli.isolation] claude_sandbox = \"off\"", why)
			}
		}
		// Text the CLI wrote before it failed stays in the thread.
		if text != "" {
			a.persistBotText(bot.ID, runID, text, false)
		}
		a.failCLI(bot.ID, runID, backend, err)
	default:
		if text != "" {
			a.persistBotText(bot.ID, runID, text, false)
		}
		// A Grok card denial cancels the turn. A broker-hook denial does not:
		// the model keeps the reason and the run stays done. Other denials
		// keep the existing end state.
		if cardDenied.Load() && cancelledStop(res.StopReason) && !a.brokerHooksOn(bot.ID) {
			_, _ = a.finishRun(runID, "stopped", "stopped after denial")
			a.bus.Publish(runID, "done", map[string]any{"run_id": runID, "status": "stopped", "reason": "stopped after denial"})
			break
		}
		_, _ = a.finishRun(runID, "done", "")
		a.bus.Publish(runID, "done", map[string]any{"run_id": runID})
	}
}

func cancelledStop(reason string) bool {
	switch strings.ToLower(strings.TrimSpace(reason)) {
	case "cancelled", "canceled":
		return true
	default:
		return false
	}
}

func (a *App) finishCLIInterrupted(botID, runID, text string) {
	if strings.TrimSpace(text) != "" {
		a.persistBotText(botID, runID, text, false)
	}
	_, _ = a.finishRun(runID, "error", "interrupted")
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": "interrupted"})
}

// cliIsolation checks the workspace for CLI override files and builds the
// daemon-owned CLI environment. A file the launch cannot neutralize, or any
// file under overrides = "refuse", fails the turn closed. Each detection is
// audited.
func (a *App) cliIsolation(bot store.Bot, backend, ws, runID string) (*clisession.Isolation, error) {
	turnPol := a.effPol(bot.ID)

	botID := bot.ID
	isolated := turnPol.CLIHome != policy.HomeUser
	found := clisession.ScanOverrides(ws)
	if len(found) > 0 {
		var blocked []string
		for _, f := range found {
			if turnPol.CLIOverrides == policy.OverridesRefuse || !clisession.Neutralized(backend, f, isolated) {
				blocked = append(blocked, f)
			}
		}
		action := "ignore"
		if len(blocked) > 0 {
			action = "refuse"
		}
		fields := map[string]any{"backend": backend, "files": found, "action": action, "mode": turnPol.CLIOverrides}
		if len(blocked) > 0 {
			fields["blocked"] = blocked
		}
		a.log(botID, "cli_override", fields)
		if a.audit != nil && a.audit.Enabled() {
			rec := map[string]any{"event": "cli_override", "bot_id": botID}
			for k, v := range fields {
				rec[k] = v
			}
			a.audit.Write(rec)
		}
		if len(blocked) > 0 {
			return nil, fmt.Errorf("workspace CLI config override refused: %s", strings.Join(blocked, ", "))
		}
	}
	state := filepath.Join(filepath.Dir(a.ws), "cli", botID)
	opts := clisession.IsolationOptions{
		Backend:   backend,
		StateDir:  state,
		Workspace: ws,
		Base:      os.Environ(),
		Extra:     turnPol.CLIEnv,
		Secrets:   a.authSecrets(),
		Grants:    botGrants(bot),
		Protect:   a.secretList(bot.ID),
		CredRoot:  a.cfg.DataDir,
	}
	if strings.EqualFold(backend, "claude") && turnPol.CLIClaudeSandbox != policy.SandboxOff {
		if missing := claudeSandboxMissing(); len(missing) > 0 {
			return nil, a.sandboxUnavailable(botID, "missing "+strings.Join(missing, ", "))
		}
		opts.ClaudeSandbox = true
	}
	opts.UserHome, _ = os.UserHomeDir()
	if a.botDeleted(bot.ID) {
		return nil, fmt.Errorf("bot was deleted")
	}
	if herr := clisession.RefuseHostConfig(turnPol.CLITrustSystemConfig, clisession.HostConfigPaths); herr != nil {
		var untrusted *clisession.UntrustedConfigError
		if errors.As(herr, &untrusted) {
			a.auditUntrustedConfig(botID, runID, backend, "host", untrusted.Names)
		}
		return nil, herr
	}
	if strings.EqualFold(backend, "grok") {
		base, err := a.ensureGrokProxy(opts.UserHome)
		if err != nil {
			a.recordGrokProxy(botID, err)
			return nil, err
		}
		opts.ProxyBase = base
		if base != "" {
			if runID == "" || !coi.SafeRouteID(bot.ID) || !coi.SafeRouteID(runID) {
				a.recordGrokProxy(botID, errGrokProxy)
				return nil, errGrokProxy
			}
			gate, gerr := newProxyGate()
			if gerr != nil {
				a.recordGrokProxy(botID, errGrokProxy)
				return nil, errGrokProxy
			}
			opts.ProxyGate = gate
			opts.ProxyBase = base + "/bots/" + bot.ID + "/runs/" + runID
		}
	}
	ownHome := isolated
	if strings.EqualFold(backend, "claude") {
		// On macOS Claude's login is in the Keychain, found through the real
		// HOME and default config dir; claude_home = auto keeps both there.
		ownHome = !turnPol.ClaudeUsesUserHome(cliGOOS)
	}
	if ownHome {
		opts.Home = filepath.Join(state, "home")
	}
	if strings.EqualFold(backend, "claude") {
		hook, herr := a.prepareBrokerHook(bot, ws, opts.Home)
		if herr != nil {
			return nil, herr
		}
		opts.PermHookCommand = hook
	}
	var iso clisession.Isolation
	var err error
	if strings.EqualFold(backend, "grok") {
		a.credMu.Lock()
		if a.botDeleted(bot.ID) {
			a.credMu.Unlock()
			return nil, fmt.Errorf("bot was deleted")
		}
		iso, err = clisession.PrepareIsolation(opts)
		if err == nil && opts.ProxyGate != "" {
			iso.ReleaseGate = a.trackGrokGate(bot.ID, runID, opts.ProxyGate, opts.Grants.Net)
		}
		a.credMu.Unlock()
	} else {
		iso, err = clisession.PrepareIsolation(opts)
	}
	if errors.Is(err, clisession.ErrCredSymlink) {
		a.auditCredSymlink(bot.ID, runID)
	}
	if err != nil {
		a.setBrokerOn(bot.ID, false)
		var untrusted *clisession.UntrustedConfigError
		if errors.As(err, &untrusted) {
			a.auditUntrustedConfig(botID, runID, backend, "grok_home", untrusted.Names)
		}
		var se *clisession.SandboxError
		if errors.As(err, &se) {
			a.recordSandboxRefusal(botID, se.Backend, se.Error())
		}
		return nil, err
	}
	if strings.EqualFold(backend, "grok") && runtime.GOOS == "linux" {
		if berr := a.attachGrokBridge(&iso, bot, runID, opts.Grants); berr != nil {
			if iso.ReleaseGate != nil {
				iso.ReleaseGate()
			}
			a.recordBridge(botID)
			return nil, berr
		}
	}
	iso.Protect = append([]string(nil), opts.Protect...)
	a.noteBotProtect(botID, iso.Protect)
	if strings.EqualFold(backend, "claude") {
		if _, seen := a.loginChecked.LoadOrStore(botID, true); !seen {
			a.recordClaudeLogin(botID, ws, iso, ownHome)
		}
	}
	return &iso, nil
}

func (a *App) botDeleted(id string) bool {
	if a == nil || id == "" {
		return false
	}
	_, ok := a.goneBots.Load(id)
	return ok
}

func newProxyGate() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "lgb_" + hex.EncodeToString(buf[:]), nil
}

// gateHold is one admitted loopback secret. drop is safe to call twice.
type gateHold struct {
	drop func()
}

// trackGrokGate admits the secret and remembers it until the turn ends or
// the bot is deleted. The caller holds credMu, which is also held across
// releaseBotGates, so a delete cannot miss a secret admitted after it starts.
func (a *App) trackGrokGate(botID, runID, secret string, net bool) func() {
	if a == nil {
		return func() {}
	}
	a.grokMu.Lock()
	eg := a.grokProxy
	a.grokMu.Unlock()
	if eg == nil {
		return func() {}
	}
	release := eg.AdmitNet(botID, runID, secret, net)
	hold := &gateHold{}
	var once sync.Once
	hold.drop = func() {
		once.Do(func() {
			release()
			a.untrackGrokGate(botID, hold)
		})
	}
	a.grokMu.Lock()
	if a.grokGates == nil {
		a.grokGates = map[string][]*gateHold{}
	}
	a.grokGates[botID] = append(a.grokGates[botID], hold)
	a.grokMu.Unlock()
	return hold.drop
}

func (a *App) untrackGrokGate(botID string, hold *gateHold) {
	if a == nil || hold == nil {
		return
	}
	a.grokMu.Lock()
	defer a.grokMu.Unlock()
	holds := a.grokGates[botID]
	for i, h := range holds {
		if h != hold {
			continue
		}
		a.grokGates[botID] = append(holds[:i], holds[i+1:]...)
		break
	}
	if len(a.grokGates[botID]) == 0 {
		delete(a.grokGates, botID)
	}
}

// releaseBotGates rejects every live secret for botID. The caller holds credMu.
func (a *App) releaseBotGates(botID string) {
	if a == nil || botID == "" {
		return
	}
	a.grokMu.Lock()
	holds := a.grokGates[botID]
	delete(a.grokGates, botID)
	a.grokMu.Unlock()
	for _, h := range holds {
		if h != nil && h.drop != nil {
			h.drop()
		}
	}
}

func (a *App) auditSymlinkNotes(botID string, notes []clisession.SymlinkNote) {
	if a == nil || len(notes) == 0 {
		return
	}
	for _, n := range notes {
		if n.Event == "" || n.Rel == "" {
			continue
		}
		fields := map[string]any{"path": n.Rel}
		a.log(botID, n.Event, fields)
		if a.audit != nil && a.audit.Enabled() {
			rec := map[string]any{"event": n.Event, "path": n.Rel}
			if botID != "" {
				rec["bot_id"] = botID
			}
			a.audit.Write(rec)
		}
	}
}

func (a *App) scrubHostGrokLogins() error {
	if a == nil {
		return nil
	}
	home, err := os.UserHomeDir()
	real := ""
	if err == nil && home != "" {
		real = filepath.Join(home, ".grok", "auth.json")
	}
	notes, err := clisession.ScrubStaleGrokAuthNotes(a.cfg.DataDir, real)
	a.auditSymlinkNotes("", notes)
	return err
}

// ensureGrokProxy starts the loopback credential proxy once. It reads the
// bearer from the user login file and does not write that file. No usable
// login means the CLI keeps the placeholder and is not pointed at a proxy.
// An expired login fails the turn instead of refreshing the user file.
func (a *App) ensureGrokProxy(userHome string) (string, error) {
	if a == nil || a.noGrokProxy {
		return "", nil
	}
	a.grokMu.Lock()
	defer a.grokMu.Unlock()
	if a.grokProxy != nil {
		return a.grokProxy.Base(), nil
	}
	userHome = strings.TrimSpace(userHome)
	if userHome == "" {
		return "", nil
	}
	path := filepath.Join(userHome, ".grok", "auth.json")
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", errGrokProxy
	}
	if _, err := coi.ReadBearer(path); err != nil {
		if errors.Is(err, coi.ErrLoginUnusable) {
			return "", err
		}
		return "", nil
	}
	eg, err := coi.StartLoopback([]string{coi.GrokChatHost}, nil, func() (string, error) {
		return coi.ReadBearer(path)
	}, a.grokTrip)
	if err != nil {
		return "", errGrokProxy
	}
	eg.SetAudit(func(botID, runID, path string, status int, suppressed int, reason string) {
		a.auditProxyRequest(botID, runID, path, status, suppressed, reason)
	})
	eg.SetRefuseAudit(func(botID, runID, path, reason string) {
		a.auditProxyRefused(botID, runID, path, reason)
	})
	eg.SetStripAudit(func(botID, runID, path string, removed []string, source string) {
		a.auditProxyStripped(botID, runID, path, removed, source)
	})
	eg.SetServerTools(func(botID string) ([]string, string) {
		return a.serverToolsFor(botID)
	})
	a.grokProxy = eg
	return eg.Base(), nil
}

func (a *App) auditEgress(botID, runID string, ev sandbox.EgressEvent) {
	if a == nil {
		return
	}
	decision := "deny"
	if ev.Allow {
		decision = "allow"
	}
	fields := map[string]any{
		"run_id":   runID,
		"host":     ev.Host,
		"port":     ev.Port,
		"decision": decision,
		"reason":   ev.Reason,
	}
	a.log(botID, "cli_egress_request", fields)
	if a == nil || a.audit == nil || !a.audit.Enabled() {
		return
	}
	rec := map[string]any{"event": "cli_egress_request", "bot_id": botID}
	for k, v := range fields {
		rec[k] = v
	}
	a.audit.Write(rec)
}

func (a *App) egressPorts() []int {
	return a.egressFor("")
}

func (a *App) egressFor(botID string) []int {
	if a == nil {
		return policy.DefaultEgressPorts()
	}
	if s, ok := a.held(botID); ok {
		pol := s.eff
		if s.freshOK {
			pol = s.secret
		}
		return pol.EgressPorts()
	}
	pol := a.pol()
	if fresh, err := a.policyNow(); err == nil && (strings.TrimSpace(a.cfg.PolicyPath) == "" || fresh.Loaded) {
		pol = fresh
	}
	return pol.EgressPorts()
}

func (a *App) auditProxyRequest(botID, runID, path string, status int, suppressed int, reason string) {
	if a == nil || a.audit == nil || !a.audit.Enabled() {
		return
	}
	rec := map[string]any{
		"event":  "cli_proxy_request",
		"bot_id": botID,
		"run_id": runID,
		"path":   path,
		"status": status,
	}
	if status == 403 {
		rec["auth"] = "none"
		if reason == "probe" {
			rec["reason"] = "probe"
		}
		if suppressed > 0 {
			rec["suppressed"] = suppressed
		}
	}
	a.audit.Write(rec)
}

// serverToolsFor is the non-function tool types one net-granted bot may
// keep, and the layer that last reduced that set. An unreadable policy
// or a missing bot record fail-closes to an empty list.
func (a *App) serverToolsFor(botID string) ([]string, string) {
	if a == nil {
		return []string{}, "default"
	}
	pol, ok := a.secretPol(botID)
	if !ok {
		return []string{}, "default"
	}
	var botList []string
	botSet := false
	if a.st != nil && botID != "" {
		b, err := a.st.GetBot(botID)
		if err != nil {
			return []string{}, "default"
		}
		if b.ServerTools != nil {
			botList = append([]string(nil), (*b.ServerTools)...)
			botSet = true
		}
	}
	return pol.EffectiveServerTools(botList, botSet)
}

func (a *App) auditProxyStripped(botID, runID, path string, removed []string, source string) {
	if a == nil || a.audit == nil || !a.audit.Enabled() || len(removed) == 0 {
		return
	}
	switch source {
	case "managed", "local", "bot", "default", "no_net":
	default:
		source = "default"
	}
	types := make([]string, 0, len(removed))
	seen := map[string]bool{}
	for _, name := range removed {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			continue
		}
		if !serverToolAuditName(name) {
			name = "invalid"
			if seen[name] {
				continue
			}
		}
		seen[name] = true
		types = append(types, name)
	}
	if len(types) == 0 {
		return
	}
	a.audit.Write(map[string]any{
		"event":   "cli_proxy_stripped",
		"bot_id":  botID,
		"run_id":  runID,
		"path":    path,
		"removed": types,
		"source":  source,
	})
}

func serverToolAuditName(s string) bool {
	if s == "" || s == "function" || len(s) > 64 || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func (a *App) auditProxyRefused(botID, runID, path, reason string) {
	if a == nil || a.audit == nil || !a.audit.Enabled() {
		return
	}
	switch reason {
	case "unparsed", "duplicate_key", "server_tool", "tools_key":
	default:
		reason = "server_tool"
	}
	a.audit.Write(map[string]any{
		"event":  "cli_proxy_refused",
		"bot_id": botID,
		"run_id": runID,
		"path":   path,
		"reason": reason,
	})
}

var errGrokProxy = errors.New("grok credential proxy is not available, so the turn was refused")

func (a *App) closeGrokProxy() {
	if a == nil {
		return
	}
	a.grokMu.Lock()
	eg := a.grokProxy
	a.grokProxy = nil
	a.grokMu.Unlock()
	if eg != nil {
		eg.Close()
	}
}

func (a *App) auditCredSymlink(botID, runID string) {
	fields := map[string]any{}
	if runID != "" {
		fields["run_id"] = runID
	}
	a.log(botID, "cli_cred_symlink_refused", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_cred_symlink_refused", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
}

// attachGrokBridge points a Linux Grok jail at the credential proxy and, when
// the bot has a net grant, at an allowlisting HTTP proxy. Both are unix
// sockets. The in-jail forwarder publishes them on 127.0.0.1. A failure here
// refuses the turn.
func (a *App) attachGrokBridge(iso *clisession.Isolation, bot store.Bot, runID string, grants clisession.Grants) error {
	if a == nil || iso == nil || runtime.GOOS != "linux" {
		return nil
	}
	needCred := envHasPrefix(iso.Env, "GROK_CLI_CHAT_PROXY_BASE_URL=http")
	if !needCred && !grants.Net {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return bridgeErr(err)
	}
	args := []string{"--coi-forward"}
	var binds [][2]string
	if needCred {
		if err := a.ensureGrokUnix(); err != nil {
			return bridgeErr(err)
		}
		a.grokMu.Lock()
		eg := a.grokProxy
		a.grokMu.Unlock()
		if eg == nil || eg.Sock() == "" {
			return bridgeErr(nil)
		}
		binds = append(binds, [2]string{eg.Sock(), clisession.JailProxySock})
		args = append(args,
			"--sock", clisession.JailProxySock,
			"--keep-key",
			"--env", "GROK_CLI_CHAT_PROXY_BASE_URL",
			"--env", "GROK_XAI_API_BASE_URL",
			"--env", "XAI_API_BASE_URL",
			"--prefix", "/bots/"+bot.ID+"/runs/"+runID+"/v1",
		)
	}
	var egress *sandbox.HTTPAllow
	if grants.Net {
		parent, err := filepath.Abs(filepath.Join(a.cfg.DataDir, "cli-egress"))
		if err != nil {
			return bridgeErr(err)
		}
		egress, err = sandbox.StartHTTPAllowProxy(parent, sandbox.EgressConfig{
			Allow: grants.NetAllow,
			Ports: a.egressFor(bot.ID),
			Audit: func(ev sandbox.EgressEvent) {
				a.auditEgress(bot.ID, runID, ev)
			},
		})
		if err != nil {
			return bridgeErr(err)
		}
		binds = append(binds, [2]string{egress.Sock(), clisession.JailEgressSock})
		args = append(args, "--http-sock", clisession.JailEgressSock)
	}
	iso.ForwardBin = exe
	iso.ForwardArgs = args
	iso.ExtraBinds = binds
	if egress != nil {
		prev := iso.ReleaseGate
		iso.ReleaseGate = func() {
			egress.Close()
			if prev != nil {
				prev()
			}
		}
	}
	return nil
}

func (a *App) ensureGrokUnix() error {
	if a == nil {
		return errGrokProxy
	}
	a.grokMu.Lock()
	defer a.grokMu.Unlock()
	if a.grokProxy == nil {
		return errGrokProxy
	}
	parent, err := filepath.Abs(filepath.Join(a.cfg.DataDir, "cli-proxy"))
	if err != nil {
		return err
	}
	return a.grokProxy.ListenUnix(parent)
}

func bridgeErr(err error) error {
	if err == nil {
		err = errors.New("credential bridge is not available")
	}
	return &clisession.BridgeError{Err: err}
}

func envHasPrefix(env []string, prefix string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
}

func (a *App) recordBridge(botID string) {
	const why = "credential bridge is not available"
	fields := map[string]any{"backend": "grok", "reason": why}
	a.log(botID, "cli_bridge_unavailable", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_bridge_unavailable", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
}

func (a *App) recordGrokProxy(botID string, err error) {
	why := errGrokProxy.Error()
	if errors.Is(err, coi.ErrLoginUnusable) {
		why = coi.ErrLoginUnusable.Error()
	}
	fields := map[string]any{"backend": "grok", "reason": why}
	a.log(botID, "cli_proxy_unavailable", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_proxy_unavailable", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
}

// lgbAllow approves the lgb and coi spool commands. Other shell commands still ask.
func lgbAllow(env map[string]string) []string {
	if env == nil {
		return nil
	}
	return []string{"Bash(lgb)", "Bash(lgb *)", "Bash(coi)", "Bash(coi *)"}
}

// withLGBEnv puts lgb first on PATH and adds its spool and run token.
func withLGBEnv(env []string, bin string, add map[string]string) []string {
	out := make([]string, 0, len(env)+len(add)+1)
	havePath := false
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, ok := add[k]; ok {
			continue
		}
		if k == "PATH" {
			havePath = true
			kv = "PATH=" + bin + string(os.PathListSeparator) + v
		}
		out = append(out, kv)
	}
	if !havePath {
		out = append(out, "PATH="+bin+string(os.PathListSeparator)+"/usr/bin:/bin")
	}
	for k, v := range add {
		out = append(out, k+"="+v)
	}
	return out
}

// botGrants maps the bot's daemon grants onto the CLI's own controls.
func botGrants(bot store.Bot) clisession.Grants {
	var g clisession.Grants
	for _, name := range bot.Grants {
		switch name {
		case "net":
			g.Net = true
		case "git":
			g.Git = true
		case "ssh":
			g.SSH = true
		}
	}
	if g.Net {
		g.NetAllow = append([]string(nil), bot.NetAllow...)
	}
	return g
}

// secretDirNames are the DATA_DIR children no CLI tool or shell may read.
// sandbox holds the SSH private key (id_ed25519). secrets is reserved for
// other daemon files. cli holds MCP tokens and CLI state. coi holds staged
// jail homes. cli-proxy and cli-egress hold per-run sockets.
var secretDirNames = []string{"cli", "coi", "cli-proxy", "cli-egress", "sandbox", "secrets"}

// daemonSecrets are paths no CLI tool or shell may read. The set is every
// configured secret, raw and resolved: the admin token, the database,
// secretDirNames, the policy file, an absolute audit_log, AUTH_TOKENS_FILE,
// the GitHub token file, and each tools.cli credential_home from the policy
// read for this call. The workspace is not included. The secret directories
// are created so Grok, which only denies paths that exist, still binds them.
func (a *App) daemonSecrets() []string {
	return a.secretList("")
}

// secretPol is the fresh policy for one call. A held turn reuses the copy
// taken at the start of that turn.
func (a *App) secretPol(botID string) (policy.Policy, bool) {
	if a == nil {
		return policy.Policy{}, false
	}
	if s, ok := a.held(botID); ok {
		if !s.freshOK {
			return policy.Policy{}, false
		}
		return s.secret, true
	}
	fresh, err := a.policyNow()
	if err != nil || (strings.TrimSpace(a.cfg.PolicyPath) != "" && !fresh.Loaded) {
		return policy.Policy{}, false
	}
	return fresh, true
}

func (a *App) secretList(botID string) []string {
	if a == nil {
		return nil
	}
	if s, ok := a.held(botID); ok {
		pol := s.eff
		if s.freshOK {
			pol = s.secret
		}
		return a.secretsFrom(pol)
	}
	pol := a.pol()
	if fresh, err := a.policyNow(); err == nil && (strings.TrimSpace(a.cfg.PolicyPath) == "" || fresh.Loaded) {
		pol = fresh
	}
	return a.secretsFrom(pol)
}

// shellProtect is the per-turn build-bind deny list. It is daemonSecrets
// plus DATA_DIR itself, raw and resolved. Blank, ".", and "/" are dropped.
// An empty result fails closed in guardBuildBinds and in the sandbox.
func (a *App) shellProtect() []string {
	return a.shellProtectBot("")
}

func (a *App) shellProtectBot(botID string) []string {
	if a == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == "/" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range a.secretList(botID) {
		add(p)
	}
	for _, p := range pathForms(a.cfg.DataDir) {
		add(p)
	}
	return out
}

// guardBuildBinds refuses every build bind when protect is empty. The
// events are daemon-generated sandbox_block rows. The returned bind list
// is nil so the sandbox does not emit the same refusal again. A non-empty
// protect returns the binds unchanged.
func guardBuildBinds(protect, binds []string) ([]string, []sandbox.Event) {
	if protectListedDaemon(protect) {
		return binds, nil
	}
	var ev []sandbox.Event
	for _, raw := range binds {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ev = append(ev, sandbox.Event{Kind: "sandbox_block", Detail: clipASCII("refused bind " + raw)})
	}
	return nil, ev
}

func protectListedDaemon(paths []string) bool {
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" && p != "." && p != "/" {
			return true
		}
	}
	return false
}

func (a *App) secretsFrom(pol policy.Policy) []string {
	dir, err := filepath.Abs(a.cfg.DataDir)
	if err != nil {
		return nil
	}
	for _, name := range secretDirNames {
		d := filepath.Join(dir, name)
		_ = os.MkdirAll(d, 0o700)
		_ = os.Chmod(d, 0o700)
	}
	return secretPaths(a.cfg, pol, true)
}

// secretPaths is the protected set. includeHomes adds each tools.cli
// credential_home. Each path is the cleaned absolute form and, when it
// differs, the nearest-existing-ancestor resolution. The directories are
// not created here.
func secretPaths(cfg config.Config, pol policy.Policy, includeHomes bool) []string {
	return expandProtected(rawSecretPaths(cfg, pol, includeHomes))
}

// rawSecretPaths lists configured secret paths before symlink resolution.
func rawSecretPaths(cfg config.Config, pol policy.Policy, includeHomes bool) []string {
	dir, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return nil
	}
	dir = filepath.Clean(dir)
	out := []string{
		filepath.Join(dir, adminTokenFile),
		filepath.Join(dir, "state.db"), filepath.Join(dir, "state.db-wal"), filepath.Join(dir, "state.db-shm"),
	}
	for _, name := range secretDirNames {
		out = append(out, filepath.Join(dir, name))
	}
	if p := strings.TrimSpace(cfg.PolicyPath); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, filepath.Clean(abs))
		}
	}
	if p := auditSecretPath(pol.AuditLog); p != "" {
		out = append(out, p)
	}
	if p := strings.TrimSpace(cfg.AuthTokensFile); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, filepath.Clean(abs))
		}
	}
	if p := strings.TrimSpace(pol.GitHub.TokenFile); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, filepath.Clean(abs))
		}
	}
	if pol.VoiceEnabled {
		bin, model, _, _ := whisperPaths(pol, cfg)
		for _, p := range []string{bin, model} {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if abs, err := filepath.Abs(p); err == nil {
				out = append(out, filepath.Clean(abs))
			}
		}
	}
	if includeHomes {
		seen := map[string]bool{}
		for _, p := range out {
			seen[filepath.Clean(p)] = true
		}
		for _, tool := range pol.CLITools {
			home := filepath.Clean(strings.TrimSpace(tool.CredentialHome))
			if home == "" || home == "." || !filepath.IsAbs(home) || seen[home] {
				continue
			}
			seen[home] = true
			out = append(out, home)
		}
	}
	return out
}

// auditSecretPath is an absolute audit_log. stderr, syslog, and empty are
// not filesystem paths.
func auditSecretPath(dest string) string {
	dest = strings.TrimSpace(dest)
	switch dest {
	case "", "stderr", "syslog":
		return ""
	}
	if !filepath.IsAbs(dest) {
		return ""
	}
	return filepath.Clean(dest)
}

// expandProtected adds the raw path and its nearest-existing-ancestor
// resolution. Duplicates are dropped.
func expandProtected(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		for _, form := range pathForms(p) {
			if form == "" || form == "." || seen[form] {
				continue
			}
			seen[form] = true
			out = append(out, form)
		}
	}
	return out
}

// noteBotProtect stores the deny list just written for this bot's turn.
func (a *App) noteBotProtect(botID string, paths []string) {
	if a == nil || botID == "" {
		return
	}
	a.protectMu.Lock()
	defer a.protectMu.Unlock()
	if a.protectByBot == nil {
		a.protectByBot = map[string][]string{}
	}
	a.protectByBot[botID] = append([]string(nil), paths...)
}

// botProtect is the deny list noted for this bot, if a turn wrote one.
func (a *App) botProtect(botID string) ([]string, bool) {
	if a == nil || botID == "" {
		return nil, false
	}
	a.protectMu.Lock()
	defer a.protectMu.Unlock()
	paths, ok := a.protectByBot[botID]
	if !ok {
		return nil, false
	}
	return append([]string(nil), paths...), true
}

// claudeSandboxMissing lists what Claude's sandbox needs and this host lacks.
// macOS uses the built-in Seatbelt. Tests replace it.
var claudeSandboxMissing = func() []string {
	if cliGOOS != "linux" {
		return nil
	}
	var missing []string
	for _, bin := range []string{"bwrap", "socat"} {
		if _, err := exec.LookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}
	return missing
}

// cliSandboxFailed reports a CLI exit that means the sandbox was not applied.
// Assistant text means the turn ran; a later tool error that mentions the
// word is not a startup refusal.
func cliSandboxFailed(backend string, iso *clisession.Isolation, err error) bool {
	if err == nil || iso == nil || !strings.Contains(strings.ToLower(err.Error()), "sandbox") {
		return false
	}
	if strings.EqualFold(backend, "grok") {
		return true
	}
	return iso.ClaudeSandbox
}

// sandboxUnavailable records that Claude's required sandbox can't run and
// returns the error the turn fails with.
func (a *App) sandboxUnavailable(botID, why string) error {
	a.recordSandboxRefusal(botID, "claude", why)
	return fmt.Errorf("Claude's sandbox is required but can't run here (%s), so the turn was refused. Install bubblewrap and socat on Linux, or a managed policy can set [cli.isolation] claude_sandbox = \"off\"", why)
}

// recordSandboxRefusal writes the bot log and the audit sink. Callers keep
// their own user-facing error so a settings failure is not described as a
// missing bubblewrap.
func (a *App) recordSandboxRefusal(botID, backend, why string) {
	fields := map[string]any{"backend": backend, "reason": clip(why, 500)}
	a.log(botID, "cli_sandbox_unavailable", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_sandbox_unavailable", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
}

// warnGrokDarwinNetwork records that this Grok turn has no network jail.
// macOS does not enforce restrict_network. The turn still runs. Linux, and a
// bot that was granted net, are quiet.
func (a *App) warnGrokDarwinNetwork(bot store.Bot, runID, backend string) {
	if !strings.EqualFold(backend, "grok") || cliGOOS != "darwin" {
		return
	}
	for _, g := range bot.Grants {
		if g == "net" {
			return
		}
	}
	const reason = "restrict_network is not enforced on macOS"
	fields := map[string]any{"backend": backend, "os": "darwin", "run_id": runID, "reason": reason}
	a.log(bot.ID, "cli_network_unrestricted", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_network_unrestricted", "bot_id": bot.ID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
	fmt.Fprintf(os.Stderr, "local-grok-bots: grok on macOS does not enforce restrict_network; bot %s has no net grant (cli_network_unrestricted)\n", bot.ID)
}

// cliGOOS is the OS the Claude home default is chosen for. Tests set it.
var cliGOOS = runtime.GOOS

// claudeLoginSource names where Claude should find its login under this
// launch, from what the daemon set up. No secret value is read or logged.
func claudeLoginSource(iso clisession.Isolation, ownHome bool, goos string) string {
	for _, kv := range iso.Env {
		switch {
		case strings.HasPrefix(kv, "CLAUDE_CODE_OAUTH_TOKEN="):
			return "env_oauth_token"
		case strings.HasPrefix(kv, "ANTHROPIC_API_KEY="):
			return "env_api_key"
		}
	}
	if ownHome {
		if _, err := os.Lstat(filepath.Join(iso.Home, ".claude", ".credentials.json")); err == nil {
			return "credentials_symlink"
		}
		return "none_found"
	}
	if goos == "darwin" {
		return "keychain_or_user_home"
	}
	return "user_home"
}

// recordClaudeLogin logs, once per bot per daemon run, the login source the
// launch provides (an API key is reported before an OAuth token, as Claude
// orders them) and what "claude auth status" reports under the same
// environment: its authMethod, loggedIn, and configDirectory only.
func (a *App) recordClaudeLogin(botID, ws string, iso clisession.Isolation, ownHome bool) {
	fields := map[string]any{
		"backend": "claude", "os": cliGOOS, "own_home": ownHome,
		"source": claudeLoginSource(iso, ownHome, cliGOOS),
	}
	if path, err := exec.LookPath("claude"); err == nil {
		ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
		cmd := exec.CommandContext(ctx, path, "auth", "status")
		cmd.Env = append([]string{}, iso.Env...)
		cmd.Dir = ws
		out, runErr := cmd.Output()
		cancel()
		var st struct {
			LoggedIn   *bool  `json:"loggedIn"`
			AuthMethod string `json:"authMethod"`
			ConfigDir  string `json:"configDirectory"`
		}
		if json.Unmarshal(out, &st) == nil {
			fields["auth_method"] = clip(st.AuthMethod, 40)
			if st.LoggedIn != nil {
				fields["logged_in"] = *st.LoggedIn
			}
			if st.ConfigDir != "" {
				fields["config_directory"] = clip(st.ConfigDir, 400)
			}
		} else {
			fields["auth_status"] = "unparsed"
		}
		if runErr != nil {
			fields["auth_status_error"] = clip(runErr.Error(), 200)
		}
	} else {
		fields["auth_status"] = "claude not on PATH"
	}
	a.log(botID, "cli_login", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_login", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
}

// cliWorkspace is the CLI process cwd. It is not a jail.
func cliWorkspace(root, botID string) (string, error) {
	if strings.TrimSpace(botID) == "" || strings.Contains(botID, "/") || strings.Contains(botID, `\`) || strings.Contains(botID, "..") {
		return "", fmt.Errorf("invalid bot id")
	}
	dir := filepath.Join(root, "bots", botID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Abs(dir)
}

func (a *App) screenDLP(ctx context.Context, botID, runID, backend, content string) error {
	turnPol := a.effPol(botID)

	err := dlp.Scan(ctx, turnPol, content)
	if err == nil {
		return nil
	}
	a.log(botID, "dlp_denied", map[string]any{"error": err.Error()})
	if a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{"event": "dlp", "action": "deny", "detail": err.Error()})
	}
	a.failCLI(botID, runID, backend, err)
	return err
}

func cliNoHostSource(ui bool) string {
	if !ui {
		return "no_ui"
	}
	return "policy"
}

func (a *App) decideStreamControl(ctx context.Context, botID, runID, sessionID string, ask clisession.ControlAsk) clisession.ControlDecision {
	// The hook is the ask path when the broker is armed. Do not open a card
	// and do not mark the turn as stopped after a denial.
	if a.brokerHooksOn(botID) {
		return clisession.ControlDecision{Behavior: permission.Deny, Message: "denied"}
	}
	turnPol := a.effPol(botID)

	req := permission.Request{
		RunID: runID, BotID: botID, SessionID: sessionID,
		Tool: ask.Tool, Args: ask.Args, ToolUseID: ask.ToolUseID,
		Transport: policy.TransportStreamControl,
	}
	if a.perm == nil {
		return clisession.ControlDecision{Behavior: permission.Deny, Message: "denied"}
	}
	// A cancel that won before the ask was registered must not open a card.
	if ctx.Err() != nil {
		a.perm.Record(req, permission.Deny, "cancel", "")
		return clisession.ControlDecision{Silent: true}
	}
	req = a.withUserRules(botID, req)
	out := a.perm.Evaluate(ctx, turnPol.Permission(), req)
	if out.Source == "cancel" {
		return clisession.ControlDecision{Silent: true}
	}
	if out.Behavior == permission.Allow {
		raw := ask.RawInput
		if out.UpdatedInput != nil {
			b, err := json.Marshal(out.UpdatedInput)
			if err != nil {
				msg := out.Message
				if msg == "" {
					msg = "denied"
				}
				return clisession.ControlDecision{Behavior: permission.Deny, Message: msg}
			}
			raw = b
		}
		return clisession.ControlDecision{Behavior: permission.Allow, RawInput: raw}
	}
	msg := out.Message
	if msg == "" {
		msg = "denied"
	}
	return clisession.ControlDecision{Behavior: permission.Deny, Message: msg}
}

func (a *App) decideGrokACP(ctx context.Context, botID, runID, sessionID string, ask clisession.ACPAsk, grokHome string) (clisession.ACPDecision, error) {
	turnPol := a.effPol(botID)

	// Prefer the id Grok returned. A fresh turn starts under a daemon id and
	// then stores Grok's id; a grant under the daemon id would not match the
	// next turn.
	if strings.TrimSpace(ask.SessionID) != "" {
		sessionID = ask.SessionID
	}
	tool := strings.TrimSpace(ask.Tool)
	if tool == "" || tool == "unknown" {
		tool = "unknown"
	}
	req := permission.Request{
		RunID: runID, BotID: botID, SessionID: sessionID,
		Tool: tool, Args: ask.Args, ToolUseID: ask.ToolUseID,
		Transport: policy.TransportACP,
		GrokHome:  grokHome,
	}
	if tool == "unknown" {
		req.Classification = "unknown"
	}
	if a.perm == nil {
		return clisession.ACPDecision{}, fmt.Errorf("no permission broker")
	}
	if ctx.Err() != nil {
		a.perm.Record(req, permission.Deny, "cancel", "")
		return clisession.ACPDecision{}, nil
	}
	req = a.withUserRules(botID, req)
	out := a.perm.Evaluate(ctx, turnPol.Permission(), req)
	if out.Behavior == permission.Allow {
		return clisession.ACPDecision{Allow: true}, nil
	}
	// Only the person's card deny is a user denial. Policy, a user rule,
	// a timeout, and a cancel keep their existing end state.
	return clisession.ACPDecision{UserDenied: out.Source == "ui" && out.Decision == permission.Deny}, nil
}

func (a *App) recordACPNote(botID, runID, kind, tool string, args map[string]any, reason string) {
	if a == nil || a.perm == nil {
		return
	}
	tool = strings.TrimSpace(tool)
	source := "host"
	class := ""
	if kind == "cli_deny" {
		source = "cli_deny"
	}
	if tool == "" || tool == "unknown" || kind == "unknown" {
		tool = "unknown"
		class = "unknown"
	}
	if args == nil {
		args = map[string]any{}
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: tool, Args: args,
		Transport: policy.TransportACP, Classification: class,
	}, permission.Deny, source, clip(reason, 200))
}

func (a *App) auditVersionRefused(botID, runID, backend, version string) {
	version = clip(oneLine(version), 200)
	if version == "" {
		version = "unknown"
	}
	fields := map[string]any{
		"backend": backend,
		"version": version,
		"action":  "refuse",
	}
	if runID != "" {
		fields["run_id"] = runID
	}
	a.log(botID, "cli_version_refused", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_version_refused", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
	if a.perm == nil {
		return
	}
	transport := ""
	if strings.EqualFold(backend, "grok") {
		transport = policy.TransportACP
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: "acp",
		Args:      map[string]any{"version": version},
		Transport: transport,
	}, permission.Deny, "host", "cli version is not allowed")
}

func envField(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return e[len(prefix):]
		}
	}
	return ""
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func (a *App) auditUntrustedConfig(botID, runID, backend, kind string, names []string) {
	copied := append([]string(nil), names...)
	fields := map[string]any{
		"backend": backend,
		"kind":    kind,
		"names":   copied,
		"action":  "refuse",
	}
	if runID != "" {
		fields["run_id"] = runID
	}
	a.log(botID, "cli_untrusted_config", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_untrusted_config", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
	if a.perm == nil {
		return
	}
	transport := ""
	if strings.EqualFold(backend, "grok") {
		transport = policy.TransportACP
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: "acp",
		Args:      map[string]any{"names": copied},
		Transport: transport,
	}, permission.Deny, "host", "untrusted CLI config")
}

func (a *App) recordACPHostFail(botID, runID, tool string, args map[string]any, reason string) {
	if a.perm == nil {
		return
	}
	if strings.TrimSpace(tool) == "" {
		tool = "acp"
	}
	if args == nil {
		args = map[string]any{}
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: tool, Args: args,
		Transport: policy.TransportACP,
	}, permission.Deny, "host", clip(reason, 200))
}

func (a *App) recordControlDeny(botID, runID, tool string, args map[string]any, rule string) {
	if a.perm == nil {
		return
	}
	if args == nil {
		args = map[string]any{}
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: tool, Args: args,
		Transport: policy.TransportStreamControl,
	}, permission.Deny, "cli", rule)
}

// noteCLIPermission records a denial the CLI reported (a permission_denied
// event or result.permission_denials). It adds a record only when the broker
// has not already decided that request for this run.
func (a *App) noteCLIPermission(botID, runID, tool string, args map[string]any, useID, source, transport string) {
	if a.perm == nil {
		return
	}
	raw, err := json.Marshal(audit.RedactValue(args))
	if err != nil || string(raw) == "null" {
		raw = []byte(`{}`)
	}
	if a.claimEcho(runID, useID, permShape(tool, raw)) {
		return
	}
	if source == "" {
		source = "cli"
	}
	a.perm.Record(permission.Request{
		RunID: runID, BotID: botID, Tool: tool, Args: args, ToolUseID: useID, Transport: transport,
	}, permission.Deny, source, "")
}

func (a *App) auditCLI(event, backend, sessionID string, pid int, result string) {
	if a.audit == nil || !a.audit.Enabled() {
		return
	}
	fields := map[string]any{
		"event":      event,
		"pid":        pid,
		"backend":    backend,
		"session_id": sessionID,
	}
	if result != "" {
		fields["result"] = result
	}
	a.audit.Write(fields)
}

func (a *App) failCLI(botID, runID, backend string, err error) {
	msg := audit.RedactText(err.Error())
	a.log(botID, "model_call", map[string]any{"model": backend, "ok": false, "error": msg})
	_, _ = a.finishRun(runID, "error", msg)
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": msg})
}

func (a *App) cliPrompt(bot store.Bot, fresh bool, inputs []store.Message) (string, error) {
	turnPol := a.effPol(bot.ID)

	var b strings.Builder
	if fresh {
		if err := a.writeCLIPreamble(&b, bot); err != nil {
			return "", err
		}
	}
	names, err := a.st.BotNames()
	if err != nil {
		return "", err
	}
	if len(inputs) == 0 {
		b.WriteString("Continue.\n")
		return b.String(), nil
	}
	grok := strings.EqualFold(turnPol.EffectiveBackend(), "grok")
	for i, m := range inputs {
		if grok && clisession.SlashPrompt(m.Content) {
			return "", clisession.ErrSlash
		}
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(mapHist(m, names).Content)
	}
	return b.String(), nil
}

// cliBoundary tells a CLI bot what actually confines it. The daemon's own
// jail and tools (run_shell, timers, memory, other bots) are not available.
func (a *App) cliBoundary(botID string) string {
	turnPol := a.effPol(botID)

	tail := "You run directly on the host, not inside the daemon's jail, and the daemon's own tools (run_shell, timers, memory, other bots) are not available to you. Some actions need the user's approval; a denied action is final for this turn.\n"
	if turnPol.CLILGB && lgbSupported {
		tail = "You run directly on the host, not inside the daemon's jail; the daemon's run_shell, read_file, and write_file are not available. Some actions need the user's approval; a denied action is final for this turn.\n" +
			"For timers, your memory notes, other bots, and direct messages, run the lgb command in your shell (run `lgb help` for usage), for example `lgb timer in 5m Remind the user to stretch` or `lgb memory set favorite_color blue`. Run each lgb command as its own shell call, with nothing chained (no ;, &&, pipes, or $?), so it is approved without asking. lgb works only during this turn.\n"
	}
	switch turnPol.EffectiveBackend() {
	case "grok":
		return "Use your own tools. Grok's sandbox confines them: files are readable and writable in your workspace and temp directories, credential paths are denied, and network access is blocked unless the user granted it (Grok can't block it on macOS). " + tail
	default:
		if turnPol.CLIClaudeSandbox == policy.SandboxOff {
			return "Use your own tools. Shell commands run under your organization's Claude sandbox settings, if any. Reads outside your workspace, credential files, web tools, git push, and ssh are denied unless the user granted them. " + tail
		}
		return "Use your own tools. Shell commands run in Claude Code's sandbox: writes go only to your workspace and temp directories, and network reaches only hosts the user granted. File tools can't read outside your workspace or touch credential files, and web tools, git push, and ssh are denied unless granted. " + tail
	}
}

func (a *App) writeCLIPreamble(b *strings.Builder, bot store.Bot) error {
	mem, err := a.st.ListMemory(bot.ID)
	if err != nil {
		return err
	}
	b.WriteString("You are ")
	b.WriteString(bot.Name)
	b.WriteString(", a bot running on a local daemon.\n\nDescription:\n")
	if strings.TrimSpace(bot.Description) == "" {
		b.WriteString("(none)\n")
	} else {
		b.WriteString(bot.Description)
		b.WriteString("\n")
	}
	b.WriteString("\nMemory:\n")
	if len(mem) == 0 {
		b.WriteString("(none)\n")
	}
	for _, m := range mem {
		b.WriteString("- ")
		b.WriteString(m.Key)
		b.WriteString(": ")
		b.WriteString(m.Value)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(a.cliBoundary(bot.ID))
	b.WriteString("Scheduled prompts are prefixed with [scheduled]. Direct messages from other bots are prefixed with [DM from Name].\n\n")
	return nil
}
