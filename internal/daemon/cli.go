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
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/coi"
	"github.com/PixnBits/local-grok-bots/internal/dlp"
	"github.com/PixnBits/local-grok-bots/internal/id"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func (a *App) executeCLI(ctx context.Context, bot store.Bot, runID string) {
	backend := a.policy.EffectiveBackend()
	a.takePending(runID)
	a.dropResume(bot.ID)
	defer a.clearCLIPID(bot.ID, runID)
	defer a.forgetRunPerms(runID)
	if !a.policy.AllowsBackend(backend) {
		a.failCLI(bot.ID, runID, backend, fmt.Errorf("cli backend %q is not allowed by policy", backend))
		return
	}
	// Empty is mcp. An unknown value is the same config error Load fail-closes on.
	transport, err := policy.NormClaudeTransport(a.policy.ClaudeTransport)
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
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	if err := a.screenDLP(ctx, bot.ID, runID, backend, prompt); err != nil {
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		return
	}
	ws, err := cliWorkspace(a.ws, bot.ID)
	if err != nil {
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	iso, err := a.cliIsolation(bot, backend, ws, runID)
	if err != nil {
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
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
	turnTimeout := a.policy.EffectiveTurnTimeout()
	turnCtx, turnCancel := context.WithTimeout(ctx, turnTimeout)
	defer turnCancel()
	a.bus.Publish(runID, "status", map[string]any{"state": "working", "text": "working"})
	var runner clisession.Runner = clisession.ExecRunner{
		Policy: a.policy,
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
	mode := a.policy.PermissionMode
	if policy.IsBypassMode(mode) && !a.policy.ManagedBypass {
		mode = ""
	}
	spec := clisession.Spec{
		Backend: backend, SessionID: sessionID, Fresh: fresh,
		Prompt: prompt, Workspace: ws, PermissionMode: mode,
		AllowRules: append(append([]string(nil), a.policy.ToolAllow...), lgbAllow(lgbEnv)...),
		DenyRules:  append([]string(nil), a.policy.ToolDeny...),
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
	host := strings.TrimSpace(a.permBase) != ""
	switch {
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
		cliDenySource = cliNoHostSource(a.policy.UIPrompts)
	case a.policy.UIPrompts && host:
		tok := a.registerPerm(bot.ID, runID, sessionID)
		defer a.unregisterPerm(tok)
		cfgPath, werr := a.writePermMCP(bot.ID, runID, a.permBase, tok)
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
			ms := (a.policy.EffectivePromptTimeout() + time.Minute).Milliseconds()
			iso.Env = append(iso.Env, fmt.Sprintf("MCP_TOOL_TIMEOUT=%d", ms))
		}
	default:
		spec.PermissionPrompts = "none"
		eventTransport = policy.TransportNone
		cliDenySource = cliNoHostSource(a.policy.UIPrompts)
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
			body := clip(audit.RedactText(ev.Text), 4000)
			trace.result(name, ev.Text)
			a.bus.Publish(runID, "tool_result", map[string]any{"name": name, "ok": true, "result_or_error": body})
			a.log(bot.ID, "tool_end", map[string]any{"name": name, "ok": true})
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
		_ = a.st.SetBotSession(bot.ID, res.SessionID)
		sessionID = res.SessionID
	}
	trace.finish()
	text := strings.TrimSpace(trace.reply(audit.RedactText(strings.TrimSpace(res.Text))))
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
			a.persistBotText(bot.ID, runID, text)
		}
		_, _ = a.finishRun(runID, "error", "turn_timeout")
		a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": "turn_timeout"})
	case ctx.Err() != nil:
		if a.ctx.Err() != nil {
			a.finishCLIInterrupted(bot.ID, runID, text)
			break
		}
		if text != "" {
			a.persistBotText(bot.ID, runID, text)
		}
		a.finishInterrupted(bot.ID, runID, ctx)
	case errors.Is(err, clisession.ErrTruncated) || res.Interrupted:
		a.finishCLIInterrupted(bot.ID, runID, text)
	case err != nil:
		if fresh && strings.TrimSpace(res.SessionID) == "" {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		// A sandbox that cannot be applied must not continue. Claude's
		// failIfUnavailable exits at startup. Grok does the same for a custom
		// profile, and a built-in profile is refused before the process starts.
		if iso != nil && strings.TrimSpace(res.Text) == "" && cliSandboxFailed(backend, iso, err) {
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
			a.persistBotText(bot.ID, runID, text)
		}
		a.failCLI(bot.ID, runID, backend, err)
	default:
		if text != "" {
			a.persistBotText(bot.ID, runID, text)
		}
		_, _ = a.finishRun(runID, "done", "")
		a.bus.Publish(runID, "done", map[string]any{"run_id": runID})
	}
}

func (a *App) finishCLIInterrupted(botID, runID, text string) {
	if strings.TrimSpace(text) != "" {
		a.persistBotText(botID, runID, text)
	}
	_, _ = a.finishRun(runID, "error", "interrupted")
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": "interrupted"})
}

// cliIsolation checks the workspace for CLI override files and builds the
// daemon-owned CLI environment. A file the launch cannot neutralize, or any
// file under overrides = "refuse", fails the turn closed. Each detection is
// audited.
func (a *App) cliIsolation(bot store.Bot, backend, ws, runID string) (*clisession.Isolation, error) {
	botID := bot.ID
	isolated := a.policy.CLIHome != policy.HomeUser
	found := clisession.ScanOverrides(ws)
	if len(found) > 0 {
		var blocked []string
		for _, f := range found {
			if a.policy.CLIOverrides == policy.OverridesRefuse || !clisession.Neutralized(backend, f, isolated) {
				blocked = append(blocked, f)
			}
		}
		action := "ignore"
		if len(blocked) > 0 {
			action = "refuse"
		}
		fields := map[string]any{"backend": backend, "files": found, "action": action, "mode": a.policy.CLIOverrides}
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
		Backend:  backend,
		StateDir: state,
		Base:     os.Environ(),
		Extra:    a.policy.CLIEnv,
		Secrets:  []string{a.cfg.AuthToken},
		Grants:   botGrants(bot),
		Protect:  a.daemonSecrets(),
		CredRoot: a.cfg.DataDir,
	}
	if strings.EqualFold(backend, "claude") && a.policy.CLIClaudeSandbox != policy.SandboxOff {
		if missing := claudeSandboxMissing(); len(missing) > 0 {
			return nil, a.sandboxUnavailable(botID, "missing "+strings.Join(missing, ", "))
		}
		opts.ClaudeSandbox = true
	}
	opts.UserHome, _ = os.UserHomeDir()
	if a.botDeleted(bot.ID) {
		return nil, fmt.Errorf("bot was deleted")
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
		ownHome = !a.policy.ClaudeUsesUserHome(cliGOOS)
	}
	if ownHome {
		opts.Home = filepath.Join(state, "home")
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
			iso.ReleaseGate = a.trackGrokGate(bot.ID, runID, opts.ProxyGate)
		}
		a.credMu.Unlock()
	} else {
		iso, err = clisession.PrepareIsolation(opts)
	}
	if errors.Is(err, clisession.ErrCredSymlink) {
		a.auditCredSymlink(bot.ID, runID)
	}
	if err != nil {
		var se *clisession.SandboxError
		if errors.As(err, &se) {
			a.recordSandboxRefusal(botID, se.Backend, se.Error())
		}
		return nil, err
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
func (a *App) trackGrokGate(botID, runID, secret string) func() {
	if a == nil {
		return func() {}
	}
	a.grokMu.Lock()
	eg := a.grokProxy
	a.grokMu.Unlock()
	if eg == nil {
		return func() {}
	}
	release := eg.Admit(botID, runID, secret)
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

func scrubHostGrokLogins(dataDir string) error {
	home, err := os.UserHomeDir()
	real := ""
	if err == nil && home != "" {
		real = filepath.Join(home, ".grok", "auth.json")
	}
	return clisession.ScrubStaleGrokAuth(dataDir, real)
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
	a.grokProxy = eg
	return eg.Base(), nil
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

// daemonSecrets are paths no CLI tool or shell may read: the admin token,
// the database, policy.toml, DATA_DIR/cli (MCP tokens and CLI state),
// DATA_DIR/coi (staged jail homes and the proxy socket), and each tools.cli
// credential_home from the policy read for this call. The workspace is not
// included. DATA_DIR/cli and DATA_DIR/coi are created so Grok, which only
// denies paths that exist, still binds those directories.
func (a *App) daemonSecrets() []string {
	pol := a.policy
	if fresh, err := a.policyNow(); err == nil && (strings.TrimSpace(a.cfg.PolicyPath) == "" || fresh.Loaded) {
		pol = fresh
	}
	return a.secretsFrom(pol)
}

func (a *App) secretsFrom(pol policy.Policy) []string {
	dir, err := filepath.Abs(a.cfg.DataDir)
	if err != nil {
		return nil
	}
	cliDir := filepath.Join(dir, "cli")
	_ = os.MkdirAll(cliDir, 0o700)
	coiDir := filepath.Join(dir, "coi")
	_ = os.MkdirAll(coiDir, 0o700)
	out := []string{
		filepath.Join(dir, adminTokenFile),
		filepath.Join(dir, "state.db"), filepath.Join(dir, "state.db-wal"), filepath.Join(dir, "state.db-shm"),
		cliDir,
		coiDir,
	}
	if p := strings.TrimSpace(a.cfg.PolicyPath); p != "" {
		abs, err := filepath.Abs(p)
		if err == nil {
			out = append(out, abs)
		}
	}
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
	err := dlp.Scan(ctx, a.policy, content)
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
	out := a.perm.Evaluate(ctx, a.policy.Permission(), req)
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
	for i, m := range inputs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(mapHist(m, names).Content)
	}
	return b.String(), nil
}

// cliBoundary tells a CLI bot what actually confines it. The daemon's own
// jail and tools (run_shell, timers, memory, other bots) are not available.
func (a *App) cliBoundary() string {
	tail := "You run directly on the host, not inside the daemon's jail, and the daemon's own tools (run_shell, timers, memory, other bots) are not available to you. Some actions need the user's approval; a denied action is final for this turn.\n"
	if a.policy.CLILGB && lgbSupported {
		tail = "You run directly on the host, not inside the daemon's jail; the daemon's run_shell, read_file, and write_file are not available. Some actions need the user's approval; a denied action is final for this turn.\n" +
			"For timers, your memory notes, other bots, and direct messages, run the lgb command in your shell (run `lgb help` for usage), for example `lgb timer in 5m Remind the user to stretch` or `lgb memory set favorite_color blue`. Run each lgb command as its own shell call, with nothing chained (no ;, &&, pipes, or $?), so it is approved without asking. lgb works only during this turn.\n"
	}
	switch a.policy.EffectiveBackend() {
	case "grok":
		return "Use your own tools. Grok's sandbox confines them: files are readable and writable in your workspace and temp directories, credential paths are denied, and network access is blocked unless the user granted it (Grok can't block it on macOS). " + tail
	default:
		if a.policy.CLIClaudeSandbox == policy.SandboxOff {
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
	b.WriteString(a.cliBoundary())
	b.WriteString("Scheduled prompts are prefixed with [scheduled]. Direct messages from other bots are prefixed with [DM from Name].\n\n")
	return nil
}
