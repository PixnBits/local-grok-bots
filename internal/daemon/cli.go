package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
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
	iso, err := a.cliIsolation(bot, backend, ws)
	if err != nil {
		if fresh {
			_ = a.st.SetBotSession(bot.ID, "")
		}
		a.failCLI(bot.ID, runID, backend, err)
		return
	}
	lgb, lgbEnv, lerr := a.startLGB(ctx, bot, runID, ws)
	if lerr != nil {
		a.log(bot.ID, "lgb_unavailable", map[string]any{"run_id": runID, "error": clip(lerr.Error(), 300)})
	}
	defer lgb.stop()
	if lgbEnv != nil {
		iso.Env = withLGBEnv(iso.Env, filepath.Join(ws, lgbDirName, "bin"), lgbEnv)
	}
	turnCtx := ctx
	if a.policy.TurnTimeout > 0 {
		var cancel context.CancelFunc
		turnCtx, cancel = context.WithTimeout(ctx, a.policy.TurnTimeout)
		defer cancel()
	}
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
		OnStart: func(child int) {
			if child <= 0 {
				return
			}
			pid = child
			a.setCLIPID(bot.ID, child)
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
		spec.MCPConfig = permissionMCPConfig(a.permBase, tok)
		spec.PermissionTool = permissionToolName
		eventTransport = policy.TransportMCP
	default:
		spec.PermissionPrompts = "none"
		eventTransport = policy.TransportNone
		cliDenySource = cliNoHostSource(a.policy.UIPrompts)
	}
	trace := &cliTrace{a: a, botID: bot.ID, runID: runID}
	res, err := runner.Run(turnCtx, spec, func(ev clisession.Event) {
		switch ev.Kind {
		case "token":
			if ev.Text == "" {
				return
			}
			streamed = true
			trace.token(ev.Text)
			a.bus.Publish(runID, "token", map[string]string{"text": ev.Text})
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
	text := strings.TrimSpace(trace.reply(strings.TrimSpace(res.Text)))
	if text != "" && !streamed {
		a.bus.Publish(runID, "token", map[string]string{"text": text})
	}
	a.log(bot.ID, "model_call", map[string]any{"model": backend, "ok": err == nil, "session_id": sessionID})
	switch {
	case a.consumeIdleKill(bot.ID):
		a.finishCLIInterrupted(bot.ID, runID, text)
	case a.policy.TurnTimeout > 0 && turnCtx.Err() != nil && ctx.Err() == nil && errors.Is(turnCtx.Err(), context.DeadlineExceeded):
		if text != "" {
			a.persistBotText(bot.ID, runID, text)
		}
		_, _ = a.st.FinishRun(runID, "error", "turn_timeout")
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
		// failIfUnavailable makes Claude exit at startup; say why.
		if iso != nil && iso.ClaudeSandbox && strings.TrimSpace(res.Text) == "" && strings.Contains(strings.ToLower(err.Error()), "sandbox") {
			err = a.sandboxUnavailable(bot.ID, err.Error())
		}
		a.failCLI(bot.ID, runID, backend, err)
	default:
		if text != "" {
			a.persistBotText(bot.ID, runID, text)
		}
		_, _ = a.st.FinishRun(runID, "done", "")
		a.bus.Publish(runID, "done", map[string]any{"run_id": runID})
	}
}

func (a *App) finishCLIInterrupted(botID, runID, text string) {
	if strings.TrimSpace(text) != "" {
		a.persistBotText(botID, runID, text)
	}
	_, _ = a.st.FinishRun(runID, "error", "interrupted")
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": "interrupted"})
}

// cliIsolation checks the workspace for CLI override files and builds the
// daemon-owned CLI environment. A file the launch cannot neutralize, or any
// file under overrides = "refuse", fails the turn closed. Each detection is
// audited.
func (a *App) cliIsolation(bot store.Bot, backend, ws string) (*clisession.Isolation, error) {
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
	}
	if strings.EqualFold(backend, "claude") && a.policy.CLIClaudeSandbox != policy.SandboxOff {
		if missing := claudeSandboxMissing(); len(missing) > 0 {
			return nil, a.sandboxUnavailable(botID, "missing "+strings.Join(missing, ", "))
		}
		opts.ClaudeSandbox = true
	}
	opts.UserHome, _ = os.UserHomeDir()
	ownHome := isolated
	if strings.EqualFold(backend, "claude") {
		// On macOS Claude's login is in the Keychain, found through the real
		// HOME and default config dir; claude_home = auto keeps both there.
		ownHome = !a.policy.ClaudeUsesUserHome(cliGOOS)
	}
	if ownHome {
		opts.Home = filepath.Join(state, "home")
	}
	iso, err := clisession.PrepareIsolation(opts)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(backend, "claude") {
		if _, seen := a.loginChecked.LoadOrStore(botID, true); !seen {
			a.recordClaudeLogin(botID, ws, iso, ownHome)
		}
	}
	return &iso, nil
}

// lgbAllow approves only the lgb command. Other shell commands still ask.
func lgbAllow(env map[string]string) []string {
	if env == nil {
		return nil
	}
	return []string{"Bash(lgb)", "Bash(lgb *)"}
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

// daemonSecrets are files no CLI tool or shell may read: the admin token and
// the database. They sit beside the workspace in DATA_DIR.
func (a *App) daemonSecrets() []string {
	dir, err := filepath.Abs(a.cfg.DataDir)
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(dir, adminTokenFile),
		filepath.Join(dir, "state.db"), filepath.Join(dir, "state.db-wal"), filepath.Join(dir, "state.db-shm"),
	}
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

// sandboxUnavailable records that Claude's required sandbox can't run and
// returns the error the turn fails with.
func (a *App) sandboxUnavailable(botID, why string) error {
	fields := map[string]any{"backend": "claude", "reason": clip(why, 500)}
	a.log(botID, "cli_sandbox_unavailable", fields)
	if a.audit != nil && a.audit.Enabled() {
		rec := map[string]any{"event": "cli_sandbox_unavailable", "bot_id": botID}
		for k, v := range fields {
			rec[k] = v
		}
		a.audit.Write(rec)
	}
	return fmt.Errorf("Claude's sandbox is required but can't run here (%s), so the turn was refused. Install bubblewrap and socat on Linux, or a managed policy can set [cli.isolation] claude_sandbox = \"off\"", why)
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
	a.log(botID, "model_call", map[string]any{"model": backend, "ok": false, "error": err.Error()})
	_, _ = a.st.FinishRun(runID, "error", err.Error())
	a.bus.Publish(runID, "error", map[string]any{"run_id": runID, "error": err.Error()})
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
