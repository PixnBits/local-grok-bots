package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// afterClaudePathCheck runs after the version check and before the launch.
// Tests use it to change the launch PATH. Production leaves it nil.
var afterClaudePathCheck func(*clisession.Isolation)

type brokerAudit struct{ a *App }

func (b brokerAudit) Record(row permbroker.AuditRow) {
	if b.a == nil || b.a.audit == nil || !b.a.audit.Enabled() {
		return
	}
	b.a.audit.Write(map[string]any{
		"event":         "permbroker",
		"bot_id":        row.BotID,
		"session_id":    row.SessionID,
		"run_id":        row.RunID,
		"decision":      row.Decision,
		"scope":         row.Scope,
		"actor":         row.Actor,
		"tool":          row.Tool,
		"level":         string(row.Level),
		"pending_id":    row.PendingID,
		"rule_id":       row.RuleID,
		"input_hash":    row.InputHash,
		"ruleset":       row.RulesetVersion,
		"classifier":    row.Classifier,
		"table_version": row.TableVersion,
	})
}

func (a *App) closeBroker() {
	if a == nil {
		return
	}
	a.brokerMu.Lock()
	for _, ln := range a.brokerLn {
		_ = ln.Close()
	}
	a.brokerLn = nil
	a.brokerOn = nil
	br := a.broker
	a.brokerMu.Unlock()
	if br != nil {
		_ = br.Close()
	}
}

func (a *App) setBrokerOn(bot string, on bool) {
	if a == nil {
		return
	}
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	if a.brokerOn == nil {
		a.brokerOn = map[string]bool{}
	}
	if on {
		a.brokerOn[bot] = true
		return
	}
	delete(a.brokerOn, bot)
}

func (a *App) brokerHooksOn(bot string) bool {
	if a == nil {
		return false
	}
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	return a.brokerOn[bot]
}

func (a *App) closeBrokerBot(id string) {
	if a == nil {
		return
	}
	a.brokerMu.Lock()
	ln := a.brokerLn[id]
	delete(a.brokerLn, id)
	delete(a.brokerOn, id)
	a.brokerMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if a.broker != nil {
		a.broker.CancelBot(id)
	}
}

// prepareBrokerHook arms the broker for this Claude turn.
// An empty command means the broker is off for this bot, and the launch
// keeps disableAllHooks. When the broker is on and the hook binary cannot
// be used, the socket cannot be created, or the hook path is unknown, the
// error refuses the turn before the CLI starts.
func (a *App) prepareBrokerHook(bot store.Bot, ws, home, runID string) (string, error) {
	a.setBrokerOn(bot.ID, false)
	if a == nil || a.broker == nil || !a.effPol(bot.ID).BrokerHook(bot.ID) {
		return "", nil
	}
	if a.repinRequired() {
		err := errors.New("hook changed; re-pin required")
		a.noteHookChange(bot.ID, err)
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	bin, err := brokerHookBinary(a.effPol(bot.ID))
	if err != nil {
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	if err := a.hookChanged(bin); err != nil {
		a.requireRepin()
		a.noteHookChange(bot.ID, err)
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	if err := permbroker.CheckHookBinary(bin, []string{ws, home, a.ws}); err != nil {
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	if !a.hookPinned() {
		err := fmt.Errorf("hook was not pinned when the policy loaded")
		a.noteHookChange(bot.ID, err)
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	copyPath, err := a.copyLaunchHook(bot.ID, runID)
	if err != nil {
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	if _, err := a.brokerSockPath(bot.ID); err != nil {
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	sock, err := a.brokerSocket(bot.ID)
	if err != nil {
		return "", a.refuseBrokerHook(bot.ID, err)
	}
	a.hookMu.Lock()
	a.hookBin = bin
	if a.hookCopy == nil {
		a.hookCopy = map[string]string{}
	}
	a.hookCopy[bot.ID] = copyPath
	a.hookMu.Unlock()
	if a.broker != nil {
		_ = a.broker.NoteHookFile(copyPath)
	}
	a.setBrokerOn(bot.ID, true)
	if a.broker != nil {
		a.broker.SetBotContext(bot.ID, ws, a.effPol(bot.ID).EffectiveGitHubRepos(bot.GitHubAllow))
		a.broker.AddCriticalPaths(a.brokerCriticalPaths(bin, "", "")...)
		a.broker.AddCriticalPaths(filepath.Dir(copyPath))
	}
	return permbroker.HookCommand(copyPath, sock), nil
}

func (a *App) copyLaunchHook(botID, runID string) (string, error) {
	if !safeBotID(botID) || !safeBotID(runID) {
		return "", errors.New("hook changed")
	}
	a.hookMu.Lock()
	pin := a.hookPin
	a.hookMu.Unlock()
	if pin == nil {
		return "", errors.New("hook changed")
	}
	dir := filepath.Join(a.cfg.DataDir, "permbroker", botID, "launch", runID)
	path, err := permbroker.CopyPinnedHook(*pin, dir)
	if err != nil {
		return "", errors.New("hook changed")
	}
	a.hookMu.Lock()
	pin = a.hookPin
	a.hookMu.Unlock()
	if pin == nil || pin.CopySum(path) != nil {
		_ = os.RemoveAll(dir)
		return "", errors.New("hook changed")
	}
	return path, nil
}

func (a *App) pinBrokerHook(p policy.Policy) {
	if a == nil || p.Broker != "hook" {
		return
	}
	bin, err := brokerHookBinary(p)
	if err != nil {
		a.requireRepin()
		return
	}
	a.hookMu.Lock()
	pin := a.hookPin
	a.hookMu.Unlock()
	if pin == nil {
		if err := permbroker.CheckHookBinary(bin, cleanRoots(a.ws)); err != nil {
			return
		}
		fresh, err := permbroker.PinHook(bin)
		if err != nil {
			return
		}
		a.installPin(fresh, bin)
		return
	}
	clean := bin
	if abs, err := filepath.Abs(bin); err == nil {
		clean = filepath.Clean(abs)
	}
	if pin.Path != clean || pin.Diff(bin) != nil {
		a.requireRepin()
		return
	}
}

func (a *App) installPin(pin permbroker.HookPin, bin string) {
	a.hookMu.Lock()
	a.hookPin = &pin
	a.hookBin = bin
	a.hookRepinRequired = false
	a.hookMu.Unlock()
	if a.broker == nil {
		return
	}
	a.broker.ClearHookIDs()
	a.broker.SetHookIdentity(pin.Dev, pin.Ino)
	_ = a.broker.NoteHookFile(bin)
	if a.cfg.DataDir != "" {
		copyPath := filepath.Join(a.cfg.DataDir, "permbroker", "hook")
		if st, err := os.Stat(copyPath); err == nil && st.Mode().IsRegular() {
			_ = a.broker.NoteHookFile(copyPath)
		}
	}
}

func (a *App) repinRequired() bool {
	if a == nil {
		return false
	}
	a.hookMu.Lock()
	defer a.hookMu.Unlock()
	return a.hookRepinRequired
}

func (a *App) requireRepin() {
	if a == nil {
		return
	}
	a.hookMu.Lock()
	already := a.hookRepinRequired
	a.hookRepinRequired = true
	var cancels []context.CancelFunc
	if a.cliCancel != nil {
		for _, fn := range a.cliCancel {
			if fn != nil {
				cancels = append(cancels, fn)
			}
		}
	}
	a.hookMu.Unlock()
	if len(cancels) > 0 {
		a.noteHookAbort("")
		for _, fn := range cancels {
			fn()
		}
	}
	if already {
		return
	}
	if a.broker != nil {
		a.broker.Note("", "deny", "hook changed; re-pin required")
	}
	a.log("", "permbroker", map[string]any{"error": "hook changed; re-pin required"})
}

func (a *App) repinBrokerHook() error {
	if a == nil || a.broker == nil {
		return errors.New("hook cannot be pinned")
	}
	pol := a.pol()
	if pol.Broker != "hook" {
		return errors.New("hook cannot be pinned")
	}
	bin, err := brokerHookBinary(pol)
	if err != nil {
		return err
	}
	if err := permbroker.CheckHookBinary(bin, cleanRoots(a.ws)); err != nil {
		return err
	}
	pin, err := permbroker.PinHook(bin)
	if err != nil {
		return err
	}
	a.installPin(pin, bin)
	a.broker.Note("", "repin", "hook re-pinned")
	if a.audit != nil && a.audit.Enabled() {
		a.audit.Write(map[string]any{"event": "permbroker", "action": "hook_repin"})
	}
	return nil
}

func (a *App) hookChanged(bin string) error {
	a.hookMu.Lock()
	pin := a.hookPin
	a.hookMu.Unlock()
	if pin == nil {
		return nil
	}
	return pin.Diff(bin)
}

func (a *App) hookPinned() bool {
	a.hookMu.Lock()
	defer a.hookMu.Unlock()
	return a.hookPin != nil
}

func (a *App) verifyLaunchHook(bot string) error {
	if a == nil {
		return nil
	}
	a.hookMu.Lock()
	pin := a.hookPin
	copyPath := ""
	if a.hookCopy != nil {
		copyPath = a.hookCopy[bot]
	}
	sticky := a.hookRepinRequired
	a.hookMu.Unlock()
	if pin == nil && !sticky {
		return nil
	}
	if sticky {
		return errors.New("hook changed")
	}
	if pin.Diff(pin.Path) != nil {
		a.markHookChanged(bot)
		return errors.New("hook changed")
	}
	if copyPath != "" && pin.CopySum(copyPath) != nil {
		a.markHookChanged(bot)
		return errors.New("hook changed")
	}
	return nil
}

func (a *App) markHookChanged(bot string) {
	if a == nil {
		return
	}
	// Mid-turn and Evaluate both arrive here. The latch stays set until
	// an admin repin, including when the original bytes are restored.
	a.requireRepin()
}

func (a *App) setCLICancel(bot string, cancel context.CancelFunc) {
	if a == nil || bot == "" {
		return
	}
	a.hookMu.Lock()
	if a.cliCancel == nil {
		a.cliCancel = map[string]context.CancelFunc{}
	}
	a.cliCancel[bot] = cancel
	a.hookMu.Unlock()
}

func (a *App) clearCLICancel(bot string) {
	if a == nil || bot == "" {
		return
	}
	a.hookMu.Lock()
	delete(a.cliCancel, bot)
	a.hookMu.Unlock()
}

func (a *App) noteHookAbort(bot string) {
	if a == nil {
		return
	}
	a.hookMu.Lock()
	if a.hookAbort == nil {
		a.hookAbort = map[string]bool{}
	}
	if bot == "" {
		for id := range a.cliCancel {
			a.hookAbort[id] = true
		}
	} else {
		a.hookAbort[bot] = true
	}
	a.hookMu.Unlock()
}

func (a *App) consumeHookAbort(bot string) bool {
	if a == nil {
		return false
	}
	a.hookMu.Lock()
	defer a.hookMu.Unlock()
	if a.hookAbort == nil || !a.hookAbort[bot] {
		return false
	}
	delete(a.hookAbort, bot)
	return true
}

func (a *App) noteHookChange(botID string, err error) {
	if a == nil || a.broker == nil || err == nil {
		return
	}
	a.broker.Note(botID, "deny", err.Error())
}

// checkClaudeBrokerVersion runs --version on the binary this launch will
// execute. The returned path is that file. The caller sets it as argv0
// so the launch does not look the name up again.
func (a *App) checkClaudeBrokerVersion(botID string, spec clisession.Spec) (string, error) {
	if a == nil || !strings.EqualFold(spec.Backend, "claude") || !a.brokerHooksOn(botID) {
		return "", nil
	}
	argv, err := clisession.Args(spec)
	if err != nil || len(argv) == 0 {
		return "", a.refuseBrokerCLI(botID, fmt.Errorf("version cannot be read"))
	}
	path, err := clisession.ResolveLaunchPath(argv[0], clisession.LaunchEnv(spec))
	if err != nil {
		return "", a.refuseBrokerCLI(botID, fmt.Errorf("version cannot be read"))
	}
	if err := clisession.CheckClaudeBrokerVersion(context.Background(), path); err != nil {
		return "", a.refuseBrokerCLI(botID, err)
	}
	if afterClaudePathCheck != nil {
		afterClaudePathCheck(spec.Isolate)
	}
	return path, nil
}

func (a *App) refuseBrokerCLI(botID string, err error) error {
	reason := brokerHookReason(err)
	a.log(botID, "permbroker", map[string]any{"error": reason})
	return fmt.Errorf("permission broker is enabled but the Claude CLI cannot be used (%s), so the turn was refused", reason)
}

func (a *App) brokerCriticalPaths(bin, settings, settingsDir string) []string {
	data := ""
	if a != nil {
		data = a.cfg.DataDir
	}
	return permbroker.BrokerCriticalPaths(data, bin, settings, settingsDir)
}

// seedStartupCriticalPaths marks broker files before any Claude launch so
// run_shell and Bash see the same set. The bot workspace is not included.
func (a *App) seedStartupCriticalPaths(p policy.Policy) {
	if a == nil || a.broker == nil || p.Broker != "hook" {
		return
	}
	bin, _ := brokerHookBinary(p)
	paths := a.brokerCriticalPaths(bin, "", "")
	if data := strings.TrimSpace(a.cfg.DataDir); data != "" {
		paths = append(paths,
			filepath.Join(data, adminTokenFile),
			filepath.Join(data, "cli"),
			filepath.Dir(filepath.Join(data, "permbroker", "hook")),
		)
	}
	if tok := strings.TrimSpace(a.cfg.AuthTokensFile); tok != "" {
		paths = append(paths, tok)
	}
	a.broker.AddCriticalPaths(paths...)
}

// brokerHookBinary is the configured hook, or lgb-permhook next to this
// daemon when policy leaves the path empty.
func brokerHookBinary(pol policy.Policy) (string, error) {
	bin := strings.TrimSpace(pol.HookPath)
	if bin != "" {
		return bin, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", errors.New("hook binary unknown")
	}
	return filepath.Join(filepath.Dir(exe), "lgb-permhook"), nil
}

// brokerHookWarning is a policy warning when broker is hook and the
// configured or derived binary fails CheckHookBinary. An empty result
// means there is nothing to print.
func brokerHookWarning(pol policy.Policy, roots []string) string {
	if pol.Broker != "hook" {
		return ""
	}
	bin, err := brokerHookBinary(pol)
	if err != nil {
		return brokerHookWarnText(err)
	}
	if err := permbroker.CheckHookBinary(bin, roots); err != nil {
		return brokerHookWarnText(err)
	}
	return ""
}

func brokerHookWarnText(err error) string {
	return "permission broker hook cannot be used (" + brokerHookReason(err) + ")"
}

func brokerHookReason(err error) string {
	if err == nil {
		return "unknown"
	}
	reason := clip(oneLine(err.Error()), 300)
	if reason == "" {
		return "unknown"
	}
	return reason
}

func cleanRoots(paths ...string) []string {
	var out []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		out = append(out, p)
	}
	return out
}

func (a *App) refuseBrokerHook(botID string, err error) error {
	reason := brokerHookReason(err)
	a.log(botID, "permbroker", map[string]any{"error": reason})
	return fmt.Errorf("permission broker is enabled but its hook cannot be used (%s), so the turn was refused", reason)
}

func (a *App) brokerSockPath(botID string) (string, error) {
	if !safeBotID(botID) {
		return "", errors.New("invalid bot id")
	}
	path, err := filepath.Abs(filepath.Join(a.cfg.DataDir, "permbroker", botID, "sock"))
	if err != nil {
		return "", err
	}
	// Linux sun_path holds 108 bytes including the trailing NUL.
	if len(path) >= 108 {
		return "", errors.New("socket path is too long")
	}
	return path, nil
}

func (a *App) brokerSocket(botID string) (string, error) {
	path, err := a.brokerSockPath(botID)
	if err != nil {
		return "", err
	}
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	if a.brokerLn == nil {
		a.brokerLn = map[string]*permbroker.Listener{}
	}
	if ln := a.brokerLn[botID]; ln != nil {
		return ln.Path(), nil
	}
	ln, err := a.broker.Listen(botID, path)
	if err != nil {
		return "", err
	}
	a.brokerLn[botID] = ln
	return ln.Path(), nil
}

func safeBotID(id string) bool {
	if id == "" || len(id) > 200 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func (a *App) clearBotSession(botID, sessionID string) {
	if a == nil || a.st == nil {
		return
	}
	_ = a.st.SetBotSession(botID, "")
	if a.broker != nil && sessionID != "" {
		a.broker.CancelSession(botID, sessionID)
	}
}

func (a *App) noteUserMessage(botID, msgID, text string) {
	if a == nil || a.broker == nil || msgID == "" || !a.effPol(botID).BrokerHook(botID) {
		return
	}
	a.broker.NoteUserText(botID, msgID, text)
}

func lastUserTask(inputs []store.Message) string {
	task := ""
	for _, m := range inputs {
		if m.Role == "user" && m.ID != "" {
			task = m.ID
		}
	}
	return task
}

func (a *App) noteBrokerTurn(botID, sessionID, runID string, inputs []store.Message) {
	if a == nil || a.broker == nil || sessionID == "" || !a.brokerHooksOn(botID) {
		return
	}
	a.broker.NoteTurn(botID, sessionID, runID, lastUserTask(inputs))
}

// armBrokerSpec drops allow lists, refuses a bypass mode, and checks the
// argv that Claude will see. Headless transports get --permission-prompts
// none and no MCP prompt tool.
func (a *App) armBrokerSpec(botID, sessionID, runID string, inputs []store.Message, spec *clisession.Spec) error {
	if a == nil || spec == nil || !strings.EqualFold(spec.Backend, "claude") || !a.brokerHooksOn(botID) {
		return nil
	}
	if clisession.BrokerModeForbidden(spec.PermissionMode) {
		return errors.New("permission broker refuses this permission mode")
	}
	spec.AllowRules = nil
	if !spec.StreamControl {
		spec.PermissionPrompts = "none"
		spec.MCPConfig = ""
		spec.PermissionTool = ""
	}
	argv, err := clisession.Args(*spec)
	if err != nil {
		return err
	}
	settings := ""
	if spec.Isolate != nil {
		settings = spec.Isolate.SettingsPath
	}
	if err := clisession.AssertBrokerLaunch(argv, settings, spec.MCPConfig); err != nil {
		return err
	}
	a.noteBrokerTurn(botID, sessionID, runID, inputs)
	return nil
}

// seedBrokerBots records each bot's workspace and, when that bot has no
// stored git baseline yet, records one. It copies profile rules into the
// broker file once. The profile rows stay where they are. A second start
// does not add duplicate broker rules and does not replace a baseline.
func (a *App) seedBrokerBots(bots []store.Bot) {
	if a == nil || a.broker == nil {
		return
	}
	userHome, _ := os.UserHomeDir()
	var legacy []permbroker.LegacyRule
	for _, b := range bots {
		ws := a.botWorkspace(b.ID)
		a.broker.SetBotContext(b.ID, ws, a.pol().EffectiveGitHubRepos(b.GitHubAllow))
		home := filepath.Join(filepath.Dir(a.ws), "cli", b.ID, "home")
		a.broker.SetBotRuntime(b.ID, home, userHome, nil)
		a.broker.SnapshotBot(b.ID)
		if a.st == nil {
			continue
		}
		rows, err := a.st.ListUserPermRules(b.ID)
		if err != nil {
			continue
		}
		for _, r := range rows {
			legacy = append(legacy, permbroker.LegacyRule{BotID: b.ID, Effect: r.Effect, Text: r.Pattern})
		}
	}
	if err := a.broker.MigrateLegacy(legacy); err != nil {
		a.log("", "permbroker_migrate", map[string]any{"error": err.Error()})
	}
}

func literalGitPush(command string) bool {
	parsed := permbroker.ParseCommand(command)
	return parsed.Eligible && len(parsed.Argv) >= 2 && parsed.Argv[0] == "git" && parsed.Argv[1] == "push"
}

// gateShell asks the broker before run_shell. A literal git push skips
// the ask so the existing push card still runs. The bool is CleanBash.
func (a *App) gateShell(ctx context.Context, bot store.Bot, command string) (bool, error) {
	if a == nil || a.broker == nil || !a.effPol(bot.ID).BrokerHook(bot.ID) {
		return false, nil
	}
	if literalGitPush(command) {
		return true, nil
	}
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		return false, errors.New("denied")
	}
	ws := a.botWorkspace(bot.ID)
	repos := a.effPol(bot.ID).EffectiveGitHubRepos(bot.GitHubAllow)
	a.broker.SetBotContext(bot.ID, ws, repos)
	userHome, _ := os.UserHomeDir()
	a.broker.EnsureBotHomes(bot.ID, filepath.Join(filepath.Dir(a.ws), "cli", bot.ID, "home"), userHome)
	a.broker.SnapshotBot(bot.ID)
	cwd, plan, cerr := a.prepareShellCwd(bot.ID, ws, command)
	if cerr != nil {
		return false, cerr
	}
	d := a.broker.Evaluate(ctx, permbroker.Request{
		BotID: bot.ID, SessionID: "shell:" + bot.ID, TaskID: a.broker.UserTask(bot.ID),
		Cwd: cwd, Workspace: ws, Repos: repos,
		ToolName: "run_shell", ToolInput: raw,
	})
	if d.Verdict != permbroker.VerdictAllow {
		a.clearShellPlan(bot.ID)
		if d.Reason == "" {
			return false, errors.New("denied")
		}
		return false, errors.New(d.Reason)
	}
	a.noteShellPlan(bot.ID, plan)
	return true, nil
}
