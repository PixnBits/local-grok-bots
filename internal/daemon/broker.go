package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/permbroker"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

type brokerAudit struct{ a *App }

func (b brokerAudit) Record(row permbroker.AuditRow) {
	if b.a == nil || b.a.audit == nil || !b.a.audit.Enabled() {
		return
	}
	b.a.audit.Write(map[string]any{
		"event":      "permbroker",
		"bot_id":     row.BotID,
		"session_id": row.SessionID,
		"run_id":     row.RunID,
		"decision":   row.Decision,
		"actor":      row.Actor,
		"tool":       row.Tool,
		"level":      string(row.Level),
		"pending_id": row.PendingID,
		"rule_id":    row.RuleID,
		"input_hash": row.InputHash,
		"ruleset":    row.RulesetVersion,
		"classifier": row.Classifier,
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

// prepareBrokerHook arms the broker for this Claude turn, or returns ""
// so the launch keeps disableAllHooks. A bad hook binary does not fail
// the turn. It stays locked down.
func (a *App) prepareBrokerHook(bot store.Bot, ws, home string) string {
	a.setBrokerOn(bot.ID, false)
	if a == nil || a.broker == nil || !a.effPol(bot.ID).BrokerHook(bot.ID) {
		return ""
	}
	bin := strings.TrimSpace(a.effPol(bot.ID).HookPath)
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			a.log(bot.ID, "permbroker", map[string]any{"error": "hook binary unknown"})
			return ""
		}
		bin = filepath.Join(filepath.Dir(exe), "lgb-permhook")
	}
	if err := permbroker.CheckHookBinary(bin, []string{ws, home, a.ws}); err != nil {
		a.log(bot.ID, "permbroker", map[string]any{"error": err.Error()})
		return ""
	}
	sock, err := a.brokerSocket(bot.ID)
	if err != nil {
		a.log(bot.ID, "permbroker", map[string]any{"error": err.Error()})
		return ""
	}
	a.setBrokerOn(bot.ID, true)
	return permbroker.HookCommand(bin, sock)
}

func (a *App) brokerSocket(botID string) (string, error) {
	a.brokerMu.Lock()
	defer a.brokerMu.Unlock()
	if a.brokerLn == nil {
		a.brokerLn = map[string]*permbroker.Listener{}
	}
	if ln := a.brokerLn[botID]; ln != nil {
		return ln.Path(), nil
	}
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
	if err := clisession.AssertBrokerLaunch(argv); err != nil {
		return err
	}
	a.noteBrokerTurn(botID, sessionID, runID, inputs)
	return nil
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
	d := a.broker.Evaluate(ctx, permbroker.Request{
		BotID: bot.ID, SessionID: "shell:" + bot.ID, Cwd: a.ws,
		ToolName: "run_shell", ToolInput: raw,
	})
	if d.Verdict != permbroker.VerdictAllow {
		if d.Reason == "" {
			return false, errors.New("denied")
		}
		return false, errors.New(d.Reason)
	}
	return true, nil
}
