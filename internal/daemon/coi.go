package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/coi"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func (a *App) coiCounter() *coi.HourCap {
	a.coiOnce.Do(func() {
		a.coiCap = coi.NewHourCap(nil)
		if a.st != nil {
			a.coiCap.SetStore(a.st)
		}
	})
	return a.coiCap
}

func (a *App) policyNow() (policy.Policy, error) {
	if a == nil {
		return policy.Policy{}, errors.New("policy is not available")
	}
	return policy.Load(policy.Options{
		Path:           a.cfg.PolicyPath,
		ManagedPath:    os.Getenv("MANAGED_POLICY"),
		EnvBind:        os.Getenv("BIND_ADDR"),
		EnvOllamaURL:   os.Getenv("OLLAMA_URL"),
		EnvOllamaModel: os.Getenv("OLLAMA_MODEL"),
	})
}

func coiName(args []string) string {
	if len(args) < 2 {
		return ""
	}
	name := strings.ToLower(strings.TrimSpace(args[1]))
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func coiRest(args []string) []string {
	if len(args) < 3 {
		return nil
	}
	return args[2:]
}

// execCOI runs one brokered CLI call. Every path audits and fails closed.
func (r *lgbRun) execCOI(ctx context.Context, args []string) (int, string) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		r.auditCOI("", nil, coi.StatusDenied, "unknown cli", "", nil, 0, false)
		return 1, "coi: unknown cli"
	}
	name := strings.ToLower(strings.TrimSpace(args[0]))
	if len(name) > 64 {
		name = name[:64]
	}
	rest := append([]string(nil), args[1:]...)
	pol, err := r.a.policyNow()
	if err != nil || (strings.TrimSpace(r.a.cfg.PolicyPath) != "" && !pol.Loaded) {
		r.auditCOI(name, rest, coi.StatusDenied, "policy is not available", "", nil, 0, false)
		return 1, "coi: policy is not available"
	}
	tool, ok := pol.COI(name)
	if !ok {
		r.auditCOI(name, rest, coi.StatusDenied, "unknown cli", "", nil, 0, false)
		return 1, "coi: unknown cli"
	}
	bot, err := r.a.st.GetBot(r.bot.ID)
	if err != nil || !tool.AllowsBot(bot.ID, bot.Name) {
		r.auditCOI(name, rest, coi.StatusDenied, "not granted", tool.CredentialHome, nil, 0, false)
		return 1, "coi: not granted"
	}
	// The turn's deny list is fixed when its settings were written. A home
	// that was not on that list is not read.
	if !r.allowsCredentialHome(tool.CredentialHome) {
		r.auditCOI(name, rest, coi.StatusDenied, "credential home is not allowed", tool.CredentialHome, nil, 0, false)
		return 1, "coi: credential home is not allowed"
	}
	// Best-effort secret list so a denial still redacts values from the
	// credential home. A read failure is denied below, after arg checks,
	// and does not consume an hourly slot.
	secrets, secErr := coi.ReadSecrets(tool.CredentialHome)
	ws := filepath.Dir(r.root)
	roots := r.argRoots(pol)
	if err := coi.CheckArgs(tool.AllowedArgs, rest, ws, tool.CredentialHome, tool.ValueFlags, roots...); err != nil {
		r.auditCOI(name, rest, coi.StatusDenied, err.Error(), tool.CredentialHome, secrets, 0, false)
		return 1, "coi: " + coi.RedactOutput(err.Error(), []string{tool.CredentialHome}, secrets)
	}
	ready, err := coi.Prepare(tool, ws)
	if err != nil {
		r.auditCOI(name, rest, coi.StatusDenied, err.Error(), tool.CredentialHome, secrets, 0, false)
		return 1, "coi: " + err.Error()
	}
	if secErr != nil {
		r.auditCOI(name, rest, coi.StatusDenied, "credential home is not available", tool.CredentialHome, nil, 0, false)
		return 1, "coi: credential home is not available"
	}
	paths := []string{tool.CredentialHome, ready.CredentialHome}
	if err := coi.JailCredentialGate(ready); err != nil {
		r.auditCOI(name, rest, coi.StatusDenied, err.Error(), tool.CredentialHome, secrets, 0, false)
		return 1, "coi: " + coi.RedactOutput(err.Error(), paths, secrets)
	}
	if coi.UsesJailCredentials(ready) {
		r.warnJailCredentials(name)
	}
	if err := coi.SandboxReady(ready.SandboxBin); err != nil {
		r.auditSandbox(name, rest, ready.CredentialHome, secrets)
		return 1, "coi: " + coi.RedactOutput(coi.ErrSandboxUnavailable.Error(), paths, secrets)
	}
	if err := coi.ProxyPreflight(ready); err != nil {
		r.auditProxy(name, rest, ready.CredentialHome, secrets)
		return 1, "coi: " + coi.RedactOutput(coi.ErrProxyUnavailable.Error(), paths, secrets)
	}
	if !r.a.coiCounter().Take(bot.ID, tool.Name, tool.MaxCallsPerHour) {
		r.auditCOI(name, rest, coi.StatusDenied, "hourly cap reached", tool.CredentialHome, secrets, 0, false)
		return 1, "coi: hourly cap reached"
	}
	perm := pol.Permission()
	res := coi.Run(ctx, coi.Call{
		Tool:      ready,
		Args:      rest,
		Workspace: ws,
		BaseEnv:   os.Environ(),
		Paths:     paths,
		Protected: roots,
		StateDir:  r.a.cfg.DataDir,
		OnPrompt: func(pctx context.Context) {
			red := make([]string, len(rest))
			for i, arg := range rest {
				red[i] = coi.RedactOutput(arg, paths, secrets)
			}
			r.noteInnerPrompt(pctx, perm, tool.Name, red)
		},
	})
	if res.Status == coi.StatusOK {
		r.auditCOI(name, rest, coi.StatusOK, "", ready.CredentialHome, secrets, res.Code, true)
		return res.Code, res.Output
	}
	msg := res.Err
	if msg == "" {
		msg = "denied"
	}
	if msg == coi.ErrSandboxUnavailable.Error() {
		r.auditSandbox(name, rest, ready.CredentialHome, secrets)
		return 1, "coi: " + coi.RedactOutput(msg, paths, secrets)
	}
	if msg == coi.ErrProxyUnavailable.Error() {
		r.auditProxy(name, rest, ready.CredentialHome, secrets)
		return 1, "coi: " + coi.RedactOutput(msg, paths, secrets)
	}
	r.auditCOI(name, rest, res.Status, msg, ready.CredentialHome, secrets, 0, false)
	return 1, "coi: " + coi.RedactOutput(msg, paths, secrets)
}

// allowsCredentialHome reports whether this turn's deny list includes home.
// A run that never wrote settings does not have a list.
func (r *lgbRun) argRoots(pol policy.Policy) []string {
	var roots []string
	if r != nil && r.a != nil {
		if dir, err := filepath.Abs(r.a.cfg.DataDir); err == nil {
			roots = append(roots, filepath.Join(dir, "coi"))
		}
	}
	for _, tool := range pol.CLITools {
		if home := strings.TrimSpace(tool.CredentialHome); home != "" {
			roots = append(roots, home)
		}
	}
	if r != nil && r.protectSet {
		roots = append(roots, r.protect...)
	}
	return roots
}

func (r *lgbRun) allowsCredentialHome(home string) bool {
	if r == nil || !r.protectSet {
		return true
	}
	return coi.Covers(r.protect, home)
}

func (r *lgbRun) auditSandbox(name string, args []string, credHome string, secrets []string) {
	r.auditCOIFailure("coi_sandbox_unavailable", coi.ErrSandboxUnavailable.Error(), name, args, credHome, secrets)
}

func (r *lgbRun) auditProxy(name string, args []string, credHome string, secrets []string) {
	r.auditCOIFailure("coi_proxy_unavailable", coi.ErrProxyUnavailable.Error(), name, args, credHome, secrets)
}

func (r *lgbRun) warnJailCredentials(name string) {
	if r == nil || r.a == nil {
		return
	}
	msg := "managed allow_jail_credentials copies credential files into the jail"
	fmt.Fprintf(os.Stderr, "local-grok-bots: coi %s: %s\n", name, msg)
	r.a.log(r.bot.ID, "coi_jail_credentials", map[string]any{
		"run_id":  r.runID,
		"cli":     name,
		"warning": msg,
	})
}

func (r *lgbRun) auditCOIFailure(event, errText, name string, args []string, credHome string, secrets []string) {
	if r == nil || r.a == nil {
		return
	}
	paths := []string{}
	if credHome != "" {
		paths = []string{credHome}
	}
	red := make([]string, 0, len(args))
	for _, a := range args {
		red = append(red, clip(coi.RedactOutput(a, paths, secrets), 500))
	}
	fields := map[string]any{
		"run_id": r.runID,
		"cli":    name,
		"args":   red,
		"status": coi.StatusDenied,
		"error":  errText,
	}
	r.a.log(r.bot.ID, event, fields)
	if r.a.audit != nil && r.a.audit.Enabled() {
		rec := map[string]any{"event": event, "bot_id": r.bot.ID}
		for k, v := range fields {
			rec[k] = v
		}
		r.a.audit.Write(rec)
	}
}

func (r *lgbRun) noteInnerPrompt(ctx context.Context, pol policy.Permission, name string, args []string) {
	if r == nil || r.a == nil || r.a.perm == nil {
		return
	}
	req := permission.Request{
		RunID:     r.runID,
		BotID:     r.bot.ID,
		Tool:      "coi:" + name,
		Transport: "coi",
		Args:      map[string]any{"argv": append([]string(nil), args...)},
	}
	// A UI wait cannot be written back into a generic CLI. Record the denial
	// instead of blocking. With UI prompts off, Evaluate denies immediately.
	if pol.UIPrompts {
		r.a.perm.Record(req, permission.Deny, "coi", "stdin-closed")
		return
	}
	_ = r.a.perm.Evaluate(ctx, pol, req)
}

func (r *lgbRun) auditCOI(name string, args []string, status, errMsg, credHome string, secrets []string, exitCode int, withExit bool) {
	if r == nil || r.a == nil {
		return
	}
	paths := []string{}
	if credHome != "" {
		paths = []string{credHome}
	}
	red := make([]string, 0, len(args))
	for _, a := range args {
		red = append(red, clip(coi.RedactOutput(a, paths, secrets), 500))
	}
	fields := map[string]any{
		"run_id": r.runID,
		"cli":    name,
		"args":   red,
		"status": status,
	}
	if errMsg != "" {
		fields["error"] = clip(coi.RedactOutput(errMsg, paths, secrets), 500)
	}
	if withExit {
		fields["exit_code"] = exitCode
	}
	r.a.log(r.bot.ID, "coi_call", fields)
	if r.a.audit != nil && r.a.audit.Enabled() {
		rec := map[string]any{"event": "coi_call", "bot_id": r.bot.ID}
		for k, v := range fields {
			rec[k] = v
		}
		r.a.audit.Write(rec)
	}
}
