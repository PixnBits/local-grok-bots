package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/coi"
	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// resumeHold is one capped run's model transcript, including tool results.
// The thread does not store those, so a later user message cannot rebuild it.
type resumeHold struct {
	runID string
	msgs  []model.Message
}

type loopState struct {
	running  bool
	again    bool
	runID    string
	cancel   context.CancelFunc
	cliPID   int
	idleKill bool
	// released is closed when running is cleared. Stored status goes idle
	// before that, so a waiter on status can still observe the loop running.
	released chan struct{}
}

// App is the daemon: HTTP API, turn queue, timers, and the model loop.
type App struct {
	cfg config.Config
	// logw receives startup lines. Nil means stderr.
	logw   io.Writer
	st     *store.Store
	model  model.Client
	ws     string
	bus    *Bus
	policy policy.Policy
	perm   *permission.Broker
	// permBase is the HTTP origin the CLI calls back, such as http://127.0.0.1:8787.
	// Empty means there is no permission host. A headless prompt still fails closed.
	permBase   string
	permMu     sync.Mutex
	permTokens map[string]permBind
	// lgbLive holds per-run lgb tokens until that run's spool stops.
	// They are not the admin token and cannot decide a permission card.
	// The value is the bot and run the token was issued for.
	lgbMu   sync.Mutex
	lgbLive map[string]lgbCred
	// authTokens is the named set from AUTH_TOKENS_FILE.
	// cfg.AuthToken, when set, is the additional name "default".
	// Reload replaces the pointer; readers load it.
	authTokens atomic.Pointer[authTokenSet]
	// protectByBot is the path deny list written for the bot's current turn.
	// The broker will not use a credential home that is absent from it.
	protectMu    sync.Mutex
	protectByBot map[string][]string
	// protectSnap is the startup inode snapshot. A successful token reload
	// appends paths that were not already recorded and does not replace
	// device or inode values. protectTrip latches the first failure until
	// the process exits.
	protectSnap atomic.Pointer[protectSnap]
	protectTrip atomic.Pointer[protectTripState]
	// coiCap counts brokered host-CLI calls per bot.
	coiOnce sync.Once
	coiCap  *coi.HourCap
	// noGrokProxy skips the Grok CLI credential proxy. Tests set it so they
	// do not read the host login. Production leaves it false.
	noGrokProxy bool
	grokMu      sync.Mutex
	grokProxy   *coi.Egress
	// grokGates are live loopback secrets for each bot. credMu is held while
	// a gate is added and while a bot's gates are released.
	grokGates map[string][]*gateHold
	// grokTrip, when set, replaces the loopback proxy's outbound transport.
	// Tests use it. Production leaves it nil.
	grokTrip http.RoundTripper
	// credMu serializes a Grok placeholder write with deletion of that file.
	credMu sync.Mutex
	// goneBots are ids that must not get a new Grok login file.
	goneBots sync.Map
	// runner, when set, replaces the real CLI exec. Tests use it.
	runner clisession.Runner
	// cliTTY, when set, overrides /dev/tty detection for permission prompts.
	cliTTY func() bool
	audit  *audit.Logger
	// shellDial, when set, is the sandbox proxy's outbound dial. Tests use it.
	shellDial func(context.Context, string, string) (net.Conn, error)
	// githubGitBase and githubAPIBase replace the GitHub upstreams. Tests set them.
	githubGitBase string
	githubAPIBase string
	// githubReadSock is the jail read-proxy socket for a bot's live shell.
	// githubWriteUp is true only while a post-approval write proxy is listening.
	githubReadSock map[string]string
	githubWriteUp  atomic.Bool
	ctx            context.Context
	cancel         context.CancelFunc

	rtMu sync.Mutex
	// turns counts bot- and timer-started turns per bot (turncap.go).
	turnsOnce sync.Once
	turns     *botTurns
	// permSeen is each live run's stored permission decisions, so a CLI
	// denial report for a request the broker already decided adds nothing.
	seenMu   sync.Mutex
	permSeen map[string]*runPerms
	// loginChecked holds bot ids whose Claude login source was recorded.
	loginChecked sync.Map
	loops        map[string]*loopState
	resume       map[string]resumeHold
	pending      map[string][]model.Message
	activity     map[string]time.Time
	closing      bool
	wg           sync.WaitGroup
}

// logOut is copied onto each App as the startup writer. Nil means stderr.
var logOut io.Writer

func New(cfg config.Config, m model.Client) (*App, error) {
	pol, err := policy.Load(policy.Options{
		Path:           cfg.PolicyPath,
		ManagedPath:    os.Getenv("MANAGED_POLICY"),
		EnvBind:        os.Getenv("BIND_ADDR"),
		EnvOllamaURL:   os.Getenv("OLLAMA_URL"),
		EnvOllamaModel: os.Getenv("OLLAMA_MODEL"),
	})
	if err != nil {
		return nil, err
	}
	for _, w := range pol.Warnings {
		fmt.Fprintf(os.Stderr, "local-grok-bots: %s\n", w)
	}
	if w := sandbox.RootJailWarning(); w != "" {
		fmt.Fprintf(os.Stderr, "local-grok-bots: %s\n", w)
	}
	if pol.HasBind {
		cfg.BindAddr = pol.Bind
	}
	if pol.HasOllamaHost {
		cfg.OllamaURL = pol.OllamaHost
	}
	if pol.HasOllamaModel {
		cfg.Model = pol.OllamaModel
	}
	// Every start, including an existing admin token, AUTH_TOKEN, and
	// Ollama-only. ensureAdminToken returns before this check when a token
	// is already present.
	if err := prepareAdminDir(cfg.DataDir); err != nil {
		return nil, err
	}
	tok, tokPath, err := ensureAdminToken(cfg.DataDir, cfg.AuthToken, pol.UsesCLI())
	if err != nil {
		return nil, err
	}
	if tokPath != "" {
		cfg.AuthToken = tok
		fmt.Fprintf(os.Stderr, "local-grok-bots: a CLI backend is enabled, so the API requires a token; it is in %s. Open /login?token=<token> once per browser.\n", tokPath)
	}
	fileTokens, err := readAuthTokenSet(cfg, cfg.AuthToken)
	if err != nil {
		return nil, err
	}
	if err := checkPathOverlaps(cfg, pol); err != nil {
		return nil, err
	}
	logw := logOut
	if logw == nil {
		logw = os.Stderr
	}
	if cfg.AuthToken == "" && len(fileTokens) == 0 && !loopbackBind(cfg.BindAddr) {
		fmt.Fprint(logw, bindWarn)
	}
	aud, err := audit.Open(pol.AuditLog)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		_ = aud.Close()
		return nil, err
	}
	procs, err := st.ReconcileOnBoot(cfg.Version, pol.UsesCLI())
	if err != nil {
		st.Close()
		_ = aud.Close()
		return nil, err
	}
	for _, proc := range procs {
		clisession.KillStoredCLI(clisession.StoredCLI{
			PID: proc.PID, PGID: proc.PGID, Start: proc.Start, Exe: proc.Exe, Marker: proc.Marker,
		})
		_ = st.ClearCLIProc(proc.BotID)
	}
	if m == nil {
		m = model.NewOllama(cfg.OllamaURL)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{
		cfg:        cfg,
		logw:       logw,
		st:         st,
		model:      m,
		ws:         cfg.Workspace(),
		bus:        NewBus(),
		policy:     pol,
		audit:      aud,
		ctx:        ctx,
		cancel:     cancel,
		loops:      map[string]*loopState{},
		resume:     map[string]resumeHold{},
		pending:    map[string][]model.Message{},
		activity:   map[string]time.Time{},
		permTokens: map[string]permBind{},
		permBase:   httpBase(cfg.BindAddr),
	}
	if len(fileTokens) > 0 {
		a.authTokens.Store(&authTokenSet{toks: fileTokens})
	}
	a.perm = permission.New(permission.Options{
		Publish: func(runID, event string, payload any) {
			if event == "permission_decision" {
				a.recordPermission(payload)
			}
			a.bus.Publish(runID, event, payload)
		},
		Audit: func(fields map[string]any) {
			if a.audit != nil && a.audit.Enabled() {
				a.audit.Write(fields)
			}
		},
	})
	coi.CleanStaleHomes(cfg.DataDir)
	if err := a.scrubHostGrokLogins(); err != nil {
		st.Close()
		_ = aud.Close()
		cancel()
		return nil, err
	}
	if err := mkdirWorkspace(a.ws); err != nil {
		st.Close()
		_ = aud.Close()
		cancel()
		return nil, err
	}
	a.RefreshProtectSnapshot()
	a.wg.Add(1)
	go a.timerLoop()
	bots, err := st.ListBots()
	if err != nil {
		a.Shutdown()
		return nil, err
	}
	for _, b := range bots {
		if b.Status != "paused" {
			a.kick(b.ID)
		}
	}
	return a, nil
}

func mkdirWorkspace(path string) error {
	return mkdir(path)
}

// Shutdown stops timers and runs, records daemon_stop, and closes the database.
func (a *App) Shutdown() {
	a.rtMu.Lock()
	if a.closing {
		a.rtMu.Unlock()
		return
	}
	a.closing = true
	a.rtMu.Unlock()
	a.cancel()
	a.wg.Wait()
	a.closeGrokProxy()
	_ = a.st.FailRunning("shutdown")
	_ = a.st.AddLog("", "daemon_stop", map[string]any{})
	_ = a.st.Close()
	if a.audit != nil {
		_ = a.audit.Close()
	}
}

// Run serves HTTP until ctx is cancelled, then shuts down cleanly.
func (a *App) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", a.cfg.BindAddr)
	if err != nil {
		a.Shutdown()
		return err
	}
	a.writeStartup("local-grok-bots %s listening on %s\n", a.cfg.Version, ln.Addr().String())
	srv := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
		a.Shutdown()
		return nil
	case err := <-errCh:
		a.Shutdown()
		return err
	}
}

func (a *App) writeStartup(format string, args ...any) {
	w := io.Writer(os.Stderr)
	if a != nil && a.logw != nil {
		w = a.logw
	}
	fmt.Fprintf(w, format, args...)
}

// bindWarn is the one startup line for a non-loopback bind when neither
// AUTH_TOKEN, the generated admin token, nor AUTH_TOKENS_FILE supplies a token.
const bindWarn = "local-grok-bots: WARN: the API is reachable beyond this machine without AUTH_TOKEN or AUTH_TOKENS_FILE; set AUTH_TOKEN, AUTH_TOKENS_FILE, or a loopback BIND_ADDR\n"

// loopbackBind reports whether addr's host is 127.0.0.0/8, ::1, or localhost.
// An empty host is not loopback.
func loopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		host = strings.TrimSpace(addr)
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *App) timerLoop() {
	defer a.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
			a.fireDue()
			a.killIdle()
		}
	}
}

func (a *App) fireDue() {
	if a.ctx.Err() != nil {
		return
	}
	a.rtMu.Lock()
	enabled := a.policy.TimersEnabled
	a.rtMu.Unlock()
	if !enabled {
		return
	}
	due, err := a.st.ClaimDueTimers(time.Now().UTC())
	if err != nil {
		return
	}
	for _, tm := range due {
		a.log(tm.BotID, "timer_fired", map[string]any{
			"timer_id": tm.ID, "scheduled_for": tm.NextFireAt,
		})
		if _, err := a.st.AddMessage(store.Message{
			BotID: tm.BotID, Thread: "user", Role: "system", Content: tm.Prompt,
		}); err != nil {
			continue
		}
		a.noteScheduledTurn(tm.BotID)
		a.kick(tm.BotID)
	}
}

func (a *App) log(botID, kind string, detail any) {
	if kind == "sandbox_block" {
		detail = clipSandboxDetail(detail)
	}
	_ = a.st.AddLog(botID, kind, detail)
	if kind == "sandbox_block" {
		a.auditSandboxBlock(botID, detail)
	}
}

// clipASCII keeps bytes in 0x20–0x7E and then cuts to 256 bytes.
func clipASCII(s string) string {
	const max = 256
	var b strings.Builder
	n := 0
	for i := 0; i < len(s) && n < max; i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			continue
		}
		b.WriteByte(c)
		n++
	}
	return b.String()
}

func clipSandboxDetail(detail any) any {
	switch v := detail.(type) {
	case string:
		return clipASCII(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = val
		}
		if s, ok := out["detail"].(string); ok {
			out["detail"] = clipASCII(s)
		}
		if s, ok := out["path"].(string); ok {
			out["path"] = clipASCII(s)
		}
		return out
	default:
		return detail
	}
}

// auditSandboxBlock mirrors a sandbox_block row into the audit log when
// audit is enabled. detail is the path text already logged, never file bytes.
func (a *App) auditSandboxBlock(botID string, detail any) {
	if a == nil || a.audit == nil || !a.audit.Enabled() {
		return
	}
	rec := map[string]any{"action": "sandbox_block"}
	if botID != "" {
		rec["bot_id"] = botID
	}
	if d := sandboxBlockDetail(detail); d != "" {
		rec["detail"] = d
	}
	a.audit.Write(rec)
}

func sandboxBlockDetail(detail any) string {
	switch v := detail.(type) {
	case string:
		return v
	case map[string]any:
		if s, ok := v["detail"].(string); ok && s != "" {
			return s
		}
		if s, ok := v["path"].(string); ok {
			return s
		}
	}
	return ""
}

// kick starts a run if the bot is idle and has pending messages.
// If a run is already going, the message stays queued and the current run id
// is returned. Empty means no run was started.
func (a *App) kick(botID string) string {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	return a.kickLocked(botID)
}

func (a *App) kickLocked(botID string) string {
	if a.closing {
		return ""
	}
	bot, err := a.st.GetBot(botID)
	// An archived bot keeps its queue; restoring it kicks a run.
	if err != nil || bot.Status == "paused" || bot.Archived {
		return ""
	}
	st := a.loops[botID]
	if st == nil {
		st = &loopState{}
		a.loops[botID] = st
	}
	if st.running {
		st.again = true
		return st.runID
	}
	need, err := a.st.NeedsRun(botID)
	if err != nil || !need {
		return ""
	}
	run, err := a.st.CreateRun(botID)
	if err != nil {
		return ""
	}
	if err := a.st.SetStatus(botID, "running"); err != nil {
		_, _ = a.st.FinishRun(run.ID, "error", err.Error())
		return ""
	}
	st.running = true
	st.runID = run.ID
	st.again = false
	st.released = make(chan struct{})
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.loop(botID, run.ID)
	}()
	return run.ID
}

// continueRun starts a new run on a capped transcript. It does not go through
// NeedsRun: there is no new user message, and the capped run stays finished.
// Running is checked before the offer is taken, so a second continue cannot
// discard the transcript the first one is already using.
func (a *App) continueRun(botID, fromRun string) (string, int, error) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if a.closing {
		return "", http.StatusConflict, errors.New("shutting down")
	}
	bot, err := a.st.GetBot(botID)
	if err != nil {
		return "", http.StatusNotFound, errors.New("not found")
	}
	if bot.Status == "paused" {
		return "", http.StatusConflict, errors.New("bot is paused")
	}
	st := a.loops[botID]
	if st != nil && st.running {
		return "", http.StatusConflict, errors.New("bot is running")
	}
	offer, ok := a.resume[botID]
	if !ok || offer.runID != fromRun || fromRun == "" {
		return "", http.StatusNotFound, errors.New("not found")
	}
	delete(a.resume, botID)
	run, err := a.st.CreateRun(botID)
	if err != nil {
		a.resume[botID] = offer
		return "", http.StatusInternalServerError, err
	}
	if err := a.st.SetStatus(botID, "running"); err != nil {
		_, _ = a.st.FinishRun(run.ID, "error", err.Error())
		a.resume[botID] = offer
		return "", http.StatusInternalServerError, err
	}
	a.pending[run.ID] = offer.msgs
	if st == nil {
		st = &loopState{}
		a.loops[botID] = st
	}
	st.running = true
	st.runID = run.ID
	st.again = false
	st.released = make(chan struct{})
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.loop(botID, run.ID)
	}()
	return run.ID, http.StatusOK, nil
}

// retryRun starts a new run of the latest timed-out turn without the partial
// reply or its notice. The user message stays, so the same turn is answered
// again. The resume offer is dropped.
func (a *App) retryRun(botID, fromRun string) (string, int, error) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if a.closing {
		return "", http.StatusConflict, errors.New("shutting down")
	}
	bot, err := a.st.GetBot(botID)
	if err != nil {
		return "", http.StatusNotFound, errors.New("not found")
	}
	if bot.Status == "paused" {
		return "", http.StatusConflict, errors.New("bot is paused")
	}
	if bot.Status == "running" {
		return "", http.StatusConflict, errors.New("bot is running")
	}
	st := a.loops[botID]
	if st != nil && st.running {
		return "", http.StatusConflict, errors.New("bot is running")
	}
	run, err := a.st.GetRun(fromRun)
	if err != nil || run.BotID != botID {
		return "", http.StatusNotFound, errors.New("not found")
	}
	latest, err := a.st.LatestRun(botID)
	if err != nil || latest.ID != fromRun {
		return "", http.StatusNotFound, errors.New("not found")
	}
	if run.Status != "timeout" {
		return "", http.StatusNotFound, errors.New("not found")
	}
	offer, hadOffer := a.resume[botID]
	delete(a.resume, botID)
	newRun, err := a.st.CreateRun(botID)
	if err != nil {
		if hadOffer {
			a.resume[botID] = offer
		}
		return "", http.StatusInternalServerError, err
	}
	if err := a.st.SetStatus(botID, "running"); err != nil {
		_, _ = a.st.FinishRun(newRun.ID, "error", err.Error())
		if hadOffer {
			a.resume[botID] = offer
		}
		return "", http.StatusInternalServerError, err
	}
	if err := a.st.DeleteRunOutput(botID, fromRun); err != nil {
		_, _ = a.st.FinishRun(newRun.ID, "error", err.Error())
		_ = a.st.SetStatus(botID, "idle")
		if hadOffer {
			a.resume[botID] = offer
		}
		return "", http.StatusInternalServerError, err
	}
	if st == nil {
		st = &loopState{}
		a.loops[botID] = st
	}
	st.running = true
	st.runID = newRun.ID
	st.again = false
	st.released = make(chan struct{})
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.loop(botID, newRun.ID)
	}()
	return newRun.ID, http.StatusOK, nil
}

func (a *App) holdResume(botID, runID string, msgs []model.Message) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	a.resume[botID] = resumeHold{runID: runID, msgs: cloneMsgs(msgs)}
}

func (a *App) dropResume(botID string) {
	a.rtMu.Lock()
	delete(a.resume, botID)
	a.rtMu.Unlock()
}

func (a *App) takePending(runID string) ([]model.Message, bool) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	msgs, ok := a.pending[runID]
	if ok {
		delete(a.pending, runID)
	}
	return msgs, ok
}

func cloneMsgs(in []model.Message) []model.Message {
	out := make([]model.Message, len(in))
	copy(out, in)
	return out
}

func (a *App) decorateBot(b store.Bot) store.Bot {
	b.PendingPermissions = a.perm.PendingCounts()[b.ID]
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if h, ok := a.resume[b.ID]; ok {
		b.ContinueRunID = h.runID
	}
	b.Warnings = descriptionWarnings(b.Description)
	return b
}

func (a *App) decorateBots(bots []store.Bot) []store.Bot {
	counts := a.perm.PendingCounts()
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	for i := range bots {
		bots[i].PendingPermissions = counts[bots[i].ID]
		if h, ok := a.resume[bots[i].ID]; ok {
			bots[i].ContinueRunID = h.runID
		}
	}
	return bots
}

func (a *App) loop(botID, runID string) {
	current := runID
	for {
		a.execute(botID, current)
		if a.ctx.Err() != nil {
			break
		}
		bot, err := a.st.GetBot(botID)
		if err != nil || bot.Status == "paused" {
			break
		}
		again := a.consumeAgain(botID)
		need, err := a.st.NeedsRun(botID)
		if err != nil || !need {
			if again {
				// A message may have landed between the check and the flag.
				need, _ = a.st.NeedsRun(botID)
			}
			if !need {
				break
			}
		}
		run, err := a.st.CreateRun(botID)
		if err != nil {
			break
		}
		a.rtMu.Lock()
		if st := a.loops[botID]; st != nil {
			st.runID = run.ID
		}
		a.rtMu.Unlock()
		current = run.ID
	}
	a.endLoop(botID)
}

func (a *App) consumeAgain(botID string) bool {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	st := a.loops[botID]
	if st == nil {
		return false
	}
	v := st.again
	st.again = false
	return v
}

func (a *App) endLoop(botID string) {
	if b, err := a.st.GetBot(botID); err == nil && b.Status == "running" {
		_ = a.st.SetStatus(botID, "idle")
	}
	a.rtMu.Lock()
	st := a.loops[botID]
	again := false
	if st != nil {
		again = st.again
		st.running = false
		st.again = false
		st.runID = ""
		st.cancel = nil
		if st.released != nil {
			close(st.released)
			st.released = nil
		}
	}
	a.rtMu.Unlock()
	if again && a.ctx.Err() == nil {
		a.kick(botID)
	}
}

func (a *App) cancelBot(botID string) {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if st := a.loops[botID]; st != nil && st.cancel != nil {
		st.cancel()
	}
}
