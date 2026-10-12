package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// resumeHold is one capped run's model transcript, including tool results.
// The thread does not store those, so a later user message cannot rebuild it.
type resumeHold struct {
	runID string
	msgs  []model.Message
}

type loopState struct {
	running bool
	again   bool
	runID   string
	cancel  context.CancelFunc
	cliPID  int
}

// App is the daemon: HTTP API, turn queue, timers, and the model loop.
type App struct {
	cfg   config.Config
	st    *store.Store
	model model.Client
	// runner executes grok/claude turns. Nil uses clisession.ExecRunner.
	runner clisession.Runner
	ws     string
	bus    *Bus
	// shellDial, when set, is the sandbox proxy's outbound dial. Tests use it.
	shellDial func(context.Context, string, string) (net.Conn, error)
	ctx       context.Context
	cancel    context.CancelFunc

	rtMu    sync.Mutex
	loops   map[string]*loopState
	resume  map[string]resumeHold
	pending map[string][]model.Message
	// activity is the last user message or CLI turn start. Idle kill reads it.
	activity map[string]time.Time
	// idleAfter caps a live CLI after the last activity. Zero means 30 minutes.
	idleAfter time.Duration
	// imminent is how soon a timer must fire to spare a live CLI. Zero means 2 minutes.
	imminent time.Duration
	// notifyFn overrides desktop notifications. Nil uses the OS notifier.
	notifyFn func(title, body string)
	closing  bool
	wg       sync.WaitGroup
}

func New(cfg config.Config, m model.Client) (*App, error) {
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return nil, err
	}
	if err := st.ReconcileOnBoot(cfg.Version); err != nil {
		st.Close()
		return nil, err
	}
	if m == nil {
		m = model.NewOllama(cfg.OllamaURL)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{
		cfg:     cfg,
		st:      st,
		model:   m,
		ws:      cfg.Workspace(),
		bus:     NewBus(),
		ctx:     ctx,
		cancel:  cancel,
		loops:   map[string]*loopState{},
		resume:  map[string]resumeHold{},
		pending: map[string][]model.Message{},
	}
	if err := mkdirWorkspace(a.ws); err != nil {
		st.Close()
		cancel()
		return nil, err
	}
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
	a.closing = true
	a.rtMu.Unlock()
	a.cancel()
	a.wg.Wait()
	_ = a.st.FailRunning("shutdown")
	_ = a.st.AddLog("", "daemon_stop", map[string]any{})
	_ = a.st.Close()
}

// Run serves HTTP until ctx is cancelled, then shuts down cleanly.
func (a *App) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              a.cfg.BindAddr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
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
		a.kick(tm.BotID)
	}
}

func (a *App) log(botID, kind string, detail any) {
	_ = a.st.AddLog(botID, kind, detail)
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
	if err != nil || bot.Status == "paused" {
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
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.loop(botID, run.ID)
	}()
	return run.ID, http.StatusOK, nil
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
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	if h, ok := a.resume[b.ID]; ok {
		b.ContinueRunID = h.runID
	}
	return b
}

func (a *App) decorateBots(bots []store.Bot) []store.Bot {
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	for i := range bots {
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
