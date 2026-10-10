package daemon

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

type loopState struct {
	running bool
	again   bool
	runID   string
	cancel  context.CancelFunc
}

// App is the daemon: HTTP API, turn queue, timers, and the model loop.
type App struct {
	cfg    config.Config
	st     *store.Store
	model  model.Client
	ws     string
	bus    *Bus
	ctx    context.Context
	cancel context.CancelFunc

	rtMu    sync.Mutex
	loops   map[string]*loopState
	closing bool
	wg      sync.WaitGroup
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
		cfg:    cfg,
		st:     st,
		model:  m,
		ws:     cfg.Workspace(),
		bus:    NewBus(),
		ctx:    ctx,
		cancel: cancel,
		loops:  map[string]*loopState{},
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
