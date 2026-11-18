package daemon

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// shellStillRunning is the placeholder tool result while run_shell has not
// finished. It exists only on the interim transcript copy.
const shellStillRunning = "run_shell is still running; no result yet."

// defaultEventLoopMaxInterim is how many interim model calls one run
// may start. It is a constant, not a policy key. A non-positive value is
// not "unlimited".
const defaultEventLoopMaxInterim = 5

// interimBudget is the per-run cap on interim starts and the throttle for
// capped audit rows. One run id owns one of these on the bot's loop state.
// The run goroutine is the only writer of its counters.
// refuseAll is set only when a caller passes a nil budget. That refuses
// every interim start and does not write the capped or suppressed rows.
type interimBudget struct {
	starts       int
	cappedLogged bool
	suppressed   int
	refuseAll    bool
}

// interimErrorLimit is how much of a redacted interim error the audit row keeps.
const interimErrorLimit = 200

// interimCall is one tool-less model call. Its reply is streamed and not
// stored: a later final answer is the one that stays on the thread.
type interimCall struct {
	cancel      context.CancelFunc
	ready       chan struct{}
	done        chan struct{}
	text        string
	err         error
	tokens      int
	interrupted bool
}

func (ic *interimCall) stop() {
	if ic == nil {
		return
	}
	select {
	case <-ic.ready:
	case <-ic.done:
	}
	if ic.cancel != nil {
		ic.cancel()
	}
	<-ic.done
}

func (ic *interimCall) finished() bool {
	if ic == nil {
		return true
	}
	select {
	case <-ic.done:
		return true
	default:
		return false
	}
}

// execShellAsync runs run_shell on its own context so a user message can
// wake an interim model call without cancelling the shell. Stop, the run
// deadline, and shutdown cancel both. The tool goroutine and any interim
// goroutine are joined before this returns.
func (a *App) execShellAsync(ctx context.Context, bot store.Bot, runID, name string, args map[string]any, callIndex int, msgs []model.Message, through string, seen map[string]bool, modelName string, turnPol policy.Policy, budget *interimBudget) (string, error) {
	// A nil budget is not a fresh cap. Refuse every interim start and do
	// not write the capped or suppressed rows a normal budget would write.
	if budget == nil {
		budget = &interimBudget{refuseAll: true}
	}
	toolCtx, toolCancel := context.WithCancel(ctx)
	defer toolCancel()
	defer func() {
		if budget.refuseAll {
			return
		}
		n, starts := a.takeSuppressed(budget)
		if n > 0 {
			a.log(bot.ID, "event_loop_interim_capped_suppressed", map[string]any{
				"run_id":     runID,
				"suppressed": n,
				"count":      starts,
				"cap":        a.maxInterim(),
			})
		}
	}()

	type toolOut struct {
		result string
		err    error
	}
	toolCh := make(chan toolOut, 1)
	// Arm the coalescer before the tool runs so a message that arrives as
	// soon as the shell is inside runTool still wakes this run.
	w := newQuietWindow(a.eventClock(), turnPol.EffectiveEventLoopQuiet(), turnPol.EffectiveEventLoopMaxWait())
	defer w.Stop()
	gen := a.installShellWake(bot.ID, runID, w)
	defer a.clearShellWake(bot.ID, runID, gen)
	go func() {
		result, err := a.runTool(toolCtx, bot, name, args)
		toolCh <- toolOut{result: result, err: err}
	}()

	covered := map[string]bool{}
	var pending *interimCall
	retire := func(superseded bool) {
		if pending == nil {
			return
		}
		ic := pending
		pending = nil
		a.retireInterim(bot.ID, runID, ic, superseded)
	}

	for {
		var interimDone <-chan struct{}
		if pending != nil {
			interimDone = pending.done
		}
		select {
		case out := <-toolCh:
			// The shell's result is the one that stays. Cancel a still-running
			// interim so this helper can join it. That is not a supersede.
			// retireInterim clears already-streamed tokens when the call
			// ended with an error.
			retire(false)
			return out.result, out.err
		case <-ctx.Done():
			toolCancel()
			retire(false)
			out := <-toolCh
			return out.result, out.err
		case <-interimDone:
			retire(false)
		case n := <-w.C():
			if budget.refuseAll {
				a.noteNilRefusal(bot.ID, runID)
				continue
			}
			fresh, ids := a.interimFresh(bot.ID, through, seen)
			uncovered := countUncovered(ids, covered)
			// A batch past the cap is dropped. Do not cancel an interim
			// that is already running just to refuse a new one. A
			// non-positive cap is not unlimited: it refuses the start.
			// Once the cap is reached, the window is not an
			// event_loop_batch row. A window with no new input is not a
			// skipped batch: it does not write the capped row and it does
			// not count toward the suppressed row. The first skipped batch
			// that has new input writes the single capped row and is counted.
			// Later ones only count. The suppressed row is written when the
			// shell ends, and only if a capped row was written.
			capN := a.maxInterim()
			if capN <= 0 || budget.starts >= capN || budget.cappedLogged {
				if uncovered > 0 {
					if !budget.cappedLogged {
						a.log(bot.ID, "event_loop_interim_capped", map[string]any{
							"run_id": runID,
							"count":  budget.starts,
							"cap":    capN,
						})
						budget.cappedLogged = true
					}
					a.addSuppressed(budget)
				}
				if a.interimCapSeen != nil {
					a.interimCapSeen(uncovered)
				}
				continue
			}
			a.log(bot.ID, "event_loop_batch", map[string]any{"run_id": runID, "count": n})
			if uncovered == 0 {
				continue
			}
			superseded := pending != nil && !pending.finished()
			retire(superseded)
			for _, id := range ids {
				covered[id] = true
			}
			pending = a.startInterim(ctx, bot, runID, modelName, turnPol, msgs, callIndex, fresh)
			budget.starts++
		}
	}
}

// interimBudgetFor returns the cap state for this run id. The same id,
// including an approval resume, keeps the counters. A different run id
// replaces them. The run goroutine is the only writer of those fields.
// An empty run id is not a fresh cap. It returns a refuse-all budget
// that is not stored on the bot.
func (a *App) interimBudgetFor(botID, runID string) *interimBudget {
	if a == nil || runID == "" {
		return &interimBudget{refuseAll: true}
	}
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	st := a.loops[botID]
	if st == nil {
		st = &loopState{}
		a.loops[botID] = st
	}
	if st.interim == nil || st.interimRunID != runID {
		st.interim = &interimBudget{}
		st.interimRunID = runID
	}
	return st.interim
}

func (a *App) addSuppressed(budget *interimBudget) {
	if budget == nil || budget.refuseAll {
		return
	}
	if a != nil {
		a.rtMu.Lock()
		defer a.rtMu.Unlock()
	}
	budget.suppressed++
}

func (a *App) takeSuppressed(budget *interimBudget) (n, starts int) {
	if budget == nil || budget.refuseAll {
		return 0, 0
	}
	if a != nil {
		a.rtMu.Lock()
		defer a.rtMu.Unlock()
	}
	n = budget.suppressed
	starts = budget.starts
	budget.suppressed = 0
	return n, starts
}

func (a *App) noteNilRefusal(botID, runID string) {
	if a == nil {
		return
	}
	count := 0
	a.rtMu.Lock()
	if st := a.loops[botID]; st != nil {
		st.nilRefused++
		count = st.nilRefused
	}
	a.rtMu.Unlock()
	a.log(botID, "event_loop_interim_refused", map[string]any{
		"run_id": runID,
		"count":  count,
	})
}

// interimAuditError is the class and the short message stored on an
// event_loop_interim row. The stream_reset payload does not include either.
func interimAuditError(err error) (class, msg string) {
	if err == nil {
		return "", ""
	}
	class = "model_error"
	var te *model.TimeoutError
	switch {
	case errors.As(err, &te):
		class = "timeout"
	case errors.Is(err, context.DeadlineExceeded):
		class = "timeout"
	case errors.Is(err, context.Canceled):
		class = "cancelled"
	}
	return class, clipUTF8(redactInterimErrorText(err.Error()), interimErrorLimit)
}

func redactInterimErrorText(s string) string {
	s = audit.RedactText(s)
	s = normalizeInterimPaths(s)
	s = stripInterimHosts(s)
	return stripAbsPaths(s)
}

// normalizeInterimPaths turns JSON-escaped and percent-encoded separators
// into the separators stripAbsPaths already scans.
func normalizeInterimPaths(s string) string {
	s = strings.ReplaceAll(s, `\/`, `/`)
	s = strings.ReplaceAll(s, "%2F", "/")
	s = strings.ReplaceAll(s, "%2f", "/")
	s = strings.ReplaceAll(s, "%5C", `\`)
	s = strings.ReplaceAll(s, "%5c", `\`)
	return s
}

func isPathBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r',
		'"', '\'', '`',
		'=', '(', ')',
		',', ';', ':',
		'[', ']', '<', '>',
		'{', '}',
		'|', '!', '.',
		'/', '\\', '@':
		return true
	default:
		return false
	}
}

func isPathEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', ',', ';', ')', ']', '>', '|':
		return true
	default:
		return false
	}
}

func isDrivePath(s string, i int) bool {
	if i+2 >= len(s) {
		return false
	}
	if i > 0 && !isPathBoundary(s[i-1]) {
		return false
	}
	c := s[i]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	return s[i+1] == ':' && (s[i+2] == '\\' || s[i+2] == '/')
}

// stripAbsPaths replaces absolute paths, UNC paths, tilde paths, and a
// relative home/… path. A token that begins with a slash, or a drive
// letter and a slash, is one path. '.' starts a path and does not end
// one, so a dotted absolute path stays one token.
func stripAbsPaths(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		switch {
		case isDrivePath(s, i), isUNC(s, i), isTildePath(s, i), isHomeRel(s, i):
			j := consumePath(s, i)
			b.WriteString("[path]")
			i = j
			continue
		case s[i] == '/' && (i == 0 || isPathBoundary(s[i-1])):
			j := i + 1
			for j < len(s) && !isPathEnd(s[j]) {
				j++
			}
			if j > i+1 {
				b.WriteString("[path]")
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func consumePath(s string, i int) int {
	j := i
	for j < len(s) && !isPathEnd(s[j]) {
		j++
	}
	if j == i {
		return i + 1
	}
	return j
}

func isUNC(s string, i int) bool {
	if i+2 >= len(s) || s[i] != '\\' || s[i+1] != '\\' {
		return false
	}
	if i > 0 && !isPathBoundary(s[i-1]) {
		return false
	}
	return !isPathEnd(s[i+2]) && s[i+2] != '\\'
}

func isTildePath(s string, i int) bool {
	if i+2 >= len(s) || s[i] != '~' {
		return false
	}
	if i > 0 && !isPathBoundary(s[i-1]) {
		return false
	}
	if s[i+1] != '/' && s[i+1] != '\\' {
		return false
	}
	return !isPathEnd(s[i+2])
}

func isHomeRel(s string, i int) bool {
	if i > 0 && !isPathBoundary(s[i-1]) {
		return false
	}
	rest := s[i:]
	sep := 0
	switch {
	case strings.HasPrefix(rest, "home/"):
		sep = len("home/")
	case strings.HasPrefix(rest, `home\`):
		sep = len(`home\`)
	default:
		return false
	}
	return sep < len(rest) && !isPathEnd(rest[sep])
}

var (
	dialHostRe    = regexp.MustCompile(`(?i)\bdial\s+(?:tcp|udp)6?\s+(\[[^\]]+\]|[A-Za-z0-9._-]+)(:\d+)?`)
	lookupHostRe  = regexp.MustCompile(`(?i)(\blookup\s+)(\S+)`)
	atHostRe      = regexp.MustCompile(`@([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)`)
	ipv4Re        = regexp.MustCompile(`(?:^|[^\d])((?:\d{1,3}\.){3}\d{1,3})(?:[^\d]|$)`)
	ipv6BracketRe = regexp.MustCompile(`(?i)\[((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})\]`)
	ipv6Re        = regexp.MustCompile(`(?i)(?:^|[^0-9a-f:])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?:[^0-9a-f:]|$)`)
)

// stripInterimHosts replaces IP literals and the host in lookup, dial, and
// user@host with [host]. Paths are stripped afterwards.
func stripInterimHosts(s string) string {
	s = stripDialHosts(s)
	s = replaceGroup(s, lookupHostRe, 2, func(string) bool { return true })
	s = replaceGroup(s, atHostRe, 1, func(string) bool { return true })
	s = replaceGroup(s, ipv4Re, 1, isIPv4Literal)
	s = replaceGroup(s, ipv6BracketRe, 0, func(tok string) bool {
		inner := strings.Trim(tok, "[]")
		return isIPv6Literal(inner)
	})
	s = replaceGroup(s, ipv6Re, 1, isIPv6Literal)
	return s
}

func stripDialHosts(s string) string {
	return dialHostRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := dialHostRe.FindStringSubmatch(m)
		if len(sub) < 2 || sub[1] == "" {
			return m
		}
		port := ""
		if len(sub) > 2 {
			port = sub[2]
		}
		prefix := strings.TrimSuffix(m, sub[1]+port)
		return prefix + "[host]" + port
	})
}

func replaceGroup(s string, re *regexp.Regexp, group int, keep func(string) bool) string {
	idxs := re.FindAllStringSubmatchIndex(s, -1)
	if len(idxs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	wrote := false
	for _, loc := range idxs {
		if group*2+1 >= len(loc) {
			continue
		}
		g0, g1 := loc[group*2], loc[group*2+1]
		if g0 < 0 || g1 < g0 || g0 < last {
			continue
		}
		tok := s[g0:g1]
		if keep != nil && !keep(tok) {
			continue
		}
		b.WriteString(s[last:g0])
		b.WriteString("[host]")
		last = g1
		wrote = true
	}
	if !wrote {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func isIPv4Literal(tok string) bool {
	ip := net.ParseIP(tok)
	return ip != nil && ip.To4() != nil
}

func isIPv6Literal(tok string) bool {
	if i := strings.IndexByte(tok, '%'); i >= 0 {
		tok = tok[:i]
	}
	ip := net.ParseIP(tok)
	return ip != nil && ip.To4() == nil
}

// maxInterim is the per-run cap on interim starts. A positive test override
// wins. Zero, negative, and a nil app resolve to defaultEventLoopMaxInterim.
// A non-positive result is not "unlimited": the caller refuses another start.
func (a *App) maxInterim() int {
	n := defaultEventLoopMaxInterim
	if a != nil && a.eventLoopMaxInterim > 0 {
		n = a.eventLoopMaxInterim
	}
	if n <= 0 {
		n = defaultEventLoopMaxInterim
	}
	return n
}

func (a *App) eventClock() windowClock {
	if a != nil && a.eventClk != nil {
		return a.eventClk
	}
	return realClock{}
}

// runTool is execTool unless a test installed a hook.
func (a *App) runTool(ctx context.Context, bot store.Bot, name string, args map[string]any) (string, error) {
	if a != nil && a.toolExec != nil {
		return a.toolExec(ctx, bot, name, args)
	}
	return a.execTool(ctx, bot, name, args)
}

// installShellWake arms the coalescer for this run only. The returned gen
// is what clearShellWake must pass. Zero means the hook was not installed.
func (a *App) installShellWake(botID, runID string, w *quietWindow) uint64 {
	if a == nil || w == nil || runID == "" {
		return 0
	}
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	st := a.loops[botID]
	if st == nil || !st.running || st.runID != runID {
		return 0
	}
	gen := st.gen
	st.wake = func(id string, g uint64) {
		if id != runID || g != gen {
			return
		}
		w.Notify()
	}
	st.wakeRun = runID
	st.wakeGen = gen
	return gen
}

// clearShellWake removes the hook only when it still belongs to this run.
func (a *App) clearShellWake(botID, runID string, gen uint64) {
	if a == nil || runID == "" {
		return
	}
	a.rtMu.Lock()
	defer a.rtMu.Unlock()
	st := a.loops[botID]
	if st == nil || st.wakeRun != runID || st.wakeGen != gen {
		return
	}
	st.wake = nil
	st.wakeRun = ""
	st.wakeGen = 0
}

func countUncovered(ids []string, covered map[string]bool) int {
	n := 0
	for _, id := range ids {
		if !covered[id] {
			n++
		}
	}
	return n
}

// interimFresh is the turn input foldInput would append, read only.
// It does not mark the run or the seen set.
func (a *App) interimFresh(botID, through string, seen map[string]bool) ([]model.Message, []string) {
	if a == nil || a.st == nil {
		return nil, nil
	}
	fresh, err := a.st.TurnInputSince(botID, through)
	if err != nil || len(fresh) == 0 {
		return nil, nil
	}
	names, _ := a.st.BotNames()
	var out []model.Message
	var ids []string
	for _, m := range fresh {
		if seen[m.ID] {
			continue
		}
		ids = append(ids, m.ID)
		out = append(out, mapHist(m, names))
	}
	return out, ids
}

// interimTranscript is a copy. The live transcript is not modified.
// Tool calls after the in-flight shell are omitted so every assistant
// call in the copy has a following tool message.
func interimTranscript(msgs []model.Message, callIndex int, fresh []model.Message) []model.Message {
	out := make([]model.Message, 0, len(msgs)+1+len(fresh))
	assistantAt := len(msgs) - 1 - callIndex
	if callIndex < 0 || assistantAt < 0 || assistantAt >= len(msgs) || msgs[assistantAt].Role != "assistant" {
		out = append(out, msgs...)
	} else {
		out = append(out, msgs[:assistantAt]...)
		asst := msgs[assistantAt]
		ncalls := callIndex + 1
		if ncalls > len(asst.ToolCalls) {
			ncalls = len(asst.ToolCalls)
		}
		if ncalls < 0 {
			ncalls = 0
		}
		calls := make([]model.ToolCall, ncalls)
		copy(calls, asst.ToolCalls[:ncalls])
		asst.ToolCalls = calls
		out = append(out, asst)
		out = append(out, msgs[assistantAt+1:]...)
	}
	out = append(out, model.Message{
		Role: "tool", ToolName: "run_shell", Content: shellStillRunning,
	})
	out = append(out, fresh...)
	return out
}

func (a *App) startInterim(ctx context.Context, bot store.Bot, runID, modelName string, turnPol policy.Policy, msgs []model.Message, callIndex int, fresh []model.Message) *interimCall {
	transcript := interimTranscript(msgs, callIndex, fresh)
	modelCap := turnPol.EffectiveOllamaModelTimeout()
	firstLim := turnPol.EffectiveOllamaFirstOutputTimeout()
	stallLim := turnPol.EffectiveOllamaStallTimeout()
	if modelCap > 0 && firstLim >= modelCap {
		firstLim = 0
	}
	if modelCap > 0 && stallLim >= modelCap {
		stallLim = 0
	}
	req := model.ChatRequest{
		Model:              modelName,
		Messages:           transcript,
		Tools:              nil,
		FirstOutputTimeout: firstLim,
		StallTimeout:       stallLim,
		KeepAlive:          turnPol.EffectiveOllamaKeepAlive(),
	}
	ic := &interimCall{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
	go func() {
		mctx, mcancel := a.modelCallContext(ctx, modelCap)
		ic.cancel = mcancel
		close(ic.ready)
		defer close(ic.done)
		defer mcancel()
		var text strings.Builder
		resp, err := a.model.Chat(mctx, req, func(tok string) {
			text.WriteString(tok)
			a.bus.Publish(runID, "token", map[string]string{"text": tok})
		})
		streamed := text.String()
		if err == nil && strings.TrimSpace(streamed) == "" && strings.TrimSpace(resp.Content) != "" {
			a.bus.Publish(runID, "token", map[string]string{"text": resp.Content})
			streamed = resp.Content
		}
		ic.text = streamed
		ic.err = err
		ic.tokens = resp.PromptTokens + resp.OutputTokens
		ic.interrupted = ctx.Err() != nil || errors.Is(mctx.Err(), context.Canceled)
	}()
	return ic
}

// retireInterim joins the call. Nothing it streamed is stored.
// A superseded call publishes stream_reset reason interim_superseded.
// A call interrupted by the shell finishing, Stop, the run deadline, or
// shutdown after streaming text publishes stream_reset reason
// interim_cancelled and no blank line. A genuine model error after
// streaming text publishes stream_reset reason interim_error and no
// blank line. A clean finish with text publishes the blank line and no
// reset. An empty stream publishes neither.
func (a *App) retireInterim(botID, runID string, ic *interimCall, superseded bool) {
	if ic == nil {
		return
	}
	ic.stop()
	// A call that finished on its own before the cancel landed is kept.
	if superseded && ic.err == nil {
		superseded = false
	}
	class, errText := interimAuditError(ic.err)
	a.log(botID, "event_loop_interim", map[string]any{
		"ok":          ic.err == nil && !superseded,
		"superseded":  superseded,
		"tokens":      ic.tokens,
		"error_class": class,
		"error":       errText,
	})
	streamed := strings.TrimSpace(ic.text) != ""
	if superseded {
		a.bus.Publish(runID, "stream_reset", map[string]any{"run_id": runID, "reason": "interim_superseded"})
		return
	}
	if ic.err != nil {
		if streamed {
			reason := "interim_cancelled"
			if !ic.interrupted {
				reason = "interim_error"
			}
			a.bus.Publish(runID, "stream_reset", map[string]any{"run_id": runID, "reason": reason})
		}
		return
	}
	if streamed {
		a.bus.Publish(runID, "token", map[string]string{"text": "\n\n"})
	}
}
