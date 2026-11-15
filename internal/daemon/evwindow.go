package daemon

import (
	"sync"
	"time"
)

// windowTimer is a timer the quiet window can stop. *time.Timer implements it.
// AfterFunc must not run fn before AfterFunc returns.
type windowTimer interface {
	Stop() bool
}

// windowClock is the clock the quiet window uses. Tests inject a fake.
// A nil clock on the window uses the process clock.
type windowClock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) windowTimer
}

// realClock is the process clock. model.ClockTimer is *time.Timer's Stop.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) AfterFunc(d time.Duration, fn func()) windowTimer {
	if fn == nil {
		fn = func() {}
	}
	if d < 0 {
		d = 0
	}
	return time.AfterFunc(d, fn)
}

// quietWindow batches wake-ups. The first wake-up arms a max-wait timer.
// Each wake-up restarts the quiet timer. The first of those to fire
// delivers one batch with the coalesced count, then the window resets.
// Notify is non-blocking and safe from any goroutine. Stop releases timers.
type quietWindow struct {
	clk     windowClock
	quiet   time.Duration
	maxWait time.Duration

	mu       sync.Mutex
	n        int
	armed    bool
	stopped  bool
	quietGen uint64
	maxGen   uint64
	quietT   windowTimer
	maxT     windowTimer
	ch       chan int
	spill    int
}

func newQuietWindow(clk windowClock, quiet, maxWait time.Duration) *quietWindow {
	if clk == nil {
		clk = realClock{}
	}
	if quiet <= 0 {
		quiet = 500 * time.Millisecond
	}
	if maxWait < quiet {
		maxWait = quiet
	}
	return &quietWindow{
		clk:     clk,
		quiet:   quiet,
		maxWait: maxWait,
		ch:      make(chan int, 1),
	}
}

// C delivers one batch at a time. The value is how many wake-ups coalesced.
// Stop does not close it.
func (w *quietWindow) C() <-chan int {
	if w == nil {
		return nil
	}
	return w.ch
}

// Notify records one wake-up. It does not block.
func (w *quietWindow) Notify() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.n++
	if !w.armed {
		w.armed = true
		w.maxGen++
		gen := w.maxGen
		w.maxT = w.clk.AfterFunc(w.maxWait, func() { w.onMax(gen) })
	}
	w.quietGen++
	gen := w.quietGen
	if w.quietT != nil {
		w.quietT.Stop()
		w.quietT = nil
	}
	w.quietT = w.clk.AfterFunc(w.quiet, func() { w.onQuiet(gen) })
}

func (w *quietWindow) onQuiet(gen uint64) { w.finish(false, gen) }

func (w *quietWindow) onMax(gen uint64) { w.finish(true, gen) }

func (w *quietWindow) finish(max bool, gen uint64) {
	w.mu.Lock()
	if w.stopped || !w.armed || w.n == 0 {
		w.mu.Unlock()
		return
	}
	if max {
		if gen != w.maxGen {
			w.mu.Unlock()
			return
		}
	} else if gen != w.quietGen {
		w.mu.Unlock()
		return
	}
	n := w.disarmLocked()
	w.mu.Unlock()
	w.deliver(n)
}

// disarmLocked drops the armed window and stops both timers.
// The caller holds w.mu. The returned count is the coalesced wake-ups.
func (w *quietWindow) disarmLocked() int {
	n := w.n
	w.n = 0
	w.armed = false
	w.quietGen++
	w.maxGen++
	w.stopTimersLocked()
	return n
}

func (w *quietWindow) stopTimersLocked() {
	if w.quietT != nil {
		w.quietT.Stop()
		w.quietT = nil
	}
	if w.maxT != nil {
		w.maxT.Stop()
		w.maxT = nil
	}
}

// Stop drops any armed timers. Later Notify calls do nothing.
// A batch already in C stays readable.
func (w *quietWindow) Stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	w.n = 0
	w.armed = false
	w.quietGen++
	w.maxGen++
	w.stopTimersLocked()
}

// deliver merges n into the single buffered batch so a slow reader
// cannot lose a count and the timer callback does not block.
func (w *quietWindow) deliver(n int) {
	if w == nil || n <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.spill += n
	select {
	case prev := <-w.ch:
		w.spill += prev
	default:
	}
	select {
	case w.ch <- w.spill:
		w.spill = 0
	default:
	}
}
