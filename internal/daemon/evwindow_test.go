package daemon

import (
	"sync"
	"testing"
	"time"
)

// manualClock is a test clock. Advance fires due timers synchronously,
// earliest deadline first. AfterFunc does not run the callback itself.
type manualClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*manualTimer
	seq    uint64
}

type manualTimer struct {
	clk     *manualClock
	when    time.Time
	seq     uint64
	fn      func()
	stopped bool
	fired   bool
}

func newManualClock() *manualClock {
	return &manualClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) AfterFunc(d time.Duration, fn func()) windowTimer {
	if fn == nil {
		fn = func() {}
	}
	if d < 0 {
		d = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	t := &manualTimer{clk: c, when: c.now.Add(d), seq: c.seq, fn: fn}
	c.timers = append(c.timers, t)
	return t
}

func (t *manualTimer) Stop() bool {
	if t == nil || t.clk == nil {
		return false
	}
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	if t.stopped || t.fired {
		return false
	}
	t.stopped = true
	return true
}

// Advance moves the clock forward by d and runs every timer that is due,
// in deadline order. A callback may arm another timer; that timer fires
// in this same call when it is already due.
func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d < 0 {
		d = 0
	}
	c.now = c.now.Add(d)
	c.fireDue()
}

func (c *manualClock) fireDue() {
	for {
		idx := -1
		for i, t := range c.timers {
			if t == nil || t.stopped || t.fired {
				continue
			}
			if t.when.After(c.now) {
				continue
			}
			if idx < 0 || t.when.Before(c.timers[idx].when) || (t.when.Equal(c.timers[idx].when) && t.seq < c.timers[idx].seq) {
				idx = i
			}
		}
		if idx < 0 {
			return
		}
		t := c.timers[idx]
		t.fired = true
		fn := t.fn
		c.mu.Unlock()
		fn()
		c.mu.Lock()
	}
}

func (c *manualClock) active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t != nil && !t.stopped && !t.fired {
			n++
		}
	}
	return n
}

func pollBatch(w *quietWindow) (int, bool) {
	select {
	case n := <-w.C():
		return n, true
	default:
		return 0, false
	}
}

func TestQuietWindowQuietOnlyBatches(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	w.Notify()
	w.Notify()
	w.Notify()
	clk.Advance(499 * time.Millisecond)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("batch at 499ms: %d", n)
	}
	clk.Advance(time.Millisecond)
	n, ok := pollBatch(w)
	if !ok || n != 3 {
		t.Fatalf("batch = %d ok %v, want 3", n, ok)
	}
	if _, ok := pollBatch(w); ok {
		t.Fatal("second batch")
	}
}

func TestQuietWindowSecondEventExtends(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	w.Notify()
	clk.Advance(400 * time.Millisecond)
	if _, ok := pollBatch(w); ok {
		t.Fatal("fired before the second event")
	}
	w.Notify()
	clk.Advance(499 * time.Millisecond)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("fired 499ms after the second event: %d", n)
	}
	clk.Advance(time.Millisecond)
	n, ok := pollBatch(w)
	if !ok || n != 2 {
		t.Fatalf("extended batch = %d ok %v, want 2", n, ok)
	}
}

func TestQuietWindowMaxWaitCeiling(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	w.Notify()
	var elapsed time.Duration
	var count int
	for elapsed < 2*time.Second {
		step := 100 * time.Millisecond
		if elapsed+step > 2*time.Second {
			step = 2*time.Second - elapsed
		}
		clk.Advance(step)
		elapsed += step
		if n, ok := pollBatch(w); ok {
			count = n
			break
		}
		w.Notify()
	}
	if elapsed != 2*time.Second || count < 2 {
		t.Fatalf("max wait fired at %s with count %d", elapsed, count)
	}
	// The ceiling closed the batch. A later quiet period does not add another
	// until a new wake-up.
	clk.Advance(time.Second)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("extra batch %d", n)
	}
}

func TestQuietWindowMaxBoundary(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	w.Notify()
	elapsed := time.Duration(0)
	for elapsed < 1999*time.Millisecond {
		step := 100 * time.Millisecond
		if elapsed+step > 1999*time.Millisecond {
			step = 1999*time.Millisecond - elapsed
		}
		clk.Advance(step)
		elapsed += step
		if n, ok := pollBatch(w); ok {
			t.Fatalf("fired at %s: %d", elapsed, n)
		}
		w.Notify()
	}
	clk.Advance(time.Millisecond)
	n, ok := pollBatch(w)
	if !ok || n < 1 {
		t.Fatalf("2000ms batch = %d ok %v", n, ok)
	}
}

func TestQuietWindowResetAfterFire(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	w.Notify()
	clk.Advance(500 * time.Millisecond)
	n, ok := pollBatch(w)
	if !ok || n != 1 {
		t.Fatalf("first batch = %d ok %v", n, ok)
	}
	clk.Advance(2 * time.Second)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("batch without a new event: %d", n)
	}
	w.Notify()
	clk.Advance(499 * time.Millisecond)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("early second batch %d", n)
	}
	clk.Advance(time.Millisecond)
	n, ok = pollBatch(w)
	if !ok || n != 1 {
		t.Fatalf("reset batch = %d ok %v, want 1", n, ok)
	}
}

func TestQuietWindowStopReleasesTimers(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	w.Notify()
	if clk.active() == 0 {
		t.Fatal("no timers armed")
	}
	w.Stop()
	if clk.active() != 0 {
		t.Fatalf("timers still armed: %d", clk.active())
	}
	clk.Advance(5 * time.Second)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("batch after stop: %d", n)
	}
	w.Notify()
	clk.Advance(5 * time.Second)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("notify after stop delivered %d", n)
	}
}

func TestQuietWindowNoEventNoBatch(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	clk.Advance(5 * time.Second)
	if n, ok := pollBatch(w); ok {
		t.Fatalf("batch with no event: %d", n)
	}
	if clk.active() != 0 {
		t.Fatalf("timers without an event: %d", clk.active())
	}
}

func TestQuietWindowMergesUnread(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	for i := 0; i < 3; i++ {
		w.Notify()
		clk.Advance(500 * time.Millisecond)
	}
	n, ok := pollBatch(w)
	if !ok || n != 3 {
		t.Fatalf("merged batch = %d ok %v, want 3", n, ok)
	}
	if _, ok := pollBatch(w); ok {
		t.Fatal("split batch")
	}
}

func TestQuietWindowConcurrentNotify(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	defer w.Stop()
	var wg sync.WaitGroup
	const goroutines = 8
	const each = 20
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				w.Notify()
			}
		}()
	}
	wg.Wait()
	clk.Advance(500 * time.Millisecond)
	n, ok := pollBatch(w)
	if !ok || n != goroutines*each {
		t.Fatalf("concurrent batch = %d ok %v, want %d", n, ok, goroutines*each)
	}
}

func TestTesterEvWindowMaxCeilingAfterReset(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	for round := 0; round < 3; round++ {
		w.Notify()
		var elapsed time.Duration
		for elapsed+300*time.Millisecond < 2*time.Second {
			clk.Advance(300 * time.Millisecond)
			elapsed += 300 * time.Millisecond
			w.Notify()
			if _, ok := pollBatch(w); ok {
				t.Fatalf("round %d early batch at %v", round, elapsed)
			}
		}
		clk.Advance(2*time.Second - elapsed)
		if _, ok := pollBatch(w); !ok {
			t.Fatalf("round %d: no max batch at 2s after first notify (elapsed %v)", round, elapsed)
		}
	}
	w.Stop()
}

func TestTesterEvWindowMaxCeilingExact(t *testing.T) {
	clk := newManualClock()
	w := newQuietWindow(clk, 500*time.Millisecond, 2*time.Second)
	w.Notify()
	var elapsed time.Duration
	for elapsed < 2*time.Second-499*time.Millisecond {
		clk.Advance(499 * time.Millisecond)
		elapsed += 499 * time.Millisecond
		w.Notify()
		if _, ok := pollBatch(w); ok {
			t.Fatalf("batch fired early at %v", elapsed)
		}
	}
	clk.Advance(2*time.Second - elapsed - time.Nanosecond)
	if _, ok := pollBatch(w); ok {
		t.Fatal("fired at 2s-1ns")
	}
	clk.Advance(time.Nanosecond)
	n, ok := pollBatch(w)
	if !ok {
		t.Fatal("no batch at exactly 2s")
	}
	if n < 4 {
		t.Fatalf("coalesced count %d", n)
	}
	w.Notify()
	clk.Advance(500*time.Millisecond - time.Nanosecond)
	if _, ok := pollBatch(w); ok {
		t.Fatal("quiet fired at 500ms-1ns after reset")
	}
	clk.Advance(time.Nanosecond)
	if n, ok := pollBatch(w); !ok || n != 1 {
		t.Fatalf("quiet batch after reset %d %v", n, ok)
	}
	w.Stop()
}
