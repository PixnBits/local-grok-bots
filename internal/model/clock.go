package model

import (
	"context"
	"sync"
	"time"
)

// ClockTimer is a timer the stall watchdog or the per-call cap can stop.
// *time.Timer implements it.
type ClockTimer interface {
	Stop() bool
}

// Clock replaces the process clock for one Ollama client. Tests set it
// through Ollama.SetClock. A nil function uses time.Now or time.AfterFunc.
// The stall watchdog and TimeoutContext share it, so a test can advance a
// minute-scale cap without waiting.
type Clock struct {
	Now       func() time.Time
	AfterFunc func(time.Duration, func()) ClockTimer
}

// callClock is the clock one client actually uses. Zero uses the process clock.
type callClock struct {
	now       func() time.Time
	afterFunc func(time.Duration, func()) ClockTimer
}

// SetClock installs c for the stall watchdog and for TimeoutContext.
// A nil clock restores the process clock.
func (o *Ollama) SetClock(c *Clock) {
	if o == nil {
		return
	}
	if c == nil {
		o.clk = callClock{}
		return
	}
	o.clk = callClock{now: c.Now, afterFunc: c.AfterFunc}
}

func (o *Ollama) activeClock() callClock {
	c := callClock{}
	if o != nil {
		c = o.clk
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.afterFunc == nil {
		c.afterFunc = func(d time.Duration, f func()) ClockTimer {
			return time.AfterFunc(d, f)
		}
	}
	return c
}

// TimeoutContext is the per-call hard cap. With no test clock it is
// context.WithTimeout. A test clock fires DeadlineExceeded when that clock
// says the cap has elapsed, and still follows parent cancellation.
func (o *Ollama) TimeoutContext(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if d <= 0 {
		return context.WithCancel(parent)
	}
	if o == nil || o.clk.afterFunc == nil {
		return context.WithTimeout(parent, d)
	}
	return newClockTimeout(parent, d, o.activeClock())
}

// clockTimeout reports DeadlineExceeded when its clock timer fires.
type clockTimeout struct {
	parent   context.Context
	deadline time.Time
	done     chan struct{}
	mu       sync.Mutex
	err      error
	once     sync.Once
}

func newClockTimeout(parent context.Context, d time.Duration, c callClock) (context.Context, context.CancelFunc) {
	tctx := &clockTimeout{
		parent:   parent,
		deadline: c.now().Add(d),
		done:     make(chan struct{}),
	}
	timer := c.afterFunc(d, func() { tctx.finish(context.DeadlineExceeded) })
	go func() {
		select {
		case <-parent.Done():
			tctx.finish(parent.Err())
		case <-tctx.done:
		}
	}()
	cancel := func() {
		if timer != nil {
			timer.Stop()
		}
		tctx.finish(context.Canceled)
	}
	return tctx, cancel
}

func (t *clockTimeout) Deadline() (time.Time, bool) {
	if pd, ok := t.parent.Deadline(); ok && pd.Before(t.deadline) {
		return pd, true
	}
	return t.deadline, true
}

func (t *clockTimeout) Done() <-chan struct{} { return t.done }

func (t *clockTimeout) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

func (t *clockTimeout) Value(key any) any { return t.parent.Value(key) }

func (t *clockTimeout) finish(err error) {
	if err == nil {
		err = context.Canceled
	}
	t.once.Do(func() {
		t.mu.Lock()
		t.err = err
		t.mu.Unlock()
		close(t.done)
	})
}
