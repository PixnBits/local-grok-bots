package daemon

import (
	"encoding/json"
	"fmt"
	"sync"
)

type frame struct {
	event string
	data  []byte
}

func (f frame) bytes() []byte {
	return []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", f.event, f.data))
}

// Bus fans out SSE frames for a run and keeps them so a late subscriber
// can catch up. History is dropped when the run finishes and the buffer
// grows past a cap, except the terminal event which is kept.
type Bus struct {
	mu   sync.Mutex
	hist map[string][]frame
	subs map[string]map[chan frame]struct{}
}

func NewBus() *Bus {
	return &Bus{
		hist: map[string][]frame{},
		subs: map[string]map[chan frame]struct{}{},
	}
}

func (b *Bus) Publish(runID, event string, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte(`{}`)
	}
	f := frame{event: event, data: raw}
	b.mu.Lock()
	defer b.mu.Unlock()
	h := append(b.hist[runID], f)
	if len(h) > 400 && event != "done" && event != "error" {
		h = h[len(h)-400:]
	}
	b.hist[runID] = h
	for ch := range b.subs[runID] {
		select {
		case ch <- f:
		default:
		}
	}
}

func (b *Bus) Subscribe(runID string) ([]frame, chan frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	hist := append([]frame(nil), b.hist[runID]...)
	ch := make(chan frame, 64)
	if b.subs[runID] == nil {
		b.subs[runID] = map[chan frame]struct{}{}
	}
	b.subs[runID][ch] = struct{}{}
	return hist, ch
}

// Subscribed reports whether a UI stream is attached to the run.
func (b *Bus) Subscribed(runID string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs[runID]) > 0
}

func (b *Bus) Unsubscribe(runID string, ch chan frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m := b.subs[runID]; m != nil {
		delete(m, ch)
		if len(m) == 0 {
			delete(b.subs, runID)
		}
	}
}

func terminal(event string) bool {
	return event == "done" || event == "error"
}
