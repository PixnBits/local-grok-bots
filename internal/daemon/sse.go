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

// sub is one stream client. prompts is true when the client declared it
// can answer a permission card, via ?prompts=1.
type sub struct {
	prompts bool
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
	subs map[string]map[chan frame]sub
}

func NewBus() *Bus {
	return &Bus{
		hist: map[string][]frame{},
		subs: map[string]map[chan frame]sub{},
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
	var drop []chan frame
	for ch := range b.subs[runID] {
		select {
		case ch <- f:
		default:
			// A full buffer used to discard the frame. A permission frame
			// is the card or its result, so drop the subscriber instead.
			// The client reconnects and reads it back from history.
			if permissionFrame(event) {
				drop = append(drop, ch)
			}
		}
	}
	for _, ch := range drop {
		b.disconnect(runID, ch)
	}
}

func permissionFrame(event string) bool {
	return event == "permission_request" || event == "permission_decision"
}

func (b *Bus) Subscribe(runID string) ([]frame, chan frame) {
	return b.subscribe(runID, false)
}

// SubscribePrompts registers a client that declared it can answer prompts.
func (b *Bus) SubscribePrompts(runID string) ([]frame, chan frame) {
	return b.subscribe(runID, true)
}

func (b *Bus) subscribe(runID string, prompts bool) ([]frame, chan frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	hist := append([]frame(nil), b.hist[runID]...)
	ch := make(chan frame, 64)
	if b.subs[runID] == nil {
		b.subs[runID] = map[chan frame]sub{}
	}
	b.subs[runID][ch] = sub{prompts: prompts}
	return hist, ch
}

// Subscribed reports whether any stream client is attached to the run.
func (b *Bus) Subscribed(runID string) bool {
	return b.count(runID, false) > 0
}

// PromptSubscribed reports whether a live client that can answer prompts is
// attached. A client removed because its buffer could not take a permission
// frame is not counted, so the broker does not treat it as a UI.
func (b *Bus) PromptSubscribed(runID string) bool {
	return b.count(runID, true) > 0
}

func (b *Bus) count(runID string, promptsOnly bool) int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, s := range b.subs[runID] {
		if !promptsOnly || s.prompts {
			n++
		}
	}
	return n
}

func (b *Bus) Unsubscribe(runID string, ch chan frame) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remove(runID, ch)
}

// disconnect removes a subscriber and closes its channel so the HTTP stream
// ends. The caller holds b.mu. Closing wakes the handler; history still has
// the frame the buffer could not take.
func (b *Bus) disconnect(runID string, ch chan frame) {
	if !b.remove(runID, ch) {
		return
	}
	close(ch)
}

func (b *Bus) remove(runID string, ch chan frame) bool {
	m := b.subs[runID]
	if m == nil {
		return false
	}
	if _, ok := m[ch]; !ok {
		return false
	}
	delete(m, ch)
	if len(m) == 0 {
		delete(b.subs, runID)
	}
	return true
}

func terminal(event string) bool {
	return event == "done" || event == "error"
}
