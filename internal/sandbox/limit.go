package sandbox

import (
	"fmt"
	"sync"
	"time"
)

// connLimit is how many connection handlers one proxy runs at once.
const connLimit = 128

// busyNote rate-limits busy records to one per second.
type busyNote struct {
	mu      sync.Mutex
	last    time.Time
	dropped int
}

// mark counts one busy connection. emit is true at most once per second.
// detail is "busy", or "busy dropped N" when earlier connections were not recorded.
func (b *busyNote) mark() (emit bool, detail string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropped++
	now := time.Now()
	if !b.last.IsZero() && now.Sub(b.last) < time.Second {
		return false, ""
	}
	n := b.dropped
	b.dropped = 0
	b.last = now
	detail = "busy"
	if n > 1 {
		detail = fmt.Sprintf("busy dropped %d", n-1)
	}
	return true, detail
}

// reasonSlotMax is the most deny slots kept.
// Further marks fold into a per-reason overflow slot.
const reasonSlotMax = 64

// reasonSlot is one deny slot. held is how many marks are not yet emitted.
type reasonSlot struct {
	last   time.Time
	held   int
	host   string
	port   int
	record Event
	doRec  bool
}

// reasonEmit is one rate-limited deny emission.
type reasonEmit struct {
	reason string
	host   string
	port   int
	count  int
	record Event
	doRec  bool
}

// reasonKey is one rate-limit slot.
// An overflow slot uses an empty host and port 0.
type reasonKey struct {
	reason string
	host   string
	port   int
}

// reasonNote emits at most once per second for each reason, host, and port.
// count is how many marks that emission stands for.
type reasonNote struct {
	mu    sync.Mutex
	slots map[reasonKey]*reasonSlot
}

func (r *reasonNote) slot(reason, host string, port int, rec *Event) *reasonSlot {
	if r.slots == nil {
		r.slots = map[reasonKey]*reasonSlot{}
	}
	key := reasonKey{reason, host, port}
	if s := r.slots[key]; s != nil {
		return s
	}
	// A record stays on the slot for its own reason, host, and port.
	if rec != nil {
		r.makeRoom()
		if s := r.slots[key]; s != nil {
			return s
		}
		if len(r.slots) < reasonSlotMax {
			return r.newSlot(key)
		}
	}
	if len(r.slots) < reasonSlotMax {
		return r.newSlot(key)
	}
	return r.overflow(reason)
}

func (r *reasonNote) newSlot(key reasonKey) *reasonSlot {
	s := &reasonSlot{host: key.host, port: key.port}
	r.slots[key] = s
	return s
}

func (r *reasonNote) overflow(reason string) *reasonSlot {
	key := reasonKey{reason: reason}
	if s := r.slots[key]; s != nil {
		return s
	}
	if s := r.adoptOverflow(reason); s != nil {
		return s
	}
	r.makeRoom()
	if s := r.slots[key]; s != nil {
		return s
	}
	return r.newSlot(key)
}

// adoptOverflow turns one slot of this reason into the overflow slot.
func (r *reasonNote) adoptOverflow(reason string) *reasonSlot {
	key := reasonKey{reason: reason}
	if s := r.slots[key]; s != nil {
		return s
	}
	for k, s := range r.slots {
		if k.reason != reason || s.doRec {
			continue
		}
		delete(r.slots, k)
		s.host = ""
		s.port = 0
		r.slots[key] = s
		return s
	}
	return nil
}

// makeRoom frees one slot by folding a non-record slot into its overflow.
func (r *reasonNote) makeRoom() {
	if len(r.slots) < reasonSlotMax {
		return
	}
	type pair struct {
		k reasonKey
		s *reasonSlot
	}
	var prev pair
	var have bool
	for k, s := range r.slots {
		if s.doRec || (k.host == "" && k.port == 0) {
			continue
		}
		okey := reasonKey{reason: k.reason}
		if o := r.slots[okey]; o != nil && !o.doRec {
			foldSlot(o, s)
			delete(r.slots, k)
			return
		}
		if have && prev.k.reason == k.reason {
			if r.slots[okey] != nil {
				// The overflow slot holds a record. Fold the extra slot
				// into the other host slot so the record stays put.
				foldSlot(prev.s, s)
				delete(r.slots, k)
				return
			}
			delete(r.slots, prev.k)
			prev.s.host = ""
			prev.s.port = 0
			r.slots[okey] = prev.s
			foldSlot(prev.s, s)
			delete(r.slots, k)
			return
		}
		prev = pair{k, s}
		have = true
	}
}

func foldSlot(dst, src *reasonSlot) {
	dst.held += src.held
	if src.last.After(dst.last) {
		dst.last = src.last
	}
}

// mark records one deny. rec, when set, is stored on that deny's own slot
// and included on the emission.
// The returned emission is ready at most once per second for this slot.
func (r *reasonNote) mark(reason, host string, port int, rec *Event) (reasonEmit, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.slot(reason, host, port, rec)
	s.held++
	if rec != nil {
		s.doRec = true
		s.record = *rec
	}
	now := time.Now()
	if !s.last.IsZero() && now.Sub(s.last) < time.Second {
		return reasonEmit{}, false
	}
	return takeReason(s, reason, now), true
}

// flush emits any marks still held, so the last partial second is not lost.
func (r *reasonNote) flush() []reasonEmit {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.slots) == 0 {
		return nil
	}
	now := time.Now()
	var out []reasonEmit
	for key, s := range r.slots {
		if s.held == 0 {
			continue
		}
		out = append(out, takeReason(s, key.reason, now))
	}
	return out
}

func takeReason(s *reasonSlot, reason string, now time.Time) reasonEmit {
	em := reasonEmit{
		reason: reason,
		host:   s.host,
		port:   s.port,
		count:  s.held,
		record: s.record,
		doRec:  s.doRec,
	}
	em.record.Count = s.held
	s.held = 0
	s.doRec = false
	s.record = Event{}
	s.last = now
	return em
}
