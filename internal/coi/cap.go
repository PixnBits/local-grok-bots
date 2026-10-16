package coi

import (
	"sync"
	"time"
)

// CapStore persists the hourly COI cap. A store error fails closed.
type CapStore interface {
	TakeCOICap(botID, cli string, limit int) (bool, error)
}

// HourCap counts calls in a sliding hour, the same way bot turns are counted.
// A limit of zero or less denies the call and does not record it.
// When Store is set, counts survive process restart; a store error denies.
type HourCap struct {
	mu    sync.Mutex
	now   func() time.Time
	seen  map[string][]time.Time
	store CapStore
}

// NewHourCap returns a counter. now may be nil, which uses time.Now.
func NewHourCap(now func() time.Time) *HourCap {
	if now == nil {
		now = time.Now
	}
	return &HourCap{now: now, seen: map[string][]time.Time{}}
}

// SetStore persists Take in SQLite. Nil keeps the in-memory counter.
func (c *HourCap) SetStore(s CapStore) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.store = s
	c.mu.Unlock()
}

// Take records one call for botID and cli unless the last hour is already full.
func (c *HourCap) Take(botID, cli string, limit int) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	store := c.store
	c.mu.Unlock()
	if store != nil {
		ok, err := store.TakeCOICap(botID, cli, limit)
		if err != nil {
			return false
		}
		return ok
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 {
		return false
	}
	key := botID + "\x00" + cli
	now := c.now()
	cut := now.Add(-time.Hour)
	kept := c.seen[key][:0]
	for _, t := range c.seen[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		c.seen[key] = kept
		return false
	}
	c.seen[key] = append(kept, now)
	return true
}
