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
