package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DurationMS is a duration stored as integer milliseconds. Zero means inherit.
// JSON is a compact Go duration string such as "10m". Empty or omitted inherits.
type DurationMS time.Duration

// MarshalJSON writes "" when d <= 0, otherwise a compact duration string.
func (d DurationMS) MarshalJSON() ([]byte, error) {
	if time.Duration(d) <= 0 {
		return []byte(`""`), nil
	}
	return json.Marshal(CompactDuration(time.Duration(d)))
}

// UnmarshalJSON accepts a Go duration string, "" or null (inherit).
func (d *DurationMS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" || string(b) == `""` {
		*d = 0
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = DurationMS(parsed)
	return nil
}

func (d DurationMS) Duration() time.Duration { return time.Duration(d) }

// CompactDuration drops zero units: 2m, 1h30m, 45s. Under a second it keeps
// milliseconds so a short test limit stays exact. Empty if d <= 0.
func CompactDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	d = d.Truncate(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	var b strings.Builder
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if s > 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}

func durationToMS(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	ms := d.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}

func msToDuration(ms int64) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}
