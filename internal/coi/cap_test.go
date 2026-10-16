package coi

import (
	"testing"
	"time"
)

func TestHourCapCountsAndSlides(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	c := NewHourCap(func() time.Time { return now })
	if !c.Take("bot", "grok", 2) || !c.Take("bot", "grok", 2) {
		t.Fatal("first calls denied")
	}
	if c.Take("bot", "grok", 2) {
		t.Fatal("third call allowed")
	}
	if !c.Take("bot", "other", 2) || !c.Take("other-bot", "grok", 1) {
		t.Fatal("caps were shared")
	}
	if c.Take("bot", "grok", 0) {
		t.Fatal("zero limit allowed a call")
	}
	now = now.Add(time.Hour + time.Second)
	if !c.Take("bot", "grok", 2) {
		t.Fatal("expired calls still counted")
	}
}
