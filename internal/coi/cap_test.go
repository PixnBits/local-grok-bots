package coi

import (
	"errors"
	"testing"
	"time"
)

type memCapStore struct {
	n   int
	err error
}

func (m *memCapStore) TakeCOICap(botID, cli string, limit int) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	if limit <= 0 {
		return false, nil
	}
	if m.n >= limit {
		return false, nil
	}
	m.n++
	return true, nil
}

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

func TestHourCapStoreFailsClosed(t *testing.T) {
	c := NewHourCap(nil)
	st := &memCapStore{n: 1}
	c.SetStore(st)
	if !c.Take("bot", "grok", 2) {
		t.Fatal("store denied under the limit")
	}
	if c.Take("bot", "grok", 2) {
		t.Fatal("store allowed over the limit")
	}
	c.SetStore(&memCapStore{err: errors.New("db down")})
	if c.Take("bot", "grok", 5) {
		t.Fatal("store error allowed a call")
	}
}
