package sandbox

import (
	"fmt"
	"testing"
)

func TestProxyEventsCoalesceAndCap(t *testing.T) {
	p := &proxy{}
	for i := 0; i < 100000; i++ {
		p.add(Event{Kind: "grant_denied", Grant: "net", Host: "same.test", Detail: "not allowlisted"})
	}
	got := p.drain()
	if len(got) != 1 || got[0].Count != 100000 || got[0].Host != "same.test" {
		n := 0
		if len(got) > 0 {
			n = got[0].Count
		}
		t.Fatalf("coalesce len %d first count %d", len(got), n)
	}

	p = &proxy{}
	p.add(Event{Kind: "grant_denied", Detail: "header", Count: 3})
	p.add(Event{Kind: "grant_denied", Detail: "header", Count: 4})
	got = p.drain()
	if len(got) != 1 || got[0].Count != 7 {
		t.Fatalf("sum len %d", len(got))
	}

	p = &proxy{}
	const distinct = 10000
	for i := 0; i < distinct; i++ {
		p.add(Event{Kind: "net_request", Grant: "net", Host: fmt.Sprintf("h%d.test", i), Detail: "not allowlisted"})
	}
	got = p.drain()
	if len(got) != eventCap+1 {
		t.Fatalf("len %d cap %d", len(got), eventCap)
	}
	if got[0].Host != "h0.test" {
		t.Fatalf("first %+v", got[0])
	}
	last := got[len(got)-1]
	if last.Kind != "grant_denied" || last.Detail != "events dropped" || last.Count != distinct-eventCap {
		t.Fatalf("summary kind %s detail %s count %d", last.Kind, last.Detail, last.Count)
	}
}
