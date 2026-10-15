package daemon

import "testing"

func TestPromptSubscribersAreSeparate(t *testing.T) {
	b := NewBus()
	if b.Subscribed("run") || b.PromptSubscribed("run") || b.PromptSubscribed("") {
		t.Fatal("empty bus reported a subscriber")
	}
	_, plain := b.Subscribe("run")
	if !b.Subscribed("run") || b.PromptSubscribed("run") {
		t.Fatal("plain subscriber counted as a prompt UI")
	}
	_, prompts := b.SubscribePrompts("run")
	if !b.PromptSubscribed("run") {
		t.Fatal("prompt subscriber was not counted")
	}
	b.Unsubscribe("run", prompts)
	if b.PromptSubscribed("run") || !b.Subscribed("run") {
		t.Fatal("disconnect did not drop only the prompt subscriber")
	}
	b.Unsubscribe("run", plain)
	if b.Subscribed("run") || b.PromptSubscribed("run") {
		t.Fatal("subscriber remained after disconnect")
	}
}

func TestPermissionOverflowDropsSubscriber(t *testing.T) {
	b := NewBus()
	_, slow := b.SubscribePrompts("run")
	_, plain := b.Subscribe("run")
	for i := 0; i < cap(slow); i++ {
		b.Publish("run", "token", map[string]string{"text": "x"})
	}
	b.Publish("run", "token", map[string]string{"text": "dropped"})
	if !b.PromptSubscribed("run") || !b.Subscribed("run") {
		t.Fatal("a full token buffer removed a subscriber")
	}
	select {
	case _, ok := <-slow:
		if !ok {
			t.Fatal("token overflow closed the subscriber")
		}
	default:
		t.Fatal("filled subscriber had no buffered token")
	}
	// The observation freed one slot. Fill it again so the permission frame
	// does not fit. plain was not drained, so it is still full.
	b.Publish("run", "token", map[string]string{"text": "refill"})
	_, live := b.SubscribePrompts("run")
	b.Publish("run", "permission_request", map[string]any{"id": "p1"})
	if !b.PromptSubscribed("run") {
		t.Fatal("the live prompt subscriber was not counted")
	}
	if !frameClosed(slow) {
		t.Fatal("permission_request was dropped instead of disconnecting the slow subscriber")
	}
	if !frameClosed(plain) {
		t.Fatal("permission_request was dropped for a full plain subscriber")
	}
	got, ok := <-live
	if !ok || got.event != "permission_request" {
		t.Fatalf("live subscriber frame %+v ok %v", got, ok)
	}
	for i := 0; i < cap(live); i++ {
		b.Publish("run", "token", map[string]string{"text": "y"})
	}
	b.Publish("run", "permission_decision", map[string]any{"id": "p1"})
	if b.PromptSubscribed("run") {
		t.Fatal("overflowed prompt subscriber still counted as a UI")
	}
	if !frameClosed(live) {
		t.Fatal("permission_decision was dropped instead of disconnecting")
	}
	hist, again := b.SubscribePrompts("run")
	if !b.PromptSubscribed("run") {
		t.Fatal("reconnected prompt subscriber was not counted")
	}
	var sawReq, sawDec bool
	for _, f := range hist {
		if f.event == "permission_request" {
			sawReq = true
		}
		if f.event == "permission_decision" {
			sawDec = true
		}
	}
	if !sawReq || !sawDec {
		t.Fatal("history did not keep the permission frames")
	}
	b.Unsubscribe("run", again)
}

func frameClosed(ch chan frame) bool {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return true
			}
		default:
			return false
		}
	}
}
