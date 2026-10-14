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
