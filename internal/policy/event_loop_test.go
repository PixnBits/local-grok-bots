package policy

import (
	"strings"
	"testing"
	"time"
)

func TestEventLoopDefaultsOff(t *testing.T) {
	p := Defaults()
	if p.EventLoopEnabled() || p.EffectiveEventLoopQuiet() != 500*time.Millisecond || p.EffectiveEventLoopMaxWait() != 2*time.Second {
		t.Fatalf("defaults on=%v quiet=%s max=%s", p.EventLoopEnabled(), p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait())
	}
	p, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.EventLoopEnabled() || p.EffectiveEventLoopQuiet() != DefaultEventLoopQuiet || p.EffectiveEventLoopMaxWait() != DefaultEventLoopMaxWait {
		t.Fatalf("load defaults on=%v quiet=%s max=%s", p.EventLoopEnabled(), p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait())
	}
}

func TestEventLoopParseAndEffective(t *testing.T) {
	body := `
[ollama]
event_loop = true
event_loop_quiet = "250ms"
event_loop_max_wait = "1500ms"
`
	p, err := Load(Options{Path: writePol(t, "on.toml", body)})
	if err != nil || !p.CLIPermitted {
		t.Fatalf("load %v permitted %v warns %v", err, p.CLIPermitted, p.Warnings)
	}
	if !p.EventLoopEnabled() || p.EffectiveEventLoopQuiet() != 250*time.Millisecond || p.EffectiveEventLoopMaxWait() != 1500*time.Millisecond {
		t.Fatalf("got on=%v quiet=%s max=%s", p.EventLoopEnabled(), p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait())
	}

	// Equal bounds are allowed. An integer is a number of seconds.
	eq := "[ollama]\nevent_loop = true\nevent_loop_quiet = 1\nevent_loop_max_wait = \"1s\"\n"
	p, err = Load(Options{Path: writePol(t, "eq.toml", eq)})
	if err != nil || !p.EventLoopEnabled() || p.EffectiveEventLoopQuiet() != time.Second || p.EffectiveEventLoopMaxWait() != time.Second {
		t.Fatalf("equal on=%v quiet=%s max=%s err %v warns %v", p.EventLoopEnabled(), p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait(), err, p.Warnings)
	}

	// One side unset uses the default, and that pair must still be ordered.
	onlyQuiet := "[ollama]\nevent_loop_quiet = \"100ms\"\n"
	p, err = Load(Options{Path: writePol(t, "quiet.toml", onlyQuiet)})
	if err != nil || p.EventLoopEnabled() || p.EffectiveEventLoopQuiet() != 100*time.Millisecond || p.EffectiveEventLoopMaxWait() != 2*time.Second {
		t.Fatalf("quiet only on=%v quiet=%s max=%s err %v", p.EventLoopEnabled(), p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait(), err)
	}
	onlyMax := "[ollama]\nevent_loop_max_wait = \"3s\"\n"
	p, err = Load(Options{Path: writePol(t, "max.toml", onlyMax)})
	if err != nil || p.EffectiveEventLoopQuiet() != 500*time.Millisecond || p.EffectiveEventLoopMaxWait() != 3*time.Second {
		t.Fatalf("max only quiet=%s max=%s err %v", p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait(), err)
	}

	off := "[ollama]\nevent_loop = false\n"
	p, err = Load(Options{Path: writePol(t, "off.toml", off)})
	if err != nil || p.EventLoopEnabled() {
		t.Fatalf("explicit off on=%v err %v", p.EventLoopEnabled(), err)
	}

	js := `{"ollama":{"event_loop":true,"event_loop_quiet":"400ms","event_loop_max_wait":"2s"}}`
	p, err = Load(Options{Path: writePol(t, "on.json", js)})
	if err != nil || !p.EventLoopEnabled() || p.EffectiveEventLoopQuiet() != 400*time.Millisecond || p.EffectiveEventLoopMaxWait() != 2*time.Second {
		t.Fatalf("json on=%v quiet=%s max=%s err %v warns %v", p.EventLoopEnabled(), p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait(), err, p.Warnings)
	}

	// Managed policy overwrites a key it sets and leaves the other in place.
	local := writePol(t, "local.toml", "[ollama]\nevent_loop = true\nevent_loop_quiet = \"100ms\"\nevent_loop_max_wait = \"1s\"\n")
	managed := writePol(t, "managed.toml", "[ollama]\nevent_loop = false\nevent_loop_quiet = \"250ms\"\n")
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil || p.EventLoopEnabled() || p.EffectiveEventLoopQuiet() != 250*time.Millisecond || p.EffectiveEventLoopMaxWait() != time.Second {
		t.Fatalf("managed on=%v quiet=%s max=%s err %v warns %v", p.EventLoopEnabled(), p.EffectiveEventLoopQuiet(), p.EffectiveEventLoopMaxWait(), err, p.Warnings)
	}
}

func TestEventLoopRejectsBadDurations(t *testing.T) {
	bad := []string{
		"[ollama]\nevent_loop_quiet = \"0s\"\n",
		"[ollama]\nevent_loop_quiet = \"soon\"\n",
		"[ollama]\nevent_loop_quiet = \"-1s\"\n",
		"[ollama]\nevent_loop_quiet = 0\n",
		"[ollama]\nevent_loop_max_wait = \"25h\"\n",
		"[ollama]\nevent_loop_max_wait = \"100ms\"\n",
		"[ollama]\nevent_loop_quiet = \"3s\"\n",
		"[ollama]\nevent_loop_quiet = \"1s\"\nevent_loop_max_wait = \"500ms\"\n",
	}
	for _, body := range bad {
		p, err := Load(Options{Path: writePol(t, "bad.toml", body)})
		if err != nil {
			t.Fatal(err)
		}
		if p.CLIPermitted {
			t.Fatalf("accepted %q", body)
		}
		got := strings.Join(p.Warnings, "\n")
		if !strings.Contains(got, "ollama.event_loop") {
			t.Fatalf("warning %q for %s", p.Warnings, body)
		}
	}
	// A bool value of the wrong TOML type fails closed at decode time.
	// The decoder names the Go field, not the dotted key.
	p, err := Load(Options{Path: writePol(t, "bad.toml", "[ollama]\nevent_loop = \"yes\"\n")})
	if err != nil || p.CLIPermitted {
		t.Fatalf("bool type err %v permitted %v", err, p.CLIPermitted)
	}
	got := strings.Join(p.Warnings, "\n")
	if !strings.Contains(got, "unparseable") || !strings.Contains(got, "EventLoop") {
		t.Fatalf("warning %q", p.Warnings)
	}
}
