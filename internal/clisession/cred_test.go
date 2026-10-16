package clisession

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestScrubStaleGrokAuth(t *testing.T) {
	user := t.TempDir()
	real := filepath.Join(user, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	const key = "unit-real-marker-value"
	body := []byte(`{"https://auth.x.ai::x":{"key":"` + key + `","refresh_token":"unit-refresh-value"}}`)
	if err := os.WriteFile(real, body, 0o600); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	hard := filepath.Join(data, "cli", "old", "home", ".grok", "auth.json")
	sym := filepath.Join(data, "cli", "old2", "home", ".grok", "auth.json")
	copied := filepath.Join(data, "cli", "old3", "grok-home", "auth.json")
	keep := filepath.Join(data, "cli", "keep", "home", ".grok", "auth.json")
	for _, p := range []string{hard, sym, copied, keep} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(real, hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, sym); err != nil {
		t.Fatal(err)
	}
	partial := []byte(`{"note":"unit-refresh-value leaked"}`)
	if err := os.WriteFile(copied, partial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte(GrokPlaceholderAuth), 0o600); err != nil {
		t.Fatal(err)
	}
	if nlink(t, real) != 2 {
		t.Fatalf("nlink before scrub %d", nlink(t, real))
	}
	if err := ScrubStaleGrokAuth(data, real); err != nil {
		t.Fatal(err)
	}
	if nlink(t, real) != 1 {
		t.Fatalf("nlink after scrub %d", nlink(t, real))
	}
	for _, p := range []string{hard, sym, copied} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still present: %v", p, err)
		}
	}
	got, err := os.ReadFile(keep)
	if err != nil || string(got) != GrokPlaceholderAuth {
		t.Fatalf("placeholder removed: %q %v", got, err)
	}
	userBody, err := os.ReadFile(real)
	if err != nil || string(userBody) != string(body) {
		t.Fatal("user login changed")
	}
}

func TestRemoveBotGrokAuth(t *testing.T) {
	user := t.TempDir()
	real := filepath.Join(user, "auth.json")
	if err := os.WriteFile(real, []byte("unit-real-marker-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	homeAuth := filepath.Join(data, "cli", "bot1", "home", ".grok", "auth.json")
	grokAuth := filepath.Join(data, "cli", "bot1", "grok-home", "auth.json")
	other := filepath.Join(data, "cli", "bot2", "home", ".grok", "auth.json")
	for _, p := range []string{homeAuth, other} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(grokAuth), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(real, homeAuth); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, grokAuth); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte(GrokPlaceholderAuth), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveBotGrokAuth(data, "bot1"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{homeAuth, grokAuth} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s still present", p)
		}
	}
	if nlink(t, real) != 1 {
		t.Fatalf("nlink %d", nlink(t, real))
	}
	if _, err := os.Lstat(real); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatal("removed another bot")
	}
	if err := RemoveBotGrokAuth(data, "../bot2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatal("unsafe id removed a bot")
	}
}

func TestSymlinkParentsRefused(t *testing.T) {
	const canaryBody = "canary-keep"
	levels := []string{"cli", "bot", "home", ".grok", "auth.json"}
	for _, level := range levels {
		t.Run("write-"+level, func(t *testing.T) {
			data, outside, canary := symlinkFixture(t, level, canaryBody)
			state := filepath.Join(data, "cli", "bot")
			home := filepath.Join(state, "home")
			user := t.TempDir()
			_, err := PrepareIsolation(IsolationOptions{
				Backend: "grok", StateDir: state, Home: home, UserHome: user, CredRoot: data,
				Base: []string{"PATH=/bin"},
			})
			if !errors.Is(err, ErrCredSymlink) {
				t.Fatalf("err %v", err)
			}
			assertCanary(t, canary, canaryBody)
			assertNotFollowed(t, outside, level)
		})
		if level == "auth.json" {
			continue
		}
		t.Run("remove-"+level, func(t *testing.T) {
			data, outside, canary := symlinkFixture(t, level, canaryBody)
			err := RemoveBotGrokAuth(data, "bot")
			if !errors.Is(err, ErrCredSymlink) {
				t.Fatalf("err %v", err)
			}
			assertCanary(t, canary, canaryBody)
			assertNotFollowed(t, outside, level)
		})
	}
}

func TestGrokHomeSymlinkRefused(t *testing.T) {
	data := t.TempDir()
	outside := t.TempDir()
	canary := filepath.Join(outside, "canary")
	if err := os.WriteFile(canary, []byte("canary-keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(data, "grok-home")); err != nil {
		t.Fatal(err)
	}
	user := t.TempDir()
	_, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: data, UserHome: user, CredRoot: data,
		Base: []string{"PATH=/bin"},
	})
	if !errors.Is(err, ErrCredSymlink) {
		t.Fatalf("err %v", err)
	}
	assertCanary(t, canary, "canary-keep")
	if _, err := os.Lstat(filepath.Join(outside, "auth.json")); !os.IsNotExist(err) {
		t.Fatalf("followed grok-home: %v", err)
	}
}

func TestScrubSkipsSymlinkParent(t *testing.T) {
	user := t.TempDir()
	real := filepath.Join(user, ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"https://auth.x.ai::x":{"key":"unit-real-marker-value","refresh_token":"unit-refresh-value"}}`)
	if err := os.WriteFile(real, body, 0o600); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "cli", "bot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(user, filepath.Join(data, "cli", "bot", "home")); err != nil {
		t.Fatal(err)
	}
	if err := ScrubStaleGrokAuth(data, real); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(real)
	if err != nil || string(got) != string(body) {
		t.Fatalf("user login changed: %q %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(data, "cli", "bot", "home")); err != nil {
		t.Fatal(err)
	}
}

func symlinkFixture(t *testing.T, level, canaryBody string) (data, outside, canary string) {
	t.Helper()
	outside = t.TempDir()
	canary = filepath.Join(outside, "canary")
	if level == ".grok" || level == "auth.json" {
		canary = filepath.Join(outside, "auth.json")
	}
	if err := os.WriteFile(canary, []byte(canaryBody), 0o600); err != nil {
		t.Fatal(err)
	}
	data = t.TempDir()
	bot := filepath.Join(data, "cli", "bot")
	switch level {
	case "cli":
		if err := os.Symlink(outside, filepath.Join(data, "cli")); err != nil {
			t.Fatal(err)
		}
	case "bot":
		if err := os.MkdirAll(filepath.Join(data, "cli"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, bot); err != nil {
			t.Fatal(err)
		}
	case "home":
		if err := os.MkdirAll(bot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(bot, "home")); err != nil {
			t.Fatal(err)
		}
	case ".grok":
		if err := os.MkdirAll(filepath.Join(bot, "home"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(bot, "home", ".grok")); err != nil {
			t.Fatal(err)
		}
	case "auth.json":
		if err := os.MkdirAll(filepath.Join(bot, "home", ".grok"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(canary, filepath.Join(bot, "home", ".grok", "auth.json")); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("level %s", level)
	}
	return data, outside, canary
}

func assertNotFollowed(t *testing.T, outside, level string) {
	t.Helper()
	var extra string
	switch level {
	case "cli":
		extra = filepath.Join(outside, "bot")
	case "bot":
		extra = filepath.Join(outside, "home")
	case "home":
		extra = filepath.Join(outside, ".grok")
	default:
		return
	}
	if _, err := os.Lstat(extra); !os.IsNotExist(err) {
		t.Fatalf("followed %s: %v", level, err)
	}
}

func assertCanary(t *testing.T, path, body string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != body {
		t.Fatalf("canary %q %v", got, err)
	}
	if nlink(t, path) != 1 {
		t.Fatalf("canary nlink %d", nlink(t, path))
	}
}
