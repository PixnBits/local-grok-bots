package clisession

import (
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
