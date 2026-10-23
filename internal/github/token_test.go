package github

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tokenSecret = "lgb-github-test-secret-value"

func TestReadTokenFileRefusesNonRoot(t *testing.T) {
	prevCheck, prevHook := tokenCheck, tokenHook
	tokenCheck, tokenHook = nil, nil
	t.Cleanup(func() { tokenCheck, tokenHook = prevCheck, prevHook })

	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	if err := os.WriteFile(good, []byte(tokenSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(good, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadToken(good)
	if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("owner: %v", err)
	}
	if !strings.Contains(err.Error(), "owner") {
		t.Fatalf("reason: %v", err)
	}

	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(tokenSecret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadToken(loose)
	if !errors.Is(err, ErrToken) || !strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("mode: %v", err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	_, err = ReadToken(link)
	if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := ReadToken("relative"); !errors.Is(err, ErrToken) {
		t.Fatalf("relative: %v", err)
	}
	if _, err := ReadToken(dir); !errors.Is(err, ErrToken) {
		t.Fatalf("dir: %v", err)
	}
}

func TestReadTokenShapeAndHook(t *testing.T) {
	prevCheck, prevHook := tokenCheck, tokenHook
	t.Cleanup(func() { tokenCheck, tokenHook = prevCheck, prevHook })

	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	write := func(body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	tokenHook = nil
	tokenCheck = func(uint32, uint32) error { return nil }
	write(tokenSecret+"\n", 0o600)
	got, err := ReadToken(path)
	if err != nil || got != tokenSecret {
		t.Fatalf("read %q %v", got, err)
	}
	write(tokenSecret+"\r\n", 0o600)
	got, err = ReadToken(path)
	if err != nil || got != tokenSecret {
		t.Fatalf("crlf %q %v", got, err)
	}
	for _, body := range []string{"", "\n", tokenSecret + "\nmore\n", "has space\n", "tab\there\n", tokenSecret + " "} {
		write(body, 0o600)
		_, err = ReadToken(path)
		if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) {
			t.Fatalf("accepted %q: %v", body, err)
		}
	}
	big := strings.Repeat("a", 4097)
	write(big, 0o600)
	if _, err := ReadToken(path); !errors.Is(err, ErrToken) {
		t.Fatalf("oversize: %v", err)
	}

	tokenCheck = func(uint32, uint32) error { return errors.New("leak " + tokenSecret) }
	write(tokenSecret+"\n", 0o600)
	_, err = ReadToken(path)
	if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) || strings.Contains(err.Error(), "leak") {
		t.Fatalf("check error leaked: %v", err)
	}

	tokenCheck = nil
	tokenHook = func(string) (string, error) { return tokenSecret, nil }
	got, err = ReadToken("/no/such")
	if err != nil || got != tokenSecret {
		t.Fatalf("hook %q %v", got, err)
	}
	tokenHook = func(string) (string, error) { return "", errors.New("leak " + tokenSecret) }
	_, err = ReadToken("/no/such")
	if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("hook error leaked: %v", err)
	}
	tokenHook = func(string) (string, error) { return "bad token", nil }
	if _, err := ReadToken("/no/such"); !errors.Is(err, ErrToken) {
		t.Fatalf("hook shape: %v", err)
	}
}
