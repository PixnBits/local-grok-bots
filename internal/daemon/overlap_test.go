package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestBuildBindOverlapsSecret(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Run("direct", func(t *testing.T) {
		dir := t.TempDir()
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			BuildBinds: []string{dir},
		})
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), dir) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		link := filepath.Join(t.TempDir(), "bind")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			BuildBinds: []string{link},
		})
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), link) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestCredentialHomeOverlapsSecret(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Run("direct", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "cli")
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
		})
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), home) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "cli")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "home")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, link),
		})
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), link) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("outside home is kept", func(t *testing.T) {
		dir := t.TempDir()
		home := t.TempDir()
		app, err := overlapOpen(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(app.Shutdown)
		if !coiListed(app.daemonSecrets(), home) {
			t.Fatalf("secrets %v lack %s", app.daemonSecrets(), home)
		}
	})
	t.Run("reload refuses the new home", func(t *testing.T) {
		dir := t.TempDir()
		home := t.TempDir()
		policyPath := writeHomePolicy(t, dir, home)
		app, err := overlapOpen(t, config.Config{DataDir: dir, PolicyPath: policyPath})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(app.Shutdown)
		target := filepath.Join(dir, adminTokenFile)
		if err := os.WriteFile(target, []byte("placeholder\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "home")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policyPath, []byte(homePolicy(link)), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := app.policyNow(); err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), link) {
			t.Fatalf("reload %v", err)
		}
		secrets := app.daemonSecrets()
		if !coiListed(secrets, home) || coiListed(secrets, link) {
			t.Fatalf("secrets %v", secrets)
		}
	})
}

func TestAuthTokensFileInsideBuildBind(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	body := "alice:" + aliceTok + "\n"
	write := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("direct", func(t *testing.T) {
		dir := t.TempDir()
		bind := t.TempDir()
		tokens := filepath.Join(bind, "tokens")
		write(t, tokens)
		err := overlapStart(t, config.Config{
			DataDir: dir, AuthTokensFile: tokens, BuildBinds: []string{bind},
		})
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), bind) || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("symlink tokens path", func(t *testing.T) {
		dir := t.TempDir()
		real := t.TempDir()
		tokens := filepath.Join(real, "tokens")
		write(t, tokens)
		link := filepath.Join(t.TempDir(), "via")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		via := filepath.Join(link, "tokens")
		err := overlapStart(t, config.Config{
			DataDir: dir, AuthTokensFile: via, BuildBinds: []string{real},
		})
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("symlink bind", func(t *testing.T) {
		dir := t.TempDir()
		real := t.TempDir()
		tokens := filepath.Join(real, "tokens")
		write(t, tokens)
		link := filepath.Join(t.TempDir(), "bind")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		err := overlapStart(t, config.Config{
			DataDir: dir, AuthTokensFile: tokens, BuildBinds: []string{link},
		})
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), link) || strings.Contains(err.Error(), aliceTok) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("reload retarget", func(t *testing.T) {
		buf := captureStartup(t)
		dir := t.TempDir()
		outside := t.TempDir()
		bind := t.TempDir()
		link := filepath.Join(t.TempDir(), "via")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		tokens := filepath.Join(link, "tokens")
		write(t, tokens)
		app, err := overlapOpen(t, config.Config{
			DataDir: dir, AuthTokensFile: tokens, BuildBinds: []string{bind},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(app.Shutdown)
		srv := serve(t, app)
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(bind, link); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(bind, "tokens"))
		app.ReloadAuthTokens()
		if res, _ := do(t, "GET", srv.URL+"/api/bots", nil, aliceTok); res.StatusCode != 200 {
			t.Fatalf("kept %d", res.StatusCode)
		}
		log := buf.String()
		if !strings.Contains(log, "local-grok-bots: WARN: AUTH_TOKENS_FILE reload failed; keeping the previous tokens:") || !strings.Contains(log, "SANDBOX_BUILD_BINDS") || strings.Contains(log, aliceTok) {
			t.Fatalf("log:\n%s", log)
		}
	})
}

func TestLinkedDataDirBuildBinds(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if ents, err := os.ReadDir(real); err != nil || len(ents) != 0 {
		t.Fatalf("real dir %v %v", ents, err)
	}
	check := func(t *testing.T, bind string) error {
		t.Helper()
		return checkPathOverlaps(config.Config{
			DataDir:    link,
			BuildBinds: []string{bind},
		}, policy.Policy{})
	}
	t.Run("resolved data dir", func(t *testing.T) {
		err := check(t, real)
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), real) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("sub of nonexistent secret", func(t *testing.T) {
		// cli does not exist. The bind is a child of that secret after the
		// symlink ancestor is resolved.
		bind := filepath.Join(real, "cli", "child")
		err := check(t, bind)
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), bind) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("unrelated bind", func(t *testing.T) {
		if err := check(t, t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPathFormsResolvesMissingAncestor(t *testing.T) {
	data := t.TempDir()
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "via")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(link, "nested", "policy.toml")
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("missing path %v", err)
	}
	cfg := config.Config{DataDir: data, PolicyPath: missing}
	cfg.BuildBinds = []string{filepath.Join(real, "nested", "policy.toml")}
	err := checkPathOverlaps(cfg, policy.Policy{})
	if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), cfg.BuildBinds[0]) {
		t.Fatalf("resolved secret %v", err)
	}
	cfg.BuildBinds = []string{filepath.Join(real, "nested", "policy.toml", "child")}
	err = checkPathOverlaps(cfg, policy.Policy{})
	if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") {
		t.Fatalf("child of missing secret %v", err)
	}
	cfg.BuildBinds = []string{t.TempDir()}
	if err := checkPathOverlaps(cfg, policy.Policy{}); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialHomeUnderDataDirCLI(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Run("under cli is allowed", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "cli", "bot", "home")
		if err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("equals data dir", func(t *testing.T) {
		dir := t.TempDir()
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, dir),
		})
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), dir) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("contains data dir", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "data")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, parent),
		})
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), parent) {
			t.Fatalf("err %v", err)
		}
	})
}

func writeHomePolicy(t *testing.T, dir, home string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(homePolicy(home)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func homePolicy(home string) string {
	return "[backend]\nbackend = \"ollama\"\n[[tools.cli]]\nname = \"grok\"\npath = \"/usr/bin/grok\"\ncredential_home = \"" + home + "\"\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n"
}

func overlapStart(t *testing.T, cfg config.Config) error {
	t.Helper()
	app, err := overlapOpen(t, cfg)
	if app != nil {
		app.Shutdown()
	}
	return err
}

func overlapOpen(t *testing.T, cfg config.Config) (*App, error) {
	t.Helper()
	if err := chmodDataDir(cfg.DataDir); err != nil {
		t.Fatal(err)
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "127.0.0.1:0"
	}
	if cfg.OllamaURL == "" {
		cfg.OllamaURL = "http://127.0.0.1:9"
	}
	if cfg.Model == "" {
		cfg.Model = "test-model"
	}
	if cfg.Version == "" {
		cfg.Version = "0.1.0"
	}
	app, err := New(cfg, nil)
	if app != nil {
		app.noGrokProxy = true
	}
	return app, err
}
