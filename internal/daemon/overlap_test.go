package daemon

import (
	"errors"
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
		prot := filepath.Join(dir, adminTokenFile)
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), prot) || !strings.Contains(err.Error(), "protected path") {
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
		prot := filepath.Join(dir, adminTokenFile)
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), prot) || !strings.Contains(err.Error(), "protected path") {
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
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), home) || !strings.Contains(err.Error(), "protected path "+home) {
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
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), "protected path "+target) {
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
		if _, err := app.policyNow(); err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), "protected path "+target) {
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
		if err == nil || !strings.Contains(err.Error(), "AUTH_TOKENS_FILE") || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), bind) || strings.Contains(err.Error(), aliceTok) || strings.HasSuffix(err.Error(), ": bind") || strings.Contains(err.Error(), ": bind") {
			t.Fatalf("err %v", err)
		}
		if !errors.Is(err, errAuthBind) {
			t.Fatalf("reason %v", err)
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
		prot := filepath.Join(link, adminTokenFile)
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), real) || !strings.Contains(err.Error(), prot) || !strings.Contains(err.Error(), "protected path") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("sub of nonexistent secret", func(t *testing.T) {
		// cli does not exist. The bind is a child of that secret after the
		// symlink ancestor is resolved.
		bind := filepath.Join(real, "cli", "child")
		err := check(t, bind)
		prot := filepath.Join(link, "cli")
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), bind) || !strings.Contains(err.Error(), prot) || !strings.Contains(err.Error(), "protected path") {
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
	if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), cfg.BuildBinds[0]) || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "protected path") {
		t.Fatalf("resolved secret %v", err)
	}
	cfg.BuildBinds = []string{filepath.Join(real, "nested", "policy.toml", "child")}
	err = checkPathOverlaps(cfg, policy.Policy{})
	if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "protected path") {
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
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), "protected path "+dir) {
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
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), parent) || !strings.Contains(err.Error(), "protected path "+dir) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestBuildBindOverlapsConfiguredSecrets(t *testing.T) {
	data := t.TempDir()
	ghDir := t.TempDir()
	gh := filepath.Join(ghDir, "github.token")
	if err := os.WriteFile(gh, []byte("not-a-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	audDir := t.TempDir()
	aud := filepath.Join(audDir, "audit.log")
	pol := policy.Policy{AuditLog: aud, GitHub: policy.GitHub{TokenFile: gh}}
	cfg := config.Config{DataDir: data, PolicyPath: filepath.Join(t.TempDir(), "policy.toml")}
	checks := []struct {
		name string
		bind string
		prot string
	}{
		{"github token dir", ghDir, gh},
		{"sandbox", filepath.Join(data, "sandbox"), filepath.Join(data, "sandbox")},
		{"audit dir", audDir, aud},
		{"secrets", filepath.Join(data, "secrets"), filepath.Join(data, "secrets")},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			cfg.BuildBinds = []string{tc.bind}
			err := checkPathOverlaps(cfg, pol)
			if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), tc.bind) || !strings.Contains(err.Error(), "protected path "+tc.prot) {
				t.Fatalf("err %v", err)
			}
		})
	}
	t.Run("unrelated", func(t *testing.T) {
		cfg.BuildBinds = []string{t.TempDir()}
		if err := checkPathOverlaps(cfg, pol); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBuildBindAbsentAtStartup(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	dir := t.TempDir()
	missing := filepath.Join(t.TempDir(), "absent-bind")
	err := overlapStart(t, config.Config{DataDir: dir, BuildBinds: []string{missing}})
	if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err %v", err)
	}
}

func TestCredentialHomeUnderDataDirCOI(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	t.Run("coi name is allowed", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "coi", "grok")
		if err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("equals coi", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "coi")
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
		})
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), "protected path "+home) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("sandbox child", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "sandbox", "keys")
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
		})
		prot := filepath.Join(dir, "sandbox")
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), home) || !strings.Contains(err.Error(), "protected path "+prot) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("overlaps another home", func(t *testing.T) {
		dir := t.TempDir()
		outer := filepath.Join(dir, "coi", "grok")
		inner := filepath.Join(outer, "nested")
		body := homePolicy(outer) + "[[tools.cli]]\nname = \"other\"\npath = \"/usr/bin/other\"\ncredential_home = \"" + inner + "\"\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n"
		path := filepath.Join(dir, "policy.toml")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		err := overlapStart(t, config.Config{DataDir: dir, PolicyPath: path})
		if err == nil || !strings.Contains(err.Error(), "credential_home") || !strings.Contains(err.Error(), inner) || !strings.Contains(err.Error(), "is inside another home "+outer) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("build bind over a home", func(t *testing.T) {
		dir := t.TempDir()
		home := t.TempDir()
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
			BuildBinds: []string{home},
		})
		if err == nil || !strings.Contains(err.Error(), "SANDBOX_BUILD_BINDS") || !strings.Contains(err.Error(), "protected path "+home) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestCredentialHomeInsideWorkspace(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	t.Run("subdirectory", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "workspace", "bot")
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, home),
		})
		ws := filepath.Join(dir, "workspace")
		if err == nil || !strings.Contains(err.Error(), "credential_home "+home) || !strings.Contains(err.Error(), "is inside the workspace "+ws) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("symlink into workspace", func(t *testing.T) {
		dir := t.TempDir()
		ws := filepath.Join(dir, "workspace", "secret")
		if err := os.MkdirAll(ws, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "home")
		if err := os.Symlink(ws, link); err != nil {
			t.Fatal(err)
		}
		err := overlapStart(t, config.Config{
			DataDir:    dir,
			PolicyPath: writeHomePolicy(t, dir, link),
		})
		if err == nil || !strings.Contains(err.Error(), "credential_home "+link) || !strings.Contains(err.Error(), "is inside the workspace") || !strings.Contains(err.Error(), "workspace") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestCredentialHomeOutsideDataDir(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	dir := t.TempDir()
	home := filepath.Join(t.TempDir(), "home", "user")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := overlapStart(t, config.Config{
		DataDir:    dir,
		PolicyPath: writeHomePolicy(t, dir, home),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTwoCOIHomesAllowed(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	dir := t.TempDir()
	a := filepath.Join(dir, "coi", "a")
	b := filepath.Join(dir, "coi", "b")
	body := homePolicy(a) + "[[tools.cli]]\nname = \"other\"\npath = \"/usr/bin/other\"\ncredential_home = \"" + b + "\"\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n"
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := overlapStart(t, config.Config{DataDir: dir, PolicyPath: path}); err != nil {
		t.Fatal(err)
	}
}

func TestProdShapedConfigStarts(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("SANDBOX_BUILD_BINDS", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	tok := strings.Repeat("p", 32)
	t.Setenv("AUTH_TOKEN", tok)
	root := t.TempDir()
	data := filepath.Join(root, "var", "lib", "local-grok-bots")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(data, 0o755); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(root, "etc", "local-grok-bots")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home", "user")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(etc, "policy.toml")
	audit := filepath.Join(data, "audit.log")
	body := "[backend]\nbackend = \"ollama\"\n[security]\naudit_log = \"" + audit + "\"\n[[tools.cli]]\nname = \"grok\"\npath = \"/usr/bin/grok\"\ncredential_home = \"" + home + "\"\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir:    data,
		PolicyPath: policyPath,
		AuthToken:  tok,
		BindAddr:   "127.0.0.1:0",
		OllamaURL:  "http://127.0.0.1:9",
		Model:      "test-model",
		Version:    "0.1.0",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
	st, err := os.Lstat(data)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
}

func TestPolicySampleCredentialHome(t *testing.T) {
	t.Setenv("MANAGED_POLICY", "")
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	t.Setenv("AUTH_TOKENS_FILE", "")
	t.Setenv("SANDBOX_BUILD_BINDS", "")
	raw, err := os.ReadFile(filepath.Join("..", "..", "policy.toml.sample"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "coi", "grok")
	body := activateSampleCLI(string(raw), home)
	if !strings.Contains(body, "credential_home = \""+home+"\"") || strings.Contains(body, "/var/lib/local-grok-bots/coi/grok") {
		t.Fatalf("sample credential_home was not substituted:\n%s", body)
	}
	policyPath := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(policy.Options{Path: policyPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.CLITools) != 1 || pol.CLITools[0].CredentialHome != home {
		t.Fatalf("tools %+v warnings %v", pol.CLITools, pol.Warnings)
	}
	app, err := New(config.Config{
		DataDir:    dir,
		PolicyPath: policyPath,
		BindAddr:   "127.0.0.1:0",
		OllamaURL:  "http://127.0.0.1:9",
		Model:      "test-model",
		Version:    "0.1.0",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
}

// activateSampleCLI uncomments the sample [[tools.cli]] example and points
// credential_home at home.
func activateSampleCLI(sample, home string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(sample, "\n") {
		trim := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(trim, "# [[tools.cli]]") {
			in = true
		}
		if in && strings.HasPrefix(trim, "#") {
			rest := strings.TrimPrefix(trim, "#")
			rest = strings.TrimPrefix(rest, " ")
			if strings.HasPrefix(strings.TrimSpace(rest), "credential_home") {
				rest = "credential_home = \"" + home + "\""
			}
			b.WriteString(rest)
			b.WriteByte('\n')
			if strings.HasPrefix(strings.TrimSpace(rest), "lock") {
				in = false
			}
			continue
		}
		if in && trim == "" {
			in = false
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
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
