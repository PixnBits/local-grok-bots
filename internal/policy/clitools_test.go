package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFixedEnvRejectsTokenFiles(t *testing.T) {
	for _, key := range []string{"AUTH_TOKEN", "AUTH_TOKENS_FILE"} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.toml")
			body := "[[tools.cli]]\nname = \"grok\"\npath = \"/usr/bin/grok\"\ncredential_home = \"/var/lib/lgb/grok\"\nfixed_env = [\"" + key + "=/tmp/tokens\"]\ntimeout = \"1s\"\nmax_output = 1\nmax_calls_per_hour = 1\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			p, err := Load(Options{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(p.Warnings, "\n")
			if !strings.Contains(text, key) || len(p.CLITools) != 0 {
				t.Fatalf("warnings %v tools %+v", p.Warnings, p.CLITools)
			}
		})
	}
}

func TestSampleHasNoLiveCLI(t *testing.T) {
	path := filepath.Join("..", "..", "policy.toml.sample")
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.CLITools) != 0 {
		t.Fatalf("sample granted CLIs: %+v", p.CLITools)
	}
	if !p.Loaded {
		t.Fatalf("sample did not load: %v", p.Warnings)
	}
}

func TestLocalCLIEntryWithoutManaged(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
allowed_args = ["edit", "--model"]
bots = ["Ada"]
timeout = "30s"
max_output = 4096
max_calls_per_hour = 4
lock = true
`)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := p.COI("grok")
	if !ok {
		t.Fatalf("missing grok, warnings %v", p.Warnings)
	}
	if tool.Lock {
		t.Fatal("local lock applied")
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "only managed policy can lock") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	if tool.Timeout != 30*time.Second || tool.MaxOutput != 4096 || tool.MaxCallsPerHour != 4 {
		t.Fatalf("limits %+v", tool)
	}
	if !tool.AllowsBot("x", "Ada") || tool.AllowsBot("x", "ada") {
		t.Fatalf("bots %+v", tool.Bots)
	}
}

func TestManagedLockBanAndNarrow(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
path = "/tmp/evil"
credential_home = "/tmp/evil-home"
allowed_args = ["edit", "--config"]
bots = ["ada", "mallory"]
timeout = "2m"
max_output = 99999
max_calls_per_hour = 100

[[tools.cli]]
name = "curl"
path = "/usr/bin/curl"
credential_home = "/var/lib/lgb/curl"
timeout = "10s"
max_output = 100
max_calls_per_hour = 1

[[tools.cli]]
name = "extra"
path = "/usr/bin/extra"
credential_home = "/var/lib/lgb/extra"
allowed_args = ["run"]
bots = ["ada"]
timeout = "10s"
max_output = 100
max_calls_per_hour = 1

[[tools.cli]]
name = "locked"
path = "/tmp/nope"
credential_home = "/tmp/nope-home"
bots = []
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	managed := writePol(t, "managed.json", `{
	  "tools": {
	    "cli_ban": ["curl"],
	    "cli": [
	      {
	        "name": "grok",
	        "path": "/usr/bin/grok",
	        "credential_home": "/var/lib/lgb/grok",
	        "allowed_args": ["edit", "--model", "--prompt"],
	        "bots": ["ada", "bob"],
	        "timeout": "1m",
	        "max_output": 8000,
	        "max_calls_per_hour": 20
	      },
	      {
	        "name": "locked",
	        "lock": true,
	        "path": "/usr/bin/locked",
	        "credential_home": "/var/lib/lgb/locked",
	        "allowed_args": ["version"],
	        "bots": ["ada", "bob"],
	        "timeout": "1m",
	        "max_output": 1000,
	        "max_calls_per_hour": 5
	      }
	    ]
	  }
	}`)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok := p.COI("grok")
	if !ok {
		t.Fatalf("grok missing, warnings %v tools %+v", p.Warnings, p.CLITools)
	}
	if grok.Path != "/usr/bin/grok" || grok.CredentialHome != "/var/lib/lgb/grok" {
		t.Fatalf("managed path changed: %+v", grok)
	}
	if strings.Join(grok.AllowedArgs, ",") != "edit" {
		t.Fatalf("args %v", grok.AllowedArgs)
	}
	if strings.Join(grok.Bots, ",") != "ada" {
		t.Fatalf("bots %v", grok.Bots)
	}
	if grok.Timeout != time.Minute || grok.MaxOutput != 8000 || grok.MaxCallsPerHour != 20 {
		t.Fatalf("limits were raised: %+v", grok)
	}
	locked, ok := p.COI("locked")
	if !ok || !locked.Lock || strings.Join(locked.Bots, ",") != "ada,bob" || locked.Path != "/usr/bin/locked" {
		t.Fatalf("lock did not hold: %+v", locked)
	}
	if _, ok := p.COI("curl"); ok {
		t.Fatal("banned curl survived")
	}
	extra, ok := p.COI("extra")
	if !ok || extra.Path != "/usr/bin/extra" {
		t.Fatalf("local entry dropped: %+v", extra)
	}
	text := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"is locked", "bans that name", "can only narrow", "cannot change a managed cli", "can only lower"} {
		if !strings.Contains(text, want) {
			t.Fatalf("warnings lack %q:\n%s", want, text)
		}
	}
}

func TestManagedForbidsLocalCLI(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
allowed_args = ["edit"]
bots = ["ada"]
timeout = "15s"
max_output = 100
max_calls_per_hour = 2

[[tools.cli]]
name = "extra"
path = "/usr/bin/extra"
credential_home = "/var/lib/lgb/extra"
timeout = "10s"
max_output = 100
max_calls_per_hour = 1
`)
	managed := writePol(t, "managed.json", `{
	  "tools": {
	    "cli_allow_local": false,
	    "cli": [{
	      "name": "grok",
	      "path": "/usr/bin/grok",
	      "credential_home": "/var/lib/lgb/grok",
	      "allowed_args": ["edit", "--model"],
	      "bots": ["ada", "bob"],
	      "timeout": "30s",
	      "max_output": 500,
	      "max_calls_per_hour": 9
	    }]
	  }
	}`)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok := p.COI("grok")
	if !ok {
		t.Fatal("grok missing", p.Warnings)
	}
	if grok.Timeout != 15*time.Second || grok.MaxOutput != 100 || grok.MaxCallsPerHour != 2 {
		t.Fatalf("did not narrow: %+v", grok)
	}
	if strings.Join(grok.AllowedArgs, ",") != "edit" || strings.Join(grok.Bots, ",") != "ada" {
		t.Fatalf("grants %+v %v", grok.AllowedArgs, grok.Bots)
	}
	if _, ok := p.COI("extra"); ok {
		t.Fatal("local cli allowed against managed forbid")
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "does not allow local cli entries") {
		t.Fatalf("warnings %v", p.Warnings)
	}
}

func TestLocalCannotRaiseUnsetManagedLimit(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
timeout = "10s"
max_calls_per_hour = 5
`)
	managed := writePol(t, "managed.json", `{
	  "tools": {"cli": [{
	    "name": "grok",
	    "path": "/usr/bin/grok",
	    "credential_home": "/var/lib/lgb/grok",
	    "max_calls_per_hour": 0,
	    "timeout": "0s",
	    "max_output": 100
	  }]}
	}`)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok := p.COI("grok")
	if !ok {
		t.Fatal(p.Warnings)
	}
	if grok.Timeout != 0 || grok.MaxCallsPerHour != 0 || grok.MaxOutput != 100 {
		t.Fatalf("raised a closed limit: %+v", grok)
	}
}

func TestIncompleteLocalCLIIsDropped(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
bots = ["ada"]
`)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.COI("grok"); ok {
		t.Fatal("incomplete entry kept")
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "absolute path") {
		t.Fatalf("warnings %v", p.Warnings)
	}
}

func TestBadCLIPathFailsClosed(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
path = "grok"
credential_home = "/var/lib/lgb/grok"
`)
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if p.Loaded || p.CLIPermitted || len(p.CLITools) != 0 {
		t.Fatalf("relative path did not fail closed: loaded %v tools %+v warnings %v", p.Loaded, p.CLITools, p.Warnings)
	}
}

func TestLocalBanIsIgnored(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(local, []byte(`
[tools]
cli_ban = ["grok"]
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.COI("grok"); !ok {
		t.Fatal("local ban dropped the entry", p.Warnings)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "only managed policy can ban") {
		t.Fatalf("warnings %v", p.Warnings)
	}
}

func TestCLIPolicyPinsAndFiles(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
path = "/tmp/evil"
credential_home = "/tmp/evil-home"
sandbox_bin = "/tmp/evil-bwrap"
allowed_args = ["-p", "--cwd"]
value_flags = ["-p", "--cwd", "--extra"]
credential_files = [".grok/auth.json", "token"]
fixed_args = ["--sandbox", "off"]
fixed_env = ["GROK_HOME=/tmp/evil"]
bots = ["ada"]
timeout = "30s"
max_output = 100
max_calls_per_hour = 2
`)
	managed := writePol(t, "managed.json", `{
	  "tools": {"cli": [{
	    "name": "grok",
	    "path": "/usr/bin/grok",
	    "credential_home": "/var/lib/lgb/grok",
	    "sandbox_bin": "/usr/bin/bwrap",
	    "allowed_args": ["-p", "--cwd", "--max-turns"],
	    "value_flags": ["-p", "--cwd", "--max-turns"],
	    "credential_files": [".grok/auth.json"],
	    "fixed_args": ["--always-approve"],
	    "fixed_env": ["GROK_CLAUDE_MCPS_ENABLED=false"],
	    "bots": ["ada"],
	    "timeout": "1m",
	    "max_output": 8000,
	    "max_calls_per_hour": 20
	  }]}
	}`)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok := p.COI("grok")
	if !ok {
		t.Fatal(p.Warnings)
	}
	if grok.SandboxBin != "/usr/bin/bwrap" {
		t.Fatalf("sandbox_bin %+v", grok)
	}
	if strings.Join(grok.FixedArgs, ",") != "--always-approve" {
		t.Fatalf("fixed_args %v", grok.FixedArgs)
	}
	if strings.Join(grok.FixedEnv, ",") != "GROK_CLAUDE_MCPS_ENABLED=false" {
		t.Fatalf("fixed_env %v", grok.FixedEnv)
	}
	if strings.Join(grok.ValueFlags, ",") != "-p,--cwd" {
		t.Fatalf("value_flags %v", grok.ValueFlags)
	}
	if strings.Join(grok.CredentialFiles, ",") != ".grok/auth.json" {
		t.Fatalf("credential_files %v", grok.CredentialFiles)
	}
	text := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"sandbox_bin ignored", "fixed_args ignored", "fixed_env ignored", "value_flags", "credential_files"} {
		if !strings.Contains(text, want) {
			t.Fatalf("warnings lack %q:\n%s", want, text)
		}
	}

	bad := writePol(t, "bad.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
credential_files = ["../auth.json"]
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	p, err = Load(Options{Path: bad})
	if err != nil {
		t.Fatal(err)
	}
	if p.Loaded || len(p.CLITools) != 0 {
		t.Fatalf("escaped credential file did not fail closed: %+v %v", p.CLITools, p.Warnings)
	}
}

func TestProxyHostsNarrowAndJailOptIn(t *testing.T) {
	local := writePol(t, "policy.toml", `
[[tools.cli]]
name = "grok"
path = "/tmp/evil"
credential_home = "/tmp/evil-home"
proxy_hosts = ["api.x.ai", "evil.example"]
allow_jail_credentials = true
timeout = "30s"
max_output = 100
max_calls_per_hour = 2
`)
	managed := writePol(t, "managed.json", `{
	  "tools": {"cli": [{
	    "name": "grok",
	    "path": "/usr/bin/grok",
	    "credential_home": "/var/lib/lgb/grok",
	    "proxy_hosts": ["api.x.ai", "cli-chat-proxy.grok.com"],
	    "allow_jail_credentials": true,
	    "timeout": "1m",
	    "max_output": 8000,
	    "max_calls_per_hour": 20
	  }]}
	}`)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok := p.COI("grok")
	if !ok {
		t.Fatal(p.Warnings)
	}
	if !grok.AllowJailCredentials {
		t.Fatal("managed jail opt-in was cleared by a rejected local true")
	}
	if strings.Join(grok.ProxyHosts, ",") != "api.x.ai" {
		t.Fatalf("proxy_hosts %v", grok.ProxyHosts)
	}
	text := strings.Join(p.Warnings, "\n")
	if !strings.Contains(text, "allow_jail_credentials is ignored") || !strings.Contains(text, "proxy_hosts") {
		t.Fatalf("warnings %s", text)
	}

	off := writePol(t, "off.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
allow_jail_credentials = false
timeout = "30s"
max_output = 100
max_calls_per_hour = 2
`)
	p, err = Load(Options{Path: off, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok = p.COI("grok")
	if !ok || grok.AllowJailCredentials {
		t.Fatalf("local false did not turn the managed opt-in off: %+v", grok)
	}

	only := writePol(t, "only.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
proxy_hosts = ["API.X.AI."]
allow_jail_credentials = true
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	p, err = Load(Options{Path: only})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok = p.COI("grok")
	if !ok || grok.AllowJailCredentials || strings.Join(grok.ProxyHosts, ",") != "api.x.ai" {
		t.Fatalf("local-only %+v warnings %v", grok, p.Warnings)
	}

	bad := writePol(t, "bad-host.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
proxy_hosts = ["https://api.x.ai/v1"]
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	p, err = Load(Options{Path: bad})
	if err != nil {
		t.Fatal(err)
	}
	if p.Loaded || len(p.CLITools) != 0 {
		t.Fatalf("bad proxy host did not fail closed: %+v", p.CLITools)
	}
}

func TestProxyPathPrefixesDefaultAndNarrow(t *testing.T) {
	omitted := writePol(t, "omit.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
proxy_hosts = ["cli-chat-proxy.grok.com"]
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	p, err := Load(Options{Path: omitted})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok := p.COI("grok")
	if !ok || strings.Join(grok.ProxyPathPrefixes, ",") != DefaultProxyPathPrefix {
		t.Fatalf("default prefixes %+v warnings %v", grok.ProxyPathPrefixes, p.Warnings)
	}

	local := writePol(t, "wide.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
proxy_path_prefixes = ["/v1", "/admin"]
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	managed := writePol(t, "managed.json", `{
	  "tools": {"cli": [{
	    "name": "grok",
	    "path": "/usr/bin/grok",
	    "credential_home": "/var/lib/lgb/grok",
	    "proxy_path_prefixes": ["/v1", "/v1/responses"],
	    "timeout": "1s",
	    "max_output": 1,
	    "max_calls_per_hour": 1
	  }]}
	}`)
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok = p.COI("grok")
	if !ok || strings.Join(grok.ProxyPathPrefixes, ",") != "/v1" {
		t.Fatalf("narrowed %+v", grok.ProxyPathPrefixes)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "proxy_path_prefixes") {
		t.Fatalf("warnings %v", p.Warnings)
	}

	empty := writePol(t, "empty.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
proxy_path_prefixes = []
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	p, err = Load(Options{Path: empty})
	if err != nil {
		t.Fatal(err)
	}
	grok, ok = p.COI("grok")
	if !ok || grok.ProxyPathPrefixes == nil || len(grok.ProxyPathPrefixes) != 0 {
		t.Fatalf("explicit empty %+v", grok.ProxyPathPrefixes)
	}

	bad := writePol(t, "bad-prefix.toml", `
[[tools.cli]]
name = "grok"
path = "/usr/bin/grok"
credential_home = "/var/lib/lgb/grok"
proxy_path_prefixes = ["/v1/../admin"]
timeout = "1s"
max_output = 1
max_calls_per_hour = 1
`)
	p, err = Load(Options{Path: bad})
	if err != nil {
		t.Fatal(err)
	}
	if p.Loaded || len(p.CLITools) != 0 {
		t.Fatalf("bad prefix did not fail closed: %+v %v", p.CLITools, p.Warnings)
	}
}
