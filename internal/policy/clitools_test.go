package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
