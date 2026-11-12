package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoEnvDefaultsAndNarrows(t *testing.T) {
	def := Defaults().EffectiveGoEnv()
	if def.Proxy != "off" || def.Toolchain != "local" || def.Flags != "" || def.SumDB != "off" {
		t.Fatalf("defaults %+v", def)
	}
	dir := t.TempDir()
	local := filepath.Join(dir, "policy.toml")
	write := func(body string) Policy {
		t.Helper()
		if err := os.WriteFile(local, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(Options{Path: local})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := write("[sandbox]\ngoproxy = \"https://proxy.golang.org,direct\"\ngotoolchain = \"auto\"\ngoflags = \"-mod=mod\"\n")
	env := p.EffectiveGoEnv()
	if env.Proxy != "off" || env.Toolchain != "local" || env.Flags != "" || env.SumDB != "off" {
		t.Fatalf("local widen %+v", env)
	}
	text := strings.Join(p.Warnings, "\n")
	if !strings.Contains(text, "goproxy") || !strings.Contains(text, "gotoolchain") || !strings.Contains(text, "goflags") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	p = write("[sandbox]\ngomodcache = \"/tmp/cache\"\n")
	env = p.EffectiveGoEnv()
	if env.Proxy != "off" || env.Toolchain != "local" || !strings.Contains(strings.Join(p.Warnings, "\n"), "unparseable") {
		t.Fatalf("cache path applied %+v %v", env, p.Warnings)
	}

	managed := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(managed, []byte(`{"sandbox":{"goproxy":"https://a.example,https://b.example,direct","gotoolchain":"auto","goflags":"-mod=readonly"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("[sandbox]\ngoproxy = \"https://a.example\"\ngotoolchain = \"local\"\ngoflags = \"-mod=readonly\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	env = p.EffectiveGoEnv()
	if env.Proxy != "https://a.example" || env.Toolchain != "local" || env.Flags != "-mod=readonly" || env.SumDB != "off" || len(p.Warnings) != 0 {
		t.Fatalf("narrow %+v %v", env, p.Warnings)
	}
	if err := os.WriteFile(local, []byte("[sandbox]\ngoproxy = \"off\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveGoEnv().Proxy != "off" {
		t.Fatalf("off %+v", p.EffectiveGoEnv())
	}
	if err := os.WriteFile(local, []byte("[sandbox]\ngoproxy = \"https://a.example,https://c.example\"\ngotoolchain = \"go1.22.0\"\ngoflags = \"-mod=mod\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	env = p.EffectiveGoEnv()
	if env.Proxy != "https://a.example,https://b.example,direct" || env.Toolchain != "auto" || env.Flags != "-mod=readonly" {
		t.Fatalf("kept ceiling %+v", env)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "keeping the tighter setting") {
		t.Fatalf("warnings %v", p.Warnings)
	}

	if err := os.WriteFile(managed, []byte(`{"sandbox":{"gotoolchain":"go1.22.0","goproxy":"off"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("[sandbox]\ngotoolchain = \"local\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveGoEnv().Toolchain != "local" || p.EffectiveGoEnv().Proxy != "off" {
		t.Fatalf("version narrowed %+v", p.EffectiveGoEnv())
	}
	if err := os.WriteFile(local, []byte("[sandbox]\ngotoolchain = \"auto\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveGoEnv().Toolchain != "go1.22.0" {
		t.Fatalf("auto widened %+v", p.EffectiveGoEnv())
	}

	base := GoEnv{Proxy: "off", Toolchain: "local", Flags: "-mod=readonly", SumDB: "off"}
	got, warns := NarrowGoEnv(base, "https://proxy.golang.org", "auto", "-mod=mod", true, true, true)
	if got.Proxy != "off" || got.Toolchain != "local" || got.Flags != "-mod=readonly" || got.SumDB != "off" || len(warns) != 3 {
		t.Fatalf("bot overlay %+v %v", got, warns)
	}
	got, warns = NarrowGoEnv(GoEnv{Proxy: "https://a.example,direct", Toolchain: "auto"}, "off", "local", "", true, true, false)
	if got.Proxy != "off" || got.Toolchain != "local" || got.SumDB != "off" || len(warns) != 0 {
		t.Fatalf("bot narrow %+v %v", got, warns)
	}
}
