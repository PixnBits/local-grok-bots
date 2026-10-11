package config

import "testing"

func TestBuildBindsFromEnv(t *testing.T) {
	t.Setenv("SANDBOX_BUILD_BINDS", " /opt/a : /opt/b ")
	c := FromEnv()
	if len(c.BuildBinds) != 2 || c.BuildBinds[0] != "/opt/a" || c.BuildBinds[1] != "/opt/b" {
		t.Fatalf("binds %#v", c.BuildBinds)
	}
	t.Setenv("SANDBOX_BUILD_BINDS", "")
	if FromEnv().BuildBinds != nil {
		t.Fatalf("empty binds %#v", FromEnv().BuildBinds)
	}
}
