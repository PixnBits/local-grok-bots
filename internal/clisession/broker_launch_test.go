package clisession

import "testing"

func TestGolden_BrokerLaunchRefusesAllowedToolsAliases(t *testing.T) {
	settings := "/data/cli/bot/claude-settings.json"
	base := []string{"claude", "--setting-sources=", "--settings", settings, "-p", "hi"}
	if err := AssertBrokerLaunch(base, settings, ""); err != nil {
		t.Fatal(err)
	}
	flags := []string{
		"--allowed-tools",
		"--allowed-tools=Bash",
		"--allowedTools",
		"--allowedTools=Bash",
		"--allowed_tools",
		"--allowed_tools=Bash",
		"--dangerously-skip-permissions",
		"--dangerously-skip-permissions=true",
		"--permission-mode=bypassPermissions",
	}
	for _, flag := range flags {
		argv := append(append([]string{}, base...), flag)
		if err := AssertBrokerLaunch(argv, settings, ""); err == nil {
			t.Fatalf("accepted %s", flag)
		}
	}
	argv := append(append([]string{}, base...), "--permission-mode", "bypassPermissions")
	if err := AssertBrokerLaunch(argv, settings, ""); err == nil {
		t.Fatal("accepted bypassPermissions")
	}
}

func TestAssertBrokerLaunch(t *testing.T) {
	settings := "/data/cli/bot/claude-settings.json"
	base := []string{"claude", "--setting-sources=", "--settings", settings, "-p", "hi"}
	if err := AssertBrokerLaunch(base, settings, ""); err != nil {
		t.Fatal(err)
	}
	two := []string{"claude", "--setting-sources", "", "--settings", settings}
	if err := AssertBrokerLaunch(two, settings, ""); err != nil {
		t.Fatal(err)
	}
	mcp := append(append([]string{}, base...), "--mcp-config", "/data/mcp.json")
	if err := AssertBrokerLaunch(mcp, settings, "/data/mcp.json"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		argv []string
		set  string
		mcp  string
	}{
		{name: "missing sources", argv: []string{"claude", "--settings", settings}, set: settings},
		{name: "two sources", argv: []string{"claude", "--setting-sources=", "--setting-sources=", "--settings", settings}, set: settings},
		{name: "sources value", argv: []string{"claude", "--setting-sources=user", "--settings", settings}, set: settings},
		{name: "wrong settings", argv: base, set: "/other.json"},
		{name: "settings equals other", argv: []string{"claude", "--setting-sources=", "--settings=/other.json"}, set: settings},
		{name: "add dir", argv: append(append([]string{}, base...), "--add-dir", "/tmp")},
		{name: "add dir equals", argv: append(append([]string{}, base...), "--add-dir=/tmp")},
		{name: "plugin dir", argv: append(append([]string{}, base...), "--plugin-dir=/opt/plugin")},
		{name: "foreign mcp", argv: mcp, set: settings, mcp: ""},
		{name: "other mcp", argv: mcp, set: settings, mcp: "/data/other.json"},
		{name: "allowed tools", argv: append(append([]string{}, base...), "--allowedTools", "Bash"), set: settings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := tc.set
			if set == "" {
				set = settings
			}
			if err := AssertBrokerLaunch(tc.argv, set, tc.mcp); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
}
