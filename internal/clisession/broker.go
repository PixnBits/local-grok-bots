package clisession

import (
	"fmt"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// BrokerModeForbidden is a Claude permission mode the broker will not
// launch. acceptEdits is not an always-allow mode for the rest of the
// daemon, and it is still refused here. An unknown mode is refused too.
func BrokerModeForbidden(mode string) bool {
	m := strings.ToLower(strings.TrimSpace(mode))
	m = strings.ReplaceAll(m, "_", "-")
	switch m {
	case "", "default", "plan":
		return false
	}
	if policy.IsBypassMode(mode) || policy.IsBypassMode(m) {
		return true
	}
	switch m {
	case "acceptedits", "accept-edits", "bypasspermissions", "bypass-permissions",
		"dontask", "dont-ask", "bypass", "always", "always-allow", "always-approve":
		return true
	default:
		return true
	}
}

// AssertBrokerLaunch rejects an argv that could skip the hook.
// settingsPath is the daemon-written --settings file. mcpConfig is the
// daemon's own MCP file; an empty value refuses every --mcp-config.
// --allowedTools is an allow list. --disallowedTools may stay.
// Exactly one empty --setting-sources is required.
func AssertBrokerLaunch(argv []string, settingsPath, mcpConfig string) error {
	sources := 0
	settings := 0
	settingsGot := ""
	mcp := 0
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "--allowedTools":
			return fmt.Errorf("broker launch refuses %s", a)
		case "--add-dir", "--plugin-dir":
			return fmt.Errorf("broker launch refuses %s", a)
		case "--permission-mode":
			if i+1 < len(argv) && BrokerModeForbidden(argv[i+1]) {
				return fmt.Errorf("broker launch refuses permission mode %s", argv[i+1])
			}
		case "--setting-sources=":
			sources++
		case "--setting-sources":
			if i+1 >= len(argv) || argv[i+1] != "" {
				return fmt.Errorf("broker launch refuses --setting-sources")
			}
			sources++
			i++
		case "--settings":
			if i+1 >= len(argv) {
				return fmt.Errorf("broker launch refuses --settings")
			}
			settings++
			settingsGot = argv[i+1]
			i++
		case "--mcp-config":
			if i+1 >= len(argv) {
				return fmt.Errorf("broker launch refuses --mcp-config")
			}
			if mcpConfig == "" || argv[i+1] != mcpConfig {
				return fmt.Errorf("broker launch refuses --mcp-config")
			}
			mcp++
			i++
		}
		if strings.HasPrefix(a, "--permission-mode=") && BrokerModeForbidden(strings.TrimPrefix(a, "--permission-mode=")) {
			return fmt.Errorf("broker launch refuses %s", a)
		}
		if strings.HasPrefix(a, "--allowedTools=") || a == "--dangerously-skip-permissions=true" {
			return fmt.Errorf("broker launch refuses %s", a)
		}
		if strings.HasPrefix(a, "--add-dir=") || strings.HasPrefix(a, "--plugin-dir=") {
			return fmt.Errorf("broker launch refuses %s", a)
		}
		if strings.HasPrefix(a, "--setting-sources=") && a != "--setting-sources=" {
			return fmt.Errorf("broker launch refuses %s", a)
		}
		if strings.HasPrefix(a, "--settings=") {
			settings++
			settingsGot = strings.TrimPrefix(a, "--settings=")
		}
		if strings.HasPrefix(a, "--mcp-config=") {
			val := strings.TrimPrefix(a, "--mcp-config=")
			if mcpConfig == "" || val != mcpConfig {
				return fmt.Errorf("broker launch refuses --mcp-config")
			}
			mcp++
		}
	}
	if sources != 1 {
		return fmt.Errorf("broker launch refuses --setting-sources")
	}
	if settings != 1 || settingsGot == "" || settingsGot != settingsPath {
		return fmt.Errorf("broker launch refuses --settings")
	}
	if mcp > 1 {
		return fmt.Errorf("broker launch refuses --mcp-config")
	}
	return nil
}
