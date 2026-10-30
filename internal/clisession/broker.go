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
// --allowedTools is an allow list. --disallowedTools may stay.
func AssertBrokerLaunch(argv []string) error {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "--allowedTools":
			return fmt.Errorf("broker launch refuses %s", a)
		case "--permission-mode":
			if i+1 < len(argv) && BrokerModeForbidden(argv[i+1]) {
				return fmt.Errorf("broker launch refuses permission mode %s", argv[i+1])
			}
		}
		if strings.HasPrefix(a, "--permission-mode=") && BrokerModeForbidden(strings.TrimPrefix(a, "--permission-mode=")) {
			return fmt.Errorf("broker launch refuses %s", a)
		}
		if strings.HasPrefix(a, "--allowedTools=") || a == "--dangerously-skip-permissions=true" {
			return fmt.Errorf("broker launch refuses %s", a)
		}
	}
	return nil
}
