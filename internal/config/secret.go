package config

import (
	"os"
	"strings"
)

const (
	readyKey = "LGB_ENV_READY"
	readyVal = "1"
)

// heldAuth is the admin token kept after the environment is scrubbed.
var heldAuth string

var secretKeys = map[string]bool{
	"AUTH_TOKEN":              true,
	"XAI_API_KEY":             true,
	"ANTHROPIC_API_KEY":       true,
	"CLAUDE_CODE_OAUTH_TOKEN": true,
}

func dropEnv(key, val, token string) bool {
	if secretKeys[key] || key == readyKey || sensitiveName(key) {
		return true
	}
	if strings.HasPrefix(key, "LGB_CANARY_") {
		return true
	}
	if token != "" && strings.Contains(val, token) {
		return true
	}
	return false
}

// sensitiveName is true when the variable name looks like a credential.
// Matching is case-insensitive and by substring. SSH_AUTH_SOCK and GPG_TTY
// do not match these fragments and stay.
func sensitiveName(key string) bool {
	u := strings.ToUpper(key)
	for _, frag := range []string{"KEY", "TOKEN", "SECRET", "PASS"} {
		if strings.Contains(u, frag) {
			return true
		}
	}
	return false
}

func scrubbedEnviron(env []string, token string) []string {
	return scrubbedEnvironMarker(env, token, readyVal)
}

func scrubbedEnvironMarker(env []string, token, marker string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || dropEnv(k, v, token) {
			continue
		}
		out = append(out, kv)
	}
	if marker == "" {
		marker = readyVal
	}
	return append(out, readyKey+"="+marker)
}

func unsetSecrets(token string) {
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !dropEnv(k, v, token) {
			continue
		}
		_ = os.Unsetenv(k)
	}
}
