package config

import (
	"os"
	"strings"
)

const (
	readyKey = "LGB_ENV_READY"
	readyVal = "1"
	secretFD = 3
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
	if secretKeys[key] || key == readyKey {
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

func scrubbedEnviron(env []string, token string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || dropEnv(k, v, token) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, readyKey+"="+readyVal)
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
