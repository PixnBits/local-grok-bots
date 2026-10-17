//go:build !linux

package config

import "os"

// ReexecIfNeeded unsets secret names. Darwin has no /proc/<pid>/environ, and
// Unsetenv does not rewrite the original startup memory.
func ReexecIfNeeded() {
	heldAuth = os.Getenv("AUTH_TOKEN")
	unsetSecrets(heldAuth)
}
