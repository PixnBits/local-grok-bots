package daemon

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// pathForms is the cleaned absolute path and, when the path exists and
// differs, the symlink-resolved path.
func pathForms(p string) []string {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil
	}
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	p = filepath.Clean(p)
	if p == "" || p == "." {
		return nil
	}
	out := []string{p}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return out
	}
	resolved = filepath.Clean(resolved)
	if resolved != p {
		out = append(out, resolved)
	}
	return out
}

// pathsOverlap reports whether a and b are the same path or one contains
// the other. Each side is compared both cleaned and, when it exists, resolved.
func pathsOverlap(a, b string) bool {
	for _, x := range pathForms(a) {
		for _, y := range pathForms(b) {
			if pathInside(x, y) || pathInside(y, x) {
				return true
			}
		}
	}
	return false
}

// checkAuthTokensBinds refuses an AUTH_TOKENS_FILE that sits inside a
// SANDBOX_BUILD_BINDS entry. Both sides use the raw and resolved paths.
func checkAuthTokensBinds(file string, binds []string) error {
	if strings.TrimSpace(file) == "" {
		return nil
	}
	paths := authTokensPaths(file)
	if len(paths) == 0 {
		paths = pathForms(file)
	}
	for _, bind := range binds {
		bind = strings.TrimSpace(bind)
		if bind == "" {
			continue
		}
		for _, p := range paths {
			if pathsOverlap(p, bind) {
				return fmt.Errorf("AUTH_TOKENS_FILE %s overlaps SANDBOX_BUILD_BINDS %s", p, bind)
			}
		}
	}
	return nil
}

// checkPathOverlaps refuses a SANDBOX_BUILD_BINDS entry or a tools.cli
// credential_home that overlaps a daemon secret. Credential homes are left
// out of the secret list when they are the path being checked.
func checkPathOverlaps(cfg config.Config, pol policy.Policy) error {
	secrets := secretPaths(cfg, pol, true)
	for _, bind := range cfg.BuildBinds {
		bind = strings.TrimSpace(bind)
		if bind == "" {
			continue
		}
		for _, secret := range secrets {
			if pathsOverlap(bind, secret) {
				return fmt.Errorf("SANDBOX_BUILD_BINDS %s overlaps a protected path", bind)
			}
		}
	}
	base := secretPaths(cfg, pol, false)
	for _, tool := range pol.CLITools {
		home := strings.TrimSpace(tool.CredentialHome)
		if home == "" {
			continue
		}
		for _, secret := range base {
			if pathsOverlap(home, secret) {
				return fmt.Errorf("tools.cli credential_home %s overlaps a protected path", home)
			}
		}
	}
	return nil
}
