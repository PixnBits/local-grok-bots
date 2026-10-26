package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// pathForms is the cleaned absolute path and, when it differs, the
// symlink-resolved path. A path that does not exist is resolved from the
// nearest existing ancestor, and the remaining components are joined back.
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
	resolved, ok := resolveThroughAncestor(p)
	if !ok {
		return out
	}
	resolved = filepath.Clean(resolved)
	if resolved != "" && resolved != p {
		out = append(out, resolved)
	}
	return out
}

// resolveThroughAncestor returns the EvalSymlinks result of p. When p does
// not exist, it resolves the nearest existing ancestor and rejoins the
// components below that ancestor. ok is false when no ancestor resolves.
func resolveThroughAncestor(p string) (string, bool) {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved, true
	}
	var pending []string
	cur := p
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
		pending = append(pending, filepath.Base(cur))
		_, err := os.Lstat(parent)
		if err != nil {
			if os.IsNotExist(err) {
				cur = parent
				continue
			}
			return "", false
		}
		resolved, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", false
		}
		for i := len(pending) - 1; i >= 0; i-- {
			resolved = filepath.Join(resolved, pending[i])
		}
		return resolved, true
	}
}

// pathsOverlap reports whether a and b are the same path or one contains
// the other. Each side is compared cleaned and symlink-resolved. A missing
// path is resolved from its nearest existing ancestor.
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
// out of the secret list when they are the path being checked. Build binds
// also treat DATA_DIR itself, raw and resolved, as a secret. A credential
// home is compared with the specific secret paths. A home under DATA_DIR/cli
// stays allowed. A home that equals or contains DATA_DIR is refused.
func checkPathOverlaps(cfg config.Config, pol policy.Policy) error {
	secrets := append([]string{}, secretPaths(cfg, pol, true)...)
	secrets = append(secrets, pathForms(cfg.DataDir)...)
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
		if credentialHomeOverlaps(home, cfg.DataDir, base) {
			return fmt.Errorf("tools.cli credential_home %s overlaps a protected path", home)
		}
	}
	return nil
}

// credentialHomeOverlaps reports whether home equals or contains DATA_DIR,
// or overlaps a specific secret. A home strictly inside DATA_DIR/cli does
// not overlap that cli directory. It still overlaps any other secret.
func credentialHomeOverlaps(home, dataDir string, secrets []string) bool {
	if homeContainsDataDir(home, dataDir) {
		return true
	}
	cli := map[string]struct{}{}
	for _, form := range cliDirForms(dataDir) {
		cli[form] = struct{}{}
	}
	for _, secret := range secrets {
		if homeOverlapsSecret(home, secret, cli) {
			return true
		}
	}
	return false
}

// homeContainsDataDir reports whether any form of home is DATA_DIR or has
// DATA_DIR inside it. A home nested under DATA_DIR is not a match.
func homeContainsDataDir(home, dataDir string) bool {
	homes := pathForms(home)
	for _, d := range pathForms(dataDir) {
		for _, h := range homes {
			if pathInside(h, d) {
				return true
			}
		}
	}
	return false
}

func cliDirForms(dataDir string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		for _, form := range pathForms(p) {
			if _, ok := seen[form]; ok {
				continue
			}
			seen[form] = struct{}{}
			out = append(out, form)
		}
	}
	add(filepath.Join(dataDir, "cli"))
	for _, form := range pathForms(dataDir) {
		add(filepath.Join(form, "cli"))
	}
	return out
}

// homeOverlapsSecret compares home with one secret path. Equality, and a
// home that contains the secret, overlap. A home strictly inside the
// DATA_DIR/cli directory does not overlap that directory.
func homeOverlapsSecret(home, secret string, cli map[string]struct{}) bool {
	for _, h := range pathForms(home) {
		for _, s := range pathForms(secret) {
			if pathInside(h, s) {
				return true
			}
			if pathInside(s, h) {
				if _, isCLI := cli[s]; isCLI && h != s {
					continue
				}
				return true
			}
		}
	}
	return false
}
