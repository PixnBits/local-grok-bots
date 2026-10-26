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
				return &authCodedError{
					msg:  fmt.Sprintf("AUTH_TOKENS_FILE %s overlaps SANDBOX_BUILD_BINDS %s", p, bind),
					code: errAuthBind,
				}
			}
		}
	}
	return nil
}

// checkPathOverlaps refuses a SANDBOX_BUILD_BINDS entry or a tools.cli
// credential_home that overlaps a daemon secret. Credential homes are left
// out of the secret list when they are the path being checked, then compared
// with each other. Build binds also treat DATA_DIR itself, raw and resolved,
// as a secret, and a bind that does not exist is refused. A home inside
// DATA_DIR is accepted only at DATA_DIR/coi/<name> (not homes), including
// paths nested under that name. Any other path inside DATA_DIR is refused.
// A home strictly inside DATA_DIR/coi does not overlap that parent directory.
// It still overlaps any other secret. A home that contains DATA_DIR is refused.
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
				return fmt.Errorf("SANDBOX_BUILD_BINDS %s overlaps protected path %s", bind, secret)
			}
		}
		if _, err := os.Stat(bind); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("SANDBOX_BUILD_BINDS %s does not exist", bind)
			}
			return fmt.Errorf("SANDBOX_BUILD_BINDS %s: %w", bind, err)
		}
	}
	base := secretPaths(cfg, pol, false)
	wsForms := pathForms(cfg.Workspace())
	var homes []string
	for _, tool := range pol.CLITools {
		home := strings.TrimSpace(tool.CredentialHome)
		if home == "" {
			continue
		}
		if hit, ok := homeInsideWorkspace(home, wsForms); ok {
			return fmt.Errorf("tools.cli credential_home %s is inside the workspace %s", home, hit)
		}
		if credentialHomeInsideDataDir(home, cfg.DataDir) {
			return fmt.Errorf("tools.cli credential_home %s is inside DATA_DIR; use DATA_DIR/coi/<name> or a path outside DATA_DIR", home)
		}
		if hit, ok := credentialHomeOverlaps(home, cfg.DataDir, base); ok {
			return fmt.Errorf("tools.cli credential_home %s overlaps protected path %s", home, hit)
		}
		for _, other := range homes {
			if inner, outer, ok := nestedCredentialHome(home, other); ok {
				return fmt.Errorf("tools.cli credential_home %s is inside another home %s", inner, outer)
			}
		}
		homes = append(homes, home)
	}
	return nil
}

// homeInsideWorkspace reports whether any form of home is the workspace or
// a path under it. The returned path is the workspace form that matched.
func homeInsideWorkspace(home string, wsForms []string) (string, bool) {
	for _, h := range pathForms(home) {
		for _, ws := range wsForms {
			if pathInside(ws, h) {
				return ws, true
			}
		}
	}
	return "", false
}

// nestedCredentialHome reports a strict nest. inner and outer are the
// configured paths, not the resolved forms. Equal homes are not a nest.
func nestedCredentialHome(a, b string) (inner, outer string, ok bool) {
	for _, x := range pathForms(a) {
		for _, y := range pathForms(b) {
			if x == y {
				continue
			}
			if pathInside(y, x) {
				return a, b, true
			}
			if pathInside(x, y) {
				return b, a, true
			}
		}
	}
	return "", "", false
}

// credentialHomeInsideDataDir reports whether any raw or resolved form of
// home is inside DATA_DIR and is not DATA_DIR/coi/<name> or a path nested
// under that name. <name> is one path component and is not "homes".
func credentialHomeInsideDataDir(home, dataDir string) bool {
	for _, d := range pathForms(dataDir) {
		for _, h := range pathForms(home) {
			if !pathInside(d, h) {
				continue
			}
			rel, err := filepath.Rel(d, h)
			if err != nil || !coiHomeRel(rel) {
				return true
			}
		}
	}
	return false
}

// coiHomeRel is true for coi/<name> and coi/<name>/deeper, where name is
// one component and is not homes, ".", or "..".
func coiHomeRel(rel string) bool {
	rel = filepath.Clean(rel)
	if rel == "" || rel == "." {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) < 2 || parts[0] != "coi" {
		return false
	}
	id := parts[1]
	if id == "" || id == "." || id == ".." || id == "homes" {
		return false
	}
	for _, p := range parts[2:] {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

// credentialHomeOverlaps reports whether home equals or contains DATA_DIR,
// or overlaps a specific secret. The returned path is the protected path
// that matched. A home strictly inside DATA_DIR/coi does not overlap that
// parent directory. It still overlaps any other secret.
func credentialHomeOverlaps(home, dataDir string, secrets []string) (string, bool) {
	if hit, ok := homeContainsDataDir(home, dataDir); ok {
		return hit, true
	}
	parents := map[string]struct{}{}
	for _, form := range homeParentForms(dataDir) {
		parents[form] = struct{}{}
	}
	for _, secret := range secrets {
		if hit, ok := homeOverlapsSecret(home, secret, parents); ok {
			return hit, true
		}
	}
	return "", false
}

// homeContainsDataDir reports whether any form of home is DATA_DIR or has
// DATA_DIR inside it. A home nested under DATA_DIR is not a match. The
// returned path is the DATA_DIR form that matched.
func homeContainsDataDir(home, dataDir string) (string, bool) {
	homes := pathForms(home)
	for _, d := range pathForms(dataDir) {
		for _, h := range homes {
			if pathInside(h, d) {
				return d, true
			}
		}
	}
	return "", false
}

// homeParentForms is DATA_DIR/cli and DATA_DIR/coi, raw and resolved.
// A credential home strictly inside DATA_DIR/coi/<name> does not overlap
// the coi directory. Homes inside DATA_DIR/cli are refused before this
// exception is reached.
func homeParentForms(dataDir string) []string {
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
	for _, name := range []string{"cli", "coi"} {
		add(filepath.Join(dataDir, name))
		for _, form := range pathForms(dataDir) {
			add(filepath.Join(form, name))
		}
	}
	return out
}

// credentialHomesNest reports whether one credential home is strictly inside
// the other. Two tools may share one home. A home that contains another
// home is refused.
func credentialHomesNest(a, b string) bool {
	for _, x := range pathForms(a) {
		for _, y := range pathForms(b) {
			if x == y {
				continue
			}
			if pathInside(x, y) || pathInside(y, x) {
				return true
			}
		}
	}
	return false
}

// homeOverlapsSecret compares home with one secret path. Equality, and a
// home that contains the secret, overlap. A home strictly inside DATA_DIR/cli
// or DATA_DIR/coi does not overlap that parent directory. The cli case is
// refused earlier when the home is inside DATA_DIR. The returned path is
// the secret form that matched.
func homeOverlapsSecret(home, secret string, parents map[string]struct{}) (string, bool) {
	for _, h := range pathForms(home) {
		for _, s := range pathForms(secret) {
			if pathInside(h, s) {
				return s, true
			}
			if pathInside(s, h) {
				if _, ok := parents[s]; ok && h != s {
					continue
				}
				return s, true
			}
		}
	}
	return "", false
}
