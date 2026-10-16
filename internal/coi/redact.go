package coi

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
)

const (
	maxSecretFiles = 256
	maxSecretFile  = 64 << 10
	minSecretLen   = 8
)

var secretKey = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|authorization|credential|bearer)`)

// ReadSecrets collects credential values under root so a later reply can hide them.
// A short value is skipped. An unreadable file or a link that leaves root fails.
func ReadSecrets(root string) ([]string, error) {
	root = filepath.Clean(root)
	dir, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	_ = dir.Close()
	seen := map[string]bool{}
	var secrets []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < minSecretLen || strings.ContainsAny(s, "\r\n") || seen[s] {
			return
		}
		seen[s] = true
		secrets = append(secrets, s)
	}
	files := 0
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if files >= maxSecretFiles {
			return io.ErrUnexpectedEOF
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		target := path
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
			if !hasPathPrefix(root, resolved) {
				return io.ErrUnexpectedEOF
			}
			target = resolved
			st, err := os.Stat(target)
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() {
				return nil
			}
		} else if !info.Mode().IsRegular() {
			return nil
		}
		body, err := readLimited(target, maxSecretFile)
		if err != nil {
			return err
		}
		files++
		extractSecrets(d.Name(), body, add)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func readLimited(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, n))
}

func extractSecrets(name string, body []byte, add func(string)) {
	secretFile := fileLooksSecret(name)
	trim := strings.TrimSpace(string(body))
	if secretFile && trim != "" && !strings.ContainsAny(trim, " \t\r\n{}[]") {
		add(trim)
	}
	if len(trim) > 0 && trim[0] == '{' || len(trim) > 0 && trim[0] == '[' {
		var v any
		if json.Unmarshal(body, &v) == nil {
			walkSecrets(v, "", secretFile, add)
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			key, val, ok = strings.Cut(line, ":")
		}
		if !ok || !secretKey.MatchString(key) {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		add(val)
	}
}

func fileLooksSecret(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"auth", "credential", "token", "secret", "password"} {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

func walkSecrets(v any, key string, secretFile bool, add func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			walkSecrets(child, k, secretFile, add)
		}
	case []any:
		for _, child := range t {
			walkSecrets(child, key, secretFile, add)
		}
	case string:
		if secretKey.MatchString(key) || (secretFile && len(t) >= minSecretLen && !strings.ContainsAny(t, " \t")) {
			add(t)
		}
	}
}

// RedactOutput hides audit-shaped tokens, credential-home paths, and literal secrets.
func RedactOutput(s string, paths, secrets []string) string {
	s = audit.RedactText(s)
	var homes []string
	for _, p := range paths {
		p = filepath.Clean(p)
		if p == "" || p == "." || p == string(filepath.Separator) {
			continue
		}
		homes = append(homes, p)
	}
	sort.Slice(homes, func(i, j int) bool { return len(homes[i]) > len(homes[j]) })
	for _, p := range homes {
		s = strings.ReplaceAll(s, p+"/", "[credential-home]/")
		s = strings.ReplaceAll(s, p, "[credential-home]")
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, sec := range secrets {
		if len(sec) < minSecretLen {
			continue
		}
		s = strings.ReplaceAll(s, sec, "[redacted]")
	}
	return s
}
