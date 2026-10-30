package clisession

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LaunchEnv is the environment the child process receives.
// A nil Isolate uses the process environment. When Isolate is set, Env is
// the child's environment even when that list is empty.
func LaunchEnv(spec Spec) []string {
	if spec.Isolate == nil {
		return os.Environ()
	}
	if spec.Isolate.Env == nil {
		return []string{}
	}
	return append([]string{}, spec.Isolate.Env...)
}

// ResolveLaunchPath is the absolute executable a launch will run.
// A name that contains a slash is that file. A bare name is searched on
// PATH from env. A nil env uses the process PATH. A relative candidate
// that is executable is a lookup failure and stops the search.
func ResolveLaunchPath(name string, env []string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%s not on PATH", name)
	}
	if strings.Contains(name, "/") {
		abs, err := filepath.Abs(name)
		if err != nil {
			return "", fmt.Errorf("%s not on PATH", name)
		}
		abs = filepath.Clean(abs)
		if err := launchExecutable(abs); err != nil {
			return "", fmt.Errorf("%s not on PATH", name)
		}
		return abs, nil
	}
	pathEnv := os.Getenv("PATH")
	if env != nil {
		pathEnv = envValue(env, "PATH")
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		if !filepath.IsAbs(candidate) {
			if launchExecutable(candidate) == nil {
				return "", fmt.Errorf("%s not on PATH", name)
			}
			continue
		}
		if launchExecutable(candidate) == nil {
			return filepath.Clean(candidate), nil
		}
	}
	return "", fmt.Errorf("%s not on PATH", name)
}

func launchExecutable(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("not a file")
	}
	if st.Mode()&0o111 == 0 {
		return fmt.Errorf("not executable")
	}
	return nil
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):]
		}
	}
	return ""
}
