package clisession

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HostConfigPaths are host files a CLI still reads. The Linux jail bind-mounts
// /etc read-only, so these stay visible inside the jail. Managed policy must
// opt in before a turn is allowed to see one.
var HostConfigPaths = []string{
	"/etc/grok/requirements.toml",
	"/etc/claude-code/managed-settings.json",
}

// UntrustedConfigError refuses a turn because a config name was not written
// by the daemon, or a host file is present and untrusted.
type UntrustedConfigError struct {
	Names []string
}

func (e *UntrustedConfigError) Error() string {
	return "untrusted CLI config, so the turn was refused"
}

// grokSealMarker is the only body the daemon writes for an inert name.
// config.toml uses grokPermissionTOML instead.
const grokSealMarker = "# Written by local-grok-bots. Do not edit.\n"

// grokSealDirEntry is the only file inside a sealed directory.
const grokSealDirEntry = "placeholder"

type grokSealEntry struct {
	name string
	dir  bool
	body []byte
}

func grokSealEntries() []grokSealEntry {
	mark := []byte(grokSealMarker)
	return []grokSealEntry{
		{name: "config.toml", body: []byte(grokPermissionTOML())},
		{name: "requirements.toml", body: mark},
		{name: "trusted_folders.toml", body: mark},
		{name: "managed_config.toml", body: mark},
		{name: "hooks-paths", body: mark},
		{name: "hooks", dir: true, body: mark},
		{name: "plugins", dir: true, body: mark},
		{name: "skills", dir: true, body: mark},
		{name: "agents", dir: true, body: mark},
	}
}

// SealGrokHome creates missing daemon-owned names under grokHome and refuses
// a name whose bytes are not the daemon's. root is the trusted directory.
// A foreign file is left in place.
func SealGrokHome(root, grokHome string) error {
	relHome, err := relUnder(root, grokHome)
	if err != nil {
		return err
	}
	for _, ent := range grokSealEntries() {
		if err := ensureGrokSeal(root, filepath.Join(relHome, ent.name), ent); err != nil {
			return err
		}
	}
	return nil
}

func ensureGrokSeal(root, rel string, ent grokSealEntry) error {
	path := filepath.Join(root, rel)
	match, missing, err := grokSealMatches(path, ent)
	if err != nil || (!match && !missing) {
		return &UntrustedConfigError{Names: []string{ent.name}}
	}
	if match {
		return nil
	}
	if ent.dir {
		if err := mkdirNoFollow(root, rel); err != nil {
			return err
		}
		return writeFileNoFollow(root, filepath.Join(rel, grokSealDirEntry), ent.body, 0o600)
	}
	return writeFileNoFollow(root, rel, ent.body, 0o600)
}

// grokSealMatches reports whether path is the daemon's content.
// missing is true only when path does not exist.
func grokSealMatches(path string, ent grokSealEntry) (match, missing bool, err error) {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, true, nil
		}
		return false, false, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return false, false, nil
	}
	if ent.dir {
		if !st.IsDir() {
			return false, false, nil
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return false, false, err
		}
		if len(entries) != 1 || entries[0].Name() != grokSealDirEntry {
			return false, false, nil
		}
		info, err := entries[0].Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, false, nil
		}
		body, err := os.ReadFile(filepath.Join(path, grokSealDirEntry))
		if err != nil || !bytes.Equal(body, ent.body) {
			return false, false, nil
		}
		return true, false, nil
	}
	if !st.Mode().IsRegular() {
		return false, false, nil
	}
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, ent.body) {
		return false, false, nil
	}
	return true, false, nil
}

// grokSealBinds are read-only mounts laid over the writable GROK_HOME bind.
// Every sealed name must already exist. A missing name refuses the turn.
func grokSealBinds(grokHome string) ([]string, error) {
	grokHome = filepath.Clean(strings.TrimSpace(grokHome))
	if grokHome == "" || grokHome == "." || !filepath.IsAbs(grokHome) {
		return nil, nil
	}
	st, err := os.Lstat(grokHome)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return nil, fmt.Errorf("grok home config is incomplete, so the turn was refused")
	}
	var args []string
	for _, ent := range grokSealEntries() {
		p := filepath.Join(grokHome, ent.name)
		match, missing, err := grokSealMatches(p, ent)
		if err != nil || missing {
			return nil, fmt.Errorf("grok home config is incomplete, so the turn was refused")
		}
		if !match {
			return nil, &UntrustedConfigError{Names: []string{ent.name}}
		}
		args = append(args, "--ro-bind", p, p)
	}
	return args, nil
}

// PresentHostConfig returns paths that exist, including a symlink.
func PresentHostConfig(paths []string) []string {
	var out []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// RefuseHostConfig fails the turn when an untrusted host file is present.
func RefuseHostConfig(trust bool, paths []string) error {
	if trust {
		return nil
	}
	names := PresentHostConfig(paths)
	if len(names) == 0 {
		return nil
	}
	return &UntrustedConfigError{Names: names}
}
