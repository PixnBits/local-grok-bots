package clisession

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// HostConfigPaths are host files a CLI still reads. The Linux jail bind-mounts
// /etc read-only, so these stay visible inside the jail. Managed policy must
// opt in before a turn is allowed to see one.
var HostConfigPaths = []string{
	"/etc/grok/requirements.toml",
	"/etc/grok/managed_config.toml",
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

// grokSealMarker is the inert body for a sealed name.
// config.toml uses grokPermissionTOML. requirements.toml uses grokRequirementsTOML.
const grokSealMarker = "# Written by local-grok-bots. Do not edit.\n"

// shellRCNames are the startup files sealed in HOME before a Grok turn.
var shellRCNames = []string{
	".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc",
}

// grokRequirementsTOML keeps remembered tool grants off. The key is under [ui].
func grokRequirementsTOML() string {
	return grokSealMarker + "[ui]\nremember_tool_approvals = false\n"
}

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
		{name: "requirements.toml", body: []byte(grokRequirementsTOML())},
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
	for _, name := range []string{"sessions", "logs"} {
		if err := ensureRealDir(root, grokHome, name); err != nil {
			return err
		}
	}
	return sealSessionPermissions(grokHome)
}

func ensureGrokSeal(root, rel string, ent grokSealEntry) error {
	path := filepath.Join(root, rel)
	match, missing, err := grokSealMatches(path, ent)
	if err != nil || (!match && !missing) {
		if ent.name == "requirements.toml" && !ent.dir {
			if upgraded, uerr := upgradeRequirementsMarker(root, rel, ent.body); upgraded {
				return uerr
			}
		}
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
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || tooManyLinks(info) {
			return false, false, nil
		}
		body, err := os.ReadFile(filepath.Join(path, grokSealDirEntry))
		if err != nil || !bytes.Equal(body, ent.body) {
			return false, false, nil
		}
		return true, false, nil
	}
	return sealFileState(path, ent.body)
}

// grokSealBinds are read-only mounts for sealed names and session permission
// files. Every sealed name must already exist. A missing name refuses the turn.
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
	perm, err := sessionPermissionBinds(grokHome)
	if err != nil {
		return nil, err
	}
	return append(args, perm...), nil
}

func sealFileState(path string, body []byte) (match, missing bool, err error) {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, true, nil
		}
		return false, false, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || tooManyLinks(st) {
		return false, false, nil
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, body) {
		return false, false, nil
	}
	return true, false, nil
}

// upgradeRequirementsMarker rewrites only the daemon's previous marker.
// Any other body, link, or extra name stays in place.
func upgradeRequirementsMarker(root, rel string, want []byte) (bool, error) {
	path := filepath.Join(root, rel)
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || tooManyLinks(st) {
		return false, nil
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, []byte(grokSealMarker)) {
		return false, nil
	}
	return true, writeFileNoFollow(root, rel, want, 0o600)
}

func ensureRealDir(root, grokHome, name string) error {
	rel, err := relUnder(root, filepath.Join(grokHome, name))
	if err != nil {
		return err
	}
	path := filepath.Join(root, rel)
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return mkdirNoFollow(root, rel)
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return &UntrustedConfigError{Names: []string{name}}
	}
	return nil
}

func sealSessionPermissions(grokHome string) error {
	bad, _, err := walkSessionPermissions(grokHome)
	if err != nil {
		return err
	}
	if len(bad) > 0 {
		return &UntrustedConfigError{Names: bad}
	}
	return nil
}

func sessionPermissionBinds(grokHome string) ([]string, error) {
	bad, binds, err := walkSessionPermissions(grokHome)
	if err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		return nil, &UntrustedConfigError{Names: bad}
	}
	return binds, nil
}

// walkSessionPermissions lists session permission files.
// bad names are relative to grokHome. Matching files are left in place.
func walkSessionPermissions(grokHome string) (bad []string, binds []string, err error) {
	sessions := filepath.Join(grokHome, "sessions")
	st, err := os.Lstat(sessions)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return []string{"sessions"}, nil, nil
	}
	err = filepath.WalkDir(sessions, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == sessions {
			return nil
		}
		rel, relErr := filepath.Rel(grokHome, path)
		if relErr != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("grok home config is incomplete, so the turn was refused")
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			bad = append(bad, rel)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		matched, matchErr := filepath.Match("permission*.toml", d.Name())
		if matchErr != nil {
			return matchErr
		}
		if !matched {
			return nil
		}
		if !info.Mode().IsRegular() || tooManyLinks(info) {
			bad = append(bad, rel)
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(body, []byte(grokSealMarker)) {
			bad = append(bad, rel)
			return nil
		}
		binds = append(binds, "--ro-bind", path, path)
		return nil
	})
	return bad, binds, err
}

// grokWritableBinds opens sessions and logs inside a read-only GROK_HOME.
// A symlink or a non-directory refuses the turn. A missing directory is created.
func grokWritableBinds(grokHome string) ([]string, error) {
	grokHome = filepath.Clean(strings.TrimSpace(grokHome))
	if grokHome == "" || grokHome == "." || !filepath.IsAbs(grokHome) {
		return nil, nil
	}
	var args []string
	for _, name := range []string{"sessions", "logs"} {
		p := filepath.Join(grokHome, name)
		st, err := os.Lstat(p)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("grok home config is incomplete, so the turn was refused")
			}
			if mkErr := os.Mkdir(p, 0o700); mkErr != nil {
				return nil, fmt.Errorf("grok home config is incomplete, so the turn was refused")
			}
			st, err = os.Lstat(p)
			if err != nil {
				return nil, fmt.Errorf("grok home config is incomplete, so the turn was refused")
			}
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return nil, &UntrustedConfigError{Names: []string{name}}
		}
		args = append(args, "--bind", p, p)
	}
	for _, name := range grokLockFiles {
		p := filepath.Join(grokHome, name)
		if err := ensureLockFile(p); err != nil {
			return nil, err
		}
		args = append(args, "--bind", p, p)
	}
	return args, nil
}

// grokLockFiles are lock files Grok must open for writing at start even when
// the rest of GROK_HOME is read-only. Their content is never read as config.
var grokLockFiles = []string{"managed_config.lock", "auth.json.lock"}

// ensureLockFile creates an empty lock file, or accepts an existing plain
// file with one link. A symlink, a directory, or an extra link refuses.
func ensureLockFile(p string) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("grok home config is incomplete, so the turn was refused")
	}
	st, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("grok home config is incomplete, so the turn was refused")
	}
	if !st.Mode().IsRegular() || tooManyLinks(st) {
		return &UntrustedConfigError{Names: []string{filepath.Base(p)}}
	}
	return nil
}

// prepareShellRC creates a missing startup file as the daemon placeholder.
// A different file, a symlink, or an extra link is left in place.
func prepareShellRC(home string) error {
	home = filepath.Clean(strings.TrimSpace(home))
	if home == "" || home == "." || !filepath.IsAbs(home) {
		return nil
	}
	st, err := os.Lstat(home)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return nil
	}
	body := []byte(grokSealMarker)
	for _, name := range shellRCNames {
		if err := ensureShellRCFile(home, name, body); err != nil {
			return err
		}
	}
	return nil
}

func ensureShellRCFile(home, name string, body []byte) error {
	dest := filepath.Join(home, name)
	match, missing, err := sealFileState(dest, body)
	if err != nil {
		return err
	}
	if match {
		return nil
	}
	if !missing {
		return &UntrustedConfigError{Names: []string{name}}
	}
	if err := createExclusiveNoFollow(home, name, body); err != nil {
		match, missing, err2 := sealFileState(dest, body)
		if err2 == nil && match {
			return nil
		}
		if err2 == nil && !missing {
			return &UntrustedConfigError{Names: []string{name}}
		}
		return err
	}
	return nil
}

func shellRCBinds(home string) ([]string, error) {
	home = filepath.Clean(strings.TrimSpace(home))
	if home == "" || home == "." || !filepath.IsAbs(home) {
		return nil, nil
	}
	st, err := os.Lstat(home)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return nil, nil
	}
	if err := prepareShellRC(home); err != nil {
		return nil, err
	}
	body := []byte(grokSealMarker)
	var args []string
	for _, name := range shellRCNames {
		p := filepath.Join(home, name)
		match, missing, err := sealFileState(p, body)
		if err != nil || missing || !match {
			return nil, &UntrustedConfigError{Names: []string{name}}
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
