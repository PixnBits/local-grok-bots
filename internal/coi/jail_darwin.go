//go:build darwin

package coi

import (
	"os"
	"os/exec"
	"path/filepath"
)

const sandboxExecDefault = "/usr/bin/sandbox-exec"
const defaultSandboxBin = sandboxExecDefault

func wrapCommand(spec jailSpec) (*exec.Cmd, error) {
	exe, err := sandboxBinary(spec.SandboxBin, sandboxExecDefault)
	if err != nil {
		return nil, err
	}
	bin, err := resolvedFile(spec.Bin)
	if err != nil {
		return nil, err
	}
	ws, err := filepath.EvalSymlinks(spec.Workspace)
	if err != nil {
		return nil, ErrSandboxUnavailable
	}
	home, err := filepath.EvalSymlinks(spec.Home)
	if err != nil {
		return nil, ErrSandboxUnavailable
	}
	tmp := filepath.Join(home, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, ErrSandboxUnavailable
	}
	entry, entryArgs, extras := jailEntry(spec, spec.ProxySock)
	entryBin := bin
	if entry != spec.Bin {
		entryBin, err = resolvedFile(entry)
		if err != nil {
			return nil, ErrSandboxUnavailable
		}
	}
	prof, err := coiSeatbeltProfile(filepath.Clean(ws), filepath.Clean(home), filepath.Clean(entryBin), spec.ProxySock, extras)
	if err != nil {
		return nil, ErrSandboxUnavailable
	}
	args := append([]string{"-p", prof, entryBin}, entryArgs...)
	cmd := exec.Command(exe, args...)
	cmd.Dir = ws
	env := envMap(spec.Env)
	env["HOME"] = home
	env["TMPDIR"] = tmp
	env["PATH"] = systemPATH()
	if _, ok := env["GROK_HOME"]; ok {
		env["GROK_HOME"] = filepath.Join(home, ".grok")
	}
	cmd.Env = envList(env)
	detach(cmd)
	return cmd, nil
}
