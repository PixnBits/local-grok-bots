//go:build darwin

package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func launchOS(ctx context.Context, p *prepared) (string, string, error) {
	if err := UnsupportedRlimits("darwin", p.rlimits); err != nil {
		return "", "", err
	}
	sb, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return "", "", fmt.Errorf("shell sandbox unavailable: sandbox-exec not on PATH")
	}
	root := mountSrc(p, "/lgb")
	if root == "" {
		return "", "", fmt.Errorf("shell sandbox unavailable: prep dir missing")
	}
	pathBin := filepath.Join(p.dir, "bin")
	realDir := filepath.Join(p.dir, "real")
	for _, dir := range []string{pathBin, realDir, filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", "", err
		}
	}
	shell := "/bin/sh"
	signedShell := filepath.Join(p.dir, "sh")
	if err := copySigned("/bin/sh", signedShell); err == nil {
		shell = signedShell
	}

	var dylib string
	var deny []string
	for _, m := range p.mounts {
		switch {
		case m.Dst == "/lgb/preload.so":
			dylib = m.Src
		case m.Dst == "/lgb/id_ed25519":
			dst := filepath.Join(realDir, "id_ed25519")
			if err := copyFile(m.Src, dst, 0o600); err != nil {
				return "", "", err
			}
		case strings.HasPrefix(m.Dst, "/usr/bin/"):
			if shell != "/bin/sh" {
				if err := retargetShebang(m.Src, shell); err != nil {
					return "", "", err
				}
			}
			link := filepath.Join(pathBin, filepath.Base(m.Dst))
			_ = os.Remove(link)
			if err := os.Symlink(m.Src, link); err != nil {
				return "", "", err
			}
		case strings.HasPrefix(m.Dst, "/lgb/real/"):
			name := filepath.Base(m.Dst)
			dst := filepath.Join(realDir, name)
			if err := copySigned(m.Src, dst); err != nil {
				_ = os.Remove(dst)
				if err := os.Symlink(m.Src, dst); err != nil {
					return "", "", err
				}
				continue
			}
			deny = append(deny, m.Src)
			if system := "/usr/bin/" + name; system != m.Src {
				if st, err := os.Stat(system); err == nil && !st.IsDir() {
					deny = append(deny, system)
				}
			}
		}
	}
	if dylib != "" {
		for _, name := range []string{"python3", "python", "perl", "ruby", "node", "curl"} {
			if _, err := os.Lstat(filepath.Join(pathBin, name)); err == nil {
				continue
			}
			src, err := exec.LookPath(name)
			if err != nil {
				continue
			}
			dst := filepath.Join(pathBin, name)
			if err := copySigned(src, dst); err != nil {
				_ = os.Remove(dst)
				continue
			}
			deny = append(deny, src)
			if system := "/usr/bin/" + name; system != src {
				if st, err := os.Stat(system); err == nil && !st.IsDir() {
					deny = append(deny, system)
				}
			}
		}
	}

	reads := append(ExistingReadRoots(), p.dir)
	for _, m := range p.mounts {
		if !m.RO || m.Src != m.Dst {
			continue
		}
		if strings.HasPrefix(m.Dst, "/lgb") || strings.HasPrefix(m.Dst, "/usr") || strings.HasPrefix(m.Dst, "/work") {
			continue
		}
		reads = append(reads, m.Src)
	}
	var socks []string
	if p.proxy != nil {
		socks = append(socks, filepath.Join(root, "sock", "proxy.sock"))
	}
	writes := []string{root}
	if p.readonly {
		reads = append(reads, p.workspace)
	} else {
		writes = append([]string{p.workspace}, writes...)
	}
	profile, err := (Seatbelt{
		Read:         reads,
		Write:        writes,
		ProxySockets: socks,
		DenyExec:     deny,
	}).Render()
	if err != nil {
		return "", "", err
	}
	profilePath := filepath.Join(p.dir, "seatbelt.sb")
	if err := os.WriteFile(profilePath, []byte(profile), 0o644); err != nil {
		return "", "", err
	}

	env := rewriteShellEnv(p.env, p.workspace, root, realDir, pathBin+":"+jailPATH(), filepath.Join(root, "tmp"))
	if p.proxy != nil {
		env = setEnv(env, "LGB_PROXY_SOCK", filepath.Join(root, "sock", "proxy.sock"))
	}
	if _, err := os.Stat(filepath.Join(realDir, "id_ed25519")); err == nil {
		env = setEnv(env, "LGB_KEY", filepath.Join(realDir, "id_ed25519"))
	}
	if dylib != "" && shell != "/bin/sh" {
		env = setEnv(env, "DYLD_INSERT_LIBRARIES", dylib)
	}

	cmd := exec.Command(sb, "-f", profilePath, shell, "-c", p.command)
	cmd.Dir = p.workspace
	cmd.Env = env
	stdout, stderr, runErr := capture(ctx, cmd)
	return stdout, StripSeatbeltWarning(stderr), runErr
}

func mountSrc(p *prepared, dst string) string {
	for _, m := range p.mounts {
		if m.Dst == dst {
			return m.Src
		}
	}
	return ""
}

func rewriteShellEnv(env []string, workspace, root, realDir, path, tmp string) []string {
	var out []string
	for _, e := range env {
		k, _, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		switch k {
		case "HOME", "PWD", "TMPDIR", "PATH", "LGB_ROOT", "LGB_REAL", "LGB_KEY", "LGB_PROXY_SOCK", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES":
			continue
		default:
			out = append(out, e)
		}
	}
	out = append(out,
		"HOME="+workspace,
		"PWD="+workspace,
		"TMPDIR="+tmp,
		"PATH="+path,
		"LGB_ROOT="+root,
		"LGB_REAL="+realDir,
	)
	return out
}

func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + val
			return env
		}
	}
	return append(env, prefix+val)
}

func retargetShebang(path, shell string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(b)
	nl := strings.IndexByte(s, '\n')
	if nl < 0 || !strings.HasPrefix(s, "#!") {
		return nil
	}
	return os.WriteFile(path, []byte("#!"+shell+"\n"+s[nl+1:]), 0o755)
}

func copySigned(src, dst string) error {
	if err := copyFile(src, dst, 0o755); err != nil {
		return err
	}
	cmd := exec.Command("codesign", "--force", "--sign", "-", dst)
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("codesign: %v %s", err, out)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	real := src
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		real = resolved
	}
	in, err := os.Open(real)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
