package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// HandleArgs runs the jailed shell stage when the process was re-exec'd
// inside a user and mount namespace. It returns true when it handled the args.
func HandleArgs(args []string) bool {
	if len(args) < 1 || args[0] != "--sandbox-stage2" {
		return false
	}
	if len(args) != 4 {
		fmt.Fprintln(os.Stderr, "sandbox: expected jail, workspace, command")
		os.Exit(2)
	}
	if err := stage2(args[1], args[2], args[3]); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		os.Exit(1)
	}
	return true
}

// Run executes command with working directory workspace.
// The process can read system libraries and write only inside the workspace
// (plus a private tmpfs). It cannot see the host filesystem.
func Run(ctx context.Context, workspace, command string) (stdout, stderr string, err error) {
	if strings.TrimSpace(command) == "" {
		return "", "", fmt.Errorf("command required")
	}
	if strings.ContainsRune(command, 0) {
		return "", "", fmt.Errorf("invalid command")
	}
	ws, err := filepath.Abs(workspace)
	if err != nil {
		return "", "", err
	}
	if st, err := os.Stat(ws); err != nil || !st.IsDir() {
		return "", "", fmt.Errorf("workspace unavailable")
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	jail, err := os.MkdirTemp("/tmp", "lgb-jail-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(jail)

	if _, err := exec.LookPath("unshare"); err != nil {
		return "", "", fmt.Errorf("shell sandbox unavailable: %w", err)
	}
	cmd := exec.Command("/usr/bin/unshare",
		"--user", "--mount", "--map-root-user", "--propagation", "private",
		exe, "--sandbox-stage2", jail, ws, command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var outBuf, errBuf bytes.Buffer
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", "", err
	}
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("shell sandbox: %w", err)
	}
	doneOut := make(chan struct{})
	doneErr := make(chan struct{})
	go func() {
		_, _ = io.Copy(&outBuf, io.LimitReader(stdoutPipe, maxCapture+1))
		doneOut <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(&errBuf, io.LimitReader(stderrPipe, maxCapture+1))
		doneErr <- struct{}{}
	}()
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	var runErr error
	select {
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-waitErr
		runErr = fmt.Errorf("shell timed out")
	case err := <-waitErr:
		runErr = err
	}
	<-doneOut
	<-doneErr
	stdout = truncate(outBuf.String())
	stderr = truncate(errBuf.String())
	if runErr != nil {
		if ctx.Err() != nil && runErr.Error() == "shell timed out" {
			return stdout, stderr, runErr
		}
		return stdout, stderr, fmt.Errorf("exit %s", exitCode(runErr))
	}
	return stdout, stderr, nil
}

const maxCapture = 16 * 1024

func truncate(s string) string {
	if len(s) > maxCapture {
		return s[:maxCapture] + "\n…(truncated)"
	}
	return s
}

func exitCode(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return fmt.Sprintf("%d", ee.ExitCode())
	}
	return err.Error()
}

func stage2(jail, workspace, command string) error {
	for _, d := range []string{"work", "bin", "lib", "lib64", "usr", "tmp", "dev", "etc"} {
		if err := os.MkdirAll(filepath.Join(jail, d), 0o755); err != nil {
			return err
		}
	}
	binds := []string{"/bin", "/lib", "/usr"}
	if st, err := os.Stat("/lib64"); err == nil && st.IsDir() {
		binds = append(binds, "/lib64")
	}
	for _, src := range binds {
		dst := filepath.Join(jail, strings.TrimPrefix(src, "/"))
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("bind %s: %w", src, err)
		}
		// Best-effort. Dropped capabilities still stop writes to host-owned files
		// if a recursive remount is rejected.
		_ = unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
	}
	if err := unix.Mount(workspace, filepath.Join(jail, "work"), "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind workspace: %w", err)
	}
	if b, err := os.ReadFile("/etc/ld.so.cache"); err == nil {
		_ = os.WriteFile(filepath.Join(jail, "etc", "ld.so.cache"), b, 0o644)
	}
	nullPath := filepath.Join(jail, "dev", "null")
	if err := os.WriteFile(nullPath, nil, 0o644); err != nil {
		return err
	}
	if err := unix.Mount("/dev/null", nullPath, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("dev/null: %w", err)
	}
	if err := unix.Mount("tmpfs", filepath.Join(jail, "tmp"), "tmpfs", 0, "size=32m,mode=1777"); err != nil {
		return fmt.Errorf("tmpfs: %w", err)
	}
	if err := unix.Chdir(jail); err != nil {
		return err
	}
	if err := unix.Chroot(jail); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	if err := unix.Chdir("/work"); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return unix.Exec("/bin/sh", []string{"sh", "-c", command}, []string{
		"PATH=/usr/bin:/bin",
		"HOME=/work",
		"TMPDIR=/tmp",
		"PWD=/work",
		"LANG=C.UTF-8",
	})
}

// Resolve keeps path inside root, rejecting traversal and symlink escapes.
func Resolve(root, p string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("path required")
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("invalid path")
	}
	p = filepath.Clean(p)
	if filepath.IsAbs(p) {
		rel, err := filepath.Rel(root, p)
		if err != nil || escapes(rel) {
			return "", fmt.Errorf("path escapes workspace")
		}
		p = rel
	}
	if escapes(p) {
		return "", fmt.Errorf("path escapes workspace")
	}
	cur := root
	for _, part := range strings.Split(p, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("path escapes workspace")
		}
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(next)
		if err != nil {
			if os.IsNotExist(err) {
				cur = next
				continue
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(next), target)
			}
			target = filepath.Clean(target)
			rel, err := filepath.Rel(root, target)
			if err != nil || escapes(rel) {
				return "", fmt.Errorf("path escapes workspace")
			}
			cur = target
			continue
		}
		cur = next
	}
	rel, err := filepath.Rel(root, cur)
	if err != nil || escapes(rel) {
		return "", fmt.Errorf("path escapes workspace")
	}
	return cur, nil
}

func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// Touch the time import so timeout callers stay obvious at the Run boundary.
var _ = time.Second
