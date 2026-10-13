//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func platformHandleArgs(args []string) bool {
	if len(args) > 0 && args[0] == "--sandbox-rlimit" {
		if err := rlimitAndExec(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "sandbox:", err)
			os.Exit(1)
		}
		return true
	}
	if len(args) < 1 || args[0] != "--sandbox-stage2" {
		return false
	}
	var err error
	switch len(args) {
	case 3:
		err = stage2FromFile(args[1], args[2])
	case 4:
		err = enterJail(args[1], stage2File{Workspace: args[2], Command: args[3]})
	default:
		fmt.Fprintln(os.Stderr, "sandbox: expected jail and config")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		os.Exit(1)
	}
	return true
}

func enterJail(jail string, cfg stage2File) error {
	workspace, command := cfg.Workspace, cfg.Command
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
	// Bind the host entropy nodes. Tools such as ssh-keygen open the device
	// file; getrandom is not a substitute. Do not mknod, and do not mount the
	// rest of /dev (disks, kvm, tun, nvidia). /dev/tty and /dev/shm stay out.
	for _, name := range []string{"null", "zero", "full", "random", "urandom"} {
		if err := mountDevNode(jail, name); err != nil {
			return err
		}
	}
	if err := unix.Mount("tmpfs", filepath.Join(jail, "tmp"), "tmpfs", 0, "size=32m,mode=1777"); err != nil {
		return fmt.Errorf("tmpfs: %w", err)
	}
	for _, m := range cfg.Mounts {
		if err := bindIntoJail(jail, m); err != nil {
			return err
		}
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
	env := cfg.Env
	if len(env) == 0 {
		env = []string{
			"PATH=" + jailPATH(),
			"HOME=/work",
			"TMPDIR=/tmp",
			"PWD=/work",
			"LANG=C.UTF-8",
		}
	}
	return unix.Exec("/bin/sh", []string{"sh", "-c", command}, env)
}

func mountDevNode(jail, name string) error {
	src := "/dev/" + name
	st, err := os.Stat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("dev/%s: %w", name, err)
	}
	if st.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("dev/%s: not a character device", name)
	}
	dst := filepath.Join(jail, "dev", name)
	if err := os.WriteFile(dst, nil, 0o644); err != nil {
		return err
	}
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("dev/%s: %w", name, err)
	}
	return nil
}

func bindIntoJail(jail string, m mount) error {
	if m.Src == "" || !strings.HasPrefix(m.Dst, "/") {
		return fmt.Errorf("bad mount")
	}
	target := filepath.Join(jail, strings.TrimPrefix(m.Dst, "/"))
	st, err := os.Stat(m.Src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if st.IsDir() {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
	} else if _, err := os.Lstat(target); err != nil {
		if err := os.WriteFile(target, nil, 0o644); err != nil {
			return err
		}
	}
	if err := unix.Mount(m.Src, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s: %w", m.Dst, err)
	}
	if m.RO {
		_ = unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
	}
	return nil
}
