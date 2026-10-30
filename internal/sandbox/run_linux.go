//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// preferUnshare forces the unshare jail even when bwrap is installed.
// Tests set it. Production leaves it false.
var preferUnshare bool

func init() {
	refuseUnshareBuildBinds = func() bool {
		if preferUnshare {
			return true
		}
		_, err := LookPath("bwrap")
		return err != nil
	}
}

func refuseUnsandboxedRoot() error {
	if msg := RootJailWarning(); msg != "" {
		return fmt.Errorf("shell sandbox unavailable: %s", msg)
	}
	return nil
}

func launch(ctx context.Context, p *prepared) (string, string, error) {
	if err := refuseUnsandboxedRoot(); err != nil {
		return "", "", err
	}
	if !preferUnshare {
		if path, err := LookPath("bwrap"); err == nil {
			return runBwrap(ctx, p, path)
		}
	}
	return runUnshare(ctx, p)
}

func runBwrap(ctx context.Context, p *prepared, bwrap string) (string, string, error) {
	uid, gid := JailIDs()
	drop := jailDrops(uid)
	args := []string{
		"--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-uts",
		"--die-with-parent",
	}
	// A root jail writes its own uid map, which cannot be combined with this flag.
	// The inner command sets the same nested-namespace limit before it drops.
	if !drop {
		args = append(args, "--disable-userns")
	}
	args = append(args, "--clearenv",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
	)
	if st, err := os.Stat("/lib64"); err == nil && st.IsDir() {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	}
	args = append(args,
		"--dir", "/etc",
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
		"--bind", p.workspace, "/work",
		"--chdir", "/work",
	)
	if st, err := os.Stat("/etc/ld.so.cache"); err == nil && !st.IsDir() {
		args = append(args, "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache")
	}
	if st, err := os.Stat("/etc/ssl"); err == nil && st.IsDir() {
		args = append(args, "--ro-bind", "/etc/ssl", "/etc/ssl")
	}
	if st, err := os.Stat("/etc/services"); err == nil && !st.IsDir() {
		args = append(args, "--ro-bind", "/etc/services", "/etc/services")
	}
	var infoR, infoW, blockR, blockW *os.File
	var extra []*os.File
	if drop {
		var err error
		infoR, infoW, err = os.Pipe()
		if err != nil {
			return "", "", err
		}
		defer infoR.Close()
		defer infoW.Close()
		blockR, blockW, err = os.Pipe()
		if err != nil {
			return "", "", err
		}
		defer blockR.Close()
		defer blockW.Close()
		// ExtraFiles start at fd 3. Info and block stay 3 and 4.
		extra = []*os.File{infoW, blockR}
		args = append(args, "--info-fd", "3", "--userns-block-fd", "4")
	}
	margs, bindFiles := mountArgs(p.mounts, len(extra))
	args = append(args, margs...)
	for _, e := range p.env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		args = append(args, "--setenv", k, v)
	}
	args = append(args, "--")
	args = append(args, commandArgvMode(p.command, p.cleanBash)...)
	cmd := exec.Command(bwrap, args...)
	cmd.ExtraFiles = cmdExtraFiles(extra, bindFiles)
	closeBinds := func() {
		for _, f := range bindFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}
	if !drop {
		return captureReady(ctx, cmd, closeBinds, nil)
	}
	return captureReady(ctx, cmd, closeBinds, func() error {
		_ = infoW.Close()
		_ = blockR.Close()
		return finishUserNamespace(ctx, infoR, blockW, uid, gid)
	})
}

// cmdExtraFiles places existing bwrap fds (info, block, and any other
// ExtraFiles) before build-bind fds so the earlier numbers stay put.
func cmdExtraFiles(extra, binds []*os.File) []*os.File {
	out := make([]*os.File, 0, len(extra)+len(binds))
	out = append(out, extra...)
	out = append(out, binds...)
	return out
}

// jailDrops is true when a root daemon has bubblewrap and must run the shell
// as the overflow uid. The workspace is owned by that uid.
func jailDrops(uid int) bool {
	return EUID() == 0 && uid != 0
}

// commandArgv is the program bubblewrap executes. A non-root daemon keeps
// /bin/sh. A root daemon maps the overflow uid and then drops to it.
func commandArgv(command string) []string {
	return commandArgvMode(command, false)
}

func commandArgvMode(command string, clean bool) []string {
	uid, gid := JailIDs()
	if !jailDrops(uid) {
		if clean {
			return []string{"/bin/bash", "--norc", "--noprofile", "-c", command}
		}
		return []string{"/bin/sh", "-c", command}
	}
	return droppedArgv(uid, gid, command, clean)
}

// droppedArgv locks nested user namespaces, then drops to uid/gid.
// command is a separate argument so it is not interpolated into the script.
func droppedArgv(uid, gid int, command string, clean bool) []string {
	shell := "/bin/sh -c \"$1\""
	if clean {
		shell = "/bin/bash --norc --noprofile -c \"$1\""
	}
	script := "echo 1 > /proc/sys/user/max_user_namespaces || exit 1\n" +
		"exec /usr/bin/setpriv --reuid=" + strconv.Itoa(uid) +
		" --regid=" + strconv.Itoa(gid) +
		" --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all " + shell + "\n"
	return []string{"/bin/sh", "-c", script, "sh", command}
}

func idMapBody(id int) string {
	if id < 0 {
		return ""
	}
	if id == 0 {
		return "0 0 1\n"
	}
	return fmt.Sprintf("0 0 1\n%d %d 1\n", id, id)
}

func finishUserNamespace(ctx context.Context, info, block *os.File, uid, gid int) error {
	done := make(chan struct{})
	var buf []byte
	var rerr error
	go func() {
		buf, rerr = io.ReadAll(io.LimitReader(info, 1<<16))
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}
	if rerr != nil {
		return rerr
	}
	pid, err := childPID(buf)
	if err != nil {
		return err
	}
	if err := writeIDMaps(pid, uid, gid); err != nil {
		return err
	}
	_, err = block.Write([]byte{1})
	return err
}

func childPID(buf []byte) (int, error) {
	var info struct {
		PID int `json:"child-pid"`
	}
	if err := json.Unmarshal(buf, &info); err != nil || info.PID < 2 {
		return 0, errors.New("user namespace")
	}
	return info.PID, nil
}

func writeIDMaps(pid, uid, gid int) error {
	if pid < 2 || uid < 0 || gid < 0 {
		return errors.New("user namespace")
	}
	if err := writeMapFile(fmt.Sprintf("/proc/%d/uid_map", pid), idMapBody(uid)); err != nil {
		return err
	}
	return writeMapFile(fmt.Sprintf("/proc/%d/gid_map", pid), idMapBody(gid))
}

func writeMapFile(path, body string) error {
	if body == "" {
		return errors.New("user namespace")
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write([]byte(body))
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func runUnshare(ctx context.Context, p *prepared) (string, string, error) {
	if _, err := exec.LookPath("unshare"); err != nil {
		return "", "", fmt.Errorf("shell sandbox unavailable: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	jail, err := os.MkdirTemp("", "lgb-jail-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(jail)
	// file is not serialized. Passing a build bind through stage2 would mount
	// it by path and reopen the race. Refuse it here if prepare did not.
	mounts := make([]mount, 0, len(p.mounts))
	for _, m := range p.mounts {
		if m.file != nil {
			p.extra = append(p.extra, blockEvent("refused bind "+m.Src+": unsupported without bwrap"))
			continue
		}
		mounts = append(mounts, m)
	}
	cfg := stage2File{Workspace: p.workspace, Command: p.command, Env: p.env, Mounts: mounts, CleanBash: p.cleanBash}
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", "", err
	}
	cfgPath := filepath.Join(p.dir, "stage2.json")
	if err := os.WriteFile(cfgPath, b, 0o644); err != nil {
		return "", "", err
	}
	cmd := exec.Command("/usr/bin/unshare",
		"--user", "--mount", "--net", "--map-root-user", "--propagation", "private",
		exe, "--sandbox-stage2", jail, cfgPath)
	return capture(ctx, cmd)
}

func stage2FromFile(jail, configPath string) error {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg stage2File
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	return enterJail(jail, cfg)
}
