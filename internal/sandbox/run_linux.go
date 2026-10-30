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
	args, extra, bindFiles, infoR, blockW, err := bwrapLaunchArgs(p)
	if err != nil {
		return "", "", err
	}
	defer func() {
		for _, f := range extra {
			if f != nil {
				_ = f.Close()
			}
		}
		if infoR != nil {
			_ = infoR.Close()
		}
		if blockW != nil {
			_ = blockW.Close()
		}
	}()
	cmd := exec.Command(bwrap, args...)
	cmd.ExtraFiles = cmdExtraFiles(extra, bindFiles)
	closeBinds := func() {
		for _, f := range bindFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}
	if !jailDrops(uid) {
		return captureReady(ctx, cmd, closeBinds, nil)
	}
	return captureReady(ctx, cmd, closeBinds, func() error {
		if len(extra) >= 2 {
			_ = extra[0].Close()
			_ = extra[1].Close()
		}
		return finishUserNamespace(ctx, infoR, blockW, uid, gid)
	})
}

// bwrapLaunchArgs is the bubblewrap argv for one prepared shell.
// extra holds the info and block pipe ends when a root jail drops.
// infoR and blockW stay with the parent for the uid map.
func bwrapLaunchArgs(p *prepared) (args []string, extra, bindFiles []*os.File, infoR, blockW *os.File, err error) {
	uid, _ := JailIDs()
	drop := jailDrops(uid)
	args = []string{
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
	if st, statErr := os.Stat("/lib64"); statErr == nil && st.IsDir() {
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
	if st, statErr := os.Stat("/etc/ld.so.cache"); statErr == nil && !st.IsDir() {
		args = append(args, "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache")
	}
	if st, statErr := os.Stat("/etc/ssl"); statErr == nil && st.IsDir() {
		args = append(args, "--ro-bind", "/etc/ssl", "/etc/ssl")
	}
	if st, statErr := os.Stat("/etc/services"); statErr == nil && !st.IsDir() {
		args = append(args, "--ro-bind", "/etc/services", "/etc/services")
	}
	if drop {
		var infoW, blockR *os.File
		infoR, infoW, err = os.Pipe()
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		blockR, blockW, err = os.Pipe()
		if err != nil {
			_ = infoR.Close()
			_ = infoW.Close()
			return nil, nil, nil, nil, nil, err
		}
		// ExtraFiles start at fd 3. Info and block stay 3 and 4.
		extra = []*os.File{infoW, blockR}
		args = append(args, "--info-fd", "3", "--userns-block-fd", "4")
	}
	var margs []string
	margs, bindFiles = mountArgs(p.mounts, len(extra))
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
	return args, extra, bindFiles, infoR, blockW, nil
}

// BwrapArgv is the bubblewrap argument vector for req, without running it.
func BwrapArgv(req Request) ([]string, error) {
	if strings.TrimSpace(req.Command) == "" {
		return nil, fmt.Errorf("command required")
	}
	ws, err := filepath.Abs(req.Workspace)
	if err != nil {
		return nil, err
	}
	if st, statErr := os.Stat(ws); statErr != nil || !st.IsDir() {
		return nil, fmt.Errorf("workspace unavailable")
	}
	p, err := prepare(context.Background(), req, ws)
	if err != nil {
		return nil, err
	}
	defer p.close()
	args, extra, _, infoR, blockW, err := bwrapLaunchArgs(p)
	if infoR != nil {
		_ = infoR.Close()
	}
	if blockW != nil {
		_ = blockW.Close()
	}
	for _, f := range extra {
		if f != nil {
			_ = f.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	return args, nil
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
	argv := append(unshareNamespaceArgs(), exe, "--sandbox-stage2", jail, cfgPath)
	cmd := exec.Command("/usr/bin/unshare", argv...)
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
