//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBuildBindFDArgs(t *testing.T) {
	ws := t.TempDir()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool.txt"), []byte("toolchain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "tool.txt")
	if err := os.WriteFile(file, []byte("file-toolchain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fileResolved := mustResolved(t, file)
	dirResolved := mustResolved(t, dir)

	protect := t.TempDir()
	mounts, events, applied := selectBuildBinds(ws, []string{file, dir}, []string{protect}, SnapshotProtect([]string{protect}), "")
	t.Cleanup(func() { closeMountFiles(mounts) })
	if len(events) != 0 || len(applied) != 2 {
		t.Fatalf("events %+v applied %v", events, applied)
	}
	if len(mounts) != 2 || mounts[0].file == nil || mounts[1].file == nil {
		t.Fatalf("mounts %+v", mounts)
	}
	for _, m := range mounts {
		flags, err := unix.FcntlInt(m.file.Fd(), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("bind fd is not O_CLOEXEC: %s", m.Dst)
		}
	}

	extraR, extraW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { extraR.Close(); extraW.Close() })
	extraR2, extraW2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { extraR2.Close(); extraW2.Close() })
	extra := []*os.File{extraW, extraW2}

	pathMount := mount{Src: "/usr/bin/true", Dst: "/usr/bin/true", RO: true}
	all := append([]mount{pathMount}, mounts...)
	args, files := mountArgs(all, len(extra))
	got := cmdExtraFiles(extra, files)
	if len(got) != 4 || got[0] != extraW || got[1] != extraW2 || got[2] != mounts[0].file || got[3] != mounts[1].file {
		t.Fatalf("extra files were renumbered: %d", len(got))
	}
	joined := strings.Join(args, "\n")
	wantFile := "--ro-bind-fd\n5\n" + fileResolved
	wantDir := "--ro-bind-fd\n6\n" + dirResolved
	if !strings.Contains(joined, "--ro-bind\n/usr/bin/true\n/usr/bin/true") || !strings.Contains(joined, wantFile) || !strings.Contains(joined, wantDir) {
		t.Fatalf("args:\n%s", joined)
	}
	if strings.Contains(joined, "--ro-bind\n"+fileResolved) || strings.Contains(joined, "--ro-bind\n"+dirResolved) || strings.Contains(joined, "--ro-bind\n"+file) || strings.Contains(joined, "--ro-bind\n"+dir) {
		t.Fatalf("build bind used a path --ro-bind:\n%s", joined)
	}
	fileAt := strings.Index(joined, wantFile)
	dirAt := strings.Index(joined, wantDir)
	if fileAt < 0 || dirAt < fileAt {
		t.Fatalf("fd order:\n%s", joined)
	}
}

func TestBuildBindSymlinkSwapRefused(t *testing.T) {
	ws := t.TempDir()
	parent := t.TempDir()
	comp := filepath.Join(parent, "comp")
	if err := os.Mkdir(comp, 0o755); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(comp, "leaf")
	if err := os.Mkdir(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := t.TempDir()
	const canary = "CANARY-SECRET-BYTES"
	if err := os.WriteFile(filepath.Join(secret, "secret"), []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	buildBindBeforeOpen = func() {
		if err := os.RemoveAll(comp); err != nil {
			t.Errorf("remove component: %v", err)
			return
		}
		if err := os.Symlink(secret, comp); err != nil {
			t.Errorf("symlink component: %v", err)
		}
	}
	t.Cleanup(func() { buildBindBeforeOpen = nil })

	mounts, events, applied := selectBuildBinds(ws, []string{leaf}, []string{secret}, SnapshotProtect([]string{secret}), "")
	t.Cleanup(func() { closeMountFiles(mounts) })
	if len(mounts) != 0 || len(applied) != 0 {
		t.Fatalf("swapped symlink was mounted: %+v %v", mounts, applied)
	}
	if len(events) != 1 || events[0].Kind != "sandbox_block" || !strings.Contains(events[0].Detail, leaf) {
		t.Fatalf("events %+v", events)
	}
	if strings.Contains(events[0].Detail, canary) || strings.Contains(events[0].Detail, secret) {
		t.Fatalf("event leaked %+v", events[0])
	}
}

func TestBuildBindRenameRecheckRefused(t *testing.T) {
	ws := t.TempDir()
	parent := t.TempDir()
	pub := filepath.Join(parent, "pub")
	sec := filepath.Join(parent, "sec")
	if err := os.Mkdir(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sec, 0o755); err != nil {
		t.Fatal(err)
	}
	const canary = "CANARY-SECRET-BYTES"
	if err := os.WriteFile(filepath.Join(pub, "hello"), []byte("public\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "secret"), []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	buildBindBeforeOpen = func() {
		away := filepath.Join(parent, "away")
		if err := os.Rename(pub, away); err != nil {
			t.Errorf("move public: %v", err)
			return
		}
		if err := os.Rename(sec, pub); err != nil {
			t.Errorf("rename protected into place: %v", err)
		}
	}
	t.Cleanup(func() { buildBindBeforeOpen = nil })

	mounts, events, applied := selectBuildBinds(ws, []string{pub}, []string{sec}, SnapshotProtect([]string{sec}), "")
	t.Cleanup(func() { closeMountFiles(mounts) })
	if len(mounts) != 0 || len(applied) != 0 {
		t.Fatalf("renamed protected dir was mounted: %+v %v", mounts, applied)
	}
	if len(events) != 1 || events[0].Kind != "sandbox_block" || !strings.Contains(events[0].Detail, "refused bind "+pub) {
		t.Fatalf("events %+v", events)
	}
	if strings.Contains(events[0].Detail, canary) {
		t.Fatalf("event leaked %+v", events[0])
	}
}

func TestBuildBindSwapLoop(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not on PATH")
	}
	const (
		n      = 300
		canary = "SWAP-LOOP-SECRET"
		public = "SWAP-LOOP-PUBLIC"
	)
	base := t.TempDir()
	secDir := filepath.Join(base, "hidden")
	if err := os.Mkdir(secDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secDir, "secret"), []byte(canary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	slot := filepath.Join(base, "slot")
	if err := os.Mkdir(slot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "hello"), []byte(public+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(secDir, link); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var swaps atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := unix.Renameat2(unix.AT_FDCWD, slot, unix.AT_FDCWD, link, unix.RENAME_EXCHANGE); err == nil {
				swaps.Add(1)
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	ws := t.TempDir()
	snap := SnapshotProtect([]string{secDir})
	command := "cat " + shQuote(filepath.Join(slot, "secret")) + " 2>/dev/null; cat " + shQuote(filepath.Join(slot, "hello")) + " 2>/dev/null; true"
	var readSecret, blocked, mountedPublic int
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		res, _ := Run(ctx, Request{
			Workspace:     ws,
			Command:       command,
			Grants:        []string{"build"},
			BuildBinds:    []string{slot},
			Protect:       []string{secDir},
			ProtectInodes: snap,
		})
		cancel()
		out := res.Stdout + res.Stderr
		if strings.Contains(out, canary) {
			readSecret++
			continue
		}
		turnBlocked := false
		for _, ev := range res.Events {
			if ev.Kind == "sandbox_block" && strings.Contains(ev.Detail, slot) {
				turnBlocked = true
				break
			}
		}
		if turnBlocked {
			blocked++
			continue
		}
		if strings.Contains(res.Stdout, public) {
			mountedPublic++
		}
	}
	t.Logf("swap-loop: %d/%d turns read the secret, %d blocked, %d mounted public", readSecret, n, blocked, mountedPublic)
	if swaps.Load() == 0 {
		t.Fatal("rename exchange never succeeded")
	}
	if readSecret != 0 {
		t.Fatalf("secret was readable")
	}
}

func TestBuildBindAncestorRenameRefused(t *testing.T) {
	ws := t.TempDir()
	base := t.TempDir()
	ancestor := filepath.Join(base, "ancestor")
	if err := os.Mkdir(ancestor, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(ancestor, "secret")
	const canary = "CANARY-SECRET-BYTES"
	if err := os.WriteFile(secret, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(base, "pub")
	if err := os.Mkdir(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pub, "hello"), []byte("public\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	buildBindBeforeOpen = func() {
		away := filepath.Join(base, "away")
		if err := os.Rename(pub, away); err != nil {
			t.Errorf("move public: %v", err)
			return
		}
		if err := os.Rename(ancestor, pub); err != nil {
			t.Errorf("rename ancestor onto bind: %v", err)
		}
	}
	t.Cleanup(func() { buildBindBeforeOpen = nil })

	mounts, events, applied := selectBuildBinds(ws, []string{pub}, []string{secret}, SnapshotProtect([]string{secret}), "")
	t.Cleanup(func() { closeMountFiles(mounts) })
	if len(mounts) != 0 || len(applied) != 0 {
		t.Fatalf("ancestor of a secret was mounted: %+v %v", mounts, applied)
	}
	if len(events) != 1 || events[0].Kind != "sandbox_block" || !strings.Contains(events[0].Detail, "refused bind "+pub) {
		t.Fatalf("events %+v", events)
	}
	if strings.Contains(events[0].Detail, canary) || events[0].Untrusted {
		t.Fatalf("event %+v", events[0])
	}
}

func TestUnshareRefusesBuildBind(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Fatal("unshare is required")
	}
	probe := exec.Command("unshare", "--user", "--map-root-user", "--mount", "true")
	if err := probe.Run(); err != nil {
		t.Fatalf("user namespace unavailable: %v", err)
	}
	preferUnshare = true
	t.Cleanup(func() { preferUnshare = false })

	dir := t.TempDir()
	file := filepath.Join(dir, "tool.txt")
	const original = "ORIGINAL-BIND\n"
	if err := os.WriteFile(file, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Run(ctx, Request{
		Workspace:  ws,
		Command:    "cat " + shQuote(file) + " || printf NOBIND\\n",
		Grants:     []string{"build"},
		BuildBinds: []string{file},
		Protect:    []string{t.TempDir()},
	})
	if err != nil {
		t.Fatalf("unshare: %v\nstdout:\n%s\nstderr:\n%s\nevents:%+v", err, res.Stdout, res.Stderr, res.Events)
	}
	if strings.Contains(res.Stdout, "ORIGINAL-BIND") || strings.Contains(res.Stdout, "SWAPPED-BIND") {
		t.Fatalf("unshare mounted the build bind:\n%s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, "NOBIND") {
		t.Fatalf("stdout %q stderr %q", res.Stdout, res.Stderr)
	}
	want := "refused bind " + file + ": unsupported without bwrap"
	var blocks int
	for _, ev := range res.Events {
		if ev.Kind == "grant_use" || ev.Kind == "grant_denied" {
			t.Fatalf("unshare build bind produced %+v", ev)
		}
		if ev.Kind != "sandbox_block" {
			continue
		}
		blocks++
		if ev.Untrusted || ev.Detail != want {
			t.Fatalf("event %+v", ev)
		}
	}
	if blocks != 1 {
		t.Fatalf("events %+v", res.Events)
	}
}

func TestProtectSnapshotDirChange(t *testing.T) {
	ws := t.TempDir()
	bind := t.TempDir()
	if err := os.WriteFile(filepath.Join(bind, "tool.txt"), []byte("toolchain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Run("missing dir", func(t *testing.T) {
		sec := t.TempDir()
		snap := SnapshotProtect([]string{sec})
		if err := os.RemoveAll(sec); err != nil {
			t.Fatal(err)
		}
		mounts, events, applied := selectBuildBinds(ws, []string{bind}, []string{sec}, snap, "")
		t.Cleanup(func() { closeMountFiles(mounts) })
		if len(mounts) != 0 || len(applied) != 0 {
			t.Fatalf("mounted %+v %v", mounts, applied)
		}
		if len(events) != 1 || events[0].Detail != "refused bind "+bind+": protected path changed" {
			t.Fatalf("events %+v", events)
		}
	})
	t.Run("replaced dir", func(t *testing.T) {
		parent := t.TempDir()
		sec := filepath.Join(parent, "sec")
		if err := os.Mkdir(sec, 0o755); err != nil {
			t.Fatal(err)
		}
		snap := SnapshotProtect([]string{sec})
		if err := os.Rename(sec, sec+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(sec, 0o755); err != nil {
			t.Fatal(err)
		}
		mounts, events, applied := selectBuildBinds(ws, []string{bind}, []string{sec}, snap, "")
		t.Cleanup(func() { closeMountFiles(mounts) })
		if len(mounts) != 0 || len(applied) != 0 {
			t.Fatalf("mounted %+v %v", mounts, applied)
		}
		if len(events) != 1 || events[0].Detail != "refused bind "+bind+": protected path changed" {
			t.Fatalf("events %+v", events)
		}
	})
}

func TestProtectSnapshotFileChangeDoesNotFailAll(t *testing.T) {
	ws := t.TempDir()
	dir := t.TempDir()
	file := filepath.Join(dir, "state.db-wal")
	if err := os.WriteFile(file, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := SnapshotProtect([]string{file})
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bind := t.TempDir()
	if err := os.WriteFile(filepath.Join(bind, "tool.txt"), []byte("toolchain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mounts, events, applied := selectBuildBinds(ws, []string{bind}, []string{file}, snap, "")
	t.Cleanup(func() { closeMountFiles(mounts) })
	if len(applied) != 1 || applied[0] != bind || len(mounts) != 1 {
		t.Fatalf("mounted %+v applied %v events %+v", mounts, applied, events)
	}
	for _, ev := range events {
		if strings.Contains(ev.Detail, "protected path changed") {
			t.Fatalf("file churn refused binds: %+v", events)
		}
	}
}

func TestBuildBindRenameBeforeRun(t *testing.T) {
	requireBin(t, "bwrap")
	const canary = "RENAME-BEFORE-SECRET"
	catSecret := func(t *testing.T, snap []ProtectInode, protect, bind, secretPath string) {
		t.Helper()
		ws := t.TempDir()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		res, err := Run(ctx, Request{
			Workspace:     ws,
			Command:       "cat " + shQuote(secretPath) + " 2>/dev/null || true",
			Grants:        []string{"build"},
			BuildBinds:    []string{bind},
			Protect:       []string{protect},
			ProtectInodes: snap,
		})
		if err != nil {
			t.Fatalf("run: %v\n%s\n%+v", err, res.Stderr, res.Events)
		}
		if strings.Contains(res.Stdout, canary) || strings.Contains(res.Stderr, canary) {
			t.Fatalf("read the secret:\n%s", res.Stdout)
		}
		found := false
		for _, ev := range res.Events {
			if ev.Kind == "sandbox_block" && strings.Contains(ev.Detail, "refused bind "+bind) && strings.Contains(ev.Detail, "protected path changed") && !ev.Untrusted {
				found = true
			}
			if strings.Contains(ev.Detail, canary) {
				t.Fatalf("event leaked %+v", ev)
			}
		}
		if !found {
			t.Fatalf("events %+v stdout %q", res.Events, res.Stdout)
		}
	}
	t.Run("protected dir", func(t *testing.T) {
		base := t.TempDir()
		sec := filepath.Join(base, "sec")
		bind := filepath.Join(base, "bind")
		if err := os.Mkdir(sec, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(bind, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sec, "secret"), []byte(canary+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		snap := SnapshotProtect([]string{sec})
		if err := os.Rename(bind, filepath.Join(base, "bind-away")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(sec, bind); err != nil {
			t.Fatal(err)
		}
		catSecret(t, snap, sec, bind, filepath.Join(bind, "secret"))
	})
	t.Run("protected parent", func(t *testing.T) {
		base := t.TempDir()
		parent := filepath.Join(base, "parent")
		sec := filepath.Join(parent, "sec")
		bind := filepath.Join(base, "bind")
		if err := os.MkdirAll(sec, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(bind, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sec, "secret"), []byte(canary+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		snap := SnapshotProtect([]string{sec})
		if err := os.Rename(bind, filepath.Join(base, "bind-away")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(parent, bind); err != nil {
			t.Fatal(err)
		}
		catSecret(t, snap, sec, bind, filepath.Join(bind, "sec", "secret"))
	})
}

func TestBuildBindRenameExchangeRace(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not on PATH")
	}
	const (
		n      = 300
		canary = "EXCHANGE-RACE-SECRET"
		public = "EXCHANGE-RACE-PUBLIC"
	)
	base := t.TempDir()
	sec := filepath.Join(base, "sec")
	pub := filepath.Join(base, "pub")
	if err := os.Mkdir(sec, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "secret"), []byte(canary+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pub, "hello"), []byte(public+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := SnapshotProtect([]string{sec})
	if len(snap) == 0 {
		t.Fatal("empty snapshot")
	}

	stop := make(chan struct{})
	var swaps atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := unix.Renameat2(unix.AT_FDCWD, pub, unix.AT_FDCWD, sec, unix.RENAME_EXCHANGE); err == nil {
				swaps.Add(1)
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()

	ws := t.TempDir()
	command := "cat " + shQuote(filepath.Join(pub, "secret")) + " 2>/dev/null; cat " + shQuote(filepath.Join(pub, "hello")) + " 2>/dev/null; true"
	var readSecret, blocked, mountedPublic int
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		res, _ := Run(ctx, Request{
			Workspace:     ws,
			Command:       command,
			Grants:        []string{"build"},
			BuildBinds:    []string{pub},
			Protect:       []string{sec},
			ProtectInodes: snap,
		})
		cancel()
		out := res.Stdout + res.Stderr
		if strings.Contains(out, canary) {
			readSecret++
			continue
		}
		turnBlocked := false
		for _, ev := range res.Events {
			if ev.Kind == "sandbox_block" && strings.Contains(ev.Detail, pub) {
				turnBlocked = true
				break
			}
		}
		if turnBlocked {
			blocked++
			continue
		}
		if strings.Contains(res.Stdout, public) {
			mountedPublic++
		}
	}
	t.Logf("exchange-race: %d/%d turns read the secret, %d blocked, %d mounted public", readSecret, n, blocked, mountedPublic)
	if swaps.Load() == 0 {
		t.Fatal("rename exchange never succeeded")
	}
	if readSecret != 0 {
		t.Fatalf("secret was readable")
	}
}

func TestBindOpenInodeRefusesSecretFile(t *testing.T) {
	ws := t.TempDir()
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret")
	if err := os.WriteFile(secret, []byte("SECRET-FILE-BYTES\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := SnapshotProtect([]string{secret})
	if got := ProtectChanged(snap); got != "" {
		t.Fatalf("file snapshot changed %s", got)
	}
	t.Run("rename", func(t *testing.T) {
		bind := filepath.Join(t.TempDir(), "tool.txt")
		if err := os.WriteFile(bind, []byte("public\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(bind); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(secret, bind); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Rename(bind, secret) })
		if got := ProtectChanged(snap); got != "" {
			t.Fatalf("directory check fired: %s", got)
		}
		mounts, events, applied := selectBuildBinds(ws, []string{bind}, []string{secret}, snap, "")
		t.Cleanup(func() { closeMountFiles(mounts) })
		if len(mounts) != 0 || len(applied) != 0 {
			t.Fatalf("mounted %+v %v", mounts, applied)
		}
		if len(events) != 1 || events[0].Kind != "sandbox_block" || events[0].Untrusted || !strings.Contains(events[0].Detail, "refused bind "+bind) {
			t.Fatalf("events %+v", events)
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		bind := filepath.Join(t.TempDir(), "tool.txt")
		if err := os.Link(secret, bind); err != nil {
			t.Fatal(err)
		}
		if got := ProtectChanged(snap); got != "" {
			t.Fatalf("directory check fired: %s", got)
		}
		mounts, events, applied := selectBuildBinds(ws, []string{bind}, []string{secret}, snap, "")
		t.Cleanup(func() { closeMountFiles(mounts) })
		if len(mounts) != 0 || len(applied) != 0 {
			t.Fatalf("mounted %+v %v", mounts, applied)
		}
		if len(events) != 1 || events[0].Kind != "sandbox_block" || !strings.Contains(events[0].Detail, "refused bind "+bind) {
			t.Fatalf("events %+v", events)
		}
	})
	t.Run("control", func(t *testing.T) {
		other := t.TempDir()
		bind := filepath.Join(t.TempDir(), "tool.txt")
		if err := os.WriteFile(bind, []byte("public\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		plain := SnapshotProtect([]string{other})
		mounts, events, applied := selectBuildBinds(ws, []string{bind}, []string{other}, plain, "")
		t.Cleanup(func() { closeMountFiles(mounts) })
		if len(mounts) != 1 || len(applied) != 1 || applied[0] != bind {
			t.Fatalf("mounted %+v applied %v events %+v", mounts, applied, events)
		}
	})
}

func mustResolved(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(resolved)
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
