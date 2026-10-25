//go:build linux

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFIFORefusesMirrorPath(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, git string) string
	}{
		{
			name: "objects",
			plant: func(t *testing.T, git string) string {
				t.Helper()
				path := filepath.Join(git, "objects", "x")
				if err := unix.Mkfifo(path, 0o644); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "head",
			plant: func(t *testing.T, git string) string {
				t.Helper()
				path := filepath.Join(git, "HEAD")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0o644); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "config",
			plant: func(t *testing.T, git string) string {
				t.Helper()
				path := filepath.Join(git, "config")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0o644); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws := t.TempDir()
			proj := filepath.Join(ws, "proj")
			writePlainGit(t, proj)
			fifo := tc.plant(t, filepath.Join(proj, ".git"))
			parent := t.TempDir()
			base := runtime.NumGoroutine()
			errCh := make(chan error, 1)
			go func() {
				errCh <- mirrorPath(context.Background(), ws, "proj", parent)
			}()
			var err error
			select {
			case err = <-errCh:
			case <-time.After(2 * time.Second):
				unblockFIFO(fifo)
				select {
				case <-errCh:
				case <-time.After(time.Second):
				}
				t.Fatal("still running after 2s")
			}
			if err == nil {
				t.Fatal("accepted a fifo")
			}
			waitGoroutines(t, base)
			left, rerr := os.ReadDir(parent)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if len(left) != 0 {
				t.Fatalf("partial mirror %v", left)
			}
		})
	}
}

func TestFIFOConfigDenialReturnsBlank(t *testing.T) {
	ws := t.TempDir()
	proj := filepath.Join(ws, "proj")
	writePlainGit(t, proj)
	fifo := filepath.Join(proj, ".git", "config")
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	app := &App{ws: ws}
	base := runtime.NumGoroutine()
	type named struct{ owner, repo string }
	ch := make(chan named, 1)
	go func() {
		owner, repo := app.deniedPushNames("proj", []string{"git", "push", "--force", "origin"})
		ch <- named{owner, repo}
	}()
	select {
	case got := <-ch:
		if got.owner != "" || got.repo != "" {
			t.Fatalf("named %s/%s", got.owner, got.repo)
		}
	case <-time.After(2 * time.Second):
		unblockFIFO(fifo)
		select {
		case <-ch:
		case <-time.After(time.Second):
		}
		t.Fatal("still running after 2s")
	}
	waitGoroutines(t, base)
}

func mirrorPath(ctx context.Context, ws, rel, parent string) error {
	h, reason := resolveWorkspaceRepo(ws, rel)
	if h != nil {
		defer h.Close()
	}
	if reason != "" || h == nil {
		if reason == "" {
			reason = "repository not found in workspace"
		}
		return errors.New(reason)
	}
	if h.configReason() == "config" {
		return errors.New("config")
	}
	_, err := copyGitMirror(ctx, parent, h)
	return err
}

func unblockFIFO(path string) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	unix.Close(fd)
}

func waitGoroutines(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base {
			return
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > base {
		t.Fatalf("goroutines %d baseline %d", got, base)
	}
}
