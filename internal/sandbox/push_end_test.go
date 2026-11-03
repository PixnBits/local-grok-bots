package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestOnPushEndFollowsOnPush(t *testing.T) {
	cases := []struct {
		name string
		code int
		drop bool
	}{
		{name: "success", code: 0},
		{name: "deny", code: 1},
		{name: "error", code: 1},
		{name: "dropped", code: 1, drop: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seq []string
			done := make(chan struct{})
			path := filepath.Join(t.TempDir(), "push.sock")
			srv, err := startPush(context.Background(), path, func(context.Context, string, []string) PushResult {
				seq = append(seq, "push")
				if tc.name == "error" {
					return PushResult{Code: 1}
				}
				if tc.code == 0 {
					return PushResult{Code: 0, Stdout: "git push sent\n"}
				}
				return PushResult{Code: tc.code, Stderr: "git push denied: no\n"}
			}, func() {
				seq = append(seq, "start")
			}, func() {
				seq = append(seq, "end")
				close(done)
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer srv.close()
			conn, err := net.Dial("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			if err := writePushRequest(conn, ".", []string{"push", "https://github.com/acme/widgets.git"}); err != nil {
				t.Fatal(err)
			}
			if tc.drop {
				conn.Close()
			} else {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 64)
				if _, err := conn.Read(buf); err != nil && err != io.EOF {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("OnPushEnd was not called")
			}
			if len(seq) != 3 || seq[0] != "start" || seq[1] != "push" || seq[2] != "end" {
				t.Fatalf("order %v", seq)
			}
		})
	}

	t.Run("truncated", func(t *testing.T) {
		started := make(chan struct{}, 1)
		ended := make(chan struct{}, 1)
		pushed := make(chan struct{}, 1)
		path := filepath.Join(t.TempDir(), "push.sock")
		srv, err := startPush(context.Background(), path, func(context.Context, string, []string) PushResult {
			pushed <- struct{}{}
			return PushResult{Code: 0}
		}, func() {
			started <- struct{}{}
		}, func() {
			ended <- struct{}{}
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer srv.close()
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			t.Fatal("unix dial")
		}
		if _, err := io.WriteString(uc, "PUSH\n"); err != nil {
			t.Fatal(err)
		}
		if err := uc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		_ = uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		if _, err := uc.Read(buf); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		select {
		case <-started:
			t.Fatal("OnPushStart ran for a truncated request")
		case <-ended:
			t.Fatal("OnPushEnd ran for a truncated request")
		case <-pushed:
			t.Fatal("OnPush ran for a truncated request")
		default:
		}
	})
}

func writePushRequest(conn net.Conn, cwd string, args []string) error {
	if _, err := io.WriteString(conn, "PUSH\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "%d\n%s", len(cwd), cwd); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "%d\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(conn, "%d\n%s", len(arg), arg); err != nil {
			return err
		}
	}
	return nil
}
