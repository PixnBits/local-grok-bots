package daemon

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWatchSIGHUP(t *testing.T) {
	t.Run("reloads when set", func(t *testing.T) {
		hup := make(chan os.Signal, 2)
		var n atomic.Int32
		buf := &safeBuf{}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			WatchSIGHUP(ctx, hup, "/tmp/lgb-tokens", func() { n.Add(1) }, nil, buf)
			close(done)
		}()
		hup <- syscall.SIGHUP
		hup <- syscall.SIGHUP
		deadline := time.Now().Add(2 * time.Second)
		for n.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("watch did not return")
		}
		if n.Load() != 2 {
			t.Fatalf("reloads %d", n.Load())
		}
		if buf.String() != "" {
			t.Fatalf("log %q", buf.String())
		}
	})
	t.Run("logs and does not reload when unset", func(t *testing.T) {
		hup := make(chan os.Signal, 2)
		var n atomic.Int32
		buf := &safeBuf{}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			WatchSIGHUP(ctx, hup, "", func() { n.Add(1) }, nil, buf)
			close(done)
		}()
		hup <- syscall.SIGHUP
		hup <- syscall.SIGHUP
		want := sighupIgnoreLine + "\n" + sighupIgnoreLine + "\n"
		deadline := time.Now().Add(2 * time.Second)
		for buf.String() != want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("watch did not return")
		}
		if n.Load() != 0 {
			t.Fatalf("reloads %d", n.Load())
		}
		if got := buf.String(); got != want || strings.Count(got, sighupIgnoreLine) != 2 {
			t.Fatalf("log %q", got)
		}
	})
	t.Run("refreshes when unset", func(t *testing.T) {
		hup := make(chan os.Signal, 1)
		var n atomic.Int32
		var also atomic.Int32
		buf := &safeBuf{}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			WatchSIGHUP(ctx, hup, "", func() { n.Add(1) }, func() { also.Add(1) }, buf)
			close(done)
		}()
		hup <- syscall.SIGHUP
		deadline := time.Now().Add(2 * time.Second)
		for also.Load() < 1 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("watch did not return")
		}
		if n.Load() != 0 || also.Load() != 1 {
			t.Fatalf("reload %d also %d", n.Load(), also.Load())
		}
		if buf.String() != sighupIgnoreLine+"\n" {
			t.Fatalf("log %q", buf.String())
		}
	})
}
