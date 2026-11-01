package sandbox

import (
	"context"
	"testing"
	"time"
)

// TestShellStopErr fails if every ended shell context is called a timeout.
func TestShellStopErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := shellStopErr(ctx)
	if err == nil || err.Error() != "shell interrupted" {
		t.Fatalf("cancel %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	err = shellStopErr(ctx)
	if err == nil || err.Error() != "shell timed out" {
		t.Fatalf("deadline %v", err)
	}
}
