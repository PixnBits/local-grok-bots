package web

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestJobCardsStay(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), node, filepath.Join("testdata", "job_cards_test.mjs"))
	cmd.Dir = "."
	if wd, err := os.Getwd(); err == nil && filepath.Base(wd) != "web" {
		cmd.Dir = "web"
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
}
