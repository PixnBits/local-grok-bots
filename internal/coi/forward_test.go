package coi

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if HandleForward(os.Args[1:]) {
		return
	}
	os.Exit(m.Run())
}
