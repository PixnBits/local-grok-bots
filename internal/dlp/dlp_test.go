package dlp

import (
	"context"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestScanOffByDefault(t *testing.T) {
	if err := Scan(context.Background(), policy.Policy{}, "secret-pattern"); err != nil {
		t.Fatal(err)
	}
}

func TestScanPatternBlocksWithoutLoggingPrompt(t *testing.T) {
	err := Scan(context.Background(), policy.Policy{DLPPatterns: []string{"secret-pattern"}}, "has secret-pattern inside")
	if err == nil || !strings.Contains(err.Error(), "pattern") || strings.Contains(err.Error(), "secret-pattern") {
		t.Fatalf("err %v", err)
	}
}
