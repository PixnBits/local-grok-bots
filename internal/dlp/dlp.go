// Package dlp is the optional prompt check before a CLI turn.
// It is off unless the policy sets patterns, a blocklist file, or a command.
package dlp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

const maxContent = 1 << 20

// Scan returns nil when the check is off or the content is allowed.
// A match, a rejecting command, or a check that cannot run fails the turn.
// The error does not include the prompt.
func Scan(ctx context.Context, pol policy.Policy, content string) error {
	if !pol.DLPEnabled() {
		return nil
	}
	if strings.TrimSpace(content) == "" {
		return nil
	}
	if len(content) > maxContent {
		return fmt.Errorf("dlp: content too large")
	}
	regs, err := rules(pol)
	if err != nil {
		return fmt.Errorf("dlp: rules unreadable")
	}
	for _, re := range regs {
		if re.MatchString(content) {
			return fmt.Errorf("dlp: blocked by pattern")
		}
	}
	if strings.TrimSpace(pol.DLPCommand) == "" {
		return nil
	}
	return runScanner(ctx, pol.DLPCommand, content)
}

func rules(pol policy.Policy) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, pattern := range pol.DLPPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	if strings.TrimSpace(pol.DLPFile) == "" {
		return out, nil
	}
	body, err := os.ReadFile(pol.DLPFile)
	if err != nil {
		return nil, err
	}
	if len(body) > 64*1024 {
		return nil, fmt.Errorf("blocklist is too large")
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var re *regexp.Regexp
		if strings.HasPrefix(line, "re:") {
			re, err = regexp.Compile(strings.TrimSpace(strings.TrimPrefix(line, "re:")))
		} else {
			re, err = regexp.Compile("(?i)" + regexp.QuoteMeta(line))
		}
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func runScanner(ctx context.Context, path, content string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("dlp: scanner failed")
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Errorf("dlp: blocked by scanner")
	}
	return fmt.Errorf("dlp: scanner failed")
}
