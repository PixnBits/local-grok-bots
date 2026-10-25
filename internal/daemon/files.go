package daemon

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func (a *App) toolReadFile(args map[string]any) (string, error) {
	rel, err := workspaceRel(a.ws, strArg(args, "path"))
	if err != nil {
		return "", err
	}
	b, err := clisession.ReadRegularInDir(a.ws, rel)
	if err != nil {
		return "", fileErr(err)
	}
	const max = 256 * 1024
	s := string(b)
	if len(s) > max {
		s = s[:max] + "\n…(truncated)"
	}
	return s, nil
}

func (a *App) toolWriteFile(botID string, args map[string]any) (string, error) {
	rel, err := workspaceRel(a.ws, strArg(args, "path"))
	if err != nil {
		return "", err
	}
	if err := sandbox.CheckWrite(a.ws, filepath.Join(a.ws, rel)); err != nil {
		a.log(botID, "sandbox_block", map[string]any{"path": rel, "detail": err.Error()})
		return "", err
	}
	content := strArg(args, "content")
	if len(content) > 1<<20 {
		return "", errors.New("content too large")
	}
	if err := clisession.WriteRegularInDir(a.ws, rel, []byte(content), 0o644); err != nil {
		return "", fileErr(err)
	}
	if err := ownWorkspaceParents(a.ws, filepath.Join(a.ws, rel)); err != nil {
		return "", err
	}
	return `{"ok":true}`, nil
}

func (a *App) toolEditFile(botID string, args map[string]any) (string, error) {
	rel, err := workspaceRel(a.ws, strArg(args, "path"))
	if err != nil {
		return "", err
	}
	if err := sandbox.CheckWrite(a.ws, filepath.Join(a.ws, rel)); err != nil {
		a.log(botID, "sandbox_block", map[string]any{"path": rel, "detail": err.Error()})
		return "", err
	}
	old := strArg(args, "old_string")
	if old == "" {
		return "", errors.New("old_string required")
	}
	if _, ok := args["new_string"]; !ok {
		return "", errors.New("new_string required")
	}
	newStr := strArg(args, "new_string")
	want, set, err := countArg(args["expected_count"])
	if err != nil {
		return "", err
	}
	b, err := clisession.ReadRegularInDir(a.ws, rel)
	if err != nil {
		return "", fileErr(err)
	}
	n := strings.Count(string(b), old)
	if !set && n != 1 {
		return "", fmt.Errorf("old_string matched %d times", n)
	}
	if set && (want < 1 || n != want) {
		return "", fmt.Errorf("old_string matched %d times", n)
	}
	next := strings.Replace(string(b), old, newStr, n)
	if len(next) > 1<<20 {
		return "", errors.New("content too large")
	}
	if err := clisession.WriteRegularInDir(a.ws, rel, []byte(next), 0o644); err != nil {
		return "", fileErr(err)
	}
	return fmt.Sprintf(`{"ok":true,"replacements":%d}`, n), nil
}

func (a *App) toolDeleteFile(botID string, args map[string]any) (string, error) {
	rel, err := workspaceRel(a.ws, strArg(args, "path"))
	if err != nil {
		return "", err
	}
	if err := sandbox.CheckWrite(a.ws, filepath.Join(a.ws, rel)); err != nil {
		a.log(botID, "sandbox_block", map[string]any{"path": rel, "detail": err.Error()})
		return "", err
	}
	if err := clisession.RemoveRegularInDir(a.ws, rel); err != nil {
		return "", fileErr(err)
	}
	return `{"ok":true}`, nil
}

func workspaceRel(root, p string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	if strings.TrimSpace(p) == "" {
		return "", errors.New("path required")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("invalid path")
	}
	p = filepath.Clean(p)
	if filepath.IsAbs(p) {
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", errors.New("path escapes workspace")
		}
		p = rel
	}
	if p == "." || p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes workspace")
	}
	return p, nil
}

func countArg(v any) (int, bool, error) {
	if v == nil {
		return 0, false, nil
	}
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) || f < 1 || f > 1_000_000 {
		return 0, true, errors.New("expected_count must be an integer >= 1")
	}
	return int(f), true, nil
}

func fileErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, clisession.ErrCredSymlink) {
		return errors.New("symlink refused")
	}
	if errors.Is(err, clisession.ErrNotRegular) {
		return errors.New("not a regular file")
	}
	return err
}
