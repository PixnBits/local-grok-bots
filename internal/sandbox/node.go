package sandbox

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// installJailNode puts node on the jail PATH. An empty NodePath installs a
// read-only shim. A configured path is resolved, checked, and bind-mounted
// read-only at JailNodeDir.
func installJailNode(p *prepared, ro string, req Request, workspace string) error {
	if p == nil {
		return fmt.Errorf("node unavailable")
	}
	hostDir := filepath.Join(ro, "nodebin")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		return err
	}
	dest := filepath.Join(hostDir, "node")
	if strings.TrimSpace(req.NodePath) == "" {
		body := "#!/bin/sh\nprintf '%s\\n' '" + nodeUnsetText + "'\nexit 127\n"
		if err := os.WriteFile(dest, []byte(body), 0o555); err != nil {
			return err
		}
	} else {
		resolved, err := checkJailNode(req.NodePath, workspace)
		if err != nil {
			return err
		}
		if err := linkOrCopy(resolved, dest); err != nil {
			return fmt.Errorf("sandbox node: %w", err)
		}
	}
	p.nodeHost = hostDir
	p.mounts = append(p.mounts, mount{Src: hostDir, Dst: JailNodeDir, RO: true})
	return nil
}

func checkJailNode(raw, workspace string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("sandbox node is empty")
	}
	if !filepath.IsAbs(v) {
		return "", fmt.Errorf("sandbox node must be an absolute path")
	}
	resolved, err := filepath.EvalSymlinks(v)
	if err != nil {
		return "", fmt.Errorf("sandbox node: %v", err)
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("sandbox node: %v", err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("sandbox node must be a regular file")
	}
	if st.Mode()&0o111 == 0 {
		return "", fmt.Errorf("sandbox node must be executable")
	}
	resolved = filepath.Clean(resolved)
	ws := filepath.Clean(strings.TrimSpace(workspace))
	if ws != "" && pathHolds(ws, resolved) {
		return "", fmt.Errorf("sandbox node must be outside the workspace")
	}
	if wsReal, werr := filepath.EvalSymlinks(ws); werr == nil {
		wsReal = filepath.Clean(wsReal)
		if pathHolds(wsReal, resolved) || pathHolds(resolved, wsReal) {
			return "", fmt.Errorf("sandbox node must be outside the workspace")
		}
	}
	return resolved, nil
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
