package permbroker

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const gitBaselineName = "git-baseline.json"

type gitBaselineDoc struct {
	Version int              `json:"version"`
	Bots    []gitBaselineBot `json:"bots"`
}

type gitBaselineBot struct {
	ID   string `json:"id"`
	Blob string `json:"blob"`
}

// gitBaselineBlob is the per-bot snapshot. It covers the repo config, a
// digest of the hooks directory, attribute files, and each home's git
// config and attributes. The text is stable for unchanged inputs.
func gitBaselineBlob(ws string, homes []string) []byte {
	var b strings.Builder
	b.WriteString("v1\n")
	repo, repoOK := readRepoConfig(ws)
	writePiece(&b, "repo-config", repo, repoOK)
	digest := hooksDigest(ws)
	b.WriteString("hooks ")
	b.WriteString(digest)
	if !strings.HasSuffix(digest, "\n") {
		b.WriteByte('\n')
	}
	var infoData []byte
	var infoOK bool
	if dir, ok := gitDir(ws); ok {
		infoData, infoOK = readBaselineFile(filepath.Join(dir, "info", "attributes"))
	}
	writePiece(&b, "info-attributes", infoData, infoOK)
	attr, attrOK := readBaselineFile(filepath.Join(ws, ".gitattributes"))
	writePiece(&b, "gitattributes", attr, attrOK)
	hs := append([]string(nil), homes...)
	sort.Strings(hs)
	seen := map[string]bool{}
	for _, h := range hs {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		h = filepath.Clean(h)
		if seen[h] {
			continue
		}
		seen[h] = true
		b.WriteString("home ")
		b.WriteString(h)
		b.WriteByte('\n')
		gc, gcOK := readBaselineFile(filepath.Join(h, ".gitconfig"))
		writePiece(&b, "gitconfig", gc, gcOK)
		xc, xcOK := readBaselineFile(filepath.Join(h, ".config", "git", "config"))
		writePiece(&b, "xdg-config", xc, xcOK)
		xa, xaOK := readBaselineFile(filepath.Join(h, ".config", "git", "attributes"))
		writePiece(&b, "xdg-attributes", xa, xaOK)
	}
	return []byte(b.String())
}

func writePiece(b *strings.Builder, name string, data []byte, ok bool) {
	if !ok {
		fmt.Fprintf(b, "%s missing\n", name)
		return
	}
	sum := sha256.Sum256(data)
	fmt.Fprintf(b, "%s %x\n", name, sum[:])
}

func readRepoConfig(ws string) ([]byte, bool) {
	if strings.TrimSpace(ws) == "" {
		return nil, false
	}
	p := filepath.Join(ws, ".git")
	st, err := os.Lstat(p)
	if err != nil {
		return nil, false
	}
	var body []byte
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(p)
		if err != nil {
			body = []byte("symlink")
		} else {
			body = []byte("symlink:" + target)
		}
	case st.Mode().IsRegular():
		b, err := os.ReadFile(p)
		if err != nil {
			body = []byte("file-unreadable")
		} else {
			body = append([]byte("file:"), b...)
		}
	case st.IsDir():
		body = []byte("dir")
	default:
		body = []byte("other")
	}
	if dir, ok := gitDir(ws); ok {
		cfg, cfgOK := readBaselineFile(filepath.Join(dir, "config"))
		if cfgOK {
			body = append(append(body, '\n'), cfg...)
		} else {
			body = append(body, []byte("\nconfig-missing")...)
		}
		return body, true
	}
	return body, true
}

// hooksDigest lists hook names, modes, and content hashes in name order.
// A missing hooks directory is "absent". The text ends with a newline
// when it has entries.
func hooksDigest(ws string) string {
	dir, ok := gitDir(ws)
	if !ok {
		return "absent"
	}
	hooks := filepath.Join(dir, "hooks")
	entries, err := os.ReadDir(hooks)
	if err != nil {
		if os.IsNotExist(err) {
			return "absent"
		}
		return "unreadable"
	}
	names := make([]string, 0, len(entries))
	for _, ent := range entries {
		names = append(names, ent.Name())
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		path := filepath.Join(hooks, name)
		info, err := os.Lstat(path)
		if err != nil {
			fmt.Fprintf(&b, "%s missing\n", name)
			continue
		}
		sum := sha256.New()
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			if target, err := os.Readlink(path); err == nil {
				_, _ = sum.Write([]byte(target))
			} else {
				_, _ = sum.Write([]byte("unreadable"))
			}
		case info.Mode().IsRegular():
			if buf, err := os.ReadFile(path); err == nil {
				_, _ = sum.Write(buf)
			} else {
				_, _ = sum.Write([]byte("unreadable"))
			}
		}
		fmt.Fprintf(&b, "%s %s %x\n", name, modeTag(info), sum.Sum(nil))
	}
	if b.Len() == 0 {
		return "empty"
	}
	return b.String()
}

func modeTag(info os.FileInfo) string {
	m := info.Mode()
	kind := "o"
	switch {
	case m&os.ModeSymlink != 0:
		kind = "l"
	case m.IsDir():
		kind = "d"
	case m.IsRegular():
		kind = "f"
	}
	return fmt.Sprintf("%s%o", kind, m.Perm())
}

func loadGitBaseline(path string) (map[string][]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]byte{}, false
		}
		log.Printf("permission broker: git baseline file is unreadable: %s", path)
		return map[string][]byte{}, true
	}
	if len(bytesTrim(b)) == 0 {
		log.Printf("permission broker: git baseline file is unreadable: %s", path)
		return map[string][]byte{}, true
	}
	var doc gitBaselineDoc
	if err := json.Unmarshal(b, &doc); err != nil || doc.Version != 1 {
		log.Printf("permission broker: git baseline file is unreadable: %s", path)
		return map[string][]byte{}, true
	}
	out := map[string][]byte{}
	for _, bot := range doc.Bots {
		id := strings.TrimSpace(bot.ID)
		if id == "" || bot.Blob == "" {
			continue
		}
		out[id] = []byte(bot.Blob)
	}
	return out, false
}

func (e *Engine) persistBaselinesLocked() error {
	ids := make([]string, 0, len(e.savedBaseline))
	for id := range e.savedBaseline {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	doc := gitBaselineDoc{Version: 1, Bots: make([]gitBaselineBot, 0, len(ids))}
	for _, id := range ids {
		doc.Bots = append(doc.Bots, gitBaselineBot{ID: id, Blob: string(e.savedBaseline[id])})
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writePrivate(e.baselinePath, body)
}

func writePrivate(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "baseline-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return os.Chmod(path, 0o600)
}
