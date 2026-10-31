package permbroker

import (
	"bytes"
	"context"
	iofs "io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// gitBaselineFormat is the piece set written from this branch onward.
// Version stays 1 so an older reader still accepts the JSON. Format 0
// is a file from before this field existed. Old and new piece sets are
// told apart by the blob, not by this number alone.
const gitBaselineFormat = 2

const (
	gitReasonConfig = "Git config changed since it was last reviewed"
	gitReasonAttrs  = "A .gitattributes file changed"
	gitReasonSystem = "System git config changed"
	gitReasonHook   = "Git hook changed"
)

// gitBaselineBlobOld is the fcc6144 piece set: repo config, hooks, info
// attributes, the worktree-root .gitattributes only, then homes. It has
// no system gitconfig piece and no nested attribute pieces.
func gitBaselineBlobOld(ws string, homes []string) []byte {
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
	writeHomes(&b, homes)
	return []byte(b.String())
}

func writeHomes(b *strings.Builder, homes []string) {
	for _, h := range cleanHomes(homes) {
		b.WriteString("home ")
		b.WriteString(h)
		b.WriteByte('\n')
		gc, gcOK := readBaselineFile(filepath.Join(h, ".gitconfig"))
		writePiece(b, "gitconfig", gc, gcOK)
		xc, xcOK := readBaselineFile(filepath.Join(h, ".config", "git", "config"))
		writePiece(b, "xdg-config", xc, xcOK)
		xa, xaOK := readBaselineFile(filepath.Join(h, ".config", "git", "attributes"))
		writePiece(b, "xdg-attributes", xa, xaOK)
	}
}

func cleanHomes(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		h = filepath.Clean(h)
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func sameHomes(a, b []string) bool {
	aa, bb := cleanHomes(a), cleanHomes(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

// blobIsOldFormat reports a baseline written before the system gitconfig
// piece and the nested attribute pieces. An empty blob is not old.
func blobIsOldFormat(blob []byte) bool {
	if !bytes.HasPrefix(blob, []byte("v1\n")) {
		return false
	}
	return !bytes.Contains(blob, []byte("system-gitconfig "))
}

func blobHomes(blob []byte) []string {
	var out []string
	for _, line := range strings.Split(string(blob), "\n") {
		if rest, ok := strings.CutPrefix(line, "home "); ok && rest != "" {
			out = append(out, rest)
		}
	}
	return out
}

func pieceText(blob []byte, name string) string {
	var b strings.Builder
	for _, line := range strings.Split(string(blob), "\n") {
		if line == name || strings.HasPrefix(line, name+" ") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func driftReason(stored, current []byte) string {
	if pieceText(stored, "gitattributes") != pieceText(current, "gitattributes") {
		return gitReasonAttrs
	}
	if pieceText(stored, "system-gitconfig") != pieceText(current, "system-gitconfig") &&
		(pieceText(stored, "system-gitconfig") != "" || pieceText(current, "system-gitconfig") != "") {
		return gitReasonSystem
	}
	if pieceText(stored, "hooks") != pieceText(current, "hooks") && hooksOnlyDrift(stored, current) {
		return gitReasonHook
	}
	return gitReasonConfig
}

// hooksOnlyDrift is true when the hooks piece is the only difference.
func hooksOnlyDrift(stored, current []byte) bool {
	return stripPiece(stored, "hooks") == stripPiece(current, "hooks")
}

func stripPiece(blob []byte, name string) string {
	var b strings.Builder
	for _, line := range strings.Split(string(blob), "\n") {
		if line == name || strings.HasPrefix(line, name+" ") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// maybeUpgradeBaselineLocked rewrites an old baseline when the files it
// covered are unchanged. Homes in the blob must already match the bot.
// The caller holds e.mu. A real change is left stored so the compare asks.
func (e *Engine) maybeUpgradeBaselineLocked(bot string) {
	if e == nil || e.baselineCorrupt || bot == "" {
		return
	}
	b := e.bots[bot]
	if !b.snapSet || strings.TrimSpace(b.Workspace) == "" {
		return
	}
	if !blobIsOldFormat(b.snapBlob) {
		return
	}
	homes := homesOf(b)
	if !sameHomes(blobHomes(b.snapBlob), homes) {
		return
	}
	old := gitBaselineBlobOld(b.Workspace, homes)
	if !bytes.Equal(old, b.snapBlob) {
		return
	}
	next := gitBaselineBlob(b.Workspace, homes)
	if e.savedBaseline == nil {
		e.savedBaseline = map[string][]byte{}
	}
	prev := append([]byte(nil), e.savedBaseline[bot]...)
	had := len(prev) > 0
	e.savedBaseline[bot] = append([]byte(nil), next...)
	if err := e.persistBaselinesLocked(); err != nil {
		if had {
			e.savedBaseline[bot] = prev
		} else {
			delete(e.savedBaseline, bot)
		}
		return
	}
	b.snapSet = true
	b.snapBlob = append([]byte(nil), next...)
	e.bots[bot] = b
	e.auditDecision(Request{BotID: bot}, inspected{
		ClassNote: "none", Hash: hashRaw("git-baseline", bot),
	}, "upgrade", "upgrade", "", "upgrade", "", "")
}

func init() {
	resolveSystemGitconfig()
}

// resolveSystemGitconfig points systemGitconfig at the file git itself
// uses, when that file can be named. Tests assign the variable after
// init and that assignment wins. The file is never written.
func resolveSystemGitconfig() {
	if systemGitconfig != "/etc/gitconfig" {
		return
	}
	if p := systemGitconfigFromCommand(); p != "" {
		systemGitconfig = p
	}
}

func systemGitconfigFromCommand() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "config", "--system", "--list", "--show-origin").Output()
	if err == nil {
		if p := firstSystemGitconfig(string(out)); p != "" {
			return p
		}
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	execOut, err := exec.CommandContext(ctx2, "git", "--exec-path").Output()
	if err != nil {
		return ""
	}
	return systemGitconfigFromExecPath(strings.TrimSpace(string(execOut)))
}

func firstSystemGitconfig(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "file:")
		if !ok {
			continue
		}
		if i := strings.IndexAny(rest, "\t "); i >= 0 {
			rest = rest[:i]
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		st, err := os.Stat(rest)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		return rest
	}
	return ""
}

// systemGitconfigFromExecPath maps `git --exec-path` to the sibling
// etc/gitconfig. /usr/lib/git-core becomes /usr/etc/gitconfig. A missing
// file returns empty so the caller keeps /etc/gitconfig.
func systemGitconfigFromExecPath(execPath string) string {
	execPath = strings.TrimSpace(execPath)
	if execPath == "" {
		return ""
	}
	p := filepath.Join(filepath.Dir(filepath.Dir(execPath)), "etc", "gitconfig")
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	return p
}

// symlinkAttrRisk reports a directory symlink inside the worktree whose
// target contains .gitattributes. Git does not apply those attributes.
// The walk does not follow the link into the baseline list.
func symlinkAttrRisk(ws string) string {
	ws = strings.TrimSpace(ws)
	if ws == "" {
		return ""
	}
	ws = filepath.Clean(ws)
	st, err := os.Stat(ws)
	if err != nil || !st.IsDir() {
		return ""
	}
	found := false
	n := 0
	_ = filepath.WalkDir(ws, func(path string, d iofs.DirEntry, err error) error {
		if err != nil || found {
			return iofs.SkipDir
		}
		if d.Name() == ".git" && path != ws {
			if d.IsDir() {
				return iofs.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(ws, path)
		if relErr != nil {
			return iofs.SkipAll
		}
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(os.PathSeparator))
		}
		if depth > gitAttrMaxDepth {
			if d.IsDir() {
				return iofs.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink == 0 {
			return nil
		}
		n++
		if n > gitAttrMaxFiles {
			return iofs.SkipAll
		}
		target, statErr := os.Stat(path)
		if statErr != nil || !target.IsDir() {
			return nil
		}
		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			return nil
		}
		for _, ent := range entries {
			if ent.Name() == ".gitattributes" && !ent.IsDir() {
				found = true
				return iofs.SkipAll
			}
		}
		return nil
	})
	if found {
		return "symlink"
	}
	return ""
}
