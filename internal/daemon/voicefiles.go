package daemon

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"golang.org/x/sys/unix"
)

type voiceStat struct {
	mode uint32
	uid  int
	err  error
}

func whisperPaths(pol policy.Policy, cfg config.Config) (bin, model, binKey, modelKey string) {
	if pol.HasWhisper {
		return pol.WhisperBin, pol.WhisperModel, "voice.bin", "voice.model"
	}
	return cfg.WhisperBin, cfg.WhisperModel, "WHISPER_BIN", "WHISPER_MODEL"
}

// applyVoiceRuntime checks the effective whisper files and records a block
// when voice is on but a path is not usable. A missing file is left for the
// request path to report as unavailable.
func (a *App) applyVoiceRuntime() {
	if a == nil {
		return
	}
	pol := a.pol()
	block, next := a.prepVoice(pol)
	a.installMu.Lock()
	prev := a.voiceBlock
	a.voiceBlock = block
	a.stt = next
	a.installMu.Unlock()
	if block != "" && block != prev {
		a.writeStartup("local-grok-bots: WARN: %s\n", block)
		a.log("", "voice_path", map[string]any{"warning": block})
	}
}

// prepVoice builds the transcriber for pol. Voice that is off, or a pair
// with an empty path, publishes no transcriber.
func (a *App) prepVoice(pol policy.Policy) (string, STT) {
	if !pol.VoiceEnabled {
		return "", nil
	}
	bin, model, binKey, modelKey := a.effectiveWhisper(pol)
	if bin == "" || model == "" {
		return "", nil
	}
	reason := voicePathProblem(bin, model, binKey, modelKey, os.Geteuid())
	built, err := sttFromConfig(bin, model)
	if err != nil || built == nil {
		return reason, nil
	}
	if w, ok := built.(WhisperCLI); ok {
		w.BinKey = binKey
		w.ModelKey = modelKey
		built = w
	}
	return reason, built
}

func (a *App) effectiveWhisper(pol policy.Policy) (bin, model, binKey, modelKey string) {
	if pol.HasWhisper {
		return pol.WhisperBin, pol.WhisperModel, "voice.bin", "voice.model"
	}
	if a != nil && a.envWhisper {
		return a.cfg.WhisperBin, a.cfg.WhisperModel, "WHISPER_BIN", "WHISPER_MODEL"
	}
	return "", "", "voice.bin", "voice.model"
}

func voicePathProblem(bin, model, binKey, modelKey string, uid int) string {
	if bin == "" || model == "" {
		return ""
	}
	if msg := checkVoicePath(bin, binKey, uid, lstatVoice); msg != "" {
		return msg
	}
	return checkVoicePath(model, modelKey, uid, lstatVoice)
}

func lstatVoice(path string) voiceStat {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return voiceStat{err: err}
	}
	return voiceStat{mode: uint32(st.Mode), uid: int(st.Uid)}
}

func checkVoicePath(path, key string, uid int, stat func(string) voiceStat) string {
	st := stat(path)
	if st.err != nil {
		if os.IsNotExist(st.err) {
			return ""
		}
		return key + " is not available"
	}
	if msg := judgeVoice(key, st, uid, true); msg != "" {
		return msg
	}
	parent := filepath.Dir(path)
	if parent == "" || parent == "." || parent == "/" || parent == path {
		return ""
	}
	pst := stat(parent)
	if pst.err != nil {
		if os.IsNotExist(pst.err) {
			return ""
		}
		return key + " parent is not available"
	}
	return judgeVoice(key+" parent", pst, uid, false)
}

func judgeVoice(key string, st voiceStat, uid int, regular bool) string {
	if st.mode&unix.S_IFMT == unix.S_IFLNK {
		return key + " is a symlink"
	}
	if regular {
		if st.mode&unix.S_IFMT != unix.S_IFREG {
			return key + " is not a regular file"
		}
	} else if st.mode&unix.S_IFMT != unix.S_IFDIR {
		return key + " is not a directory"
	}
	if st.uid != 0 && st.uid != uid {
		return key + " owner is not root or the daemon"
	}
	if st.mode&0o022 != 0 {
		return key + " is group or other writable"
	}
	return ""
}

// voiceExecProblem checks the binary, the model, both parents, and each
// lib*.so* file next to the binary. A missing file returns an empty string.
func voiceExecProblem(bin, model, binKey, modelKey string, uid int) string {
	if msg := checkVoicePath(bin, binKey, uid, lstatVoice); msg != "" {
		return msg + " " + bin
	}
	if msg := checkVoicePath(model, modelKey, uid, lstatVoice); msg != "" {
		return msg + " " + model
	}
	return voiceLibsProblem(bin, uid)
}

func voiceLibsProblem(bin string, uid int) string {
	dir := filepath.Clean(filepath.Dir(bin))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "voice.bin is not available"
	}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasPrefix(name, "lib") || !strings.Contains(name, ".so") {
			continue
		}
		path := filepath.Join(dir, name)
		if msg := judgeVoiceLib(path, dir, uid); msg != "" {
			return msg
		}
	}
	return ""
}

func judgeVoiceLib(path, dir string, uid int) string {
	st := lstatVoice(path)
	if st.err != nil {
		if os.IsNotExist(st.err) {
			return ""
		}
		return "voice.bin lib " + path + " is not available"
	}
	if st.mode&unix.S_IFMT == unix.S_IFLNK {
		target, err := filepath.EvalSymlinks(path)
		if err != nil || !insideDir(dir, target) {
			return "voice.bin lib " + path + " is a symlink"
		}
		tst := lstatVoice(target)
		if tst.err != nil {
			return "voice.bin lib " + path + " is not available"
		}
		if msg := judgeVoice("voice.bin lib "+path, tst, uid, true); msg != "" {
			return msg
		}
		return ""
	}
	return judgeVoice("voice.bin lib "+path, st, uid, true)
}

func insideDir(dir, target string) bool {
	dir = filepath.Clean(dir)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
