package daemon

import (
	"os"
	"path/filepath"

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
	a.rtMu.Lock()
	enabled := a.policy.VoiceEnabled
	bin, model, binKey, modelKey := whisperPaths(a.policy, a.cfg)
	prev := a.voiceBlock
	a.rtMu.Unlock()

	reason := ""
	if enabled {
		reason = voicePathProblem(bin, model, binKey, modelKey, os.Geteuid())
	}
	var next STT
	if bin != "" && model != "" {
		if built, err := sttFromConfig(bin, model); err == nil {
			if w, ok := built.(WhisperCLI); ok {
				w.BinKey = binKey
				w.ModelKey = modelKey
				built = w
			}
			next = built
		}
	}
	a.rtMu.Lock()
	a.voiceBlock = reason
	if next != nil {
		a.stt = next
	}
	a.rtMu.Unlock()
	if reason != "" && reason != prev {
		a.writeStartup("local-grok-bots: WARN: %s\n", reason)
		a.log("", "voice_path", map[string]any{"warning": reason})
	}
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
