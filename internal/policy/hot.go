package policy

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
)

// hotView is the subset a running daemon may copy from a later file read.
type hotView struct {
	VoiceEnabled           bool
	VoiceMaxAudio          int
	VoiceMaxAudioSet       bool
	VoiceMaxBody           int64
	VoiceMaxBodySet        bool
	VoiceMaxPerHour        int
	VoiceMaxPerHourSet     bool
	LocalVoiceAudio        int64
	LocalVoiceBody         int64
	LocalVoicePerHour      int
	LocalVoiceAudioSet     bool
	LocalVoiceBodySet      bool
	LocalVoicePerHourSet   bool
	ManagedVoiceAudioSet   bool
	ManagedVoiceBodySet    bool
	ManagedVoicePerHourSet bool
	MaxVoiceAudio          int
	MaxVoiceBody           int64
	MaxVoicePerHour        int
	WhisperBin             string
	WhisperModel           string
	HasWhisper             bool
	ManagedWhisper         bool
	ClaudeTransport        string
}

func hotOf(p Policy) hotView {
	return hotView{
		VoiceEnabled:           p.VoiceEnabled,
		VoiceMaxAudio:          p.VoiceMaxAudio,
		VoiceMaxAudioSet:       p.VoiceMaxAudioSet,
		VoiceMaxBody:           p.VoiceMaxBody,
		VoiceMaxBodySet:        p.VoiceMaxBodySet,
		VoiceMaxPerHour:        p.VoiceMaxPerHour,
		VoiceMaxPerHourSet:     p.VoiceMaxPerHourSet,
		LocalVoiceAudio:        p.localVoiceAudio,
		LocalVoiceBody:         p.localVoiceBody,
		LocalVoicePerHour:      p.localVoicePerHour,
		LocalVoiceAudioSet:     p.localVoiceAudioSet,
		LocalVoiceBodySet:      p.localVoiceBodySet,
		LocalVoicePerHourSet:   p.localVoicePerHourSet,
		ManagedVoiceAudioSet:   p.managedVoiceAudioSet,
		ManagedVoiceBodySet:    p.managedVoiceBodySet,
		ManagedVoicePerHourSet: p.managedVoicePerHourSet,
		MaxVoiceAudio:          p.MaxVoiceAudio,
		MaxVoiceBody:           p.MaxVoiceBody,
		MaxVoicePerHour:        p.MaxVoicePerHour,
		WhisperBin:             p.WhisperBin,
		WhisperModel:           p.WhisperModel,
		HasWhisper:             p.HasWhisper,
		ManagedWhisper:         p.managedWhisper,
		ClaudeTransport:        p.ClaudeTransport,
	}
}

// WithHot returns a copy of p with voice settings and claude_transport taken from fresh.
func (p Policy) WithHot(fresh Policy) Policy {
	out := p
	h := hotOf(fresh)
	out.VoiceEnabled = h.VoiceEnabled
	out.VoiceMaxAudio = h.VoiceMaxAudio
	out.VoiceMaxAudioSet = h.VoiceMaxAudioSet
	out.VoiceMaxBody = h.VoiceMaxBody
	out.VoiceMaxBodySet = h.VoiceMaxBodySet
	out.VoiceMaxPerHour = h.VoiceMaxPerHour
	out.VoiceMaxPerHourSet = h.VoiceMaxPerHourSet
	out.localVoiceAudio = h.LocalVoiceAudio
	out.localVoiceBody = h.LocalVoiceBody
	out.localVoicePerHour = h.LocalVoicePerHour
	out.localVoiceAudioSet = h.LocalVoiceAudioSet
	out.localVoiceBodySet = h.LocalVoiceBodySet
	out.localVoicePerHourSet = h.LocalVoicePerHourSet
	out.managedVoiceAudioSet = h.ManagedVoiceAudioSet
	out.managedVoiceBodySet = h.ManagedVoiceBodySet
	out.managedVoicePerHourSet = h.ManagedVoicePerHourSet
	out.MaxVoiceAudio = h.MaxVoiceAudio
	out.MaxVoiceBody = h.MaxVoiceBody
	out.MaxVoicePerHour = h.MaxVoicePerHour
	out.WhisperBin = h.WhisperBin
	out.WhisperModel = h.WhisperModel
	out.HasWhisper = h.HasWhisper
	out.managedWhisper = h.ManagedWhisper
	out.ClaudeTransport = h.ClaudeTransport
	return out
}

// HotEqual reports whether voice settings and claude_transport match.
func HotEqual(a, b Policy) bool {
	return reflect.DeepEqual(hotOf(a), hotOf(b))
}

// VoiceOff returns a copy with voice disabled and whisper paths cleared.
// claude_transport is left as it is on p.
func (p Policy) VoiceOff() Policy {
	out := p
	out.VoiceEnabled = false
	out.VoiceMaxAudio = 0
	out.VoiceMaxAudioSet = false
	out.VoiceMaxBody = 0
	out.VoiceMaxBodySet = false
	out.VoiceMaxPerHour = 0
	out.VoiceMaxPerHourSet = false
	out.localVoiceAudio = 0
	out.localVoiceBody = 0
	out.localVoicePerHour = 0
	out.localVoiceAudioSet = false
	out.localVoiceBodySet = false
	out.localVoicePerHourSet = false
	out.managedVoiceAudioSet = false
	out.managedVoiceBodySet = false
	out.managedVoicePerHourSet = false
	out.MaxVoiceAudio = 0
	out.MaxVoiceBody = 0
	out.MaxVoicePerHour = 0
	out.WhisperBin = ""
	out.WhisperModel = ""
	out.HasWhisper = false
	out.managedWhisper = false
	return out
}

// RestartKeys names startup settings that differ. The names are sorted.
// Values are not included.
func RestartKeys(start, fresh Policy) []string {
	var keys []string
	if start.Backend != fresh.Backend || start.CLIPermitted != fresh.CLIPermitted ||
		start.EffectiveBackend() != fresh.EffectiveBackend() || start.UsesCLI() != fresh.UsesCLI() {
		keys = append(keys, "backend")
	}
	if start.Bind != fresh.Bind || start.HasBind != fresh.HasBind {
		keys = append(keys, "bind")
	}
	if start.HasTLS != fresh.HasTLS || start.TLSCert != fresh.TLSCert {
		keys = append(keys, "tls_cert")
	}
	if start.TLSKey != fresh.TLSKey {
		keys = append(keys, "tls_key")
	}
	if start.TLSSelfSigned != fresh.TLSSelfSigned {
		keys = append(keys, "tls_self_signed")
	}
	if start.PermCallbackAddr != fresh.PermCallbackAddr || start.HasPermCallback != fresh.HasPermCallback {
		keys = append(keys, "perm_callback_addr")
	}
	if start.AuditLog != fresh.AuditLog {
		keys = append(keys, "audit_log")
	}
	if !reflect.DeepEqual(start.AllowedHosts, fresh.AllowedHosts) {
		keys = append(keys, "allowed_hosts")
	}
	sort.Strings(keys)
	if keys == nil {
		keys = []string{}
	}
	return keys
}

// ValidHostName accepts a hostname or IP with no scheme, port, or wildcard.
func ValidHostName(h string) error {
	if h == "" || strings.Contains(h, "://") || strings.ContainsAny(h, " \t\r\n/?#*") || strings.Contains(h, "*") || strings.Contains(h, "?") {
		return fmt.Errorf("allowed_hosts entry %q is not a host name", h)
	}
	if ip := net.ParseIP(h); ip != nil {
		return nil
	}
	if strings.ContainsAny(h, ":[]") {
		return fmt.Errorf("allowed_hosts entry %q is not a host name", h)
	}
	if len(h) > 253 {
		return fmt.Errorf("allowed_hosts entry %q is not a host name", h)
	}
	for _, lab := range strings.Split(h, ".") {
		if lab == "" || len(lab) > 63 || lab[0] == '-' || lab[len(lab)-1] == '-' {
			return fmt.Errorf("allowed_hosts entry %q is not a host name", h)
		}
		for _, c := range lab {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("allowed_hosts entry %q is not a host name", h)
			}
		}
	}
	return nil
}

// NormalizeHosts checks each entry. nil in is nil out.
func NormalizeHosts(in []string) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.TrimSpace(h)
		if err := ValidHostName(h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}
