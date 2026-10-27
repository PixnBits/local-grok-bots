package policy

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// DefaultVoiceMaxAudioSeconds is the cap when [voice] omits max_audio_seconds.
	DefaultVoiceMaxAudioSeconds = 240
	// DefaultVoiceMaxBodyBytes is the cap when [voice] omits max_body_bytes.
	DefaultVoiceMaxBodyBytes int64 = 8 << 20
	// DefaultVoiceRequestsPerHour is the cap when [voice] omits max_requests_per_hour.
	DefaultVoiceRequestsPerHour = 60

	maxVoiceAudioSeconds          = 24 * 60 * 60
	maxVoiceBodyBytes       int64 = 64 << 20
	maxVoiceRequestsPerHour       = 100000
)

// voiceDoc is [voice]. Limits are optional. bin and model are a pair.
type voiceDoc struct {
	Enabled            *bool   `toml:"enabled" json:"enabled"`
	Bin                *string `toml:"bin" json:"bin"`
	Model              *string `toml:"model" json:"model"`
	MaxAudioSeconds    *int    `toml:"max_audio_seconds" json:"max_audio_seconds"`
	MaxBodyBytes       *int64  `toml:"max_body_bytes" json:"max_body_bytes"`
	MaxRequestsPerHour *int    `toml:"max_requests_per_hour" json:"max_requests_per_hour"`
}

func (p *Policy) applyDaemonExtra(d daemonDoc, trusted bool) error {
	if err := p.applyTLS(d, trusted); err != nil {
		return err
	}
	if d.PermCallbackAddr == nil {
		return nil
	}
	addr := strings.TrimSpace(*d.PermCallbackAddr)
	if err := RequireLoopbackAddr(addr); err != nil {
		return err
	}
	p.PermCallbackAddr = addr
	p.HasPermCallback = true
	if trusted {
		p.managedPermCallback = true
	}
	return nil
}

func (p *Policy) applyTLS(d daemonDoc, trusted bool) error {
	if d.TLSCert == nil && d.TLSKey == nil && d.TLSSelfSigned == nil {
		return nil
	}
	cert, key := "", ""
	self := false
	if d.TLSCert != nil {
		cert = strings.TrimSpace(*d.TLSCert)
	}
	if d.TLSKey != nil {
		key = strings.TrimSpace(*d.TLSKey)
	}
	if d.TLSSelfSigned != nil {
		self = *d.TLSSelfSigned
	}
	if (cert == "") != (key == "") {
		return fmt.Errorf("daemon.tls_cert and daemon.tls_key must be set together")
	}
	if cert != "" && self {
		return fmt.Errorf("daemon.tls_self_signed cannot be combined with tls_cert and tls_key")
	}
	if cert != "" && (!filepath.IsAbs(cert) || !filepath.IsAbs(key)) {
		return fmt.Errorf("daemon.tls_cert and daemon.tls_key must be absolute paths")
	}
	p.TLSCert = cert
	p.TLSKey = key
	p.TLSSelfSigned = self
	p.HasTLS = true
	if trusted {
		p.managedTLS = true
	}
	return nil
}

func (p *Policy) applyVoice(doc voiceDoc, trusted bool) error {
	if doc.Enabled != nil {
		p.VoiceEnabled = *doc.Enabled
	}
	if doc.Bin != nil || doc.Model != nil {
		if doc.Bin == nil || doc.Model == nil {
			return fmt.Errorf("voice.bin and voice.model must be set together")
		}
		bin := strings.TrimSpace(*doc.Bin)
		model := strings.TrimSpace(*doc.Model)
		if bin == "" || model == "" {
			return fmt.Errorf("voice.bin and voice.model must be set together")
		}
		if !filepath.IsAbs(bin) || !filepath.IsAbs(model) {
			return fmt.Errorf("voice.bin and voice.model must be absolute paths")
		}
		p.WhisperBin = bin
		p.WhisperModel = model
		p.HasWhisper = true
		if trusted {
			p.managedWhisper = true
		}
	}
	if doc.MaxAudioSeconds != nil {
		n := *doc.MaxAudioSeconds
		if n <= 0 || n > maxVoiceAudioSeconds {
			return fmt.Errorf("voice.max_audio_seconds must be from 1 to %d", maxVoiceAudioSeconds)
		}
		p.VoiceMaxAudio = n
		p.VoiceMaxAudioSet = true
		if trusted {
			p.managedVoiceAudioSet = true
		} else {
			p.localVoiceAudio = int64(n)
			p.localVoiceAudioSet = true
		}
	}
	if doc.MaxBodyBytes != nil {
		n := *doc.MaxBodyBytes
		if n <= 0 || n > maxVoiceBodyBytes {
			return fmt.Errorf("voice.max_body_bytes must be from 1 to %d", maxVoiceBodyBytes)
		}
		p.VoiceMaxBody = n
		p.VoiceMaxBodySet = true
		if trusted {
			p.managedVoiceBodySet = true
		} else {
			p.localVoiceBody = n
			p.localVoiceBodySet = true
		}
	}
	if doc.MaxRequestsPerHour != nil {
		n := *doc.MaxRequestsPerHour
		if n <= 0 || n > maxVoiceRequestsPerHour {
			return fmt.Errorf("voice.max_requests_per_hour must be from 1 to %d", maxVoiceRequestsPerHour)
		}
		p.VoiceMaxPerHour = n
		p.VoiceMaxPerHourSet = true
		if trusted {
			p.managedVoicePerHourSet = true
		} else {
			p.localVoicePerHour = n
			p.localVoicePerHourSet = true
		}
	}
	return nil
}

func (p *Policy) applyVoiceCeilings(doc managedDoc, trusted bool) error {
	if doc.MaxVoiceAudioSeconds == nil && doc.MaxVoiceBodyBytes == nil && doc.MaxVoiceRequestsPerHour == nil {
		return nil
	}
	var audio, body, perHour int64
	var setAudio, setBody, setPerHour bool
	if doc.MaxVoiceAudioSeconds != nil {
		n := *doc.MaxVoiceAudioSeconds
		if n <= 0 || n > maxVoiceAudioSeconds {
			return fmt.Errorf("managed.max_voice_audio_seconds must be from 1 to %d", maxVoiceAudioSeconds)
		}
		audio = int64(n)
		setAudio = true
	}
	if doc.MaxVoiceBodyBytes != nil {
		n := *doc.MaxVoiceBodyBytes
		if n <= 0 || n > maxVoiceBodyBytes {
			return fmt.Errorf("managed.max_voice_body_bytes must be from 1 to %d", maxVoiceBodyBytes)
		}
		body = n
		setBody = true
	}
	if doc.MaxVoiceRequestsPerHour != nil {
		n := *doc.MaxVoiceRequestsPerHour
		if n <= 0 || n > maxVoiceRequestsPerHour {
			return fmt.Errorf("managed.max_voice_requests_per_hour must be from 1 to %d", maxVoiceRequestsPerHour)
		}
		perHour = int64(n)
		setPerHour = true
	}
	if !trusted {
		p.Warnings = append(p.Warnings, "voice ceilings in [managed] are ignored; only managed policy can set them")
		return nil
	}
	if setAudio {
		p.MaxVoiceAudio = int(audio)
	}
	if setBody {
		p.MaxVoiceBody = body
	}
	if setPerHour {
		p.MaxVoicePerHour = int(perHour)
	}
	return nil
}

func (p *Policy) warnVoiceCeilings() {
	if p.localVoiceAudioSet && !p.managedVoiceAudioSet && p.MaxVoiceAudio > 0 && p.localVoiceAudio > int64(p.MaxVoiceAudio) {
		p.Warnings = append(p.Warnings, fmt.Sprintf("voice.max_audio_seconds %d lowered to managed max_voice_audio_seconds %d", p.localVoiceAudio, p.MaxVoiceAudio))
	}
	if p.localVoiceBodySet && !p.managedVoiceBodySet && p.MaxVoiceBody > 0 && p.localVoiceBody > p.MaxVoiceBody {
		p.Warnings = append(p.Warnings, fmt.Sprintf("voice.max_body_bytes %d lowered to managed max_voice_body_bytes %d", p.localVoiceBody, p.MaxVoiceBody))
	}
	if p.localVoicePerHourSet && !p.managedVoicePerHourSet && p.MaxVoicePerHour > 0 && p.localVoicePerHour > p.MaxVoicePerHour {
		p.Warnings = append(p.Warnings, fmt.Sprintf("voice.max_requests_per_hour %d lowered to managed max_voice_requests_per_hour %d", p.localVoicePerHour, p.MaxVoicePerHour))
	}
}

// EffectiveVoiceMaxAudio is max_audio_seconds, or the default, then the managed ceiling.
func (p Policy) EffectiveVoiceMaxAudio() int {
	n := DefaultVoiceMaxAudioSeconds
	if p.VoiceMaxAudioSet {
		n = p.VoiceMaxAudio
	}
	if p.MaxVoiceAudio > 0 && n > p.MaxVoiceAudio {
		n = p.MaxVoiceAudio
	}
	return n
}

// EffectiveVoiceMaxBody is max_body_bytes, or the default, then the managed ceiling.
func (p Policy) EffectiveVoiceMaxBody() int64 {
	n := DefaultVoiceMaxBodyBytes
	if p.VoiceMaxBodySet {
		n = p.VoiceMaxBody
	}
	if p.MaxVoiceBody > 0 && n > p.MaxVoiceBody {
		n = p.MaxVoiceBody
	}
	return n
}

// EffectiveVoiceMaxPerHour is max_requests_per_hour, or the default, then the managed ceiling.
func (p Policy) EffectiveVoiceMaxPerHour() int {
	n := DefaultVoiceRequestsPerHour
	if p.VoiceMaxPerHourSet {
		n = p.VoiceMaxPerHour
	}
	if p.MaxVoicePerHour > 0 && n > p.MaxVoicePerHour {
		n = p.MaxVoicePerHour
	}
	return n
}

// RequireLoopbackAddr accepts host:port where the host is 127.0.0.1 or ::1.
// An IPv4-mapped IPv6 address is read as its IPv4 form. The port is a number
// from 0 through 65535. Other addresses, including the rest of 127.0.0.0/8,
// localhost, and wildcards, are rejected.
func RequireLoopbackAddr(addr string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("perm_callback_addr %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("perm_callback_addr %q: port must be from 0 through 65535", addr)
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return fmt.Errorf("perm_callback_addr %q: port must be from 0 through 65535", addr)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("perm_callback_addr %q: port must be from 0 through 65535", addr)
	}
	if !loopbackHost(host) {
		return fmt.Errorf("perm_callback_addr %q must be 127.0.0.1 or ::1", addr)
	}
	return nil
}

// loopbackHost reports whether host is 127.0.0.1 or ::1.
// IPv4-mapped IPv6 forms are normalized first.
func loopbackHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.IPv6loopback)
}
