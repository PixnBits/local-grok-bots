package policy

import (
	"strings"
	"testing"
)

func TestVoiceDefaultsAndCeilings(t *testing.T) {
	p := Defaults()
	if p.VoiceEnabled || p.EffectiveVoiceMaxAudio() != DefaultVoiceMaxAudioSeconds ||
		p.EffectiveVoiceMaxBody() != DefaultVoiceMaxBodyBytes ||
		p.EffectiveVoiceMaxPerHour() != DefaultVoiceRequestsPerHour {
		t.Fatalf("defaults enabled %v audio %d body %d rate %d", p.VoiceEnabled, p.EffectiveVoiceMaxAudio(), p.EffectiveVoiceMaxBody(), p.EffectiveVoiceMaxPerHour())
	}

	local := writePol(t, "local.toml", `
[voice]
enabled = true
bin = "/opt/whisper/whisper-cli"
model = "/opt/whisper/model.bin"
max_audio_seconds = 600
max_body_bytes = 8000000
max_requests_per_hour = 100
`)
	managed := writePol(t, "managed.toml", `
[voice]
enabled = false
bin = "/managed/whisper-cli"
model = "/managed/model.bin"

[managed]
max_voice_audio_seconds = 30
max_voice_body_bytes = 100000
max_voice_requests_per_hour = 4
`)
	p, err := Load(Options{Path: local, ManagedPath: managed})
	if err != nil {
		t.Fatal(err)
	}
	if p.VoiceEnabled {
		t.Fatal("managed enabled=false did not win")
	}
	if p.WhisperBin != "/managed/whisper-cli" || p.WhisperModel != "/managed/model.bin" {
		t.Fatalf("whisper %#v %#v", p.WhisperBin, p.WhisperModel)
	}
	if p.EffectiveVoiceMaxAudio() != 30 || p.EffectiveVoiceMaxBody() != 100000 || p.EffectiveVoiceMaxPerHour() != 4 {
		t.Fatalf("ceilings audio %d body %d rate %d", p.EffectiveVoiceMaxAudio(), p.EffectiveVoiceMaxBody(), p.EffectiveVoiceMaxPerHour())
	}
	warn := strings.Join(p.Warnings, "\n")
	for _, needle := range []string{
		"voice.max_audio_seconds 600 lowered to managed max_voice_audio_seconds 30",
		"voice.max_body_bytes 8000000 lowered to managed max_voice_body_bytes 100000",
		"voice.max_requests_per_hour 100 lowered to managed max_voice_requests_per_hour 4",
	} {
		if !strings.Contains(warn, needle) {
			t.Fatalf("missing %q in %s", needle, warn)
		}
	}

	under := writePol(t, "under.toml", `
[voice]
enabled = true
max_audio_seconds = 10
max_body_bytes = 1000
max_requests_per_hour = 2
`)
	capOK := writePol(t, "cap.toml", `
[managed]
max_voice_audio_seconds = 30
max_voice_body_bytes = 5000
max_voice_requests_per_hour = 4
`)
	p, err = Load(Options{Path: under, ManagedPath: capOK})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveVoiceMaxAudio() != 10 || p.EffectiveVoiceMaxBody() != 1000 || p.EffectiveVoiceMaxPerHour() != 2 {
		t.Fatalf("under ceiling audio %d body %d rate %d", p.EffectiveVoiceMaxAudio(), p.EffectiveVoiceMaxBody(), p.EffectiveVoiceMaxPerHour())
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "lowered") {
			t.Fatalf("unexpected clamp warning %s", w)
		}
	}
}

func TestLocalVoiceCeilingIgnored(t *testing.T) {
	path := writePol(t, "local.toml", `
[voice]
enabled = true
max_audio_seconds = 100

[managed]
max_voice_audio_seconds = 5
max_voice_body_bytes = 10
max_voice_requests_per_hour = 1
`)
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if !p.CLIPermitted || p.MaxVoiceAudio != 0 || p.EffectiveVoiceMaxAudio() != 100 {
		t.Fatalf("local ceiling applied: max %d effective %d permitted %v", p.MaxVoiceAudio, p.EffectiveVoiceMaxAudio(), p.CLIPermitted)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "only managed policy can set them") {
		t.Fatalf("warnings %v", p.Warnings)
	}
}

func TestVoicePolicyFailClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown key", "[voice]\nnope = true\n"},
		{"wrong type", "[voice]\nenabled = \"yes\"\n"},
		{"zero audio", "[voice]\nmax_audio_seconds = 0\n"},
		{"negative audio", "[voice]\nmax_audio_seconds = -1\n"},
		{"audio above hard max", "[voice]\nmax_audio_seconds = 999999\n"},
		{"zero body", "[voice]\nmax_body_bytes = 0\n"},
		{"negative body", "[voice]\nmax_body_bytes = -5\n"},
		{"body above hard max", "[voice]\nmax_body_bytes = 999999999\n"},
		{"zero rate", "[voice]\nmax_requests_per_hour = 0\n"},
		{"negative rate", "[voice]\nmax_requests_per_hour = -2\n"},
		{"rate wrong type", "[voice]\nmax_requests_per_hour = \"many\"\n"},
		{"half whisper", "[voice]\nbin = \"/opt/whisper\"\n"},
		{"relative whisper", "[voice]\nbin = \"whisper\"\nmodel = \"model\"\n"},
		{"tls half", "[daemon]\ntls_cert = \"/tmp/cert.pem\"\n"},
		{"tls both modes", "[daemon]\ntls_self_signed = true\ntls_cert = \"/tmp/cert.pem\"\ntls_key = \"/tmp/key.pem\"\n"},
		{"relative tls", "[daemon]\ntls_cert = \"cert.pem\"\ntls_key = \"key.pem\"\n"},
		{"callback wildcard", "[daemon]\nperm_callback_addr = \"0.0.0.0:9\"\n"},
		{"callback localhost", "[daemon]\nperm_callback_addr = \"localhost:9\"\n"},
		{"managed ceiling zero", "[managed]\nmax_voice_audio_seconds = 0\n"},
		{"managed ceiling negative", "[managed]\nmax_voice_requests_per_hour = -1\n"},
		{"managed ceiling too high", "[managed]\nmax_voice_body_bytes = 999999999\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Load(Options{Path: writePol(t, "bad.toml", tc.body)})
			if err != nil {
				t.Fatal(err)
			}
			if p.CLIPermitted || p.Loaded {
				t.Fatalf("not fail-closed permitted %v loaded %v warnings %v", p.CLIPermitted, p.Loaded, p.Warnings)
			}
			if !strings.Contains(strings.Join(p.Warnings, "\n"), "unparseable") {
				t.Fatalf("warnings %v", p.Warnings)
			}
		})
	}
}

func TestPolicyOverridesEnvTLSAndVoice(t *testing.T) {
	path := writePol(t, "policy.toml", `
[daemon]
tls_self_signed = false
perm_callback_addr = "127.0.0.1:0"

[voice]
enabled = true
bin = "/policy/whisper-cli"
model = "/policy/model.bin"
max_audio_seconds = 12
max_body_bytes = 4096
max_requests_per_hour = 3
`)
	p, err := Load(Options{
		Path:             path,
		EnvTLSCert:       "/env/cert.pem",
		EnvTLSKey:        "/env/key.pem",
		EnvTLSSelfSigned: "1",
		EnvWhisperBin:    "/env/whisper",
		EnvWhisperModel:  "/env/model",
		EnvPermCallback:  "127.0.0.1:9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasTLS || p.TLSSelfSigned || p.TLSCert != "" || p.TLSKey != "" {
		t.Fatalf("tls %#v self %v", p.TLSCert, p.TLSSelfSigned)
	}
	if p.WhisperBin != "/policy/whisper-cli" || p.WhisperModel != "/policy/model.bin" {
		t.Fatalf("whisper %s %s", p.WhisperBin, p.WhisperModel)
	}
	if p.PermCallbackAddr != "127.0.0.1:0" || !p.VoiceEnabled || p.EffectiveVoiceMaxAudio() != 12 {
		t.Fatalf("callback %s enabled %v audio %d", p.PermCallbackAddr, p.VoiceEnabled, p.EffectiveVoiceMaxAudio())
	}
	warn := strings.Join(p.Warnings, "\n")
	for _, needle := range []string{"TLS_CERT", "WHISPER_BIN", "PERM_CALLBACK_ADDR"} {
		if !strings.Contains(warn, needle) {
			t.Fatalf("warning missing %s: %s", needle, warn)
		}
	}
}

func TestManagedTLSAndVoiceConflictRefuses(t *testing.T) {
	local := writePol(t, "local.toml", "[backend]\nbackend = \"ollama\"\n")
	managed := writePol(t, "managed.toml", `
[daemon]
tls_cert = "/managed/cert.pem"
tls_key = "/managed/key.pem"

[voice]
bin = "/managed/whisper-cli"
model = "/managed/model.bin"
`)
	_, err := Load(Options{
		Path:             local,
		ManagedPath:      managed,
		EnvTLSCert:       "/env/cert.pem",
		EnvTLSKey:        "/env/key.pem",
		EnvTLSSelfSigned: "1",
		EnvWhisperBin:    "/env/whisper",
		EnvWhisperModel:  "/env/model",
	})
	if err == nil || !strings.Contains(err.Error(), "TLS_CERT") || !strings.Contains(err.Error(), "WHISPER_BIN") || !strings.Contains(err.Error(), "TLS_SELF_SIGNED") {
		t.Fatalf("err %v", err)
	}
}

func TestRequireLoopbackAddr(t *testing.T) {
	ok := []string{"127.0.0.1:0", "127.0.0.1:8787", "[::1]:0", "[::1]:9"}
	for _, addr := range ok {
		if err := RequireLoopbackAddr(addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	bad := []string{"0.0.0.0:0", "192.168.1.2:9", "localhost:0", ":0", "[::]:0", "nonsense", "127.0.0.1"}
	for _, addr := range bad {
		if err := RequireLoopbackAddr(addr); err == nil {
			t.Errorf("%s: accepted", addr)
		}
	}
}
