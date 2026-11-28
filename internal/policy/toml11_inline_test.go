package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// policyDenySnap is the stable field set compared with the f3ed31c decoder.
type policyDenySnap struct {
	Loaded       bool     `json:"Loaded"`
	CLIPermitted bool     `json:"CLIPermitted"`
	DaemonJail   bool     `json:"DaemonJail"`
	Bind         string   `json:"Bind"`
	HasBind      bool     `json:"HasBind"`
	Backend      string   `json:"Backend"`
	Allow        []string `json:"Allow"`
	ToolAllow    []string `json:"ToolAllow"`
	ToolDeny     []string `json:"ToolDeny"`
	GoProxy      string   `json:"GoProxy"`
	GoToolchain  string   `json:"GoToolchain"`
	AllowedHosts []string `json:"AllowedHosts"`
}

func snapPolicy(p Policy) policyDenySnap {
	return policyDenySnap{
		Loaded:       p.Loaded,
		CLIPermitted: p.CLIPermitted,
		DaemonJail:   p.DaemonJail,
		Bind:         p.Bind,
		HasBind:      p.HasBind,
		Backend:      p.Backend,
		Allow:        p.Allow,
		ToolAllow:    p.ToolAllow,
		ToolDeny:     p.ToolDeny,
		GoProxy:      p.GoProxy,
		GoToolchain:  p.GoToolchain,
		AllowedHosts: p.AllowedHosts,
	}
}

func marshalSnap(p Policy) ([]byte, error) {
	b, err := json.MarshalIndent(snapPolicy(p), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func assertUnparseableFailClosed(t *testing.T, body string) {
	t.Helper()
	path := writePolicyFile(t, "policy.toml", body)
	p, err := Load(Options{Path: path})
	text := strings.Join(p.Warnings, "\n")
	if err != nil {
		text += "\n" + err.Error()
	}
	if p.Loaded || p.CLIPermitted || !p.DaemonJail || p.Bind == "127.0.0.1:9" || !strings.Contains(text, "unparseable") {
		t.Fatalf("loaded=%v cli=%v jail=%v bind=%q err=%v warnings=%q", p.Loaded, p.CLIPermitted, p.DaemonJail, p.Bind, err, p.Warnings)
	}
}

func TestTOML11InlineTableFailClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"trailing-comma-inline", "daemon = { bind = \"127.0.0.1:9\", }\n"},
		{"inline-newline", "daemon = {\nbind = \"127.0.0.1:9\"\n}\n"},
		{"inline-newline-comma", "daemon = {\nbind = \"127.0.0.1:9\",\n}\n"},
		{"inline-comment-nl", "daemon = {\n  # c\n  bind = \"127.0.0.1:9\",\n}\n"},
		{"spaced-trailing-comma", "daemon = { bind = \"127.0.0.1:9\" , }\n"},
		{"newline-before-close", "daemon = { bind = \"127.0.0.1:9\"\n}\n"},
		{"nested-inline-trailing-comma", "[ollama]\nmodel_options = { llama3 = { num_ctx = 1024, } }\n"},
		{"inline-in-array-trailing-comma", "[cli]\npins = [{ backend = \"ollama\", path = \"/bin/ollama\", }]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertUnparseableFailClosed(t, tc.body)
		})
	}
}

func TestParseErrorWarningContainsUnparseable(t *testing.T) {
	t.Run("classic-typo", func(t *testing.T) {
		assertUnparseableFailClosed(t, "[daemon\nbind = oops\n")
	})
	t.Run("inline-newline", func(t *testing.T) {
		assertUnparseableFailClosed(t, "daemon = {\nbind = \"127.0.0.1:9\"\n}\n")
	})
}

func TestTOML10PolicySyntaxStillLoads(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		check func(t *testing.T, p Policy)
	}{
		{
			name: "inline-single-line",
			body: "daemon = { bind = \"127.0.0.1:9\" }\n",
			check: func(t *testing.T, p Policy) {
				if !p.HasBind || p.Bind != "127.0.0.1:9" {
					t.Fatalf("bind %#v set %v", p.Bind, p.HasBind)
				}
			},
		},
		{
			name: "table-comments-newlines",
			body: "[daemon]\n# comment { not, a table }\n\nbind = \"127.0.0.1:9\"\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "127.0.0.1:9" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "array-trailing-comma",
			body: "[backend]\nallow = [\"ollama\",]\n",
			check: func(t *testing.T, p Policy) {
				if strings.Join(p.Allow, ",") != "ollama" {
					t.Fatalf("allow %#v", p.Allow)
				}
			},
		},
		{
			name: "separator-comma-inline",
			body: "sandbox = { goproxy = \"off\", gotoolchain = \"local\" }\n",
			check: func(t *testing.T, p Policy) {
				if p.GoProxy != "off" || p.GoToolchain != "local" {
					t.Fatalf("go env proxy=%q tool=%q", p.GoProxy, p.GoToolchain)
				}
			},
		},
		{
			name: "braces-comma-in-string",
			body: "[daemon]\nbind = \"{not, an inline}\"\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "{not, an inline}" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "braces-comma-in-comment",
			body: "# daemon = { bind = \"127.0.0.1:9\", }\n[daemon]\nbind = \"127.0.0.1:8\"\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "127.0.0.1:8" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "hash-inside-string-inline",
			body: "daemon = { bind = \"a#b\" }\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "a#b" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "literal-string-braces",
			body: "daemon = { bind = '{a, b}' }\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "{a, b}" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "escaped-quote-in-inline",
			body: "daemon = { bind = \"say \\\"{hi}\\\"\" }\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "say \"{hi}\"" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "comment-after-inline",
			body: "daemon = { bind = \"127.0.0.1:9\" } # { leftover, }\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "127.0.0.1:9" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "multiline-string-in-inline",
			body: "daemon = { bind = \"\"\"\n127.0.0.1:9\n\"\"\" }\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "127.0.0.1:9" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "newline-inside-array-in-inline",
			body: "daemon = { allowed_hosts = [\"voice.example\",\n\"::1\"] }\n",
			check: func(t *testing.T, p Policy) {
				if strings.Join(p.AllowedHosts, ",") != "voice.example,::1" {
					t.Fatalf("hosts %#v", p.AllowedHosts)
				}
			},
		},
		{
			name: "comment-inside-array-in-inline",
			body: "daemon = { allowed_hosts = [\"voice.example\", # voice\n\"::1\"] }\n",
			check: func(t *testing.T, p Policy) {
				if strings.Join(p.AllowedHosts, ",") != "voice.example,::1" {
					t.Fatalf("hosts %#v", p.AllowedHosts)
				}
			},
		},
		{
			name: "array-of-inline-with-newline",
			body: "[cli]\npins = [\n{ backend = \"ollama\", path = \"/bin/ollama\" },\n]\n",
			check: func(t *testing.T, p Policy) {
				if len(p.Pins) != 1 || p.Pins[0].Path != "/bin/ollama" || p.Pins[0].Backend != "ollama" {
					t.Fatalf("pins %#v", p.Pins)
				}
			},
		},
		{
			name: "multiline-basic-with-braces",
			body: "[daemon]\nbind = \"\"\"\n{ bind = \"x\", }\n\"\"\"\n",
			check: func(t *testing.T, p Policy) {
				if !strings.Contains(p.Bind, "{ bind") {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "literal-multiline-with-braces",
			body: "[daemon]\nbind = '''\n{a, b}\n'''\n",
			check: func(t *testing.T, p Policy) {
				if !strings.Contains(p.Bind, "{a, b}") {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "multiline-ends-with-quote",
			body: "[daemon]\nbind = \"\"\"foo\"\"\"\"\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "foo\"" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "crlf-table",
			body: "[daemon]\r\n# {a,}\r\nbind = \"127.0.0.1:9\"\r\n",
			check: func(t *testing.T, p Policy) {
				if p.Bind != "127.0.0.1:9" {
					t.Fatalf("bind %#v", p.Bind)
				}
			},
		},
		{
			name: "nested-inline-without-trailing-comma",
			body: "[ollama]\nmodel_options = { llama3 = { num_ctx = 1024 } }\n",
			check: func(t *testing.T, p Policy) {
				opt, ok := p.OllamaModelOptions["llama3"]
				if !ok || opt.NumCtx != 1024 {
					t.Fatalf("models %#v", p.OllamaModelOptions)
				}
			},
		},
		{
			name: "braces-in-github-email",
			body: "[github]\nauthor_email = \"{name}@users.noreply\"\nrepos = [\"acme/widgets\"]\n",
			check: func(t *testing.T, p Policy) {
				if p.GitHub.AuthorEmail != "{name}@users.noreply" {
					t.Fatalf("email %#v", p.GitHub.AuthorEmail)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writePolicyFile(t, "policy.toml", tc.body)
			p, err := Load(Options{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			if !p.Loaded || !p.CLIPermitted || !p.DaemonJail {
				t.Fatalf("loaded=%v cli=%v jail=%v warnings=%q", p.Loaded, p.CLIPermitted, p.DaemonJail, p.Warnings)
			}
			tc.check(t, p)
		})
	}
}

func TestJSONPolicyNotSubjectToInlineTableRule(t *testing.T) {
	const body = `{
  "daemon": { "bind": "127.0.0.1:9" },
  "backend": { "allow": ["ollama", "claude"] }
}
`
	path := writePolicyFile(t, "policy.json", body)
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Loaded || !p.CLIPermitted || !p.DaemonJail || p.Bind != "127.0.0.1:9" {
		t.Fatalf("loaded=%v cli=%v jail=%v bind=%q warnings=%q", p.Loaded, p.CLIPermitted, p.DaemonJail, p.Bind, p.Warnings)
	}
	if strings.Join(p.Allow, ",") != "ollama,claude" {
		t.Fatalf("allow %#v", p.Allow)
	}
}

func TestPolicyDenySetGolden(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "deny_set.toml"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "deny_set.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := writePolicyFile(t, "policy.toml", string(body))
	p, err := Load(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalSnap(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("deny set mismatch\n got: %s\nwant: %s", got, want)
	}
	var decoded policyDenySnap
	if err := json.Unmarshal(want, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, snapPolicy(p)) {
		t.Fatalf("snap %#v decoded %#v", snapPolicy(p), decoded)
	}
}
