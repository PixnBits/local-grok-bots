package policy

import (
	"fmt"
	"os"
	"strings"
)

// applyFile overlays keys that are present in a small YAML subset.
// Each key is one line. Lists are inline. Unknown keys fail closed.
func applyFile(p *Policy, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy file: %w", err)
	}
	if len(b) > 64*1024 {
		return fmt.Errorf("policy file is too large")
	}
	text := strings.TrimPrefix(string(b), "\uFEFF")
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = stripComment(line)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("policy file line %d is invalid", i+1)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" || seen[key] {
			return fmt.Errorf("policy file line %d is invalid", i+1)
		}
		seen[key] = true
		if err := applyKey(p, key, val); err != nil {
			return fmt.Errorf("policy file %s: %w", key, err)
		}
	}
	return nil
}

func applyKey(p *Policy, key, val string) error {
	switch key {
	case "allow_cli_backends":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		p.AllowCLIBackends = normBackends(list)
	case "cli_network":
		p.CLINetwork = strings.ToLower(unquote(val))
	case "cli_net_allow":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		p.CLINetAllow = normHosts(list)
	case "env_allowlist":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		p.EnvAllowlist = list
	case "default_net_allow":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		p.DefaultNetAllow = normHosts(list)
	case "force_local_only":
		on, err := parseBool(unquote(val))
		if err != nil {
			return err
		}
		p.ForceLocalOnly = on
	case "build_binds":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		p.BuildBinds = list
	case "cli_ro_binds":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		binds, err := parseCLIROList(list, true)
		if err != nil {
			return err
		}
		p.CLIROBinds = binds
	case "rlimit_nofile":
		n, err := parseRlimit(val)
		if err != nil {
			return err
		}
		p.RlimitNofile = n
	case "rlimit_nproc":
		n, err := parseRlimit(val)
		if err != nil {
			return err
		}
		p.RlimitNproc = n
	case "rlimit_cpu_seconds":
		n, err := parseRlimit(val)
		if err != nil {
			return err
		}
		p.RlimitCPU = n
	case "turn_timeout":
		d, err := parseTurnTimeout(val)
		if err != nil {
			return err
		}
		p.TurnTimeout = d
	case "workspace_readonly":
		on, err := parseBool(unquote(val))
		if err != nil {
			return err
		}
		p.WorkspaceReadonly = on
	case "http_proxy":
		p.HTTPProxy = unquote(val)
	case "https_proxy":
		p.HTTPSProxy = unquote(val)
	case "no_proxy":
		p.NoProxy = unquote(val)
	case "audit_log":
		p.AuditLog = unquote(val)
	case "dlp_patterns":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		p.DLPPatterns = list
	case "dlp_file":
		p.DLPFile = unquote(val)
	case "dlp_command":
		p.DLPCommand = unquote(val)
	case "dlp_scan_tools":
		on, err := parseBool(unquote(val))
		if err != nil {
			return err
		}
		p.DLPScanTools = on
	case "cli_pins":
		list, err := parseList(val)
		if err != nil {
			return err
		}
		pins := make([]CLIPin, 0, len(list))
		for _, item := range list {
			pin, err := parsePin(item)
			if err != nil {
				return err
			}
			pins = append(pins, pin)
		}
		p.CLIPins = pins
	default:
		return fmt.Errorf("unknown key")
	}
	return nil
}

func parseList(val string) ([]string, error) {
	if !strings.HasPrefix(val, "[") || !strings.HasSuffix(val, "]") {
		return nil, fmt.Errorf("expected a list")
	}
	inner := strings.TrimSpace(val[1 : len(val)-1])
	if inner == "" {
		return []string{}, nil
	}
	var out []string
	for _, part := range strings.Split(inner, ",") {
		part = unquote(strings.TrimSpace(part))
		if part == "" {
			return nil, fmt.Errorf("empty list item")
		}
		out = append(out, part)
	}
	return out, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func stripComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}
