package policy

import (
	"fmt"
	"sort"
	"strings"
)

// GoEnv is the toolchain environment for one shell jail.
// SumDB is always off. Cache directories are not part of policy.
type GoEnv struct {
	Proxy     string
	Toolchain string
	Flags     string
	SumDB     string
}

// EffectiveGoEnv is the toolchain ceiling after managed and local policy.
// Empty values are the defaults: GOPROXY=off, GOTOOLCHAIN=local, no GOFLAGS.
func (p Policy) EffectiveGoEnv() GoEnv {
	proxy := strings.TrimSpace(p.GoProxy)
	if proxy == "" {
		proxy = "off"
	}
	tool := strings.TrimSpace(p.GoToolchain)
	if tool == "" {
		tool = "local"
	}
	sum := strings.TrimSpace(p.GoSumDB)
	if sum == "" {
		sum = "off"
	}
	return GoEnv{Proxy: proxy, Toolchain: tool, Flags: strings.TrimSpace(p.GoFlags), SumDB: sum}
}

// NarrowGoEnv applies a bot overlay. It can only narrow the ceiling.
// A wider proxy, toolchain, or flag set is ignored. SumDB stays off.
func NarrowGoEnv(base GoEnv, proxy, toolchain, flags string, proxySet, toolSet, flagsSet bool) (GoEnv, []string) {
	if strings.TrimSpace(base.Proxy) == "" {
		base.Proxy = "off"
	}
	if strings.TrimSpace(base.Toolchain) == "" {
		base.Toolchain = "local"
	}
	var warns []string
	outProxy, proxyWarn := narrowProxy(base.Proxy, proxy, proxySet)
	if proxyWarn {
		warns = append(warns, "bot goproxy is wider than the policy ceiling; keeping the tighter setting")
	}
	outTool, toolWarn := narrowTool(base.Toolchain, toolchain, toolSet)
	if toolWarn {
		warns = append(warns, "bot gotoolchain is wider than the policy ceiling; keeping the tighter setting")
	}
	outFlags, flagWarn := narrowFlags(base.Flags, flags, flagsSet)
	if flagWarn {
		warns = append(warns, "bot goflags is wider than the policy ceiling; keeping the tighter setting")
	}
	return GoEnv{Proxy: outProxy, Toolchain: outTool, Flags: outFlags, SumDB: "off"}, warns
}

func (p *Policy) applySandbox(doc *sandboxDoc, trusted bool) error {
	if doc == nil {
		return nil
	}
	if doc.GoProxy != nil {
		v := strings.TrimSpace(*doc.GoProxy)
		if strings.ContainsAny(v, "\r\n\x00") || (v != "" && !validProxy(v)) {
			return fmt.Errorf("sandbox.goproxy is invalid")
		}
		if trusted {
			if v == "" {
				return fmt.Errorf("sandbox.goproxy is empty")
			}
			p.goProxyManaged = v
			p.goProxyManagedSet = true
		} else {
			p.goProxyLocal = v
			p.goProxyLocalSet = true
		}
	}
	if doc.GoToolchain != nil {
		v := strings.TrimSpace(*doc.GoToolchain)
		if strings.ContainsAny(v, "\r\n\x00") || (v != "" && !validTool(v)) {
			return fmt.Errorf("sandbox.gotoolchain is invalid")
		}
		if trusted {
			if v == "" {
				return fmt.Errorf("sandbox.gotoolchain is empty")
			}
			p.goToolManaged = v
			p.goToolManagedSet = true
		} else {
			p.goToolLocal = v
			p.goToolLocalSet = true
		}
	}
	if doc.GoFlags != nil {
		v := strings.TrimSpace(*doc.GoFlags)
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("sandbox.goflags is invalid")
		}
		if trusted {
			p.goFlagsManaged = v
			p.goFlagsManagedSet = true
		} else {
			p.goFlagsLocal = v
			p.goFlagsLocalSet = true
		}
	}
	return nil
}

func (p *Policy) finishGoEnv() {
	managedProxy := "off"
	if p.goProxyManagedSet {
		managedProxy = p.goProxyManaged
	}
	proxy, proxyWarn := narrowProxy(managedProxy, p.goProxyLocal, p.goProxyLocalSet)
	if proxyWarn {
		p.Warnings = append(p.Warnings, "local sandbox goproxy is wider than the managed value; keeping the tighter setting")
	}
	managedTool := "local"
	if p.goToolManagedSet {
		managedTool = p.goToolManaged
	}
	tool, toolWarn := narrowTool(managedTool, p.goToolLocal, p.goToolLocalSet)
	if toolWarn {
		p.Warnings = append(p.Warnings, "local sandbox gotoolchain is wider than the managed value; keeping the tighter setting")
	}
	managedFlags := ""
	if p.goFlagsManagedSet {
		managedFlags = p.goFlagsManaged
	}
	flags, flagWarn := narrowFlags(managedFlags, p.goFlagsLocal, p.goFlagsLocalSet)
	if flagWarn {
		p.Warnings = append(p.Warnings, "local sandbox goflags is wider than the managed value; keeping the tighter setting")
	}
	p.GoProxy = proxy
	p.GoToolchain = tool
	p.GoFlags = flags
	p.GoSumDB = "off"
}

func validProxy(s string) bool {
	if s == "off" {
		return true
	}
	if strings.ContainsAny(s, " \t\r\n\x00") {
		return false
	}
	parts := proxyParts(s)
	return len(parts) > 0
}

func validTool(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00") || strings.Contains(s, "..") {
		return false
	}
	return true
}

func narrowProxy(managed, local string, localSet bool) (string, bool) {
	if strings.TrimSpace(managed) == "" {
		managed = "off"
	}
	if !localSet {
		return managed, false
	}
	local = strings.TrimSpace(local)
	if local == "" || strings.ContainsAny(local, " \t\r\n\x00") || !validProxy(local) && local != "" {
		return managed, true
	}
	if local == managed || local == "off" {
		return local, false
	}
	if managed == "off" {
		return managed, true
	}
	have := map[string]struct{}{}
	for _, part := range proxyParts(managed) {
		have[part] = struct{}{}
	}
	localParts := proxyParts(local)
	if len(localParts) == 0 {
		return managed, true
	}
	for _, part := range localParts {
		if _, ok := have[part]; !ok {
			return managed, true
		}
	}
	return local, false
}

func proxyParts(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '|' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func narrowTool(managed, local string, localSet bool) (string, bool) {
	if strings.TrimSpace(managed) == "" {
		managed = "local"
	}
	if !localSet {
		return managed, false
	}
	local = strings.TrimSpace(local)
	if local == "" || !validTool(local) {
		return managed, true
	}
	if local == managed || local == "local" {
		return local, false
	}
	if managed == "local" || managed == "auto" {
		return managed, true
	}
	return managed, true
}

func narrowFlags(managed, local string, localSet bool) (string, bool) {
	if !localSet {
		return managed, false
	}
	if strings.ContainsAny(local, "\r\n\x00") {
		return managed, true
	}
	if flagSetEqual(managed, local) {
		return managed, false
	}
	return managed, true
}

func flagSetEqual(a, b string) bool {
	af := strings.Fields(a)
	bf := strings.Fields(b)
	if len(af) != len(bf) {
		return false
	}
	sort.Strings(af)
	sort.Strings(bf)
	for i := range af {
		if af[i] != bf[i] {
			return false
		}
	}
	return true
}
