package sandbox

import "testing"

func TestSpliceRefusesGitHubEvenWhenAllowlisted(t *testing.T) {
	p := &proxy{
		grants:   setOf([]string{"net", "github"}),
		netAllow: setOf([]string{"github.com", "api.github.com", "allowed.test"}),
	}
	for _, host := range []string{"github.com", "api.github.com", "GitHub.com.", "API.github.com"} {
		ok, ev := p.decide(host, 443)
		if ok {
			t.Fatalf("allowed %s", host)
		}
		if ev.Kind != "grant_denied" || ev.Grant != "github" || ev.Host == "" {
			t.Fatalf("%s event %#v", host, ev)
		}
	}
	ok, ev := p.decide("allowed.test", 80)
	if !ok || ev.Kind != "grant_use" {
		t.Fatalf("other host %#v %v", ev, ok)
	}
}

func TestGitWrapRefusesUnsafeAuthor(t *testing.T) {
	const bad = "Ada$(touch /tmp/pwn)"
	script := gitWrap(gitWrapOpts{Grant: true, Name: bad, Email: "bot@localhost"})
	if containsAny(script, bad, "touch", "/tmp/pwn") {
		t.Fatalf("unsafe author embedded:\n%s", script)
	}
	if !containsAny(script, "invalid author") {
		t.Fatalf("script did not refuse:\n%s", script)
	}
}

func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if p != "" && len(s) >= len(p) && (s == p || len(p) > 0 && contains(s, p)) {
			return true
		}
	}
	return false
}

func contains(s, part string) bool {
	return len(part) > 0 && len(s) >= len(part) && (func() bool {
		for i := 0; i+len(part) <= len(s); i++ {
			if s[i:i+len(part)] == part {
				return true
			}
		}
		return false
	})()
}
