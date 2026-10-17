package permission

import (
	"fmt"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
)

// Sample is one logged permission request.
type Sample struct {
	Tool string
	Args map[string]any
}

// Card is a suggested durable rule. Refused cards are shown and cannot be
// accepted until the pattern is edited into a low-risk allow.
type Card struct {
	Pattern  string
	Effect   string
	Class    Class
	Count    int
	Examples []string
	Summary  string
	Refused  bool
}

type cluster struct {
	id       string
	tool     string
	count    int
	extra    bool
	mixed    bool
	examples []string
	paths    []string
}

// Suggest clusters historical permission requests into candidate rules.
// A cluster that mixes a read with a write, a redirect, or a sensitive path
// is returned as a refused card and is not an allow.
func Suggest(samples []Sample, workspace string) []Card {
	groups := map[string]*cluster{}
	var order []string
	take := func(key string) *cluster {
		c := groups[key]
		if c == nil {
			c = &cluster{}
			groups[key] = c
			order = append(order, key)
		}
		return c
	}
	for _, s := range samples {
		text := strings.TrimSpace(argText(s.Args))
		class := ClassifyCall(s.Tool, s.Args, workspace)
		if strings.EqualFold(strings.TrimSpace(s.Tool), "Bash") {
			id := bashGroupID(text)
			if id == "" {
				continue
			}
			c := take("bash\x00" + id)
			c.id = id
			c.tool = "Bash"
			c.count++
			if !class.AutoAllow || shellComposed(text) {
				c.mixed = true
			}
			if len(splitCmd(stripMeta(text))) > len(splitCmd(id)) {
				c.extra = true
			}
			c.examples = addExample(c.examples, text)
			continue
		}
		if !isReadTool(s.Tool) {
			continue
		}
		if text == "" {
			continue
		}
		dir := pathGroup(text)
		c := take("read\x00" + strings.ToLower(s.Tool) + "\x00" + dir)
		c.id = dir
		c.tool = canonicalRead(s.Tool)
		c.count++
		if !class.AutoAllow {
			c.mixed = true
		}
		c.paths = append(c.paths, text)
		c.examples = addExample(c.examples, text)
	}
	var out []Card
	for _, key := range order {
		c := groups[key]
		out = append(out, cardFor(c, workspace))
	}
	return out
}

func cardFor(c *cluster, workspace string) Card {
	pattern := suggestedPattern(c)
	if c.mixed {
		return Card{
			Pattern: pattern, Effect: "allow",
			Class: Class{
				Kind: "mixed", Sensitivity: "unknown", Risk: "high",
				Reason: "classification refused auto-allow",
			},
			Count: c.count, Examples: c.examples, Refused: true,
			Summary: fmt.Sprintf("%d prior requests look like %s but at least one is a write, a redirect, or a sensitive path. Classification refused auto-allow.", c.count, pattern),
		}
	}
	class, err := CheckUserRule("allow", pattern, workspace)
	if err != nil {
		reason := err.Error()
		return Card{
			Pattern: pattern, Effect: "allow",
			Class: Class{Kind: "unknown", Sensitivity: "unknown", Risk: "high", Reason: reason},
			Count: c.count, Examples: c.examples, Refused: true,
			Summary: fmt.Sprintf("%d prior requests match %s. %s", c.count, pattern, reason),
		}
	}
	return Card{
		Pattern: pattern, Effect: "allow", Class: class,
		Count: c.count, Examples: c.examples,
		Summary: fmt.Sprintf("%d prior %s requests, all classified %s / %s. Suggest permanent allow? Risk: %s (%s).",
			c.count, pattern, class.Kind, class.Sensitivity, class.Risk, class.Reason),
	}
}

func suggestedPattern(c *cluster) string {
	if strings.EqualFold(c.tool, "Bash") {
		if c.extra {
			return "Bash(" + c.id + " *)"
		}
		return "Bash(" + c.id + ")"
	}
	glob := c.id
	if !strings.HasSuffix(glob, "*") {
		if strings.HasSuffix(glob, "/") {
			glob += "**"
		} else {
			glob += "/**"
		}
	}
	return c.tool + "(" + glob + ")"
}

func bashGroupID(cmd string) string {
	plain := stripMeta(cmd)
	if id, ok := readOnlyIdentity(plain); ok {
		return id
	}
	return ""
}

func stripMeta(s string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			b.WriteByte(c)
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			}
			if c == '$' || c == '`' || c == '\n' || c == '\r' {
				break
			}
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if strings.ContainsRune(";|&<>`$\n\r", rune(c)) {
			break
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

func isReadTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "read", "grep", "glob", "ls":
		return true
	default:
		return false
	}
}

func canonicalRead(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "grep":
		return "Grep"
	case "glob":
		return "Glob"
	case "ls":
		return "LS"
	default:
		return "Read"
	}
}

func pathGroup(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[:i+1]
	}
	return "./"
}

func addExample(have []string, cmd string) []string {
	ex := audit.RedactText(strings.TrimSpace(cmd))
	if len(ex) > 180 {
		ex = ex[:180]
	}
	for _, e := range have {
		if e == ex {
			return have
		}
	}
	if len(have) >= 3 {
		return have
	}
	return append(have, ex)
}
