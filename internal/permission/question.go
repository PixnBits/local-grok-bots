package permission

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
)

// Answer is a UI decision that fills AskUserQuestion answers.
// Behavior sent back to Claude is still allow.
const Answer = "answer"

// ErrAnswer means the body cannot answer this request. The request stays pending.
var ErrAnswer = errors.New("invalid permission answer")

// interactiveQuestions are tool names that collect an answer instead of an
// allow/deny. The match is case-sensitive. AskUserQuestion is the built-in
// from @anthropic-ai/claude-agent-sdk 0.3.300 sdk-tools.d.ts.
var interactiveQuestions = map[string]struct{}{
	"AskUserQuestion": {},
}

func isInteractiveQuestion(tool string) bool {
	_, ok := interactiveQuestions[tool]
	return ok
}

// Question is one validated AskUserQuestion entry.
type Question struct {
	Text    string
	Header  string
	Multi   bool
	Options []Option
}

// Option is one choice. Preview is set only when the input included it.
type Option struct {
	Label       string
	Description string
	Preview     string
	HasPreview  bool
}

// Note is an optional per-question annotation. Nil pointers were omitted.
type Note struct {
	Preview *string `json:"preview,omitempty"`
	Notes   *string `json:"notes,omitempty"`
}

func parseQuestions(args map[string]any) ([]Question, error) {
	if args == nil {
		return nil, fmt.Errorf("questions is required")
	}
	raw, ok := args["questions"].([]any)
	if !ok || len(raw) < 1 || len(raw) > 4 {
		return nil, fmt.Errorf("questions must be an array of 1 to 4")
	}
	out := make([]Question, 0, len(raw))
	seen := map[string]struct{}{}
	seenRedacted := map[string]struct{}{}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("question must be an object")
		}
		text, ok := m["question"].(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("question text is required")
		}
		header, ok := m["header"].(string)
		if !ok || strings.TrimSpace(header) == "" {
			return nil, fmt.Errorf("question header is required")
		}
		multi, ok := m["multiSelect"].(bool)
		if !ok {
			return nil, fmt.Errorf("multiSelect must be a boolean")
		}
		opts, err := parseOptions(m["options"])
		if err != nil {
			return nil, err
		}
		q := Question{Text: text, Header: header, Multi: multi, Options: opts}
		if _, dup := seen[text]; dup {
			return nil, fmt.Errorf("duplicate question")
		}
		seen[text] = struct{}{}
		red := redactStr(text)
		if _, dup := seenRedacted[red]; dup {
			return nil, fmt.Errorf("duplicate question")
		}
		seenRedacted[red] = struct{}{}
		out = append(out, q)
	}
	return out, nil
}

func parseOptions(raw any) ([]Option, error) {
	items, ok := raw.([]any)
	if !ok || len(items) < 2 || len(items) > 4 {
		return nil, fmt.Errorf("options must be an array of 2 to 4")
	}
	out := make([]Option, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("option must be an object")
		}
		label, ok := m["label"].(string)
		if !ok || strings.TrimSpace(label) == "" {
			return nil, fmt.Errorf("option label is required")
		}
		desc, ok := m["description"].(string)
		if !ok || strings.TrimSpace(desc) == "" {
			return nil, fmt.Errorf("option description is required")
		}
		opt := Option{Label: label, Description: desc}
		if preview, exists := m["preview"]; exists {
			s, ok := preview.(string)
			if !ok {
				return nil, fmt.Errorf("option preview must be a string")
			}
			opt.Preview = s
			opt.HasPreview = true
		}
		out = append(out, opt)
	}
	return out, nil
}

func (q Question) public() map[string]any {
	opts := make([]any, len(q.Options))
	for i, o := range q.Options {
		m := map[string]any{
			"label":       redactStr(o.Label),
			"description": redactStr(o.Description),
		}
		if o.HasPreview {
			m["preview"] = redactStr(o.Preview)
		}
		opts[i] = m
	}
	return map[string]any{
		"question":    redactStr(q.Text),
		"header":      redactStr(q.Header),
		"options":     opts,
		"multiSelect": q.Multi,
	}
}

func publicQuestions(qs []Question) []any {
	out := make([]any, len(qs))
	for i, q := range qs {
		out[i] = q.public()
	}
	return out
}

// validateAnswers checks keys and values and returns answers keyed by the
// original question text. notes is nil when the caller sent none.
func validateAnswers(qs []Question, answers map[string]string, notes map[string]Note) (map[string]string, map[string]map[string]any, error) {
	if len(answers) == 0 {
		return nil, nil, fmt.Errorf("%w: answers are required", ErrAnswer)
	}
	if len(answers) != len(qs) {
		return nil, nil, fmt.Errorf("%w: answer each question", ErrAnswer)
	}
	canon := make(map[string]string, len(qs))
	used := make([]bool, len(qs))
	for key, value := range answers {
		idx := questionIndex(qs, key)
		if idx < 0 {
			return nil, nil, fmt.Errorf("%w: unknown question", ErrAnswer)
		}
		if used[idx] {
			return nil, nil, fmt.Errorf("%w: duplicate question", ErrAnswer)
		}
		used[idx] = true
		got, err := canonicalValue(qs[idx], value)
		if err != nil {
			return nil, nil, err
		}
		canon[qs[idx].Text] = got
	}
	if notes == nil {
		return canon, nil, nil
	}
	ann := make(map[string]map[string]any, len(notes))
	for key, note := range notes {
		idx := questionIndex(qs, key)
		if idx < 0 {
			return nil, nil, fmt.Errorf("%w: unknown annotation", ErrAnswer)
		}
		m := map[string]any{}
		if note.Preview != nil {
			m["preview"] = *note.Preview
		}
		if note.Notes != nil {
			m["notes"] = *note.Notes
		}
		ann[qs[idx].Text] = m
	}
	return canon, ann, nil
}

func questionIndex(qs []Question, key string) int {
	for i, q := range qs {
		if key == q.Text {
			return i
		}
	}
	red := map[string]int{}
	for i, q := range qs {
		k := redactStr(q.Text)
		if _, dup := red[k]; dup {
			continue
		}
		red[k] = i
	}
	if i, ok := red[key]; ok && key != "" {
		return i
	}
	return -1
}

// maxFreeAnswer is the largest free-text AskUserQuestion answer, in bytes.
// A matching option label is not free text and is not measured against it.
const maxFreeAnswer = 4 << 10

func canonicalValue(q Question, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%w: empty answer", ErrAnswer)
	}
	if label, ok := matchLabel(q, value); ok {
		return label, nil
	}
	if !q.Multi {
		if len(value) > maxFreeAnswer {
			return "", fmt.Errorf("%w: answer is too long", ErrAnswer)
		}
		return value, nil
	}
	parts := strings.Split(value, ", ")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) == "" {
			return "", fmt.Errorf("%w: empty answer", ErrAnswer)
		}
		if label, ok := matchLabel(q, part); ok {
			out = append(out, label)
			continue
		}
		if len(part) > maxFreeAnswer {
			return "", fmt.Errorf("%w: answer is too long", ErrAnswer)
		}
		out = append(out, part)
	}
	return strings.Join(out, ", "), nil
}

func matchLabel(q Question, value string) (string, bool) {
	for _, o := range q.Options {
		if value == o.Label || value == redactStr(o.Label) {
			return o.Label, true
		}
	}
	return "", false
}

func withAnswers(args map[string]any, answers map[string]string, notes map[string]map[string]any) map[string]any {
	out := make(map[string]any, len(args)+2)
	for k, v := range args {
		out[k] = v
	}
	encoded := make(map[string]any, len(answers))
	for k, v := range answers {
		encoded[k] = v
	}
	out["answers"] = encoded
	if len(notes) > 0 {
		out["annotations"] = notes
	}
	return out
}

func redactStr(s string) string {
	v := audit.RedactValue(s)
	if out, ok := v.(string); ok {
		return out
	}
	return s
}

func redactAnswers(in map[string]string) map[string]any {
	m := make(map[string]any, len(in))
	for k, v := range in {
		m[redactStr(k)] = redactStr(v)
	}
	return m
}

func questionDenyMessage(tool, behavior, source, rule string) string {
	if isInteractiveQuestion(tool) && behavior != "allow" {
		switch source {
		case "timeout", "no_ui", "cancel":
			return "The user did not answer the question (" + source + ")."
		case "ui":
			return "The user did not answer the question (deny)."
		}
	}
	return denyMessage(behavior, source, rule)
}
