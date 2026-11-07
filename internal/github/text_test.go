package github

import (
	"strings"
	"testing"
)

func TestCleanTextRefuses(t *testing.T) {
	classes := []struct {
		name    string
		samples []string
	}{
		{"bidi", []string{"\u202A", "\u202E", "\u2066", "\u2069", "\u200E", "\u200F", "\u061C"}},
		{"zero-width", []string{"\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF"}},
		{"tag", []string{"\U000E0000", "\U000E0053", "\U000E007F"}},
		{"c1", []string{"\u0080", "\u0085", "\u009F"}},
		{"format", []string{"\u2061", "\u00AD", "\u2064"}},
		{"variation", []string{"\uFE00", "\uFE0F", "\U000E0100"}},
	}
	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			for _, sample := range c.samples {
				for _, kind := range []string{"body", "title", "comment"} {
					t.Run(kind, func(t *testing.T) {
						text := "hello" + sample
						if kind == "comment" {
							text = "note" + sample
						}
						_, reason := CleanText(text, kind)
						if reason != "text" {
							t.Fatalf("%s %q reason %q", kind, sample, reason)
						}
					})
				}
			}
		})
	}
}

func TestCleanTextLimits(t *testing.T) {
	if _, reason := CleanText("hello", "title"); reason != "" {
		t.Fatal(reason)
	}
	if _, reason := CleanText("a\nb", "title"); reason != "arguments" {
		t.Fatalf("title newline %q", reason)
	}
	kept, reason := CleanText("a\r\nb", "body")
	if reason != "" || kept != "a\nb" {
		t.Fatalf("crlf %q %q", kept, reason)
	}
	if _, reason := CleanText("a\rb", "body"); reason != "arguments" {
		t.Fatalf("cr %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("a\n", 399), "body"); reason != "" {
		t.Fatalf("400 lines %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("a\n", 400), "body"); reason != "lines" {
		t.Fatalf("401 lines %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("a", 1<<16), "body"); reason != "" {
		t.Fatal(reason)
	}
	if _, reason := CleanText(strings.Repeat("a", 1<<16+1), "body"); reason != "arguments" {
		t.Fatalf("size %q", reason)
	}
	if ValidCommentBody("  ") || !ValidCommentBody("hi") {
		t.Fatal("comment blank")
	}
}

func TestVisibleRunes(t *testing.T) {
	got := VisibleRunes("a\u202Eb")
	if got != "a⟦U+202E⟧b" || strings.ContainsRune(got, '\u202E') {
		t.Fatalf("%q", got)
	}
	if VisibleRunes("hello") != "hello" {
		t.Fatal(VisibleRunes("hello"))
	}
	if VisibleRunes("x\u200By") != "x⟦U+200B⟧y" {
		t.Fatal(VisibleRunes("x\u200By"))
	}
}

func TestSecretAndExternalLinks(t *testing.T) {
	if !LooksSecret("ghp_example") || !LooksSecret("github_pat_example") || !LooksSecret("sk-ant-example") || !LooksSecret("Password=hunter") {
		t.Fatal("missed a secret shape")
	}
	if LooksSecret("hello") {
		t.Fatal("ordinary text")
	}
	links := ExternalLinks("see https://user-images.githubusercontent.com/1/x.png and https://github.com/acme/widgets and https://www.github.com/x and https://evil.example/a")
	joined := strings.Join(links, " ")
	if !strings.Contains(joined, "https://user-images.githubusercontent.com/1/x.png") || !strings.Contains(joined, "https://evil.example/a") {
		t.Fatalf("%v", links)
	}
	if strings.Contains(joined, "https://github.com/acme/widgets") || strings.Contains(joined, "www.github.com") {
		t.Fatalf("%v", links)
	}
	var many []string
	for i := 0; i < 9; i++ {
		many = append(many, "https://evil.example/"+strings.Repeat("a", i+1))
	}
	if got := ExternalLinks(strings.Join(many, " ")); len(got) != 8 {
		t.Fatalf("cap %d", len(got))
	}
	long := "https://evil.example/" + strings.Repeat("b", 300)
	got := ExternalLinks(long)
	if len(got) != 1 || len(got[0]) != 200 {
		t.Fatalf("%v", got)
	}
}
