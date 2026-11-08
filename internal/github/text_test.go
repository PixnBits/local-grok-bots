package github

import (
	"strings"
	"testing"
	"unicode"
)

func TestRefusedRune(t *testing.T) {
	classes := []struct {
		name   string
		runes  []rune
		refuse bool
	}{
		{"other-default-ignorable", []rune{0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2065, 0x17B4, 0x17B5, 0xE0000, 0xE0080, 0xE00FF, 0xE01F0, 0xE0FFF}, true},
		{"mongolian", []rune{0x180B, 0x180C, 0x180D, 0x180E, 0x180F}, true},
		{"private-use-bmp", []rune{0xE000, 0xF8FF}, true},
		{"private-use-plane", []rune{0xF0000, 0xFFFFD, 0xFFFFE, 0x100000, 0x10FFFD, 0x10FFFF}, true},
		{"line-sep", []rune{0x2028, 0x2029}, true},
		{"braille-blank", []rune{0x2800}, true},
		{"del", []rune{0x7F}, true},
		{"c0", []rune{0x00, 0x01, 0x08, 0x0B, 0x0C, 0x0D, 0x1F}, true},
		{"c1", []rune{0x80, 0x85, 0x9F}, true},
		{"bidi", []rune{0x202A, 0x202E, 0x2066, 0x2069, 0x200E, 0x200F, 0x061C}, true},
		{"zero-width", []rune{0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}, true},
		{"tag", []rune{0xE0000, 0xE0053, 0xE007F}, true},
		{"format", []rune{0x2061, 0x00AD, 0x2064}, true},
		{"variation", []rune{0xFE00, 0xFE0F, 0xE0100}, true},
		{"allowed", []rune{'\n', '\t', 'a', ' ', 0x00A0, 0x3000}, false},
	}
	for _, c := range classes {
		t.Run(c.name, func(t *testing.T) {
			for _, r := range c.runes {
				if got := refusedRune(r); got != c.refuse {
					t.Fatalf("U+%04X got %v", r, got)
				}
			}
		})
	}
	if !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, 0x034F) {
		t.Fatal("table missing Other_Default_Ignorable_Code_Point")
	}
}

func TestCleanTextRefuses(t *testing.T) {
	classes := []struct {
		name    string
		samples []string
		reason  string
	}{
		{"bidi", []string{"\u202A", "\u202E", "\u2066", "\u2069", "\u200E", "\u200F", "\u061C"}, "text"},
		{"zero-width", []string{"\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF"}, "text"},
		{"tag", []string{"\U000E0000", "\U000E0053", "\U000E007F"}, "text"},
		{"c1", []string{"\u0080", "\u0085", "\u009F"}, "text"},
		{"format", []string{"\u2061", "\u00AD", "\u2064"}, "text"},
		{"variation", []string{"\uFE00", "\uFE0F", "\U000E0100"}, "text"},
		{"other-default-ignorable", []string{"\u034F", "\u115F", "\u1160", "\u3164", "\uFFA0", "\u2065", "\u17B4", "\u17B5", "\U000E0000", "\U000E0FFF"}, "text"},
		{"mongolian", []string{"\u180B", "\u180C", "\u180D", "\u180E", "\u180F"}, "text"},
		{"private-use-bmp", []string{"\uE000", "\uF8FF"}, "text"},
		{"private-use-plane", []string{"\U000F0000", "\U000FFFFD", "\U00100000", "\U0010FFFD"}, "text"},
		{"line-sep", []string{"\u2028", "\u2029"}, "text"},
		{"braille-blank", []string{"\u2800"}, "text"},
		{"del", []string{"\x7f"}, "arguments"},
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
						if reason != c.reason {
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
	if _, reason := CleanText("a\tb", "title"); reason != "arguments" {
		t.Fatalf("title tab %q", reason)
	}
	if _, reason := CleanText("   ", "title"); reason != "arguments" {
		t.Fatalf("title blank %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("a", 256), "title"); reason != "" {
		t.Fatal(reason)
	}
	if _, reason := CleanText(strings.Repeat("a", 257), "title"); reason != "arguments" {
		t.Fatalf("title size %q", reason)
	}
	if _, reason := CleanText("a\x7fb", "title"); reason != "arguments" {
		t.Fatalf("title del %q", reason)
	}
	if _, reason := CleanText("a\u034Fb", "title"); reason != "text" {
		t.Fatalf("title ignorable %q", reason)
	}
	kept, reason := CleanText("a\r\nb", "body")
	if reason != "" || kept != "a\nb" {
		t.Fatalf("crlf %q %q", kept, reason)
	}
	if _, reason := CleanText("a\rb", "body"); reason != "arguments" {
		t.Fatalf("cr %q", reason)
	}
	if _, reason := CleanText("a\x7fb", "body"); reason != "arguments" {
		t.Fatalf("body del %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("a\n", 399), "body"); reason != "" {
		t.Fatalf("400 lines %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("a\n", 400), "body"); reason != "lines" {
		t.Fatalf("401 lines %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("\u2028", 400), "body"); reason != "lines" {
		t.Fatalf("separator lines %q", reason)
	}
	if _, reason := CleanText(strings.Repeat("\u2029", 400), "body"); reason != "lines" {
		t.Fatalf("paragraph lines %q", reason)
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

func TestCountLines(t *testing.T) {
	if CountLines("") != 0 || CountLines("hello") != 1 {
		t.Fatal("plain")
	}
	if CountLines("a\nb") != 2 || CountLines("a\n") != 2 {
		t.Fatal("newline")
	}
	if CountLines("a\u2028b") != 2 || CountLines("a\u2029b") != 2 {
		t.Fatal("separator")
	}
	if CountLines("a\u2028b\u2029c\nd") != 4 {
		t.Fatal("mixed")
	}
	if CountLines(strings.Repeat("\u2028", 400)) != 401 {
		t.Fatal("400 separators")
	}
	if !CardNeedsCue(strings.Repeat("a\n", 8) + "z") {
		t.Fatal("nine lines")
	}
	if CardNeedsCue("single") {
		t.Fatal("short")
	}
	if !CardNeedsCue(strings.Repeat("a", CardCueBytes+1)) {
		t.Fatal("long line")
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
	cases := []struct{ in, want string }{
		{"a\u034Fb", "a⟦U+034F⟧b"},
		{"a\uE000b", "a⟦U+E000⟧b"},
		{"a\U000F0000b", "a⟦U+F0000⟧b"},
		{"a\u2028b", "a⟦U+2028⟧b"},
		{"a\u2800b", "a⟦U+2800⟧b"},
		{"a\x7fb", "a⟦U+007F⟧b"},
		{"a\u115Fb", "a⟦U+115F⟧b"},
	}
	for _, c := range cases {
		if VisibleRunes(c.in) != c.want {
			t.Fatalf("%q → %q", c.in, VisibleRunes(c.in))
		}
	}
}

func TestSecretAndExternalLinks(t *testing.T) {
	for _, s := range []string{
		"ghp_example", "GHP_example", "gho_example", "ghs_example", "ghu_example", "ghr_example",
		"github_pat_example", "sk-ant-example", "SK-ANT-example", "sk-proj-abc",
		"Password=hunter", "password = hunter", "PASSWORD: hunter", "passwd=x",
		"AKIA" + strings.Repeat("A", 16), "ASIA" + strings.Repeat("B", 16),
		"xoxb-123", "xoxp-123", "-----BEGIN RSA PRIVATE KEY-----",
		"Bearer abcdefghijkl", "token=abc",
	} {
		if !LooksSecret(s) {
			t.Fatalf("missed %q", s)
		}
	}
	if LooksSecret("hello") || LooksSecret("ask-me") {
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
	mixed := ExternalLinks("HTTPS://Evil.Example/a and //sneaky.example/x and www.also.example/y")
	mix := strings.Join(mixed, " ")
	if !strings.Contains(mix, "HTTPS://Evil.Example/a") || !strings.Contains(mix, "//sneaky.example/x") || !strings.Contains(mix, "www.also.example/y") {
		t.Fatalf("shapes %v", mixed)
	}
	if got := ExternalLinks("https://evilgithub.com/x"); len(got) != 1 || got[0] != "https://evilgithub.com/x" {
		t.Fatalf("suffix host %v", got)
	}
	if got := ExternalLinks("https://github.com/acme/widgets"); len(got) != 0 {
		t.Fatalf("exact host %v", got)
	}
	if got := ExternalLinks(`https://evil\@github.com/x`); len(got) != 1 {
		t.Fatalf("backslash %v", got)
	}
	var many []string
	for i := 0; i < 9; i++ {
		many = append(many, "https://evil.example/"+strings.Repeat("a", i+1))
	}
	got := ExternalLinks(strings.Join(many, " "))
	if len(got) != 9 || got[8] != "+1 more" {
		t.Fatalf("cap %v", got)
	}
	long := "https://evil.example/" + strings.Repeat("b", 300)
	got = ExternalLinks(long)
	if len(got) != 1 || len(got[0]) != 200 {
		t.Fatalf("%v", got)
	}
	if !LooksSecret("see ghp_example") {
		t.Fatal("title secret")
	}
	if len(ExternalLinks("https://evil.example/from-title")) != 1 {
		t.Fatal("title link")
	}
}
