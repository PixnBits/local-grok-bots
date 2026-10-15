package audit

import (
	"strings"
	"testing"
)

func TestStreamRedactsKeysSplitAcrossDeltas(t *testing.T) {
	ant, oat, adminKey, xai, ghp, ghPat, lgbr, adminTok, openai, bearer := fakeSecrets()
	prose := "The sandbox cannot start. Status is good. A flag is set. The box is extra large."
	samples := []string{
		prose,
		"before " + ant + " after",
		"see " + oat + " and " + adminKey,
		"k " + xai + " done",
		ghp + " " + ghPat,
		"run " + lgbr + " admin " + adminTok + " end",
		"old " + openai + " and sk-supersecretvalue12",
		"use " + bearer + " please",
		"sk-test stays and xai-short stays " + strings.Repeat("ef", 31),
	}
	for _, text := range samples {
		want := RedactText(text)
		for _, n := range []int{1, 2, 3, 5, 7, 11, len(text)} {
			if n <= 0 {
				continue
			}
			var s Stream
			var b strings.Builder
			for i := 0; i < len(text); i += n {
				j := i + n
				if j > len(text) {
					j = len(text)
				}
				part := s.Push(text[i:j])
				if strings.Contains(part, ant) || strings.Contains(part, xai) || strings.Contains(part, lgbr) || strings.Contains(part, adminTok) {
					t.Fatalf("chunk %d emitted a secret %q from %q", n, part, text)
				}
				b.WriteString(part)
			}
			b.WriteString(s.Flush())
			if b.String() != want {
				t.Fatalf("chunk %d\n got %q\nwant %q\ntext %q", n, b.String(), want, text)
			}
		}
	}
}

func TestStreamHoldsAPartialAnthropicKey(t *testing.T) {
	ant, _, _, _, _, _, _, _, _, _ := fakeSecrets()
	cut := strings.Index(ant, "-api03-") + len("-api03-")
	var s Stream
	first := s.Push("note " + ant[:cut])
	if first != "note " || strings.Contains(first, "sk-ant") {
		t.Fatalf("partial published: %q", first)
	}
	second := s.Push(ant[cut:] + " tail")
	flushed := s.Flush()
	// A trailing "l" is a prefix of lgbr_ and stays held until flush.
	got := first + second + flushed
	if got != "note [redacted] tail" || strings.Contains(second, ant) || !strings.Contains(second, "[redacted]") {
		t.Fatalf("rest %q flush %q", second, flushed)
	}
}
