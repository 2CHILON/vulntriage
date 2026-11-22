package contextbuilder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractSnippetLineOutOfRange(t *testing.T) {
	// 3 real lines; the trailing newline must NOT count as a 4th line.
	p := writeTemp(t, "a.go", "one\ntwo\nthree\n")
	for _, line := range []int{4, 99} {
		snippet, start, end, _, reason := ExtractSnippet(p, line, 2, 8000, Config{})
		if snippet != "" || reason == "" {
			t.Errorf("line %d: want empty snippet with a reason, got %q reason %q (window %d-%d)", line, snippet, reason, start, end)
		}
	}
	snippet, _, end, _, reason := ExtractSnippet(p, 3, 2, 8000, Config{})
	if reason != "" || end != 3 || !strings.Contains(snippet, ">> 3: three") {
		t.Errorf("last real line must work: end=%d reason=%q snippet=%q", end, reason, snippet)
	}
}

func TestExtractSnippetTruncationKeepsFlaggedLine(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 41; i++ {
		fmt.Fprintf(&sb, "line %d %s\n", i, strings.Repeat("x", 100))
	}
	p := writeTemp(t, "big.js", sb.String())

	snippet, start, end, _, reason := ExtractSnippet(p, 21, 20, 600, Config{})
	if reason != "" {
		t.Fatalf("unexpected reason %q", reason)
	}
	if !strings.Contains(snippet, ">> 21: line 21") {
		t.Errorf("flagged line was cut out of the snippet:\n%s", snippet)
	}
	if start > 21 || end < 21 {
		t.Errorf("window %d-%d must contain line 21", start, end)
	}
	if len(snippet) > 600+len("\n... (truncated)") {
		t.Errorf("snippet too long: %d bytes", len(snippet))
	}
	if !utf8.ValidString(snippet) {
		t.Error("snippet is not valid UTF-8")
	}
}

func TestExtractSnippetLongLineIsCappedAndUTF8Safe(t *testing.T) {
	long := strings.Repeat("é", 2000) // multi-byte characters, far over the line cap
	p := writeTemp(t, "min.js", "short\n"+long+"\nshort2\n")

	snippet, _, _, _, reason := ExtractSnippet(p, 2, 1, 8000, Config{})
	if reason != "" {
		t.Fatalf("unexpected reason %q", reason)
	}
	if len(snippet) > 2000 {
		t.Errorf("long line was not capped: %d bytes", len(snippet))
	}
	if !utf8.ValidString(snippet) {
		t.Error("line truncation split a multi-byte character")
	}
	if !strings.Contains(snippet, ">> 2:") || !strings.Contains(snippet, "short2") {
		t.Errorf("neighbouring lines or marker missing:\n%s", snippet)
	}
}

func TestExtractSnippetCRLF(t *testing.T) {
	p := writeTemp(t, "win.txt", "a\r\nb\r\nc\r\n")
	snippet, _, end, _, _ := ExtractSnippet(p, 2, 5, 8000, Config{})
	if strings.Contains(snippet, "\r") {
		t.Error("carriage returns must not appear in the snippet")
	}
	if end != 3 {
		t.Errorf("want 3 lines, got end=%d", end)
	}
}