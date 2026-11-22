package contextbuilder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

func TestExtractSnippetLineZero(t *testing.T) {
	dir := t.TempDir()
	file := "test.go"
	filePath := dir + "/" + file

	if err := os.WriteFile(filePath, []byte("line1\nline2\nline3"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	snippet, _, _, _, reason := ExtractSnippet(filePath, 0, 1, 1000, cfg)
	if reason == "" {
		t.Error("line 0 should have withheldReason")
	}
	if snippet != "" {
		t.Error("line 0 should return empty snippet")
	}
}

func TestExtractSnippetMissingFile(t *testing.T) {
	cfg := DefaultConfig()
	snippet, _, _, _, reason := ExtractSnippet("/nonexistent/file.go", 10, 1, 1000, cfg)
	if reason == "" {
		t.Error("missing file should have withheldReason")
	}
	if snippet != "" {
		t.Error("missing file should return empty snippet")
	}
}

func TestExtractSnippetBinaryFile(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.bin"

	// Write binary content with NUL byte
	if err := os.WriteFile(filePath, []byte("binary\x00content"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	snippet, _, _, _, reason := ExtractSnippet(filePath, 2, 1, 1000, cfg)
	if reason == "" {
		t.Error("binary file should have withheldReason")
	}
	if snippet != "" {
		t.Error("binary file should return empty snippet")
	}
}

func TestExtractSnippetOversizedFile(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.go"

	// Create file larger than MaxFileBytes
	largeContent := strings.Repeat("x", 2*1048576)
	if err := os.WriteFile(filePath, []byte(largeContent), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.MaxFileBytes = 1048576
	snippet, _, _, _, reason := ExtractSnippet(filePath, 2, 1, 1000, cfg)
	if reason == "" {
		t.Error("oversized file should have withheldReason")
	}
	if snippet != "" {
		t.Error("oversized file should return empty snippet")
	}
}

func TestExtractSnippetValidWindow(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.go"

	content := "line 1\nline 2\nline 3\nline 4\nline 5"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	snippet, startLine, endLine, _, reason := ExtractSnippet(filePath, 3, 1, 1000, cfg)
	if reason != "" {
		t.Errorf("valid file should not have withheldReason: %s", reason)
	}
	if snippet == "" {
		t.Error("valid file should return snippet")
	}
	if startLine != 2 || endLine != 4 {
		t.Errorf("expected startLine=2, endLine=4, got %d, %d", startLine, endLine)
	}
	// Check line numbering
	if !strings.Contains(snippet, ">> 3:") {
		t.Error("flagged line should have >> marker")
	}
}

func TestExtractSnippetLineNumbering(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.go"

	content := "line 1\nline 2\nline 3"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	snippet, _, _, _, _ := ExtractSnippet(filePath, 2, 1, 1000, cfg)

	// Check line numbers are present
	if !strings.Contains(snippet, "1:") && !strings.Contains(snippet, "2:") && !strings.Contains(snippet, "3:") {
		t.Error("snippet should contain line numbers")
	}
}

func TestExtractSnippetClipAtFileStart(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.go"

	content := "line 1\nline 2\nline 3"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	snippet, _, _, _, _ := ExtractSnippet(filePath, 1, 10, 1000, cfg)
	if !strings.Contains(snippet, ">> 1:") {
		t.Error("line 1 should be flagged")
	}
}

func TestExtractSnippetClipAtFileEnd(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.go"

	content := "line 1\nline 2\nline 3"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	snippet, _, _, _, _ := ExtractSnippet(filePath, 3, 10, 1000, cfg)
	if !strings.Contains(snippet, ">> 3:") {
		t.Error("line 3 should be flagged")
	}
}

func TestExtractSnippetTruncatedAtMaxChars(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.go"

	// Create a file with many lines
	var lines []string
	for i := 1; i <= 100; i++ {
		lines = append(lines, "long line with some content that takes up space")
	}
	content := strings.Join(lines, "\n")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.MaxContextChars = 100
	snippet, _, _, _, _ := ExtractSnippet(filePath, 50, 10, 100, cfg)

	if len(snippet) > 125 { // maxChars + length of truncation marker
		t.Errorf("snippet should be truncated, got length %d", len(snippet))
	}
	if !strings.Contains(snippet, "... (truncated)") {
		t.Error("truncated snippet should indicate truncation")
	}
}

func TestExtractSnippetSecretNotLeaking(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/test.go"

	// Create secret at runtime
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	content := "line 1\n" + secret + "\nline 3"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	snippet, _, _, _, _ := ExtractSnippet(filePath, 2, 1, 1000, cfg)

	if strings.Contains(snippet, "ABCDEFGHIJKLMNOP") {
		t.Error("secret should be redacted in snippet")
	}
	if !strings.Contains(snippet, "[REDACTED:") {
		t.Error("redacted marker should be present")
	}
}

func TestSnippetPEMBeginOutsideWindow(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o755); err != nil {
		t.Fatal(err)
	}

	bodyA, bodyB, bodyC := "FAKEBODY-AAA-1111", "FAKEBODY-BBB-2222", "FAKEBODY-CCC-3333"
	lines := []string{
		"package app",             // 1
		"// filler 2",             // 2
		"// filler 3",             // 3
		"// filler 4",             // 4
		"// filler 5",             // 5
		pemBegin,                  // 6  (outside the window in case 1)
		bodyA,                     // 7
		bodyB,                     // 8  (flagged line in case 1)
		bodyC,                     // 9
		pemEnd,                    // 10 (outside the window in case 1)
		"// filler 11",            // 11
		"// filler 12",            // 12
		"var x = TARGET_LINE_MARKER", // 13 (flagged line in case 2)
		"// filler 14",            // 14
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(root, "app", "keys.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	b := NewBuilder(Config{
		SourceRoot:      root,
		ContextLines:    1,
		MaxContextChars: 8000,
		MaxFileBytes:    1 << 20,
		MaxFilesScanned: 100,
	})

	// Case 1: window covers only the key BODY lines (7-9); BEGIN and END are outside it.
	got := b.Build(model.Finding{ID: "f1", Source: "semgrep", File: "app/keys.go", Line: 8})
	for _, body := range []string{bodyA, bodyB, bodyC} {
		if strings.Contains(got.CodeSnippet, body) {
			t.Errorf("key material %q leaked into the snippet:\n%s", body, got.CodeSnippet)
		}
	}

	// Case 2: a line AFTER the key block must keep its original line number.
	got = b.Build(model.Finding{ID: "f2", Source: "semgrep", File: "app/keys.go", Line: 13})
	flagged := ""
	for _, l := range strings.Split(got.CodeSnippet, "\n") {
		if strings.HasPrefix(l, ">>") {
			flagged = l
		}
	}
	if !strings.Contains(flagged, "13:") || !strings.Contains(flagged, "TARGET_LINE_MARKER") {
		t.Errorf("flagged line must be original line 13 with its own content, got %q\nfull snippet:\n%s", flagged, got.CodeSnippet)
	}
}