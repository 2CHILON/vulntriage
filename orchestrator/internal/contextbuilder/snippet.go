package contextbuilder

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// ErrFileTooLarge is returned when a file exceeds the configured byte limit.
var ErrFileTooLarge = errors.New("file too large")

// maxLineChars caps a single line so minified files cannot fill the whole snippet.
const maxLineChars = 500

// ReadAndRedactFile reads a regular file, rejects oversized or binary content,
// and redacts all secrets. It checks size BEFORE reading.
func ReadAndRedactFile(path string, maxBytes int) (content string, redactionCount int, isBinary bool, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, false, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, false, errors.New("not a regular file")
	}
	if info.Size() > int64(maxBytes) {
		return "", 0, false, ErrFileTooLarge
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, false, err
	}
	if len(data) > maxBytes { // file grew between stat and read
		return "", 0, false, ErrFileTooLarge
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return "", 0, true, nil
	}

	redacted, count := Redact(string(data))
	return redacted, count, false, nil
}

// truncateUTF8 cuts s to at most max bytes without splitting a multi-byte character.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ExtractSnippet extracts a numbered code window around lineNumber. The file is
// redacted BEFORE the window is cut. The flagged line is marked with ">>" and is
// always kept, even when the window has to shrink to fit maxChars.
func ExtractSnippet(filePath string, lineNumber int, contextLines int, maxChars int, cfg Config) (snippet string, startLine, endLine, redactionCount int, withheldReason string) {
	if lineNumber < 1 {
		return "", 0, 0, 0, "line number is 0 or invalid"
	}
	if cfg.MaxFileBytes == 0 {
		cfg.MaxFileBytes = 1048576
	}
	if contextLines == 0 {
		contextLines = 20
	}
	if maxChars == 0 {
		maxChars = 8000
	}

	content, redCount, isBinary, err := ReadAndRedactFile(filePath, cfg.MaxFileBytes)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return "", 0, 0, 0, "file not found"
		case errors.Is(err, ErrFileTooLarge):
			return "", 0, 0, 0, "file too large"
		default:
			// Generic on purpose: raw errors can contain local paths.
			return "", 0, 0, 0, "file could not be read"
		}
	}
	if isBinary {
		return "", 0, 0, 0, "file is binary or contains NUL bytes"
	}

	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimSuffix(content, "\n")
	if content == "" {
		return "", 0, 0, 0, "file is empty"
	}
	lines := strings.Split(content, "\n")

	if lineNumber > len(lines) {
		return "", 0, 0, 0, "line number is beyond the end of the file"
	}

	startLine = lineNumber - contextLines
	if startLine < 1 {
		startLine = 1
	}
	endLine = lineNumber + contextLines
	if endLine > len(lines) {
		endLine = len(lines)
	}

	render := func(from, to int) string {
		var sb strings.Builder
		for i := from; i <= to; i++ {
			text := lines[i-1]
			if len(text) > maxLineChars {
				text = truncateUTF8(text, maxLineChars) + " ...(line truncated)"
			}
			if i == lineNumber {
				fmt.Fprintf(&sb, ">> %d: %s", i, text)
			} else {
				fmt.Fprintf(&sb, "%5d: %s", i, text)
			}
			if i < to {
				sb.WriteByte('\n')
			}
		}
		return sb.String()
	}

	snippet = render(startLine, endLine)
	truncated := false

	// Too long: shrink the window around the flagged line until it fits.
	for len(snippet) > maxChars && (startLine < lineNumber || endLine > lineNumber) {
		if startLine < lineNumber {
			startLine++
		}
		if endLine > lineNumber {
			endLine--
		}
		snippet = render(startLine, endLine)
		truncated = true
	}
	// Even the single flagged line is too long.
	if len(snippet) > maxChars {
		snippet = truncateUTF8(snippet, maxChars)
		truncated = true
	}
	if truncated {
		snippet += "\n... (truncated)"
	}

	return snippet, startLine, endLine, redCount, ""
}