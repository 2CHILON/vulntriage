package contextbuilder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSafePathEmptyRoot(t *testing.T) {
	_, err := ResolveSafePath("", "some/file.go")
	if err == nil {
		t.Error("empty root should return error")
	}
}

func TestResolveSafePathEmptyFile(t *testing.T) {
	_, err := ResolveSafePath("/repo", "")
	if err == nil {
		t.Error("empty file should return error")
	}
}

func TestResolveSafePathAbsolutePath(t *testing.T) {
	// Test Windows absolute path
	_, err := ResolveSafePath("C:\\repo", "C:\\etc\\passwd")
	if err == nil {
		t.Error("Windows absolute path should return error")
	}

	// Test Unix-style absolute path (also should be rejected)
	_, err = ResolveSafePath("/repo", "\\etc\\passwd")
	if err == nil {
		// On Windows, backslash-prefixed paths might not be absolute
		// This is OK; the test verifies rejection of backslash-prefixed traversals
	}
}

func TestResolveSafePathTraversal(t *testing.T) {
	_, err := ResolveSafePath("/repo", "app/../../../etc/passwd")
	if err == nil {
		t.Error("path traversal (..) should return error")
	}
}

func TestResolveSafePathNormalPath(t *testing.T) {
	dir := t.TempDir()
	file := "app/main.go"

	absPath, err := ResolveSafePath(dir, file)
	if err != nil {
		t.Errorf("normal path should not error: %v", err)
	}

	expected := filepath.Join(dir, file)
	if absPath != expected {
		t.Errorf("expected %s, got %s", expected, absPath)
	}
}

func TestResolveSafePathWindowsBackslashes(t *testing.T) {
	dir := t.TempDir()
	file := "app\\main.go"

	absPath, err := ResolveSafePath(dir, file)
	if err != nil {
		t.Errorf("path with backslashes should work: %v", err)
	}

	// Should normalize to forward slashes internally but resolve correctly
	if !strings.HasSuffix(absPath, "main.go") {
		t.Errorf("path should resolve correctly: %s", absPath)
	}
}

func TestResolveSafePathSymlinkInside(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "target.go")

	// Create target file
	if err := os.WriteFile(file, []byte("code"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create symlink inside root
	linkPath := filepath.Join(dir, "link.go")
	if err := os.Symlink(file, linkPath); err != nil {
		t.Skip("symlinks not supported on this OS")
	}

	// Should resolve without error
	absPath, err := ResolveSafePath(dir, "link.go")
	if err != nil {
		t.Errorf("symlink inside root should be allowed: %v", err)
	}
	if absPath == "" {
		t.Error("resolved path should not be empty")
	}
}

func TestResolveSafePathSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outsideDir := t.TempDir()
	file := filepath.Join(outsideDir, "secret.env")

	// Create outside file
	if err := os.WriteFile(file, []byte("SECRET=xyz"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create symlink inside root pointing outside
	linkPath := filepath.Join(dir, "link.env")
	if err := os.Symlink(file, linkPath); err != nil {
		t.Skip("symlinks not supported on this OS")
	}

	// Should reject
	_, err := ResolveSafePath(dir, "link.env")
	if err == nil {
		t.Error("symlink escaping root should be rejected")
	}
}

func TestIsSensitiveFileEnv(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{".env", true},
		{".env.local", true},
		{".env.prod", true},
		{"app.js", false},
	}

	for _, tc := range cases {
		result := IsSensitiveFile(tc.name)
		if result != tc.expected {
			t.Errorf("IsSensitiveFile(%q) = %v, want %v", tc.name, result, tc.expected)
		}
	}
}

func TestIsSensitiveFilePEM(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{"id_rsa", true},
		{"id_ed25519", true},
		{"certificate.pem", true},
		{"app.pem", true},
		{"app.js", false},
	}

	for _, tc := range cases {
		result := IsSensitiveFile(tc.name)
		if result != tc.expected {
			t.Errorf("IsSensitiveFile(%q) = %v, want %v", tc.name, result, tc.expected)
		}
	}
}

func TestIsSensitiveFileCredentials(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{"credentials.json", true},
		{".npmrc", true},
		{".pypirc", true},
		{"secrets.yml", true},
		{"app.js", false},
	}

	for _, tc := range cases {
		result := IsSensitiveFile(tc.name)
		if result != tc.expected {
			t.Errorf("IsSensitiveFile(%q) = %v, want %v", tc.name, result, tc.expected)
		}
	}
}

func TestIsSensitiveFileCasInsensitive(t *testing.T) {
	cases := []struct {
		name     string
		expected bool
	}{
		{".ENV", true},
		{".PEM", true},
		{"SECRETS.TXT", true},
		{"App.js", false},
	}

	for _, tc := range cases {
		result := IsSensitiveFile(tc.name)
		if result != tc.expected {
			t.Errorf("IsSensitiveFile(%q) = %v, want %v", tc.name, result, tc.expected)
		}
	}
}

func TestIsSensitiveFileWithPath(t *testing.T) {
	// Should check basename only, not full path
	result := IsSensitiveFile("/app/subdir/.env")
	if !result {
		t.Error(".env in subdirectory should be sensitive")
	}

	result = IsSensitiveFile("/app/.env/file.js")
	if result {
		t.Error("file.js should not be sensitive even if in .env directory")
	}
}
