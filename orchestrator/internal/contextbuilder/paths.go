package contextbuilder

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ResolveSafePath maps a finding's file path to an absolute path within the repo root.
// It applies the same normalization as dedupe.NormalizePath and rejects unsafe paths.
// Returns an error if the path tries to escape the root or is otherwise unsafe.
func ResolveSafePath(root, findingFile string) (absPath string, err error) {
	if root == "" {
		return "", fmt.Errorf("root path is empty")
	}

	if findingFile == "" {
		return "", fmt.Errorf("finding file is empty")
	}

	// Normalize forward slashes first (cross-platform)
	normalized := strings.ReplaceAll(findingFile, "\\", "/")

	// Reject absolute paths that don't start with the root
	if filepath.IsAbs(findingFile) {
		return "", fmt.Errorf("finding file is an absolute path: %s", findingFile)
	}

	// Reject ".." traversals
	if strings.Contains(normalized, "..") {
		return "", fmt.Errorf("finding file contains path traversal: %s", findingFile)
	}

	// Convert to absolute path relative to root
	absPath = filepath.Join(root, findingFile)

	// Evaluate symlinks and check the resolved path stays within root
	evalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// File might not exist yet, but we still check if it would escape
		// Use the unresolved path for the escape check
		evalPath = absPath
	}

	// Normalize both paths for comparison
	rootAbs := filepath.Clean(root)
	evalAbs := filepath.Clean(evalPath)

	// Check if the resolved path starts with the root (is within it)
	if !strings.HasPrefix(evalAbs+string(filepath.Separator), rootAbs+string(filepath.Separator)) &&
		evalAbs != rootAbs {
		return "", fmt.Errorf("finding file would resolve outside root: %s", findingFile)
	}

	return absPath, nil
}

// IsSensitiveFile returns true if the filename should not be read (contains credentials or keys).
// Check is case-insensitive and matches the basename only.
func IsSensitiveFile(name string) bool {
	// Extract basename to avoid matching on directory names
	basename := strings.ToLower(filepath.Base(name))

	// List of sensitive file patterns (case-insensitive match on basename)
	sensitivePatterns := []string{
		".env", // env files and their variants
		".env.",
		".pem",
		".key",
		".p12",
		".pfx",
		"id_rsa",
		"id_ed25519",
		"credentials",
		".npmrc",
		".pypirc",
		".tfvars",
		".tfstate",
		"secrets.",
	}

	for _, pattern := range sensitivePatterns {
		if strings.HasPrefix(basename, pattern) || strings.HasSuffix(basename, pattern) {
			return true
		}
	}

	return false
}
