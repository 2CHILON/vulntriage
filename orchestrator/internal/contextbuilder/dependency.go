package contextbuilder

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// ExtractPackageName derives the package name from a Finding's description.
// For Trivy dependency findings, the description typically contains "Package: <name>".
// Returns ok=false if the name cannot be determined.
func ExtractPackageName(finding model.Finding) (name string, ok bool) {
	// Look for "Package: <name>" pattern in the description
	pattern := regexp.MustCompile(`(?i)Package:\s*([^\s,\n]+)`)
	matches := pattern.FindStringSubmatch(finding.Description)
	if len(matches) > 1 {
		pkg := strings.TrimSpace(matches[1])
		if pkg != "" {
			return pkg, true
		}
	}

	return "", false
}

// FindImports searches the codebase for imports of a given package.
// Returns a Reachability struct with the import status and evidence.
// Respects MaxFileBytes, MaxFilesScanned, and skips node_modules, .git, vendor, etc.
func FindImports(cfg Config, packageName string) Reachability {
	if cfg.SourceRoot == "" {
		return Reachability{
			Package:      packageName,
			Status:       "unknown",
			Evidence:     []string{},
			FilesScanned: 0,
		}
	}

	var imports []string
	filesScanned := 0
	found := false

	// Walk the source tree
	err := filepath.Walk(cfg.SourceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		// Skip directories
		if info.IsDir() {
			name := strings.ToLower(info.Name())
			// Skip common dependency and cache directories
			if name == "node_modules" || name == ".git" || name == "vendor" ||
				name == "dist" || name == "build" || name == ".venv" ||
				name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(path))
		if !isCodeFile(ext) {
			return nil
		}

		// Skip sensitive files
		if IsSensitiveFile(path) {
			return nil
		}

		// Count files
		if filesScanned >= cfg.MaxFilesScanned {
			return filepath.SkipDir
		}
		filesScanned++

		// Check file size
		if info.Size() > int64(cfg.MaxFileBytes) {
			return nil
		}

		// Read and search for imports
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		text := string(content)
		if hasNULByte(text) {
			return nil // Skip binary files
		}

		// Find imports in this file
		importsInFile := findImportsInFile(text, packageName, path)
		found = found || len(importsInFile) > 0
		imports = append(imports, importsInFile...)

		return nil
	})

	if err != nil && err != filepath.SkipDir {
		// Error during walk, still return what we found
	}

	status := "not_imported"
	if found {
		status = "imported"
	}

	// Cap evidence to 5 items
	evidence := imports
	if len(evidence) > 5 {
		evidence = evidence[:5]
	}

	msg := "Direct imports only; transitive dependencies are not traced, so not_imported does NOT prove the package is unused."
	if status == "imported" {
		msg = fmt.Sprintf("Found %d import(s). %s", len(imports), msg)
	}

	return Reachability{
		Package:      packageName,
		Status:       status,
		Evidence:     evidence,
		FilesScanned: filesScanned,
	}
}

// isCodeFile checks if a file extension is a code file.
func isCodeFile(ext string) bool {
	codeExts := map[string]bool{
		".js":  true,
		".jsx": true,
		".ts":  true,
		".tsx": true,
		".mjs": true,
		".cjs": true,
		".py":  true,
		".go":  true,
	}
	return codeExts[ext]
}

// hasNULByte checks if the text contains a NUL byte (binary file indicator).
func hasNULByte(text string) bool {
	return strings.Contains(text, "\x00")
}

// findImportsInFile finds all imports of a package in a file and returns evidence lines.
func findImportsInFile(content string, packageName string, filePath string) []string {
	var evidence []string
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// JavaScript/TypeScript imports
		// import x from 'pkg' or 'pkg/sub'
		jsPattern := regexp.MustCompile(`(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)`)
		if jsPattern.MatchString(line) {
			matches := jsPattern.FindStringSubmatch(line)
			if len(matches) > 1 && matchesPackage(matches[1], packageName) {
				relPath := getRelativePath(filePath)
				evidence = append(evidence, fmt.Sprintf("%s:%d: %s", relPath, lineNum, trimmed))
			}
		}

		// import ... from 'pkg'
		jsFromPattern := regexp.MustCompile(`import\s+.*?\s+from\s+['"]([^'"]+)['"]`)
		if jsFromPattern.MatchString(line) {
			matches := jsFromPattern.FindStringSubmatch(line)
			if len(matches) > 1 && matchesPackage(matches[1], packageName) {
				relPath := getRelativePath(filePath)
				evidence = append(evidence, fmt.Sprintf("%s:%d: %s", relPath, lineNum, trimmed))
			}
		}

		// Python imports
		// import pkg or from pkg import
		pyPattern := regexp.MustCompile(`(?:^|\s)(?:import|from)\s+([a-zA-Z0-9_\.]+)`)
		if pyPattern.MatchString(line) {
			matches := pyPattern.FindStringSubmatch(line)
			if len(matches) > 1 && matchesPackage(matches[1], packageName) {
				relPath := getRelativePath(filePath)
				evidence = append(evidence, fmt.Sprintf("%s:%d: %s", relPath, lineNum, trimmed))
			}
		}

		// Go imports
		// import "pkg" or import ( "pkg" )
		goPattern := regexp.MustCompile(`import\s+(?:\(|\s*)[^"]*"([^"]+)"`)
		if goPattern.MatchString(line) {
			matches := goPattern.FindStringSubmatch(line)
			if len(matches) > 1 && matchesPackage(matches[1], packageName) {
				relPath := getRelativePath(filePath)
				evidence = append(evidence, fmt.Sprintf("%s:%d: %s", relPath, lineNum, trimmed))
			}
		}
	}

	return evidence
}

// matchesPackage checks if an import path matches the target package name.
// Handles subpaths like 'pkg/sub'.
func matchesPackage(importPath, packageName string) bool {
	// Normalize slashes
	importPath = strings.ReplaceAll(importPath, "\\", "/")
	packageName = strings.ReplaceAll(packageName, "\\", "/")

	// Exact match
	if importPath == packageName {
		return true
	}

	// Subpath match: 'pkg/sub' matches packageName 'pkg'
	if strings.HasPrefix(importPath, packageName+"/") {
		return true
	}

	return false
}

// getRelativePath returns a file path relative to the current working directory for display.
func getRelativePath(filePath string) string {
	// For simplicity, just use the basename with a simple relative path
	// In a real scenario, we'd use filepath.Rel, but for evidence we keep it short
	parts := strings.Split(strings.ReplaceAll(filePath, "\\", "/"), "/")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return filePath
}
