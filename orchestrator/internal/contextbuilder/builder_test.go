package contextbuilder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

func TestBuilderCodeFinding(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "app.go")

	content := "package main\n\nfunc main() {\n    fmt.Println(\"Hello\")\n}\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := Config{
		SourceRoot:      dir,
		ContextLines:    1,
		MaxContextChars: 1000,
		MaxFileBytes:    1048576,
	}

	builder := NewBuilder(cfg)
	finding := model.Finding{
		ID:          "test-1",
		File:        "app.go",
		Line:        3,
		Description: "test finding",
	}

	ctx := builder.Build(finding)

	if ctx.Kind != "code" {
		t.Errorf("expected kind=code, got %q", ctx.Kind)
	}
	if ctx.CodeSnippet == "" {
		t.Error("code snippet should not be empty")
	}
	if ctx.SnippetStartLine == 0 || ctx.SnippetEndLine == 0 {
		t.Error("line numbers should be set")
	}
}

func TestBuilderDependencyFinding(t *testing.T) {
	dir := t.TempDir()
	lockfilePath := filepath.Join(dir, "package-lock.json")

	// Create a minimal package-lock.json
	content := `{"packages":{}}`
	if err := os.WriteFile(lockfilePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := Config{
		SourceRoot:      dir,
		ContextLines:    1,
		MaxContextChars: 1000,
		MaxFileBytes:    1048576,
	}

	builder := NewBuilder(cfg)
	finding := model.Finding{
		ID:          "test-1",
		File:        "package-lock.json",
		Line:        1,
		Description: "Package: lodash\nVulnerability in lodash",
	}

	ctx := builder.Build(finding)

	if ctx.Kind != "dependency" {
		t.Errorf("expected kind=dependency, got %q", ctx.Kind)
	}
	if ctx.CodeSnippet != "" {
		t.Error("code snippet should be empty for dependency findings")
	}
	if ctx.DependencyUsage == "" {
		t.Error("dependency usage should not be empty")
	}
}

func TestBuilderEmptySourceRoot(t *testing.T) {
	cfg := Config{
		SourceRoot: "",
	}

	builder := NewBuilder(cfg)
	finding := model.Finding{
		ID:   "test-1",
		File: "app.go",
		Line: 1,
	}

	ctx := builder.Build(finding)

	if ctx.Kind != "none" {
		t.Errorf("expected kind=none when source root is empty, got %q", ctx.Kind)
	}
	if ctx.WithheldReason == "" {
		t.Error("should have withheld reason when source root is empty")
	}
}

func TestBuilderSensitiveFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	content := "SECRET_KEY=xyz123abc"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := Config{
		SourceRoot:      dir,
		ContextLines:    1,
		MaxContextChars: 1000,
		MaxFileBytes:    1048576,
	}

	builder := NewBuilder(cfg)
	finding := model.Finding{
		ID:   "test-1",
		File: ".env",
		Line: 1,
	}

	ctx := builder.Build(finding)

	if ctx.WithheldReason == "" {
		t.Error("sensitive file should have withheld reason")
	}
	if ctx.CodeSnippet != "" {
		t.Error("code snippet should be empty for sensitive file")
	}
}

func TestBuilderSecretNotInResponse(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "config.js")

	// Create secret at runtime
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	content := "const key = '" + secret + "';\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := Config{
		SourceRoot:      dir,
		ContextLines:    1,
		MaxContextChars: 1000,
		MaxFileBytes:    1048576,
	}

	builder := NewBuilder(cfg)
	finding := model.Finding{
		ID:   "test-1",
		File: "config.js",
		Line: 1,
	}

	ctx := builder.Build(finding)

	// Convert context to JSON (simulating HTTP response)
	if strings.Contains(ctx.CodeSnippet, "ABCDEFGHIJKLMNOP") {
		t.Error("secret should not appear in code snippet")
	}
	if ctx.RedactionCount == 0 {
		t.Error("redaction count should be > 0 when secret is redacted")
	}
}

func TestBuilderToLLMContext(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "app.go")

	content := "package main\n\nfunc main() {\n}\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := Config{
		SourceRoot:      dir,
		ContextLines:    1,
		MaxContextChars: 1000,
		MaxFileBytes:    1048576,
	}

	builder := NewBuilder(cfg)
	finding := model.Finding{
		ID:   "test-1",
		File: "app.go",
		Line: 2,
	}

	ctx := builder.Build(finding)

	codeSnippet, dependencyUsage := ctx.ToLLMContext()
	if ctx.Kind == "code" && codeSnippet != ctx.CodeSnippet {
		t.Error("ToLLMContext code snippet should match CodeSnippet")
	}
	if ctx.Kind == "dependency" && dependencyUsage != ctx.DependencyUsage {
		t.Error("ToLLMContext dependency usage should match DependencyUsage")
	}
}

func TestBuilderManifestFiles(t *testing.T) {
	manifests := []string{
		"package.json",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"go.mod",
		"requirements.txt",
		"poetry.lock",
		"pom.xml",
		"build.gradle",
	}

	dir := t.TempDir()
	cfg := Config{
		SourceRoot: dir,
	}
	builder := NewBuilder(cfg)

	for _, manifest := range manifests {
		filePath := filepath.Join(dir, manifest)
		if err := os.WriteFile(filePath, []byte("{}"), 0644); err != nil {
			t.Fatalf("failed to create %s: %v", manifest, err)
		}

		finding := model.Finding{
			ID:          "test-" + manifest,
			File:        manifest,
			Line:        1,
			Description: "Package: test-pkg",
		}

		ctx := builder.Build(finding)

		if ctx.Kind != "dependency" {
			t.Errorf("%s should be classified as dependency, got %q", manifest, ctx.Kind)
		}
	}
}

func TestBuilderUnsafePath(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		SourceRoot: dir,
	}
	builder := NewBuilder(cfg)

	finding := model.Finding{
		ID:   "test-1",
		File: "../../../etc/passwd",
		Line: 1,
	}

	ctx := builder.Build(finding)

	if ctx.WithheldReason == "" {
		t.Error("unsafe path should have withheld reason")
	}
	if ctx.Kind != "code" {
		t.Errorf("should still classify as code, got %q", ctx.Kind)
	}
}
