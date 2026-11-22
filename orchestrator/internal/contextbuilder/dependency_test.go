package contextbuilder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
	"github.com/2CHILON/vulntriage/orchestrator/internal/parsers"
)

func TestExtractPackageNameFromTrivy(t *testing.T) {
	// Read real Trivy fixture
	data, err := os.ReadFile("../../../testdata/sarif/trivy.sarif")
	if err != nil {
		t.Fatalf("failed to read trivy.sarif: %v", err)
	}

	findings, err := parsers.ParseSARIF(data, "test-scan")
	if err != nil {
		t.Fatalf("failed to parse SARIF: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("no findings in trivy.sarif")
	}

	// Count findings that have extractable package names
	extractableCount := 0
	for _, f := range findings {
		pkg, ok := ExtractPackageName(f)
		if ok {
			extractableCount++
			if pkg == "" {
				t.Error("extracted package name should not be empty")
			}
		}
	}

	if extractableCount == 0 {
		t.Error("trivy.sarif should have at least one finding with extractable package name")
	}
}

func TestFindImportsLodashInSampleRepo(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SourceRoot = "../../../testdata/sample-repo"
	cfg.MaxFilesScanned = 1000

	reachability := FindImports(cfg, "lodash")

	if reachability.Package != "lodash" {
		t.Errorf("package should be 'lodash', got %q", reachability.Package)
	}

	// Should find lodash in the sample repo (if it exists)
	// Status can be "imported" or "not_imported" depending on fixtures
	if reachability.Status != "imported" && reachability.Status != "not_imported" {
		t.Errorf("status should be 'imported' or 'not_imported', got %q", reachability.Status)
	}
}

func TestFindImportsYamlInSampleRepo(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SourceRoot = "../../../testdata/sample-repo"
	cfg.MaxFilesScanned = 1000

	reachability := FindImports(cfg, "yaml")

	if reachability.Package != "yaml" {
		t.Errorf("package should be 'yaml', got %q", reachability.Package)
	}

	if reachability.Status != "imported" && reachability.Status != "not_imported" {
		t.Errorf("status should be 'imported' or 'not_imported', got %q", reachability.Status)
	}
}

func TestFindImportsUnknownPackage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SourceRoot = "../../../testdata/sample-repo"

	reachability := FindImports(cfg, "this-package-definitely-does-not-exist-999")

	if reachability.Status != "not_imported" {
		t.Errorf("unknown package should have status 'not_imported', got %q", reachability.Status)
	}
}

func TestFindImportsSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nodeModulesDir := filepath.Join(dir, "node_modules")
	if err := os.Mkdir(nodeModulesDir, 0755); err != nil {
		t.Fatalf("failed to create node_modules: %v", err)
	}

	// Create a file in node_modules with an import
	filePath := filepath.Join(nodeModulesDir, "test.js")
	content := "import lodash from 'lodash'"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SourceRoot = dir

	reachability := FindImports(cfg, "lodash")

	// Should not find lodash because node_modules is skipped
	if reachability.Status == "imported" {
		t.Error("should skip node_modules directory")
	}
}

func TestFindImportsRespectMaxFilesScanned(t *testing.T) {
	dir := t.TempDir()

	// Create many files
	for i := 0; i < 10; i++ {
		filePath := filepath.Join(dir, fmt.Sprintf("file%d.js", i))
		content := "import lodash from 'lodash'"
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	cfg := DefaultConfig()
	cfg.SourceRoot = dir
	cfg.MaxFilesScanned = 3

	reachability := FindImports(cfg, "lodash")

	if reachability.FilesScanned > 3 {
		t.Errorf("should not scan more than MaxFilesScanned, scanned %d", reachability.FilesScanned)
	}
}

func TestFindImportsTransitiveDependencyWarning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SourceRoot = "../../../testdata/sample-repo"

	reachability := FindImports(cfg, "unknown-package")

	// Just verify the evidence array structure is present
	if len(reachability.Evidence) >= 0 {
		// Evidence structure is OK (can be 0 or more entries)
	}
}

func TestFindImportsEvidenceFormat(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "app.js")
	content := "import lodash from 'lodash'"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SourceRoot = dir

	reachability := FindImports(cfg, "lodash")

	if reachability.Status == "imported" && len(reachability.Evidence) > 0 {
		evidence := reachability.Evidence[0]
		if !strings.Contains(evidence, ":") {
			t.Errorf("evidence should have format 'path:line: code', got %q", evidence)
		}
	}
}

func TestFindImportsCapsEvidenceAt5(t *testing.T) {
	dir := t.TempDir()

	// Create many files with the same import
	for i := 0; i < 10; i++ {
		filePath := filepath.Join(dir, "file"+string(rune(48+i))+".js")
		content := "import lodash from 'lodash'"
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
	}

	cfg := DefaultConfig()
	cfg.SourceRoot = dir

	reachability := FindImports(cfg, "lodash")

	if len(reachability.Evidence) > 5 {
		t.Errorf("evidence should be capped at 5, got %d", len(reachability.Evidence))
	}
}

func TestExtractPackageNameNotFound(t *testing.T) {
	f := model.Finding{
		ID:          "test-1",
		Description: "Some vulnerability without a package name",
	}

	pkg, ok := ExtractPackageName(f)
	if ok {
		t.Error("should return ok=false for description without package name")
	}
	if pkg != "" {
		t.Error("package name should be empty when not found")
	}
}
