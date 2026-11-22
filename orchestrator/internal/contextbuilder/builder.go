package contextbuilder

import (
	"log"
	"path/filepath"
	"strings"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// Builder orchestrates context building for a finding.
type Builder struct {
	cfg Config
}

// NewBuilder creates a new Builder with the given config.
func NewBuilder(cfg Config) *Builder {
	return &Builder{cfg: cfg}
}

// Build constructs context for a finding. It classifies the finding as "code" or "dependency",
// fetches the appropriate context, and returns a Context struct.
// Never returns an error for missing/unreadable files; only for programmer errors.
func (b *Builder) Build(f model.Finding) Context {
	ctx := Context{
		FindingID:      f.ID,
		RedactionCount: 0,
	}

	// If SourceRoot is not configured, return Kind "none"
	if b.cfg.SourceRoot == "" {
		ctx.Kind = "none"
		ctx.WithheldReason = "source root not configured"
		return ctx
	}

	// Classify: check if file is a manifest or lockfile
	basename := strings.ToLower(filepath.Base(f.File))
	if isManifestOrLockfile(basename) {
		ctx.Kind = "dependency"
		// Don't read the file; instead, extract package name and find imports
		pkg, ok := ExtractPackageName(f)
		if !ok {
			ctx.WithheldReason = "could not extract package name from description"
			return ctx
		}

		// Log the finding ID and kind
		log.Printf("contextbuilder: finding=%s kind=dependency package=%s", f.ID, pkg)

		// Find imports
		reachability := FindImports(b.cfg, pkg)
		ctx.Reachability = &reachability

		// Build dependency usage string
		depUsage := "Package: " + pkg + "\n"
		if reachability.Status == "imported" {
			depUsage += "Status: Imported\n"
			if len(reachability.Evidence) > 0 {
				depUsage += "Evidence:\n"
				for _, ev := range reachability.Evidence {
					depUsage += "  " + ev + "\n"
				}
			}
		} else {
			depUsage += "Status: Not imported in scanned files\n"
		}
		depUsage += "\nDirect imports only; transitive dependencies are not traced, so not_imported does NOT prove the package is unused.\n"

		ctx.DependencyUsage = depUsage
		return ctx
	}

	// Code finding
	ctx.Kind = "code"

	// Resolve safe path
	absPath, err := ResolveSafePath(b.cfg.SourceRoot, f.File)
	if err != nil {
		ctx.WithheldReason = "unsafe path: " + err.Error()
		log.Printf("contextbuilder: finding=%s kind=code error=%v", f.ID, err)
		return ctx
	}

	// Check if the file is sensitive
	if IsSensitiveFile(absPath) {
		ctx.WithheldReason = "sensitive file (contains credentials)"
		log.Printf("contextbuilder: finding=%s kind=code reason=sensitive_file", f.ID)
		return ctx
	}

	// Extract snippet (redacts secrets first, then clips)
	snippet, startLine, endLine, redactionCount, withheldReason := ExtractSnippet(absPath, f.Line, b.cfg.ContextLines, b.cfg.MaxContextChars, b.cfg)

	if withheldReason != "" {
		ctx.WithheldReason = withheldReason
		log.Printf("contextbuilder: finding=%s kind=code reason=%s", f.ID, withheldReason)
		return ctx
	}

	ctx.CodeSnippet = snippet
	ctx.SnippetStartLine = startLine
	ctx.SnippetEndLine = endLine
	ctx.RedactionCount = redactionCount

	log.Printf("contextbuilder: finding=%s kind=code lines=%d-%d redactions=%d", f.ID, startLine, endLine, redactionCount)

	return ctx
}

// isManifestOrLockfile checks if the basename is a package manifest or lockfile.
func isManifestOrLockfile(basename string) bool {
	manifests := map[string]bool{
		"package-lock.json": true,
		"yarn.lock":         true,
		"pnpm-lock.yaml":    true,
		"package.json":      true,
		"go.mod":            true,
		"go.sum":            true,
		"requirements.txt":  true,
		"pipfile.lock":      true,
		"poetry.lock":       true,
		"pom.xml":           true,
		"build.gradle":      true,
	}
	return manifests[basename]
}
