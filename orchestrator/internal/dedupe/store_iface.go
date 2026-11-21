package dedupe

import (
	"context"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// FindingStore defines the minimal Store interface that handlers and DedupeScan need.
// This avoids import cycles and allows testing with a fake Store.
type FindingStore interface {
	// ScanExists checks if a scan record exists for the given scanID.
	ScanExists(ctx context.Context, scanID string) (bool, error)
	// InsertScan inserts a scan record. Idempotent (ON CONFLICT DO NOTHING).
	InsertScan(ctx context.Context, scanID string, toolName string) error
	// InsertFindings inserts multiple findings. Returns count actually inserted.
	// ON CONFLICT (id) DO NOTHING: existing IDs are skipped, not counted.
	InsertFindings(ctx context.Context, findings []model.Finding) (int, error)
	// ListAllFindingsByScan retrieves all findings for a scan.
	ListAllFindingsByScan(ctx context.Context, scanID string) ([]model.Finding, error)
	// ReplaceDedupeResults atomically updates all dedupe metadata and groups for a scan.
	ReplaceDedupeResults(ctx context.Context, scanID string, findings []model.Finding) error
}

// DedupeStats holds statistics from a DedupeScan operation.
type DedupeStats struct {
	TotalFindings     int
	GroupsCreated     int
	CanonicalFindings int
	DuplicatesRemoved int
}

// DedupeScan loads all findings for a scan, runs the deduplication engine,
// and writes the dedupe results back in one transaction. Safe to call repeatedly.
func DedupeScan(ctx context.Context, store FindingStore, scanID string) (*DedupeStats, error) {
	// Load all findings for this scan
	findings, err := store.ListAllFindingsByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}

	if len(findings) == 0 {
		return &DedupeStats{}, nil
	}

	// Run deduplication
	deduplicator := NewDefaultDeduplicator()
	findingPtrs := make([]*model.Finding, len(findings))
	for i := range findings {
		findingPtrs[i] = &findings[i]
	}
	groups := deduplicator.Dedup(findingPtrs)
	deduplicator.Mark(findingPtrs, groups)

	// Write results back atomically
	if err := store.ReplaceDedupeResults(ctx, scanID, findings); err != nil {
		return nil, err
	}

	// Compute stats
	stats := GetStats(groups)
	return &DedupeStats{
		TotalFindings:     stats.TotalFindings,
		GroupsCreated:     stats.GroupsCreated,
		CanonicalFindings: stats.CanonicalFindings,
		DuplicatesRemoved: stats.DuplicatesRemoved,
	}, nil
}
