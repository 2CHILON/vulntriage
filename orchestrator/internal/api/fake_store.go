package api

import (
	"context"
	"sync"

	"github.com/2CHILON/vulntriage/orchestrator/internal/analysis"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// FakeStore is an in-memory mock implementation of FindingStore for testing.
type FakeStore struct {
	mu        sync.Mutex
	scans     map[string]bool            // scanID -> exists
	findings  map[string][]model.Finding // scanID -> findings
	seenIDs   map[string]bool            // finding ID -> exists (for ON CONFLICT DO NOTHING)
	analyses  map[string]*analysis.Analysis // findingID -> analysis
}

// NewFakeStore creates a new FakeStore.
func NewFakeStore() *FakeStore {
	return &FakeStore{
		scans:    make(map[string]bool),
		findings: make(map[string][]model.Finding),
		seenIDs:  make(map[string]bool),
		analyses: make(map[string]*analysis.Analysis),
	}
}

// InsertScan adds a scan record.
func (fs *FakeStore) InsertScan(ctx context.Context, scanID, toolName string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.scans[scanID] = true
	if fs.findings[scanID] == nil {
		fs.findings[scanID] = []model.Finding{}
	}
	return nil
}

// InsertFindings stores findings, skipping duplicates (ON CONFLICT DO NOTHING).
// Returns the number of rows actually inserted.
func (fs *FakeStore) InsertFindings(ctx context.Context, findings []model.Finding) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	inserted := 0
	for _, f := range findings {
		// ON CONFLICT DO NOTHING: skip if ID already exists
		if fs.seenIDs[f.ID] {
			continue
		}
		fs.seenIDs[f.ID] = true
		if fs.findings[f.ScanID] == nil {
			fs.findings[f.ScanID] = []model.Finding{}
		}
		fs.findings[f.ScanID] = append(fs.findings[f.ScanID], f)
		inserted++
	}
	return inserted, nil
}

// ListAllFindingsByScan retrieves all findings for a scan.
func (fs *FakeStore) ListAllFindingsByScan(ctx context.Context, scanID string) ([]model.Finding, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.findings[scanID], nil
}

// ReplaceDedupeResults clears and replaces the dedupe results for a scan in one operation.
func (fs *FakeStore) ReplaceDedupeResults(ctx context.Context, scanID string, dedupedFindings []model.Finding) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.findings[scanID] = dedupedFindings
	return nil
}

// ScanExists checks if a scan exists.
func (fs *FakeStore) ScanExists(ctx context.Context, scanID string) (bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.scans[scanID], nil
}

// GetFinding retrieves a single finding by ID.
func (fs *FakeStore) GetFinding(ctx context.Context, findingID string) (*model.Finding, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	for _, findings := range fs.findings {
		for i := range findings {
			if findings[i].ID == findingID {
				return &findings[i], nil
			}
		}
	}
	return nil, nil // Not found
}

// ListCanonicalFindings retrieves canonical findings for a scan.
func (fs *FakeStore) ListCanonicalFindings(ctx context.Context, scanID string) ([]model.Finding, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var canonical []model.Finding
	for _, f := range fs.findings[scanID] {
		if f.IsCanonical {
			canonical = append(canonical, f)
		}
	}
	return canonical, nil
}

// UpsertAnalysis stores or updates an analysis.
func (fs *FakeStore) UpsertAnalysis(ctx context.Context, a *analysis.Analysis) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.analyses[a.FindingID] = a
	return nil
}

// GetAnalysis retrieves an analysis by finding ID.
func (fs *FakeStore) GetAnalysis(ctx context.Context, findingID string) (*analysis.Analysis, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.analyses[findingID], nil
}

// ListAnalysesByScan retrieves analyses for a scan (canonical findings only).
func (fs *FakeStore) ListAnalysesByScan(ctx context.Context, scanID string) ([]analysis.Analysis, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var result []analysis.Analysis
	for _, f := range fs.findings[scanID] {
		if !f.IsCanonical {
			continue
		}
		if a, ok := fs.analyses[f.ID]; ok {
			result = append(result, *a)
		}
	}
	return result, nil
}
