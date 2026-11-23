package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// Store provides access to the Postgres database.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new Store with the given connection pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// InsertFinding inserts a single finding into the database.
func (s *Store) InsertFinding(ctx context.Context, finding model.Finding) error {
	query := `
		INSERT INTO findings (id, scan_id, source, severity, file, line, cwe, cve, description, dedupe_group_id, is_canonical, dedup_reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO NOTHING
	`
	_, err := s.pool.Exec(ctx, query,
		finding.ID,
		finding.ScanID,
		finding.Source,
		finding.Severity,
		finding.File,
		finding.Line,
		finding.CWE,
		finding.CVE,
		finding.Description,
		finding.DedupeGroupID,
		finding.IsCanonical,
		finding.DedupeReason,
		finding.CreatedAt,
	)
	return err
}

// InsertFindings inserts multiple findings into the database, respecting ON CONFLICT (id) DO NOTHING.
// Returns the count of findings actually inserted (not duplicated by existing IDs).
func (s *Store) InsertFindings(ctx context.Context, findings []model.Finding) (int, error) {
	inserted := 0
	for _, finding := range findings {
		count, err := s.insertFindingWithCount(ctx, finding)
		if err != nil {
			return inserted, fmt.Errorf("failed to insert finding: %w", err)
		}
		inserted += count
	}
	return inserted, nil
}

// insertFindingWithCount inserts a single finding and returns 1 if inserted, 0 if skipped (conflict).
func (s *Store) insertFindingWithCount(ctx context.Context, finding model.Finding) (int, error) {
	query := `
		INSERT INTO findings (id, scan_id, source, severity, file, line, cwe, cve, description, dedupe_group_id, is_canonical, dedup_reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO NOTHING
	`
	tag, err := s.pool.Exec(ctx, query,
		finding.ID,
		finding.ScanID,
		finding.Source,
		finding.Severity,
		finding.File,
		finding.Line,
		finding.CWE,
		finding.CVE,
		finding.Description,
		finding.DedupeGroupID,
		finding.IsCanonical,
		finding.DedupeReason,
		finding.CreatedAt,
	)
	if err != nil {
		return 0, err
	}
	// pgx returns number of rows affected; ON CONFLICT DO NOTHING returns 0 if skipped
	if tag.RowsAffected() > 0 {
		return 1, nil
	}
	return 0, nil
}

// InsertScan inserts a scan record into the database.
func (s *Store) InsertScan(ctx context.Context, scanID string, toolName string) error {
	query := `
		INSERT INTO scans (id, tool_name)
		VALUES ($1, $2)
		ON CONFLICT (id) DO NOTHING
	`
	_, err := s.pool.Exec(ctx, query, scanID, toolName)
	return err
}

// ListFindings returns all findings for a given scan.
func (s *Store) ListFindings(ctx context.Context, scanID string) ([]model.Finding, error) {
	query := `
		SELECT id, scan_id, source, severity, file, line, cwe, cve, description, dedupe_group_id, is_canonical, dedup_reason, created_at
		FROM findings
		WHERE scan_id = $1
		ORDER BY created_at DESC
	`
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []model.Finding
	for rows.Next() {
		var f model.Finding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Source, &f.Severity, &f.File, &f.Line, &f.CWE, &f.CVE, &f.Description, &f.DedupeGroupID, &f.IsCanonical, &f.DedupeReason, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// GetFinding returns a single finding by ID, or (nil, nil) when it does not exist.
func (s *Store) GetFinding(ctx context.Context, findingID string) (*model.Finding, error) {
	query := `
		SELECT id, scan_id, source, severity, file, line, cwe, cve, description, dedupe_group_id, is_canonical, dedup_reason, created_at
		FROM findings
		WHERE id = $1
	`
	var f model.Finding
	err := s.pool.QueryRow(ctx, query, findingID).Scan(
		&f.ID, &f.ScanID, &f.Source, &f.Severity, &f.File, &f.Line, &f.CWE, &f.CVE, &f.Description, &f.DedupeGroupID, &f.IsCanonical, &f.DedupeReason, &f.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// UpdateFindingDedup updates the deduplication fields of a finding.
func (s *Store) UpdateFindingDedup(ctx context.Context, findingID, dedupeGroupID string, isCanonical bool, reason string) error {
	query := `
		UPDATE findings
		SET dedupe_group_id = $1, is_canonical = $2, dedup_reason = $3
		WHERE id = $4
	`
	_, err := s.pool.Exec(ctx, query, dedupeGroupID, isCanonical, reason, findingID)
	return err
}

// ListCanonicalFindings returns only the canonical findings for a given scan.
func (s *Store) ListCanonicalFindings(ctx context.Context, scanID string) ([]model.Finding, error) {
	query := `
		SELECT id, scan_id, source, severity, file, line, cwe, cve, description, dedupe_group_id, is_canonical, dedup_reason, created_at
		FROM findings
		WHERE scan_id = $1 AND is_canonical = true
		ORDER BY severity DESC, created_at DESC
	`
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []model.Finding
	for rows.Next() {
		var f model.Finding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Source, &f.Severity, &f.File, &f.Line, &f.CWE, &f.CVE, &f.Description, &f.DedupeGroupID, &f.IsCanonical, &f.DedupeReason, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// ScanExists checks if a scan record exists for the given scanID.
func (s *Store) ScanExists(ctx context.Context, scanID string) (bool, error) {
	query := `SELECT 1 FROM scans WHERE id = $1`
	var exists int
	err := s.pool.QueryRow(ctx, query, scanID).Scan(&exists)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListAllFindingsByScan returns all findings for a scan (used by DedupeScan).
func (s *Store) ListAllFindingsByScan(ctx context.Context, scanID string) ([]model.Finding, error) {
	query := `
		SELECT id, scan_id, source, severity, file, line, cwe, cve, description, dedupe_group_id, is_canonical, dedup_reason, created_at
		FROM findings
		WHERE scan_id = $1
		ORDER BY created_at ASC
	`
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []model.Finding
	for rows.Next() {
		var f model.Finding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Source, &f.Severity, &f.File, &f.Line, &f.CWE, &f.CVE, &f.Description, &f.DedupeGroupID, &f.IsCanonical, &f.DedupeReason, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// ReplaceDedupeResults atomically clears and rewrites all dedupe metadata for a scan and its dedupe_groups.
// This is called by DedupeScan after re-deduplicating all findings for a scan.
func (s *Store) ReplaceDedupeResults(ctx context.Context, scanID string, findings []model.Finding) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Clear all dedupe metadata for this scan's findings
	_, err = tx.Exec(ctx, `
		UPDATE findings
		SET dedupe_group_id = NULL, is_canonical = FALSE, dedup_reason = NULL
		WHERE scan_id = $1
	`, scanID)
	if err != nil {
		return fmt.Errorf("failed to clear dedupe metadata: %w", err)
	}

	// Clear all dedupe_groups entries for this scan
	_, err = tx.Exec(ctx, `DELETE FROM dedupe_groups WHERE scan_id = $1`, scanID)
	if err != nil {
		return fmt.Errorf("failed to clear dedupe groups: %w", err)
	}

	// Update findings with new dedupe metadata
	for _, f := range findings {
		_, err := tx.Exec(ctx, `
			UPDATE findings
			SET dedupe_group_id = $1, is_canonical = $2, dedup_reason = $3
			WHERE id = $4
		`, f.DedupeGroupID, f.IsCanonical, f.DedupeReason, f.ID)
		if err != nil {
			return fmt.Errorf("failed to update finding dedupe metadata: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// analysisColumns is the SELECT list shared by the analysis queries. Text columns
// are COALESCEd so NULLs scan into plain strings.
const analysisColumns = `
	a.finding_id, a.scan_id, a.status, a.exploitable, a.confidence, a.priority,
	COALESCE(a.reasoning, ''), COALESCE(a.suggested_fix, ''), COALESCE(a.provider, ''),
	COALESCE(a.prompt_version, ''), COALESCE(a.error, ''), a.updated_at`

func scanAnalysis(row pgx.Row) (model.Analysis, error) {
	var a model.Analysis
	err := row.Scan(&a.FindingID, &a.ScanID, &a.Status, &a.Exploitable, &a.Confidence, &a.Priority,
		&a.Reasoning, &a.SuggestedFix, &a.Provider, &a.PromptVersion, &a.Error, &a.UpdatedAt)
	return a, err
}

// UpsertAnalysis stores the single current analysis of a finding, replacing any previous one.
func (s *Store) UpsertAnalysis(ctx context.Context, a model.Analysis) error {
	query := `
		INSERT INTO analyses (finding_id, scan_id, status, exploitable, confidence, priority,
			reasoning, suggested_fix, provider, prompt_version, error, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
		ON CONFLICT (finding_id) DO UPDATE SET
			scan_id = EXCLUDED.scan_id,
			status = EXCLUDED.status,
			exploitable = EXCLUDED.exploitable,
			confidence = EXCLUDED.confidence,
			priority = EXCLUDED.priority,
			reasoning = EXCLUDED.reasoning,
			suggested_fix = EXCLUDED.suggested_fix,
			provider = EXCLUDED.provider,
			prompt_version = EXCLUDED.prompt_version,
			error = EXCLUDED.error,
			updated_at = now()
	`
	_, err := s.pool.Exec(ctx, query, a.FindingID, a.ScanID, a.Status, a.Exploitable, a.Confidence, a.Priority,
		a.Reasoning, a.SuggestedFix, a.Provider, a.PromptVersion, a.Error)
	if err != nil {
		return fmt.Errorf("failed to upsert analysis: %w", err)
	}
	return nil
}

// GetAnalysis returns the current analysis of a finding, or (nil, nil) when none exists.
func (s *Store) GetAnalysis(ctx context.Context, findingID string) (*model.Analysis, error) {
	query := `SELECT ` + analysisColumns + ` FROM analyses a WHERE a.finding_id = $1`
	a, err := scanAnalysis(s.pool.QueryRow(ctx, query, findingID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get analysis: %w", err)
	}
	return &a, nil
}

// ListAnalysesByScan returns the analyses of a scan's canonical findings, ordered by finding ID.
func (s *Store) ListAnalysesByScan(ctx context.Context, scanID string) ([]model.Analysis, error) {
	query := `SELECT ` + analysisColumns + `
		FROM analyses a
		JOIN findings f ON f.id = a.finding_id
		WHERE a.scan_id = $1 AND f.is_canonical = true
		ORDER BY a.finding_id`
	rows, err := s.pool.Query(ctx, query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to list analyses: %w", err)
	}
	defer rows.Close()

	analyses := []model.Analysis{}
	for rows.Next() {
		a, err := scanAnalysis(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan analysis row: %w", err)
		}
		analyses = append(analyses, a)
	}
	return analyses, rows.Err()
}
