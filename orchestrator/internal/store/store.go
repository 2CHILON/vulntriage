package store

import (
	"context"
	"fmt"

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

// InsertFindings inserts multiple findings into the database.
func (s *Store) InsertFindings(ctx context.Context, findings []model.Finding) error {
	for _, finding := range findings {
		if err := s.InsertFinding(ctx, finding); err != nil {
			return fmt.Errorf("failed to insert finding: %w", err)
		}
	}
	return nil
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

// GetFinding returns a single finding by ID.
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
