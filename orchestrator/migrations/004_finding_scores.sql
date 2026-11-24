-- Phase 5a: Risk scoring table
CREATE TABLE IF NOT EXISTS finding_scores (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    priority TEXT NOT NULL CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    breakdown JSONB NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_scores_scan_id ON finding_scores(scan_id);
