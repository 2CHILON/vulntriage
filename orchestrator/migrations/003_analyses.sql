-- Migration 003: Create analyses table for LLM analysis results
CREATE TABLE IF NOT EXISTS analyses (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('ok', 'analysis_failed', 'skipped')),
    exploitable BOOLEAN,
    confidence DOUBLE PRECISION CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    priority TEXT CHECK (priority IS NULL OR priority IN ('critical', 'high', 'medium', 'low')),
    reasoning TEXT,
    suggested_fix TEXT,
    provider TEXT,
    prompt_version TEXT,
    error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_analyses_scan_id ON analyses(scan_id);
