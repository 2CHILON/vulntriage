-- 003_analyses.sql: One current LLM analysis per canonical finding (upsert, no history)

CREATE TABLE IF NOT EXISTS analyses (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('ok', 'analysis_failed', 'skipped')),
    exploitable BOOLEAN NULL,
    confidence DOUBLE PRECISION NULL,
    priority TEXT NULL,
    reasoning TEXT,
    suggested_fix TEXT,
    provider TEXT,
    prompt_version TEXT,
    error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_analyses_scan_id ON analyses(scan_id);
