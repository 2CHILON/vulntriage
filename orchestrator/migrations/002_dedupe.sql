-- 002_dedupe.sql: Add deduplication tracking to findings

ALTER TABLE findings ADD COLUMN dedupe_group_id TEXT;
ALTER TABLE findings ADD COLUMN is_canonical BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN dedup_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_dedupe_group_id ON findings(dedupe_group_id);
CREATE INDEX IF NOT EXISTS idx_findings_is_canonical ON findings(is_canonical);

-- Table to store deduplication metadata
CREATE TABLE IF NOT EXISTS dedupe_groups (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    representative_finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    finding_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dedupe_groups_scan_id ON dedupe_groups(scan_id);
CREATE INDEX IF NOT EXISTS idx_dedupe_groups_representative ON dedupe_groups(representative_finding_id);
