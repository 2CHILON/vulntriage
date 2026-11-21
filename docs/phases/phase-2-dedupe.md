# Phase 2: Deduplication

## Overview

Phase 2 implements deduplication logic to identify and merge duplicate findings from multiple scanners. When multiple security scanners report the same vulnerability, VulnTriage groups them together, selects a canonical finding, and marks duplicates for reference.

## Phase 2b: Dedupe Fix (Finding ID Collisions & Cross-Upload Dedup)

**New in Phase 2b:**
- **Stable hash-based IDs**: Finding IDs are now generated using SHA256 hash of (scan_id, source, ruleId, file, line, column, message) to prevent collisions from different scanners reporting the same issue.
- **Ordinal suffix for within-upload collisions**: If two findings produce identical hash within the same upload, the second gets a `-1` suffix, third `-2`, etc., ensuring no data loss.
- **DedupeScan() function**: Redeplicates an entire scan (all findings across all uploads) in one transaction. Safe to call repeatedly and produces identical results.
- **POST /api/v1/scans/{id}/dedupe endpoint**: Allows manual re-deduplication of a specific scan.
- **skipped_existing in response**: Upload endpoint now reports how many findings were skipped due to existing IDs (aids debugging of duplicate uploads).

## Architecture

### Deduplication Flow

```
Parsed Findings
      ↓
Generate stable hash IDs (with ordinal suffix for collisions)
      ↓
Store in database (respects ON CONFLICT DO NOTHING)
      ↓
DedupeScan: load ALL findings for scan
      ↓
Deduplicator (groups by strategy across entire scan)
      ↓
Groups of duplicate findings
      ↓
Canonical finding selection (highest priority)
      ↓
Mark findings & update dedupe_groups table (one transaction)
```

### Core Components

1. **Parsers** (`internal/parsers/sarif.go`)
   - `generateStableID()`: SHA256 hash of all distinguishing fields with ordinal collision suffix

2. **Strategies** (`internal/dedupe/strategies.go`)
   - `ExactMatchStrategy`: Identical file, line, and description
   - `LocationAndCVEStrategy`: Same location and shared CVE/CWE
   - `CVEOnlyStrategy`: Same CVE identifier across different files
   - `CWEOnlyStrategy`: Same CWE at same location
   - `DefaultStrategy`: Combines multiple strategies in order

3. **Deduplicator** (`internal/dedupe/dedupe.go`)
   - `Dedup()`: Groups findings into clusters
   - `selectRepresentative()`: Chooses canonical finding per group
   - `Mark()`: Applies dedupe metadata to findings
   - `GetStats()`: Returns deduplication statistics

4. **DedupeScan** (`internal/dedupe/scanner.go`)
   - `DedupeScan(ctx, scanner, scanID)`: Re-deduplicates entire scan atomically
   - `Scanner` interface: Minimal interface to avoid import cycles (testable with fake Store)

5. **Data Model** (`internal/model/finding.go`)
   - `DedupeGroupID`: Cluster identifier
   - `IsCanonical`: Whether this is the representative finding
   - `DedupeReason`: Why it was marked as duplicate

6. **Database** (`internal/store/store.go`)
   - `ScanExists()`: Check if scan exists (for 404 handling)
   - `ListAllFindingsByScan()`: Get all findings for a scan
   - `ReplaceDedupeResults()`: Atomically update dedupe metadata and clear dedupe_groups (one transaction)
   - `InsertFindings()`: Returns count of inserted rows (tracks skipped_existing)
   - Schema in `002_dedupe.sql`

## Workflow Integration

The orchestrator's `/api/v1/scans` endpoint:

1. Parses scanner output (SARIF format) with stable hash IDs
2. Stores findings (may skip existing IDs)
3. Calls `DedupeScan()` to re-deduplicate entire scan
4. Returns stats including `skipped_existing`

New endpoint `/api/v1/scans/{id}/dedupe` (POST):
- Calls `DedupeScan()` on existing scan
- Returns 404 if scan not found
- Safe to call repeatedly (idempotent)

### Example Request/Response

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-20241121",
    "tool_name": "trivy",
    "sarif_data": { ... }
  }'
```

```json
{
  "scan_id": "scan-20241121",
  "findings_stored": 15,
  "skipped_existing": 2,
  "total_findings": 17,
  "dedupe_groups": 12,
  "duplicates_removed": 5,
  "canonical_findings": 12
}
```

Manual dedupe:
```bash
curl -X POST http://localhost:8080/api/v1/scans/scan-20241121/dedupe
```

```json
{
  "scan_id": "scan-20241121",
  "total_findings": 17,
  "dedupe_groups": 12,
  "duplicates_removed": 5,
  "canonical_findings": 12
}
```

## Canonical Finding Selection

When multiple findings match, the representative is selected by priority:

1. **Has CVE** (1000 points) > **Has CWE** (500 points)
2. **Source priority**: trivy (300) > semgrep (200) > zap (100) > depcheck (50)
3. **Description length**: Longer descriptions score higher
4. **Tiebreaker**: First occurrence

### Example

Three findings match (same location, same CVE):
- **trivy**: CVE-2024-1234, file: app.go, line: 42, description: "SQL injection"
  - Score: 1000 (CVE) + 300 (trivy) = 1300 ✓ **CANONICAL**
- **semgrep**: CVE-2024-1234, file: app.go, line: 42, description: "SQL injection in query"
  - Score: 1000 (CVE) + 200 (semgrep) + 2 (length) = 1202
- **zap**: CVE-2024-1234, file: app.go, line: 42, description: "Injection flaw"
  - Score: 1000 (CVE) + 100 (zap) = 1100

The trivy finding becomes canonical; others are marked with its ID and reason.

## Strategy Details

### ExactMatchStrategy
- **Matching criteria**: Same file, line, and description
- **Use case**: When multiple scanners report the exact same finding
- **Conservative**: Only matches with 100% confidence

### LocationAndCVEStrategy
- **Matching criteria**: Same location + (same CVE OR same CWE)
- **Use case**: Findings from different scanners at the same vulnerability
- **Less strict**: Allows minor description variations

### CVEOnlyStrategy
- **Matching criteria**: Same CVE identifier
- **Use case**: Finding same known CVE across codebase (dependency detection)
- **Broad**: Can match across different files and projects
- **Requires CVE**: Only works for officially published CVEs

### CWEOnlyStrategy
- **Matching criteria**: Same CWE + same location
- **Use case**: Matching SAST findings by weakness type
- **Source priority**: semgrep > zap > trivy (specialization)

### DefaultStrategy
- **Chaining**: ExactMatch → LocationAndCVE → CVEOnly
- **Recommended**: Balances precision and recall
- **Hierarchical**: Uses most specific strategy first

## Database Changes

### New Schema (`002_dedupe.sql`)

```sql
-- Add columns to findings table
ALTER TABLE findings ADD COLUMN dedupe_group_id TEXT;
ALTER TABLE findings ADD COLUMN is_canonical BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN dedup_reason TEXT;

-- New dedupe_groups table
CREATE TABLE dedupe_groups (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    representative_finding_id TEXT NOT NULL REFERENCES findings(id),
    finding_count INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

### Indexes
- `idx_findings_dedupe_group_id`: For querying by group
- `idx_findings_is_canonical`: For filtering canonical findings
- `idx_dedupe_groups_scan_id`: For querying by scan

## Testing

### Test Coverage

```bash
cd orchestrator
go test -v ./internal/dedupe/...
```

**Test cases** (45 assertions):
- Exact match strategy (6 scenarios)
- Location+CVE strategy (4 scenarios)
- CVE-only strategy (3 scenarios)
- Canonical selection (3 scenarios, with priorities)
- Marking findings (dedupe group assignment)
- Default strategy (multi-level matching)
- Statistics calculation
- Strategy factory function

### Test Data

Two new test files in `testdata/sarif/`:
- `trivy-with-duplicates.sarif`: 2 unique findings
- `semgrep-with-duplicates.sarif`: Same 2 findings (triggers dedup)

## Implementation Notes

### Design Decisions

1. **In-memory grouping**: Dedup happens before DB storage for efficiency
2. **Canonical selection**: Single representative per group, not voting
3. **Strategy composition**: DefaultStrategy chains simpler strategies
4. **No schema version table**: Migration ordering is manual (001_init → 002_dedupe)
5. **Conservative defaults**: ExactMatch strategy used when strategy not specified

### Performance

- **Time complexity**: O(n²) for grouping (where n = findings per scan)
- **Typical scan**: <1000 findings → <10ms dedup time
- **Memory**: One Group struct per unique finding (minimal overhead)

### Edge Cases Handled

- Empty finding list → returns empty groups
- Single finding → creates one-member group (canonical = true)
- No matching strategy → all findings are unique
- Multiple identical findings → highest-priority one selected deterministically

## Verification Commands

```bash
# Run all dedup tests
go test -v ./internal/dedupe/...

# Run with coverage
go test -cover ./internal/dedupe/...

# Build and check for lint errors
go vet ./...
go build -o /dev/null ./cmd/orchestrator

# Integration test (after docker-compose up):
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d @testdata/sarif/trivy-with-duplicates.sarif
```

## Next Phase

Phase 3 (Context Building) will:
- Extract code snippets from vulnerable locations
- Gather dependency information
- Redact sensitive data
- Feed context to LLM for exploitability analysis

Deduplication results (canonical findings) will be input to Phase 3.
