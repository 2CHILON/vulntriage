# Phase 4b: LLM Client Integration

## Overview

Phase 4b implements the Go orchestrator's integration with the Python LLM service for analyzing vulnerability findings. The orchestrator now:

1. **Calls the LLM service** via HTTP for exploitability analysis of canonical findings
2. **Manages concurrency** with bounded goroutines (default 4 concurrent requests)
3. **Enforces timeouts** per-request (LLM client) and per-scan (overall analysis)
4. **Redacts secrets** from LLM responses before storage
5. **Stores analysis results** in a new `analyses` table with status, confidence, priority, and reasoning
6. **Exposes analysis endpoints** for querying results by scan or finding

## Architecture

```
Orchestrator (Phase 2 output: canonical findings)
        ↓
Analysis Service:
  - Filter by minimum severity (default "medium")
  - Skip existing status "ok" (unless forced)
  - Cap at ANALYSIS_MAX_FINDINGS (default 100)
  - Bounded concurrency (default 4)
        ↓
Per Finding:
  - Build context (code snippet, dependencies)
  - Create LLM request
  - POST /analyze to Python LLM service
  - Validate response
  - Redact reasoning and suggested_fix
  - Upsert to analyses table
        ↓
Summary { ScanID, Considered, AnalyzedOK, AnalysisFailed, SkippedExisting, SkippedLowSeverity, NotAttempted, Provider }
        ↓
HTTP 200
```

## Scope Completed

### 1. Schema (003_analyses.sql)

**Table:** `analyses`

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `finding_id` | TEXT | PK, FK→findings | Identifies the finding |
| `scan_id` | TEXT | FK→scans | Scan this analysis belongs to |
| `status` | TEXT | NOT NULL, CHECK | "ok" \| "analysis_failed" \| "skipped" |
| `exploitable` | BOOLEAN | NULL | True if vulnerability is exploitable |
| `confidence` | DOUBLE | NULL, [0–1] | LLM's confidence in the analysis |
| `priority` | TEXT | NULL, CHECK | "critical" \| "high" \| "medium" \| "low" |
| `reasoning` | TEXT | | Why the finding is or isn't exploitable |
| `suggested_fix` | TEXT | | Recommended remediation (if applicable) |
| `provider` | TEXT | | "mock" or future real provider name |
| `prompt_version` | TEXT | | Prompt template version used (e.g., "v1") |
| `error` | TEXT | | If status is "analysis_failed", why |
| `updated_at` | TIMESTAMPTZ | DEFAULT now() | Audit timestamp |

**Index:** `idx_analyses_scan_id` for efficient scan queries.

**One current analysis per finding:** Upsert on `finding_id` replaces previous result.

### 2. LLM Client (orchestrator/internal/llmclient/)

**Types (types.go):**
- `Finding`: id (required), source (required), severity, file, line, cwe, cve, description
- `ContextInput`: code_snippet, dependency_usage
- `AnalyzeRequest`: finding, context (optional)
- `AnalysisResult`: exploitable, confidence (0–1), reasoning (non-empty), suggested_fix, priority (critical|high|medium|low)
- `AnalyzeResponse`: finding_id, status (ok|analysis_failed), result, error, provider, prompt_version

**Client (client.go):**

```go
// Create a client
client := llmclient.NewClient(baseURL, requestTimeout)

// Check health (2-second timeout)
err := client.Health(ctx)

// Analyze a finding (per-request timeout, 1 retry on 5xx/net errors)
response, err := client.Analyze(ctx, request)
```

**Features:**
- Per-request timeout from `LLM_CLIENT_TIMEOUT_SECONDS` (default 30s)
- Response body capped at 1 MiB (via `io.LimitReader`)
- Up to 2 total attempts (1 initial + 1 retry on 5xx or network errors)
- 100ms backoff between retries
- Context cancellation respected
- No redirect following
- Validation: reject unknown status, out-of-bounds confidence, invalid priority, empty reasoning with status "ok", mismatched finding_id
- Error strings sanitized: no URLs, response bodies, or secrets

### 3. Analysis Service (orchestrator/internal/analysis/)

**Service Interface:**

```go
analysisService := analysis.NewService(
    store,           // AnalysisStore implementation
    builder,         // ContextBuilder (or any implementation of Build())
    llmClient,       // LLMClient (or any implementation of Analyze())
    concurrency,     // Max concurrent requests (default 4)
    maxFindings,     // Max findings per scan (default 100)
    minSeverity,     // Skip findings below this severity (default "medium")
    overallTimeout,  // Per-scan deadline (default 300s)
)

summary, err := analysisService.AnalyzeScan(ctx, scanID, analysis.Options{
    Force: false, // If true, re-analyze existing "ok" results
})
```

**Processing:**

1. **Load canonical findings** for the scan from the database
2. **Severity filtering:** Skip findings below `minSeverity`; store with status "skipped"
3. **Existing check:** Skip findings with status "ok" unless `Force=true`
4. **Max findings cap:** Only send up to `maxFindings` to LLM; count rest as "not_attempted"
5. **Bounded concurrency:** Use channel semaphore to limit concurrent goroutines
6. **Per-scan timeout:** Apply overall deadline; mark remaining findings "not_attempted" on timeout
7. **Per-finding processing:**
   - Build context via contextbuilder
   - Create LLM request with finding data and context
   - Call LLM client
   - Validate response
   - **Redact** reasoning and suggested_fix via `contextbuilder.Redact()`
   - Upsert to database with status "ok" or "analysis_failed"
8. **Return summary** with counts and provider name

**Logging:**
- Finding ID, status, provider name only
- **No logging** of code, context, reasoning, or secrets

**Severity Ranking:**
- Uses existing ranking from dedupe package: critical (4) > high (3) > medium (2) > low (1)
- Minimum severity checked via integer rank, not string comparison

### 4. Store Extension

**New methods added to both PostgreSQL and in-memory FakeStore:**

```go
// Upsert an analysis (one per finding, replaces previous)
err := store.UpsertAnalysis(ctx, &Analysis{...})

// Get analysis for a finding
analysis, err := store.GetAnalysis(ctx, findingID)

// List analyses for a scan (canonical findings only)
analyses, err := store.ListAnalysesByScan(ctx, scanID)

// List canonical findings (already existed, now used by analysis service)
findings, err := store.ListCanonicalFindings(ctx, scanID)
```

**Analysis type:**

```go
type Analysis struct {
    FindingID     string
    ScanID        string
    Status        string // "ok" | "analysis_failed" | "skipped"
    Exploitable   *bool
    Confidence    *float64
    Priority      *string
    Reasoning     string
    SuggestedFix  string
    Provider      string
    PromptVersion string
    Error         string
}
```

### 5. API Handlers

**New endpoints:**

#### POST /api/v1/scans/{id}/analyze?force=true

Analyze all canonical findings for a scan.

**Query parameters:**
- `force=true` (optional): Re-analyze findings with status "ok"

**Responses:**

- **200 OK:** Analysis started and completed
  ```json
  {
    "scan_id": "scan-123",
    "considered": 25,
    "analyzed_ok": 20,
    "analysis_failed": 2,
    "skipped_existing": 1,
    "skipped_low_severity": 2,
    "not_attempted": 0,
    "provider": "mock"
  }
  ```

- **404 Not Found:** Scan does not exist

- **503 Service Unavailable:** LLM service is unreachable (returned BEFORE any work starts)

**Special behavior:**
- Uses `http.NewResponseController` to extend write deadline to `ANALYSIS_TIMEOUT_SECONDS + 15s`
- If deadline extension fails, logs warning and continues
- Respects overall analysis timeout; findings not completed by deadline are counted "not_attempted"

#### GET /api/v1/scans/{id}/analyses

List all analyses for a scan (canonical findings only).

**Response (200 OK):**
```json
[
  {
    "finding_id": "finding-123",
    "scan_id": "scan-123",
    "status": "ok",
    "exploitable": true,
    "confidence": 0.95,
    "priority": "high",
    "reasoning": "redacted: code...",
    "suggested_fix": "Use parameterized queries",
    "provider": "mock",
    "prompt_version": "v1",
    "error": null
  },
  ...
]
```

- **404 Not Found:** Scan does not exist

#### GET /api/v1/scans/{id}/findings/{findingID}/analysis

Retrieve a single analysis for a finding.

**Response (200 OK):**
```json
{
  "finding_id": "finding-123",
  "scan_id": "scan-123",
  "status": "ok",
  "exploitable": true,
  "confidence": 0.95,
  "priority": "high",
  "reasoning": "redacted: code...",
  "suggested_fix": "Use parameterized queries",
  "provider": "mock",
  "prompt_version": "v1",
  "error": null
}
```

- **404 Not Found:** Scan, finding, or analysis does not exist

### 6. Configuration (Environment Variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `LLM_SERVICE_URL` | http://localhost:8000 | Python LLM service base URL |
| `LLM_CLIENT_TIMEOUT_SECONDS` | 30 | Per-request timeout for LLM calls |
| `ANALYSIS_CONCURRENCY` | 4 | Max concurrent LLM requests |
| `ANALYSIS_MIN_SEVERITY` | medium | Skip findings below this severity |
| `ANALYSIS_MAX_FINDINGS` | 100 | Max findings per scan to send to LLM |
| `ANALYSIS_TIMEOUT_SECONDS` | 300 | Overall deadline for a scan analysis (0 < x ≤ 900) |

**Validation:**
- `ANALYSIS_TIMEOUT_SECONDS`: If 0 or > 900, falls back to 300 and logs warning

### 7. Docker Compose

**Orchestrator service additions:**
- Env vars: `LLM_SERVICE_URL`, `LLM_CLIENT_TIMEOUT_SECONDS`, `ANALYSIS_*`
- `depends_on` llm-service with `condition: service_healthy`

**Example:**
```yaml
orchestrator:
  environment:
    LLM_SERVICE_URL: http://llm-service:8000
    ANALYSIS_TIMEOUT_SECONDS: 300
  depends_on:
    llm-service:
      condition: service_healthy
```

### 8. Testing

**Standard library only. Table-driven tests. No network except httptest servers.**

#### llmclient (client_test.go)

- ✅ Success response
- ✅ 500 error → retry → success
- ✅ 500 error → retry → error
- ✅ Invalid JSON response
- ✅ Invalid status value rejected
- ✅ Confidence out of bounds rejected
- ✅ Invalid priority rejected
- ✅ Empty reasoning with status "ok" rejected
- ✅ Finding ID mismatch rejected
- ✅ Response body > 1 MiB rejected
- ✅ Slow server (timeout)
- ✅ Cancelled context
- ✅ Request JSON contains ONLY allowed keys (no extras)

#### analysis service (service_test.go)

- ✅ Non-canonical findings never sent
- ✅ Secret-like string never appears in request (temp file + real context builder)
- ✅ One finding failure does not stop others
- ✅ Existing status "ok" skipped; `Force` re-analyzes
- ✅ Below-min-severity findings stored as "skipped"
- ✅ MAX_FINDINGS cap; excess counted "not_attempted"
- ✅ Observed concurrency never exceeds configured limit
- ✅ Timeout: remaining findings "not_attempted", finished results kept
- ✅ LLM reasoning redacted before storage
- ✅ Rerun is idempotent (same counts, unless `Force=true`)

#### handlers (handlers_test.go)

- ✅ POST /analyze: 404 unknown scan
- ✅ POST /analyze: 503 when LLM Health fails (before any work)
- ✅ POST /analyze: 200 with correct Summary
- ✅ GET /analyses: 404 unknown scan; lists analyses
- ✅ GET /findings/{id}/analysis: 404 not found; returns single analysis

#### main (main_test.go, real httptest server)

- ✅ Server with 200ms WriteTimeout, fake analysis service takes ~600ms
- ✅ POST /analyze returns 200 with analysis response
- ✅ Other endpoints keep the short (10s) WriteTimeout
- ✅ Deadline extension via ResponseController works

## Workflow

### Request Flow: POST /api/v1/scans/{id}/analyze

```
Client
  │
  └─→ POST /api/v1/scans/{id}/analyze?force=true
       │
       ├─ Handler.HandleAnalyzeScan
       │   ├─ Verify scan exists
       │   ├─ Check LLM health (2s timeout)
       │   ├─ Extend write deadline to (timeout + 15s)
       │   │
       │   └─ AnalyzeScan(ctx, scanID, Options{Force: true})
       │       │
       │       ├─ Load canonical findings
       │       ├─ Filter by severity
       │       ├─ Check existing status "ok" (skip unless Force)
       │       ├─ Cap at MAX_FINDINGS
       │       │
       │       └─ Per finding (bounded to 4 concurrent):
       │           ├─ Build context
       │           ├─ Create LLM request
       │           ├─ Client.Analyze(ctx, request)
       │           │   ├─ POST /analyze to llm-service
       │           │   ├─ Validate response
       │           │   └─ Retry on 5xx / network error
       │           ├─ Redact reasoning and suggested_fix
       │           └─ UpsertAnalysis(ctx, result)
       │
       └─ Return 200 with Summary
           {
             "scan_id": "...",
             "analyzed_ok": 18,
             "analysis_failed": 2,
             ...
           }
```

## Cost Guards

### 1. Minimum Severity Filter

Findings below "medium" are stored as skipped, never sent to LLM. Saves cost on low-priority findings.

### 2. MAX_FINDINGS Cap

Only the first 100 findings (by default) per scan are sent to LLM. Remaining are "not_attempted". Prevents runaway cost on large scans.

### 3. Existing Status "ok" Skip

If a finding was already analyzed with status "ok", it is skipped on re-runs unless `?force=true`. Avoids redundant LLM calls.

### 4. Per-Request Timeout

Default 30s per LLM call. Network hangs are cut short.

### 5. Per-Scan Timeout

Default 300s overall. If not all findings finish in time, remainder are "not_attempted". Prevents indefinite job duration.

### 6. Redaction Before Storage

Secrets from reasoning and suggested_fix are redacted before storage. Reduces risk of leaking secrets in logs or analysis output.

## Limitations

### 1. Synchronous Analysis

The `/analyze` endpoint is **synchronous**: it holds the HTTP connection for up to `ANALYSIS_TIMEOUT_SECONDS + 15s` while processing findings. This is suitable for small to medium scans but becomes unwieldy for very large scans.

**Future fix:** Implement an async job queue with 202 Accepted response and polling endpoint.

### 2. Connection Timeout

The HTTP server's `WriteTimeout` is 10 seconds globally. The `/analyze` endpoint extends this to `ANALYSIS_TIMEOUT_SECONDS + 15s` via `http.NewResponseController`, but **reverse proxies or load balancers with shorter timeouts will terminate the connection early**. Workaround: configure upstream proxies to allow longer timeouts.

### 3. Redaction is Best-Effort

The `contextbuilder.Redact()` function patterns match common secret shapes (API keys, tokens, credentials) but is not 100% accurate. **Review analysis output before pointing at real LLM providers.** A secret-like string in user comments or code may evade redaction.

### 4. One Analysis Per Finding

The schema enforces one current analysis per finding (upsert on `finding_id`). No history is retained. If you need to compare analyses over time, snapshot the results externally.

### 5. Mock Provider Only

Phase 4b uses only the MockProvider (from Phase 3). Real provider support is deferred. Follow TODO(REAL-LLM) markers in llm-service/ for where to implement real API calls.

## Example Workflow

### Setup

```bash
cd deploy
docker compose up -d
```

Verify services are ready:
```bash
curl http://localhost:8080/health
curl http://localhost:8000/health
```

### Upload a Scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "semgrep-2024",
    "tool_name": "semgrep",
    "sarif_data": {...}
  }'
```

### Deduplicate

```bash
curl -X POST http://localhost:8080/api/v1/scans/semgrep-2024/dedupe
```

### Analyze (Using Mock Provider)

```bash
curl -X POST http://localhost:8080/api/v1/scans/semgrep-2024/analyze
```

Expected response (all findings get "MOCK PROVIDER" reasoning):
```json
{
  "scan_id": "semgrep-2024",
  "considered": 10,
  "analyzed_ok": 8,
  "analysis_failed": 0,
  "skipped_existing": 0,
  "skipped_low_severity": 2,
  "not_attempted": 0,
  "provider": "mock"
}
```

### Retrieve Analyses

```bash
curl http://localhost:8080/api/v1/scans/semgrep-2024/analyses
```

### Single Finding

```bash
curl http://localhost:8080/api/v1/scans/semgrep-2024/findings/finding-sql-01/analysis
```

## Files Created/Modified

### Created
- `orchestrator/migrations/003_analyses.sql`
- `orchestrator/internal/llmclient/types.go`
- `orchestrator/internal/llmclient/client.go`
- `orchestrator/internal/analysis/service.go`
- `docs/phases/phase-04b-llm-integration.md`

### Modified
- `orchestrator/internal/api/handlers.go` – Added HandleAnalyzeScan, HandleListAnalyses, HandleGetAnalysis
- `orchestrator/internal/api/fake_store.go` – Added analysis methods
- `orchestrator/internal/store/store.go` – Added UpsertAnalysis, GetAnalysis, ListAnalysesByScan
- `orchestrator/cmd/orchestrator/main.go` – Wired LLM client, analysis service, timeout validation
- `deploy/docker-compose.yml` – Added LLM env vars and depends_on
- `.env.example` – Added new configuration variables

### No Changes
- `llm-service/` – Zero modifications to Python service
- `.github/` – No changes

## Tests Included

All tests use standard library only. Table-driven. Fakes for dependencies. One real httptest server test for deadline extension behavior.

Run tests:
```bash
cd orchestrator
go test ./... -count=1 -v
```

---

**Status:** ✅ **Phase 4b complete.** Orchestrator can now call LLM service, store analyses, and expose analysis endpoints.
