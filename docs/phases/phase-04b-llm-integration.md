# Phase 4b – LLM integration (orchestrator → LLM service)

## What was built
The Go orchestrator sends each **canonical** finding of a scan, with its redacted
context, to the Python LLM service and stores **one current analysis per finding**.

```
POST /api/v1/scans/{id}/analyze[?force=true]
  ├─ 404 if the scan does not exist
  ├─ GET llm-service /health (2 s) ── fails → 503, nothing stored
  └─ analysis.AnalyzeScan
       ├─ ListCanonicalFindings (non-canonical findings are never sent)
       ├─ sort by severity (critical first), then ID
       ├─ status "ok" already stored and !force → skipped_existing
       ├─ below ANALYSIS_MIN_SEVERITY        → stored as "skipped"
       ├─ beyond ANALYSIS_MAX_FINDINGS       → not_attempted
       └─ worker pool (ANALYSIS_CONCURRENCY) under ANALYSIS_TIMEOUT_SECONDS
            contextbuilder.Build → ToLLMContext → llmclient.Analyze
            → validate → Redact(reasoning, suggested_fix) → UpsertAnalysis
```

| Component | File |
|---|---|
| Schema | `orchestrator/migrations/003_analyses.sql` |
| Severity ranking | `orchestrator/internal/model/severity.go` (`SeverityRank`) |
| Analysis record | `orchestrator/internal/model/analysis.go` |
| HTTP client | `orchestrator/internal/llmclient/{types.go,client.go}` |
| Batch service | `orchestrator/internal/analysis/service.go` |
| Store | `orchestrator/internal/store/store.go`, `orchestrator/internal/api/fake_store.go` |
| Endpoints | `orchestrator/internal/api/handlers.go` |
| Wiring | `orchestrator/cmd/orchestrator/main.go`, `deploy/docker-compose.yml`, `.env.example` |

### Endpoints
| Method and path | Result |
|---|---|
| `POST /api/v1/scans/{id}/analyze` | 200 with Summary; 404 unknown scan; 503 LLM service down; 400 invalid `force` |
| `GET /api/v1/scans/{id}/analyses` | 200 list of analyses of canonical findings (ordered by finding ID); 404 unknown scan |
| `GET /api/v1/scans/{id}/findings/{findingID}/analysis` | 200 one analysis; 404 if scan, finding or analysis does not exist |

Summary:
```json
{"scan_id":"demo","considered":2,"analyzed_ok":2,"analysis_failed":0,
 "skipped_existing":0,"skipped_low_severity":0,"not_attempted":0,"provider":"mock"}
```
Every considered finding is counted in exactly one of the other counters.

Analysis item: `finding_id, status (ok|analysis_failed|skipped), exploitable, confidence,
priority, reasoning, suggested_fix, provider, prompt_version, error, updated_at`.
`exploitable`, `confidence` and `priority` are `null` unless status is `ok`.

## The contract (llm-service/llm_service/app/schemas.py)
Request (`POST /analyze`). The service forbids extra keys; the Go client always sends
exactly these keys, with empty values as `null`:
```json
{"finding": {"id","source","severity","file","line","cwe","cve","description"},
 "context": {"code_snippet","dependency_usage"}}
```
Response: `finding_id, status (ok|analysis_failed), result {exploitable, confidence,
reasoning, suggested_fix, priority} | null, error, provider, prompt_version`.

### The Go side does not trust the service
`llmclient` rejects: unknown JSON keys, unknown `status`, `confidence` outside 0..1,
`priority` outside critical|high|medium|low, empty reasoning with status `ok`, `ok`
without a result, a `finding_id` different from the request, and bodies over 1 MiB.
Redirects are not followed. Error messages never contain URLs, response bodies or
request contents.

## Cost and safety guards
| Variable | Default | Effect |
|---|---|---|
| `LLM_SERVICE_URL` | `http://localhost:8000` (compose: `http://llm-service:8000`) | Base URL |
| `LLM_CLIENT_TIMEOUT_SECONDS` | 30 | Per request; one retry on network errors and 5xx |
| `ANALYSIS_CONCURRENCY` | 4 | Parallel requests (fixed worker pool) |
| `ANALYSIS_MIN_SEVERITY` | medium | Lower findings are stored as `skipped`, never sent |
| `ANALYSIS_MAX_FINDINGS` | 100 | Max findings sent per call; the rest are `not_attempted` |
| `ANALYSIS_TIMEOUT_SECONDS` | 300 | Overall deadline; also sets HTTP `WriteTimeout` (+15 s) |

- Findings with status `ok` are **not re-sent** unless `?force=true` (protects real API cost).
  `analysis_failed` findings are retried on the next call.
- One failing finding never stops the batch; it is stored as `analysis_failed` with a
  short, redacted error.
- When the overall deadline hits, finished results are kept and in-flight or queued
  findings are counted `not_attempted` with no row stored, so the next call picks them up.
- Context comes from the Phase 4a context builder (already redacted). The finding
  description is redacted too, and `contextbuilder.Redact` runs over the LLM's
  `reasoning`, `suggested_fix` and error text before storing.
- Logs contain only finding IDs, statuses and counts, never code, context, reasoning or keys.

## Database reset (migration 003 does not apply to an existing volume)
Postgres runs `docker-entrypoint-initdb.d` only on an empty volume. This deletes all local data:
```bash
cd deploy
docker compose down -v
docker compose up -d --build
```

## Tests
```bash
cd orchestrator && go test ./... -count=1
```
- `internal/llmclient`: success, retry on 500, invalid responses, oversized body, timeout,
  cancellation, the exact request keys.
- `internal/analysis`: non-canonical never sent, a secret in a source file never reaches a
  request (real context builder over `t.TempDir()`), failure isolation, skip and force,
  severity floor, cap, concurrency limit, overall timeout, reasoning redaction, idempotent reruns.
- `internal/api`: 404, 503 with nothing stored, Summary numbers, both GET endpoints.

## Limitations
- **Synchronous endpoint.** `POST /analyze` blocks until the batch finishes (up to
  `ANALYSIS_TIMEOUT_SECONDS`). There is no job queue, no progress endpoint and no
  protection against two concurrent analyze calls on the same scan (the last write wins).
- **Redaction is best-effort.** It is pattern-based (Phase 4a patterns) and will miss
  secrets of unknown shapes. Review it before pointing the service at a real provider;
  only the mock provider has been used so far.
- **One current analysis per finding, no history.** `force=true` overwrites the previous result.
- **Re-dedupe leaves stale rows.** If a later dedupe makes a finding non-canonical, its old
  analysis stays in the table but is hidden by both GET endpoints.
- **Live retries only on network errors and 5xx.** A 422 (contract mismatch) is not
  retried and is stored as `analysis_failed`.
- The mock provider's answers are not real analyses (reasoning starts with "MOCK PROVIDER").
