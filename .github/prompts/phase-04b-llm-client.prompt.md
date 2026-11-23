---
agent: agent
description: Phase 4b – Go orchestrator calls the Python LLM service on canonical findings and stores the analyses
---
Implement Phase 4b of VulnTriage ONLY, following .github/copilot-instructions.md and the repo layout in it.

TOKEN BUDGET (strict):
- Never open files under testdata/sarif/ in full. Never re-read a file you just wrote.
- For test runs, show only the "--- FAIL" lines, the per-package ok/FAIL lines, and failure details. Show the complete output only if something fails.
- Keep each one-line file summary to one line.

BEFORE ANYTHING ELSE:
- Run `git branch --show-current`. If it is not `phase-4b-llm-client`, STOP and tell me.
- Run `go version`. Report it.
- Read: docs/phases/phase-04a-context-builder.md, docs/phases/phase-03-llm-service.md, llm-service/app/schemas.py (the exact request and response contract), orchestrator/internal/contextbuilder/types.go and builder.go (note: Build returns ONE value, a Context), orchestrator/internal/api/handlers.go, orchestrator/internal/api/fake_store.go, orchestrator/internal/dedupe/store_iface.go, orchestrator/internal/store/store.go, orchestrator/cmd/orchestrator/main.go, deploy/docker-compose.yml, .env.example. Summarize in at most 8 lines what exists. In particular report: how the severity ranking is implemented in the dedupe package, whether a "list canonical findings of a scan" store method already exists, how the scan router parses paths, and whether main.go sets any http.Server ReadTimeout/WriteTimeout.
- If the existing code contradicts this prompt, tell me instead of guessing.

GOAL: for one scan, send each CANONICAL finding (with its redacted context) to the Python LLM service, validate the answer again on the Go side, and store one current analysis per finding. Standard library only. No new Go dependency. Do NOT modify anything under llm-service/. If the Go client cannot match the Python contract exactly, STOP and tell me.

SCOPE (files only under orchestrator/, deploy/, docs/ and the root files named below):
1. orchestrator/migrations/003_analyses.sql – table analyses: finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, status TEXT NOT NULL (ok | analysis_failed | skipped), exploitable BOOLEAN NULL, confidence DOUBLE PRECISION NULL, priority TEXT NULL, reasoning TEXT, suggested_fix TEXT, provider TEXT, prompt_version TEXT, error TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(). Index on scan_id. One current analysis per finding (upsert); no history. This is the ONLY schema change allowed.
2. orchestrator/internal/llmclient/ (types.go, client.go) – HTTP client for the Python service:
   - Request types whose JSON keys match schemas.py EXACTLY: finding {id, source, severity, file, line, cwe, cve, description}, context {code_snippet, dependency_usage}. Response: finding_id, status, result {exploitable, confidence, reasoning, suggested_fix, priority}, error, provider, prompt_version.
   - Analyze(ctx, req) (Response, error) and Health(ctx) error (GET /health, 2 second timeout).
   - Per-request timeout (LLM_CLIENT_TIMEOUT_SECONDS, default 30), response body capped at 1 MiB (io.LimitReader), at most ONE retry on network errors and 5xx with a short backoff, context cancellation respected, no redirect following.
   - Do NOT trust the service: reject unknown status values, confidence outside 0..1, priority outside critical|high|medium|low, an empty reasoning when status is ok, and a response whose finding_id differs from the request.
   - Error values must be safe: no full URLs, no response bodies, no request contents.
3. orchestrator/internal/analysis/service.go – AnalyzeScan(ctx, scanID, opts) (Summary, error). Depends only on small interfaces defined in this package (finding source, analysis store, context builder, LLM client) so it can be tested with fakes and has no import cycle.
   - Only CANONICAL findings are analyzed. Non-canonical findings are never sent anywhere.
   - Findings below ANALYSIS_MIN_SEVERITY (default "medium"; reuse the existing severity ranking, do not duplicate it) are stored with status "skipped" and error "below minimum severity". Never silently dropped.
   - A finding that already has status "ok" is skipped unless opts.Force is true (this protects real API cost). Findings with analysis_failed are retried.
   - ANALYSIS_MAX_FINDINGS (default 100) caps how many findings are sent per run. The rest are counted as not_attempted.
   - Bounded concurrency (ANALYSIS_CONCURRENCY, default 4) using only sync and channels. ANALYSIS_TIMEOUT_SECONDS (default 300) is the overall deadline; when it hits, remaining findings are not_attempted and finished results are kept.
   - One finding failing NEVER stops the batch: store status "analysis_failed" with a safe error string.
   - Send the context from contextbuilder (Build then ToLLMContext). Before storing, run contextbuilder.Redact over the LLM's reasoning and suggested_fix (a model can echo secret-like text).
   - Never log code, context, reasoning or API keys. Log only finding ID, status and counts.
   - Summary { ScanID, Considered, AnalyzedOK, AnalysisFailed, SkippedExisting, SkippedLowSeverity, NotAttempted, Provider }.
4. Store: extend the Store interface, the Postgres implementation and the in-memory fake with UpsertAnalysis, GetAnalysis(findingID), ListAnalysesByScan (canonical findings only), and a canonical-findings-by-scan method if one does not exist.
5. API handlers (same router style as the existing ones):
   - POST /api/v1/scans/{id}/analyze with optional ?force=true. 404 for an unknown scan. If llmclient.Health fails BEFORE any work starts, return 503 with a short message and store nothing. Otherwise 200 with the Summary.
   - GET /api/v1/scans/{id}/analyses – list of {finding_id, status, exploitable, confidence, priority, reasoning, suggested_fix, provider, prompt_version, error, updated_at}. 404 for an unknown scan.
   - GET /api/v1/scans/{id}/findings/{findingID}/analysis – one analysis, 404 if the scan, finding or analysis does not exist.
6. orchestrator/cmd/orchestrator/main.go – wiring only. Read LLM_SERVICE_URL (default http://localhost:8000), LLM_CLIENT_TIMEOUT_SECONDS, ANALYSIS_CONCURRENCY, ANALYSIS_MIN_SEVERITY, ANALYSIS_MAX_FINDINGS, ANALYSIS_TIMEOUT_SECONDS. If an http.Server ReadTimeout or WriteTimeout is lower than ANALYSIS_TIMEOUT_SECONDS, tell me in the plan instead of silently changing it.
7. deploy/docker-compose.yml – for the orchestrator service add LLM_SERVICE_URL=http://llm-service:8000 and a depends_on on llm-service with condition service_healthy (verify the llm-service healthcheck from Phase 3 exists). Do not change other services. .env.example: add the new variables with comments, placeholders only.
8. Tests (standard library, table-driven, no network except httptest servers, no real database):
   - llmclient: success; 500 then retry then error; 500 then 200 succeeds on retry; invalid JSON; invalid status, confidence, priority; empty reasoning with status ok; mismatched finding_id; oversized body; slow server beyond the client timeout; cancelled context; the marshalled request contains ONLY the allowed keys listed in item 2.
   - analysis (fake store, fake client, fake context builder): non-canonical findings are never sent; a runtime-built secret placed in a temp source file NEVER appears in any request the fake client recorded (use the real contextbuilder over t.TempDir() for this one); one failing finding does not stop the others; existing ok is skipped, Force re-analyzes; below-severity findings stored as skipped; ANALYSIS_MAX_FINDINGS cap gives not_attempted; observed maximum concurrency never exceeds the configured limit; overall timeout leaves remaining findings not_attempted and keeps finished results; a secret-looking string in the LLM's reasoning is redacted before it is stored; a rerun gives identical counts (idempotent).
   - handlers: 404 unknown scan; 503 when Health fails and nothing is stored; correct Summary numbers; both GET endpoints.
   - Build every secret-looking string at runtime from pieces. No secret-shaped literal in any committed file.
9. docs/phases/phase-04b-llm-integration.md – what was built, the contract, the cost guards, and an honest LIMITATIONS section: the analyze endpoint is synchronous (no job queue), redaction is best-effort and must be reviewed before pointing at a real provider, one current analysis per finding (no history).

OUT OF SCOPE: scoring, GitHub issues, dashboard, CI changes, any change to llm-service/, any new Go dependency, anything under .github/, async job queues.

RULES:
- First give me a short plan listing files in order and WAIT for my "go".
- Create ONE file at a time with a one-line summary after each.
- From orchestrator/ run `gofmt -l .` (must print nothing), `go vet ./...` and `go test ./... -count=1` (output limited as in TOKEN BUDGET).
- NEVER create binaries: no plain `go build`. If needed: `go build -o /dev/null ./cmd/orchestrator` (PowerShell: `-o NUL`).
- Do NOT run `docker compose down -v` or touch my database volume. Migration 003 will NOT apply to an existing volume; in your final instructions give me the exact commands to reset it.
- Do NOT run state-changing git commands (add, commit, push, branch, merge, reset).
- Do NOT weaken a test to make it pass. If something fails, report the real reason.

WHEN DONE, give me exactly this and then STOP:
A. Live verification commands (Git Bash): reset the volume and start all three services; upload semgrep-with-duplicates.sarif and trivy-with-duplicates.sarif into one scan_id (use the real request format of the upload handler); call dedupe; call POST analyze; GET analyses; call analyze a second time and show that existing results are skipped; call analyze with ?force=true. State what output I should expect (the mock provider answers every reply with a "MOCK PROVIDER" reasoning prefix; a context file may be "not found" because the fixture paths do not exist in sample-repo, which is fine).
B. A SELF-AUDIT table, one row per scope item 1 to 9, with PASS, FAIL or NOT DONE and EVIDENCE (a file path, or a test name copied from the test output). Count rows correctly. No PASS without evidence.
C. `git status --short` output, confirming nothing under .github/ or llm-service/ changed, no binary, no go.mod or go.sum change.
D. ONE COMMIT MESSAGE PER FILE: every created or modified file with its own conventional-commit message in a sensible order (dependencies first), then a copy-pasteable bash block with one line per file: git add <path> && git commit -m "<message>".
E. The branch name (phase-4b-llm-client), a PR title and a PR description.
Then say "Phase 4b complete – awaiting review".