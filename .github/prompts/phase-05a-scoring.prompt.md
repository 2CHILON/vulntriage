---
agent: agent
description: Phase 5a – deterministic risk scoring engine, stored scores, ranked API
---
Implement Phase 5a of VulnTriage ONLY, following .github/copilot-instructions.md and the repo layout in it.

TOKEN BUDGET (strict):
- Never open files under testdata/sarif/ in full. Never re-read a file you just wrote.
- For test runs show only "--- FAIL" lines, per-package ok/FAIL lines and failure details. Show the full output only if something fails.
- Keep each one-line file summary to one line.

BEFORE ANYTHING ELSE:
- Run `git branch --show-current`. If it is not `phase-5a-scoring`, STOP and tell me.
- Run `go version`. Report it.
- Read: docs/phases/phase-04b-llm-integration.md, docs/phases/phase-04a-context-builder.md, orchestrator/internal/model/finding.go, orchestrator/internal/analysis/service.go, orchestrator/internal/contextbuilder/builder.go and types.go, orchestrator/internal/dedupe/normalize.go, orchestrator/internal/api/handlers.go and fake_store.go, orchestrator/internal/store/store.go, orchestrator/cmd/orchestrator/main.go, deploy/docker-compose.yml, .env.example. Summarize in at most 8 lines. In particular report: how severity ranking is implemented (reuse it, do not duplicate it), which store method lists a scan's canonical findings, how analyses are stored, and how the 4b analyze handler responds when a scan has no canonical findings (mirror that behaviour).
- If the existing code contradicts this prompt, tell me instead of guessing.

GOAL: compute a transparent 0-100 risk score and a priority for every CANONICAL finding of a scan, store it, and serve a ranked list. Standard library only. No new Go dependency. Do NOT modify anything under llm-service/. Scoring is a PURE, DETERMINISTIC function with an explainable breakdown. No network calls anywhere in this phase.

FORMULA (implement exactly; every component is a number from 0 to 1):
- severity component: critical 1.00, high 0.75, medium 0.50, low 0.25, note or unknown 0.10. (This is a stand-in for CVSS; the real CVSS number is not stored yet.)
- llm component: analysis status "ok" and exploitable: 0.5 + 0.5*confidence. Status "ok" and not exploitable: 0.5 - 0.5*confidence. No analysis, analysis_failed or skipped: 0.5 (neutral) with the note "LLM verdict unavailable".
- reachability component: dependency findings (the context builder classifies them): imported 1.0, not_imported 0.3, unknown 0.5. Code findings: 1.0. Source root not configured or anything unknown: 0.5.
- exposure component: normalized file path (reuse dedupe.NormalizePath) starting with any prefix in EXPOSURE_CRITICAL_PATHS (comma separated, default empty): 1.0. Otherwise starting with a prefix in EXPOSURE_LOW_PATHS (default "test/,tests/,testdata/,spec/,docs/,examples/"): 0.2. Otherwise 0.5.
- weights (env, defaults): SCORE_WEIGHT_SEVERITY 0.35, SCORE_WEIGHT_LLM 0.35, SCORE_WEIGHT_REACHABILITY 0.20, SCORE_WEIGHT_EXPOSURE 0.10. Each must be 0 or more and the sum above 0. Normalize them so they sum to 1. If any value is invalid, use the defaults and log one safe warning.
- score = round(100 * sum(weight_i * component_i)), clamped to 0..100, an int.
- priority: score 80 or more critical; 60 or more high; 40 or more medium; otherwise low.
- Ranking order everywhere: score descending, then severity rank descending, then finding ID ascending.

SCOPE (files only under orchestrator/, deploy/, docs/ and the root files named below):
1. orchestrator/migrations/004_finding_scores.sql – table finding_scores: finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100), priority TEXT NOT NULL, breakdown JSONB NOT NULL, computed_at TIMESTAMPTZ NOT NULL DEFAULT now(). Index on scan_id. This is the ONLY schema change allowed.
2. orchestrator/internal/scoring/ (types.go, weights.go, score.go):
   - Weights type with LoadWeights taking an env getter func (so tests do not touch the real environment).
   - Input { Severity string; Analysis *AnalysisInput (status, exploitable, confidence); ReachabilityStatus string; Kind string; File string }.
   - Result { Score int; Priority string; Breakdown } where Breakdown holds the weights used, the four components (name, value, weight, contribution, note) and the final score. It marshals to JSON.
   - Score(input, weights, exposureCfg) Result. Pure: no logging, no clock, no randomness, no I/O.
3. orchestrator/internal/contextbuilder/builder.go – ADD a small method ReachabilityFor(f model.Finding) (kind string, status string) that classifies the finding and, for dependency findings only, returns the import status via the existing dependency code. It must NOT read or snippet source files for code findings. If SourceRoot is empty it returns kind "none" and status "unknown". Add a test. Do not change any existing behaviour.
4. orchestrator/internal/scoring/service.go – ScoreScan(ctx, scanID) (Summary, error) depending only on small interfaces defined in this package (finding source, analysis source, reachability provider, score store). It scores ONLY canonical findings, then stores the scores in ONE transaction that replaces the scan's previous scores. Summary { ScanID, Scored int, WithoutAnalysis int, ByPriority map[string]int, Top []TopItem (up to 5: finding_id, score, priority) }. Unknown scan returns a not-found error type the handler maps to 404. A scan with no canonical findings behaves like the 4b analyze endpoint does (report what you found in the pre-read).
5. Store: extend the Store interface, the Postgres implementation and the in-memory fake with ReplaceScores(ctx, scanID, scores) and ListScoresByScan(ctx, scanID) (returns the ranked order described above, joined with the finding's source, severity, file, line, cve, cwe).
6. API handlers in the same router style as the existing ones:
   - POST /api/v1/scans/{id}/score – runs ScoreScan and returns the Summary. 404 for an unknown scan.
   - GET /api/v1/scans/{id}/scores – the ranked list: finding_id, score, priority, severity, source, file, line, cve, cwe, breakdown, computed_at. 404 for an unknown scan. Never return code snippets or any LLM text from this endpoint.
7. orchestrator/cmd/orchestrator/main.go – wiring only: the weight and path variables above. An adapter that satisfies the scoring reachability interface using contextbuilder.ReachabilityFor.
8. deploy/docker-compose.yml – pass the new env variables to the orchestrator service (do not change other services). .env.example: add the new variables with comments and the defaults above, placeholders only.
9. Tests (standard library, table-driven, no network, no real database):
   - scoring: one row per component rule above, including both branches of the llm component; weight normalization; invalid weights fall back to defaults; priority boundaries exactly at 39/40, 59/60, 79/80; the score is always an int from 0 to 100 for every combination of inputs (loop over all of them); MONOTONIC properties: with everything else equal, a higher severity never lowers the score, and for an exploitable verdict a higher confidence never lowers it (and for a not-exploitable verdict a higher confidence never raises it); determinism (same input twice gives an identical Result); the breakdown contributions sum to the score within rounding; the Breakdown JSON round-trips.
   - service (fakes): non-canonical findings are never scored; a canonical finding with no analysis is scored with neutral llm and counted in WithoutAnalysis; ranking order including both tie-breakers; a rerun gives identical scores (compare everything except timestamps); replacing scores removes rows of findings that are no longer canonical; unknown scan gives the not-found error.
   - contextbuilder: ReachabilityFor for a lockfile finding with a JS import in a temp dir, a code finding (no file read: prove it with a file that does not exist), and an empty SourceRoot.
   - handlers: 404 for both endpoints on an unknown scan, POST then GET returns the ranked list, and the GET response never contains snippet or reasoning fields.
   - Build every secret-looking string at runtime if one is needed at all. No secret-shaped literal in any committed file.
10. docs/phases/phase-05a-scoring.md – what was built, the exact formula and defaults, how to tune the weights, how to read a breakdown, and an honest LIMITATIONS section: severity stands in for CVSS, reachability means direct imports only, exposure is path-prefix based, weights are untuned guesses until the Phase 7 benchmark.

OUT OF SCOPE: GitHub issues (that is Phase 5b), any network call, dashboard, CI changes, any change to llm-service/, any new Go dependency, anything under .github/, changing existing endpoints.

RULES:
- First give me a short plan listing files in order and WAIT for my "go".
- Create ONE file at a time with a one-line summary after each.
- From orchestrator/ run `gofmt -l .` (must print nothing), `go vet ./...` and `go test ./... -count=1` (output limited as in TOKEN BUDGET).
- NEVER create binaries: no plain `go build`. If needed: `go build -o /dev/null ./cmd/orchestrator` (PowerShell: `-o NUL`).
- Do NOT run `docker compose down -v` or touch my database volume. Migration 004 will NOT apply to an existing volume; in your final instructions give me the exact commands to reset it.
- Do NOT run state-changing git commands (add, commit, push, branch, merge, reset).
- Do NOT weaken a test to make it pass. If something fails, report the real reason.

WHEN DONE, give me exactly this and then STOP:
A. Live verification commands (Git Bash): reset the volume and start the services; upload trivy-with-duplicates.sarif and semgrep-with-duplicates.sarif into one scan_id (use the real request format of the upload handler); call dedupe; call analyze; call POST score; GET scores; call POST score a second time and show the scores are identical; GET scores for an unknown scan (expect 404). State what output I should expect.
B. A SELF-AUDIT table, one row per scope item 1 to 10, with PASS, FAIL or NOT DONE and EVIDENCE (a file path, or a test name copied from the test output). Count rows correctly. No PASS without evidence.
C. `git status --short` output, confirming nothing under .github/ or llm-service/ changed, no binary, no go.mod or go.sum change.
D. ONE COMMIT MESSAGE PER FILE: every created or modified file with its own conventional-commit message in a sensible order (dependencies first), then a copy-pasteable bash block with one line per file: git add <path> && git commit -m "<message>".
E. The branch name (phase-5a-scoring), a PR title and a PR description.
Then say "Phase 5a complete – awaiting review".