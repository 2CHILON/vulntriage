---
agent: agent
description: Phase 2 – deduplicate findings, persist groups, expose via API
---
Implement Phase 2 of VulnTriage ONLY, following .github/copilot-instructions.md and the repo layout in it.

BEFORE ANYTHING ELSE:
- Run `git branch --show-current`. If it is not `phase-2-dedupe`, STOP and tell me.
- Phase 1 is merged and working. Read these first, then summarize what already exists in at most 8 lines: docs/architecture.md, orchestrator/internal/model/finding.go, orchestrator/internal/parsers/sarif.go, orchestrator/internal/store/store.go, the handlers in orchestrator/internal/api/, orchestrator/migrations/001_init.sql, deploy/docker-compose.yml.
- Inspect the Finding.File values the parser produces from testdata/sarif/trivy.sarif and testdata/sarif/semgrep.sarif. The two were scanned from different mount points, so their path forms may differ. Report what you see.
- If the existing code contradicts this prompt, tell me instead of guessing.

GOAL: group duplicate/overlapping findings within one scan, store the groups, and report before/after counts.

DEDUPE RULES (in this priority order):
A. Finding has a CVE: group by normalized file + CVE.
B. No CVE but has a CWE: group by normalized file + CWE, then cluster by line proximity. Sort by line; a finding joins the current cluster if its line is within LineWindow (default 3) of the previous finding in that cluster (chaining allowed: lines 10, 13, 16 are one cluster). Line 0 or unknown lines are never clustered; each stays its own group.
C. No CVE and no CWE: every finding is its own group. Never guess.

SCOPE:
1. orchestrator/internal/dedupe/normalize.go – NormalizePath(p string, stripPrefixes []string) string: backslashes to forward slashes, trim "./" and leading "/", strip configured mount prefixes. Pick the default prefixes from what you saw in the fixtures.
2. orchestrator/internal/dedupe/dedupe.go:
   - Options { LineWindow int; StripPrefixes []string }
   - Group { Fingerprint, Kind ("cve"|"cwe"|"single"), CVE, CWE, File, Line, Severity (highest member), Sources []string (unique, sorted), Representative model.Finding, MemberIDs []string (sorted) }
   - Stats { Before, After int; ReductionPct float64 }
   - Dedupe(findings []model.Finding, opts Options) ([]Group, Stats)
   - Representative = highest severity member; ties broken deterministically (source name, then ID).
   - Fingerprint = stable hash of (kind, CVE-or-CWE, normalized file, cluster index within that key ordered by line). Document in a comment that line shifts can change it and that Phase 5 may refine it.
   - Output must be deterministic: same input in any order gives the same output order (severity desc, file, line, fingerprint).
3. orchestrator/internal/dedupe/dedupe_test.go – table-driven:
   - path normalization cases
   - CVE merge across two different sources (build these Finding structs in the test and comment that they are synthetic unit-test inputs, since the Trivy and Semgrep fixtures will rarely overlap)
   - proximity boundaries: lines 10 and 13 merge, 10 and 14 do not, 10/13/16 chain into one
   - different CWE, different file, and unknown line (0) are NOT merged
   - highest severity wins, Sources unique and sorted
   - determinism: shuffle the input, expect identical output
   - fixture run: parse both real SARIF fixtures, run Dedupe, then assert INVARIANTS only: every input finding ID appears in exactly one group, the sum of len(MemberIDs) equals Before, After <= Before. Do not assert exact reduction numbers.
4. orchestrator/migrations/002_finding_groups.sql – table finding_groups (id, scan_id FK, fingerprint, kind, cve, cwe, file, line, severity, sources, member_count, representative_finding_id) and a nullable findings.group_id FK. Add indexes on scan_id and fingerprint.
5. orchestrator/internal/store/ – extend the Store interface and the Postgres implementation: SaveGroups(ctx, scanID, groups) which replaces any existing groups for that scan in ONE transaction and sets findings.group_id; ListGroups(ctx, scanID); plus anything else needed (e.g. ScanExists, ListFindings by scan). Keep existing methods working.
6. orchestrator/internal/api/:
   - POST /api/v1/scans gets an optional query param `scan_id`. If present, the uploaded findings are appended to that existing scan (404 if it does not exist). This lets Trivy and Semgrep results land in the SAME scan.
   - POST /api/v1/scans/{id}/dedupe – loads all findings of the scan, runs Dedupe, saves groups, returns Stats as JSON, and logs one line: dedupe scan=<id> before=<N> after=<M> reduction=<X>%. It must be safe to call repeatedly.
   - GET /api/v1/scans/{id}/groups – returns the groups as JSON.
   - Handler tests using a fake Store (no real database): success, unknown scan (404), append via scan_id, repeated dedupe call.
7. docs/phases/phase-02-dedupe.md – short: what was built, the rules, how to verify. A future chat will read this.

OUT OF SCOPE: LLM service, context builder, GitHub issues, scoring, dashboard, CI changes, new dependencies.

RULES:
- First give me a short plan listing files in order, then WAIT for my "go".
- Create ONE file at a time with a one-line summary after each.
- After the code is written, run `go vet ./...` and `go test ./...` from orchestrator/ and show me the real output.
- NEVER create binaries. Do not run plain `go build`. If a build check is needed use `go build -o /dev/null ./cmd/orchestrator` (PowerShell: `-o NUL`). After testing, run `git status` and confirm no binary appears.
- Do NOT run `docker compose down -v` and do not touch my database volume. Migration 002 will NOT apply to an existing Postgres volume, because initdb.d only runs on first init. In your final instructions, give me the exact commands to apply it (both options: recreate the volume, or run the SQL with docker exec and psql).
- Do NOT run git add, commit, push or any state-changing git command.
- When done, give me: exact verification commands (create a scan by uploading trivy.sarif, upload semgrep.sarif into the SAME scan using scan_id, call the dedupe endpoint, then GET the groups), then the branch name, a conventional commit message, a PR title and a PR description. Then STOP and say "Phase 2 complete – awaiting review".