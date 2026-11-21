---
agent: agent
description: Phase 2b – fix finding ID collisions and make dedupe span the whole scan
---
Implement Phase 2b ONLY, following .github/copilot-instructions.md. This is a bug-fix phase for Phase 2.

BEFORE ANYTHING ELSE:
- Run `git branch --show-current`. If it is not `phase-2b-dedupe-fix`, STOP and tell me.
- Read docs/phases/phase-2-dedupe.md, orchestrator/internal/dedupe/, orchestrator/internal/parsers/sarif.go, orchestrator/internal/store/store.go, and the upload handler in orchestrator/cmd/orchestrator/main.go. Summarize in at most 6 lines how Finding IDs are built and where dedupe runs today.

PROBLEMS TO FIX (confirmed by investigation):
1. Finding ID is derived from scan_id + ruleId + file only. Two scanners reporting the same rule at the same file collide, and `ON CONFLICT (id) DO NOTHING` silently drops the second finding (data loss).
2. Dedupe only runs inside a single upload, so findings added to a scan by a later upload are never compared with earlier ones.

REQUIRED CHANGES:
1. New ID scheme: a stable hash of scan_id, source, ruleId, file, line, column and message. If two results inside the SAME upload still produce the same ID, append a deterministic ordinal suffix so no finding is ever dropped. Different sources must never collide.
2. Re-uploading the identical file into the same scan must stay idempotent, but must no longer be silent: the upload response gets `skipped_existing` (count of findings that already existed).
3. Create one shared function DedupeScan(ctx, scanID) that loads ALL findings of the scan, clears their existing dedupe fields and groups, runs the existing Dedupe engine, and writes the results back in ONE transaction. Safe to call repeatedly.
4. The upload handler calls DedupeScan after storing, so a later upload into an existing scan_id re-dedupes the whole scan. The response reports stats for the whole scan.
5. Add POST /api/v1/scans/{id}/dedupe that calls DedupeScan and returns the stats (404 for an unknown scan).

TESTS (no real database for handler tests, use the fake Store):
- Same CVE, file and line from two different sources: different IDs, both stored, one dedupe group, exactly one canonical.
- Fixture invariant: uploading testdata/sarif/trivy.sarif stores exactly 54 findings and semgrep.sarif exactly 25. No finding lost.
- trivy-with-duplicates.sarif then semgrep-with-duplicates.sarif into the SAME scan_id: 4 findings stored, 2 groups, 2 canonical.
- Uploading the same file twice: nothing duplicated, skipped_existing equals the file's finding count.
- DedupeScan called twice gives identical results.
- Unknown scan_id on the dedupe endpoint returns 404.

RULES:
- Do NOT rewrite the matching strategies in internal/dedupe beyond what these changes need. Do NOT modify any file under .github/.
- Avoid schema changes. If one is truly needed, use migrations/003_*.sql and give me exact commands to apply it (do not run `docker compose down -v`).
- Give a short plan listing files in order and WAIT for my "go". Create one file at a time with a one-line summary.
- Run `go vet ./...` and `go test ./...` from orchestrator/ and show the real output. Never create binaries (no plain `go build`).
- No state-changing git commands.
- When done, give me exact curl verification commands for the duplicate-fixture scenario in the same scan_id, then the branch name, a conventional commit message, a PR title and a PR description. Then STOP and say "Phase 2b complete – awaiting review".