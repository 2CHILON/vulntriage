---
agent: agent
description: Phase 4a – context builder with secret redaction, path safety and dependency usage
---
Implement Phase 4a of VulnTriage ONLY, following .github/copilot-instructions.md and the repo layout in it.

BEFORE ANYTHING ELSE:
- Run `git branch --show-current`. If it is not `phase-4a-context-builder`, STOP and tell me.
- Run `go version`. Report it.
- Read docs/architecture.md, docs/phases/phase-02-dedupe.md (or phase-2-dedupe.md), orchestrator/internal/model/finding.go, orchestrator/internal/dedupe/normalize.go (NormalizePath), orchestrator/internal/api/handlers.go, orchestrator/internal/api/fake_store.go, orchestrator/internal/store/store.go, orchestrator/cmd/orchestrator/main.go, deploy/docker-compose.yml, .env.example, .gitignore. Parse testdata/sarif/trivy.sarif and semgrep.sarif mentally: look at what Finding.File and Finding.Description contain for Trivy findings (lockfile paths? package names inside the message?). Summarize in at most 8 lines what exists and what you saw.
- If the existing code contradicts this prompt, tell me instead of guessing.

GOAL: for one stored finding, build SAFE context to send to the LLM service later: a code snippet around the flagged line (for source findings) or dependency usage (for dependency findings), with secrets redacted BEFORE anything leaves this process. Standard library only. Do NOT add any dependency. Do NOT change the database schema. Do NOT store code snippets in the database.

SCOPE (files only under orchestrator/, deploy/, docs/, testdata/sample-repo/ and the root files named below):
1. orchestrator/internal/contextbuilder/types.go
   - Config { SourceRoot string; ContextLines int (default 20); MaxContextChars int (default 8000); MaxFileBytes int (default 1048576); MaxFilesScanned int (default 5000) }
   - Context { FindingID, Kind ("code"|"dependency"|"none"), CodeSnippet, SnippetStartLine, SnippetEndLine, DependencyUsage, Reachability, RedactionCount int, WithheldReason string }
   - Reachability { Package, Status ("imported"|"not_imported"|"unknown"), Evidence []string (max 5), FilesScanned int }
   - A method ToLLMContext() returning the two strings the Python service expects: code_snippet and dependency_usage.
2. orchestrator/internal/contextbuilder/paths.go
   - ResolveSafePath(root, findingFile string) (absPath string, err error). Map the finding path to a repo-relative path using the SAME normalization as dedupe.NormalizePath (reuse it, do not duplicate logic). Reject: empty root, absolute paths that escape, any ".." traversal, and symlinks that resolve outside the root (use filepath.EvalSymlinks and check the prefix). Always use forward-slash normalization first (Windows).
   - IsSensitiveFile(name string) bool. Withheld, NEVER read: .env and .env.*, *.pem, *.key, *.p12, *.pfx, id_rsa*, id_ed25519*, credentials*, .npmrc, .pypirc, *.tfvars, *.tfstate, secrets.* . Case-insensitive.
3. orchestrator/internal/contextbuilder/redact.go
   - Redact(text string) (redacted string, count int). Replace each match with [REDACTED:<type>]. Cover: PEM private key blocks (BEGIN ... PRIVATE KEY through END, multi-line, whole block), AWS access key IDs, GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_), Slack tokens (xox*), Google API keys (AIza...), Stripe live keys (sk_live_), JWTs (three base64url parts starting eyJ), "Bearer <token>" headers, URLs with embedded credentials (scheme://user:pass@host), and generic assignments where the key name contains secret, token, password, passwd, pwd, api_key, apikey, auth or credential and the value is 8+ characters (quoted or unquoted, = or : separators).
   - Over-redaction is acceptable; UNDER-redaction is not. Fail closed.
   - Redact must be idempotent: Redact(Redact(x)) equals Redact(x).
4. orchestrator/internal/contextbuilder/snippet.go
   - Read the file (skip if larger than MaxFileBytes, or if it looks binary: contains a NUL byte). REDACT THE ENTIRE FILE CONTENT FIRST, THEN cut the window of ContextLines before and after the flagged line. (Reason: a private key whose BEGIN line is outside the window must not leak its body lines inside the window.)
   - Prefix lines with their numbers and mark the flagged line, e.g. "42: code" and ">> 43: code". Cap at MaxContextChars after redaction. Line 0 or a missing file means no snippet, with a WithheldReason, never an error.
5. orchestrator/internal/contextbuilder/dependency.go
   - ExtractPackageName(finding) (name string, ok bool): derive the package name from Finding.Description using what the real Trivy fixture contains. Do NOT change the schema or the parser. If it cannot be determined, return ok=false.
   - FindImports(cfg, packageName) Reachability: walk SourceRoot, skipping node_modules, .git, vendor, dist, build, .venv, __pycache__ and any sensitive file. Only these extensions: .js .jsx .ts .tsx .mjs .cjs .py .go. Respect MaxFileBytes and MaxFilesScanned. Detect: JS/TS import from 'pkg' / require('pkg') / dynamic import('pkg') including subpaths like 'pkg/sub'; Python import pkg / from pkg import; Go import "pkg" (including subpackages). Evidence entries look like "path:line: <redacted line>" (max 5).
   - The DependencyUsage text MUST state: "Direct imports only; transitive dependencies are not traced, so not_imported does NOT prove the package is unused."
6. orchestrator/internal/contextbuilder/builder.go
   - Builder with Build(f model.Finding) (Context, error). Classify: if the file basename is a manifest or lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, package.json, go.mod, go.sum, requirements.txt, Pipfile.lock, poetry.lock, pom.xml, build.gradle) then Kind "dependency" (NO snippet from the lockfile); otherwise Kind "code". If SourceRoot is empty, return Kind "none" with WithheldReason "source root not configured". Return an error only for programmer errors, never for missing or unreadable files.
   - Never log snippets, evidence lines, or raw file content. Log only finding ID, kind, redaction count and withheld reason.
7. Tests (standard library testing, table-driven, in the same package):
   - redact_test.go: one case per pattern. Build every secret-looking string AT RUNTIME by concatenating pieces (for example "AKIA" + "ABCDEFGHIJKLMNOP") so no secret-shaped literal exists anywhere in the repo (GitHub push protection can block the push otherwise). Assert the original is gone, [REDACTED:...] is present and the count is right. Also: a PEM block fully removed; ordinary code lines unchanged; idempotence; a PEM block whose BEGIN line is OUTSIDE the snippet window leaves no key material in the snippet.
   - paths_test.go: ".." traversal, absolute path, symlink escape (t.Skip with a reason if the OS refuses to create the symlink), normal path inside root, path prefix handling consistent with dedupe.NormalizePath, and every pattern in IsSensitiveFile.
   - snippet_test.go (use t.TempDir() files): window clipping at file start and end, line numbering and the >> marker, line 0 gives no snippet, missing file gives a WithheldReason, oversized file withheld, binary file withheld, MaxContextChars cap, a file containing a runtime-built secret never appears unredacted in the snippet.
   - dependency_test.go: ExtractPackageName run over the findings parsed from the REAL testdata/sarif/trivy.sarif (assert that every dependency finding either yields a name or ok=false, do not assert exact counts); FindImports on testdata/sample-repo (lodash imported in the JS file, yaml in the Python file, an unknown package gives not_imported); node_modules is skipped (temp-dir test); MaxFilesScanned is respected; the transitive-dependency sentence is present in DependencyUsage.
   - builder_test.go: code finding gives a snippet; lockfile finding gives Kind "dependency" and no snippet; empty SourceRoot gives Kind "none"; a sensitive file is withheld and its content never read; ToLLMContext maps correctly.
8. testdata/sample-repo/ – BENIGN fixture files only, containing NO secret-looking strings: app/db.go (a small function that builds a SQL string by concatenation, with a known line number), app/server.js (uses require('lodash')), app/util.py (import yaml), package.json (lists lodash). Replace the placeholder .gitkeep only if it is now redundant, and tell me instead of deleting it.
9. API: add GET /api/v1/scans/{scanID}/findings/{findingID}/context. Handlers depend on a small ContextProvider interface (Build(model.Finding)). Extend the api's store interface with a way to get one finding if it is missing, and update the fake store. Response: the Context as JSON. Unknown scan or finding gives 404. If SourceRoot is not configured, return 200 with Kind "none" and the WithheldReason. Handler tests with the fake store and a fake or real builder over t.TempDir(): 200 with context, 404 for unknown scan, 404 for unknown finding, and a runtime-built secret in the source file never appears in the HTTP response body.
10. orchestrator/cmd/orchestrator/main.go – read SOURCE_ROOT and CONTEXT_LINES from the environment, build the Builder, inject it. Keep main.go as wiring only.
11. deploy/docker-compose.yml – for the orchestrator service add env SOURCE_ROOT=/src and a READ-ONLY volume ${SOURCE_DIR:-../testdata/sample-repo}:/src:ro (check the relative path against the compose file's own location). Do not change other services. .env.example: add SOURCE_DIR= and CONTEXT_LINES=20 with comments, placeholders only.
12. docs/phases/phase-04a-context-builder.md – what was built, the output contract, the redaction patterns, and an honest LIMITATIONS section: regex redaction is best-effort and must be reviewed before any real provider is used; direct imports only; no enclosing-function extraction yet.

OUT OF SCOPE: calling the Python LLM service from Go and storing verdicts (that is Phase 4b), scoring, GitHub issues, dashboard, CI changes, schema changes, new dependencies, anything under .github/.

RULES:
- First give me a short plan listing files in order, then WAIT for my "go".
- Create ONE file at a time with a one-line summary after each.
- Run `go vet ./...`, `gofmt -l .` and `go test ./... -count=1 -v` from orchestrator/ and show me the real, complete output. `gofmt -l .` must print nothing.
- NEVER create binaries: no plain `go build`. If needed: `go build -o /dev/null ./cmd/orchestrator` (PowerShell: `-o NUL`).
- Do NOT run `docker compose down -v` or touch my database volume.
- Do NOT run state-changing git commands (add, commit, push, branch, merge, reset).
- Do NOT weaken a test to make it pass. If something fails, report the real reason.
- Do NOT put any realistic secret, key, token or PEM text in any committed file, including tests and docs. Build them at runtime from pieces.

WHEN DONE, give me exactly this and then STOP:
A. Verification: how to run the orchestrator with SOURCE_DIR pointing at testdata/sample-repo, upload testdata/sarif/semgrep-with-duplicates.sarif (use the real request format of the upload handler), list the findings to get a finding ID, and curl the new context endpoint for it. Git Bash syntax.
B. A SELF-AUDIT table, one row per scope item 1 to 12, with PASS, FAIL or NOT DONE and EVIDENCE for each (a file path, or a test name copied from the go test -v output). Count rows correctly. No PASS without evidence.
C. `git status --short` output, confirming nothing under .github/ changed, no binary, no migration, no go.mod change.
D. ONE COMMIT MESSAGE PER FILE: every created or modified file with its own conventional-commit message, in a sensible commit order (dependencies first), then a copy-pasteable bash block with one line per file: git add <path> && git commit -m "<message>".
E. The branch name (phase-4a-context-builder), a PR title and a PR description.
Then say "Phase 4a complete – awaiting review".