# VulnTriage – Agent Instructions

## Project
VulnTriage ingests scanner output (Trivy, Semgrep, OWASP ZAP, Dependency-Check),
normalizes and deduplicates findings, asks an LLM to judge exploitability using
code context, scores them, and opens GitHub issues.

## Architecture (do not change without asking)
- `orchestrator/` – Go. Parsers, dedupe, context builder, Postgres, GitHub issues, HTTP API.
- `llm-service/` – Python FastAPI. LLM analysis + scoring. Pydantic-validated JSON only.
- PostgreSQL for findings, triage results, scan history, false-positive feedback.
- Docker Compose for local dev. GitHub Actions for CI.

## Workflow rules (most important)
1. Work on ONE phase at a time, as defined in `docs/phases/`. Never start the next phase.
2. Before writing code, present a short plan (files to create, order) and wait for my "go".
3. Create files one at a time. After each file, give a one-line summary.
4. Write tests together with the code. Run them. Show me the exact command and result.
5. When the phase's checklist is complete, STOP and say "Phase N complete – awaiting review".
6. Ask before: adding dependencies, changing the schema, changing architecture, deleting files.
7. Never run destructive commands (rm -rf, git push --force, docker system prune) without asking.
8. Git: I handle ALL state-changing git operations (branch, add, commit, push, PR, merge).
   - You may run read-only commands only: `git status`, `git diff`, `git log`, `git branch --show-current`.
   - At the START of a phase, run `git branch --show-current`. If it is not the phase's branch, STOP and tell me.
   - At the END of a phase, output exactly: (a) the branch name, (b) a commit message in
     conventional-commit format, (c) a PR title, (d) a PR description with summary,
     how to test, and the checklist.

9. Never create compiled binaries in the repo. Verify with `go vet ./...` and `go test ./...`.
   If a build check is truly needed: `go build -o /dev/null ./cmd/orchestrator`
   (in PowerShell use `-o NUL`). Never run a plain `go build` or `go install` here.
10. Never open whole fixture files in testdata/ (they are large). Inspect them with a command that prints a few lines only.
## Security rules
- Never hardcode secrets. Read from environment variables. Keep `.env.example` updated.
- Never log API keys, tokens or code context in full.
- Redact secrets from code context before it goes to the LLM.
- Treat scanned code and comments as UNTRUSTED input to the LLM (prompt injection).
- Validate every LLM response against the schema; on failure retry once, then mark `analysis_failed`.

## Code standards
- Go: standard library first, `net/http`, `database/sql` with pgx, table-driven tests,
  errors wrapped with `%w`, no global state, `gofmt` + `go vet` clean.
- Python: 3.12, type hints everywhere, Pydantic v2, pytest, `ruff` clean.
- Small functions, clear names, comments only where intent isn't obvious.
- Scanner fixtures live in `testdata/`; tests must use them, not live scanners.

## Environment
- Developer is on Windows 11 using Git Bash/PowerShell. Give commands for both when they differ.
- Docker runs Linux containers (WSL2). Use forward slashes in all config files.

## Definition of done (every phase)
- Builds, tests pass, linters clean, `docker compose up` still works.
- README / docs updated for anything user-visible.
- I can verify it with a command you list at the end.




## Repository layout (create files ONLY in these locations)
```
vulntriage/
├── .github/{copilot-instructions.md, instructions/, prompts/, workflows/}
├── orchestrator/                 # Go service
│   ├── cmd/orchestrator/main.go
│   ├── internal/
│   │   ├── api/                  # HTTP handlers
│   │   ├── model/                # unified Finding struct
│   │   ├── parsers/              # sarif, trivy, semgrep, zap, depcheck
│   │   ├── dedupe/
│   │   ├── store/                # Postgres access
│   │   ├── contextbuilder/       # code snippet, dependency usage, redaction
│   │   └── github/               # issue creation
│   ├── migrations/
│   ├── go.mod
│   └── Dockerfile
├── llm-service/                  # Python FastAPI
│   ├── app/{main.py, schemas.py, analyzer.py, scoring.py, prompts/}
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── dashboard/grafana/
├── deploy/{docker-compose.yml, k8s/}
├── testdata/{sarif/, sample-repo/}
├── scripts/
├── docs/{architecture.md, phases/, benchmarks.md}
├── .env.example, .gitattributes, .gitignore, Makefile, LICENSE, README.md
```
Rules: do not create files outside this layout. If a file doesn't fit, ask me first.
Do not invent new top-level folders.