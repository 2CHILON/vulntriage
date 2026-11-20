---
mode: agent
description: Phase 1 – unified model, SARIF parser, Postgres storage
---
Implement Phase 1 only, following `.github/copilot-instructions.md`.

Scope:
1. `orchestrator/internal/model/finding.go` – unified Finding struct
   (id, source, severity, file, line, cwe, cve, description).
2. `orchestrator/internal/parsers/sarif.go` – parse SARIF into Findings.
   Use the real files in `testdata/sarif/`.
3. `orchestrator/migrations/001_init.sql` – tables: scans, findings.
4. `orchestrator/internal/store/` – insert/list findings in Postgres.
5. `POST /api/v1/scans` – accepts SARIF, stores normalized findings.
6. `deploy/docker-compose.yml` – Postgres + orchestrator.

Out of scope: dedupe, LLM, GitHub issues, dashboard.

Acceptance:
- `go test ./...` passes using the fixtures.
- `docker compose up` works and a curl upload stores findings.

First give me a plan and wait for my "go". Create files one at a time.
When done, list the exact commands I should run to verify, then STOP.