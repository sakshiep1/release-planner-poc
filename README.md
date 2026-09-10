# Cert-Manager Z-Stream Release Planner POC

A proof-of-concept tool for automating cert-manager z-stream release planning. Discovers CVEs from Jira Vulnerability tickets and govulncheck, classifies fix complexity, estimates engineering effort, and generates a suggested release schedule.

**Jira:** CM-1217 | **Epic:** CM-1143 | **Sprint:** OAPE Sprint 293

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Import cached CVE evidence and run full pipeline
python -m src.cli.main run --evidence ~/cm-1222-evidence-20260805/operator-analyze-cve --output release-plan.md

# Or step by step:
python -m src.cli.main config show
python -m src.cli.main import ~/cm-1222-evidence-20260805/operator-analyze-cve
python -m src.cli.main classify
python -m src.cli.main estimate
python -m src.cli.main plan
python -m src.cli.main matrix
python -m src.cli.main report --output release-plan.md
```

## Web Dashboard

```bash
# Install dependencies
pip install -r requirements.txt
pip install cursor-sdk   # optional, for Full Analysis

# Set Jira credentials in config.json (or via env vars — env overrides config)
# Also set jira.enabled: true in releases.yaml

# Start backend API
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Start frontend (in another terminal)
cd web && npm install && npm run dev   # http://localhost:5173
```

Or use `make dev` to start both.

### Prerequisites

| Tool | Purpose |
|------|---------|
| Python 3.10+ | Backend |
| `JIRA_EMAIL` + `JIRA_TOKEN` + `JIRA_BASE_URL` | Jira CVE discovery (Quick Scan) |
| `govulncheck` | Delta CVE discovery (`go install golang.org/x/vuln/cmd/govulncheck@latest`) |
| `git` | Branch checkout / auto-clone |
| `CURSOR_API_KEY` | Full Analysis only (analyze-cve via Cursor SDK) |
| Compliance plugin | ai-helpers `compliance:analyze-cve` skill for Full Analysis |

> **Note:** Access to Jira Vulnerability tickets requires your account to have the
> appropriate security level permissions in the Jira project. Contact your Jira admin
> if you get empty results from Quick Scan.

### Scan modes

- **Quick Scan (Jira)** — Queries Jira Vulnerability tickets for the selected branch (~2s). Returns real CVEs with severity, CVSS, CWE, affected images, and SLA deadlines. Maps Jira ticket status to verdicts automatically.
- **Full Analysis** — Jira discovery + govulncheck delta scan + analyze-cve enrichment via Cursor SDK. Most complete but slowest. Configure analysis filters in `releases.yaml` under `scanner:`.
- **govulncheck-only** — Legacy mode, runs govulncheck without Jira. All CVEs stored with UNKNOWN severity.

### Jira credentials (`config.json`)

```json
"jira": {
  "url": "https://redhat.atlassian.net",
  "email": "your-redhat-email@redhat.com",
  "api_token": "your-atlassian-api-token"
}
```

Also set `jira.enabled: true` in `releases.yaml`. Environment variables (`JIRA_EMAIL`, `JIRA_TOKEN`, `JIRA_BASE_URL`) override `config.json` if set.

Set `CURSOR_API_KEY` in `config.json` under `scanner` (or env) for Full Analysis.

```bash
export PATH=$PATH:$HOME/go/bin
```

```bash
# Legacy quick start via Makefile
make backend   # http://localhost:8000 (Swagger at /docs)

# Start frontend (in another terminal)
cd web && npm install && npm run dev   # http://localhost:5173

# Import data via API
curl -X POST http://localhost:8000/api/v1/branches/sync
curl -X POST http://localhost:8000/api/v1/scans/import \
  -H 'Content-Type: application/json' \
  -d '{"evidence_path": "/home/spatidar/cm-1222-evidence-20260805/operator-analyze-cve"}'
curl -X POST http://localhost:8000/api/v1/plan/generate
```

## Architecture

```
Input Sources           Processing Pipeline          Output
─────────────          ────────────────────         ──────
Jira Vuln JQL   ──►    Jira Discovery (primary)──►  SQLite DB
govulncheck     ──►    Delta Scanner           ──►      │
evidence.json   ──►    Evidence Importer        ──►     ▼
releases.yaml   ──►    Config Loader            ──►  FastAPI API ──► React Dashboard
                       Fix Classifier           ──►  CLI Reports
                       Effort Estimator         ──►  Markdown Report
                       Plan Generator           ──►
```

## Configuration

Edit `releases.yaml` to configure:
- Release branches and OCP version mappings
- Support windows (start/end dates, EUS flag)
- CVE analysis filters (`scanner.min_cve_year`, `max_analyze_per_branch`, `analyze_cve_allowlist`)
- Effort estimation defaults (hours per fix type)
- Urgency rules (SLA days for CRITICAL/HIGH CVEs)

Set `CURSOR_API_KEY` in your shell for Full Analysis. Leave `scanner.cursor_api_key` empty in `config.json`.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/branches` | GET | List release branches |
| `/api/v1/branches/sync` | POST | Sync branches from config |
| `/api/v1/cves` | GET | List CVEs |
| `/api/v1/cves/{cve_id}` | GET | CVE detail with evidence |
| `/api/v1/matrix` | GET | CVE-branch applicability matrix |
| `/api/v1/plan` | GET | Current release plan |
| `/api/v1/plan/generate` | POST | Generate release plan |
| `/api/v1/effort` | GET | Effort summary per branch |
| `/api/v1/report` | GET | Markdown report |
| `/api/v1/scans/import` | POST | Import cached evidence |
| `/api/v1/scans/run` | POST | Trigger scan (`jira`, `govulncheck`, or `full`) |

## Testing

```bash
python -m pytest tests/ -v
```

## Tech Stack

- **Backend:** Python 3.10+, FastAPI, SQLAlchemy (async), SQLite
- **Frontend:** React, TypeScript, Vite, Tailwind CSS
- **CLI:** Click
- **CVE Discovery:** Jira Vulnerability tickets (primary) + govulncheck (delta)
- **Evidence Format:** Compatible with OAPE-390 compliance plugin output
