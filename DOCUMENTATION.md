# Release Planner POC — Detailed Technical Documentation

**Project:** Cert-Manager Z-Stream Release Planner  
**Epic:** CM-1143 — Automated CVE tracking, classification, effort estimation & release planning  
**Repository:** `openshift/cert-manager-operator`  
**Generated:** September 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [The Analysis Pipeline](#3-the-analysis-pipeline)
   - 3.1 [Stage 1: Jira Discovery](#31-stage-1-jira-discovery)
   - 3.2 [Stage 2: analyze-cve Enrichment (Cursor SDK)](#32-stage-2-analyze-cve-enrichment-cursor-sdk)
   - 3.3 [Stage 3: Fix Type Classification](#33-stage-3-fix-type-classification)
   - 3.4 [Stage 4: Effort Estimation & T-shirt Sizing](#34-stage-4-effort-estimation--t-shirt-sizing)
   - 3.5 [Stage 5: Release Plan Generation](#35-stage-5-release-plan-generation)
4. [Report Generation](#4-report-generation)
5. [Data Provenance: Fact vs Inference vs Assumption](#5-data-provenance-fact-vs-inference-vs-assumption)
6. [CVE Detail Panel — Data Sources](#6-cve-detail-panel--data-sources)
7. [Multi-Ticket Support (One CVE → Many Jira Tickets)](#7-multi-ticket-support-one-cve--many-jira-tickets)
8. [Repository Cloning & Branch Checkout](#8-repository-cloning--branch-checkout)
9. [SLA Rules & Urgency Policies](#9-sla-rules--urgency-policies)
10. [FedRAMP / GovCloud SLA Status](#10-fedramp--govcloud-sla-status)
11. [Configuration Reference](#11-configuration-reference)
12. [Prerequisites & Setup](#12-prerequisites--setup)
13. [Known Limitations](#13-known-limitations)
14. [Future Direction: Using LLMs for Release Planning](#14-future-direction-using-llms-for-release-planning)

---

## 1. Overview

The Release Planner POC automates the end-to-end workflow for z-stream release planning of the **cert-manager operator** across multiple OpenShift release branches. It replaces the manual process of:

- Pulling CVE data from Jira spreadsheets
- Manually checking which branches are affected
- Estimating fix complexity and engineering effort
- Deciding release dates and priorities

The tool provides a **single dashboard** where engineers and leads can:

- See all open CVEs across all branches in a matrix view
- Understand the fix complexity for each CVE (version bump, backport, etc.)
- Get automated effort estimates in person-days
- Generate a release plan with SLA-driven target dates
- Export a Markdown report for stakeholder reviews

---

## 2. Architecture

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend | Python 3.12+, FastAPI | REST API, pipeline orchestration |
| Frontend | React 18, TypeScript, TailwindCSS | Dashboard UI |
| Database | SQLite (aiosqlite) | Persistent storage |
| Real-time | Server-Sent Events (SSE) | Progress updates during analysis |
| CVE Analysis | Cursor SDK (`cursor-sdk` Python package) | Runs `analyze-cve` skill per CVE |
| Issue Tracker | Red Hat Jira REST API v3 | CVE discovery, ticket metadata |
| VCS | Git (auto-clone via `RepoManager`) | Branch checkout for analysis |

### Project Structure

```
Release Planner POC/
├── src/
│   ├── main.py                       # FastAPI app entrypoint
│   ├── api/v1/                       # API endpoints
│   │   ├── branches.py               # Branch sync/listing
│   │   ├── cves.py                   # CVE listing + detail
│   │   ├── matrix.py                 # CVE-Branch matrix
│   │   ├── scans.py                  # Trigger scans
│   │   ├── plan.py                   # Generate/view plans
│   │   ├── jira.py                   # Jira status/discovery
│   │   ├── events.py                 # SSE endpoint
│   │   └── router.py                 # Route aggregator
│   ├── models/                       # SQLAlchemy ORM models
│   │   ├── branch.py                 # ReleaseBranch
│   │   ├── cve.py                    # CVEEntry
│   │   ├── fix.py                    # BranchCVE, FixType enum
│   │   ├── plan.py                   # ReleasePlan, PlanItem
│   │   └── scan.py                   # ScanRun
│   ├── schemas/                      # Pydantic API schemas
│   │   ├── matrix.py                 # MatrixCell, MatrixRow, MatrixOut
│   │   ├── cve.py                    # CVEOut, CVEDetailOut, BranchCVEOut
│   │   ├── branch.py, plan.py, scan.py
│   ├── services/                     # Business logic
│   │   ├── cve_analyzer.py           # Pipeline orchestrator
│   │   ├── jira_discovery.py         # Jira REST API integration
│   │   ├── evidence_importer.py      # Parse analyze-cve evidence.json
│   │   ├── fix_classifier.py         # Fix type classification logic
│   │   ├── effort_estimator.py       # T-shirt sizing + hour estimates
│   │   ├── plan_generator.py         # Release plan from urgency rules
│   │   ├── report_generator.py       # Markdown report generation
│   │   ├── repo_manager.py           # Git clone/checkout management
│   │   └── config_loader.py          # releases.yaml parser
│   ├── core/                         # Framework utilities
│   │   ├── config.py                 # Settings from config.json
│   │   ├── dependencies.py           # FastAPI DI
│   │   └── sse.py                    # SSE broker
│   └── db/
│       ├── base.py                   # SQLAlchemy Base
│       └── engine.py                 # DB init + migration
├── web/                              # React frontend
│   ├── src/App.tsx                   # Main dashboard UI
│   └── src/types/index.ts           # TypeScript interfaces
├── tests/                            # pytest test suite (124 tests)
├── config.json                       # Server/DB/scanner config
├── releases.yaml                     # Branch/Jira/effort/SLA config
└── data/dashboard.db                 # SQLite database (auto-created)
```

### Data Model

```
ReleaseBranch (1) ──┐
                    ├── BranchCVE (many-to-many junction)
CVEEntry (1) ───────┘
     │
     └── jira_key, source, linked_prs, evidence_json

BranchCVE:
  - risk_level, confidence, dependency_type
  - current_version, symbol_reachable
  - fix_type (enum), effort_hours, effort_tshirt
  - linked_jira_tickets_json (all Jira tickets for this CVE on this branch)

ReleasePlan (1) ──── PlanItem (many)
  - target_date, urgency, estimated_effort_days, cve_ids
```

---

## 3. The Analysis Pipeline

The system executes a 5-stage pipeline when the user clicks **"Analyze Branch"**:

```
┌─────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│  Jira Discovery  │ ──▶ │  analyze-cve (SDK) │ ──▶ │  Fix Classifier   │
│  (Vulnerability  │     │  Per-CVE enrichment│     │  Heuristic rules  │
│   ticket query)  │     │  via Cursor agent  │     │                   │
└─────────────────┘     └───────────────────┘     └──────────────────┘
                                                          │
                              ┌──────────────────┐        │
                              │  Release Plan     │ ◀──── │
                              │  SLA-based dates  │        │
                              └──────────────────┘  ┌──────────────────┐
                                                    │ Effort Estimator  │
                                                    │ T-shirt + hours   │
                                                    └──────────────────┘
```

### 3.1 Stage 1: Jira Discovery

**Code:** `src/services/jira_discovery.py`, `src/services/cve_analyzer.py:discover_from_jira()`

**What it does:** Queries Red Hat Jira REST API v3 for **Vulnerability-type tickets** associated with a specific release branch.

**API Used:** `POST /rest/api/3/search/jql` with authentication via email + API token (basic auth).

**JQL Template:**
```
project = CM AND issuetype = Vulnerability
AND summary ~ "cert-manager-1.18"
AND statusCategory != Done
ORDER BY created DESC
```

**Custom Field Mappings (Red Hat Jira):**

| Custom Field | Jira Field ID | What It Contains |
|-------------|--------------|------------------|
| CVE ID | `customfield_10667` | The CVE identifier (e.g., CVE-2026-33186) |
| Severity | `customfield_10840` | Critical / Important / Moderate / Low |
| CVSS Score | `customfield_10859` | Score string like "9.1 CVSS:3.1/AV:N/AC:L/..." |
| Affected Image | `customfield_10669` | Downstream component (e.g., cert-manager-operator) |
| Upstream Component | `customfield_10632` | Go module path (e.g., golang.org/x/net) |
| CWE ID | `customfield_10630` | CWE classification |

**Severity Mapping:**

| Jira Severity | Internal Severity |
|--------------|------------------|
| Critical | CRITICAL |
| Important | HIGH |
| Moderate | MEDIUM |
| Low | LOW |

**Output:** For each Vulnerability ticket, the system creates:
- A `CVEEntry` record with severity, CVSS, module from Jira
- A `BranchCVE` junction record linking the CVE to the branch
- All Jira tickets for the same CVE are stored in `linked_jira_tickets_json` (deduped by ticket key)

**Important:** Jira discovery provides **severity, CVSS, and module** but does **NOT** provide:
- `dependency_type` (direct vs indirect) — defaults to `"unknown"`
- `current_version` — defaults to `""`
- `symbol_reachable` — defaults to `False`
- `fixed_version` — defaults to `None`

This means Jira-only data is insufficient for granular fix classification — that's why Stage 2 exists.

### 3.2 Stage 2: analyze-cve Enrichment (Cursor SDK)

**Code:** `src/services/cve_analyzer.py:_analyze_cve_with_sdk()`

**What it does:** For each CVE discovered from Jira, invokes the **Cursor SDK** to run the `analyze-cve` compliance skill against the repository checked out to the target branch.

**How it works:**

1. The `RepoManager` ensures the `openshift/cert-manager-operator` repository is available (auto-clones to `/tmp/release-planner-XXXX/` if no local path is configured)
2. The repo is checked out to the target branch (e.g., `git checkout cert-manager-1.18`)
3. For each CVE, the SDK runs:
   ```python
   Agent.prompt(
       "/compliance:analyze-cve CVE-2026-XXXXX",
       AgentOptions(
           api_key=cursor_api_key,
           model="composer-2.5",
           local=LocalAgentOptions(cwd=repo_path),
       ),
   )
   ```
4. The Cursor agent analyzes the CVE against the codebase and writes structured output to:
   ```
   .work/compliance/analyze-cve/<CVE-ID>/evidence.json
   ```
5. The `evidence_importer.py` parses this JSON and extracts enrichment data

**Data extracted by analyze-cve:**

| Field | Description | Source within analyze-cve |
|-------|------------|--------------------------|
| `risk_level` | CRITICAL / HIGH / MEDIUM / LOW / NOT_VULNERABLE | Agent's risk assessment |
| `confidence` | Confidence in the assessment (HIGH / MEDIUM / LOW) | Agent's confidence |
| `dependency_type` | "direct" or "indirect" | From `go.mod` module graph analysis |
| `current_version` | Version our code currently uses | From `go.mod` / `go.sum` |
| `symbol_reachable` | Whether vulnerable symbols are called | Static call graph analysis |
| `fixed_version` | Version that patches the vulnerability | From NVD / Go vuln DB / GHSA |
| `description` | Vulnerability description | From upstream advisory |
| `affected_package` | Specific vulnerable package | From advisory database |
| `vulnerable_versions` | Version range affected | From advisory database |

**Evidence JSON schemas supported:**
- `analyze_cve` — primary schema from the Cursor compliance plugin
- `operator` — flat operator-schema from earlier evidence format
- `operand` — nested schema from `codebase-impact-analysis` skill

**Risk level normalization:** The system normalizes risk level strings at ingestion:
- `"NOT VULNERABLE"` (with space) → `"NOT_VULNERABLE"`
- `"Not-Vulnerable"` (with dash) → `"NOT_VULNERABLE"`
- All converted to uppercase, underscored format

### 3.3 Stage 3: Fix Type Classification

**Code:** `src/services/fix_classifier.py:classify_single()`

**What it does:** Classifies each (branch, CVE) pair into one of five fix types using **deterministic heuristic rules**. This is entirely **inference** — no external system provides this classification.

#### Fix Type Definitions

| Fix Type | Enum Value | T-shirt | Meaning |
|----------|-----------|---------|---------|
| Version Bump | `VERSION_BUMP` | S | Update the dependency version in `go.mod` — a minor or patch version bump on a direct dependency, or a transitive dependency update |
| Trivial Backport | `TRIVIAL_BACKPORT` | M | A small code change is needed — the vulnerable symbol is reachable via an indirect dependency and the version gap is minor/patch |
| Non-Trivial Backport | `NON_TRIVIAL_BACKPORT` | L | Significant engineering work — the version gap crosses a major version boundary, potentially involving API changes |
| Needs Review | `NEEDS_REVIEW` | XL | Cannot be auto-classified — insufficient data (no fixed version, no current version, or unknown dependency type). Requires manual engineer assessment |
| Not Applicable | `NOT_APPLICABLE` | - | The CVE does not affect this branch — the risk is "NOT_VULNERABLE" or "NONE", or the risk is LOW and the vulnerable symbol is not reachable |

#### Classification Decision Tree

```
classify_single(branch_cve, cve_entry):
│
├─ risk_level is NOT_VULNERABLE or NONE?
│  └─ YES → NOT_APPLICABLE
│
├─ risk_level is LOW and symbol NOT reachable?
│  └─ YES → NOT_APPLICABLE
│
├─ risk_level is UNKNOWN and no current_version
│  and no fixed_version and dep_type is "unknown"?
│  └─ YES → None (unclassified, skip)
│
├─ No fixed_version known?
│  └─ YES → NEEDS_REVIEW
│
├─ No current_version known?
│  └─ YES → NEEDS_REVIEW
│
├─ Dependency type is "direct"?
│  ├─ Version gap is patch or minor?
│  │  └─ VERSION_BUMP
│  ├─ Version gap is major?
│  │  └─ NON_TRIVIAL_BACKPORT
│  └─ Version gap unknown?
│     └─ NEEDS_REVIEW
│
├─ Dependency type is "indirect"?
│  ├─ Symbol reachable?
│  │  ├─ Version gap is major?
│  │  │  └─ NON_TRIVIAL_BACKPORT
│  │  └─ Version gap is minor/patch?
│  │     └─ TRIVIAL_BACKPORT
│  └─ Symbol NOT reachable?
│     └─ VERSION_BUMP
│
└─ Unknown dependency type?
   └─ NEEDS_REVIEW
```

#### Version Gap Calculation

The classifier computes semantic version gaps by parsing semver strings:

```
_version_gap_size(current, fixed):
  Parse both as (major, minor, patch)
  If major differs → "major"
  If minor differs → "minor"
  If only patch differs → "patch"
  If either can't be parsed → "unknown"
```

Examples:
- `v0.38.0` → `v0.38.1` = **patch** gap → VERSION_BUMP for direct deps
- `v0.38.0` → `v0.39.0` = **minor** gap → VERSION_BUMP for direct deps
- `v0.38.0` → `v1.0.0` = **major** gap → NON_TRIVIAL_BACKPORT

#### Why Most CVEs Show as NEEDS_REVIEW (XL) with Jira-Only Data

When only Jira discovery runs (without analyze-cve), the BranchCVE records have:
- `dependency_type = "unknown"` (Jira doesn't know this)
- `current_version = ""` (Jira doesn't know this)
- `fixed_version = None` (Jira doesn't track this)

With these defaults, the classifier falls through to `NEEDS_REVIEW` because it doesn't have enough information to make a more specific classification. **To get S/M/L classifications, the analyze-cve enrichment (Stage 2) must run successfully.**

### 3.4 Stage 4: Effort Estimation & T-shirt Sizing

**Code:** `src/services/effort_estimator.py`

**What it does:** Assigns estimated engineering hours and a T-shirt size to each classified BranchCVE pair.

#### Effort Defaults (Configurable in `releases.yaml`)

| Fix Type | T-shirt Size | Default Hours | Rationale |
|----------|-------------|---------------|-----------|
| VERSION_BUMP | S (Small) | 3 hours | Update go.mod, run tests, submit PR |
| TRIVIAL_BACKPORT | M (Medium) | 8 hours | Small code change + test updates + review |
| NON_TRIVIAL_BACKPORT | L (Large) | 20 hours | Significant refactoring, API adaptation, extensive testing |
| NEEDS_REVIEW | XL (Extra Large) | 28 hours | Manual assessment + uncertain scope — treated as worst case |
| NOT_APPLICABLE | - (None) | 0 hours | No work needed |

**These are assumptions.** They are configurable in `releases.yaml` under `effort_defaults` and should be calibrated based on the team's historical velocity.

#### CVSS Severity Multiplier

For CVEs with **CVSS ≥ 9.0** (Critical severity), the base hours are multiplied by **1.2x** to account for:
- Expedited review and approval processes
- Additional testing and verification requirements
- Potential need for emergency release procedures

Example: A NEEDS_REVIEW CVE with CVSS 9.1 → `28h × 1.2 = 33.6h`

#### Testing Overhead Multiplier

All effort totals are multiplied by a **testing overhead factor** (default: **1.5x**) when aggregated at the branch level. This accounts for:
- QE testing time
- CI/CD pipeline runs
- Integration and regression testing
- Documentation updates

#### Aggregation Formula

For a branch with N actionable CVEs:

```
total_hours = Σ(individual CVE hours)
total_with_overhead = total_hours × testing_overhead_multiplier (1.5)
total_days = total_with_overhead / 8
```

Example: A branch with 5 VERSION_BUMPs (5×3=15h) and 2 NEEDS_REVIEW (2×28=56h):
```
total_hours = 15 + 56 = 71h
with overhead = 71 × 1.5 = 106.5h
person_days = 106.5 / 8 = 13.3 days
```

### 3.5 Stage 5: Release Plan Generation

**Code:** `src/services/plan_generator.py`

**What it does:** Creates a draft release plan that groups CVEs by urgency tier and assigns target release dates based on SLA rules.

#### Urgency Classification (from CVSS score)

| CVSS Score Range | Urgency Tier | Target Date |
|-----------------|-------------|-------------|
| ≥ 9.0 | CRITICAL | Today + 14 days |
| ≥ 7.0 and < 9.0 | HIGH | Today + 28 days |
| < 7.0 or unknown | ROUTINE | Today + 42 days (28 + 14, batched) |

#### Plan Structure

For each active branch:
1. **Skip EOL branches** — if `support_end < today`, the branch is excluded
2. **Filter out NOT_APPLICABLE** CVEs — they don't need action
3. **Group remaining CVEs** into CRITICAL / HIGH / ROUTINE buckets
4. **Create a PlanItem** per (branch, urgency tier) with:
   - Target release date (based on SLA days)
   - Estimated effort (from effort aggregation)
   - List of CVE IDs included
   - Notes (e.g., "3 CRITICAL CVE(s) - 14-day SLA")

#### Example Plan Output

```
cert-manager-1.18 — z-stream by 2026-09-20
  Urgency: CRITICAL
  CVEs (3): CVE-2026-33186, CVE-2026-71235, CVE-2026-33810
  Estimated effort: 12.6 days
  Notes: 3 CRITICAL CVE(s) - 14-day SLA

cert-manager-1.18 — z-stream by 2026-10-04
  Urgency: HIGH
  CVEs (15): CVE-2026-39828, CVE-2026-39832, ...
  Estimated effort: 63.0 days
  Notes: 15 HIGH CVE(s) - 28-day SLA
```

---

## 4. Report Generation

**Code:** `src/services/report_generator.py`

The report is a **Markdown document** generated from the database. It contains five sections:

### 4.1 Executive Summary
- Total CVE count across all branches
- Severity breakdown (CRITICAL / HIGH / MEDIUM / LOW counts)
- Total estimated engineering effort in person-days

### 4.2 CVE-Branch Applicability Matrix
A markdown table showing every CVE × every branch with the fix classification:
```
| CVE ID          | Severity | CVSS | cert-manager-1.18 | cert-manager-1.19 | cert-manager-1.20 |
|-----------------|----------|------|--------------------|--------------------|---------------------|
| CVE-2026-33186  | CRITICAL | 9.1  | HIGH/REVIEW        | HIGH/REVIEW         | HIGH/REVIEW          |
```

### 4.3 Effort Summary by Branch
Per-branch table with CVE counts, effort in days, and S/M/L/XL breakdown.

### 4.4 Suggested Release Plan
The generated plan items with target dates, urgency, effort, and CVE lists.

### 4.5 Detailed CVE Analysis
Full details per CVE: module, package, vulnerable versions, fixed version, Go Vuln ID, description, and affected branches.

The report can be **downloaded as a `.md` file** from the UI and shared in Jira epics, Google Docs, or Confluence pages.

---

## 5. Data Provenance: Fact vs Inference vs Assumption

Understanding which data points are verified facts, computed inferences, or configurable assumptions is critical for trusting the dashboard output.

### Facts (from verified external sources)

| Data Point | Source | Justification |
|-----------|--------|---------------|
| CVE ID | Jira Vulnerability ticket (`customfield_10667`) | Directly from the issue tracker |
| Severity rating | Jira (`customfield_10840`) | Red Hat Product Security assigns this |
| CVSS score | Jira (`customfield_10859`) | From the NVD CVSS assessment |
| Affected module (Go path) | Jira (`customfield_10632`) or analyze-cve | From upstream advisory databases |
| Affected image | Jira (`customfield_10669`) | From Red Hat security team's triage |
| Ticket status | Jira (status field) | Live ticket status |
| Fixed version | analyze-cve → NVD / Go Vuln DB / GHSA | From upstream patch release notes |
| Description | analyze-cve → NVD / GHSA | From the published advisory |
| Current version in our repo | analyze-cve → `go.mod` / `go.sum` | From our actual source code |
| Dependency type (direct/indirect) | analyze-cve → Go module graph | From `go.mod` require directives |
| Symbol reachability | analyze-cve → static call graph | From code analysis of our entry points |

### Inferences (computed by our logic)

| Data Point | How It's Computed | Code Location |
|-----------|-------------------|---------------|
| Risk level | analyze-cve's assessment combining CVSS, reachability, dependency depth | Cursor agent logic |
| Confidence | analyze-cve's self-assessed confidence | Cursor agent logic |
| Fix Type classification | Heuristic decision tree based on risk, dep type, version gap, reachability | `fix_classifier.py:classify_single()` |
| Version gap (patch/minor/major) | Semver parsing of current vs fixed version | `fix_classifier.py:_version_gap_size()` |
| Risk level normalization | String normalization ("NOT VULNERABLE" → "NOT_VULNERABLE") | `fix_classifier.py:normalize_risk_level()` |
| Urgency tier (CRITICAL/HIGH/ROUTINE) | CVSS threshold buckets (≥9.0, ≥7.0, <7.0) | `plan_generator.py:_urgency_from_cvss()` |

### Assumptions (configurable, team-decided)

| Data Point | Default Value | Where Configured | Should Be Calibrated By |
|-----------|--------------|-----------------|------------------------|
| VERSION_BUMP effort | 3 hours | `releases.yaml` → `effort_defaults.version_bump_hours` | Historical PR merge times |
| TRIVIAL_BACKPORT effort | 8 hours | `releases.yaml` → `effort_defaults.trivial_backport_hours` | Past backport timelines |
| NON_TRIVIAL_BACKPORT effort | 20 hours | `releases.yaml` → `effort_defaults.non_trivial_backport_hours` | Major version migration experience |
| NEEDS_REVIEW effort | 28 hours | `releases.yaml` → `effort_defaults.needs_review_hours` | Worst-case manual assessment |
| Testing overhead multiplier | 1.5x | `releases.yaml` → `effort_defaults.testing_overhead_multiplier` | QE team capacity ratio |
| Critical CVSS multiplier | 1.2x | Hardcoded in `effort_estimator.py` | Emergency process overhead |
| Critical SLA days | 14 days | `releases.yaml` → `urgency_rules.critical_cve_days` | Red Hat vulnerability response policy |
| High SLA days | 28 days | `releases.yaml` → `urgency_rules.high_cve_days` | Red Hat vulnerability response policy |
| MEDIUM/LOW batching | Enabled | `releases.yaml` → `urgency_rules.medium_low_batch` | Release cadence preference |
| FedRAMP SLA days | 30 days | `releases.yaml` → `urgency_rules.fedramp_sla_days` | FedRAMP ATO requirements |
| Minimum CVE year filter | 2024 | `releases.yaml` → `scanner.min_cve_year` | Historical relevance cutoff |
| Max CVEs per branch | 50 | `releases.yaml` → `scanner.max_analyze_per_branch` | API rate/cost limits |

---

## 6. CVE Detail Panel — Data Sources

When a user clicks a CVE row in the matrix, a slide-out detail panel shows comprehensive information. Here's where each field comes from:

| Panel Field | Primary Source | Fallback Source |
|------------|---------------|-----------------|
| CVE ID | Jira discovery | Evidence import |
| Severity badge | Jira (`customfield_10840`) | analyze-cve evidence |
| CVSS score | Jira (`customfield_10859`) | analyze-cve evidence |
| Go Vuln ID | analyze-cve evidence | Not available from Jira |
| GHSA ID | analyze-cve evidence | Not available from Jira |
| Module | Jira (`customfield_10632`) | analyze-cve evidence |
| Package | analyze-cve evidence | Not available from Jira |
| Vulnerable versions | analyze-cve evidence | Not available from Jira |
| **Fixed version** | **analyze-cve → upstream advisories (NVD, Go vuln DB, GHSA)** | Not available from Jira |
| **Description** | **analyze-cve → upstream advisories (NVD, GHSA)** | Not available from Jira |
| Source badge | Computed ("jira", "evidence", or "both") | — |
| Jira ticket link | Jira key from discovery | — |
| Linked Jira tickets | `linked_jira_tickets_json` from all branch discoveries | — |
| Linked PRs | Jira ticket remote links + description PR URLs | — |
| Risk level (per branch) | analyze-cve assessment | Jira severity as fallback |
| Fix type (per branch) | `fix_classifier.py` inference | — |
| Effort (per branch) | `effort_estimator.py` calculation | — |
| Dependency type (per branch) | analyze-cve → `go.mod` analysis | "unknown" if not enriched |
| Current version (per branch) | analyze-cve → `go.mod`/`go.sum` | Empty if not enriched |
| Symbol reachable (per branch) | analyze-cve → static call graph | False if not enriched |
| Affected image (per branch) | Jira (`customfield_10669`) | — |
| Raw evidence JSON | analyze-cve `evidence.json` output | — |

**Key takeaway:** `fixed_version` and `description` are **not available from Jira alone**. They come from the `analyze-cve` enrichment stage, which queries upstream vulnerability databases (NVD, Go vulnerability database at `vuln.go.dev`, GitHub Security Advisories). If analyze-cve hasn't run, these fields will be empty.

---

## 7. Multi-Ticket Support (One CVE → Many Jira Tickets)

A single CVE can have **multiple Jira Vulnerability tickets** — typically one per affected container image (e.g., `cert-manager-operator`, `cert-manager-webhook`, `cert-manager-cainjector`).

### How it works

- During Jira discovery, each ticket is parsed independently
- If the same CVE ID appears in multiple tickets, the first creates the `CVEEntry` + `BranchCVE`, and subsequent tickets are **merged** into `linked_jira_tickets_json`
- Each ticket entry stores: `jira_key`, `summary`, `status`, `affected_image`
- Deduplication is by `jira_key` — no duplicate tickets are stored

### How it appears in the UI

- **Matrix row:** A purple badge shows "`N tickets`" next to the CVE ID when N > 1
- **Detail panel:** A "Linked Jira Tickets" section lists all unique tickets with clickable links, affected image, and status

---

## 8. Repository Cloning & Branch Checkout

**Code:** `src/services/repo_manager.py`

### What gets cloned

The **cert-manager operator repository**: `https://github.com/openshift/cert-manager-operator`

This is configured in `releases.yaml` → `repository.url`.

### Where it's cloned

| Scenario | Location |
|----------|----------|
| `local_path` configured and exists | Uses that path directly (no clone) |
| `local_path` not set or path doesn't exist | Auto-clones to `/tmp/release-planner-XXXXXXX/` |

### Clone strategy

```bash
git clone --depth=1 --no-single-branch <repo-url> /tmp/release-planner-XXXX/
```

- `--depth=1`: Shallow clone (only latest commit per branch) for speed
- `--no-single-branch`: Fetches all remote branch refs so we can `git checkout` any branch

### Per-branch analysis

For each active branch, the orchestrator runs:
```bash
git checkout cert-manager-1.18
```
Then analyze-cve runs against the checked-out code. After all branches are analyzed, the temp directory is **cleaned up** (`shutil.rmtree`).

### Configuring a local path (recommended for development)

Uncomment in `releases.yaml`:
```yaml
repository:
  url: https://github.com/openshift/cert-manager-operator
  local_path: /home/user/repos/cert-manager-operator
```
This avoids re-cloning on every run and is faster.

---

## 9. SLA Rules & Urgency Policies

**SLA = Service Level Agreement** — the maximum number of days the team commits to shipping a CVE fix after discovery.

### Current Configuration

```yaml
urgency_rules:
  critical_cve_days: 14       # ≤14 days for CVSS ≥ 9.0
  high_cve_days: 28            # ≤28 days for CVSS ≥ 7.0
  medium_low_batch: true       # Group MEDIUM/LOW into next scheduled z-stream
  fedramp_sla_days: 30         # FedRAMP ATO compliance (not yet implemented)
```

### How SLA rules drive the release plan

| CVE CVSS Score | Urgency | Target Release Date | Policy Basis |
|---------------|---------|--------------------|----|
| ≥ 9.0 | CRITICAL | Today + 14 days | Red Hat Critical vulnerability response |
| ≥ 7.0 | HIGH | Today + 28 days | Red Hat Important vulnerability response |
| < 7.0 | ROUTINE | Today + 42 days | Batched into next z-stream cycle |
| None / Unknown | ROUTINE | Today + 42 days | Conservative default |

### Important notes

- These are **policy assumptions**, not Jira-enforced deadlines
- The target dates are suggestions for planning — the plan has "draft" status
- The `fedramp_sla_days: 30` is defined in config but **not yet implemented** in the plan generator
- SLA days should be aligned with the team's actual release cadence and management expectations

---

## 10. FedRAMP / GovCloud SLA Status

### Current status: Infrastructure exists, not fully wired

The codebase has **preparatory infrastructure** for FedRAMP/GovCloud tracking:

| Component | Status | Details |
|-----------|--------|---------|
| GovCloud JQL query | ✅ Implemented | `build_govcloud_jql()` in `jira_discovery.py` |
| GovCloud label detection | ✅ Implemented | Detects `ROSA-GovCloud` and `FedRAMP` labels |
| `is_govcloud` flag | ✅ Implemented | On `JiraTicketContext` dataclass |
| `fedramp_sla_days: 30` config | ✅ Configured | In `releases.yaml` |
| FedRAMP urgency tier in plan | ❌ Not implemented | `plan_generator.py` doesn't use the 30-day SLA |
| FedRAMP column in UI | ❌ Not implemented | No separate FedRAMP indicator in the matrix |
| GovCloud ticket querying | ❌ Not wired | `discover_from_jira()` doesn't call `build_govcloud_jql()` |

### What would be needed

1. During Jira discovery, run the GovCloud JQL and tag matching CVE/branch pairs
2. In the plan generator, apply the 30-day SLA (which may be stricter than the standard 42-day ROUTINE) to FedRAMP-flagged CVEs
3. Optionally, add a FedRAMP badge/column to the matrix UI

---

## 11. Configuration Reference

### `config.json` — Server & Runtime

```json
{
  "server": { "host": "0.0.0.0", "port": 8000, "log_level": "info" },
  "database": { "url": "sqlite+aiosqlite:///data/dashboard.db" },
  "scanner": {
    "cursor_api_key": "crsr_...",    // Required for analyze-cve
    "cursor_model": "composer-2.5"    // Cursor model for analyze-cve agents
  },
  "jira": {
    "url": "https://redhat.atlassian.net",
    "email": "user@redhat.com",
    "api_token": ""                    // Or use JIRA_API_TOKEN env var
  }
}
```

### `releases.yaml` — Branch & Policy Configuration

See the full file in the repository root. Key sections:
- `repository` — Git URL and optional local path
- `jira` — Project key, JQL templates, custom field mappings
- `branches` — Branch definitions with OCP versions, support dates, EUS flags
- `scanner` — Year filter, max CVEs per branch
- `effort_defaults` — Hours per fix type, testing multiplier
- `urgency_rules` — SLA days per severity tier

---

## 12. Prerequisites & Setup

### Minimum requirements (Jira-only mode)

| Prerequisite | Purpose | How to Install/Configure |
|-------------|---------|-------------------------|
| Python 3.12+ | Backend runtime | System package manager |
| Node.js 18+ | Frontend dev server | `nvm install 18` |
| Git | Repository operations | System package manager |
| Jira credentials | CVE discovery | Set `JIRA_URL`, `JIRA_API_TOKEN`, `JIRA_EMAIL` env vars or in `config.json` |

### Full requirements (with analyze-cve enrichment)

All of the above, plus:

| Prerequisite | Purpose | How to Install/Configure |
|-------------|---------|-------------------------|
| Cursor IDE installed | Required by `cursor-sdk` | Install from cursor.com |
| `cursor-sdk` Python package | Invokes Cursor agents | `pip install cursor-sdk` |
| Cursor API key | Authentication for SDK | Set in `config.json` → `scanner.cursor_api_key` or `CURSOR_API_KEY` env var |
| analyze-cve skill/plugin | The compliance skill that analyzes CVEs | Enabled in Cursor settings (plugin system) — **no separate repo clone needed** |
| Network access to GitHub | Auto-cloning cert-manager repo | Required if `local_path` not set |

### What you do NOT need

- ❌ You do **not** need to clone the `analyze-cve` repo — it's a Cursor plugin invoked via the SDK
- ❌ You do **not** need the cert-manager repo pre-cloned — `RepoManager` auto-clones it
- ❌ You do **not** need `govulncheck` installed — it's optional and not used in the current pipeline

### Quick start

```bash
# 1. Install backend dependencies
cd "Release Planner POC"
pip install -r requirements.txt

# 2. Install frontend dependencies
cd web && npm install && cd ..

# 3. Configure credentials
export JIRA_URL="https://redhat.atlassian.net"
export JIRA_API_TOKEN="your-token"
export JIRA_EMAIL="you@redhat.com"
# Edit config.json to set cursor_api_key if using analyze-cve

# 4. Start backend
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# 5. Start frontend (separate terminal)
cd web && npm run dev

# 6. Open http://localhost:5173
```

---

## 13. Known Limitations

| Limitation | Impact | Potential Fix |
|-----------|--------|---------------|
| Jira-only analysis produces all NEEDS_REVIEW (XL) | Effort is overestimated without analyze-cve | Ensure Cursor SDK is configured with valid API key |
| Branch selector "Analyzing" state persists when switching branches | UI shows wrong loading state | Reset `analyzing` state on branch change (useEffect on selectedBranch) |
| analyze-cve is sequential per CVE | Full analysis of 30+ CVEs takes 15-30 minutes | Could parallelize with worker pool |
| FedRAMP SLA not wired into plan generator | FedRAMP tickets may get ROUTINE urgency instead of 30-day | Implement FedRAMP urgency tier |
| Single-branch evidence path | analyze-cve writes to a fixed path per CVE, not per branch | Could namespace by branch for parallel multi-branch runs |
| Effort defaults are rough estimates | May over/underestimate actual work | Calibrate with historical team data |
| No authentication on dashboard | Anyone with network access can trigger scans | Add auth middleware for production |
| SQLite doesn't support concurrent writes | Could be an issue with parallel users | Swap to PostgreSQL for production |

---

## 14. Future Direction: Using LLMs for Release Planning

The current release plan is generated by **deterministic rules** — CVSS thresholds map to urgency tiers, which map to SLA-driven target dates. While predictable and transparent, this approach misses nuances that experienced engineers naturally consider. Large Language Models (LLMs) could significantly enhance the planning process.

### 14.1 Where LLMs Could Add Value

#### A. Intelligent Prioritization

The current system prioritizes purely by CVSS score. An LLM could consider a richer context:

- **Symbol reachability + attack surface**: "CVE-2026-33186 has CVSS 9.1 but the vulnerable symbol is NOT reachable in our operator. Despite the high score, actual exploitation risk is minimal. Recommend deprioritizing to HIGH tier."
- **Cross-branch impact**: "This CVE affects all 3 active branches. Fixing cert-manager-1.20 first and cherry-picking to 1.19/1.18 reduces total effort by ~40%."
- **Fix availability**: "CVE-2026-71235 has no upstream fix yet. Monitoring is more appropriate than a rushed workaround."
- **Business context**: "cert-manager-1.18 is EUS (Extended Update Support) and supports a major customer deployment. Prioritize over 1.19."

#### B. Natural Language Release Notes

Instead of raw markdown tables, an LLM could generate stakeholder-friendly narratives:

> "We recommend an emergency z-stream release for cert-manager-1.18 by September 20th to address 3 critical CVEs in golang.org/x/net and gRPC. The most urgent is CVE-2026-33186 (CVSS 9.1) affecting authentication flows. Estimated engineering effort is 12.6 person-days. The remaining 15 HIGH-severity CVEs can be batched into the October 4th release."

#### C. Risk Assessment Narratives

For each CVE, generate a contextual risk assessment:

> "CVE-2026-48050 affects github.com/bassicklabs/arc (CVSS 8.2). Three Jira tickets track this across cert-manager-operator, cert-manager-webhook, and cert-manager-cainjector. However, static analysis shows the vulnerable codepath is only reachable in the webhook component. Recommend fixing webhook first (VERSION_BUMP, ~3h) and deferring operator/cainjector to the next batch."

#### D. Effort Refinement

Instead of fixed hours per fix type, an LLM could analyze the actual code change needed:

- Look at the diff between current and fixed versions
- Estimate based on the size and complexity of API changes
- Consider test coverage requirements
- Factor in the team's familiarity with the affected module

#### E. Cross-Branch Optimization

An LLM could reason about optimal fix ordering:

> "CVEs X, Y, Z all require bumping golang.org/x/crypto. On branch 1.20 (latest), this is a direct version bump. For 1.18 (oldest), the dependency tree differs and requires a 2-step transitive update. Recommend: fix on 1.20 → verify CI → cherry-pick to 1.19 → adapt and apply to 1.18. This sequencing reduces duplicate debugging effort."

### 14.2 Proposed Architecture

```
┌───────────────────────────────────┐
│   Existing Pipeline (Stages 1-5)  │
│   Jira → analyze-cve → classify  │
│   → estimate → rule-based plan   │
└───────────────┬───────────────────┘
                │ Structured data (JSON)
                ▼
┌───────────────────────────────────┐
│   LLM Enhancement Layer           │
│                                   │
│   Input:                          │
│   - CVE matrix (all branches)     │
│   - Fix classifications           │
│   - Effort estimates              │
│   - Symbol reachability data      │
│   - Branch support dates/EUS      │
│   - Team capacity (configurable)  │
│   - Historical release data       │
│                                   │
│   Output:                         │
│   - Optimized release plan        │
│   - Risk narratives per CVE       │
│   - Prioritization rationale      │
│   - Cross-branch fix strategy     │
│   - Stakeholder-ready summary     │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│   Dual-View UI                    │
│   ┌──────────┐  ┌──────────────┐ │
│   │ Rule-based│  │ LLM-enhanced │ │
│   │   Plan    │  │    Plan      │ │
│   │ (current) │  │ (AI-assisted)│ │
│   └──────────┘  └──────────────┘ │
│   Engineer reviews both,          │
│   accepts/modifies the plan       │
└───────────────────────────────────┘
```

### 14.3 Implementation Approach

**Option A: Post-pipeline LLM call (simplest)**

After Stage 5, pass the structured plan data to an LLM:

```python
prompt = f"""
You are a release planning assistant for the cert-manager operator team.

Given this CVE data across {len(branches)} release branches:
{json.dumps(matrix_data, indent=2)}

And the current rule-based release plan:
{json.dumps(plan_data, indent=2)}

Generate:
1. An optimized release plan considering cross-branch dependencies
2. A risk summary for leadership
3. Specific recommendations for each CRITICAL/HIGH CVE
4. Suggested fix ordering to minimize total effort

Consider that cert-manager-1.18 and cert-manager-1.20 are EUS branches
and should be prioritized for stability.
"""
```

This could use the **Cursor SDK** (already integrated) or a direct API call to an LLM provider.

**Option B: Agent-based planning (more sophisticated)**

Use a Cursor agent with access to:
- The CVE database (via MCP or API)
- The Git repository (for code-level analysis)
- Jira (for ticket status and dependencies)
- Historical release data

The agent would iteratively build a plan, verify assumptions against the code, and produce a justified recommendation.

### 14.4 Guardrails & Trust

LLM-generated plans should be treated as **suggestions**, not automated decisions:

1. **Always show the deterministic plan alongside the LLM plan** — engineers can compare
2. **Require human approval** before any plan is finalized
3. **Log the LLM's reasoning** — every recommendation should have an explanation
4. **Audit trail** — record which plan was approved and by whom
5. **Confidence indicators** — the LLM should flag areas of uncertainty
6. **Fail-safe to rule-based** — if the LLM is unavailable, the rule-based plan is always there

### 14.5 Cost & Latency Considerations

| Approach | Estimated Cost per Run | Latency |
|----------|----------------------|---------|
| Post-pipeline summary (single LLM call) | ~$0.05-0.15 | 10-30 seconds |
| Per-CVE risk narratives (N calls) | ~$0.50-2.00 for 30 CVEs | 2-5 minutes |
| Agent-based planning (multi-turn) | ~$1.00-5.00 | 5-15 minutes |

For a POC, Option A (single post-pipeline call) provides the best value-to-effort ratio.

---

*This document was generated from the Release Planner POC codebase. All code references point to the actual source files in the repository.*
