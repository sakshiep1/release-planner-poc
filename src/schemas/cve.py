from __future__ import annotations

from datetime import date

from pydantic import BaseModel


class CVEOut(BaseModel):
    id: str
    cve_id: str
    go_vuln_id: str | None = None
    ghsa_id: str | None = None
    severity_rating: str = "UNKNOWN"
    cvss_score: float | None = None
    affected_module: str = ""
    affected_package: str = ""
    vulnerable_versions: str = ""
    fixed_version: str | None = None
    description: str = ""
    analysis_date: date | None = None
    jira_key: str | None = None
    source: str = "evidence"
    linked_prs: str = "[]"

    model_config = {"from_attributes": True}


class CVEDetailOut(CVEOut):
    evidence_json: str = "{}"
    branches: list[BranchCVEOut] = []


class JiraTicketInfo(BaseModel):
    jira_key: str
    summary: str = ""
    status: str = ""
    affected_image: str = ""


class BranchCVEOut(BaseModel):
    branch_id: str
    branch_name: str = ""
    risk_level: str
    confidence: str
    dependency_type: str
    current_version: str
    symbol_reachable: bool
    fix_type: str | None = None
    effort_hours: float = 0.0
    effort_tshirt: str = ""
    component: str = "operator"
    jira_verdict: str | None = None
    affected_image: str | None = None
    jira_tickets: list[JiraTicketInfo] = []

    model_config = {"from_attributes": True}


CVEDetailOut.model_rebuild()
