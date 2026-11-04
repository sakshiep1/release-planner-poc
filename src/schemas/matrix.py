from __future__ import annotations

from pydantic import BaseModel


class JiraTicketInfo(BaseModel):
    jira_key: str
    summary: str = ""
    status: str = ""
    affected_image: str = ""


class MatrixCell(BaseModel):
    risk_level: str = ""
    fix_type: str = ""
    effort_tshirt: str = ""
    effort_hours: float = 0.0
    symbol_reachable: bool = False
    component: str = "operator"
    jira_verdict: str | None = None
    affected_image: str | None = None
    due_date: str | None = None
    notes: str = ""
    jira_ticket_count: int = 0
    jira_tickets: list[JiraTicketInfo] = []


class MatrixRow(BaseModel):
    cve_id: str
    severity: str
    cvss_score: float | None = None
    affected_module: str = ""
    fixed_version: str | None = None
    source: str = "evidence"
    jira_key: str | None = None
    linked_prs: list[str] = []
    jira_ticket_count: int = 0
    branches: dict[str, MatrixCell] = {}


class MatrixOut(BaseModel):
    branch_names: list[str]
    rows: list[MatrixRow]
