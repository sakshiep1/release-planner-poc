from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ScanRunOut(BaseModel):
    id: str
    branch_id: str | None = None
    branch_name: str | None = None
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    cves_found: int
    error_log: str = ""

    model_config = {"from_attributes": True}


class ImportRequest(BaseModel):
    evidence_path: str
    branch_name: str | None = None
    component: str = "operator"


class ScanRequest(BaseModel):
    branch_name: str | None = None
    branches: list[str] | None = None
    scan_type: str = "full"  # "full" | "analyze" | "jira" (CLI)
