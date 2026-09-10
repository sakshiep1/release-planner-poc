from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class BranchOut(BaseModel):
    id: str
    name: str
    ocp_version: str
    cert_manager_version: str
    support_start: date | None = None
    support_end: date | None = None
    is_eus: bool = False
    active: bool = True
    cve_count: int = 0
    total_effort_days: float = 0.0

    model_config = {"from_attributes": True}
