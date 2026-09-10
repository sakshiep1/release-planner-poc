from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel


class PlanItemOut(BaseModel):
    id: str
    branch_name: str
    target_date: date
    urgency: str
    estimated_effort_days: float
    cve_ids: list[str] = []
    status: str = "planned"
    notes: str = ""

    model_config = {"from_attributes": True}


class ReleasePlanOut(BaseModel):
    id: str
    name: str
    status: str
    created_at: datetime
    items: list[PlanItemOut] = []

    model_config = {"from_attributes": True}


class EffortBranchSummary(BaseModel):
    branch_name: str
    cve_count: int = 0
    total_effort_days: float = 0.0
    s_count: int = 0
    m_count: int = 0
    l_count: int = 0
    xl_count: int = 0
    na_count: int = 0


class EffortSummaryOut(BaseModel):
    branches: list[EffortBranchSummary]
    total_effort_days: float = 0.0
    total_cve_count: int = 0
