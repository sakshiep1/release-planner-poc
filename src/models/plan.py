from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Date, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.db.base import Base


class ReleasePlan(Base):
    __tablename__ = "release_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="draft")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class PlanItem(Base):
    __tablename__ = "plan_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_id: Mapped[str] = mapped_column(String(36), ForeignKey("release_plans.id"), index=True)
    branch_id: Mapped[str] = mapped_column(String(36), ForeignKey("release_branches.id"))
    branch_name: Mapped[str] = mapped_column(String(128), default="")
    target_date: Mapped[date] = mapped_column(Date)
    urgency: Mapped[str] = mapped_column(String(16), default="ROUTINE")
    estimated_effort_days: Mapped[float] = mapped_column(Float, default=0.0)
    cve_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(16), default="planned")
    notes: Mapped[str] = mapped_column(Text, default="")
