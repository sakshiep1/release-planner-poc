from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.db.base import Base


class FixType(str, enum.Enum):
    VERSION_BUMP = "VERSION_BUMP"
    TRIVIAL_BACKPORT = "TRIVIAL_BACKPORT"
    NON_TRIVIAL_BACKPORT = "NON_TRIVIAL_BACKPORT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class BranchCVE(Base):
    """Junction table: each row is one (branch, CVE) pairing with analysis results."""
    __tablename__ = "branch_cves"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    branch_id: Mapped[str] = mapped_column(String(36), ForeignKey("release_branches.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(36), ForeignKey("cve_entries.id"), index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    confidence: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    dependency_type: Mapped[str] = mapped_column(String(16), default="unknown")
    current_version: Mapped[str] = mapped_column(String(64), default="")
    symbol_reachable: Mapped[bool] = mapped_column(Boolean, default=False)
    fix_type: Mapped[FixType | None] = mapped_column(Enum(FixType), nullable=True)
    effort_hours: Mapped[float] = mapped_column(Float, default=0.0)
    effort_tshirt: Mapped[str] = mapped_column(String(4), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    component: Mapped[str] = mapped_column(String(32), default="operator")

    # V3: Jira tracking
    jira_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    affected_image: Mapped[str | None] = mapped_column(String(128), nullable=True)
    linked_jira_tickets_json: Mapped[str] = mapped_column(Text, default="[]")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
