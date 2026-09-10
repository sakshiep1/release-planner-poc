from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Date, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.db.base import Base


class CVEEntry(Base):
    __tablename__ = "cve_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    go_vuln_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ghsa_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity_rating: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    affected_module: Mapped[str] = mapped_column(String(256), default="")
    affected_package: Mapped[str] = mapped_column(String(256), default="")
    vulnerable_versions: Mapped[str] = mapped_column(String(128), default="")
    fixed_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    analysis_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")

    # V3: Jira integration fields
    jira_key: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(16), default="evidence")
    linked_prs: Mapped[str] = mapped_column(Text, default="[]")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
