from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from src.db.base import Base


class ReleaseBranch(Base):
    __tablename__ = "release_branches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    ocp_version: Mapped[str] = mapped_column(String(32), default="")
    cert_manager_version: Mapped[str] = mapped_column(String(32), default="")
    support_start: Mapped[date | None] = mapped_column(Date, nullable=True)
    support_end: Mapped[date | None] = mapped_column(Date, nullable=True)
    is_eus: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
