from __future__ import annotations

import logging
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import get_settings
from src.db.base import Base

logger = logging.getLogger(__name__)

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _ensure_data_dir(url: str) -> None:
    if url.startswith("sqlite"):
        db_path = url.split("///")[-1]
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_settings().database
        _ensure_data_dir(cfg.url)
        _engine = create_async_engine(cfg.url, echo=cfg.echo)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return _session_factory


async def init_db() -> None:
    # Import all models so Base.metadata knows all tables
    import src.models  # noqa: F401

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Lightweight migration: add columns that may not exist in older DBs
    async with engine.begin() as conn:
        for col, col_type, default in [
            ("linked_jira_tickets_json", "TEXT", "'[]'"),
        ]:
            try:
                await conn.execute(
                    text(f"ALTER TABLE branch_cves ADD COLUMN {col} {col_type} DEFAULT {default}")
                )
                logger.info("Added column branch_cves.%s", col)
            except Exception:
                pass  # column already exists

    logger.info("Database tables created")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        yield session
