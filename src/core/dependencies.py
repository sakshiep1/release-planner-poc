from __future__ import annotations

from typing import Annotated, AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import AppConfig, get_settings
from src.db.engine import get_db


async def _db_session() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db():
        yield session


DBSession = Annotated[AsyncSession, Depends(_db_session)]
Settings = Annotated[AppConfig, Depends(get_settings)]
