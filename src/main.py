from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.core.sse import sse_broker
from src.db.engine import init_db
from src.api.v1.router import v1_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    await init_db()
    await sse_broker.start()
    logger.info("Release Planner API started")
    yield
    await sse_broker.stop()


def create_app() -> FastAPI:
    cfg = get_settings()
    logging.basicConfig(level=cfg.server.log_level.upper())

    application = FastAPI(
        title="Cert-Manager Release Planner",
        description="Z-stream release planning tool for cert-manager-operator",
        version="0.1.0",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(v1_router, prefix="/api/v1")
    return application


app = create_app()
