from __future__ import annotations

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from src.core.sse import sse_broker

router = APIRouter(prefix="/events", tags=["events"])


@router.get("/stream")
async def event_stream(channel: str | None = None):
    return EventSourceResponse(sse_broker.subscribe(channel))
