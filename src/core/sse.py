from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator

from src.core.config import get_settings

logger = logging.getLogger(__name__)


class SSEBroker:
    """Publish/subscribe broker for Server-Sent Events."""

    def __init__(self) -> None:
        self._subscribers: dict[str | None, list[asyncio.Queue[dict[str, Any] | None]]] = {}
        self._heartbeat_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        cfg = get_settings().sse
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(cfg.heartbeat_interval_s))

    async def stop(self) -> None:
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        for queues in self._subscribers.values():
            for q in queues:
                await q.put(None)
        self._subscribers.clear()

    def _channel_queues(self, channel: str | None) -> list[asyncio.Queue[dict[str, Any] | None]]:
        if channel not in self._subscribers:
            self._subscribers[channel] = []
        return self._subscribers[channel]

    async def subscribe(self, channel: str | None = None) -> AsyncGenerator[str, None]:
        cfg = get_settings().sse
        total = sum(len(v) for v in self._subscribers.values())
        if total >= cfg.max_connections:
            yield f"event: error\ndata: {json.dumps({'error': 'max connections reached'})}\nretry: {cfg.retry_ms}\n\n"
            return

        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self._channel_queues(channel).append(queue)
        try:
            while True:
                msg = await queue.get()
                if msg is None:
                    break
                event_type = msg.get("event", "message")
                data = json.dumps(msg.get("data", {}))
                yield f"event: {event_type}\ndata: {data}\nretry: {cfg.retry_ms}\n\n"
        finally:
            self._channel_queues(channel).remove(queue)

    async def publish(self, event_type: str, data: dict[str, Any], channel: str | None = None) -> None:
        msg = {"event": event_type, "data": data}
        targets = list(self._channel_queues(channel)) + list(self._channel_queues(None))
        for q in targets:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                logger.warning("SSE subscriber queue full, dropping event")

    async def _heartbeat_loop(self, interval: int) -> None:
        while True:
            await asyncio.sleep(interval)
            ts = time.time()
            for queues in self._subscribers.values():
                for q in queues:
                    try:
                        q.put_nowait({"event": "heartbeat", "data": {"ts": ts}})
                    except asyncio.QueueFull:
                        pass


sse_broker = SSEBroker()
