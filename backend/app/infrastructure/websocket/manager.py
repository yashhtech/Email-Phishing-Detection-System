"""WebSocket Connection Manager for real-time analysis progress streaming.

Responsibilities:
- Manage live WebSocket connections per analysis_id subscription
- Broadcast structured lifecycle events (queued, processing, completed, failed)
- Thread-safe, non-blocking delivery with automatic dead-client cleanup
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import WebSocket

logger = structlog.get_logger(__name__)


class WebSocketConnectionManager:
    """Manages active WebSocket subscriptions and broadcasts analysis events."""

    def __init__(self) -> None:
        # Maps analysis_id (string) -> set of active WebSocket connections
        self._analysis_subscribers: dict[str, set[WebSocket]] = {}
        # Global subscribers (e.g. SOC live monitoring dashboard)
        self._global_subscribers: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, analysis_id: str | None = None) -> None:
        """Accept connection and register subscriber."""
        await websocket.accept()
        async with self._lock:
            if analysis_id:
                clean_id = analysis_id.strip()
                if clean_id not in self._analysis_subscribers:
                    self._analysis_subscribers[clean_id] = set()
                self._analysis_subscribers[clean_id].add(websocket)
                logger.info("websocket_client_subscribed_to_analysis", analysis_id=clean_id)
            else:
                self._global_subscribers.add(websocket)
                logger.info("websocket_client_subscribed_globally")

    async def disconnect(self, websocket: WebSocket, analysis_id: str | None = None) -> None:
        """Unregister a disconnected WebSocket client."""
        async with self._lock:
            if analysis_id:
                clean_id = analysis_id.strip()
                if clean_id in self._analysis_subscribers:
                    self._analysis_subscribers[clean_id].discard(websocket)
                    if not self._analysis_subscribers[clean_id]:
                        del self._analysis_subscribers[clean_id]
            self._global_subscribers.discard(websocket)

    async def broadcast_event(
        self,
        analysis_id: str,
        status: str,
        stage: str,
        data: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> int:
        """Broadcast a structured progress event to all interested subscribers."""
        event_payload = {
            "analysis_id": analysis_id,
            "status": status,
            "stage": stage,
            "data": data or {},
            "error_message": error_message,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        # Gather targets: direct subscribers to this analysis + global listeners
        async with self._lock:
            direct = set(self._analysis_subscribers.get(analysis_id.strip(), set()))
            targets = direct | set(self._global_subscribers)

        if not targets:
            return 0

        sent_count = 0
        dead_connections: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json(event_payload)
                sent_count += 1
            except Exception as exc:
                logger.debug("websocket_send_failed_marking_dead", error=str(exc))
                dead_connections.append(ws)

        if dead_connections:
            async with self._lock:
                for dead_ws in dead_connections:
                    if analysis_id.strip() in self._analysis_subscribers:
                        self._analysis_subscribers[analysis_id.strip()].discard(dead_ws)
                    self._global_subscribers.discard(dead_ws)

        return sent_count

    def subscriber_count(self, analysis_id: str | None = None) -> int:
        """Return number of active connections."""
        if analysis_id:
            return len(self._analysis_subscribers.get(analysis_id.strip(), set()))
        return len(self._global_subscribers) + sum(
            len(s) for s in self._analysis_subscribers.values()
        )

    async def send_personal_message(
        self,
        message: dict[str, Any],
        websocket: WebSocket,
    ) -> None:
        """Send a direct JSON message to a single connected client."""
        await websocket.send_json(message)


# Global singleton instance
ws_manager = WebSocketConnectionManager()
