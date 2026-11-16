"""Message bus: Azure Storage Queues (identity auth) in Azure, in-memory locally."""
from __future__ import annotations

import json
import logging
from typing import Any, Protocol

log = logging.getLogger(__name__)


class Bus(Protocol):
    def send(self, queue: str, message: dict[str, Any]) -> None: ...


class MemoryBus:
    def __init__(self) -> None:
        self.messages: dict[str, list[dict[str, Any]]] = {}

    def send(self, queue: str, message: dict[str, Any]) -> None:
        self.messages.setdefault(queue, []).append(message)


class StorageQueueBus:
    def __init__(self, account_url: str) -> None:
        from azure.identity import DefaultAzureCredential
        self._url = account_url
        self._cred = DefaultAzureCredential()
        self._clients: dict[str, Any] = {}

    def send(self, queue: str, message: dict[str, Any]) -> None:
        from azure.storage.queue import QueueClient
        try:
            if queue not in self._clients:
                self._clients[queue] = QueueClient(self._url, queue, credential=self._cred)
            self._clients[queue].send_message(json.dumps(message))
        except Exception:  # never break a user request because telemetry failed
            log.exception("queue send failed: %s", queue)


_bus: Bus | None = None


def get_bus() -> Bus:
    global _bus
    if _bus is None:
        from .config import get_settings
        s = get_settings()
        _bus = StorageQueueBus(s.queue_account_url) if s.bus_provider == "storage" else MemoryBus()
    return _bus


def set_bus(bus: Bus) -> None:
    global _bus
    _bus = bus
