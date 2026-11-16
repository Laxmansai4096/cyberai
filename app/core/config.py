"""Runtime settings for CyberSentinel."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass(frozen=True)
class Settings:
    app_name: str
    environment: str
    store_provider: str
    cosmos_endpoint: str
    cosmos_database: str
    bus_provider: str
    queue_account_url: str
    vuln_feed: str             # local | osv  (OSV.dev is a free public API)
    jwt_secret: str
    seed_password: str
    commands_queue: str
    detection_window_min: int
    log_ttl_seconds: int
    ingest_api_key: str        # for external systems (e.g. MediFlow) posting to /api/ingest; empty = endpoint disabled


@lru_cache
def get_settings() -> Settings:
    return Settings(
        app_name="cybersentinel",
        environment=_env("ENVIRONMENT", "local"),
        store_provider=_env("STORE_PROVIDER", "memory"),
        cosmos_endpoint=_env("COSMOS_ENDPOINT"),
        cosmos_database=_env("COSMOS_DATABASE", "cybersentinel"),
        bus_provider=_env("BUS_PROVIDER", "memory"),
        queue_account_url=_env("QUEUE_ACCOUNT_URL"),
        vuln_feed=_env("VULN_FEED", "local"),
        jwt_secret=_env("JWT_SECRET", "local-dev-only-secret-change-me-0123456789"),
        seed_password=_env("SEED_PASSWORD", "Demo@12345"),
        commands_queue=_env("COMMANDS_QUEUE", "mediflow-commands"),
        detection_window_min=int(_env("DETECTION_WINDOW_MIN", "60")),
        log_ttl_seconds=int(_env("LOG_TTL_SECONDS", str(30 * 24 * 3600))),
        ingest_api_key=_env("INGEST_API_KEY"),
    )
