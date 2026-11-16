import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.update(STORE_PROVIDER="memory", BUS_PROVIDER="memory", SEED_PASSWORD="Test@12345", INGEST_API_KEY="test-ingest-key")

from fastapi.testclient import TestClient  # noqa: E402

from app.core import bus, store  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture()
def client():
    store.set_store(store.MemoryStore())
    bus.set_bus(bus.MemoryBus())
    return TestClient(create_app())


@pytest.fixture()
def login(client):
    def _login(username: str) -> dict:
        r = client.post("/api/auth/login", json={"username": username, "password": "Test@12345"})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}
    return _login
