"""Document store: one Cosmos DB container `items` partitioned by `/type`, or in-memory for local/tests."""
from __future__ import annotations

import copy
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

Doc = dict[str, Any]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


class Store(Protocol):
    def upsert(self, kind: str, doc: Doc) -> Doc: ...
    def get(self, kind: str, doc_id: str) -> Doc | None: ...
    def query(self, kind: str, where: dict[str, Any] | None = None, since: tuple[str, str] | None = None,
              order_by: str | None = None, desc: bool = True, limit: int | None = None) -> list[Doc]: ...
    def delete(self, kind: str, doc_id: str) -> None: ...


class MemoryStore:
    def __init__(self) -> None:
        self._data: dict[str, dict[str, Doc]] = {}
        self._lock = threading.Lock()

    def upsert(self, kind: str, doc: Doc) -> Doc:
        doc = {**doc, "type": kind}
        with self._lock:
            self._data.setdefault(kind, {})[doc["id"]] = copy.deepcopy(doc)
        return doc

    def get(self, kind: str, doc_id: str) -> Doc | None:
        d = self._data.get(kind, {}).get(doc_id)
        return copy.deepcopy(d) if d else None

    def query(self, kind, where=None, since=None, order_by=None, desc=True, limit=None):
        rows = [copy.deepcopy(d) for d in self._data.get(kind, {}).values()]
        for k, v in (where or {}).items():
            rows = [r for r in rows if r.get(k) == v]
        if since:
            field, value = since
            rows = [r for r in rows if str(r.get(field, "")) >= value]
        if order_by:
            rows.sort(key=lambda r: str(r.get(order_by, "")), reverse=desc)
        return rows[:limit] if limit else rows

    def delete(self, kind: str, doc_id: str) -> None:
        self._data.get(kind, {}).pop(doc_id, None)


class CosmosStore:
    """Cosmos DB with Entra ID (managed identity) auth; account keys are disabled in Azure."""

    def __init__(self, endpoint: str, database: str) -> None:
        from azure.cosmos import CosmosClient
        from azure.identity import DefaultAzureCredential

        client = CosmosClient(endpoint, credential=DefaultAzureCredential())
        self._c = client.get_database_client(database).get_container_client("items")

    @staticmethod
    def _clean(d: Doc) -> Doc:
        return {k: v for k, v in d.items() if not k.startswith("_")}

    def upsert(self, kind: str, doc: Doc) -> Doc:
        doc = {**doc, "type": kind}
        return self._clean(self._c.upsert_item(doc))

    def get(self, kind: str, doc_id: str) -> Doc | None:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError
        try:
            return self._clean(self._c.read_item(doc_id, partition_key=kind))
        except CosmosResourceNotFoundError:
            return None

    def query(self, kind, where=None, since=None, order_by=None, desc=True, limit=None):
        sql = "SELECT * FROM c WHERE c.type = @type"
        params: list[dict[str, Any]] = [{"name": "@type", "value": kind}]
        for i, (k, v) in enumerate((where or {}).items()):
            if not k.replace("_", "").isalnum():
                raise ValueError(f"bad field {k}")
            sql += f" AND c.{k} = @p{i}"
            params.append({"name": f"@p{i}", "value": v})
        if since:
            sql += f" AND c.{since[0]} >= @since"
            params.append({"name": "@since", "value": since[1]})
        if order_by:
            sql += f" ORDER BY c.{order_by} {'DESC' if desc else 'ASC'}"
        if limit:
            sql += f" OFFSET 0 LIMIT {int(limit)}"
        items = self._c.query_items(sql, parameters=params, partition_key=kind)
        return [self._clean(d) for d in items]

    def delete(self, kind: str, doc_id: str) -> None:
        from azure.cosmos.exceptions import CosmosResourceNotFoundError
        try:
            self._c.delete_item(doc_id, partition_key=kind)
        except CosmosResourceNotFoundError:
            pass


_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        from .config import get_settings
        s = get_settings()
        _store = CosmosStore(s.cosmos_endpoint, s.cosmos_database) if s.store_provider == "cosmos" else MemoryStore()
    return _store


def set_store(store: Store) -> None:
    global _store
    _store = store
