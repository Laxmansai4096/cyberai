"""Ingest -> normalise -> store -> detect -> alert (dedupe) -> correlate into incidents -> explain."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from ..core.config import get_settings
from ..core.store import Store, get_store, new_id, now_iso
from . import detection
from .detection import RULES, ts
from .explain import SEV_ORDER, explain
from .normalize import normalize

OPEN_ALERT = ("new", "acknowledged")
OPEN_INCIDENT = ("open", "investigating", "contained")


def iocs(store: Store) -> dict[str, str]:
    return {d["value"]: d.get("description", "custom IoC") for d in store.query("ioc")}


def ingest(raws: list[dict[str, Any]], store: Store | None = None) -> dict[str, Any]:
    store = store or get_store()
    s = get_settings()
    logs, skipped = [], 0
    for raw in raws[:2000]:
        n = normalize(raw)
        if n is None:
            skipped += 1
            continue
        n["ttl"] = s.log_ttl_seconds
        logs.append(store.upsert("log", n))
    if not logs:
        return {"ingested": 0, "skipped": skipped, "alerts_created": 0, "alerts_updated": 0, "incidents": []}
    new_ids = {l["id"] for l in logs}
    anchor = min(l["timestamp"] for l in logs)
    since = (ts(anchor) - timedelta(minutes=s.detection_window_min)).strftime("%Y-%m-%dT%H:%M:%SZ")
    recent = store.query("log", since=("timestamp", since), order_by="timestamp", desc=False)
    hist_since = (ts(anchor) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    users = {l["user"] for l in logs if l.get("user")}
    history = [l for l in store.query("log", since=("timestamp", hist_since)) if l.get("user") in users] if users else []
    created = updated = 0
    touched: set[str] = set()
    for hit in detection.run_all(recent, history, iocs(store)):
        if not new_ids & set(hit["evidence"]):
            continue  # only alert on detections that involve the newly ingested events
        alert, is_new = upsert_alert(store, hit)
        created += is_new
        updated += not is_new
        touched.add(correlate(store, alert))
    return {"ingested": len(logs), "skipped": skipped, "alerts_created": created, "alerts_updated": updated, "incidents": sorted(touched)}


def upsert_alert(store: Store, hit: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    rule = RULES[hit["rule_id"]]
    key = f"{hit['rule_id']}|{hit['entity_type']}|{hit['entity']}"
    existing = [a for a in store.query("alert", {"dedupe_key": key}) if a["status"] in OPEN_ALERT]
    if existing:
        a = existing[0]
        a["evidence"] = list(dict.fromkeys(a["evidence"] + hit["evidence"]))[:100]
        a["count"] = len(a["evidence"])
        a["last_seen"] = max(a["last_seen"], hit["last_seen"])
        a["extra"] = {**a.get("extra", {}), **hit["extra"]}
        a["updated_at"] = now_iso()
        return store.upsert("alert", a), False
    a = {"id": new_id("al_"), "dedupe_key": key, "rule_id": rule.id, "rule_name": rule.name, "severity": rule.severity,
         "mitre": list(rule.mitre), "description": rule.description, "entity_type": hit["entity_type"], "entity": hit["entity"],
         "evidence": hit["evidence"], "count": hit["count"], "first_seen": hit["first_seen"], "last_seen": hit["last_seen"],
         "extra": hit["extra"], "status": "new", "incident_id": None, "created_at": now_iso(), "updated_at": now_iso()}
    return store.upsert("alert", a), True


def correlate(store: Store, alert: dict[str, Any]) -> str:
    """Group alerts by entity (and link a compromised user to the attacking IP's incident)."""
    candidates = [i for i in store.query("incident", {"entity": alert["entity"]}) if i["status"] in OPEN_INCIDENT]
    ip = alert.get("extra", {}).get("success_ip")
    if not candidates and ip:
        candidates = [i for i in store.query("incident", {"entity": ip}) if i["status"] in OPEN_INCIDENT]
    if candidates:
        inc = candidates[0]
        if alert["id"] not in inc["alert_ids"]:
            inc["alert_ids"].append(alert["id"])
    else:
        inc = {"id": new_id("inc_"), "entity_type": alert["entity_type"], "entity": alert["entity"], "alert_ids": [alert["id"]],
               "status": "open", "assigned_to": None, "notes": [], "created_at": now_iso()}
    alerts = [a for a in (store.get("alert", aid) for aid in inc["alert_ids"]) if a]
    alerts = [alert if a["id"] == alert["id"] else a for a in alerts]
    inc["severity"] = SEV_ORDER[max(SEV_ORDER.index(a["severity"]) for a in alerts)]
    top = max(alerts, key=lambda a: SEV_ORDER.index(a["severity"]))
    inc["title"] = f"{top['rule_name']} - {inc['entity_type']} {inc['entity']}"
    inc["mitre"] = sorted({t for a in alerts for t in a["mitre"]})
    inc["first_seen"] = min(a["first_seen"] for a in alerts)
    inc["last_seen"] = max(a["last_seen"] for a in alerts)
    inc["explanation"] = explain(inc, alerts, iocs(store))
    inc["updated_at"] = now_iso()
    store.upsert("incident", inc)
    alert["incident_id"] = inc["id"]
    store.upsert("alert", alert)
    return inc["id"]
