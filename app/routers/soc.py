"""Log ingestion, alerts, incidents (triage + explanation), response actions and the SOC dashboard."""
from __future__ import annotations

import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from ..core.config import get_settings
from ..core.security import ANY, LEAD, WRITE, User, audit
from ..core.store import get_store, now_iso
from ..domain import pipeline, response
from ..domain.normalize import parse_file

router = APIRouter(prefix="/api", tags=["soc"])


class IngestIn(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=2000)


class AlertStatusIn(BaseModel):
    status: Literal["new", "acknowledged", "resolved", "false_positive"]
    note: str = Field(default="", max_length=500)


class IncidentPatch(BaseModel):
    status: Literal["open", "investigating", "contained", "closed"] | None = None
    assigned_to: str | None = None
    note: str | None = Field(default=None, max_length=1000)


class ActionIn(BaseModel):
    kind: Literal["block_ip", "disable_user", "force_password_reset", "isolate_host"]
    target: str = Field(min_length=1, max_length=120)
    target_system: Literal["mediflow", "local", "simulated"] = "local"
    dry_run: bool = True
    reason: str = Field(default="", max_length=300)


class RejectIn(BaseModel):
    note: str = Field(default="", max_length=300)


# ---------------------------------------------------------------- ingestion
@router.post("/logs")
def ingest(body: IngestIn, request: Request, user: User = Depends(WRITE)) -> dict:
    result = pipeline.ingest(body.events)
    audit(user, "logs.ingest", "logs", None, request, count=result["ingested"])
    return result


@router.post("/logs/upload")
async def upload(request: Request, file: UploadFile = File(...), source: str = Form(""), user: User = Depends(WRITE)) -> dict:
    data = await file.read()
    if len(data) > 2 * 1024 * 1024:
        raise HTTPException(413, "File larger than 2 MB")
    try:
        rows = parse_file(data.decode("utf-8", errors="replace"), source)
    except ValueError as e:
        raise HTTPException(422, f"Could not parse file: {e}")
    result = pipeline.ingest(rows)
    audit(user, "logs.upload", "logs", file.filename, request, count=result["ingested"])
    return result


@router.post("/ingest", tags=["integration"])
def external_ingest(body: IngestIn, x_ingest_key: str = Header(default="")) -> dict:
    """Machine-to-machine ingestion for external apps (e.g. MediFlow). Auth: X-Ingest-Key header."""
    key = get_settings().ingest_api_key
    if not key or not hmac.compare_digest(x_ingest_key, key):
        raise HTTPException(401, "Invalid ingest key")
    return pipeline.ingest(body.events)


@router.get("/logs")
def list_logs(source: str | None = None, user_name: str | None = None, ip: str | None = None, event_type: str | None = None,
              hours: int = 24, limit: int = 200, user: User = Depends(ANY)) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(hours=min(hours, 24 * 30))).strftime("%Y-%m-%dT%H:%M:%SZ")
    where = {k: v for k, v in {"source": source, "user": user_name, "ip": ip, "event_type": event_type}.items() if v}
    return get_store().query("log", where, since=("timestamp", since), order_by="timestamp", limit=min(limit, 1000))


# ---------------------------------------------------------------- alerts
@router.get("/alerts")
def list_alerts(status: str | None = None, severity: str | None = None, user: User = Depends(ANY)) -> list[dict]:
    where = {k: v for k, v in {"status": status, "severity": severity}.items() if v}
    return get_store().query("alert", where, order_by="last_seen", limit=500)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, user: User = Depends(ANY)) -> dict:
    s = get_store()
    a = s.get("alert", alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    a["evidence_logs"] = [l for l in (s.get("log", i) for i in a["evidence"][:30]) if l]
    return a


@router.post("/alerts/{alert_id}/status")
def set_alert_status(alert_id: str, body: AlertStatusIn, request: Request, user: User = Depends(WRITE)) -> dict:
    s = get_store()
    a = s.get("alert", alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    a.update(status=body.status, updated_at=now_iso(), triaged_by=user.username, triage_note=body.note)
    audit(user, f"alert.{body.status}", "alert", alert_id, request)
    return s.upsert("alert", a)


# ---------------------------------------------------------------- incidents
@router.get("/incidents")
def list_incidents(status: str | None = None, user: User = Depends(ANY)) -> list[dict]:
    rows = get_store().query("incident", {"status": status} if status else None, order_by="updated_at", limit=300)
    return [{k: i.get(k) for k in ("id", "title", "severity", "status", "entity_type", "entity", "alert_ids", "mitre", "first_seen",
                                    "last_seen", "assigned_to", "updated_at")} for i in rows]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, user: User = Depends(ANY)) -> dict:
    s = get_store()
    inc = s.get("incident", incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    inc["alerts"] = [a for a in (s.get("alert", i) for i in inc["alert_ids"]) if a]
    inc["actions"] = s.query("action", {"incident_id": incident_id}, order_by="created_at")
    return inc


@router.patch("/incidents/{incident_id}")
def patch_incident(incident_id: str, body: IncidentPatch, request: Request, user: User = Depends(WRITE)) -> dict:
    s = get_store()
    inc = s.get("incident", incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    if body.status:
        inc["status"] = body.status
        if body.status == "closed":
            for aid in inc["alert_ids"]:
                a = s.get("alert", aid)
                if a and a["status"] in ("new", "acknowledged"):
                    a["status"] = "resolved"
                    s.upsert("alert", a)
    if body.assigned_to is not None:
        inc["assigned_to"] = body.assigned_to or None
    if body.note:
        inc.setdefault("notes", []).append({"at": now_iso(), "by": user.username, "text": body.note})
    inc["updated_at"] = now_iso()
    audit(user, "incident.update", "incident", incident_id, request, status=body.status)
    return s.upsert("incident", inc)


# ---------------------------------------------------------------- response actions
def _run(fn, *args):
    try:
        return fn(get_store(), *args)
    except response.ActionError as e:
        raise HTTPException(e.status, str(e))


@router.post("/incidents/{incident_id}/actions", status_code=201)
def propose_action(incident_id: str, body: ActionIn, request: Request, user: User = Depends(WRITE)) -> dict:
    a = _run(response.propose, incident_id, body.kind, body.target, body.target_system, body.dry_run, body.reason, user.username)
    audit(user, "action.propose", "action", a["id"], request, kind=body.kind, target=body.target, dry_run=body.dry_run)
    return a


@router.get("/actions")
def list_actions(status: str | None = None, user: User = Depends(ANY)) -> list[dict]:
    return get_store().query("action", {"status": status} if status else None, order_by="created_at", limit=300)


@router.post("/actions/{action_id}/approve")
def approve_action(action_id: str, request: Request, user: User = Depends(LEAD)) -> dict:
    a = _run(response.approve, action_id, user.username)
    audit(user, "action.approve", "action", action_id, request)
    return a


@router.post("/actions/{action_id}/reject")
def reject_action(action_id: str, body: RejectIn, request: Request, user: User = Depends(LEAD)) -> dict:
    a = _run(response.reject, action_id, user.username, body.note)
    audit(user, "action.reject", "action", action_id, request)
    return a


@router.post("/actions/{action_id}/execute")
def execute_action(action_id: str, request: Request, user: User = Depends(LEAD)) -> dict:
    a = _run(response.execute, action_id, user.username)
    audit(user, "action.execute", "action", action_id, request, mode=a["result"]["mode"])
    return a


@router.post("/actions/{action_id}/revert")
def revert_action(action_id: str, request: Request, user: User = Depends(LEAD)) -> dict:
    a = _run(response.revert, action_id, user.username)
    audit(user, "action.revert", "action", action_id, request)
    return a


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard")
def dashboard(user: User = Depends(ANY)) -> dict:
    s = get_store()
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs = s.query("log", since=("timestamp", since))
    alerts = s.query("alert")
    open_alerts = [a for a in alerts if a["status"] in ("new", "acknowledged")]
    incidents = s.query("incident")
    hours = [(now - timedelta(hours=h)).strftime("%Y-%m-%dT%H") for h in range(23, -1, -1)]
    per_hour = {h: {"total": 0, "failures": 0} for h in hours}
    for l in logs:
        b = per_hour.get(l["timestamp"][:13])
        if b:
            b["total"] += 1
            b["failures"] += l.get("outcome") == "failure"
    ip_count: dict[str, int] = {}
    for a in open_alerts:
        if a["entity_type"] == "ip":
            ip_count[a["entity"]] = ip_count.get(a["entity"], 0) + a["count"]
    assets = s.query("asset")
    return {
        "logs_24h": len(logs), "failures_24h": sum(l.get("outcome") == "failure" for l in logs),
        "open_alerts": len(open_alerts),
        "alerts_by_severity": {sev: sum(a["severity"] == sev for a in open_alerts) for sev in ("critical", "high", "medium", "low")},
        "open_incidents": sum(i["status"] != "closed" for i in incidents),
        "pending_actions": len(s.query("action", {"status": "proposed"})) + len(s.query("action", {"status": "approved"})),
        "timeline": [{"hour": h[11:] + ":00", **per_hour[h]} for h in hours],
        "top_ips": sorted(({"ip": k, "events": v} for k, v in ip_count.items()), key=lambda x: -x["events"])[:5],
        "top_rules": sorted(({"rule": r, "count": sum(a["rule_name"] == r for a in open_alerts)} for r in {a["rule_name"] for a in open_alerts}), key=lambda x: -x["count"])[:6],
        "assets": len(assets), "assets_high_risk": sum((a.get("last_scan") or {}).get("rating") in ("high", "critical") for a in assets),
    }
