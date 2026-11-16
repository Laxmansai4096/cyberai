"""Assets & vulnerability scans, threat-intel IoCs, users, audit log and the attack simulator."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.config import get_settings
from ..core.security import ANY, LEAD, WRITE, User, audit, require_roles
from ..core.store import get_store, new_id, now_iso
from ..domain import pipeline, vulns
from ..domain.seed import SCENARIOS, scenario

router = APIRouter(prefix="/api", tags=["admin"])
ADMIN = require_roles("Admin")


class Package(BaseModel):
    ecosystem: Literal["PyPI", "npm", "Maven", "Debian", "Go", "NuGet", "crates.io", "RubyGems"]
    name: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=40)


class AssetIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    kind: Literal["server", "application", "database", "network", "endpoint"] = "server"
    owner: str = ""
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    environment: str = "prod"
    packages: list[Package] = []
    config: dict[str, Any] = {}


class IocIn(BaseModel):
    value: str = Field(min_length=3, max_length=100)
    kind: Literal["ip"] = "ip"
    description: str = Field(default="", max_length=200)


class SimIn(BaseModel):
    scenario: str = "all"


@router.get("/assets")
def list_assets(user: User = Depends(ANY)) -> list[dict]:
    return get_store().query("asset", order_by="name", desc=False)


@router.post("/assets", status_code=201)
def create_asset(body: AssetIn, request: Request, user: User = Depends(WRITE)) -> dict:
    doc = get_store().upsert("asset", {"id": new_id("as_"), **body.model_dump(), "created_at": now_iso(), "last_scan": None})
    audit(user, "asset.create", "asset", doc["id"], request)
    return doc


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: str, request: Request, user: User = Depends(LEAD)) -> dict:
    get_store().delete("asset", asset_id)
    audit(user, "asset.delete", "asset", asset_id, request)
    return {"deleted": asset_id}


@router.post("/assets/{asset_id}/scan")
def scan_asset(asset_id: str, request: Request, user: User = Depends(WRITE)) -> dict:
    s = get_store()
    a = s.get("asset", asset_id)
    if not a:
        raise HTTPException(404, "Asset not found")
    a["last_scan"] = {**vulns.scan(a, get_settings().vuln_feed), "scanned_at": now_iso(), "scanned_by": user.username}
    audit(user, "asset.scan", "asset", asset_id, request, risk=a["last_scan"]["risk_score"])
    return s.upsert("asset", a)


@router.get("/iocs")
def list_iocs(user: User = Depends(ANY)) -> list[dict]:
    from ..domain.detection import THREAT_INTEL
    custom = get_store().query("ioc")
    return [{"value": k, "description": v, "builtin": True} for k, v in THREAT_INTEL.items()] + [{**c, "builtin": False} for c in custom]


@router.post("/iocs", status_code=201)
def add_ioc(body: IocIn, request: Request, user: User = Depends(LEAD)) -> dict:
    doc = get_store().upsert("ioc", {"id": body.value.replace(".", "_").replace(":", "_"), **body.model_dump(), "added_by": user.username, "added_at": now_iso()})
    audit(user, "ioc.add", "ioc", body.value, request)
    return doc


@router.get("/blocklist")
def blocklist(user: User = Depends(ANY)) -> list[dict]:
    return get_store().query("blocklist")


@router.get("/admin/users")
def users(user: User = Depends(ADMIN)) -> list[dict]:
    return [{k: u.get(k) for k in ("id", "username", "display_name", "roles", "disabled", "last_login")} for u in get_store().query("user")]


@router.post("/admin/users/{uid}/{action}")
def user_state(uid: str, action: str, request: Request, user: User = Depends(ADMIN)) -> dict:
    if action not in ("disable", "enable") or uid == user.id:
        raise HTTPException(409, "Not allowed")
    s = get_store()
    u = s.get("user", uid)
    if not u:
        raise HTTPException(404, "User not found")
    u["disabled"] = action == "disable"
    s.upsert("user", u)
    audit(user, f"user.{action}", "user", uid, request)
    return {"id": uid, "disabled": u["disabled"]}


@router.get("/admin/audit")
def audit_log(limit: int = 200, user: User = Depends(require_roles("Admin", "SecurityLead", "Viewer"))) -> list[dict]:
    return get_store().query("audit", order_by="ts", limit=min(limit, 500))


@router.get("/demo/scenarios")
def scenarios(user: User = Depends(ANY)) -> list[str]:
    return SCENARIOS


@router.post("/demo/simulate")
def simulate(body: SimIn, request: Request, user: User = Depends(require_roles("Admin", "SecurityLead"))) -> dict:
    names = SCENARIOS if body.scenario == "all" else [body.scenario]
    if any(n not in SCENARIOS for n in names):
        raise HTTPException(422, f"scenario must be 'all' or one of {SCENARIOS}")
    totals = {"ingested": 0, "alerts_created": 0, "alerts_updated": 0, "incidents": set()}
    for n in names:
        r = pipeline.ingest(scenario(n))
        totals["ingested"] += r["ingested"]
        totals["alerts_created"] += r["alerts_created"]
        totals["alerts_updated"] += r["alerts_updated"]
        totals["incidents"] |= set(r["incidents"])
    audit(user, "demo.simulate", "scenario", body.scenario, request)
    return {**totals, "incidents": sorted(totals["incidents"])}
