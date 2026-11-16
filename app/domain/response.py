"""Controlled incident response: propose -> approve (two-person rule) -> execute (dry-run by default) -> revert.

Live execution targets:
* `mediflow` - sends a command to the `mediflow-commands` Storage Queue (disable/enable user, block/unblock IP).
* `local`    - records the block in CyberSentinel's own blocklist (always available, free).
Anything else is simulated and clearly labelled.
"""
from __future__ import annotations

from typing import Any

from ..core.bus import get_bus
from ..core.config import get_settings
from ..core.store import Store, new_id, now_iso

KINDS = ("block_ip", "disable_user", "force_password_reset", "isolate_host")
INVERSE = {"block_ip": "unblock_ip", "disable_user": "enable_user", "isolate_host": "release_host", "force_password_reset": None}
MEDIFLOW_CMDS = {"block_ip", "unblock_ip", "disable_user", "enable_user"}


class ActionError(Exception):
    def __init__(self, status: int, msg: str) -> None:
        super().__init__(msg)
        self.status = status


def _apply(store: Store, action: dict[str, Any], command: str) -> dict[str, Any]:
    if action["dry_run"]:
        return {"mode": "dry-run", "detail": f"Would run {command} on {action['target']} ({action['target_system']}). Nothing changed."}
    if command in ("block_ip", "unblock_ip"):
        key = action["target"].replace(".", "_").replace(":", "_")
        if command == "block_ip":
            store.upsert("blocklist", {"id": key, "ip": action["target"], "action_id": action["id"], "at": now_iso()})
        else:
            store.delete("blocklist", key)
    if action["target_system"] == "mediflow" and command in MEDIFLOW_CMDS:
        s = get_settings()
        get_bus().send(s.commands_queue, {"command": command, "target": action["target"], "action_id": action["id"],
                                          "reason": action.get("reason", ""), "requested_by": action["approved_by"], "at": now_iso()})
        return {"mode": "live", "detail": f"Sent {command} for {action['target']} to MediFlow via queue '{s.commands_queue}'."}
    if command in ("block_ip", "unblock_ip"):
        return {"mode": "live", "detail": f"{command} recorded in CyberSentinel blocklist."}
    return {"mode": "simulated", "detail": f"{command} on {action['target']} simulated (no connector configured for {action['target_system']})."}


def propose(store: Store, incident_id: str, kind: str, target: str, target_system: str, dry_run: bool, reason: str, user: str) -> dict[str, Any]:
    if kind not in KINDS:
        raise ActionError(422, f"kind must be one of {KINDS}")
    if not store.get("incident", incident_id):
        raise ActionError(404, "Incident not found")
    if not target.strip():
        raise ActionError(422, "target is required")
    return store.upsert("action", {"id": new_id("act_"), "incident_id": incident_id, "kind": kind, "target": target.strip(),
                                   "target_system": target_system, "dry_run": dry_run, "reason": reason, "status": "proposed",
                                   "requested_by": user, "approved_by": None, "created_at": now_iso(), "history": [
                                       {"at": now_iso(), "by": user, "event": "proposed"}]})


def _get(store: Store, action_id: str) -> dict[str, Any]:
    a = store.get("action", action_id)
    if not a:
        raise ActionError(404, "Action not found")
    return a


def approve(store: Store, action_id: str, user: str) -> dict[str, Any]:
    a = _get(store, action_id)
    if a["status"] != "proposed":
        raise ActionError(409, f"Action is {a['status']}")
    if a["requested_by"] == user:
        raise ActionError(403, "Two-person rule: the requester cannot approve their own action")
    a.update(status="approved", approved_by=user)
    a["history"].append({"at": now_iso(), "by": user, "event": "approved"})
    return store.upsert("action", a)


def reject(store: Store, action_id: str, user: str, note: str) -> dict[str, Any]:
    a = _get(store, action_id)
    if a["status"] not in ("proposed", "approved"):
        raise ActionError(409, f"Action is {a['status']}")
    a["status"] = "rejected"
    a["history"].append({"at": now_iso(), "by": user, "event": f"rejected: {note}"})
    return store.upsert("action", a)


def execute(store: Store, action_id: str, user: str) -> dict[str, Any]:
    a = _get(store, action_id)
    if a["status"] != "approved":
        raise ActionError(409, "Only approved actions can be executed")
    a["result"] = _apply(store, a, a["kind"])
    a.update(status="executed", executed_by=user, executed_at=now_iso())
    a["history"].append({"at": now_iso(), "by": user, "event": f"executed ({a['result']['mode']})"})
    inc = store.get("incident", a["incident_id"])
    if inc and inc["status"] in ("open", "investigating") and not a["dry_run"]:
        inc["status"] = "contained"
        inc["updated_at"] = now_iso()
        store.upsert("incident", inc)
    return store.upsert("action", a)


def revert(store: Store, action_id: str, user: str) -> dict[str, Any]:
    a = _get(store, action_id)
    if a["status"] != "executed":
        raise ActionError(409, "Only executed actions can be reverted")
    inverse = INVERSE.get(a["kind"])
    if inverse is None:
        raise ActionError(409, f"{a['kind']} cannot be reverted")
    a["revert_result"] = _apply(store, a, inverse)
    a.update(status="reverted", reverted_by=user, reverted_at=now_iso())
    a["history"].append({"at": now_iso(), "by": user, "event": "reverted"})
    return store.upsert("action", a)
