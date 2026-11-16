"""Normalise heterogeneous security logs into one schema.

Supported inputs: MediFlow security events, firewall JSON, Linux sshd syslog, Windows Security events (4624/4625/4720/4732),
and generic JSON already in the normalised shape. JSONL and plain .log files are parsed by `parse_file`.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from ..core.store import new_id, now_iso

SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
SUDO = re.compile(r"sudo:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$")
WIN = {4624: ("auth.login_success", "success"), 4625: ("auth.login_failure", "failure"),
       4720: ("admin.user_created", "success"), 4732: ("admin.group_member_added", "success"),
       4740: ("auth.account_locked", "failure"), 1102: ("defense.audit_log_cleared", "success")}


def norm_ts(value: Any) -> str:
    if not value:
        return now_iso()
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return now_iso()


def normalize(raw: dict[str, Any]) -> dict[str, Any] | None:
    src = str(raw.get("source", "generic")).lower()
    base: dict[str, Any] = {"id": new_id("log_"), "ingested_at": now_iso(), "source": src, "user": None, "ip": None,
                            "host": raw.get("host"), "outcome": None, "dst_port": None, "roles": [], "resource": None, "details": {}}
    if src == "mediflow":
        base.update(timestamp=norm_ts(raw.get("timestamp")), event_type=raw.get("event_type", "unknown"), user=raw.get("user"),
                    ip=raw.get("ip"), outcome=raw.get("outcome"), roles=raw.get("roles") or [], resource=raw.get("resource"),
                    host="mediflow", details=raw.get("details") or {})
    elif src == "firewall":
        action = str(raw.get("action", "")).lower()
        base.update(timestamp=norm_ts(raw.get("timestamp")), event_type="net.connection", ip=raw.get("src_ip"),
                    host=raw.get("dst_ip"), dst_port=int(raw.get("dst_port") or 0),
                    outcome="failure" if action in ("deny", "drop", "block") else "success", details={"action": action, "protocol": raw.get("protocol")})
    elif src == "linux_auth":
        msg = str(raw.get("message", ""))
        base.update(timestamp=norm_ts(raw.get("timestamp")), host=raw.get("host"))
        if m := SSH_FAIL.search(msg):
            base.update(event_type="auth.login_failure", user=m["user"], ip=m["ip"], outcome="failure", dst_port=22)
        elif m := SSH_OK.search(msg):
            base.update(event_type="auth.login_success", user=m["user"], ip=m["ip"], outcome="success", dst_port=22)
        elif m := SUDO.search(msg):
            base.update(event_type="priv.sudo", user=m["user"], outcome="success", details={"command": m["cmd"][:200]})
        else:
            return None
    elif src == "windows":
        eid = int(raw.get("EventID", 0))
        if eid not in WIN:
            return None
        et, outcome = WIN[eid]
        base.update(timestamp=norm_ts(raw.get("TimeCreated")), event_type=et, outcome=outcome, user=raw.get("TargetUserName"),
                    ip=raw.get("IpAddress") if raw.get("IpAddress") not in ("-", "") else None, host=raw.get("Computer"),
                    details={"event_id": eid, "group": raw.get("TargetGroup"), "subject": raw.get("SubjectUserName")})
    else:
        if not raw.get("event_type"):
            return None
        base.update(timestamp=norm_ts(raw.get("timestamp")), event_type=str(raw["event_type"]), user=raw.get("user"), ip=raw.get("ip"),
                    outcome=raw.get("outcome"), dst_port=raw.get("dst_port"), roles=raw.get("roles") or [],
                    resource=raw.get("resource"), details=raw.get("details") or {})
    return base


def parse_file(text: str, source_hint: str = "") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    stripped = text.strip()
    if stripped.startswith("["):
        return [r for r in json.loads(stripped) if isinstance(r, dict)]
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
                continue
            except json.JSONDecodeError:
                pass
        rows.append({"source": source_hint or "linux_auth", "message": line})
    return rows
