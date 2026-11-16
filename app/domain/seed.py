"""Synthetic demo data and attack simulator (TEST-NET documentation IPs only)."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

from ..core.config import get_settings
from ..core.security import hash_password
from ..core.store import Store, now_iso

USERS = [("u_admin", "admin", "Ananya Admin", ["Admin"]), ("u_lead1", "lead.sara", "Sara Thomas (SOC Lead)", ["SecurityLead"]),
         ("u_lead2", "lead.omar", "Omar Farooq (SOC Lead)", ["SecurityLead"]), ("u_analyst", "analyst.ravi", "Ravi Teja (Analyst)", ["Analyst"]),
         ("u_viewer", "viewer.neha", "Neha Gupta (Auditor)", ["Viewer"])]

ASSETS = [
    {"id": "as_mediflow", "name": "mediflow-api", "kind": "application", "owner": "Hospital IT", "criticality": "critical", "environment": "prod",
     "packages": [{"ecosystem": "PyPI", "name": "jinja2", "version": "3.1.2"}, {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0"},
                  {"ecosystem": "PyPI", "name": "fastapi", "version": "0.115.0"}],
     "config": {"mfa_enabled": True, "tls_min_version": "1.2", "open_ports": [443], "internet_exposed": True, "encryption_at_rest": True, "days_since_patch": 20, "logging_enabled": True}},
    {"id": "as_legacy", "name": "legacy-lab-server", "kind": "server", "owner": "Pathology", "criticality": "high", "environment": "prod",
     "packages": [{"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"}, {"ecosystem": "Debian", "name": "openssh-server", "version": "9.2"}],
     "config": {"mfa_enabled": False, "tls_min_version": "1.0", "open_ports": [22, 23, 8080, 5432], "internet_exposed": True, "encryption_at_rest": False, "days_since_patch": 240, "default_credentials": True}},
    {"id": "as_portal", "name": "patient-portal-web", "kind": "application", "owner": "Digital", "criticality": "medium", "environment": "prod",
     "packages": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}, {"ecosystem": "npm", "name": "axios", "version": "1.7.2"}],
     "config": {"mfa_enabled": True, "tls_min_version": "1.2", "open_ports": [443], "internet_exposed": True, "encryption_at_rest": True, "days_since_patch": 45}},
]


def seed(store: Store) -> None:
    if store.get("user", "u_admin"):
        return
    pw = hash_password(get_settings().seed_password)
    for uid, username, name, roles in USERS:
        store.upsert("user", {"id": uid, "username": username, "display_name": name, "roles": roles, "password_hash": pw,
                              "disabled": False, "failed_logins": 0, "locked_until": None, "created_at": now_iso()})
    for a in ASSETS:
        store.upsert("asset", {**a, "created_at": now_iso(), "last_scan": None})


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mf(t: datetime, et: str, user: str, ip: str, outcome: str = "success", resource: str | None = None, roles: list[str] | None = None) -> dict[str, Any]:
    return {"source": "mediflow", "timestamp": _iso(t), "event_type": et, "user": user, "ip": ip, "outcome": outcome,
            "resource": resource, "roles": roles or []}


def scenario(name: str, now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    rnd = random.Random(42)
    t0 = now - timedelta(minutes=8)
    ev: list[dict[str, Any]] = []
    if name == "brute_force":
        ev = [_mf(t0 + timedelta(seconds=20 * i), "auth.login_failure", "dr.rao", "203.0.113.66", "failure") for i in range(8)]
        ev.append(_mf(t0 + timedelta(seconds=200), "auth.login_success", "dr.rao", "203.0.113.66", roles=["Doctor"]))
    elif name == "password_spray":
        users = ["admin", "nurse.priya", "billing.kavya", "reception.arun", "dr.mehta", "patient.anita"]
        ev = [_mf(t0 + timedelta(seconds=15 * i), "auth.login_failure", u, "198.51.100.77", "failure") for i, u in enumerate(users)]
    elif name == "mass_record_access":
        ev = [_mf(t0 + timedelta(seconds=10 * i), "phi.read", "nurse.priya", "10.20.0.15", resource=f"patient/p_{1000 + i}", roles=["Nurse"]) for i in range(22)]
        ev += [_mf(t0 + timedelta(seconds=240 + 20 * i), "phi.export", "nurse.priya", "10.20.0.15", resource=f"patient/p_{1000 + i}/fhir", roles=["Nurse"]) for i in range(3)]
    elif name == "port_scan":
        ev = [{"source": "firewall", "timestamp": _iso(t0 + timedelta(seconds=3 * i)), "src_ip": "192.0.2.200", "dst_ip": "10.0.0.4",
               "dst_port": p, "action": "deny", "protocol": "tcp"} for i, p in enumerate([21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080])]
    elif name == "privilege_probe":
        ev = [_mf(t0 + timedelta(seconds=30 * i), "authz.denied", "reception.arun", "10.20.0.31", "failure", r, ["Receptionist"])
              for i, r in enumerate(["GET /api/admin/users", "GET /api/admin/audit", "POST /api/prescriptions", "GET /api/admin/users", "GET /api/patients/p_anita/fhir", "POST /api/admin/users/u_admin/disable"])]
    elif name == "ssh_linux":
        ev = [{"source": "linux_auth", "host": "legacy-lab-server", "timestamp": _iso(t0 + timedelta(seconds=10 * i)),
               "message": f"sshd[2211]: Failed password for invalid user {u} from 203.0.113.9 port {40000 + i} ssh2"} for i, u in enumerate(["root", "admin", "oracle", "test", "ubuntu", "pi"])]
    elif name == "windows_persistence":
        ev = [{"source": "windows", "EventID": 4732, "TimeCreated": _iso(t0), "Computer": "HIS-DC01", "TargetUserName": "svc_backup", "TargetGroup": "Administrators", "SubjectUserName": "jdoe"},
              {"source": "windows", "EventID": 1102, "TimeCreated": _iso(t0 + timedelta(minutes=2)), "Computer": "HIS-DC01", "SubjectUserName": "jdoe"}]
    elif name == "baseline_then_spike":
        for h in range(1, 8):
            base = now - timedelta(hours=h)
            ev += [_mf(base - timedelta(minutes=rnd.randint(0, 50)), "api.request", "billing.kavya", "10.20.0.40", resource="GET /api/invoices") for _ in range(rnd.randint(3, 6))]
        for _ in range(5):
            ev.append(_mf(now - timedelta(days=1, minutes=rnd.randint(0, 600)), "auth.login_success", "billing.kavya", "10.20.0.40", roles=["Billing"]))
        ev += [_mf(t0 + timedelta(seconds=15 * i), "api.request", "billing.kavya", "10.20.0.40", resource="GET /api/invoices") for i in range(30)]
        ev.append(_mf(t0 + timedelta(seconds=460), "auth.login_success", "billing.kavya", "192.0.2.55", roles=["Billing"]))
    return ev


SCENARIOS = ["brute_force", "password_spray", "mass_record_access", "port_scan", "privilege_probe", "ssh_linux", "windows_persistence", "baseline_then_spike"]
