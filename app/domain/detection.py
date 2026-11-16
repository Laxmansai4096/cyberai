"""Detection engine: sliding-window rules (MITRE ATT&CK mapped) + statistical anomaly detection. No paid ML/LLM.

Each detector receives the recent normalised logs (sorted by time) and returns "hits":
{rule_id, entity_type, entity, evidence: [log ids], first_seen, last_seen, extra}
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

Log = dict[str, Any]
Hit = dict[str, Any]
IST = timezone(timedelta(hours=5, minutes=30))

# Local threat-intel feed (documentation IP ranges, safe for demos). Admins can add more IoCs via the API.
THREAT_INTEL: dict[str, str] = {
    "203.0.113.66": "Known brute-force botnet node (demo feed)",
    "198.51.100.23": "Tor exit / anonymiser (demo feed)",
    "192.0.2.200": "C2 infrastructure seen in phishing campaign (demo feed)",
}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    mitre: tuple[str, ...]
    description: str


RULES: dict[str, Rule] = {r.id: r for r in [
    Rule("CS-R001", "Brute-force login", "high", ("T1110",), "Many failed logins from one IP in a short window."),
    Rule("CS-R002", "Password spraying", "high", ("T1110.003",), "One IP failing logins against many different accounts."),
    Rule("CS-R003", "Successful login after failures", "critical", ("T1110", "T1078"), "An account logged in successfully right after a run of failures - possible compromise."),
    Rule("CS-R004", "Mass sensitive-record access", "high", ("T1213", "T1530"), "A user read an unusually large number of distinct records (e.g. patient files)."),
    Rule("CS-R005", "Privilege probing", "medium", ("T1069", "T1078"), "Repeated authorisation denials: a user is trying functions outside their role."),
    Rule("CS-R006", "Port scan", "medium", ("T1046",), "One source touched many destination ports in a short window."),
    Rule("CS-R007", "Threat-intel IP match", "high", ("T1071",), "Activity from an IP address on the threat-intelligence list."),
    Rule("CS-R008", "Off-hours privileged activity", "medium", ("T1078.004",), "Administrative actions between 00:00 and 05:00 IST."),
    Rule("CS-R009", "Bulk data export", "high", ("T1020", "T1567"), "Several record exports in a short window - possible exfiltration."),
    Rule("CS-R010", "Account added to privileged group / log cleared", "high", ("T1098", "T1070.001"), "Persistence or defence-evasion activity on a host."),
    Rule("CS-A001", "Activity volume anomaly", "medium", ("T1078",), "A user's hourly activity is far above their own baseline (z-score)."),
    Rule("CS-A002", "Login from new IP", "low", ("T1078",), "Successful login from an IP this user has never used before."),
]}

THRESHOLDS = {"bruteforce_n": 5, "bruteforce_min": 10, "spray_users": 4, "spray_min": 10, "after_fail_n": 3, "after_fail_min": 15,
              "mass_read_n": 15, "mass_read_min": 15, "probe_n": 5, "probe_min": 10, "scan_ports": 10, "scan_min": 5,
              "export_n": 3, "export_min": 10, "anomaly_z": 3.0, "anomaly_min_count": 15, "baseline_buckets": 5, "new_ip_history": 5}


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _hit(rule_id: str, etype: str, entity: str, logs: list[Log], **extra: Any) -> Hit:
    return {"rule_id": rule_id, "entity_type": etype, "entity": entity, "evidence": [l["id"] for l in logs][:50],
            "first_seen": logs[0]["timestamp"], "last_seen": logs[-1]["timestamp"], "count": len(logs), "extra": extra}


def _window(logs: list[Log], minutes: int, ok: Callable[[list[Log]], bool]) -> list[Log] | None:
    """Two-pointer sliding window; returns the largest qualifying window."""
    best, j = None, 0
    for i in range(len(logs)):
        while ts(logs[i]["timestamp"]) - ts(logs[j]["timestamp"]) > timedelta(minutes=minutes):
            j += 1
        w = logs[j:i + 1]
        if ok(w) and (best is None or len(w) > len(best)):
            best = w
    return best


def _group(logs: list[Log], key: str, pred: Callable[[Log], bool]) -> dict[str, list[Log]]:
    g: dict[str, list[Log]] = defaultdict(list)
    for l in logs:
        if l.get(key) and pred(l):
            g[str(l[key])].append(l)
    return g


def r001_bruteforce(logs: list[Log]) -> list[Hit]:
    out = []
    for ip, ev in _group(logs, "ip", lambda l: l["event_type"] == "auth.login_failure").items():
        if w := _window(ev, THRESHOLDS["bruteforce_min"], lambda w: len(w) >= THRESHOLDS["bruteforce_n"]):
            out.append(_hit("CS-R001", "ip", ip, w, users=sorted({l["user"] for l in w if l.get("user")})[:10]))
    return out


def r002_spray(logs: list[Log]) -> list[Hit]:
    out = []
    for ip, ev in _group(logs, "ip", lambda l: l["event_type"] == "auth.login_failure").items():
        if w := _window(ev, THRESHOLDS["spray_min"], lambda w: len({l.get("user") for l in w}) >= THRESHOLDS["spray_users"]):
            out.append(_hit("CS-R002", "ip", ip, w, distinct_users=len({l.get("user") for l in w})))
    return out


def r003_success_after_fail(logs: list[Log]) -> list[Hit]:
    out = []
    for user, ev in _group(logs, "user", lambda l: l["event_type"] in ("auth.login_failure", "auth.login_success")).items():
        fails: list[Log] = []
        for l in ev:
            if l["event_type"] == "auth.login_failure":
                fails = [f for f in fails if ts(l["timestamp"]) - ts(f["timestamp"]) <= timedelta(minutes=THRESHOLDS["after_fail_min"])] + [l]
            elif len(fails) >= THRESHOLDS["after_fail_n"] and ts(l["timestamp"]) - ts(fails[-1]["timestamp"]) <= timedelta(minutes=THRESHOLDS["after_fail_min"]):
                out.append(_hit("CS-R003", "user", user, fails + [l], success_ip=l.get("ip")))
                fails = []
    return out


def r004_mass_read(logs: list[Log]) -> list[Hit]:
    out = []
    for user, ev in _group(logs, "user", lambda l: l["event_type"] == "phi.read").items():
        n = THRESHOLDS["mass_read_n"]
        if w := _window(ev, THRESHOLDS["mass_read_min"], lambda w: len({l.get("resource") for l in w}) >= n):
            out.append(_hit("CS-R004", "user", user, w, distinct_records=len({l.get("resource") for l in w})))
    return out


def r005_probe(logs: list[Log]) -> list[Hit]:
    out = []
    for user, ev in _group(logs, "user", lambda l: l["event_type"] == "authz.denied").items():
        if w := _window(ev, THRESHOLDS["probe_min"], lambda w: len(w) >= THRESHOLDS["probe_n"]):
            out.append(_hit("CS-R005", "user", user, w, resources=sorted({l.get("resource") or "" for l in w})[:10]))
    return out


def r006_portscan(logs: list[Log]) -> list[Hit]:
    out = []
    for ip, ev in _group(logs, "ip", lambda l: l["event_type"] == "net.connection" and bool(l.get("dst_port"))).items():
        if w := _window(ev, THRESHOLDS["scan_min"], lambda w: len({l["dst_port"] for l in w}) >= THRESHOLDS["scan_ports"]):
            out.append(_hit("CS-R006", "ip", ip, w, ports=sorted({l["dst_port"] for l in w})[:30]))
    return out


def r007_threat_intel(logs: list[Log], iocs: dict[str, str]) -> list[Hit]:
    feed = {**THREAT_INTEL, **iocs}
    return [_hit("CS-R007", "ip", ip, ev, intel=feed[ip]) for ip, ev in _group(logs, "ip", lambda l: l["ip"] in feed).items()]


def r008_off_hours(logs: list[Log]) -> list[Hit]:
    def priv(l: Log) -> bool:
        h = ts(l["timestamp"]).astimezone(IST).hour
        return h < 5 and (l["event_type"].startswith("admin.") or "Admin" in (l.get("roles") or []) or l["event_type"] == "priv.sudo")
    return [_hit("CS-R008", "user", u, ev) for u, ev in _group(logs, "user", priv).items()]


def r009_export(logs: list[Log]) -> list[Hit]:
    out = []
    for user, ev in _group(logs, "user", lambda l: l["event_type"] in ("phi.export", "data.export")).items():
        if w := _window(ev, THRESHOLDS["export_min"], lambda w: len(w) >= THRESHOLDS["export_n"]):
            out.append(_hit("CS-R009", "user", user, w))
    return out


def r010_persistence(logs: list[Log]) -> list[Hit]:
    ev = [l for l in logs if l["event_type"] in ("admin.group_member_added", "defense.audit_log_cleared")]
    g: dict[str, list[Log]] = defaultdict(list)
    for l in ev:
        g[l.get("host") or "unknown"].append(l)
    return [_hit("CS-R010", "host", h, e, events=sorted({x["event_type"] for x in e})) for h, e in g.items()]


def a001_volume(recent: list[Log], history: list[Log]) -> list[Hit]:
    """Per-user hourly count vs that user's own active-hour baseline."""
    out = []
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for l in history:
        if l.get("user"):
            buckets[l["user"]][l["timestamp"][:13]] += 1
    for user, ev in _group(recent, "user", lambda l: True).items():
        last_hour = ev[-1]["timestamp"][:13]
        current = [l for l in ev if l["timestamp"][:13] == last_hour]
        base = [c for h, c in buckets.get(user, {}).items() if h != last_hour]
        if len(base) < THRESHOLDS["baseline_buckets"] or len(current) < THRESHOLDS["anomaly_min_count"]:
            continue
        mean, sd = statistics.mean(base), statistics.pstdev(base)
        z = (len(current) - mean) / max(sd, 1.0)
        if z >= THRESHOLDS["anomaly_z"]:
            out.append(_hit("CS-A001", "user", user, current, z_score=round(z, 2), baseline_mean=round(mean, 1), current=len(current)))
    return out


def a002_new_ip(recent: list[Log], history: list[Log]) -> list[Hit]:
    out = []
    seen: dict[str, set[str]] = defaultdict(set)
    count: dict[str, int] = defaultdict(int)
    recent_ids = {l["id"] for l in recent}
    merged = sorted({l["id"]: l for l in history + recent}.values(), key=lambda l: l["timestamp"])
    for l in merged:
        u, ip = l.get("user"), l.get("ip")
        if l["event_type"] != "auth.login_success" or not u or not ip:
            continue
        if l["id"] in recent_ids and count[u] >= THRESHOLDS["new_ip_history"] and ip not in seen[u]:
            out.append(_hit("CS-A002", "user", u, [l], new_ip=ip, known_ips=sorted(seen[u])[:5]))
        seen[u].add(ip)
        count[u] += 1
    return out


def run_all(recent: list[Log], history: list[Log], iocs: dict[str, str] | None = None) -> list[Hit]:
    recent = sorted(recent, key=lambda l: l["timestamp"])
    hits: list[Hit] = []
    for fn in (r001_bruteforce, r002_spray, r003_success_after_fail, r004_mass_read, r005_probe, r006_portscan,
               r008_off_hours, r009_export, r010_persistence):
        hits += fn(recent)
    hits += r007_threat_intel(recent, iocs or {})
    hits += a001_volume(recent, history)
    hits += a002_new_ip(recent, sorted(history, key=lambda l: l["timestamp"]))
    return hits
