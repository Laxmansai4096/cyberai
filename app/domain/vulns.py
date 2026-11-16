"""Vulnerability assessment: package CVE matching (local feed or free OSV.dev API) + configuration checks + risk score."""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

log = logging.getLogger(__name__)
SEV_W = {"low": 2, "medium": 5, "high": 10, "critical": 20}
CRIT_MULT = {"low": 0.6, "medium": 1.0, "high": 1.4, "critical": 1.8}

# ecosystem, package, introduced (inclusive), fixed (exclusive), id, severity, summary
LOCAL_FEED: list[tuple[str, str, str, str, str, str, str]] = [
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.0", "2.15.0", "CVE-2021-44228", "critical", "Log4Shell remote code execution via JNDI lookups."),
    ("PyPI", "jinja2", "0", "3.1.4", "CVE-2024-34064", "medium", "XSS via xmlattr filter keys."),
    ("PyPI", "requests", "0", "2.32.0", "CVE-2024-35195", "medium", "Session keeps verify=False for subsequent requests."),
    ("PyPI", "urllib3", "0", "1.26.19", "CVE-2024-37891", "medium", "Proxy-Authorization header not stripped on cross-origin redirects."),
    ("PyPI", "django", "4.2", "4.2.14", "CVE-2024-38875", "high", "Denial of service in urlize/urlizetrunc."),
    ("PyPI", "pillow", "0", "10.3.0", "CVE-2024-28219", "high", "Buffer overflow in _imagingcms.c."),
    ("npm", "lodash", "0", "4.17.21", "CVE-2021-23337", "high", "Command injection via template."),
    ("npm", "express", "0", "4.19.2", "CVE-2024-29041", "medium", "Open redirect in malformed URLs."),
    ("npm", "axios", "1.0.0", "1.6.0", "CVE-2023-45857", "medium", "XSRF-TOKEN leaked to third-party hosts."),
    ("Debian", "openssh-server", "8.5", "9.8", "CVE-2024-6387", "high", "regreSSHion: unauthenticated RCE race condition in sshd."),
    ("Debian", "openssl", "3.0.0", "3.0.7", "CVE-2022-3602", "high", "X.509 email address buffer overflow."),
]


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def _local(pkgs: list[dict[str, str]]) -> list[dict[str, Any]]:
    out = []
    for p in pkgs:
        for eco, name, intro, fixed, vid, sev, summary in LOCAL_FEED:
            if p["ecosystem"].lower() == eco.lower() and p["name"].lower() == name.lower() and vtuple(intro) <= vtuple(p["version"]) < vtuple(fixed):
                out.append({"type": "package", "id": vid, "severity": sev, "package": name, "version": p["version"],
                            "fixed_in": fixed, "summary": summary, "source": "local-feed"})
    return out


def _osv_severity(v: dict[str, Any]) -> str:
    s = str((v.get("database_specific") or {}).get("severity", "")).lower()
    return {"moderate": "medium"}.get(s, s) if s in ("low", "moderate", "medium", "high", "critical") else "medium"


def _osv(pkgs: list[dict[str, str]]) -> list[dict[str, Any]]:
    queries = [{"package": {"ecosystem": p["ecosystem"], "name": p["name"]}, "version": p["version"]} for p in pkgs]
    r = httpx.post("https://api.osv.dev/v1/querybatch", json={"queries": queries}, timeout=20)
    r.raise_for_status()
    out = []
    for p, res in zip(pkgs, r.json().get("results", [])):
        for v in (res.get("vulns") or [])[:5]:
            d = httpx.get(f"https://api.osv.dev/v1/vulns/{v['id']}", timeout=15).json()
            aliases = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
            fixed = next((e["fixed"] for a in d.get("affected", []) for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e), None)
            out.append({"type": "package", "id": aliases[0] if aliases else v["id"], "severity": _osv_severity(d), "package": p["name"],
                        "version": p["version"], "fixed_in": fixed, "summary": (d.get("summary") or d.get("details", ""))[:200], "source": "osv.dev"})
    return out


def config_checks(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    f = []
    def add(cid: str, sev: str, summary: str, fix: str) -> None:
        f.append({"type": "config", "id": cid, "severity": sev, "summary": summary, "remediation": fix, "source": "config-baseline"})
    if cfg.get("mfa_enabled") is False:
        add("CFG-001", "high", "MFA is disabled for administrative access.", "Enforce MFA (Entra ID Conditional Access / app MFA).")
    tls = str(cfg.get("tls_min_version", "1.2"))
    if vtuple(tls) < (1, 2):
        add("CFG-002", "high", f"Minimum TLS version is {tls}.", "Set minimum TLS to 1.2 or higher.")
    ports = set(cfg.get("open_ports", []))
    public = bool(cfg.get("internet_exposed"))
    if 23 in ports:
        add("CFG-003", "critical", "Telnet (23) is open.", "Disable telnet; use SSH with keys.")
    if public and ports & {22, 3389}:
        add("CFG-004", "high", f"Remote admin ports {sorted(ports & {22, 3389})} exposed to the internet.", "Restrict with NSG/JIT access or Azure Bastion.")
    if public and ports & {3306, 5432, 1433, 27017, 6379}:
        add("CFG-005", "critical", "Database port exposed to the internet.", "Use private endpoints / firewall rules.")
    if cfg.get("encryption_at_rest") is False:
        add("CFG-006", "medium", "Encryption at rest is disabled.", "Enable storage/disk encryption.")
    if int(cfg.get("days_since_patch", 0)) > 90:
        add("CFG-007", "medium", f"Not patched for {cfg['days_since_patch']} days.", "Apply OS and package updates monthly.")
    if cfg.get("default_credentials") is True:
        add("CFG-008", "critical", "Default credentials are in use.", "Rotate credentials and store them in a vault.")
    if cfg.get("logging_enabled") is False:
        add("CFG-009", "medium", "Security logging is disabled.", "Forward logs to CyberSentinel / Log Analytics.")
    return f


def scan(asset: dict[str, Any], feed: str = "local") -> dict[str, Any]:
    pkgs = asset.get("packages", [])
    source = "local-feed"
    findings: list[dict[str, Any]]
    if feed == "osv" and pkgs:
        try:
            findings, source = _osv(pkgs), "osv.dev"
        except Exception:
            log.warning("OSV lookup failed; using local feed")
            findings = _local(pkgs)
    else:
        findings = _local(pkgs)
    findings += config_checks(asset.get("config", {}))
    raw = sum(SEV_W.get(f["severity"], 5) for f in findings)
    score = min(100, round(raw * CRIT_MULT.get(asset.get("criticality", "medium"), 1.0)))
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEV_W}
    return {"findings": findings, "risk_score": score, "counts": counts, "package_source": source,
            "rating": "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 15 else "low"}
