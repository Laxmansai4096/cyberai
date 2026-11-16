"""Incident explainer: deterministic natural-language generation (no LLM, zero cost, fully reproducible).

Produces a plain-English summary, timeline, MITRE ATT&CK context, risk factors, recommended response steps and a confidence score.
"""
from __future__ import annotations

from typing import Any

from .detection import RULES, THREAT_INTEL, ts

MITRE: dict[str, tuple[str, str]] = {
    "T1110": ("Brute Force", "Credential Access"), "T1110.003": ("Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence"), "T1078.004": ("Valid Accounts: Cloud Accounts", "Privilege Escalation"),
    "T1213": ("Data from Information Repositories", "Collection"), "T1530": ("Data from Cloud Storage", "Collection"),
    "T1069": ("Permission Groups Discovery", "Discovery"), "T1046": ("Network Service Discovery", "Discovery"),
    "T1071": ("Application Layer Protocol", "Command and Control"), "T1020": ("Automated Exfiltration", "Exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "Exfiltration"), "T1098": ("Account Manipulation", "Persistence"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion"),
}

WHY: dict[str, str] = {
    "CS-R001": "Attackers guess passwords at speed; if any account uses a weak password it will eventually be taken over.",
    "CS-R002": "Spraying tries a few common passwords against many accounts to stay under lockout limits.",
    "CS-R003": "A success right after many failures often means the guessing worked and the attacker is now inside with a real account.",
    "CS-R004": "Reading many unrelated records quickly is typical of data harvesting by an insider or a stolen account.",
    "CS-R005": "Repeatedly hitting forbidden functions suggests someone exploring what the account can reach.",
    "CS-R006": "Scanning many ports maps exposed services before an attack.",
    "CS-R007": "The address is already associated with malicious infrastructure.",
    "CS-R008": "Privileged actions at unusual hours are a common sign of misuse of admin credentials.",
    "CS-R009": "Several exports in a short time can indicate data being taken out of the system.",
    "CS-R010": "Adding accounts to admin groups or clearing logs is how attackers keep access and hide their tracks.",
    "CS-A001": "The account is far busier than its own normal pattern, which can mean automation or account misuse.",
    "CS-A002": "The account signed in from an address it has never used before.",
}

PLAYBOOK: dict[str, list[dict[str, str]]] = {
    "CS-R001": [{"kind": "block_ip", "why": "Stop further guessing from this source."}],
    "CS-R002": [{"kind": "block_ip", "why": "Stop the spray source."}],
    "CS-R003": [{"kind": "disable_user", "why": "Contain a likely compromised account."}, {"kind": "force_password_reset", "why": "Invalidate the guessed password."}, {"kind": "block_ip", "why": "Cut off the attacker's source."}],
    "CS-R004": [{"kind": "disable_user", "why": "Stop further data access while you verify with the user's manager."}],
    "CS-R005": [{"kind": "force_password_reset", "why": "In case the account is being misused."}],
    "CS-R006": [{"kind": "block_ip", "why": "Block the scanner at the edge."}],
    "CS-R007": [{"kind": "block_ip", "why": "Known-bad infrastructure."}],
    "CS-R008": [{"kind": "force_password_reset", "why": "Confirm the admin activity was legitimate first."}],
    "CS-R009": [{"kind": "disable_user", "why": "Prevent further exports pending review."}],
    "CS-R010": [{"kind": "isolate_host", "why": "Contain the host while you investigate."}],
    "CS-A001": [], "CS-A002": [],
}
SEV_ORDER = ["low", "medium", "high", "critical"]


def explain(incident: dict[str, Any], alerts: list[dict[str, Any]], iocs: dict[str, str] | None = None) -> dict[str, Any]:
    alerts = sorted(alerts, key=lambda a: a["first_seen"])
    rule_ids = list(dict.fromkeys(a["rule_id"] for a in alerts))
    entity = f"{incident['entity_type']} {incident['entity']}"
    first, last = alerts[0]["first_seen"], max(a["last_seen"] for a in alerts)
    minutes = max(1, int((ts(last) - ts(first)).total_seconds() // 60))
    events = sum(a["count"] for a in alerts)
    names = [RULES[r].name.lower() for r in rule_ids]
    summary = (f"{entity.capitalize()} triggered {len(alerts)} alert(s) - {', '.join(names)} - involving {events} events "
               f"over about {minutes} minute(s) between {first} and {last} UTC.")
    if "CS-R003" in rule_ids:
        summary += " A successful login followed the failures, so treat this account as potentially compromised."
    feed = {**THREAT_INTEL, **(iocs or {})}
    risk: list[str] = []
    ips = {a["entity"] for a in alerts if a["entity_type"] == "ip"} | {a.get("extra", {}).get("success_ip") for a in alerts} - {None}
    for ip in sorted(i for i in ips if i):
        if ip in feed:
            risk.append(f"IP {ip} is on the threat-intel list: {feed[ip]}.")
    if len(rule_ids) > 1:
        risk.append("Multiple independent detections point at the same entity (correlated activity).")
    for a in alerts:
        x = a.get("extra", {})
        if "z_score" in x:
            risk.append(f"Activity was {x['z_score']} standard deviations above this user's baseline ({x['current']} vs ~{x['baseline_mean']} per hour).")
        if "distinct_records" in x:
            risk.append(f"{x['distinct_records']} distinct records were accessed.")
        if "ports" in x:
            risk.append(f"{len(x['ports'])} distinct ports probed.")
        if "users" in x and x["users"]:
            risk.append(f"Targeted accounts: {', '.join(x['users'][:5])}.")
    techniques = sorted({t for r in rule_ids for t in RULES[r].mitre})
    steps: list[dict[str, str]] = []
    seen: set[str] = set()
    for r in rule_ids:
        for p in PLAYBOOK.get(r, []):
            if p["kind"] not in seen:
                seen.add(p["kind"])
                target = incident["entity"]
                if p["kind"] == "block_ip" and incident["entity_type"] != "ip":
                    target = next((a["extra"].get("success_ip") for a in alerts if a.get("extra", {}).get("success_ip")), "")
                if p["kind"] in ("disable_user", "force_password_reset") and incident["entity_type"] == "ip":
                    users = next((a["extra"].get("users") for a in alerts if a.get("extra", {}).get("users")), [])
                    target = users[0] if users else ""
                if target:
                    steps.append({**p, "target": target})
    sev_idx = max(SEV_ORDER.index(a["severity"]) for a in alerts)
    confidence = min(0.97, 0.45 + 0.12 * len(rule_ids) + 0.08 * sev_idx + (0.1 if risk else 0))
    return {
        "generator": "deterministic-nlg-v1 (no LLM)",
        "summary": summary,
        "why_it_matters": [WHY[r] for r in rule_ids],
        "timeline": [{"at": a["first_seen"], "text": f"{RULES[a['rule_id']].name}: {a['count']} event(s)"} for a in alerts],
        "mitre": [{"id": t, "name": MITRE.get(t, (t, ""))[0], "tactic": MITRE.get(t, ("", ""))[1]} for t in techniques],
        "risk_factors": risk,
        "recommended_actions": steps,
        "next_steps": ["Confirm with the account owner or system owner whether the activity was expected.",
                       "Review the evidence events listed on each alert.",
                       "Propose containment actions below; a SecurityLead must approve before anything runs."],
        "confidence": round(confidence, 2),
    }
