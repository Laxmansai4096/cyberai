"""Unit tests for normalisation, detection rules, anomaly detection, explainer and vulnerability scanning."""
from app.core.store import MemoryStore
from app.domain import detection, pipeline, vulns
from app.domain.normalize import normalize, parse_file
from app.domain.seed import scenario


def _rules(events):
    s = MemoryStore()
    pipeline.ingest(events, s)
    return {a["rule_id"] for a in s.query("alert")}, s


def test_normalize_sources():
    assert normalize({"source": "linux_auth", "message": "sshd[1]: Failed password for invalid user bob from 203.0.113.9 port 4444 ssh2"})["event_type"] == "auth.login_failure"
    assert normalize({"source": "windows", "EventID": 4625, "TargetUserName": "x", "IpAddress": "1.2.3.4"})["outcome"] == "failure"
    assert normalize({"source": "firewall", "src_ip": "1.1.1.1", "dst_port": 22, "action": "deny"})["dst_port"] == 22
    assert normalize({"source": "linux_auth", "message": "random noise"}) is None
    assert len(parse_file('{"source":"generic","event_type":"x"}\nsshd: Accepted password for a from 1.2.3.4 port 1 ssh2')) == 2


def test_bruteforce_success_after_fail_and_threat_intel():
    rules, s = _rules(scenario("brute_force"))
    assert {"CS-R001", "CS-R003", "CS-R007"} <= rules
    inc = s.query("incident")
    assert any(i["severity"] == "critical" for i in inc)


def test_password_spray():
    assert "CS-R002" in _rules(scenario("password_spray"))[0]


def test_mass_access_and_export():
    assert {"CS-R004", "CS-R009"} <= _rules(scenario("mass_record_access"))[0]


def test_port_scan_and_ti():
    assert {"CS-R006", "CS-R007"} <= _rules(scenario("port_scan"))[0]


def test_privilege_probe():
    assert "CS-R005" in _rules(scenario("privilege_probe"))[0]


def test_ssh_and_windows():
    assert "CS-R001" in _rules(scenario("ssh_linux"))[0]
    assert "CS-R010" in _rules(scenario("windows_persistence"))[0]


def test_anomaly_volume_and_new_ip():
    assert {"CS-A001", "CS-A002"} <= _rules(scenario("baseline_then_spike"))[0]


def test_no_false_positive_on_normal_activity():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = [{"source": "mediflow", "timestamp": now, "event_type": "auth.login_failure", "user": "a", "ip": "10.0.0.1", "outcome": "failure"},
          {"source": "mediflow", "timestamp": now, "event_type": "auth.login_success", "user": "a", "ip": "10.0.0.1"}]
    assert _rules(ev)[0] == set()


def test_alert_dedup_on_reingest():
    s = MemoryStore()
    pipeline.ingest(scenario("brute_force"), s)
    n = len(s.query("alert"))
    pipeline.ingest(scenario("brute_force"), s)
    assert len(s.query("alert")) == n


def test_explanation_contents():
    _, s = _rules(scenario("brute_force"))
    inc = max(s.query("incident"), key=lambda i: len(i["alert_ids"]))
    ex = inc["explanation"]
    assert "no LLM" in ex["generator"] and ex["mitre"] and ex["recommended_actions"] and 0 < ex["confidence"] <= 0.97
    assert any(a["kind"] == "block_ip" for a in ex["recommended_actions"])


def test_vuln_scan_local_feed_and_config():
    from app.domain.seed import ASSETS
    legacy = vulns.scan(ASSETS[1])
    ids = {f["id"] for f in legacy["findings"]}
    assert {"CVE-2021-44228", "CVE-2024-6387", "CFG-001", "CFG-003", "CFG-005", "CFG-008"} <= ids
    assert legacy["rating"] == "critical" and legacy["risk_score"] == 100
    ok = vulns.scan({"packages": [{"ecosystem": "PyPI", "name": "jinja2", "version": "3.1.4"}], "config": {}, "criticality": "low"})
    assert ok["findings"] == [] and ok["rating"] == "low"


def test_version_compare():
    assert vulns.vtuple("2.14.1") < vulns.vtuple("2.15.0") and vulns.vtuple("10.0") > vulns.vtuple("9.8")


def test_sliding_window():
    logs = [{"timestamp": f"2026-01-01T00:{m:02d}:00Z"} for m in (0, 1, 2, 30, 31)]
    assert len(detection._window(logs, 5, lambda w: len(w) >= 3)) == 3
    assert detection._window(logs, 5, lambda w: len(w) >= 4) is None
