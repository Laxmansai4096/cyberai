"""API tests: auth, RBAC, ingestion, triage, two-person response workflow, MediFlow commands, assets."""
from app.core import bus


def test_health_and_ui(client):
    assert client.get("/api/health").json()["app"] == "cybersentinel"
    assert "CyberSentinel" in client.get("/").text


def test_login_and_rbac(client, login):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "bad"}).status_code == 401
    viewer = login("viewer.neha")
    assert client.get("/api/dashboard", headers=viewer).status_code == 200
    assert client.post("/api/logs", headers=viewer, json={"events": [{"event_type": "x"}]}).status_code == 403
    assert client.post("/api/demo/simulate", headers=login("analyst.ravi"), json={"scenario": "all"}).status_code == 403
    assert client.get("/api/alerts").status_code == 401


def test_external_ingest_key(client):
    ev = {"events": [{"source": "mediflow", "event_type": "auth.login_success", "user": "u", "ip": "10.0.0.1"}]}
    assert client.post("/api/ingest", json=ev).status_code == 401
    r = client.post("/api/ingest", json=ev, headers={"X-Ingest-Key": "test-ingest-key"})
    assert r.status_code == 200 and r.json()["ingested"] == 1


def test_simulate_all_creates_incidents_and_dashboard(client, login):
    h = login("lead.sara")
    r = client.post("/api/demo/simulate", headers=h, json={"scenario": "all"}).json()
    assert r["alerts_created"] >= 10 and len(r["incidents"]) >= 6
    d = client.get("/api/dashboard", headers=h).json()
    assert d["open_alerts"] >= 10 and d["alerts_by_severity"]["critical"] >= 1 and len(d["timeline"]) == 24


def _brute_incident(client, h):
    client.post("/api/demo/simulate", headers=h, json={"scenario": "brute_force"})
    inc = next(i for i in client.get("/api/incidents", headers=h).json() if i["entity"] == "203.0.113.66")
    return client.get(f"/api/incidents/{inc['id']}", headers=h).json()


def test_two_person_rule_and_live_mediflow_command(client, login):
    lead1, lead2, analyst = login("lead.sara"), login("lead.omar"), login("analyst.ravi")
    inc = _brute_incident(client, lead1)
    a = client.post(f"/api/incidents/{inc['id']}/actions", headers=analyst,
                    json={"kind": "block_ip", "target": "203.0.113.66", "target_system": "mediflow", "dry_run": False, "reason": "brute force"}).json()
    assert a["status"] == "proposed"
    assert client.post(f"/api/actions/{a['id']}/execute", headers=lead1).status_code == 409   # not approved yet
    assert client.post(f"/api/actions/{a['id']}/approve", headers=analyst).status_code == 403  # analyst can't approve
    assert client.post(f"/api/actions/{a['id']}/approve", headers=lead1).json()["status"] == "approved"
    ex = client.post(f"/api/actions/{a['id']}/execute", headers=lead2).json()
    assert ex["status"] == "executed" and ex["result"]["mode"] == "live"
    q = bus.get_bus().messages["mediflow-commands"]
    assert q[-1]["command"] == "block_ip" and q[-1]["target"] == "203.0.113.66"
    assert any(b["ip"] == "203.0.113.66" for b in client.get("/api/blocklist", headers=lead1).json())
    assert client.get(f"/api/incidents/{inc['id']}", headers=lead1).json()["status"] == "contained"
    rv = client.post(f"/api/actions/{a['id']}/revert", headers=lead1).json()
    assert rv["status"] == "reverted" and q[-1]["command"] == "unblock_ip"


def test_requester_cannot_self_approve(client, login):
    lead = login("lead.sara")
    inc = _brute_incident(client, lead)
    a = client.post(f"/api/incidents/{inc['id']}/actions", headers=lead, json={"kind": "disable_user", "target": "dr.rao"}).json()
    assert client.post(f"/api/actions/{a['id']}/approve", headers=lead).status_code == 403


def test_dry_run_changes_nothing(client, login):
    lead1, lead2 = login("lead.sara"), login("lead.omar")
    inc = _brute_incident(client, lead1)
    a = client.post(f"/api/incidents/{inc['id']}/actions", headers=lead1, json={"kind": "block_ip", "target": "203.0.113.66"}).json()
    client.post(f"/api/actions/{a['id']}/approve", headers=lead2)
    ex = client.post(f"/api/actions/{a['id']}/execute", headers=lead2).json()
    assert ex["result"]["mode"] == "dry-run" and client.get("/api/blocklist", headers=lead1).json() == []


def test_close_incident_resolves_alerts(client, login):
    h = login("analyst.ravi")
    inc = _brute_incident(client, login("lead.sara"))
    client.patch(f"/api/incidents/{inc['id']}", headers=h, json={"status": "closed", "note": "blocked at firewall"})
    full = client.get(f"/api/incidents/{inc['id']}", headers=h).json()
    assert full["status"] == "closed" and all(a["status"] == "resolved" for a in full["alerts"]) and full["notes"]


def test_upload_syslog_file(client, login):
    h = login("analyst.ravi")
    lines = "\n".join(f"sshd[9]: Failed password for root from 203.0.113.50 port {i} ssh2" for i in range(6))
    r = client.post("/api/logs/upload", headers=h, files={"file": ("auth.log", lines, "text/plain")}, data={"source": "linux_auth"})
    assert r.json()["ingested"] == 6 and r.json()["alerts_created"] >= 1


def test_asset_scan(client, login):
    h = login("analyst.ravi")
    a = client.post("/api/assets/as_legacy/scan", headers=h).json()
    assert a["last_scan"]["rating"] == "critical"
    new = client.post("/api/assets", headers=h, json={"name": "web-01", "packages": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}]}).json()
    assert any(f["id"] == "CVE-2021-23337" for f in client.post(f"/api/assets/{new['id']}/scan", headers=h).json()["last_scan"]["findings"])


def test_custom_ioc_triggers_rule(client, login):
    lead = login("lead.sara")
    client.post("/api/iocs", headers=lead, json={"value": "10.66.66.66", "description": "internal red team"})
    r = client.post("/api/logs", headers=lead, json={"events": [{"source": "generic", "event_type": "api.request", "user": "x", "ip": "10.66.66.66"}]}).json()
    assert r["alerts_created"] == 1


def test_audit_log_records_actions(client, login):
    lead = login("lead.sara")
    client.post("/api/demo/simulate", headers=lead, json={"scenario": "port_scan"})
    assert any(a["action"] == "demo.simulate" for a in client.get("/api/admin/audit", headers=lead).json())
