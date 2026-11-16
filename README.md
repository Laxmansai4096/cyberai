# CyberSentinel AI

Security operations platform on Azure: security-log ingestion, rule-based and statistical anomaly detection, vulnerability assessment, plain-English incident explanations, alerting, and human-approved incident response. It also monitors the **MediFlow AI** hospital app through a queue or HTTP integration.

It runs **entirely on free tiers**. There are no paid LLMs, Sentinel, Container Registry or Service Bus.

| | |
|---|---|
| **Live demo** | `https://fn-cyberai-7qhue.azurewebsites.net` (UI) · `/docs` (OpenAPI) |
| **Stack** | Python 3.12 · FastAPI · Azure Functions (Flex Consumption) · Cosmos DB (free tier) · Azure Storage Queues · App Insights · vanilla JS SPA |
| **Auth** | JWT (PBKDF2-hashed passwords, lockout after 5 failures) · roles: Admin, SecurityLead, Analyst, Viewer |
| **Azure auth** | System-assigned managed identity + RBAC for Cosmos DB and Queues (Cosmos key auth disabled) |

## Features

| Area | What it does |
|---|---|
| **Ingestion** | JSON API, file upload (JSONL / JSON array / Linux `auth.log`), machine-to-machine `/api/ingest` with `X-Ingest-Key`, and the Storage Queue `security-events` (Functions queue trigger). |
| **Normalisation** | MediFlow security events, firewall logs, Linux sshd/sudo syslog, Windows Security events (4624, 4625, 4720, 4732, 4740, 1102) and generic JSON are all mapped to one schema. Logs expire after 30 days (Cosmos TTL). |
| **Detection (10 rules)** | Brute force, password spraying, success after failures, mass sensitive-record access, privilege probing, port scan, threat-intel IP, off-hours privileged activity, bulk export, and privileged-group change or log clearing. Every rule is mapped to MITRE ATT&CK. |
| **Anomaly detection** | Per-user hourly z-score against the user's own baseline, and first-seen-IP login detection. |
| **Alerting** | Alerts are de-duplicated per rule and entity, then correlated into incidents by entity (a compromised user is linked to the attacker IP's incident). Triage statuses: ack, false positive, resolved. |
| **AI explanations** | A deterministic natural-language explainer (no LLM, no cost, reproducible). It writes a summary, why it matters, risk factors, MITRE context, a timeline, recommended containment, and a confidence score. |
| **Vulnerability assessment** | Package CVE matching through the **free OSV.dev API**, with a built-in offline feed as fallback. Configuration baseline checks (MFA, TLS, exposed admin and database ports, telnet, encryption, patch age, default credentials, logging) and a 0–100 risk score weighted by asset criticality. |
| **Controlled response** | Actions (block IP, disable user, force password reset, isolate host) go propose → approve → execute → revert. Approval follows a two-person rule: the requester cannot approve their own action. Actions default to **dry-run**. Live mode writes to CyberSentinel's blocklist or sends a command to MediFlow over the `mediflow-commands` queue. Everything is audited. |
| **Threat intel** | Built-in demo indicators (documentation IP ranges only), plus custom IoCs that SecurityLeads can add. |
| **Dashboard** | 24-hour activity chart, open alerts by severity, top detections, top attacking IPs, and asset risk. |
| **Simulator** | Eight synthetic attack scenarios that run through the real pipeline, for demos. |

## Quick start (local, no Azure needed)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
pytest -q                                   # 26 tests
uvicorn app.main:app --reload --port 8002   # http://localhost:8002  (password Demo@12345)
```

Sign in as `lead.sara`, open **Dashboard → Attack simulator → all**, then open an incident. Propose an action as `analyst.ravi` and approve or execute it as `lead.sara` or `lead.omar`.

## Deploy to Azure

```powershell
az login
./scripts/deploy.ps1                 # infra + code (idempotent), prints the demo password once
./scripts/deploy.ps1 -CodeOnly       # redeploy code only
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the details and cost table, [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, and [docs/INTEGRATION.md](docs/INTEGRATION.md) to connect MediFlow.

## Repository layout

```
app/
  core/      config, Cosmos/in-memory store, Storage Queue bus, auth + RBAC + audit
  domain/    normalize, detection (rules + anomaly), pipeline (alert/correlate), explain, vulns, response, seed/simulator
  routers/   auth, soc (logs/alerts/incidents/actions/dashboard), admin (assets/iocs/users/audit/simulate)
  static/    SOC console (index.html, app.js, styles.css)
function_app.py   Azure Functions entry: HTTP (ASGI) + queue trigger `security-events`
host.json         routePrefix "" so FastAPI owns all routes; raw (non-base64) queue messages
scripts/deploy.ps1
sample-data/      mixed_security_logs.jsonl, auth.log
tests/            26 pytest tests (engine + API + RBAC + response workflow)
```

All data is synthetic. Threat-intel and attack IPs use the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
