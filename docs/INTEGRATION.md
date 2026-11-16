# Connecting MediFlow AI (or any app) to CyberSentinel

There are two ways in, and you can use both.

## A. HTTP push (simplest)

```http
POST https://fn-cyberai-7qhue.azurewebsites.net/api/ingest
X-Ingest-Key: <INGEST_API_KEY app setting of fn-cyberai-7qhue>
Content-Type: application/json

{"events": [
  {"source": "mediflow", "timestamp": "2026-11-16T10:00:05Z", "event_type": "auth.login_failure",
   "user": "dr.rao", "ip": "203.0.113.66", "outcome": "failure", "roles": [], "resource": null, "details": {}}
]}
```

To read the key, run `az functionapp config appsettings list -g rg-cyberai -n fn-cyberai-7qhue --query "[?name=='INGEST_API_KEY'].value" -o tsv`.
In MediFlow, store it as an app setting, never in code.

## B. Storage Queue (decoupled, retries for free)

Send plain-text JSON (not base64) to the queue `security-events` on `https://stexplore12.queue.core.windows.net`.
Grant MediFlow's managed identity **Storage Queue Data Message Sender** on the storage account.

```python
from azure.identity import DefaultAzureCredential
from azure.storage.queue import QueueClient
q = QueueClient("https://stexplore12.queue.core.windows.net", "security-events", credential=DefaultAzureCredential())
q.send_message(json.dumps(event))
```

## Event types CyberSentinel understands

| event_type | Used by |
|---|---|
| `auth.login_failure`, `auth.login_success`, `auth.account_locked` | Brute force, spraying, success after failure, new-IP anomaly |
| `authz.denied` (`resource` = "METHOD /path") | Privilege probing |
| `phi.read` (`resource` = "patient/<id>") | Mass record access |
| `phi.export`, `data.export` | Bulk export |
| `admin.*` (with `roles` containing Admin) | Off-hours privileged activity |
| anything else | Volume anomaly, threat-intel IP match |

## Response commands back to MediFlow (optional)

When a SecurityLead executes a **live** action with target system `mediflow`, CyberSentinel sends this message to the queue `mediflow-commands`:

```json
{"command": "block_ip|unblock_ip|disable_user|enable_user", "target": "203.0.113.66", "action_id": "act_...",
 "reason": "...", "requested_by": "lead.sara", "at": "2026-11-16T10:05:00Z"}
```

MediFlow should consume it with a queue trigger (connection setting `SecurityQueue__queueServiceUri`, role **Storage Queue Data Message Processor**). It should apply the command and never auto-disable Admin accounts.
