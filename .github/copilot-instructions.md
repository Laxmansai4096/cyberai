# Copilot instructions – CyberSentinel AI

- Python 3.12, FastAPI, Pydantic v2; deployed as Azure Functions Flex Consumption (`function_app.py` wraps `app.main:app`).
- Layers: `app/routers` (HTTP only) → `app/domain` (logic) → `app/core` (store, bus, security). Routers never call Azure SDKs directly.
- Storage: `get_store()` with `upsert/get/query/delete(kind, ...)`. Cosmos container `items`, partition key `/type`. Tests use `MemoryStore`.
- Free tiers only: no LLMs, Sentinel, ACR, Service Bus or Key Vault. Use managed identity (`DefaultAzureCredential`); never write keys into code.
- New detection rule: add a `Rule` to `RULES`, a detector function in `detection.py` that is wired into `run_all`, plus `WHY`/`PLAYBOOK` entries in `explain.py`, and a test in `tests/test_engine.py`.
- Response actions must stay human-approved (two-person rule), default to dry-run, be audited and be reversible.
- UI is vanilla JS under a strict CSP: no inline scripts or handlers, and always `esc()` data.
- Run `pytest -q` after every change.
