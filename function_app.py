"""Azure Functions entry point (Python v2 model, Flex Consumption).

* HTTP  : FastAPI app (UI + REST API) via AsgiFunctionApp
* Queue : `security-events` - events pushed by MediFlow or any other app (identity-based connection `SecurityQueue`)
"""
import json
import logging

import azure.functions as func

from app.domain import pipeline
from app.main import app as fastapi_app

app = func.AsgiFunctionApp(app=fastapi_app, http_auth_level=func.AuthLevel.ANONYMOUS)


@app.queue_trigger(arg_name="msg", queue_name="security-events", connection="SecurityQueue")
def security_events(msg: func.QueueMessage) -> None:
    body = json.loads(msg.get_body().decode("utf-8"))
    events = body if isinstance(body, list) else [body]
    result = pipeline.ingest(events)
    logging.info("queue ingest: %s logs, %s new alerts", result["ingested"], result["alerts_created"])
