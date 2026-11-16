"""CyberSentinel AI - FastAPI application (Azure Functions Flex Consumption, or uvicorn locally)."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .core.config import get_settings
from .core.store import get_store
from .domain.seed import seed
from .routers import admin, auth, soc

STATIC = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="CyberSentinel AI", version="1.0.0",
                  description="Security log analytics, detection, vulnerability assessment and controlled response. Free-tier Azure only.")
    state = {"seeded": False}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if not state["seeded"]:
            seed(get_store())
            state["seeded"] = True
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    for r in (auth, soc, admin):
        app.include_router(r.router)

    @app.get("/api/health", tags=["meta"])
    def health() -> dict:
        s = get_settings()
        return {"status": "ok", "app": "cybersentinel", "env": s.environment, "store": s.store_provider, "bus": s.bus_provider,
                "vuln_feed": s.vuln_feed, "ingest_endpoint": bool(s.ingest_api_key)}

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    return app


app = create_app()
