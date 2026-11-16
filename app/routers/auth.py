from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.security import User, client_ip, create_token, current_user, verify_password
from ..core.store import get_store, new_id, now_iso

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


def _self_log(event_type: str, user: str, ip: str, outcome: str) -> None:
    """CyberSentinel monitors its own sign-ins too (stored as normal logs, picked up by the next detection run)."""
    get_store().upsert("log", {"id": new_id("log_"), "timestamp": now_iso(), "ingested_at": now_iso(), "source": "cybersentinel",
                               "event_type": event_type, "user": user, "ip": ip, "outcome": outcome, "host": "cybersentinel",
                               "roles": [], "resource": None, "dst_port": None, "details": {}, "ttl": 2592000})


@router.post("/login")
def login(body: LoginIn, request: Request) -> dict:
    s = get_store()
    ip = client_ip(request)
    found = s.query("user", {"username": body.username.lower()})
    user = found[0] if found else None
    if user and user.get("locked_until") and user["locked_until"] > now_iso():
        raise HTTPException(423, "Account temporarily locked. Try again later.")
    if not user or user.get("disabled") or not verify_password(body.password, user["password_hash"]):
        if user:
            user["failed_logins"] = user.get("failed_logins", 0) + 1
            if user["failed_logins"] >= 5:
                user["locked_until"] = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
                user["failed_logins"] = 0
            s.upsert("user", user)
        _self_log("auth.login_failure", body.username, ip, "failure")
        raise HTTPException(401, "Invalid username or password")
    user.update(failed_logins=0, locked_until=None, last_login=now_iso())
    s.upsert("user", user)
    _self_log("auth.login_success", user["username"], ip, "success")
    return {"access_token": create_token(user), "token_type": "bearer",
            "user": {k: user[k] for k in ("id", "username", "display_name", "roles")}}


@router.get("/me")
def me(user: User = Depends(current_user)) -> User:
    return user
