"""Authentication (PBKDF2 + JWT), role checks and audit log for CyberSentinel."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from .config import get_settings
from .store import get_store, new_id, now_iso

_bearer = HTTPBearer(auto_error=False)
ITERATIONS = 120_000
ROLES = ("Admin", "SecurityLead", "Analyst", "Viewer")


class User(BaseModel):
    id: str
    username: str
    display_name: str
    roles: list[str]


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, it, salt, dk = stored.split("$")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(it)),
                                   base64.b64decode(dk))
    except ValueError:
        return False


def create_token(user: dict[str, Any]) -> str:
    return jwt.encode({"sub": user["id"], "usr": user["username"], "roles": user["roles"],
                       "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, get_settings().jwt_secret, algorithm="HS256")


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")
    return ip.split(":")[0] if ip.count(":") == 1 else ip


def audit(user: User, action: str, resource_type: str, resource_id: str | None, request: Request | None, **extra: Any) -> None:
    get_store().upsert("audit", {"id": new_id("aud_"), "ts": now_iso(), "actor": user.username, "roles": user.roles,
                                 "action": action, "resource_type": resource_type, "resource_id": resource_id,
                                 "ip": client_ip(request) if request else None, **extra})


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> User:
    if cred is None:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(cred.credentials, get_settings().jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    doc = get_store().get("user", payload["sub"])
    if not doc or doc.get("disabled"):
        raise HTTPException(401, "Account disabled")
    return User(**{k: doc[k] for k in User.model_fields})


def require_roles(*roles: str) -> Callable[..., User]:
    def dep(user: User = Depends(current_user)) -> User:
        if not set(roles) & set(user.roles):
            raise HTTPException(403, "Forbidden for your role")
        return user
    return dep


ANY = require_roles(*ROLES)
WRITE = require_roles("Admin", "SecurityLead", "Analyst")
LEAD = require_roles("Admin", "SecurityLead")
