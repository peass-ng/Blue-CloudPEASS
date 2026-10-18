"""Opaque, high-entropy read-only API keys and safe public metadata."""
from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
import time
from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, Field, field_validator


KEY_PREFIX = "hacktricks_cspm"
KEY_PATTERN = re.compile(r"(?:hacktricks_cspm|peaso)_([a-f0-9]{32})_([A-Za-z0-9_-]{43})\Z")
KEY_ID_PATTERN = re.compile(r"[a-f0-9]{32}\Z")
MAX_UNREVOKED_KEYS = 20
MAX_LIST_PAGE = 50


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    expires_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Invalid API key name")
        return value

    @field_validator("expires_at")
    @classmethod
    def aware_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("Timezone required")
        return value


def mint_key() -> tuple[str, str, str]:
    """Return (id, plaintext, SHA-256 hex digest); callers persist only digest."""
    key_id = secrets.token_hex(16)
    token = f"{KEY_PREFIX}_{key_id}_{secrets.token_urlsafe(32)}"
    return key_id, token, hashlib.sha256(token.encode("ascii")).hexdigest()


def parse_key(token: str) -> str | None:
    if not isinstance(token, str) or len(token) not in (82, len(KEY_PREFIX) + 1 + 32 + 1 + 43):
        return None
    match = KEY_PATTERN.fullmatch(token)
    return match.group(1) if match else None


def valid_key_id(key_id: str) -> bool:
    return bool(isinstance(key_id, str) and KEY_ID_PATTERN.fullmatch(key_id))


def matches(token: str, digest: str) -> bool:
    """Compare fixed-length digests without exposing the stored hash."""
    candidate = hashlib.sha256(token.encode("ascii")).hexdigest()
    return isinstance(digest, str) and len(digest) == 64 and hmac.compare_digest(candidate, digest)


def active(row: dict, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    if row.get("revoked_at") is not None:
        return False
    expiry = row.get("expires_at")
    if expiry is None:
        return True
    try:
        timestamp = float(expiry)
    except (TypeError, ValueError, OverflowError):
        return False
    return math.isfinite(timestamp) and timestamp > now


def public(row: dict) -> dict:
    """Allowlist fields; never serialize hash, username, or lookup metadata."""
    def timestamp(value):
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat() if value is not None else None

    return {"id": row["id"], "name": row["name"], "prefix": row["prefix"],
            "created_at": timestamp(row["created_at"]),
            "expires_at": timestamp(row.get("expires_at")),
            "revoked_at": timestamp(row.get("revoked_at")),
            "last_used_at": timestamp(row.get("last_used_at"))}
