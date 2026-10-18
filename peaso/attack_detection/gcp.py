"""Normalize proven service-account key creation from Google Cloud Audit Logs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def normalize_gcp_audit(record: Mapping[str, Any]) -> dict[str, Any] | None:
    payload = record.get("protoPayload")
    if not isinstance(payload, Mapping) or payload.get("@type") != "type.googleapis.com/google.cloud.audit.AuditLog":
        return None
    if payload.get("serviceName") != "iam.googleapis.com":
        return None
    log_name = record.get("logName")
    if not isinstance(log_name, str) or not log_name.endswith("/logs/cloudaudit.googleapis.com%2Factivity"):
        return None
    auth = payload.get("authenticationInfo")
    auth = auth if isinstance(auth, Mapping) else {}
    request = payload.get("request")
    request = request if isinstance(request, Mapping) else {}
    response = payload.get("response")
    response = response if isinstance(response, Mapping) else {}
    status = payload.get("status")
    status = status if isinstance(status, Mapping) else {}
    code = status.get("code")
    target = request.get("name")
    key_name = response.get("name")
    key_returned = isinstance(key_name, str) and "/serviceAccounts/" in key_name and "/keys/" in key_name and bool(key_name.rsplit("/keys/", 1)[-1])
    explicit_success = code == 0 and not isinstance(code, bool)
    if code not in (None, 0) or not (explicit_success or key_returned):
        return None
    if not isinstance(target, str) or not target.startswith("projects/") or "/serviceAccounts/" not in target or not target.rsplit("/serviceAccounts/", 1)[-1]:
        return None
    return {
        "cloud.provider": "gcp",
        "event.name": payload.get("methodName"),
        "event.source": payload.get("serviceName"),
        "event.outcome": "success",
        "event.id": record.get("insertId"),
        "event.time": record.get("timestamp"),
        "account.id": log_name.split("/logs/", 1)[0],
        "actor.id": auth.get("principalEmail"),
        "target.id": target,
        "credential.key_name": key_name if key_returned else None,
        "credential.effect_confirmed": True,
    }
