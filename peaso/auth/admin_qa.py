"""Validate an operator-issued, short-lived tenant QA entitlement.

No request, JWT, API key, Stripe cache, or Cognito custom:plan field can issue
this authority. The storage row is only a candidate after live Cognito identity
verification has already succeeded.
"""
from __future__ import annotations

import math
import re
import time

AUTHORITY = "administrator_comped_qa"
MAX_LIFETIME_SECONDS = 24 * 60 * 60
ISSUE_FIELDS = frozenset({"tenant", "cognito_pool_id", "cognito_subject", "cognito_client_id",
                          "verified_email", "authority", "actor", "reason", "audit_id",
                          "issued_at", "hard_expires_at"})
_ACTOR = re.compile(r"arn:aws:(?:iam::[0-9]{12}:(?:role|user)|sts::[0-9]{12}:assumed-role)/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
_AUDIT_ID = re.compile(r"[a-f0-9]{32}\Z")


def valid_actor(value):
    return isinstance(value, str) and _ACTOR.fullmatch(value) is not None


def active_grant(value, *, tenant, pool_id, client_id, attributes, now=None):
    """Fail closed unless the complete row matches a live verified Cognito user."""
    if not isinstance(value, dict) or not isinstance(attributes, dict):
        return False
    if not ISSUE_FIELDS <= value.keys():
        return False
    if (value["tenant"] != tenant or value["cognito_subject"] != tenant or
            attributes.get("sub") != tenant or value["cognito_pool_id"] != pool_id or
            value["cognito_client_id"] != client_id or value["authority"] != AUTHORITY or
            attributes.get("email_verified") != "true" or
            value["verified_email"] != attributes.get("email")):
        return False
    if not isinstance(value["verified_email"], str) or "@" not in value["verified_email"]:
        return False
    if (not valid_actor(value["actor"]) or
            not isinstance(value["reason"], str) or not (8 <= len(value["reason"].strip()) <= 500) or
            not isinstance(value["audit_id"], str) or not _AUDIT_ID.fullmatch(value["audit_id"])):
        return False
    issued, expiry = value["issued_at"], value["hard_expires_at"]
    if (type(issued) not in (int, float) or type(expiry) not in (int, float) or
            not math.isfinite(issued) or not math.isfinite(expiry)):
        return False
    current = time.time() if now is None else now
    if not (issued <= current < expiry and 0 < expiry - issued <= MAX_LIFETIME_SECONDS):
        return False
    if value.get("revoked_at") is not None:
        return False
    return True


def valid_issue(value, *, tenant, now=None):
    """Storage-side shape/lifetime guard; operator must verify Cognito separately."""
    if not isinstance(value, dict) or set(value) != ISSUE_FIELDS or value.get("tenant") != tenant:
        return False
    if (not isinstance(tenant, str) or not tenant or len(tenant) > 128 or
            any(not isinstance(value.get(field), str) or not value[field].strip() or len(value[field]) > 256
                for field in ("cognito_pool_id", "cognito_client_id", "cognito_subject"))):
        return False
    return active_grant(
        value, tenant=tenant, pool_id=value.get("cognito_pool_id"),
        client_id=value.get("cognito_client_id"),
        attributes={"sub": tenant, "email": value.get("verified_email"),
                    "email_verified": "true"}, now=now)
