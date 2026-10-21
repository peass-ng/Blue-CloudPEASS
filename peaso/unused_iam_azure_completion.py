"""Source-bound Azure IAM completion helpers; no absence-only inactivity claims."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"
SUCCESS_FIELD_START = datetime(2023, 12, 1, tzinfo=timezone.utc)


def _guid(value):
    if not isinstance(value, str):
        raise ValueError("missing object ID")
    result = str(UUID(value))
    if result != value.lower() or UUID(result).int == 0:
        raise ValueError("invalid object ID")
    return result


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return result.astimezone(timezone.utc)


def _result(status, summary, **details):
    return status, {"summary": summary, **details}


def _authority(receipt, *, tenant, context, endpoint, audience):
    if not isinstance(receipt, dict) or receipt.get("tenant_id") != _guid(tenant):
        raise ValueError("receipt tenant is unverified")
    if receipt.get("tenant_verified") is not True or receipt.get("credential_context_id") != context:
        raise ValueError("receipt belongs to another capture")
    if receipt.get("read_only") is not True or receipt.get("method") != "GET" or receipt.get("body") is not None:
        raise ValueError("receipt is not a read-only GET")
    if receipt.get("endpoint") != endpoint or receipt.get("audience") != audience:
        raise ValueError("receipt source differs from selected endpoint")
    if receipt.get("status") not in {"collected", "empty", "partial", "denied", "unknown"}:
        raise ValueError("receipt status is unavailable")
    if not isinstance(receipt.get("items"), list):
        raise ValueError("receipt items are malformed")


def evaluate_user_success(user, *, tenant, context, captured_at, receipt, days=90):
    """Assess a selected Graph user only from last successful sign-in."""
    try:
        if type(days) is not int or days <= 0:
            raise ValueError("invalid inactivity interval")
        uid = _guid(user["id"])
        endpoint = "/v1.0/users?$select=id,displayName,accountEnabled,signInActivity"
        _authority(receipt, tenant=tenant, context=context, endpoint=endpoint, audience=GRAPH)
        if receipt["status"] not in {"collected", "empty"}:
            return _result("DENIED" if receipt["status"] == "denied" else "UNKNOWN", "User sign-in inventory is incomplete.")
        matches = [row for row in receipt["items"] if isinstance(row, dict) and row.get("id", "").lower() == uid]
        if len(matches) != 1 or matches[0] != user:
            raise ValueError("selected user is absent or ambiguous in the current roster")
        if user.get("accountEnabled") is False:
            return _result("NOT_APPLICABLE", "User account is disabled.", user_id=uid)
        if user.get("accountEnabled") is not True:
            raise ValueError("user enabled state is unavailable")
        coverage = user.get("_coverage", {}).get("signInActivity", {})
        if coverage and coverage.get("status") not in {"collected", "empty"}:
            return _result("DENIED" if coverage.get("status") == "denied" else "UNKNOWN", "Successful sign-in field is unavailable.", user_id=uid)
        now = _instant(captured_at)
        if now - timedelta(days=days) < SUCCESS_FIELD_START:
            raise ValueError("successful sign-in field does not cover the selected interval")
        activity = user.get("signInActivity")
        if not isinstance(activity, dict) or not activity.get("lastSuccessfulSignInDateTime"):
            raise ValueError("successful sign-in is absent; Graph does not backfill this field")
        success = _instant(activity["lastSuccessfulSignInDateTime"])
        if not SUCCESS_FIELD_START <= success <= now:
            raise ValueError("successful sign-in is outside the observed interval")
        elapsed = now - success
        detail = {"user_id": uid, "last_successful_sign_in": success.isoformat(),
                  "days_since_success": elapsed.days, "threshold_days": days}
        if elapsed > timedelta(days=days):
            return _result("FAIL", f"User {user.get('displayName', uid)} last signed in successfully on {success.date()}.\nThat recorded success is older than {days} days.\nReview the account owner before changing access.", **detail)
        return _result("PASS", f"User {user.get('displayName', uid)} signed in successfully on {success.date()}.\nThat recorded success is within {days} days.\nThe user has recent observed authentication.", **detail)
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        return _result("UNKNOWN", f"User successful sign-in is unresolved: {exc}.", reason=str(exc))


def _arm_id(value):
    if not isinstance(value, str) or not value.startswith("/subscriptions/") or "?" in value or "#" in value:
        raise ValueError("invalid ARM resource ID")
    parts = value.split("/")
    if len(parts) < 7 or any(part in ("", ".", "..") for part in parts[1:]):
        raise ValueError("invalid ARM resource ID")
    _guid(parts[2])
    return value.lower()


def evaluate_managed_identity_consumers(identity, *, tenant, context, receipt):
    """Report positive ARM assignments; zero assignments cannot prove global absence."""
    try:
        principal = _guid(identity["properties"]["principalId"])
        resource_id = _arm_id(identity["id"])
        if "/providers/microsoft.managedidentity/userassignedidentities/" not in resource_id or resource_id.count("/providers/") != 1:
            raise ValueError("selected resource is not a user-assigned managed identity")
        if identity["properties"].get("tenantId") is not None and _guid(identity["properties"]["tenantId"]) != _guid(tenant):
            raise ValueError("managed identity belongs to another tenant")
        scope = "/subscriptions/" + resource_id.split("/")[2]
        _authority(receipt, tenant=tenant, context=context,
                   endpoint=scope + "/resources?api-version=2021-04-01", audience=ARM)
        if receipt.get("scope") != scope:
            raise ValueError("identity assignment source has another subscription")
        consumers = []
        for row in receipt["items"]:
            rid = _arm_id(row["id"])
            if not rid.startswith(scope + "/"):
                raise ValueError("resource belongs to another subscription")
            metadata = row.get("identity")
            if metadata is None:
                continue
            if not isinstance(metadata, dict):
                raise ValueError("resource identity field is malformed")
            assignments = metadata.get("userAssignedIdentities", {})
            if not isinstance(assignments, dict):
                raise ValueError("user-assigned identity map is malformed")
            if resource_id in { _arm_id(key) for key in assignments }:
                consumers.append(rid)
        consumers = sorted(set(consumers))
        if consumers:
            return _result("PASS", f"Managed identity {resource_id} is assigned to {len(consumers)} captured resources.\nThese assignments are declared consumers.\nThey do not establish token use.", principal_id=principal, consumer_ids=consumers)
        return _result("UNKNOWN", "No managed identity assignment was found in the captured resources.\nThe inventory may omit another supported resource or subscription.\nAuthentication use is not established by resource metadata.", principal_id=principal)
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        return _result("UNKNOWN", f"Managed identity consumers are unresolved: {exc}.", reason=str(exc))


def evaluate_federated_credentials(parent, *, tenant, context, receipt, managed=False):
    """Project exact current federated credentials, without inferring their use."""
    try:
        parent_id = _arm_id(parent["id"]) if managed else _guid(parent["id"])
        endpoint = (parent_id + "/federatedIdentityCredentials?api-version=2024-11-30" if managed
                    else "/v1.0/applications/" + parent_id + "/federatedIdentityCredentials")
        _authority(receipt, tenant=tenant, context=context, endpoint=endpoint,
                   audience=ARM if managed else GRAPH)
        if receipt["status"] not in {"collected", "empty"}:
            return _result("DENIED" if receipt["status"] == "denied" else "UNKNOWN", "Federated credential inventory is incomplete.")
        credentials, seen = [], set()
        for row in receipt["items"]:
            identity = _arm_id(row["id"]) if managed else _guid(row["id"])
            if managed and not identity.startswith(parent_id + "/federatedidentitycredentials/"):
                raise ValueError("federated credential belongs to another managed identity")
            if identity in seen:
                raise ValueError("duplicate federated credential")
            seen.add(identity)
            fields = row.get("properties", row) if managed else row
            issuer, subject, audience = fields.get("issuer"), fields.get("subject"), fields.get("audiences")
            if not isinstance(issuer, str) or not issuer.startswith("https://") or not subject or not isinstance(audience, list) or not audience:
                raise ValueError("federated credential trust fields are malformed")
            credentials.append({"id": identity, "issuer": issuer, "subject": subject, "audiences": audience})
        if receipt["status"] == "empty" and credentials:
            raise ValueError("empty receipt contains credentials")
        if credentials:
            return _result("UNKNOWN", f"{len(credentials)} federated credentials are configured for {parent_id}.\nTheir trust subjects are recorded in this inventory.\nNo credential-specific successful-use history was captured.", credentials=credentials)
        return _result("NOT_APPLICABLE", "No federated credentials are configured for this identity.", credentials=[])
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        return _result("UNKNOWN", f"Federated credential inventory is unresolved: {exc}.", reason=str(exc))
