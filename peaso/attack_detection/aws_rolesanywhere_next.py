"""Project accepted Roles Anywhere anchor/profile and CRL control events.

Certificate and CRL bytes, signed headers and session credentials never enter
normalized evidence. Existing IAM Roles Anywhere mutation signals have a
separate, narrower normalizer.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


EVENTS = {"CreateTrustAnchor", "CreateProfile", "DisableCrl", "UpdateCrl", "DeleteCrl"}
UUID = re.compile(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")


def _field(value: object, key: str) -> object:
    if not isinstance(value, Mapping):
        return None
    wanted = "".join(char for char in key.lower() if char.isalnum())
    for candidate, item in value.items():
        if isinstance(candidate, str) and "".join(char for char in candidate.lower() if char.isalnum()) == wanted:
            return item
    return None


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "rolesanywhere.amazonaws.com" or name not in EVENTS
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None
            or not isinstance(region, str) or re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", region) is None):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    kind = "trust-anchor" if name == "CreateTrustAnchor" else "profile" if name == "CreateProfile" else "crl"
    key = {"trust-anchor": "trustAnchor", "profile": "profile", "crl": "crl"}[kind]
    detail = _field(response, key)
    id_key = {"trust-anchor": "trustAnchorId", "profile": "profileId", "crl": "crlId"}[kind]
    identifier = _field(request, id_key) or _field(detail, id_key)
    target = (f"arn:aws:rolesanywhere:{region}:{account}:{kind}/{identifier}"
              if isinstance(identifier, str) and UUID.fullmatch(identifier) else None)
    source = _field(request, "source")
    roles = _field(request, "roleArns")
    same_account_roles = (isinstance(roles, list) and bool(roles)
                          and all(isinstance(role, str) and
                                  role.startswith(f"arn:aws:iam::{account}:role/") for role in roles))
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return {
        "cloud.provider": "aws", "event.source": "rolesanywhere.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "cloud.region": region,
        "actor.id": actor, "target.id": target,
        "request.rolesanywhere_bundle_anchor_created": not failed and name == "CreateTrustAnchor"
            and target is not None and _field(source, "sourceType") == "CERTIFICATE_BUNDLE",
        "request.rolesanywhere_profile_with_roles_created": not failed and name == "CreateProfile"
            and target is not None and same_account_roles,
        "request.rolesanywhere_crl_disabled": not failed and name == "DisableCrl"
            and target is not None and _field(detail, "enabled") is False,
        "request.rolesanywhere_crl_data_updated": not failed and name == "UpdateCrl"
            and target is not None and _field(request, "crlData") is not None,
        "request.rolesanywhere_crl_deleted": not failed and name == "DeleteCrl" and target is not None,
    }
