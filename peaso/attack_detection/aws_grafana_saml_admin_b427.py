"""Managed Grafana SAML administrator mapping updates."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_WORKSPACE = re.compile(r"g-[a-z0-9]{8,32}\Z")


def _admin_mapping(value: Any) -> bool:
    # CloudTrail masks the submitted values as "***" in this API.
    return value == "***" or (isinstance(value, list) and bool(value)
                              and all(isinstance(item, str) and item for item in value))


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Flag an accepted SAML admin mapping without exporting IdP configuration."""
    if (record.get("eventSource") != "grafana.amazonaws.com"
            or record.get("eventName") != "UpdateWorkspaceAuthentication"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = (record.get("userIdentity"),
                                   record.get("requestParameters"), record.get("responseElements"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    workspace = request.get("workspaceId")
    config = request.get("samlConfiguration")
    auth = response.get("authentication")
    if (not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace)
            or not isinstance(request.get("authenticationProviders"), list)
            or "SAML" not in request["authenticationProviders"]
            or not isinstance(config, Mapping)
            or not isinstance(config.get("idpMetadata"), Mapping)
            or not config["idpMetadata"]
            or not isinstance(config.get("roleValues"), Mapping)
            or not _admin_mapping(config["roleValues"].get("admin"))
            or not isinstance(auth, Mapping)
            or not isinstance(auth.get("providers"), list)
            or "SAML" not in auth["providers"]
            or not isinstance(auth.get("saml"), Mapping)
            or auth["saml"].get("status") != "CONFIGURED"
            or not isinstance(auth["saml"].get("configuration"), Mapping)
            or not isinstance(auth["saml"]["configuration"].get("roleValues"), Mapping)
            or auth["saml"]["configuration"]["roleValues"].get("admin")
               != config["roleValues"]["admin"]):
        return None
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{workspace}".encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "grafana.amazonaws.com",
        "event.name": "UpdateWorkspaceAuthentication", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.grafana_saml_admin_mapping_submitted": True,
    }
