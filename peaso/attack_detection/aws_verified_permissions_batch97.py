"""Normalize accepted Verified Permissions management operations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_NAMES = {
    "CreatePolicy", "GetPolicy", "BatchGetPolicy", "CreatePolicyStoreAlias",
    "PutSchema", "UpdatePolicyStore", "DeletePolicy", "DeletePolicyStore",
    "CreateIdentitySource", "UpdateIdentitySource",
}
_FIELDS = {
    "CreatePolicy": "vp_static_permit_policy_created",
    "GetPolicy": "vp_policy_body_read_requested",
    "BatchGetPolicy": "vp_policy_body_read_requested",
    "CreatePolicyStoreAlias": "vp_alias_mapped",
    "PutSchema": "vp_schema_written",
    "UpdatePolicyStore": "vp_validation_disabled",
    "DeletePolicy": "vp_policy_deleted",
    "DeletePolicyStore": "vp_policy_store_deleted",
    "CreateIdentitySource": "vp_oidc_source_created",
    "UpdateIdentitySource": "vp_oidc_source_updated",
}


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def normalize_aws_verified_permissions_batch97(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if record.get("eventSource") != "verifiedpermissions.amazonaws.com" or not isinstance(name, str) or name not in _NAMES:
        return None
    read = name in {"GetPolicy", "BatchGetPolicy"}
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not read):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    if record.get("errorCode") or record.get("errorMessage"):
        accepted = False
    elif isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        accepted = False
    else:
        store = request.get("policyStoreId")
        same_store = isinstance(response, Mapping) and response.get("policyStoreId") == store
        policy = request.get("policyId")
        has_policy = _nonempty(store) and _nonempty(policy)
        oidc = (request.get("configuration") if name == "CreateIdentitySource"
                else request.get("updateConfiguration"))
        oidc = oidc.get("openIdConnectConfiguration") if isinstance(oidc, Mapping) else None
        has_oidc = (isinstance(oidc, Mapping) and _nonempty(oidc.get("issuer"))
                    and isinstance(oidc.get("tokenSelection"), Mapping))
        if name == "CreatePolicy":
            accepted = (_nonempty(store) and same_store and _nonempty(response.get("policyId"))
                        and response.get("policyType") == "STATIC" and response.get("effect") == "Permit")
        elif name in {"GetPolicy", "BatchGetPolicy", "DeletePolicy"}:
            accepted = has_policy
        elif name == "DeletePolicyStore":
            accepted = _nonempty(store)
        elif name == "CreatePolicyStoreAlias":
            accepted = (_nonempty(store) and _nonempty(request.get("aliasName")) and same_store
                        and response.get("aliasName") == request.get("aliasName"))
        elif name == "PutSchema":
            accepted = _nonempty(store) and same_store
        elif name == "UpdatePolicyStore":
            settings = request.get("validationSettings")
            accepted = (_nonempty(store) and same_store and isinstance(settings, Mapping)
                        and settings.get("mode") == "OFF")
        elif name in {"CreateIdentitySource", "UpdateIdentitySource"}:
            accepted = (_nonempty(store) and same_store and has_oidc
                        and _nonempty(response.get("identitySourceId")))
            if name == "UpdateIdentitySource":
                accepted = accepted and request.get("identitySourceId") == response.get("identitySourceId")
        else:
            accepted = False
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    result = {
        "cloud.provider": "aws", "event.source": record["eventSource"], "event.name": name,
        "event.outcome": "failure" if record.get("errorCode") or record.get("errorMessage") else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": request.get("policyStoreId"),
    }
    result["request." + _FIELDS[name]] = bool(accepted)
    return result
