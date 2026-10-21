"""Optional read-only sources for Azure unused-IAM completion checks."""
from __future__ import annotations

from peaso.unused_iam_azure_completion import ARM, GRAPH, _arm_id, _guid


def _capture(reader, request, *, endpoint, audience, tenant, context, project, scope=None):
    receipt = {"tenant_id": _guid(tenant), "tenant_verified": True,
               "credential_context_id": context, "read_only": True, "method": "GET",
               "body": None, "endpoint": endpoint, "audience": audience,
               "status": "unknown", "items": []}
    if scope is not None:
        receipt["scope"] = scope
    seen = set()
    try:
        for page in reader.pages(request, audience + endpoint, audience=audience,
                                 next_key="@odata.nextLink" if audience == GRAPH else "nextLink"):
            for raw in page:
                item = project(raw)
                key = item["id"].lower()
                if key in seen:
                    raise ValueError("duplicate source identity")
                seen.add(key)
                receipt["items"].append(item)
        receipt["status"] = "collected" if receipt["items"] else "empty"
    except Exception as exc:
        code = getattr(exc, "status_code", None) or getattr(exc, "status", None)
        receipt["status"] = "partial" if receipt["items"] else "denied" if code in (401, 403, "401", "403") else "unknown"
        receipt["error"] = {"code": "source_read_incomplete"}
    return receipt


def collect_user_success(reader, request, *, tenant, context):
    endpoint = "/v1.0/users?$select=id,displayName,accountEnabled,signInActivity"
    def project(raw):
        if not isinstance(raw, dict):
            raise ValueError("malformed Graph user")
        uid = _guid(raw.get("id"))
        return {key: raw[key] for key in ("id", "displayName", "accountEnabled", "signInActivity", "_coverage") if key in raw} | {"id": uid}
    return _capture(reader, request, endpoint=endpoint, audience=GRAPH, tenant=tenant, context=context, project=project)


def collect_arm_assignments(reader, request, *, tenant, context, subscription):
    scope = "/subscriptions/" + _guid(subscription)
    endpoint = scope + "/resources?api-version=2021-04-01"
    def project(raw):
        if not isinstance(raw, dict):
            raise ValueError("malformed ARM resource")
        rid = _arm_id(raw.get("id"))
        return {"id": rid, **({"identity": raw["identity"]} if "identity" in raw else {})}
    return _capture(reader, request, endpoint=endpoint, audience=ARM, tenant=tenant,
                    context=context, project=project, scope=scope)


def collect_federated_credentials(reader, request, parent, *, tenant, context, managed=False):
    parent_id = _arm_id(parent["id"]) if managed else _guid(parent["id"])
    endpoint = (parent_id + "/federatedIdentityCredentials?api-version=2024-11-30" if managed
                else "/v1.0/applications/" + parent_id + "/federatedIdentityCredentials")
    def project(raw):
        if not isinstance(raw, dict):
            raise ValueError("malformed federated credential")
        if managed:
            rid = _arm_id(raw.get("id"))
            if not rid.startswith(parent_id + "/federatedidentitycredentials/"):
                raise ValueError("credential belongs to another managed identity")
            fields = raw.get("properties")
        else:
            rid = _guid(raw.get("id"))
            fields = raw
        if not isinstance(fields, dict):
            raise ValueError("credential trust metadata is missing")
        return {"id": rid, **({"properties": {key: fields[key] for key in ("issuer", "subject", "audiences") if key in fields}}
                              if managed else {key: fields[key] for key in ("issuer", "subject", "audiences") if key in fields})}
    return _capture(reader, request, endpoint=endpoint, audience=ARM if managed else GRAPH,
                    tenant=tenant, context=context, project=project)
