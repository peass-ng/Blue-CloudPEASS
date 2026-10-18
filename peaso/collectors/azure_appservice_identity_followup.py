"""Private opt-in, metadata-only GET job for one listed Microsoft.Web/sites ID.

Integrate with azure.collect's existing reader.call/request cache and reader.run.
Only select this job when app_service_identity_detail is an admitted dependency.
"""
from __future__ import annotations

import re

ARM_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+", re.I)


def site_identity_job(reader, request, arm_origin, site, *, api_version="2025-03-01"):
    rid = site.get("id") if isinstance(site, dict) else None
    if not isinstance(rid, str) or not ARM_SITE.fullmatch(rid):
        raise ValueError("invalid App Service site ID")
    scope = "/".join(rid.split("/")[:3])
    if not re.fullmatch(r"/subscriptions/[A-Za-z0-9._-]+", scope, re.I):
        raise ValueError("invalid App Service subscription")

    def fetch():
        detail = reader.call(request, arm_origin + rid + "?api-version=" + api_version)
        if not isinstance(detail, dict) or str(detail.get("id", "")).casefold() != rid.casefold():
            raise ValueError("foreign or malformed App Service detail")
        if str(detail.get("type", "")).casefold() != "microsoft.web/sites":
            raise ValueError("incorrect App Service resource type")
        # No app settings, secrets or credentials are retained.
        identity = detail.get("identity")
        if not isinstance(identity, dict):
            raise ValueError("missing or malformed managed identity detail")
        safe = {k: identity[k] for k in ("type", "principalId", "userAssignedIdentities") if k in identity}
        if "userAssignedIdentities" in safe and isinstance(safe["userAssignedIdentities"], dict):
            safe["userAssignedIdentities"] = {k: None for k in safe["userAssignedIdentities"]}
        yield [{"id": rid + "/identityDetail", "parent_id": rid, "kind": detail.get("kind"), "identity": safe,
                "_provenance": {"representation": "full", "source_operation": "get", "read_only": True,
                                "api_version": api_version}}]

    # Engine indexes both parent and child under the subscription scope;
    # parent_id and the synthetic exact site ID retain the one-site binding.
    return ("app_service_identity_detail", scope, "Microsoft.Web", fetch)
