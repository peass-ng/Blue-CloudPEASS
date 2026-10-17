"""Read-only Kubernetes server version enrichment for signed scope checks.

The caller owns the API client, retry policy, request budget, and discovery
collection. This helper only adds the observed ``GET /version`` declaration to
an already complete API discovery row; a failed read is explicit coverage.
"""
from __future__ import annotations

import re


_VERSION = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


def attach_server_version(reader, api, discovered, safe_error):
    """Enrich one complete cluster discovery row without inferring a version."""
    if discovered.get("status") != "collected" or len(discovered.get("items", [])) != 1:
        return
    item = discovered["items"][0]
    if "serverVersion" in item or "serverVersion" in item.get("_coverage", {}):
        return
    try:
        response = reader.call(api.get_json, "/version")
        raw = response.get("gitVersion") if isinstance(response, dict) else None
        if not isinstance(raw, str) or len(raw) > 253 or not _VERSION.fullmatch(raw):
            raise ValueError("malformed Kubernetes server version")
        item["serverVersion"] = {"gitVersion": raw}
        item.setdefault("provenance", {})["server_version_source"] = "GET /version"
    except Exception as exc:
        status, error = safe_error(exc)
        item.setdefault("_coverage", {})["serverVersion"] = {
            "status": status, "error": error, "reason": "Server version read unavailable"}
