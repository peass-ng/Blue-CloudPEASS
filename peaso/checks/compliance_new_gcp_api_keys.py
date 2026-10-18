"""Signed API-key target restriction predicate over cached API Keys list facts."""
from __future__ import annotations

from datetime import datetime
import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized, optional
from .fixtures import CASES


CHECK_ID = "gcp_api_keys_active_services_only"
SPEC_SHA256 = "3e6da3ff5ec3b72360ab8946e7e512c035aeb332a3bf70613fd0913f01c10202"
SIGNED_SOURCE_CATEGORY = "identity"  # The native registry normalizes this configuration finding to hardening.
_KEY = re.compile(r"^projects/[0-9]+/locations/global/keys/[A-Za-z0-9-]+$")


def _inventory(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "gcp":
        raise Unavailable("API key provider authority unavailable")
    scope = get(context, "scope", str)
    if not scope.startswith("projects/") or len(scope.split("/")) != 2:
        raise Unavailable("API key project scope unavailable")
    envelopes = get(index, "collections", dict).get("api_key")
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or
            envelopes[0].get("type") != "api_key" or
            envelopes[0].get("scope") != scope):
        raise Unavailable("API key inventory scope authority unavailable")
    rows = complete_items(index, "api_key")
    by_name = {}
    for row in rows:
        name = get(row, "name", str)
        if not _KEY.fullmatch(name) or name in by_name:
            raise Unavailable("API key identity malformed or duplicated")
        provenance = get(row, "_provenance", dict)
        requests = get(provenance, "source_requests", list)
        if get(provenance, "scope", str) != scope or not requests or not all(
                isinstance(request_id, str) and request_id for request_id in requests):
            raise Unavailable("API Keys list provenance unavailable")
        by_name[name] = row
    return by_name


@register(CHECK_ID, "gcp", "hardening", "api_key",
          "Active API key declares API target restrictions", "medium", "IA-5",
          "Set the active key's API restrictions to the specific services the application needs; review client restrictions separately.",
          dependencies=["api_key"])
def active_api_key_targets(item, index):
    by_name = memoized(index, ("verified_api_key_inventory",), lambda: _inventory(index))
    name = get(item, "name", str)
    if by_name.get(name) != item:
        raise Unavailable("API key differs from collected list fact")
    deleted_at = optional(item, "deleteTime", "", str)
    if deleted_at:
        try:
            instant = datetime.fromisoformat(deleted_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Unavailable("API key deletion time malformed") from exc
        if instant.tzinfo is None:
            raise Unavailable("API key deletion time lacks zone")
        return "NOT_APPLICABLE", {"api_key": name, "reason": "key is deleted"}

    # The owned keys.list projection explicitly includes restrictions and
    # deleteTime. The API omits restrictions/apiTargets when none are set.
    # Any explicit _coverage denial is rejected by optional/get.
    restrictions = optional(item, "restrictions", {}, dict)
    targets = optional(restrictions, "apiTargets", [], list)
    services = []
    for target in list_of_objects(targets):
        service = get(target, "service", str)
        if not service.strip():
            raise Unavailable("API target service unavailable")
        services.append(service)
    if not services:
        return result(True, api_key=name, restricted_services=[],
                      semantics="Complete API Keys list has no declared API target restrictions")
    if "cloudapis.googleapis.com" in services:
        return unknown("broad cloudapis target does not prove a specific approved API scope",
                       api_key=name, restricted_services=services)
    return result(False, api_key=name, restricted_services=services,
                  semantics="At least one API target declared; service approval and client restrictions are separate")


def _fixture(row):
    scope = "projects/fixture-project"
    return {"context": {"provider": "gcp", "scope": scope},
            "collections": {"api_key": [{"type": "api_key", "scope": scope,
                                          "status": "collected", "items": [row]}]},
            "api_key": [{"type": "api_key", "scope": scope, "data": row}]}


_key = {"name": "projects/123456789012/locations/global/keys/key-1",
        "_provenance": {"scope": "projects/fixture-project", "source_requests": ["request-1"]}}
_pass = {**_key, "restrictions": {"apiTargets": [{"service": "storage.googleapis.com"}]}}
_fail = {**_key, "restrictions": {"apiTargets": []}}
_unknown = {**_key, "_coverage": {"restrictions": {"status": "denied"}}}
CASES[CHECK_ID] = {"pass": _pass, "pass_index": _fixture(_pass),
                   "fail": _fail, "fail_index": _fixture(_fail),
                   "unknown": _unknown, "unknown_index": _fixture(_unknown)}
