"""Successful FHIR conditional deletes by redacted identifier search."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .aws_healthlake_fhir_b429 import normalize as normalize_fhir


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventName") != "DeleteResource":
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    query = request.get("queryStrings")
    if not isinstance(query, Mapping) or "identifier" not in query:
        return None
    base = normalize_fhir(record)
    if base is None:
        return None
    return {**base, "request.healthlake_conditional_delete_by_identifier": True}
