"""Bind GKE Admin Activity events to the project declared by their resource."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


_ACTIVITY_LOG = re.compile(r"projects/([^/]+)/logs/cloudaudit\.googleapis\.com%2Factivity\Z")


def project_scope(log_name: Any, resource_labels: Any) -> str | None:
    """Return a project scope only when present log and resource projects agree."""
    if not isinstance(log_name, str) or not isinstance(resource_labels, Mapping):
        return None
    match = _ACTIVITY_LOG.fullmatch(log_name)
    if match is None:
        return None
    project = match.group(1)
    if "project_id" in resource_labels and (
            not isinstance(resource_labels["project_id"], str)
            or resource_labels["project_id"] != project):
        return None
    return f"projects/{project}"


def successful_status(payload: Mapping[str, Any]) -> bool:
    """Accept absent/empty GKE status or an explicit integer success code."""
    if "status" not in payload:
        return True
    status = payload["status"]
    if not isinstance(status, Mapping):
        return False
    if not status:
        return True
    return type(status.get("code")) is int and status["code"] == 0
