"""Validate explicit, project-bound GCP Data Access owner policy input."""

from __future__ import annotations

import re
import unicodedata


OPTION = "gcp_data_access_required_principals"
SERVICES = frozenset({"spanner.googleapis.com", "pubsub.googleapis.com"})
PROJECT = re.compile(r"projects/[A-Za-z0-9_-]+\Z")
FIELDS = frozenset({"status", "scope", "service", "source_ref", "principals"})
DIRECT_PREFIXES = ("user:", "serviceAccount:")


def malformed_direct_principal(value):
    """Identify a direct IAM member string that lacks a usable email identity.

    Collective and other member forms remain for the evaluator's UNKNOWN path;
    this check does not assert membership or invent a set of principals.
    """
    if not isinstance(value, str) or not value.startswith(DIRECT_PREFIXES):
        return False
    email = value.split(":", 1)[1]
    if email.count("@") != 1:
        return True
    local, domain = email.split("@", 1)
    return (not local or not domain
            or any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in value))


def normalize_owner_policy(value, selected_scopes=None):
    """Return a bounded JSON-safe copy, or reject an unapproved/foreign declaration.

    An explicit empty list is valid but cannot yield a PASS or FAIL because
    no required-principal evidence then exists.
    """
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError(OPTION + " must be a list of at most 100 records")
    if selected_scopes is not None and (not isinstance(selected_scopes, list)
            or not all(isinstance(s, str) for s in selected_scopes)):
        raise ValueError("selected GCP scopes must be strings")
    selected = set(selected_scopes) if selected_scopes is not None else None
    result, seen = [], set()
    for row in value:
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise ValueError(OPTION + " record fields are incomplete or unsupported")
        scope, service = row["scope"], row["service"]
        if (row["status"] != "approved" or not isinstance(scope, str) or not PROJECT.fullmatch(scope)
                or not isinstance(service, str) or service not in SERVICES
                or selected is not None and scope not in selected):
            raise ValueError(OPTION + " requires approved selected project and supported service")
        source = row["source_ref"]
        if not isinstance(source, str) or not source.strip() or source != source.strip() or len(source) > 512:
            raise ValueError(OPTION + " requires a bounded, nonempty approval source_ref")
        principals = row["principals"]
        if (not isinstance(principals, list) or not 1 <= len(principals) <= 500
                or any(not isinstance(p, str) or not p.strip() or p != p.strip() or len(p) > 512 for p in principals)
                or len(principals) != len(set(principals))):
            raise ValueError(OPTION + " requires distinct, nonempty required principals")
        if any(malformed_direct_principal(p) for p in principals):
            raise ValueError(OPTION + " has a malformed direct required principal")
        key = (scope, service)
        if key in seen:
            raise ValueError(OPTION + " has duplicate project/service declarations")
        seen.add(key)
        result.append({"status": "approved", "scope": scope, "service": service,
                       "source_ref": source, "principals": list(principals)})
    return result


def evidence_for(metadata, scope, service):
    """Read one exact record from sealed snapshot metadata; invalid input is unknown."""
    if not isinstance(metadata, dict):
        return None
    if OPTION not in metadata:
        return None
    try:
        entries = normalize_owner_policy(metadata[OPTION])
    except ValueError:
        return None
    return next((row for row in entries if row["scope"] == scope and row["service"] == service), None)
