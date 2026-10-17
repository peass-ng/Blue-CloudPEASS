"""Fail-closed, reviewed pivots into named non-IAM principals.

The cloud API action only exposes or changes a credential. It is not an edge
until a complete review proves the exact external subject, usable credential,
successful authentication, and newly allowed target-plane action.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from urllib.parse import urlsplit

from . import Node, inventory_status, items

COLLECTION = "gcp_external_principal_evidence"


def _exact(value):
    return (isinstance(value, str) and bool(value.strip()) and value == value.strip()
            and not any(char in value for char in ("*", "?", "\n", "\r", "\x00")))


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp")
    return parsed


def _valid(record, scope, snapshot):
    if not isinstance(record, dict) or not scope.startswith("projects/"):
        return False
    fields = ("TechniqueId", "SourceId", "ActionResource", "AccessPermission",
              "TargetPlane", "TargetServiceResource", "TargetPrincipalId",
              "CredentialRef", "GainedPermission", "EvidenceRef",
              "PriorTestedPermission", "AfterTestedPermission",
              "PriorTestedResource", "AfterTestedResource")
    if any(not _exact(record.get(field)) for field in fields):
        return False
    if record.get("TargetScope") != scope:
        return False
    if record["ActionResource"] != scope and not record["ActionResource"].startswith(scope + "/"):
        return False
    target_resource = record["TargetServiceResource"]
    try:
        external = urlsplit(target_resource)
        external_ok = (external.scheme == "https" and external.hostname and external.path
                       and not external.username and not external.password
                       and not external.query and not external.fragment and external.port != 0)
    except ValueError:
        external_ok = False
    if (not target_resource.startswith(scope + "/")
            and not external_ok):
        return False
    if not (record["PriorTestedPermission"] == record["GainedPermission"]
            == record["AfterTestedPermission"]):
        return False
    if not (record["PriorTestedResource"] == record["TargetServiceResource"]
            == record["AfterTestedResource"]):
        return False
    try:
        captured = _instant(snapshot.get("created_at"))
        observed = _instant(record.get("EvidenceObservedAt"))
        expiry = _instant(record.get("CredentialExpiresAt"))
        prior = _instant(record.get("PriorAccessCheckedAt"))
        action = _instant(record.get("ActionObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        fresh = (prior < action <= after <= observed <= captured < expiry
                 and (captured - prior).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        fresh = False
    return (fresh and record.get("Status") == "verified"
            and all(record.get(key) is True for key in (
                "ActionSucceeded", "PriorSourceAccessDenied", "CredentialUsable",
                "CredentialFreshnessVerified", "AfterAuthenticationSucceeded",
                "AfterTargetPermissionAllowed"))
            and record.get("ObservedPrincipalId") == record["TargetPrincipalId"])


def _node_id(record):
    fields = ("TechniqueId", "SourceId", "TargetPlane", "TargetServiceResource", "TargetPrincipalId")
    digest = hashlib.sha256("\x00".join(record[field] for field in fields).encode()).hexdigest()[:20]
    return f"gcp_external_principal:{record['TargetPlane']}:{digest}"


def load(model):
    """Only a unique record in a complete project collection creates a node."""
    status = inventory_status(model.snapshot, COLLECTION)
    grouped = {}
    poisoned = set()
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = model._norm_scope(collection_scope)
        if not isinstance(record, dict):
            continue
        technique, source = record.get("TechniqueId"), record.get("SourceId")
        if not _exact(technique) or not _exact(source):
            continue
        owner = (technique, source, scope)
        if not all(_exact(record.get(key)) for key in (
                "ActionResource", "AccessPermission", "TargetPlane", "TargetServiceResource")):
            poisoned.add(owner)
            continue
        key = (record["TechniqueId"], record["SourceId"], scope,
               record["ActionResource"], record["AccessPermission"], record["TargetPlane"],
               record["TargetServiceResource"])
        grouped.setdefault(key, []).append((collection_scope, record))
    nodes, records = {}, {}
    for (technique, source, scope, _, _, _, _), matches in grouped.items():
        if (technique, source, scope) in poisoned:
            continue
        if len(matches) != 1 or status.get(matches[0][0]) != "collected":
            continue
        record = matches[0][1]
        if not _valid(record, scope, model.snapshot):
            poisoned.add((technique, source, scope))
            continue
        ident = _node_id(record)
        if record["ActionResource"] != scope:
            model.parents.setdefault(record["ActionResource"], scope)
        nodes[ident] = Node(ident, "gcp_external_principal", "gcp", scope,
                            f"{record['TargetPrincipalId']} on {record['TargetServiceResource']}",
                            attrs={"scope": scope, "resource": record["ActionResource"],
                                   "external_plane": record["TargetPlane"],
                                   "external_principal": record["TargetPrincipalId"],
                                   "external_resource": record["TargetServiceResource"]})
        records[ident] = record
    if poisoned:
        for ident, record in list(records.items()):
            if (record["TechniqueId"], record["SourceId"], record["TargetScope"]) in poisoned:
                records.pop(ident)
                nodes.pop(ident)
    return nodes, records


def select(model, candidates, source):
    if source is None:
        return {}
    entry = model.current_entry or {}
    if (entry.get("target") or {}).get("outcome") != "credentials":
        return {}
    def actions(value):
        if isinstance(value, dict):
            if isinstance(value.get("action"), str):
                yield value["action"].lower()
            for nested in value.values():
                yield from actions(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from actions(nested)
    required = set(actions(entry.get("requires") or {}))
    out = {}
    for ident, node in candidates.items():
        record = model.external_principal_records.get(ident)
        if (record is None or record["TechniqueId"] != entry.get("id")
                or record["SourceId"] != source.id
                or record["AccessPermission"].lower() not in required
                or node.attrs.get("resource") != record["ActionResource"]):
            continue
        authority = model.check(source, {"action": record["AccessPermission"]}, record["ActionResource"])
        if authority is not None and authority.confidence != "unknown":
            out[ident] = ("conditional", "reviewed_external_principal_gain")
    return out
