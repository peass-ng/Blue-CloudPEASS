"""Reviewed, resource-scoped GCP permission grants to the acting principal.

IAM policy writes and policy-grant DDL are both supported when the catalog
declares their complete requirements. Mutation authority alone does not
identify a new permission. The optional
collection attests the exact resource, grantee, granted permissions, and before/
after authorization result. Incomplete or conflicting records create no target.
"""
from __future__ import annotations

import hashlib

from . import Node, inventory_status, items

COLLECTION = "gcp_resource_self_grant_evidence"


def _name(value):
    return isinstance(value, str) and bool(value.strip()) and "*" not in value


def _valid(record, scope):
    if not isinstance(record, dict) or not scope.startswith("projects/"):
        return False
    for key in ("TechniqueId", "SourceId", "TargetResource", "GrantedResource",
                "AccessPermission", "EvidenceRef"):
        if not _name(record.get(key)):
            return False
    if record.get("TargetScope") != scope or record.get("GrantedPrincipalId") != record.get("SourceId"):
        return False
    resource = record["TargetResource"]
    if resource != scope and not resource.startswith(scope + "/"):
        return False
    # A policy grant can be effective on the resource or a child governed by
    # it. The reviewed allow result must identify
    # the exact resource where the newly granted permission was tested.
    granted_resource = record["GrantedResource"]
    if granted_resource != resource and not granted_resource.startswith(resource + "/"):
        return False
    permissions = record.get("GrantedPermissions")
    if (not isinstance(permissions, list) or not permissions
            or any(not _name(permission) for permission in permissions)
            or len(permissions) != len(set(permissions))):
        return False
    return (record.get("Status") == "verified"
            and all(record.get(key) is True for key in (
                "PriorPermissionAbsent", "PolicyMutationAuthorized", "PolicyMutationAccepted", "AfterPermissionAllowed")))


def _node_id(technique, source, resource, granted_resource):
    digest = hashlib.sha256(f"{technique}\x00{source}\x00{resource}\x00{granted_resource}".encode()).hexdigest()[:20]
    return f"gcp_verified_authority:self-grant:{technique}:{digest}"


def load(model):
    """Return only unique records from complete project collections."""
    status = inventory_status(model.snapshot, COLLECTION)
    grouped = {}
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = model._norm_scope(collection_scope)
        if not isinstance(record, dict) or not all(_name(record.get(key)) for key in (
                "TechniqueId", "SourceId", "TargetResource", "GrantedResource")):
            continue
        key = (record["TechniqueId"], record["SourceId"], scope,
               record["TargetResource"], record["GrantedResource"])
        grouped.setdefault(key, []).append((collection_scope, record))
    nodes, records = {}, {}
    for (technique, source, scope, resource, granted_resource), matches in grouped.items():
        if len(matches) != 1 or status.get(matches[0][0]) not in ("collected", "empty"):
            continue
        record = matches[0][1]
        if not _valid(record, scope):
            continue
        ident = _node_id(technique, source, resource, granted_resource)
        # The reviewed resource-to-project join lets the ordinary GCP IAM
        # evaluator test the declared mutation permission on this exact target.
        if resource != scope:
            model.parents.setdefault(resource, scope)
        if granted_resource != resource:
            model.parents.setdefault(granted_resource, resource)
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", scope,
                            f"{source} gains {', '.join(record['GrantedPermissions'])} on {granted_resource}",
                            attrs={"scope": scope, "resource": granted_resource,
                                   "policy_resource": resource, "source_id": source,
                                   "technique_id": technique}, entity=True)
        records[ident] = record
    return nodes, records


def select(model, candidates, source):
    """Join the reviewed new grant to the YAML action and its exact source."""
    entry = model.current_entry or {}
    if source is None or entry.get("target", {}).get("outcome") != "permission_grant":
        return {}
    technique = entry.get("id")
    grants = (entry.get("target") or {}).get("grants")
    if not isinstance(grants, list) or not grants:
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
    required_actions = set(actions(entry.get("requires") or {}))
    out = {}
    for target_id, node in candidates.items():
        record = model.resource_self_grant_records.get(target_id)
        if (record is None or record["TechniqueId"] != technique
                or record["SourceId"] != source.id
                or record["GrantedPermissions"] != grants
                or node.attrs.get("policy_resource") != record["TargetResource"]
                or node.attrs.get("resource") != record["GrantedResource"]):
            continue
        permission = record["AccessPermission"]
        if permission.lower() not in required_actions:
            continue
        authority = model.check(source, {"action": permission}, record["TargetResource"])
        if authority is not None and authority.confidence != "unknown":
            out[target_id] = ("conditional", "reviewed_resource_self_grant")
    return out
