"""Reviewed proof for the documented KRTE Helm values to RBAC grant.

This collection is deliberately narrower than a generic Helm or challenge fact:
each field identifies the source object, privileged applier, rendered binding,
bound subject, and observed permission differential. The collector cannot infer
these joins from RBAC inventory alone.
"""
from __future__ import annotations

from . import Node, inventory_status, items

COLLECTION = "k8s_helm_values_rbac_evidence"
TECHNIQUE = "k8s-helm-values-rbac-privileged-reconciler"
TARGET = "get,list secrets in krte-sc-prod"


def _exact(value, expected):
    return type(value) is type(expected) and value == expected


def _name(value):
    return isinstance(value, str) and bool(value) and "*" not in value and "/" not in value


def valid(record, cluster):
    """Accept only a complete, single-source review of the specific documented lab path."""
    if not isinstance(record, dict) or not _name(cluster):
        return False
    fixed = {
        "TechniqueId": TECHNIQUE,
        "Status": "verified",
        "SourceConfigMapNamespace": "krte-sc-source",
        "SourceConfigMapName": "prod-values",
        "SourceConfigMapKey": "values.json",
        "ChartRuleField": "rbac.extraRules",
        "ChartSubjectField": "serviceAccount",
        "RenderedRoleNamespace": "krte-sc-prod",
        "BoundSubjectKind": "ServiceAccount",
        "BoundSubjectNamespace": "krte-sc-tenant",
        "GrantedResource": "secrets",
        "GrantedApiGroup": "",
        "GrantedNamespace": "krte-sc-prod",
        "GrantedVerbs": ["get", "list"],
        "PriorPermissionAbsent": True,
        "ValuesConsumedByReconciler": True,
        "ReconcilerCanApplyRole": True,
        "ReconcilerCanApplyRoleBinding": True,
        "AdmissionAccepted": True,
        "ReconcileSucceeded": True,
        "AfterPermissionAllowed": True,
    }
    if any(not _exact(record.get(key), value) for key, value in fixed.items()):
        return False
    if not all(_name(record.get(key)) for key in (
        "ReconcilerNamespace", "ReconcilerServiceAccount", "RenderedRoleName",
        "RenderedRoleBindingName", "BoundSubjectName")):
        return False
    if not isinstance(record.get("EvidenceRef"), str) or not record["EvidenceRef"].strip():
        return False
    if record.get("SourceId") != f"k8s:{cluster}:sa:krte-sc-tenant:{record['BoundSubjectName']}":
        return False
    return (record.get("RenderedRoleBindingSubject") == record["SourceId"]
            and record.get("RenderedRoleBindingRoleRef") ==
            f"Role/krte-sc-prod/{record['RenderedRoleName']}")


def load(model):
    """Return bounded authority nodes and the unique reviewed record for each."""
    records = {}
    status = inventory_status(model.snapshot, COLLECTION)
    for cluster, record in items(model.snapshot, COLLECTION):
        if status.get(cluster) not in ("collected", "empty") or not valid(record, cluster):
            continue
        target_id = f"k8s:verified-authority:{cluster}:krte-sc-prod:secrets:get,list:{record['SourceId']}"
        records.setdefault(target_id, []).append(record)
    nodes = {}
    unique = {}
    for target_id, matches in records.items():
        if len(matches) != 1:
            continue
        record = matches[0]
        cluster = target_id.split(":", 3)[2]
        nodes[target_id] = Node(target_id, "k8s_verified_authority", "k8s", cluster,
                                TARGET, attrs={"cluster": cluster, "resource": TARGET,
                                               "source_id": record["SourceId"]}, entity=True)
        unique[target_id] = record
    return nodes, unique
