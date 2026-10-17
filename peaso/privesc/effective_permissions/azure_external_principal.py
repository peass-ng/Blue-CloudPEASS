"""Reviewed Azure control-plane pivots into exact adjacent-plane principals.

An ARM permission, a returned secret, or a successful command is not enough to
name a new principal. The optional evidence collection must prove one exact
subject and a newly authorized action after the credential or grant was used.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from urllib.parse import urlsplit

from . import Node, inventory_status, items

COLLECTION = "azure_external_principal_evidence"
CONTRACT = {
    "azure-avs-list-vcenter-cloudadmin-external-principal":
        ("microsoft.avs/privateclouds/listadmincredentials/action", "vmware_vcenter", "credential"),
    "azure-avs-list-nsxt-admin-external-principal":
        ("microsoft.avs/privateclouds/listadmincredentials/action", "vmware_nsx", "credential"),
    "azure-avs-run-command-vcenter-grant-external-principal":
        ("microsoft.avs/privateclouds/scriptexecutions/write", "vmware_vcenter", "identity_grant"),
    "azure-apim-developer-portal-sso-external-principal":
        ("microsoft.apimanagement/service/users/token/action", "apim_developer_portal", "credential"),
    "azure-datafactory-github-oauth-external-principal":
        ("microsoft.datafactory/factories/getgithubaccesstoken/action", "github_repository", "credential"),
    "azure-eventgrid-mqtt-client-grant-external-principal":
        ("microsoft.eventgrid/namespaces/permissionbindings/write", "eventgrid_mqtt", "identity_grant"),
}


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
    if not isinstance(record, dict) or not scope.startswith("/subscriptions/"):
        return False
    contract = CONTRACT.get(record.get("TechniqueId"))
    if contract is None or (record.get("AccessPermission", "").casefold(), record.get("TargetPlane"),
                            record.get("AccessArtifactKind")) != contract:
        return False
    fields = ("TechniqueId", "SourceId", "ActionResource", "AccessPermission",
              "TargetPlane", "TargetServiceResource", "TargetPrincipalId",
              "AccessArtifactRef", "GainedPermission", "EvidenceRef",
              "TargetServiceBindingEvidenceRef", "TargetSubjectBindingEvidenceRef",
              "PriorTestedPermission", "AfterTestedPermission",
              "PriorTestedResource", "AfterTestedResource")
    if any(not _exact(record.get(field)) for field in fields):
        return False
    if record.get("TargetScope", "").casefold() != scope.casefold():
        return False
    action_resource = record["ActionResource"].casefold()
    if action_resource != scope.casefold() and not action_resource.startswith(scope.casefold() + "/"):
        return False
    target_resource = record["TargetServiceResource"]
    try:
        url = urlsplit(target_resource)
        external_ok = (url.scheme == "https" and bool(url.hostname) and bool(url.path)
                       and not url.username and not url.password and not url.query and not url.fragment)
    except ValueError:
        external_ok = False
    if not (external_ok or target_resource.casefold().startswith(scope.casefold() + "/")):
        return False
    if (record["PriorTestedPermission"] != record["GainedPermission"]
            or record["AfterTestedPermission"] != record["GainedPermission"]
            or record["PriorTestedResource"] != target_resource
            or record["AfterTestedResource"] != target_resource
            or record.get("ObservedPrincipalId") != record["TargetPrincipalId"]):
        return False
    if record.get("AccessArtifactKind") not in ("credential", "identity_grant"):
        return False
    if record["TechniqueId"] == "azure-avs-run-command-vcenter-grant-external-principal":
        if (not all(_exact(record.get(key)) for key in (
                "ExecutedPackageId", "ExecutedCmdletId", "GrantOperationEvidenceRef"))
                or record.get("GrantOperationSucceeded") is not True):
            return False
    if record["TechniqueId"] == "azure-eventgrid-mqtt-client-grant-external-principal":
        if (not all(_exact(record.get(key)) for key in (
                "MqttClientId", "MqttClientGroupId", "PermissionBindingId",
                "OwnedCredentialEvidenceRef", "GrantOperationEvidenceRef"))
                or record.get("MqttClientId") != record["TargetPrincipalId"]
                or not all(record.get(key) is True for key in (
                    "ClientCreated", "ClientGroupBound", "PermissionBindingCreated",
                    "CredentialOwnedBySource", "GrantOperationSucceeded"))):
            return False
    try:
        captured = _instant(snapshot.get("created_at"))
        observed = _instant(record.get("EvidenceObservedAt"))
        expiry = _instant(record.get("EvidenceExpiresAt"))
        prior = _instant(record.get("PriorAccessCheckedAt"))
        action = _instant(record.get("ActionObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        fresh = (prior < action <= after <= observed <= captured < expiry
                 and (captured - prior).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        fresh = False
    return (fresh and record.get("Status") == "verified"
            and all(record.get(key) is True for key in (
                "ActionSucceeded", "PriorSourceAccessDenied", "AccessArtifactUsable",
                "AfterAuthenticationSucceeded", "AfterTargetPermissionAllowed",
                "TargetServiceBindingVerified", "TargetSubjectBindingVerified")))


def _node_id(record):
    fields = ("TechniqueId", "SourceId", "TargetPlane", "TargetServiceResource", "TargetPrincipalId")
    digest = hashlib.sha256("\x00".join(record[field] for field in fields).encode()).hexdigest()[:20]
    return f"azure_external_principal:{record['TargetPlane']}:{digest}"


def load(model):
    """A unique record in a complete subscription collection creates a target."""
    status = inventory_status(model.snapshot, COLLECTION)
    grouped, poisoned = {}, set()
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = str(collection_scope).casefold()
        if not isinstance(record, dict):
            continue
        technique, source = record.get("TechniqueId"), record.get("SourceId")
        if not _exact(technique) or not _exact(source):
            continue
        owner = (technique, source, scope)
        if not all(_exact(record.get(key)) for key in (
                "ActionResource", "AccessPermission", "TargetPlane", "TargetServiceResource",
                "TargetPrincipalId")):
            poisoned.add(owner)
            continue
        key = (technique, source, scope, record["ActionResource"],
               record["AccessPermission"], record["TargetPlane"], record["TargetServiceResource"],
               record["TargetPrincipalId"])
        grouped.setdefault(key, []).append((collection_scope, record))
    nodes, records = {}, {}
    for (technique, source, scope, _, _, _, _, _), matches in grouped.items():
        if (technique, source, scope) in poisoned:
            continue
        if len(matches) != 1 or status.get(matches[0][0]) != "collected":
            continue
        record = matches[0][1]
        if not _valid(record, scope, model.snapshot):
            poisoned.add((technique, source, scope))
            continue
        ident = _node_id(record)
        if record["ActionResource"].casefold() != scope.casefold():
            model.parents.setdefault(record["ActionResource"].casefold(), scope.casefold())
        nodes[ident] = Node(ident, "azure_external_principal", "azure", scope,
                            f"{record['TargetPrincipalId']} on {record['TargetServiceResource']}",
                            attrs={"scope": scope, "resource": record["ActionResource"],
                                   "external_plane": record["TargetPlane"],
                                   "external_principal": record["TargetPrincipalId"],
                                   "external_resource": record["TargetServiceResource"]})
        records[ident] = record
    if poisoned:
        for ident, record in list(records.items()):
            if (record["TechniqueId"], record["SourceId"], record["TargetScope"].casefold()) in poisoned:
                nodes.pop(ident)
                records.pop(ident)
    return nodes, records


def select(model, candidates, source):
    if source is None:
        return {}
    entry = model.current_entry or {}
    if (entry.get("target") or {}).get("outcome") not in ("credentials", "identity"):
        return {}

    def actions(value):
        if isinstance(value, dict):
            if isinstance(value.get("action"), str):
                yield value["action"].casefold()
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
                or record["AccessPermission"].casefold() not in required
                or node.attrs.get("resource") != record["ActionResource"]):
            continue
        authority = model.check(source, {"action": record["AccessPermission"]}, record["ActionResource"])
        if authority is not None and authority.confidence != "unknown":
            out[ident] = ("conditional", "reviewed_external_principal_gain")
    return out
