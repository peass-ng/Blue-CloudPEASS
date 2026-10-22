"""Typed proof for an attacker-controlled Container App deployment and identity."""
from __future__ import annotations

import re

from . import items
from .azure_containerapp_exec import _attached, _identity_main_stage


CONTRACT = frozenset({"azure-containerapp-sourcecontrols-write"})
_ACTION = "microsoft.app/containerapps/sourcecontrols/write"
_TYPE = "microsoft.app/containerapps"


def valid(model, technique, fact, source_id, target_id, target_scope):
    if technique not in CONTRACT or not isinstance(fact, dict):
        return False
    host = fact.get("ActionResourceId")
    if not isinstance(host, str) or not host.startswith("/subscriptions/") or "*" in host or "?" in host:
        return False
    child = fact.get("SourceControlResourceId")
    if (not isinstance(child, str) or not re.fullmatch(
            re.escape(host.casefold()) + r"/sourcecontrols/[a-z0-9][a-z0-9._-]*",
            child.casefold())):
        return False
    if not all(fact.get(key) is True for key in (
        "VerifiedPreconditions", "SourceBindingChanged",
        "AttackerControlledSourceVerified", "BuildSucceeded", "RevisionDeployed",
    )):
        return False
    if not all(isinstance(fact.get(key), str) and fact[key].strip() for key in (
        "EvidenceRef", "SourceBindingEvidenceRef",
        "BuildEvidenceRef", "DeploymentEvidenceRef", "DeploymentRevisionId",
    )):
        return False
    if (fact.get("TechniqueId") != technique or fact.get("Status") != "verified"
            or fact.get("EffectType") != "source_control_deployment_identity"
            or fact.get("SourceId") != source_id
            or fact.get("TargetKind") != "azure_managed_identity"
            or fact.get("TargetId") != target_id
            or fact.get("TargetScope", "").casefold() != host.casefold()
            or target_scope.casefold() != host.casefold()
            or fact.get("ManagedIdentityPrincipalId") != target_id
            or fact.get("SourceAction", "").casefold() != _ACTION):
        return False
    resource = model.resources.get(host.casefold())
    identity = model.principals.get(target_id)
    source = model.principals.get(source_id)
    grant = model.cached_check(source, {"action": _ACTION}, child.casefold()) if source else None
    if grant is None or grant.confidence == "unknown":
        return False
    if not (resource is not None and resource.get("type") == _TYPE
            and identity is not None and identity.kind == "azure_managed_identity"
            and host.casefold() in identity.attrs.get("hosts", ())):
        return False
    runtimes = [row for _, row in items(model.snapshot, "container_app_runtime")
                if str(row.get("id") or "").casefold() == host.casefold()
                and str(row.get("type") or "").casefold() == _TYPE]
    if len(runtimes) != 1 or _attached(runtimes[0], identity) is not True:
        return False
    if _identity_main_stage(runtimes[0], identity) is not True:
        return False
    props = runtimes[0].get("properties") or {}
    if (str(props.get("provisioningState") or "").casefold() != "succeeded"
            or str(props.get("runningStatus") or "").casefold() != "running"):
        return False
    revision_name = str(fact["DeploymentRevisionId"]).casefold()
    if "/" in revision_name:
        return False
    for revision in runtimes[0].get("revisions") or ():
        rid = str(revision.get("id") or "").casefold()
        rev = revision.get("properties") or {}
        replicas = rev.get("replicas")
        if (rid == host.casefold() + "/revisions/" + revision_name
                and rev.get("active") is True
                and str(rev.get("runningState") or "").casefold() == "running"
                and isinstance(replicas, int) and not isinstance(replicas, bool)
                and replicas > 0):
            return True
    return False
