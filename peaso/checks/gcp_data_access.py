"""Configured GCP Data Access audit policy checks for Spanner and Pub/Sub."""

from __future__ import annotations

import re
from copy import deepcopy

from peaso.gcp_project_alias import AliasUnavailable, prove_project_alias, root_candidate

from peaso.gcp_data_access_policy import evidence_for, malformed_direct_principal
from peaso.checks import register
from peaso.checks.facts import Unavailable, get, optional


CHECK_SERVICES = {
    "gcp_pci_iam_policy_ca1281da7ab2": "spanner.googleapis.com",
    "gcp_pci_iam_policy_9a8ce875703d": "pubsub.googleapis.com",
}
REQUIRED_TYPES = frozenset({"DATA_READ", "DATA_WRITE"})
VALID_TYPES = frozenset({"ADMIN_READ", "DATA_READ", "DATA_WRITE"})


def _verdict(status, reason, **evidence):
    return {"status": status, "reason": reason, "evidence": evidence,
            "claim": "configured Data Access audit policy only; log delivery and method coverage unverified"}


def evaluate(policy_item, check_id, principal_evidence, project_scope, *, collection_status="collected"):
    """Evaluate one project-root policy against one signed service proposal.

    ``principal_evidence`` is an owner-supplied policy input, not a cloud-derived
    default: {status, scope, service, source_ref, principals}. Unresolved
    group/domain membership is never guessed.
    """
    if check_id not in CHECK_SERVICES:
        raise ValueError("unsupported signed check ID")
    service = CHECK_SERVICES[check_id]
    if not isinstance(project_scope, str) or not re.fullmatch(r"projects/[A-Za-z0-9_-]+", project_scope):
        return _verdict("UNKNOWN", "project scope authority unavailable", service=service)
    if collection_status != "collected" or not isinstance(policy_item, dict):
        return _verdict("UNKNOWN", "complete project-root IAM policy unavailable", service=service, scope=project_scope)
    try:
        policy_name = get(policy_item, "name", str)
    except Unavailable:
        return _verdict("UNKNOWN", "complete project-root IAM policy unavailable", service=service, scope=project_scope)
    if policy_name != project_scope:
        return _verdict("UNKNOWN", "complete project-root IAM policy unavailable", service=service, scope=project_scope)

    coverage = policy_item.get("_coverage", {}).get("effectiveAuditConfigs") if isinstance(policy_item.get("_coverage"), dict) else None
    if (not isinstance(coverage, dict) or coverage.get("status") != "collected"
            or coverage.get("ancestry_known") is not True or coverage.get("missing_scopes") != []
            or coverage.get("malformed_scopes", []) != []):
        return _verdict("UNKNOWN", "inherited audit policy inventory incomplete", service=service, scope=project_scope)

    entries = policy_item.get("effectiveAuditConfigs")
    if not isinstance(entries, list) or not entries:
        return _verdict("UNKNOWN", "effective audit chain unavailable", service=service, scope=project_scope)
    scopes = []
    for entry in entries:
        try:
            scope = get(entry, "scope", str)
        except Unavailable:
            return _verdict("UNKNOWN", "malformed effective audit entry", service=service, scope=project_scope)
        scopes.append(scope)
    if (scopes[0] != project_scope or len(scopes) != len(set(scopes))
            or any(not re.fullmatch(r"(?:folders|organizations)/[0-9]+", scope) for scope in scopes[1:])
            or any(scope.startswith("organizations/") for scope in scopes[:-1])):
        return _verdict("UNKNOWN", "effective audit chain has missing or foreign scope", service=service, scope=project_scope)

    if (not isinstance(principal_evidence, dict) or principal_evidence.get("status") != "approved"
            or principal_evidence.get("scope") != project_scope or principal_evidence.get("service") != service
            or not isinstance(principal_evidence.get("source_ref"), str) or not principal_evidence["source_ref"].strip()):
        return _verdict("UNKNOWN", "required-principal evidence absent or unbound", service=service, scope=project_scope)
    principals = principal_evidence.get("principals")
    if (not isinstance(principals, list) or not principals
            or any(not isinstance(p, str) or not p.strip() or p != p.strip() for p in principals)
            or len(set(principals)) != len(principals)):
        return _verdict("UNKNOWN", "required-principal set missing or malformed", service=service, scope=project_scope)
    if any(malformed_direct_principal(p) for p in principals):
        return _verdict("UNKNOWN", "malformed direct required principal", service=service, scope=project_scope)

    enabled = set()
    exemptions = {kind: set() for kind in REQUIRED_TYPES}
    configured_at = {kind: [] for kind in REQUIRED_TYPES}
    for entry in entries:
        try:
            configs = optional(entry, "auditConfigs", [], list)
        except Unavailable:
            return _verdict("UNKNOWN", "ancestor auditConfigs unavailable", service=service, scope=project_scope)
        for config in configs:
            try:
                configured_service = get(config, "service", str)
            except Unavailable:
                return _verdict("UNKNOWN", "malformed auditConfig", service=service, scope=project_scope)
            try:
                rows = optional(config, "auditLogConfigs", [], list)
            except Unavailable:
                return _verdict("UNKNOWN", "auditLogConfigs unavailable", service=service, scope=project_scope)
            for row in rows:
                try:
                    kind = get(row, "logType", str)
                except Unavailable:
                    return _verdict("UNKNOWN", "malformed audit log type", service=service, scope=project_scope)
                if kind not in VALID_TYPES:
                    return _verdict("UNKNOWN", "malformed audit log type", service=service, scope=project_scope)
                try:
                    members = optional(row, "exemptedMembers", [], list)
                except Unavailable:
                    return _verdict("UNKNOWN", "malformed exemption list", service=service, scope=project_scope)
                if any(not isinstance(p, str) or not p.strip()
                        or malformed_direct_principal(p) for p in members):
                    return _verdict("UNKNOWN", "malformed exemption list", service=service, scope=project_scope)
                if configured_service not in ("allServices", service) or kind not in REQUIRED_TYPES:
                    continue
                enabled.add(kind)
                exemptions[kind].update(members)
                configured_at[kind].append({"scope": entry["scope"], "service": configured_service})

    base = {"service": service, "scope": project_scope, "evaluated_scopes": scopes,
            "source_requests": coverage.get("source_requests", []),
            "enabled_types": sorted(enabled), "configured_at": configured_at,
            "required_principal_count": len(principals)}
    missing = sorted(REQUIRED_TYPES - enabled)
    if missing:
        return _verdict("FAIL", "required Data Access log types absent from complete policy", **base, missing_types=missing)

    exact = sorted({principal for principal in principals for kind in REQUIRED_TYPES if principal in exemptions[kind]})
    if exact:
        return _verdict("FAIL", "required principal explicitly exempted", **base, exempted_required=exact)

    # A group, domain, or principalSet requirement denotes more than its
    # literal IAM string. The collected audit config has no membership closure,
    # so even an empty exemption list cannot establish that every member was
    # evaluated. A direct user exemption may also overlap a required group.
    unsupported = sorted(p for p in principals if not p.startswith(("user:", "serviceAccount:")))
    if unsupported:
        return _verdict("UNKNOWN", "required principal membership closure unavailable",
                        **base, unresolved_required_principals=unsupported)

    # IAM audit exemptions may name groups or domains. Without a reviewed
    # membership closure, a different exemption string can still cover a
    # required individual; preserve UNKNOWN instead of claiming PASS.
    ambiguous = sorted({member for kind in REQUIRED_TYPES for member in exemptions[kind]
                        if not member.startswith(("user:", "serviceAccount:"))
                        or any(member.casefold() == principal.casefold() for principal in principals)})
    if ambiguous:
        return _verdict("UNKNOWN", "possible required-principal exemption membership unresolved",
                        **base, ambiguous_exemptions=ambiguous)
    return _verdict("PASS", "both required Data Access log types configured without known required-principal exemptions", **base)


def _root_candidate(row):
    return root_candidate(row)


def _native(item, index, check_id):
    context = index.get("context") if isinstance(index, dict) else None
    scope = context.get("scope") if isinstance(context, dict) else None
    if not isinstance(scope, str) or not scope.startswith("projects/"):
        return "NOT_APPLICABLE", {"reason": "project-root IAM policy required"}
    try:
        name = get(item, "name", str)
    except Unavailable:
        return "UNKNOWN", {"reason": "project-root IAM policy name unavailable"}
    if name.count("/") > 1 and not root_candidate(item):
        return "NOT_APPLICABLE", {"reason": "resource-level IAM policy is outside the project-root check"}
    # Only a direct root or its exact CRM project view needs the inventory-wide
    # alias proof. Ordinary resource peers retain their prior applicability.
    if name.count("/") > 1 and not re.fullmatch(
            r"//cloudresourcemanager\.googleapis\.com/projects/[1-9][0-9]*", name):
        if _root_candidate(item):
            return "UNKNOWN", {"reason": "resource IAM policy identity unavailable or may be a hierarchy root"}
        return "NOT_APPLICABLE", {"reason": "resource-level IAM policy is outside the project-root check"}
    collections = index.get("collections", {}) if isinstance(index, dict) else {}
    policies = collections.get("iam_policy", []) if isinstance(collections, dict) else []
    matching = [row for row in policies if isinstance(row, dict) and row.get("scope") == scope] if isinstance(policies, list) else []
    if len(matching) == 1 and isinstance(matching[0].get("items"), list):
        candidates = [row for row in matching[0]["items"] if root_candidate(row)]
        if (len(candidates) == 2 and sum(row.get("name") == scope for row in candidates if isinstance(row, dict)) == 1
                and any(isinstance(row.get("name"), str) and row["name"].startswith(
                    "//cloudresourcemanager.googleapis.com/projects/") for row in candidates if isinstance(row, dict))):
            projects = collections.get("project", []) if isinstance(collections, dict) else []
            selected = [row for row in projects if isinstance(row, dict) and row.get("scope") == scope] if isinstance(projects, list) else []
            try:
                if len(selected) != 1:
                    raise AliasUnavailable("project collection unavailable or ambiguous")
                raw = deepcopy(matching[0])
                for row in raw["items"]:
                    if isinstance(row, dict):
                        row.pop("effectiveAuditConfigs", None)
                        coverage = row.get("_coverage")
                        if isinstance(coverage, dict):
                            coverage.pop("effectiveAuditConfigs", None)
                            coverage.pop("projectAlias", None)
                metadata = context.get("metadata") if isinstance(context, dict) else None
                ledger = get(metadata, "source_requests", list)
                binding = prove_project_alias(scope, selected[0], raw, ledger)
            except (AliasUnavailable, Unavailable) as exc:
                return "UNKNOWN", {"reason": "project alias authority unresolved", "detail": str(exc)}
            direct = matching[0]["items"][binding.direct_position]
            alias = matching[0]["items"][binding.alias_position]
            if item == alias:
                return "NOT_APPLICABLE", {"reason": "verified CAI project projection; direct root evaluated"}
            if item != direct:
                return "UNKNOWN", {"reason": "project-root IAM policy identity unavailable"}
            narrowed = dict(index)
            narrowed["collections"] = dict(collections)
            narrowed["collections"]["iam_policy"] = [{**matching[0], "items": [direct]}]
            status, evidence = _native(direct, narrowed, check_id)
            if status in ("PASS", "FAIL"):
                evidence = {**evidence, "project_alias_requests": list(binding.source_requests),
                            "project_number": binding.project_number}
            return status, evidence
    if name.count("/") > 1:
        if _root_candidate(item):
            return "UNKNOWN", {"reason": "resource IAM policy identity unavailable or may be a hierarchy root"}
        return "NOT_APPLICABLE", {"reason": "resource-level IAM policy is outside the project-root check"}

    # The engine can collapse duplicate root identities before invoking us.
    # The original collection must establish a single root before PASS or FAIL.
    collections = index.get("collections", {}).get("iam_policy", [])
    if not isinstance(collections, list):
        collections = []
    matching = [row for row in collections if isinstance(row, dict) and row.get("scope") == scope]
    items = matching[0].get("items") if len(matching) == 1 else None
    roots = [row for row in items if _root_candidate(row)] if isinstance(items, list) else []
    if len(matching) != 1 or len(roots) != 1 or roots[0] != item:
        verdict = _verdict("UNKNOWN", "project-root IAM policy collection is not unique",
                           service=CHECK_SERVICES[check_id], scope=scope,
                           root_candidate_count=len(roots))
        return verdict["status"], {"reason": verdict["reason"], "claim": verdict["claim"], **verdict["evidence"]}
    status = matching[0].get("status", "not_collected")
    principal = evidence_for(context.get("metadata"), scope, CHECK_SERVICES[check_id])
    verdict = evaluate(item, check_id, principal, scope, collection_status=status)
    return verdict["status"], {"reason": verdict["reason"], "claim": verdict["claim"], **verdict["evidence"],
                              **({"principal_source_ref": principal["source_ref"]} if principal else {})}


# The signed proposal category is `logging`, which register does not accept.
# Native `hardening` is an explicit companion choice pending source-owner review;
# signed entries and exact requirement references remain unchanged.
@register("gcp_pci_iam_policy_ca1281da7ab2", "gcp", "hardening", "iam_policy",
          "Spanner Data Access audit logging", "medium", "AU-2",
          "Add effective Spanner auditConfigs with required DATA_READ and DATA_WRITE types and remove relevant exemptions.")
def spanner_data_access(item, index):
    return _native(item, index, "gcp_pci_iam_policy_ca1281da7ab2")


@register("gcp_pci_iam_policy_9a8ce875703d", "gcp", "hardening", "iam_policy",
          "Pub/Sub Data Access audit logging", "medium", "AU-2",
          "Add effective Pub/Sub auditConfigs with required DATA_READ and DATA_WRITE types and remove relevant exemptions.")
def pubsub_data_access(item, index):
    return _native(item, index, "gcp_pci_iam_policy_9a8ce875703d")
