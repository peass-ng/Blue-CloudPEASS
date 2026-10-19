"""Public snapshot engine. Evaluation is deterministic and never calls a provider."""
from __future__ import annotations
import copy
import json
import re
from urllib.parse import quote
from collections import Counter, defaultdict
from importlib import import_module
from .snapshot import SCHEMA_VERSION, PROVIDERS, digest, freeze, validate, resources, resource_id, seal
from .progress import emit_progress
from .report_quality import normalize_unknown_reasons

CATEGORIES = ("hardening", "exposure", "least_privilege", "iam_graph", "network", "privesc",
              "monitoring", "encryption", "compliance", "logging", "identity", "recovery",
              "vulnerability", "threat_detection", "secure_development", "backup",
              "supply_chain", "malware", "asset_management", "patch_management")
# Catalog-driven privilege-escalation map (peaso.privesc). "privesc" selects every technique.
PRIVESC_CHECK_ID = "privesc"
PRIVESC_FRAMEWORK = "HackTricks Cloud Best Practices"
# Report schema 1.1 stores native items once (in the snapshot) and references them from resources and graphs;
# expand_report() restores the embedded 1.0 form and compact_report() migrates 1.0 reports to 1.1.
REPORT_SCHEMA_VERSION = "1.1"
FRAMEWORK_ALIASES = {"hacktricks": "HackTricks Cloud Best Practices", "hacktricks_cloud_best_practices": "HackTricks Cloud Best Practices",
    "nist_800_53": "NIST 800-53", "nist": "NIST 800-53"}


def _registry():
    from .checks import CHECKS
    from .checks.native_only import automated_checks
    return automated_checks(CHECKS)


def get_catalog():
    from .analysis import ANALYSIS_CHECKS
    from .checks.catalog import coverage as upstream_coverage, description_for, framework_catalog, requirement_tags_for
    from .collectors import supported_types
    from .collectors.bulk_evidence import coverage as evidence_coverage
    from .privesc.versioned_catalog import current_binding
    analysis_checks = copy.deepcopy(ANALYSIS_CHECKS)
    for check in analysis_checks:
        reviewed = description_for(check["id"])
        if reviewed:
            check.update(reviewed)
            check["rationale"] = reviewed["description"]
            check["requirement_controls"] = requirement_tags_for(check["id"])
    from .checks.native_only import scope as automation_scope, automated_coverage, automated_inventory_coverage, automated_inventory_types
    checks = [check.public() for check in _registry()] + analysis_checks
    return {"schema_version": SCHEMA_VERSION, "privesc_catalog": current_binding(), "providers": list(PROVIDERS), "categories": list(CATEGORIES),
        "inventories": {p: automated_inventory_types(p, supported_types(p)) for p in PROVIDERS}, "inventory_coverage": automated_inventory_coverage(evidence_coverage(), _registry()), "framework_versions": framework_catalog(), "manual_requirements": [], "automation_scope": automation_scope(), "checks": checks, "privesc_techniques": privesc_techniques(), "upstream_coverage": automated_coverage(upstream_coverage()), "frameworks": framework_labels(checks),
        "limitations": ["Native reviewed snapshot checks only; upstream catalogs are provenance, not migrated runtime coverage.",
                         "Framework mappings are thematic review guidance, not certification.", "Graphs describe declared relationships; effective access and reachability require separate validation."]}


catalog = get_catalog


def framework_labels(checks):
    """One row per canonical framework label: its filter id (alias or name) and the version ids it names."""
    from .checks.catalog import framework_display_names
    by_name = defaultdict(set)
    for fid, name in framework_display_names().items():
        by_name[name].add(fid)
    names = sorted({framework for check in checks for framework in check["frameworks"]})
    return [{"id": next((k for k, v in FRAMEWORK_ALIASES.items() if v == name), name), "name": name,
             "framework_ids": sorted(by_name.get(name, ()))} for name in names]


def _expand_frameworks(frameworks):
    from .checks.catalog import expand_framework_selectors
    return expand_framework_selectors([FRAMEWORK_ALIASES.get(value, value) for value in frameworks])


def privesc_techniques(provider=None):
    """Public summary of the privilege-escalation technique catalog (one row per technique)."""
    try:
        from . import privesc
        entries = privesc.catalog()["entries"]
    except ImportError:  # packages built without peaso.privesc (e.g. a trimmed API bundle)
        return []
    return [{"id": e["id"], "provider": e.get("provider"), "service": e.get("service"), "title": e.get("title"),
             "severity": e.get("severity"), "confidence": e.get("confidence"), "category": "privesc",
             "frameworks": [PRIVESC_FRAMEWORK], "source": e.get("source"), "source_revision": e.get("source_revision"),
             "mitigation": e.get("mitigation")}
            for e in entries if provider is None or e.get("provider") == provider]


ADMIN_EQUIVALENT_TECHNIQUE = {
    "id": "admin-equivalent", "title": "Principal already administers the target scope", "provider": None, "service": "iam",
    "summary": "The principal's collected grants are equivalent to administrator of the scope; no escalation step is needed.",
    "required_permissions": {"all_of": ["administrator-equivalent grant on the scope"], "any_of": [],
                             "leaves": ["administrator-equivalent grant on the scope"],
                             "alternatives": [["administrator-equivalent grant on the scope"]]}, "requires": {},
    "source": None, "source_revision": None, "conditions": [], "blockers": [], "severity": "critical", "catalog_confidence": "derived",
    "mitigation": "Review why this principal needs full administrative control; prefer scoped, time-bound access.", "references": []}


def _permission_text(requirement):
    if not isinstance(requirement, dict):
        return str(requirement)
    for key in ("action", "data_action", "entra_permission", "graph_app_permission", "entra_role", "entra_pim_eligible_role", "entra_tenant_setting"):
        if requirement.get(key):
            text = str(requirement[key])
            break
    else:
        if requirement.get("verb"):
            resource = "/".join(str(requirement[k]) for k in ("resource", "subresource") if requirement.get(k))
            group = requirement.get("api_group")
            text = f"{requirement['verb']} {group + '/' if group else ''}{resource}"
        elif requirement.get("entra_owner_of"):
            text = f"owner of {requirement['entra_owner_of']}"
        else:
            text = ", ".join(f"{k}={v}" for k, v in sorted(requirement.items()))
    where = requirement.get("resource") if "action" in requirement or "data_action" in requirement else None
    where = where or requirement.get("scope") or requirement.get("namespace") or requirement.get("resource_name")
    return f"{text} on {where}" if where and where != "*" else text


def _requirement_text(item):
    """Text of one requires item: a leaf requirement, or a nested {all_of}/{any_of} group rendered recursively
    ("(a AND b)", "(a OR (b AND c))"); a list inside any_of is one conjunction."""
    from .privesc.schema import is_group
    if not is_group(item):
        return _permission_text(item)
    key = "all_of" if "all_of" in item else "any_of"
    parts = ["(" + " AND ".join(_requirement_text(c) for c in child) + ")" if isinstance(child, list) and len(child) != 1
             else _requirement_text(child[0] if isinstance(child, list) else child) for child in item.get(key) or []]
    if len(parts) == 1:
        return parts[0]
    return "(" + (" AND " if key == "all_of" else " OR ").join(parts) + ")"


def _required_permissions(requires):
    """Readable required permissions. all_of / any_of keep the catalog's top-level structure (nested groups are
    rendered by _requirement_text); leaves lists every leaf permission (flatten_requirements) and alternatives the
    disjunctive normal form (expand_requires: each alternative is a set of permissions that together suffice)."""
    from .privesc.schema import CatalogError, expand_requires, flatten_requirements
    out = {"all_of": [_requirement_text(r) for r in requires.get("all_of") or []],
           "any_of": [[_requirement_text(r) for r in (group if isinstance(group, list) else [group])] for group in requires.get("any_of") or []],
           "leaves": list(dict.fromkeys(_permission_text(r) for r in flatten_requirements(requires)))}
    try:
        out["alternatives"] = [[_permission_text(r) for r in alternative] for alternative in expand_requires(requires)]
    except CatalogError:
        out["alternatives"] = None  # beyond the evaluator's expansion cap; the structured all_of/any_of still apply
    return out


def privesc_technique_details(technique_ids, *, catalog_binding=None, tenant_id=None):
    """Catalog details (summary, required permissions, HackTricks source, conditions, mitigation) per technique id."""
    try:
        from .privesc.versioned_catalog import lookup_entries
        entries, lookup_status = lookup_entries(technique_ids, catalog_binding, tenant_id=tenant_id)
    except ImportError:
        entries, lookup_status = {}, "catalog_unavailable"
    details = {}
    for technique in technique_ids:
        if technique == "admin-equivalent" and lookup_status in ("exact_bounded_v5", "exact_additive_v4", "exact_legacy", "legacy_unversioned_fallback"):
            details[technique] = dict(copy.deepcopy(ADMIN_EQUIVALENT_TECHNIQUE), catalog_lookup_status="synthetic")
            continue
        entry = entries.get(technique)
        if entry is None:
            details[technique] = {"id": technique, "unknown": True, "catalog_lookup_status": lookup_status}
            continue
        requires = entry.get("requires") or {}
        from .privesc.effective_permissions.principal_evidence import BULK_CONTRACT
        if technique in BULK_CONTRACT:
            requires = BULK_CONTRACT[technique]["requires"]
        details[technique] = {
            "id": technique, "title": entry.get("title"), "provider": entry.get("provider"), "service": entry.get("service"),
            "summary": entry.get("summary"), "requires": copy.deepcopy(requires),
            "required_permissions": _required_permissions(requires),
            "source": entry.get("source"), "source_revision": entry.get("source_revision"),
            "conditions": copy.deepcopy(entry.get("conditions") or []), "blockers": list(entry.get("blockers") or []),
            "severity": entry.get("severity"), "catalog_confidence": entry.get("confidence"),
            "mitigation": entry.get("mitigation"), "references": list(entry.get("references") or []),
            "catalog_lookup_status": lookup_status}
    return details


def _privesc_selected(provider, categories, checks, frameworks):
    """None when privesc is not selected; otherwise the technique-id filter (empty set = every technique)."""
    if "privesc" not in categories:
        return None
    frameworks = [FRAMEWORK_ALIASES.get(value, value) for value in frameworks] if frameworks else None
    if frameworks and PRIVESC_FRAMEWORK not in frameworks:
        return None
    if not checks or PRIVESC_CHECK_ID in checks:
        return set()
    techniques = {t["id"] for t in privesc_techniques(provider)} & set(checks)
    return techniques or None


def _selection(provider, categories, checks, frameworks):
    selected_categories = list(CATEGORIES) if not categories else _string_list(categories, "categories")
    if any(category not in CATEGORIES for category in selected_categories):
        raise ValueError("unsupported category")
    registry = _registry()
    from .analysis import ANALYSIS_CHECKS
    checks = checks or None
    frameworks = frameworks or None
    if checks is not None:
        from .checks import CHECK_ALIASES
        checks = list(dict.fromkeys(CHECK_ALIASES.get(check, check) for check in _string_list(checks, "checks")))
        from .checks.native_only import exclusions
        from .checks.catalog import manual_requirement_ids
        unavailable = set(checks).intersection(exclusions()) | set(checks).intersection(manual_requirement_ids(provider))
        if unavailable:
            raise ValueError("check requires external policy or manual evidence and is not available for automated scans: " + ", ".join(sorted(unavailable)))
        known = {c.id for c in registry if c.provider == provider} | {c["id"] for c in ANALYSIS_CHECKS}
        if any(check not in known for check in checks):
            known |= {PRIVESC_CHECK_ID} | {t["id"] for t in privesc_techniques(provider)}
        if any(check not in known for check in checks):
            raise ValueError("unknown check ID for selected provider")
    if frameworks is not None:
        frameworks = [FRAMEWORK_ALIASES.get(value, value) for value in _string_list(frameworks, "frameworks")]
        from .checks.catalog import _framework_rows, framework_selector_index
        provider_ids = {row["id"] for row in _framework_rows() if row["provider"] in (provider, "all")}
        supported = {f for c in registry if c.provider == provider for f in c.frameworks} | {f for c in ANALYSIS_CHECKS for f in c["frameworks"]} | provider_ids
        index = framework_selector_index()
        # Ids, canonical display names and family labels (e.g. "CIS", "NIST 800-53") are all valid selectors.
        if any(f not in supported and not provider_ids.intersection(index.get(f.lower(), ())) for f in frameworks):
            raise ValueError("unsupported framework")
        frameworks = _expand_frameworks(frameworks)
    selected = [c for c in registry if c.provider == provider and c.category in selected_categories
        and (checks is None or c.id in checks) and (frameworks is None or (set(c.frameworks) | set(getattr(c, "framework_ids", []))).intersection(frameworks))]
    return selected_categories, selected


def _string_list(value, name):
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(name + " must be a string list")
    return list(dict.fromkeys(value))


def _request(request):
    if not isinstance(request, dict):
        raise ValueError("scan request must be an object")
    # API compatibility accepts either a connector or the complete scan request.
    connector = request.get("connector", request if "provider" in request else None)
    if not isinstance(connector, dict) or connector.get("provider") not in PROVIDERS:
        raise ValueError("connector requires a supported provider")
    for field in ("auth", "options"):
        if field in connector and not isinstance(connector[field], dict):
            raise ValueError("connector " + field + " must be an object")
    if "scopes" in connector:
        _string_list(connector["scopes"], "scopes")
    _selection(connector["provider"], request.get("categories"), request.get("checks"), request.get("frameworks"))
    return copy.deepcopy(connector)


def _full_selection(provider, categories, selected):
    return set(categories) == set(CATEGORIES) and {c.id for c in selected} == {c.id for c in _registry() if c.provider == provider}


def collect_snapshot(request):
    connector = _request(request)
    emit_progress(phase="collecting", provider=connector["provider"], completed=0, total=None, resources=0, dynamic_total=True)
    options = connector.get("options", {})
    if "snapshot" in options:
        snapshot = validate(options["snapshot"])
        if snapshot["provider"] != connector["provider"]:
            raise ValueError("connector/snapshot provider mismatch")
        requested = connector.get("scopes", [])
        if requested and requested != snapshot["scopes"]:
            raise ValueError("connector/snapshot scope mismatch")
        emit_progress(phase="collecting", provider=connector["provider"], completed=len(snapshot["collections"]),
                      total=len(snapshot["collections"]), resources=sum(len(c["items"]) for c in snapshot["collections"]), dynamic_total=False)
        return snapshot
    if options.get("demo"):
        from .demo import demo_snapshot
        snapshot = demo_snapshot(connector["provider"])
        emit_progress(phase="collecting", provider=connector["provider"], completed=len(snapshot["collections"]),
                      total=len(snapshot["collections"]), resources=sum(len(c["items"]) for c in snapshot["collections"]), dynamic_total=False)
        return snapshot
    from .collectors import collect_live
    requirements = plan_collection(request)
    # Repository inventory is shared by ECR checks. Carry the selected native
    # predicate as an internal collector fact signal without adding a fake
    # inventory type to the public collection plan.
    if connector["provider"] == "aws":
        _, selected = _selection("aws", request.get("categories"), request.get("checks"), request.get("frameworks"))
        connector.setdefault("options", {})["_ecr_latest_scan_requested"] = any(
            check.id == "aws.c2b.ecr.latest_image_no_medium_plus_findings" for check in selected)
    if connector["provider"] == "azure":
        _, selected = _selection("azure", request.get("categories"), request.get("checks"), request.get("frameworks"))
        connector.setdefault("options", {})["_azure_database_native_requested"] = any(
            check.id in {"azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d",
                         "azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a",
                         "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf"}
            for check in selected)
        connector.setdefault("options", {})["_azure_apim_diagnostics_checks"] = [
            check.id for check in selected if check.id in {
                "azure_api_management_app_http_logs_enabled_21c108d",
                "azure_api_management_app_http_logs_enabled_9b3b56e",
                "azure_api_management_app_http_logs_enabled_9ef06db"}]
    snapshot = validate(collect_live(connector, requirements))
    emit_progress(phase="collecting", provider=connector["provider"], completed=len(snapshot["collections"]),
                  total=len(snapshot["collections"]), resources=sum(len(c["items"]) for c in snapshot["collections"]), dynamic_total=False)
    snapshot["metadata"]["collection_plan"] = {"mode": "collect_all" if options.get("collect_all") else "explicit_inventories" if "inventories" in options else "full_default" if _full_selection(connector["provider"], *_selection(connector["provider"], request.get("categories"), request.get("checks"), request.get("frameworks"))) else "dependencies", "requirements": requirements,
        "categories": request.get("categories") or list(CATEGORIES), "checks": request.get("checks") or "all_selected", "frameworks": request.get("frameworks") or "all_selected"}
    return validate(seal(snapshot))


def _analysis_selection(provider, categories, checks, frameworks):
    from .analysis import ANALYSIS_CHECKS
    frameworks = _expand_frameworks(frameworks) if frameworks else None
    return [c for c in ANALYSIS_CHECKS if c["category"] in categories and c.get("provider") in (provider, "all")
        and (not checks or c["id"] in checks) and (not frameworks or set(c["frameworks"]).intersection(frameworks))]


# Bulk log/audit event streams. No registered check, analysis, graph or privesc rule reads them, and on
# large tenants they dominate the snapshot (Azure: ~75% of items and peak memory). They are collected
# only on explicit request (options.inventories, or collect_all) or when a selected check declares them.
BULK_STREAM_TYPES = {
    "azure": frozenset({"activity_log", "directory_audit", "sign_in_log", "directory_sign_in"}),
    "gcp": frozenset({"activity", "log_entry", "audit_log_entry"}),
    "aws": frozenset({"cloudtrail_event", "cloudtrail_lookup_event"}),
    "k8s": frozenset({"event", "audit_event"}),
}


def _selected_graph_categories(categories, native, analyzed, explicit_categories, checks, frameworks):
    """Filtered requests collect graphs only for categories actually selected."""
    selected = set(explicit_categories or categories)
    if not explicit_categories and (checks or frameworks):
        selected = {check.category for check in native} | {check["category"] for check in analyzed}
    return selected & {"network", "iam_graph"}


def plan_collection(request):
    connector = _request(request)
    provider = connector["provider"]
    categories, checks = _selection(provider, request.get("categories"), request.get("checks"), request.get("frameworks"))
    from .collectors import supported_types
    from .analysis import REQUIRED_TYPES, privesc_required_types
    from .checks.native_only import automated_inventory_types
    available = set(automated_inventory_types(provider, supported_types(provider)))
    required = {kind for check in checks for kind in getattr(check, "dependencies", [check.kind])}
    # The signed PCI bucket read-grant predicate needs ACL closure only when
    # this exact check is selected; other bucket-only checks stay cheap.
    if provider == "gcp" and any(c.id == "gcp_pci_bucket_157fb0c69361" for c in checks):
        required.update({"bucket_acl", "object_acl"})
    # Extra facts required by cross-resource native predicates.
    if any(c.id == "k8s.network.namespace_policy_inventory" for c in checks):
        required.add("networkpolicy")
    # Read key metadata opportunistically for a definite configured-CMK failure.
    # It is not a check dependency: an unavailable key read must not suppress
    # independent contradictions already observed on the recovery vault.
    if provider == "azure" and any(c.id == "azure.gap.recovery_service_vault_encrypted_with_cmk" for c in checks):
        required.add("vault_key")
    analysis_selected = _analysis_selection(provider, categories, request.get("checks"), request.get("frameworks"))
    graph_categories = _selected_graph_categories(categories, checks, analysis_selected,
        request.get("categories"), request.get("checks"), request.get("frameworks"))
    for category in {c["category"] for c in analysis_selected} | graph_categories:
        required.update(REQUIRED_TYPES.get(provider, {}).get(category, []))
    if _privesc_selected(provider, categories, request.get("checks"), request.get("frameworks")) is not None:
        required.update(privesc_required_types(provider))
    collect_all = connector.get("options", {}).get("collect_all", False)
    if type(collect_all) is not bool:
        raise ValueError("collect_all must be a boolean")
    if collect_all and "inventories" in connector.get("options", {}):
        raise ValueError("collect_all and inventories are mutually exclusive")
    default_full = _full_selection(provider, categories, checks)
    if collect_all:
        return sorted(available)
    inventories = connector.get("options", {}).get("inventories")
    if inventories is not None:
        if not isinstance(inventories, list) or any(kind not in available for kind in inventories):
            raise ValueError("inventories must be supported resource types")
        required = set(inventories)
    if default_full and inventories is None:
        # The full default plan keeps inventories used by graphs, cards and resource views.
        # Bulk event streams and the AWS-owned managed policy library are opt-in
        # when no selected check or analysis consumer declares them.
        return sorted(available - BULK_STREAM_TYPES.get(provider, frozenset())
                      - ({"iam_managed_policy"} if provider == "aws" and "iam_managed_policy" not in required else set()))
    from .collectors.bulk_evidence import declared_types, expand_native_requirements
    required = expand_native_requirements(provider, required)
    # Explicit check selections can request declared evidence contracts; the
    # dispatcher records unavailable projections as not_collected, never empty.
    if request.get('checks') or request.get('frameworks'):
        available |= declared_types(provider)
    return sorted(required & available)


def _index(snapshot, inventory):
    index = defaultdict(list)
    # resources() sorts public wrappers by native identity. Dependency rows
    # must instead preserve the authoritative collection order: predicates
    # verify that complete_items() matches the collection's exact items.
    # Keep wrappers and duplicate handling unchanged; only their index order
    # changes. Missing/conflicting rows still fail the inventory guards.
    positions = {}
    for collection in snapshot['collections']:
        for item in collection['items']:
            key = (collection['type'], collection['scope'],
                   resource_id(snapshot['provider'], collection['type'], collection['scope'], item))
            positions.setdefault(key, len(positions))
    ordered = sorted(inventory, key=lambda row: positions.get((row['type'], row['scope'], row['native_id']), len(positions)))
    for resource in ordered:
        index[resource["type"]].append(resource)
    collections = defaultdict(list)
    for collection in snapshot["collections"]:
        # A completely enumerated empty inventory is still present evidence.
        # Keep its typed resource list so scope predicates can distinguish it
        # from an inventory that was never collected. Envelope status remains
        # authoritative for denied, partial and foreign-scope facts.
        index.setdefault(collection["type"], [])
        collections[collection["type"]].append(collection)
    index["collections"] = dict(collections)
    return dict(index)


def _finding(check, provider, scope, rid, service, status, evidence, frameworks=None):
    from .finding_priority import effective_priority
    current = {"id": digest([provider, scope, rid, check.id]), "category": check.category, "check_id": check.id,
        "title": check.title, "provider": provider, "service": service, "resource_id": rid, "scope": scope,
        "severity": effective_priority(check.id, check.severity), "status": status, "frameworks": list(check.frameworks if frameworks is None else frameworks),
        "evidence": evidence, "remediation": check.remediation}
    if provider == "aws":
        from .checks.aws_finding_priority import contextual_severity as aws_contextual_severity
        from .checks.aws_compute_storage_priority import contextual_severity as compute_contextual_severity
        current["severity"] = compute_contextual_severity(current, aws_contextual_severity(current, current["severity"]))
    if provider == "azure":
        from .checks.azure_finding_priority import contextual_severity
        current["severity"] = contextual_severity(current, current["severity"])
    return current


def _unknown_coverage_reason(findings=(), *, collection_status=None):
    """Describe evidence gaps without copying SDK messages or native payloads."""
    states = {"denied": "Read access to required inventory was denied.",
              "malformed": "Required inventory response was malformed.",
              "timeout": "Required inventory read timed out.",
              "partial": "Required inventory collection is partial; conclusions need the missing evidence.",
              "not_collected": "Required inventory was not collected.",
              "unknown": "Required inventory could not be collected conclusively."}
    if collection_status in states:
        return states[collection_status]
    import re
    reasons = []
    for finding in findings:
        if finding.get("status") not in {"UNKNOWN", "DENIED"}:
            continue
        evidence = finding.get("evidence", {})
        reason = evidence.get("reason") if isinstance(evidence, dict) else None
        if not isinstance(reason, str):
            continue
        field = re.fullmatch(r"missing fact: ([A-Za-z_][A-Za-z0-9_.]{0,120})", reason)
        lower = reason.lower()
        if field:
            safe = "Missing collected field: " + field[1] + "."
        elif "user inherited from uninspected image metadata" == reason:
            safe = "Container user is inherited from image metadata that was not inspected."
        elif "denied" in lower or finding.get("status") == "DENIED":
            safe = "A required metadata read was denied."
        elif "dependency" in lower or "required scoped inventory" in lower or "incomplete" in lower:
            safe = "Required dependency inventory is missing or incomplete."
        elif "applicability" in lower:
            safe = "Check applicability is unresolved because required evidence is unavailable."
        elif "window" in lower or "activity" in lower or "observation" in lower:
            safe = "The required observation window lacks conclusive evidence."
        elif "malformed" in lower or "invalid" in lower:
            safe = "Required native facts are malformed or invalid."
        elif lower.startswith(("unknown ", "unrecognized ", "unsupported ")):
            safe = "The selected check cannot interpret a provider setting or version."
        elif "missing" in lower or "unavailable" in lower or "not collected" in lower:
            safe = "Required native facts are missing or unavailable."
        else:
            safe = "No conclusive evidence was available for this selected check."
        if safe not in reasons:
            reasons.append(safe)
        if len(reasons) == 3:
            break
    return " ".join(reasons) or "No conclusive evidence was available for this selected check."


def _safe_collection_error_code(collection):
    """Known machine error identifiers remain evidence; arbitrary text is omitted."""
    error = collection.get("error", {})
    code = error.get("code") if isinstance(error, dict) else None
    known = {"demo_permission_denied", "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Forbidden", "Unauthorized",
             "PermissionDenied", "permission_denied", "PERMISSION_DENIED", "401", "403", "read_timeout",
             "resource_limit", "page_limit", "scope_limit", "collection_cancelled", "malformed_response",
             "not_requested", "unsupported_inventory", "api_unavailable", "SERVICE_DISABLED", "NOT_FOUND"}
    return code if isinstance(code, str) and code in known else None


def _retired_collection_evidence(provider, snapshot, collection):
    """Interpret a no-call marker only for a reviewed exact kind and clock."""
    from datetime import datetime
    from .aws_service_lifecycle import RETIRED_SERVICES, retirement_state

    error = collection.get("error", {})
    if provider != "aws" or not isinstance(error, dict) or error.get("code") != "retired_service":
        return None
    kind = collection.get("type")
    entry = next(((service, value) for service, value in RETIRED_SERVICES.items()
        if collection.get("service") == service and kind in value["applies_to_service_kinds"]), None)
    if entry is None:
        return None
    service, reviewed = entry
    stamp = snapshot.get("created_at")
    try:
        observed = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if isinstance(stamp, str) else None
    except ValueError:
        observed = None
    state = retirement_state(kind, observed)
    evidence = {"reason": f"{reviewed['name']} is in full shutdown; current inventory is not applicable.",
        "service": service, "end_of_support": reviewed["end_of_support"].isoformat(),
        "no_access_after": reviewed["no_access_after"].isoformat(), "source": reviewed["primary_url"],
        "collection_status": collection.get("status"), "semantics": "Service lifecycle coverage, not a resource security pass."}
    if state != "retired" or collection.get("status") != "empty" or collection.get("items"):
        return "unknown", {**evidence, "reason": "Retired-service marker conflicts with collection status or observation date; applicability is unknown.", "lifecycle_state": state}
    return "retired", evidence


# Reviewed PSP-object predicates only. A later scope or enforcement check must opt in
# through a separate source review, even if it uses the same collection kind.
_PSP_RESOURCE_CHECK_IDS = frozenset({
    "k8s.ports.podsecuritypolicy.pod_security_policy_container_privilege_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_hostpid_sharing_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_hostipc_sharing_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_host_network_access_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_container_privilege_escalation_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_immutable_container_filesystem",
    "k8s.ports.podsecuritypolicy.pod_security_policy_non_root_container",
    "k8s.claude.podsecuritypolicy.allowed_host_path_restricted",
    "k8s.claude.podsecuritypolicy.default_seccomp_profile",
    "k8s.claude.podsecuritypolicy.security_services_hardening",
})


def _psp_resource_absence_evidence(provider, snapshot, collection):
    """Recognize only the native, same-cluster proof that PSP objects cannot exist."""
    if provider != "k8s" or collection.get("type") != "podsecuritypolicy":
        return None
    error, marker = collection.get("error"), collection.get("applicability")
    if (collection.get("scope") not in snapshot.get("scopes", ())
            or collection.get("service") != "kubernetes"
            or collection.get("status") != "not_collected"
            or collection.get("coverage_status") != "not_applicable"
            or collection.get("items") != [] or not isinstance(error, dict)
            or error.get("kind") != "not_applicable"
            or error.get("code") != "pod_security_policy_api_absent"
            or not isinstance(marker, dict)
            or marker.get("observed_resource_absent") != "policy/v1beta1/podsecuritypolicies"
            or marker.get("source") != "GET /apis and GET /version"):
        return None
    cluster = snapshot.get("metadata", {}).get("cluster_id")
    if not isinstance(cluster, str) or not cluster or len(cluster) > 256:
        return None
    discovery = [row for row in snapshot["collections"]
        if row.get("type") == "api_discovery" and row.get("scope") == collection["scope"]]
    if (len(discovery) != 1 or discovery[0].get("service") != "kubernetes"
            or discovery[0].get("status") != "collected"
            or discovery[0].get("error") or len(discovery[0].get("items", [])) != 1):
        return None
    item = discovery[0]["items"][0]
    provenance = item.get("provenance")
    if (item.get("id") != "k8s://" + quote(cluster, safe="") + "/api-discovery"
            or not isinstance(provenance, dict)
            or provenance.get("cluster_id") != cluster
            or provenance.get("source") != "GET /apis"
            or item.get("_coverage")
            or item.get("podSecurityPolicyAdvertised") is not False):
        return None
    server_version = item.get("serverVersion")
    version = server_version.get("gitVersion") if isinstance(server_version, dict) else None
    if (not isinstance(version, str) or len(version) > 128
            or marker.get("kubernetes_version") != version):
        return None
    match = re.fullmatch(r"v?([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})([-+][0-9A-Za-z.\-]{1,96})?", version)
    if not match or tuple(int(part) for part in match.groups()[:3]) < (1, 25, 0):
        return None
    suffix = match.group(4) or ""
    # A hyphen may be a vendor build or a prerelease; accept only recognized
    # release build labels. Unknown labels cannot prove a stable server.
    if suffix.startswith("-") and not re.fullmatch(
            r"-(?:gke[.-][0-9]+|(?:eks|aks)[.-][0-9a-f]+|k3s[0-9]+|rke2r[0-9]+)", suffix):
        return None
    return {"reason": "PodSecurityPolicy resource API removed on observed Kubernetes version; legacy PSP resource check is not applicable.",
        "kubernetes_version": version, "observed_resource_absent": "policy/v1beta1/podsecuritypolicies",
        "source": "GET /apis and GET /version", "collection_status": collection["status"],
        "semantics": "Legacy PSP resource applicability only; no secure admission or enforcement conclusion."}


AGGREGATED_STATUSES = ("NOT_APPLICABLE", "EMPTY")
AGGREGATE_SCOPE_CAP = 500
AGGREGATE_SAMPLE = 5


class _FindingAggregator:
    """Per-check counts for NOT_APPLICABLE / EMPTY rows (they carry no security conclusion per resource)."""

    def __init__(self, enabled):
        self.enabled, self.rows = enabled, {}

    def __call__(self, findings):
        if not self.enabled:
            return findings
        kept = []
        for finding in findings:
            if finding["status"] not in AGGREGATED_STATUSES:
                kept.append(finding)
                continue
            key = (finding["category"], finding["check_id"], finding["status"])
            row = self.rows.get(key)
            if row is None:
                row = self.rows[key] = {"category": finding["category"], "check_id": finding["check_id"], "title": finding.get("title"),
                    "provider": finding["provider"], "service": finding.get("service"), "severity": finding.get("severity"),
                    "status": finding["status"], "frameworks": list(finding.get("frameworks", [])), "count": 0, "scopes": {},
                    "sample_resource_ids": []}
            row["count"] += 1
            # A cross-scope inventory row (see _dedupe_cross_scope) still reports every scope it covers.
            merged_scopes = finding["evidence"].get("scopes") if str(finding.get("resource_id", "")).startswith("inventory:") and isinstance(finding.get("evidence"), dict) else None
            for scope in merged_scopes if isinstance(merged_scopes, list) else [finding.get("scope", "unknown")]:
                if scope in row["scopes"] or len(row["scopes"]) < AGGREGATE_SCOPE_CAP:
                    row["scopes"][scope] = row["scopes"].get(scope, 0) + 1
                else:
                    row["scopes_truncated"] = True
            if len(row["sample_resource_ids"]) < AGGREGATE_SAMPLE:
                row["sample_resource_ids"].append(finding["resource_id"])
        return kept

    def result(self):
        return [self.rows[key] for key in sorted(self.rows)]


def _arn_region(arn):
    parts = arn.split(":", 5)
    return parts[3] if len(parts) > 3 else ""


def _common_scope(provider, scopes):
    if len(scopes) == 1:
        return scopes[0]
    import re
    accounts = {scope.split("/", 1)[0] for scope in scopes}
    if provider == "aws" and len(accounts) == 1 and re.fullmatch(r"[0-9]{12}", next(iter(accounts))):
        return next(iter(accounts))
    return "selected_scopes"


def _dedupe_cross_scope(findings, native_ids, provider):
    """One finding per (check, global resource) and per (provider, check) EMPTY inventory row.

    A resource whose native id is an ARN is globally unique; when several regional collections return
    it (e.g. a multi-region CloudTrail trail listed by every region) and every copy reached the same
    status, a single finding is kept (the home-region copy when the ARN names a region) with the
    scopes listed in evidence. The home-region copy is also kept alone when every other copy is
    NOT_APPLICABLE (a home-region-only predicate evaluated on shadow copies). Other status differences
    stay separate, and resources without an ARN (per-region settings such as EBS default encryption or
    registry scanning) are never merged. Inventory rows of one check (EMPTY, or UNKNOWN when the
    collection was not collected) with the same status and evidence collapse to one row whose evidence
    lists every scope; coverage stays per scope."""
    groups = defaultdict(list)
    for position, finding in enumerate(findings):
        native = native_ids.get(finding["resource_id"])
        if isinstance(native, str) and native.startswith("arn:"):
            groups[("arn", native)].append(position)
        elif finding["resource_id"].startswith("inventory:") and finding["status"] in ("EMPTY", "UNKNOWN"):
            shape = json.dumps(finding.get("evidence"), sort_keys=True, default=str)
            groups[("inventory", (finding["resource_id"], finding["status"], shape))].append(position)
    replaced, dropped = {}, set()
    for (kind, key), members in groups.items():
        if len(members) < 2:
            continue
        rows = [findings[position] for position in members]
        scopes = list(dict.fromkeys(row["scope"] for row in rows))
        if kind == "arn":
            region = _arn_region(key)
            home = [row for row in rows if region and row["scope"].rsplit("/", 1)[-1] == region]
            if len({row["status"] for row in rows}) == 1:
                note = "Same ARN returned by several scoped collections; reported once."
            elif len(home) == 1 and all(row["status"] == "NOT_APPLICABLE" for row in rows if row is not home[0]):
                note = "Same ARN returned by several scoped collections; the home-region result is reported and NOT_APPLICABLE shadow copies are folded."
            else:
                continue
            primary = home[0] if home else rows[0]
            merged = dict(primary, evidence=dict(primary["evidence"], observed_in_scopes=scopes, deduplication=note))
        else:
            first = rows[0]
            scope = _common_scope(provider, scopes)
            merged = dict(first, id=digest([provider, scope, first["resource_id"], first["check_id"]]), scope=scope,
                evidence=dict(first["evidence"], scopes=scopes, scope_count=len(scopes)))
        replaced[members[0]] = merged
        dropped.update(members[1:])
    if not replaced:
        return findings
    return [replaced.get(position, finding) for position, finding in enumerate(findings) if position not in dropped]


def _scope_check_scopes(snapshot, check):
    """Explicit tenant questions run once on their verified native tenant capture."""
    import re
    selected = snapshot["scopes"] or ["unknown"]
    callback, seen, tenant_question, account_question = check.evaluate, set(), False, False
    tenant_anchor_kind = check.kind
    for _ in range(8):
        if callback is None or id(callback) in seen:
            break
        seen.add(id(callback))
        if getattr(callback, "evaluation_scope", None) == "aws_account":
            account_question = True
            break
        if getattr(callback, "evaluation_scope", None) == "tenant":
            tenant_question = True
            tenant_anchor_kind = getattr(callback, "evaluation_scope_kind", check.kind)
            break
        callback = getattr(callback, "__wrapped__", None)
    if snapshot.get("provider") == "aws" and account_question:
        accounts = sorted({scope.split("/", 1)[0] for scope in selected
            if isinstance(scope, str) and re.fullmatch(r"[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)", scope)})
        return [account + "/global" for account in accounts] or selected
    if snapshot.get("provider") != "azure" or not tenant_question:
        return selected
    metadata = snapshot.get("metadata", {})
    tenant = metadata.get("tenant_id")
    if (metadata.get("tenant_verified") is not True or not isinstance(tenant, str)
            or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", tenant, re.I)):
        return selected
    bindings = metadata.get("subscription_tenants", {})
    if not isinstance(bindings, dict) or not any(isinstance(bound, str) and bound.casefold() == tenant.casefold()
            and scope.casefold() in {str(s).casefold() for s in selected}
            for scope, bound in bindings.items() if isinstance(scope, str)):
        return selected
    tenant_scope = "/tenants/" + tenant.casefold()
    for collection in snapshot["collections"]:
        if collection.get("type") != tenant_anchor_kind or str(collection.get("scope", "")).casefold() != tenant_scope:
            continue
        proof = collection.get("_provenance", {})
        if (isinstance(proof, dict) and proof.get("tenant_verified") is True and proof.get("read_only") is True
                and isinstance(proof.get("tenant_id"), str) and proof["tenant_id"].casefold() == tenant.casefold()
                and all(isinstance(metadata.get(field), str) and metadata[field]
                        and proof.get(field) == metadata[field] for field in ("credential_context_id", "customer_context_id"))):
            return [tenant_scope]
    return selected


def _azure_tenant_group_collection_authorized(scope, metadata, collection):
    """Expose only this scan's exact tenant-child native group inventory."""
    import re
    guid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    if (collection.get("type") != "conditional_access_group_membership"
            or collection.get("service") != "Microsoft.Graph"
            or not isinstance(scope, str) or not re.fullmatch("/tenants/" + guid, scope, re.I)
            or not isinstance(metadata, dict) or metadata.get("tenant_verified") is not True):
        return False
    tenant = scope.removeprefix("/tenants/").casefold()
    if (str(metadata.get("tenant_id", "")).casefold() != tenant
            or not re.fullmatch(re.escape(scope) + "/groups/" + guid,
                                str(collection.get("scope", "")), re.I)):
        return False
    expected = {key: metadata.get(key) for key in ("credential_context_id", "customer_context_id")}
    if any(not isinstance(value, str) or not value for value in expected.values()):
        return False
    def bound(proof, *, item=False):
        return (isinstance(proof, dict) and proof.get("tenant_verified") is True
                and str(proof.get("tenant_id", "")).casefold() == tenant
                and all(proof.get(key) == value for key, value in expected.items())
                and (not item or proof.get("read_only") is True))
    rows = collection.get("items")
    return (bound(collection.get("_provenance")) and isinstance(rows, list)
            and all(isinstance(row, dict) and bound(row.get("_provenance"), item=True) for row in rows))


def evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None, timings=None, include_not_applicable=True,
                      related_snapshots=None):
    """timings: optional dict that receives wall-clock timings; they never enter the deterministic report.

    related_snapshots: other-provider snapshots of the same scan group (e.g. the GCP project of a GKE
    cluster scan). They are read only and only joined by the privesc evaluator (K8s cloud identities,
    GKE/EKS cluster techniques); findings, coverage and every other category stay about `snapshot`.

    include_not_applicable=False keeps NOT_APPLICABLE / EMPTY results out of findings and reports them as
    per-check counts in finding_aggregates (stats.by_status still counts every result). Scan entry points
    (CLI, run_scan, the worker) default to False; this library default stays True for compatibility."""
    from .checks.facts import MemoIndex
    collapse = _FindingAggregator(not include_not_applicable)
    emit_progress(phase="evaluating", provider=snapshot.get("provider") if isinstance(snapshot, dict) else None,
                  completed=0, total=None, dynamic_total=True)
    snapshot = validate(snapshot, read_only=True)
    provider = snapshot["provider"]
    related = _related_snapshots(snapshot, related_snapshots)
    selected_categories, selected = _selection(provider, categories, checks, frameworks)
    inventory = resources(snapshot)
    index = _index(snapshot, inventory)
    coverage, findings = [], []
    for collection in snapshot["collections"]:
        retirement = _retired_collection_evidence(provider, snapshot, collection)
        psp_absence = _psp_resource_absence_evidence(provider, snapshot, collection)
        coverage_status = "unknown" if retirement and retirement[0] == "unknown" else "not_applicable" if psp_absence else collection["status"]
        coverage.append({"level": "collection", "type": collection["type"], "scope": collection["scope"],
            "service": collection.get("service", collection["type"]), "status": coverage_status,
            "resource_count": len(collection["items"]), "reason": retirement[1]["reason"] if retirement else psp_absence["reason"] if psp_absence else
                _unknown_coverage_reason(collection_status=collection["status"])
                if collection["status"] not in ("collected", "empty") else ""})
        code = "retired_service" if retirement else "pod_security_policy_api_absent" if psp_absence else _safe_collection_error_code(collection)
        if code is not None:
            coverage[-1]["error_code"] = code
    scoped_indexes = {}
    native_ids = {resource["id"]: resource["native_id"] for resource in inventory}
    by_scope = defaultdict(list)
    for resource in inventory:
        by_scope[(resource["type"], resource["scope"])].append(resource)
    def scoped_index(scope):
        if scope not in scoped_indexes:
            import re
            azure_sql_scopes = set()
            if provider == 'azure' and scope.lower().startswith('/subscriptions/'):
                from .collectors.azure_sql_inventory import authorized_database_scopes
                azure_sql_scopes = authorized_database_scopes(snapshot, scope)
            account = scope.split("/", 1)[0] if provider == "aws" else None
            if not account or not re.fullmatch(r"[0-9]{12}", account):
                account = None
            def relevant(collection):
                if (provider == 'azure' and collection.get('service') == 'Microsoft.Graph'
                        and scope.lower().startswith('/subscriptions/')):
                    from .checks.facts import azure_directory_join_authorized
                    return azure_directory_join_authorized(scope, snapshot.get('metadata', {}), collection)
                if (provider == "azure" and _azure_tenant_group_collection_authorized(
                        scope, snapshot.get("metadata", {}), collection)):
                    return True
                if collection["scope"] == scope:
                    return True
                if (provider == 'azure' and collection['type'] == 'sql_database'
                        and collection['scope'] in azure_sql_scopes):
                    return True
                return bool(account and collection.get("global") is True and collection.get("account_id") == account
                    and collection["scope"].split("/", 1)[0] == account
                    and all(item.get("AccountId") == account for item in collection["items"]))
            selected_collections = [c for c in snapshot["collections"] if relevant(c)]
            resource_scopes = {(c["type"], c["scope"]) for c in selected_collections}
            # MemoIndex: joins that checks derive from this read-only index are computed once per scope.
            scoped_indexes[scope] = MemoIndex({kind: [r for r in rows if (r["type"], r["scope"]) in resource_scopes] for kind, rows in index.items() if kind != "collections"})
            scoped_indexes[scope]["collections"] = {kind: [c for c in rows if relevant(c)] for kind, rows in index["collections"].items()}
            context = {"provider": provider, "scope": scope, "_scope": scope, "created_at": snapshot["created_at"],
                "snapshot_id": snapshot["snapshot_id"], "metadata": snapshot.get("metadata", {})}
            if account:
                context["Account"] = account
            # One read-only view per scope, shared by every scoped check (no per-check deep copy).
            context = freeze(context)
            scoped_indexes[scope]["context"] = context
            scoped_indexes[scope]["_snapshot"] = context
        return scoped_indexes[scope]

    for settled_checks, check in enumerate(selected):
        emit_progress(phase="evaluating", provider=provider, completed=settled_checks,
                      total=len(selected), resources=len(inventory), dynamic_total=False)
        check_frameworks = list(check.frameworks)
        if getattr(check, "target", "resource") == "scope":
            for scope in _scope_check_scopes(snapshot, check):
                scoped = scoped_index(scope)
                incomplete = [{"type": kind, "status": "not_collected"} for kind in check.dependencies if not scoped["collections"].get(kind)]
                incomplete += [{"type": kind, "status": c["status"]} for kind in check.dependencies for c in scoped["collections"].get(kind, []) if c["status"] not in ("collected", "empty")]
                if incomplete:
                    status, evidence = "DENIED" if any(row["status"] == "denied" for row in incomplete) else "UNKNOWN", {"reason": "required scoped inventory incomplete", "dependencies": incomplete, "target": "scope"}
                    empty_dependencies = getattr(check, "empty_applicability_dependencies", ())
                    empty_applicable = bool(empty_dependencies) and set(empty_dependencies) <= set(check.dependencies) and all(
                        scoped["collections"].get(kind) and all(
                            collection["status"] == "empty" and collection["items"] == []
                            for collection in scoped["collections"][kind])
                        for kind in empty_dependencies)
                    if getattr(check, "allow_incomplete_failure", False) or empty_applicable:
                        # A conclusive violation or an explicitly empty target
                        # inventory may resolve the check. Their independent
                        # opt-ins can never produce PASS from incomplete data.
                        try:
                            observed_status, observed_evidence = check.evaluate(scoped["context"], scoped)
                            if (observed_status == "FAIL" and getattr(check, "allow_incomplete_failure", False)
                                    and isinstance(observed_evidence, dict)):
                                status = "FAIL"
                                evidence = {**observed_evidence, "incomplete_dependencies": incomplete}
                            elif observed_status == "NOT_APPLICABLE" and empty_applicable and isinstance(observed_evidence, dict):
                                status = "NOT_APPLICABLE"
                                evidence = {**observed_evidence, "incomplete_dependencies": incomplete,
                                            "empty_applicability_dependencies": list(empty_dependencies)}
                        except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError):
                            pass
                else:
                    try:
                        status, evidence = check.evaluate(scoped["context"], scoped)
                        if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                            raise ValueError("invalid scoped check result")
                    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                        status, evidence = "UNKNOWN", {"reason": "missing or malformed scoped facts", "error_kind": type(exc).__name__}
                findings.extend(collapse([_finding(check, provider, scope, "scope:" + scope, check.kind, status, evidence, check_frameworks)]))
                coverage.append({"level": "check", "check_id": check.id, "type": check.kind, "scope": scope,
                    "target": "scope", "status": "unknown" if status in ("UNKNOWN", "DENIED") else "manual" if status == "MANUAL" else "evaluated",
                    "by_status": {status: 1}, "reason": _unknown_coverage_reason([{"status": status, "evidence": evidence}])
                    if status in ("UNKNOWN", "DENIED") else "Scoped presence/aggregate evaluation over collected facts."})
            continue
        check_findings = []
        collections = index["collections"].get(check.kind, [])
        # Global inventories may use native account/global scope; their explicit envelope is authoritative.
        if not collections:
            collections = [{"type": check.kind, "scope": scope, "service": check.kind, "status": "not_collected", "items": []} for scope in snapshot["scopes"] or ["unknown"]]
        for collection in collections:
            scope, collection_status = collection["scope"], collection["status"]
            retirement = _retired_collection_evidence(provider, snapshot, collection)
            psp_absence = (_psp_resource_absence_evidence(provider, snapshot, collection)
                if check.id in _PSP_RESOURCE_CHECK_IDS and check.kind == "podsecuritypolicy"
                and getattr(check, "target", "resource") == "resource" else None)
            scope_findings = []
            for resource in by_scope.get((check.kind, scope), []):
                # The rule index is scoped; foreign subscriptions/namespaces cannot satisfy a check.
                scoped = scoped_index(scope)
                try:
                    # Sealed native data is a read-only view: checks share it instead of deep-copying it.
                    status, evidence = check.evaluate(resource["data"], scoped)
                    if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "EMPTY", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                        raise ValueError("invalid check result")
                except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                    status, evidence = "UNKNOWN", {"reason": "missing or malformed provider facts", "error_kind": type(exc).__name__}
                scope_findings.append(_finding(check, provider, scope, resource["id"], resource["service"], status, evidence, check_frameworks))
            unavailable = (collection_status not in ("collected", "empty") and not psp_absence) or bool(retirement and retirement[0] == "unknown")
            empty_evaluated = False
            if (not retirement and not scope_findings and collection_status == "empty"
                    and collection.get("type") == check.kind and collection.get("scope") == scope
                    and collection.get("items") == []):
                # Private opt-in for controls whose scoped decision is meaningful
                # without a primary resource. No incomplete collection can enter.
                callback, visited, empty_callback = check.evaluate, set(), None
                for _ in range(8):
                    if callback is None or id(callback) in visited:
                        break
                    visited.add(id(callback))
                    candidate = getattr(callback, "evaluate_empty_inventory", None)
                    if callable(candidate):
                        empty_callback = candidate
                        break
                    callback = getattr(callback, "__wrapped__", None)
                if empty_callback is not None:
                    try:
                        if sum(c.get("scope") == scope for c in collections) != 1:
                            raise ValueError("ambiguous empty primary inventory")
                        outcome = empty_callback(scoped_index(scope)["context"], freeze(collection))
                        if outcome is not None:
                            status, evidence = outcome
                            if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                                raise ValueError("invalid empty inventory decision")
                            evidence = {**evidence, "evaluation_target": "scope", "empty_primary_inventory": check.kind}
                            empty_evaluated = True
                    except Exception as exc:
                        status, evidence = "UNKNOWN", {"reason": "empty inventory decision unavailable",
                            "error_kind": type(exc).__name__, "evaluation_target": "scope", "empty_primary_inventory": check.kind}
                        empty_evaluated = True
                    if empty_evaluated:
                        scope_findings.append(_finding(check, provider, scope, "scope:" + scope,
                            collection.get("service", check.kind), status, evidence, check_frameworks))
            if unavailable or not scope_findings:
                status = "UNKNOWN" if retirement and retirement[0] == "unknown" else "NOT_APPLICABLE" if retirement or psp_absence else "DENIED" if collection_status == "denied" else "EMPTY" if collection_status == "empty" else "UNKNOWN"
                scope_findings.append(_finding(check, provider, scope, "inventory:" + check.kind, collection.get("service", check.kind), status,
                    retirement[1] if retirement else psp_absence if psp_absence else {"collection_status": collection_status, "reason": collection.get("error", {}).get("code", "no collected resources"),
                     "semantics": "Inventory coverage, not a resource security pass."}, check_frameworks))
            check_findings.extend(scope_findings)
            counts = dict(Counter(f["status"] for f in scope_findings))
            check_status = "partial" if unavailable and collection_status == "partial" else "denied" if collection_status == "denied" else "unknown" if unavailable or counts.get("UNKNOWN") or counts.get("DENIED") else "empty" if collection_status == "empty" else "manual" if counts.get("MANUAL") else "evaluated"
            if empty_evaluated:
                check_status = "unknown" if counts.get("UNKNOWN") or counts.get("DENIED") else "manual" if counts.get("MANUAL") else "evaluated"
            coverage.append({"level": "check", "check_id": check.id, "type": check.kind, "scope": scope,
                **({"target": "scope"} if empty_evaluated else {}),
                "status": check_status, "by_status": counts, "reason": _unknown_coverage_reason(scope_findings, collection_status=collection_status)
                if check_status in ("unknown", "denied", "partial") and not retirement and not psp_absence else retirement[1]["reason"] if retirement else psp_absence["reason"] if psp_absence else ""})
        findings.extend(collapse(_dedupe_cross_scope(check_findings, native_ids, provider)))
    emit_progress(phase="evaluating", provider=provider, completed=len(selected), total=len(selected),
                  resources=len(inventory), dynamic_total=False)
    # Native predicate count is known, but graph/manual/post-processing work
    # does not have the same unit. Do not estimate the remainder from that count.
    emit_progress(phase="evaluating", provider=provider, completed=len(selected), total=None,
                  resources=len(inventory), dynamic_total=True)
    from .analysis import analysis_context
    from scripts.cloud_permission_risks import offline_rules
    with offline_rules(), analysis_context(snapshot):
        analysis_selected = _analysis_selection(provider, selected_categories, checks, frameworks)
        if analysis_selected:
            from .analysis import analyze_findings
            expected_ids = {c["id"] for c in analysis_selected}
            analyzed = [f for f in analyze_findings(snapshot, inventory, index) if f["check_id"] in expected_ids and f["category"] in selected_categories]
            # Group once (order kept) instead of rescanning every analyzed finding per analysis check.
            analyzed_by_check = defaultdict(list)
            for f in analyzed:
                analyzed_by_check[f["check_id"]].append(f)
            findings.extend(collapse(analyzed))
            for check in analysis_selected:
                own = analyzed_by_check.get(check["id"], [])
                by_status = dict(Counter(f["status"] for f in own))
                coverage.append({"level": "check", "check_id": check["id"], "type": "projection", "scope": "selected_scopes",
                    "status": "unknown" if by_status.get("UNKNOWN") else "manual" if by_status.get("MANUAL") else "evaluated",
                    "by_status": by_status, "reason": _unknown_coverage_reason(own)
                    if by_status.get("UNKNOWN") else "Defensive review signals; no finding is not an effective-access pass."})
        graphs = {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [], "edges": []}}
        graph_categories = _selected_graph_categories(selected_categories, selected, analysis_selected,
            categories, checks, frameworks)
        if graph_categories:
            from .analysis import build_graphs
            # The report keeps the complete (uncollapsed) graph; bounded views are server-side projections.
            built = build_graphs(snapshot, inventory, index, max_nodes=None, collapse_unreferenced=not include_not_applicable)
            for graph, category in (("network", "network"), ("iam", "iam_graph")):
                if category in graph_categories:
                    graphs[graph] = built[graph]
            if not include_not_applicable:  # unassigned role definitions -> per-scope aggregates with member refs
                from .analysis import collapse_unreferenced_definitions
                graphs["iam"] = collapse_unreferenced_definitions(graphs["iam"])
    privesc_stats = None
    graphs.setdefault("privesc", {"nodes": [], "edges": []})
    privesc_filter = _privesc_selected(provider, selected_categories, checks, frameworks)
    if privesc_filter is not None:
        privesc_findings, privesc_coverage, graphs["privesc"], privesc_stats, privesc_timing = _run_privesc(snapshot, privesc_filter, related)
        if timings is not None:
            timings["privesc"] = privesc_timing
        findings.extend(collapse(privesc_findings))
        coverage.extend(privesc_coverage)
    from .checks.catalog import framework_display_names
    display_names = framework_display_names()
    # Attestation questions are source references, not provider-API checks.
    # Historic reports retain their original manual findings unchanged.
    selected_manual = []
    resource_lookup = {resource["id"]: resource for resource in inventory}
    for finding in findings:
        resource = resource_lookup.get(finding["resource_id"])
        if resource is None:
            continue
        data = resource["data"]
        name = data.get("UserName") or data.get("RoleName") or data.get("name") or data.get("Name") or (data.get("metadata", {}).get("name") if isinstance(data.get("metadata", {}), dict) else None)
        tags = data.get("Tags", [])
        if not name and isinstance(tags, list):
            name = next((tag.get("Value") for tag in tags if isinstance(tag, dict) and tag.get("Key") == "Name" and isinstance(tag.get("Value"), str)), None)
        finding["native_resource_id"] = resource["native_id"]
        finding["resource_name"] = name if isinstance(name, str) else resource["native_id"]
    selected_framework_versions = []
    from .checks.catalog import _framework_rows
    from .checks.native_only import automated_frameworks
    if frameworks:
        # Only explicitly requested versions (id or canonical name); a family label selects checks, not checklists.
        requested_frameworks = {FRAMEWORK_ALIASES.get(value, value) for value in frameworks}
        selected_framework_versions = [copy.deepcopy(row) for row in _framework_rows() if (row["id"] in requested_frameworks or display_names.get(row["id"]) in requested_frameworks) and row["provider"] in (provider, "all")]
        selected_native_ids = {c.id for c in selected}
        for row in selected_framework_versions:
            covered_ids = selected_native_ids.intersection(row["native_check_ids"])
            coverage.append({"level": "framework", "framework_id": row["id"], "framework_name": row["name"],
                "scope": "selected_scopes", "status": "unknown" if not covered_ids else "partial" if row["pending_source_checks"] else "evaluated",
                "selected_native_checks": len(covered_ids), "source_checks": row["source_checks"], "pending_source_checks": row["pending_source_checks"],
                "reason": "Pending upstream definitions are unimplemented; selected native predicates do not establish complete checklist coverage."})
    else:
        # Unfiltered run: every provider checklist version that has selected native checks or findings.
        selected_native_ids = {c.id for c in selected}
        labelled = {label for finding in findings for label in finding.get("frameworks", ())}
        labelled.update(label for row in collapse.rows.values() for label in row.get("frameworks", ()))
        selected_framework_versions = [copy.deepcopy(row) for row in _framework_rows() if row["provider"] in (provider, "all")
            and (selected_native_ids.intersection(row["native_check_ids"]) or display_names.get(row["id"]) in labelled)]
    scope_coverage = snapshot.get("metadata", {}).get("scope_coverage", {})
    if snapshot.get("metadata", {}).get("intentional_partial") is True or (isinstance(scope_coverage, dict) and scope_coverage.get("status") not in (None, "collected", "complete")):
        coverage.append({"level": "scope", "scope": "requested_scopes", "status": "partial" if snapshot.get("metadata", {}).get("intentional_partial") else "unknown",
            "reason": scope_coverage.get("reason", "Explicit scope limit or incomplete discovery") if isinstance(scope_coverage, dict) else "Malformed scope coverage metadata"})
    findings = normalize_unknown_reasons(findings)
    selected_framework_versions = automated_frameworks(selected_framework_versions)
    counts = Counter(f["status"] for f in findings)
    aggregates = collapse.result()
    for row in aggregates:
        counts[row["status"]] += row["count"]
    counts = dict(counts)
    complete = bool(selected or analysis_selected or privesc_stats is not None) and all(c["status"] in ("empty", "evaluated") for c in coverage if c["level"] in ("check", "framework", "manual", "scope"))
    inventory_complete = all(c["status"] in ("collected", "empty") for c in coverage if c["level"] in ("collection", "scope"))
    from .finding_priority import VERSION as risk_model_version
    report = {"schema_version": REPORT_SCHEMA_VERSION, "risk_model_version": risk_model_version, "snapshot_id": snapshot["snapshot_id"], "provider": provider,
        "scopes": list(snapshot["scopes"]), "created_at": snapshot["created_at"],
        "resources": [{key: value for key, value in resource.items() if key != "data"} for resource in inventory],
        "native_data": dict(NATIVE_DATA, snapshot_id=snapshot["snapshot_id"]),
        "findings": sorted(findings, key=lambda f: (f["category"], f["check_id"], f["scope"], f["resource_id"])),
        "coverage": sorted(coverage, key=lambda row: (row["level"], row.get("check_id", ""), row.get("framework_id", ""), row.get("type", ""), row.get("scope", ""))), "framework_versions": selected_framework_versions, "snapshot_metadata": copy.deepcopy(snapshot.get("metadata", {})), "manual_requirements": selected_manual, "graphs": graphs, "stats": {"resource_count": len(inventory), "finding_count": len(findings),
            "check_count": len(selected) + len(analysis_selected), "manual_requirement_count": len(selected_manual), "by_status": counts, "by_severity": dict(Counter(f["severity"] for f in findings if f["status"] == "FAIL")),
            "coverage_complete": complete, "inventory_complete": inventory_complete, "categories": selected_categories,
            "limitations": ["Framework mappings retain reviewed source provenance; they are not compliance certification.", "Declared IAM relationships are not effective access.",
                "Network inventory relationships are not proven reachability.", "Upstream hardening catalogs have not all been ported; only selected native checks ran."]}}
    if collapse.enabled:
        # NOT_APPLICABLE / EMPTY results are per-check counts, not rows; stats.by_status still counts them.
        report["finding_aggregates"] = aggregates
        report["stats"]["aggregated_finding_count"] = sum(row["count"] for row in aggregates)
        report["stats"]["aggregated_statuses"] = list(AGGREGATED_STATUSES)
    if privesc_stats is not None:
        from .privesc.versioned_catalog import current_binding
        report["privesc_catalog"] = current_binding()
        report["stats"]["privesc"] = privesc_stats
        report["stats"]["check_count"] += 1
        report["stats"]["limitations"].append("Privilege-escalation paths are derived offline from collected policies and the technique catalog; they are not exploited or proven.")
    if related:
        # Provenance of the joined snapshots (the report stays reproducible from them plus `snapshot`).
        report["related_snapshots"] = [{"snapshot_id": r["snapshot_id"], "provider": r["provider"], "scopes": list(r["scopes"]),
                                        "created_at": r["created_at"]} for r in related]
    from .remediation import report_templates
    report["remediation_templates"] = report_templates((f["check_id"] for f in report["findings"]), provider)
    for finding in report["findings"]:
        detail = report["remediation_templates"].get(finding["check_id"])
        if detail and finding["check_id"] != "analysis.internet_exposure":
            finding["remediation"] = detail["summary"]
    report["check_frameworks"] = factor_frameworks(report["findings"])
    report["check_meta"] = encode_check_meta(
        attach_reviewed_description_meta(factor_check_meta(report["findings"])),
        report["remediation_templates"])
    report["check_meta_encoding"] = dict(CHECK_META_ENCODING)
    return report


def _related_snapshots(snapshot, related_snapshots):
    """Validated related snapshots: other providers only, the primary and duplicates dropped, stable order."""
    out, seen = [], {snapshot["snapshot_id"]}
    for candidate in related_snapshots or ():
        candidate = validate(candidate, read_only=True)
        if candidate["snapshot_id"] in seen or candidate["provider"] == snapshot["provider"]:
            continue
        seen.add(candidate["snapshot_id"])
        out.append(candidate)
    return sorted(out, key=lambda r: (r["provider"], r["snapshot_id"]))


def factor_frameworks(findings):
    """Move per-finding framework labels to one list per check (schema 1.1 check_frameworks).

    A check's default is the label list most of its findings carry (ties: the lexically smallest);
    those findings drop "frameworks", and any finding whose labels differ (e.g. a manual requirement)
    keeps its own explicit list. Findings are modified in place; hydrate_frameworks reverses it."""
    tallies = defaultdict(Counter)
    for finding in findings:
        if isinstance(finding.get("frameworks"), list):
            tallies[finding["check_id"]][tuple(finding["frameworks"])] += 1
    defaults = {check_id: min(tally.items(), key=lambda item: (-item[1], item[0]))[0] for check_id, tally in tallies.items()}
    for finding in findings:
        if isinstance(finding.get("frameworks"), list) and tuple(finding["frameworks"]) == defaults.get(finding["check_id"]):
            del finding["frameworks"]
    return {check_id: list(labels) for check_id, labels in sorted(defaults.items())}


def finding_frameworks(finding, check_frameworks):
    """The labels of one finding: its explicit list, else its check's default list."""
    if "frameworks" in finding:
        return list(finding["frameworks"])
    return list((check_frameworks or {}).get(finding.get("check_id"), []))


CHECK_META_FIELDS = ("title", "remediation", "service", "category", "severity",
                     "description", "evaluated", "pass_when", "fail_when", "not_applicable_when", "rationale", "clarity_evaluation_contract")
CHECK_META_ENCODING = {"version": 1, "per_check_marker": "_derived",
                       "r": "description", "m": "remediation_templates.summary"}


def attach_reviewed_description_meta(meta):
    """Keep verified check prose once per check, without copying it into every finding row."""
    from .checks.catalog import description_for
    from .finding_presentation import evaluator_contract_fingerprint
    for check_id, values in meta.items():
        reviewed = description_for(check_id)
        if not isinstance(reviewed, dict):
            continue
        values["clarity_evaluation_contract"] = evaluator_contract_fingerprint()
        for field in ("description", "evaluated", "pass_when", "fail_when", "not_applicable_when"):
            value = reviewed.get(field)
            if isinstance(value, str) and value.strip():
                values[field] = value
            elif field == "evaluated" and isinstance(value, list) and value and all(isinstance(item, str) and item.strip() for item in value):
                values[field] = list(value)
        if "description" in values:
            values["rationale"] = values["description"]
    return meta


def encode_check_meta(meta, remediation_templates):
    """Keep identical archived prose once and mark exactly which defaults were removed."""
    encoded = {}
    templates = remediation_templates if isinstance(remediation_templates, dict) else {}
    for check_id, values in meta.items():
        fields = dict(values)
        flags = ""
        if isinstance(fields.get("description"), str) and fields.get("rationale") == fields["description"]:
            del fields["rationale"]
            flags += "r"
        template = templates.get(check_id)
        summary = template.get("summary") if isinstance(template, dict) else None
        if isinstance(summary, str) and fields.get("remediation") == summary:
            del fields["remediation"]
            flags += "m"
        if flags:
            fields["_derived"] = flags
        encoded[check_id] = fields
    return encoded


def factor_check_meta(findings):
    """Move per-check finding fields (CHECK_META_FIELDS) to one value per check (schema 1.1 check_meta).

    Per field and check, the default is the most common string value (ties: the lexically smallest);
    findings carrying it drop the field, and findings whose value differs (e.g. a check that picks
    severity per resource) keep it. A field is factored only when every finding of the check carries
    it, so hydration never adds a field a finding did not have. Findings are modified in place."""
    tallies = defaultdict(lambda: defaultdict(Counter))
    totals, present = Counter(), Counter()
    for finding in findings:
        totals[finding["check_id"]] += 1
        for field in CHECK_META_FIELDS:
            if field in finding:
                present[finding["check_id"], field] += 1
                value = finding[field]
                if isinstance(value, str):
                    tallies[finding["check_id"]][field][value] += 1
                elif field == "evaluated" and isinstance(value, list) and all(isinstance(item, str) for item in value):
                    tallies[finding["check_id"]][field][tuple(value)] += 1
    meta = {}
    for check_id, fields in tallies.items():
        defaults = {}
        for field, tally in fields.items():
            if present[check_id, field] == totals[check_id]:
                chosen = min(tally.items(), key=lambda item: (-item[1], item[0]))[0]
                defaults[field] = list(chosen) if field == "evaluated" and isinstance(chosen, tuple) else chosen
        if defaults:
            meta[check_id] = defaults
    for finding in findings:
        for field, value in meta.get(finding["check_id"], {}).items():
            if finding[field] == value:
                del finding[field]
        # Deletion leaves the original large hash table allocated. Rebuild only
        # its storage while retaining this finding's identity, order and values.
        compact = {key: value for key, value in finding.items()}
        finding.clear()
        finding.update(compact)
    return {check_id: meta[check_id] for check_id in sorted(meta)}


def hydrate_finding(finding, check_frameworks=None, check_meta=None, check_meta_encoding=None,
                    remediation_templates=None):
    """One finding with its per-check defaults (frameworks and CHECK_META_FIELDS) restored; not modified in place."""
    defaults = (check_meta or {}).get(finding.get("check_id")) or {}
    encoded = check_meta_encoding == CHECK_META_ENCODING
    flags = defaults.get("_derived", "") if encoded else ""
    if not isinstance(flags, str) or flags not in {"r", "m", "rm"}:
        flags = ""
    missing = {field: value for field, value in defaults.items()
               if field not in finding and (field != "_derived" or not encoded)}
    if "r" in flags and "rationale" not in finding and "rationale" not in defaults:
        description = defaults.get("description")
        if isinstance(description, str):
            missing["rationale"] = description
    if "m" in flags and "remediation" not in finding and "remediation" not in defaults:
        templates = remediation_templates if isinstance(remediation_templates, dict) else {}
        template = templates.get(finding.get("check_id"))
        summary = template.get("summary") if isinstance(template, dict) else None
        if isinstance(summary, str):
            missing["remediation"] = summary
    if check_frameworks is not None and "frameworks" not in finding:
        missing["frameworks"] = list(check_frameworks.get(finding.get("check_id"), []))
    hydrated = dict(finding, **missing) if missing else finding
    if finding.get("check_id") == "analysis.internet_exposure":
        from .remediation import exposure_action
        return dict(hydrated, remediation=exposure_action(finding.get("evidence"), finding.get("status")))
    return hydrated


def hydrate_frameworks(report):
    """Per-finding frameworks and per-check fields restored from check_frameworks / check_meta (no snapshot
    needed); the input is not modified. Reports without either map (schema 1.0, or 1.1 written before
    factoring) are returned unchanged."""
    labels = report.get("check_frameworks") if isinstance(report.get("check_frameworks"), dict) else None
    meta = report.get("check_meta") if isinstance(report.get("check_meta"), dict) else None
    if labels is None and meta is None:
        return report
    out = {key: value for key, value in report.items() if key not in ("check_frameworks", "check_meta")}
    out["findings"] = [hydrate_finding(finding, labels, meta, report.get("check_meta_encoding"),
                                       report.get("remediation_templates")) for finding in report.get("findings", [])]
    return out


hydrate_findings = hydrate_frameworks


NATIVE_DATA = {"mode": "snapshot_reference",
    "resources": "resources[].data is omitted; the native item is the snapshot item that resources(snapshot) maps to resources[].id",
    "graph_nodes": "evidence.native_resource_ref is a resources[].id; policy_document evidence.native_document_ref is a path inside the referenced native resource",
    "referenced_grants": "card.referenced_grants[].grant_count is the referenced source_node's card.grant_count (all declared grants); its card.source_grants is a bounded highest-risk sample and the full list is behind card.detail_ref (GET /api/scans/{id}/graphs/iam/grants/{detail_ref.resource_ref}; expand_report inlines it)",
    "frameworks": "findings[].frameworks is omitted when it equals check_frameworks[check_id]; peaso.engine.hydrate_frameworks(report) restores it",
    "check_meta": "Per-check defaults live in check_meta; check_meta_encoding marks rationale equal to stored description and remediation equal to the same report's stored template summary. peaso.engine.hydrate_frameworks(report) restores them without a live catalog lookup",
    "expand": "peaso.engine.expand_report(report, snapshot) restores schema 1.0 with embedded native data"}


def _referenced_full_grants(source_node, inventory, provider, cache):
    """The complete declared grants behind a referenced graph node. Cards keep a bounded sample
    (card.source_grants); the full list is re-derived from the node's native resource, falling back
    to the stored sample only when that resource is not in the snapshot."""
    from .analysis.iam import full_grants
    card = source_node.get("card") or {}
    evidence = source_node.get("evidence") or {}
    ref = evidence.get("native_resource_ref") or (card.get("detail_ref") or {}).get("resource_ref")
    if ref not in inventory:
        return card.get("source_grants", [])
    if ref not in cache:
        try:
            cache[ref] = full_grants(inventory[ref], provider)
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            cache[ref] = card.get("source_grants", [])
    return cache[ref]


def expand_report(report, snapshot=None):
    """Schema 1.1 -> 1.0: inline native data by reference (objects are shared, never copied).
    The input report is not modified; the snapshot comes from the argument or report["snapshot"]."""
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        return report
    snapshot = snapshot if snapshot is not None else report.get("snapshot")
    if snapshot is None:
        raise ValueError("expanding a schema 1.1 report needs its snapshot")
    if snapshot.get("snapshot_id") != report.get("snapshot_id"):
        raise ValueError("snapshot does not match the report snapshot_id")
    from .analysis.iam import policy_documents
    inventory = {resource["id"]: resource for resource in resources(snapshot)}
    by_native = {(r["scope"], r["type"], r["native_id"]): r for r in inventory.values()}
    out = {key: value for key, value in hydrate_frameworks(report).items() if key != "native_data"}
    out["schema_version"] = SCHEMA_VERSION
    out["resources"] = [dict(resource, data=inventory[resource["id"]]["data"]) if resource.get("id") in inventory and "data" not in resource
                        else resource for resource in report.get("resources", [])]
    documents = {}
    full_lists = {}  # resource id -> complete grant list, shared by every node that references it
    graphs = {}
    for name, graph in (report.get("graphs") or {}).items():
        if not isinstance(graph, dict) or not graph.get("nodes"):
            graphs[name] = graph
            continue
        by_id = {n.get("id"): n for n in graph["nodes"]}
        nodes = []
        for current in graph["nodes"]:
            evidence = current.get("evidence")
            card = current.get("card")
            changed = False
            if isinstance(evidence, dict) and "native_resource_ref" in evidence and evidence["native_resource_ref"] in inventory:
                data = inventory[evidence["native_resource_ref"]]["data"]
                evidence = {("native_resource" if k == "native_resource_ref" else k): (data if k == "native_resource_ref" else v) for k, v in evidence.items()}
                changed = True
            if isinstance(evidence, dict) and "native_document_ref" in evidence:
                src = evidence.get("source") or {}
                owner = by_native.get((src.get("scope"), src.get("resource_type"), src.get("resource_id")))
                if owner is not None:
                    if owner["id"] not in documents:
                        documents[owner["id"]] = dict(policy_documents(owner["data"]))
                    doc = documents[owner["id"]].get(evidence["native_document_ref"])
                    if doc is not None:
                        evidence = {("native_document" if k == "native_document_ref" else k): (doc if k == "native_document_ref" else v) for k, v in evidence.items()}
                        changed = True
            if isinstance(card, dict) and card.get("referenced_grants"):
                refs = []
                for ref in card["referenced_grants"]:
                    if isinstance(ref, dict) and "grant_count" in ref and "grants" not in ref:
                        grants = _referenced_full_grants(by_id.get(ref.get("source_node")) or {}, inventory, report.get("provider"), full_lists)
                        ref = {("grants" if k == "grant_count" else k): (grants if k == "grant_count" else v) for k, v in ref.items()}
                    refs.append(ref)
                card = dict(card, referenced_grants=refs)
                changed = True
            if changed:
                current = dict(current, evidence=evidence)
                if card is not None:
                    current["card"] = card
            nodes.append(current)
        graphs[name] = dict(graph, nodes=nodes)
    out["graphs"] = graphs
    return out


def compact_report(report):
    """Schema 1.0 -> 1.1 migration (the inverse of expand_report); the input report is not modified."""
    if report.get("schema_version") == REPORT_SCHEMA_VERSION:
        return report
    findings = [dict(finding) for finding in report.get("findings", [])]
    out = dict(report, schema_version=REPORT_SCHEMA_VERSION,
               resources=[{k: v for k, v in r.items() if k != "data"} for r in report.get("resources", [])],
               native_data=dict(NATIVE_DATA, snapshot_id=report.get("snapshot_id")),
               findings=findings, check_frameworks=factor_frameworks(findings))
    # A historical report without stored templates must not acquire today's
    # remediation text during schema migration.
    out.setdefault("remediation_templates", {})
    out["check_meta"] = encode_check_meta(factor_check_meta(findings), out["remediation_templates"])
    out["check_meta_encoding"] = dict(CHECK_META_ENCODING)
    graphs = {}
    for name, graph in (report.get("graphs") or {}).items():
        if not isinstance(graph, dict) or not graph.get("nodes"):
            graphs[name] = graph
            continue
        nodes = []
        for current in graph["nodes"]:
            evidence, card = current.get("evidence"), current.get("card")
            if isinstance(evidence, dict) and "native_resource" in evidence and current.get("resource_id"):
                evidence = {("native_resource_ref" if k == "native_resource" else k): (current["resource_id"] if k == "native_resource" else v) for k, v in evidence.items()}
            if isinstance(evidence, dict) and "native_document" in evidence and isinstance((evidence.get("source") or {}).get("path"), str):
                evidence = {("native_document_ref" if k == "native_document" else k): (evidence["source"]["path"] if k == "native_document" else v) for k, v in evidence.items()}
            if isinstance(card, dict) and card.get("referenced_grants"):
                card = dict(card, referenced_grants=[{("grant_count" if k == "grants" else k): (len(v) if k == "grants" else v) for k, v in ref.items()}
                                                     if isinstance(ref, dict) else ref for ref in card["referenced_grants"]])
            if evidence is not current.get("evidence") or card is not current.get("card"):
                current = dict(current, evidence=evidence)
                if card is not None:
                    current["card"] = card
            nodes.append(current)
        graphs[name] = dict(graph, nodes=nodes)
    out["graphs"] = graphs
    return out


def _run_privesc(snapshot, technique_filter, related=()):
    """Run the read-only privesc evaluator; an evaluator failure becomes coverage, never a crashed scan."""
    import time
    started = time.perf_counter()
    try:
        from . import privesc
        # Related snapshots join cross-provider paths (contract: docs/peaso-privesc.md "Cross-snapshot analysis").
        # A missing target inventory or unresolved selector is coverage evidence,
        # not an identified principal that can be reached by an escalation path.
        # Keep those diagnostics in coverage without emitting memberless graph nodes.
        extra = {"include_unknown": False}
        if related:
            extra["related_snapshots"] = list(related)
        if technique_filter:
            entries = [e for e in privesc.catalog()["entries"] if e["id"] in technique_filter]
            result = privesc.analyze(snapshot, entries=entries, **extra)
        else:
            result = privesc.analyze(snapshot, **extra)
        findings = [dict(f) for f in result.get("findings", [])]
        coverage = list(result.get("coverage", []))
        graph = result.get("graph") or {"nodes": [], "edges": []}
        stats = dict(result.get("stats", {}))
        # Wall-clock timings are reported out of band so evaluation stays repeatable.
        timing = dict(stats.pop("timing_seconds", None) or {})
    except Exception as exc:  # noqa: BLE001 - the evaluator must not abort the other categories
        elapsed = round(time.perf_counter() - started, 4)
        return [], [{"level": "check", "check_id": PRIVESC_CHECK_ID, "type": "privesc", "scope": "selected_scopes", "status": "unknown",
                     "by_status": {}, "error_kind": type(exc).__name__,
                     "reason": "Privilege-escalation evaluation failed; no privesc result is a pass."}], \
            {"nodes": [], "edges": []}, {"error": type(exc).__name__}, {"engine_seconds": elapsed}
    for finding in findings:
        finding["category"] = "privesc"
        finding.setdefault("frameworks", [PRIVESC_FRAMEWORK])
        if PRIVESC_FRAMEWORK not in finding["frameworks"]:
            finding["frameworks"] = [PRIVESC_FRAMEWORK] + list(finding["frameworks"])
        finding.setdefault("scope", "unknown")
        source = (finding.get("evidence") or {}).get("source") or {}
        finding.setdefault("native_resource_id", finding.get("resource_id"))
        if isinstance(source.get("label"), str):
            finding.setdefault("resource_name", source["label"])
    coverage.append({"level": "check", "check_id": PRIVESC_CHECK_ID, "type": "privesc", "scope": "selected_scopes",
                     "status": "unknown" if any(c.get("status") != "partial" for c in coverage) else "evaluated",
                     "by_status": dict(Counter(f["status"] for f in findings)),
                     "reason": "Catalog-driven privilege-escalation paths; see coverage level privesc."})
    timing["engine_seconds"] = round(time.perf_counter() - started, 4)
    return findings, coverage, graph, stats, timing


def scan(request):
    """Collect and evaluate: (report, snapshot). The report references the snapshot by snapshot_id only.

    request["include_not_applicable"] (default False) keeps per-resource NOT_APPLICABLE / EMPTY rows;
    request["related_snapshots"] (optional) are other-provider snapshots joined by the privesc evaluator."""
    snapshot = collect_snapshot(request)
    timings = {}
    report = evaluate_snapshot(snapshot, request.get("categories"), request.get("checks"), request.get("frameworks"), timings=timings,
                               include_not_applicable=bool(request.get("include_not_applicable", False)),
                               related_snapshots=request.get("related_snapshots"))
    if timings:
        report["timings"] = timings
    return report, snapshot


def run_scan(request):
    """scan() as one report; request["embed_snapshot"] (default False) also embeds the collected snapshot."""
    report, snapshot = scan(request)
    if request.get("embed_snapshot"):
        report["snapshot"] = snapshot
    return report


def diff_reports(before, after):
    """Compare stable finding IDs and full evidence; timestamp-only scan differences are ignored."""
    if before.get("provider") != after.get("provider"):
        raise ValueError("cannot diff reports across providers")
    if set(before.get("scopes", [])) != set(after.get("scopes", [])):
        raise ValueError("cannot diff reports across different scope selections")
    before, after = hydrate_frameworks(before), hydrate_frameworks(after)
    def canonical(findings):
        # Findings stored under a retired duplicate check id are keyed as their surviving check; when the survivor's
        # finding for the same resource is also present, the retired duplicate is dropped.
        from .checks import CHECK_ALIASES
        rows = {}
        for f in findings:
            survivor = CHECK_ALIASES.get(f.get("check_id"))
            if survivor:
                f = dict(f, check_id=survivor, id=digest([f.get("provider"), f.get("scope"), f.get("resource_id"), survivor]))
                rows.setdefault(f["id"], f)
            else:
                rows[f["id"]] = f
        return rows
    left = canonical(before.get("findings", []))
    right = canonical(after.get("findings", []))
    added = [right[key] for key in sorted(right.keys() - left.keys())]
    removed = [left[key] for key in sorted(left.keys() - right.keys())]
    def comparable(value):
        if isinstance(value, dict):
            return {k: comparable(v) for k, v in value.items() if k != "snapshot_id"}
        if isinstance(value, list):
            return [comparable(v) for v in value]
        return value
    changed = [{"id": key, "before": left[key], "after": right[key]} for key in sorted(left.keys() & right.keys()) if comparable(left[key]) != comparable(right[key])]

    return {"schema_version": SCHEMA_VERSION, "provider": before["provider"], "scopes": before.get("scopes", []),
        "before_snapshot_id": before.get("snapshot_id"), "after_snapshot_id": after.get("snapshot_id"),
        "added": added, "removed": removed, "changed": changed,
        "stats": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        "coverage_before": before.get("coverage", []), "coverage_after": after.get("coverage", [])}
