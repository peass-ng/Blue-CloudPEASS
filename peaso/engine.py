"""Public snapshot engine. Evaluation is deterministic and never calls a provider."""
from __future__ import annotations
import copy
from collections import Counter, defaultdict
from importlib import import_module
from .snapshot import SCHEMA_VERSION, PROVIDERS, digest, validate, resources, seal

CATEGORIES = ("hardening", "exposure", "least_privilege", "iam_graph", "network", "privesc")
# Catalog-driven privilege-escalation map (peaso.privesc). "privesc" selects every technique.
PRIVESC_CHECK_ID = "privesc"
PRIVESC_FRAMEWORK = "HackTricks Cloud Best Practices"
FRAMEWORK_ALIASES = {"hacktricks": "HackTricks Cloud Best Practices", "hacktricks_cloud_best_practices": "HackTricks Cloud Best Practices",
    "nist_800_53": "NIST 800-53", "nist": "NIST 800-53"}


def _registry():
    from .checks import CHECKS
    return list(CHECKS)


def get_catalog():
    from .analysis import ANALYSIS_CHECKS
    from .checks.catalog import coverage as upstream_coverage, framework_catalog, manual_requirements
    from .collectors import supported_types
    checks = [check.public() for check in _registry()] + copy.deepcopy(ANALYSIS_CHECKS)
    names = sorted({framework for check in checks for framework in check["frameworks"]})
    return {"schema_version": SCHEMA_VERSION, "providers": list(PROVIDERS), "categories": list(CATEGORIES),
        "inventories": {p: supported_types(p) for p in PROVIDERS}, "framework_versions": framework_catalog(), "manual_requirements": manual_requirements(), "checks": checks, "privesc_techniques": privesc_techniques(), "upstream_coverage": upstream_coverage(), "frameworks": [{"id": next((k for k, v in FRAMEWORK_ALIASES.items() if v == name), name), "name": name} for name in names],
        "limitations": ["Native reviewed snapshot checks only; upstream catalogs are provenance, not migrated runtime coverage.",
                         "Framework mappings are thematic review guidance, not certification.", "Graphs describe declared relationships; effective access and reachability require separate validation."]}


catalog = get_catalog


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
    "required_permissions": {"all_of": ["administrator-equivalent grant on the scope"], "any_of": []}, "requires": {},
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


def privesc_technique_details(technique_ids):
    """Catalog details (summary, required permissions, HackTricks source, conditions, mitigation) per technique id."""
    try:
        from . import privesc
        entries = {e["id"]: e for e in privesc.catalog()["entries"]}
    except ImportError:
        entries = {}
    details = {}
    for technique in technique_ids:
        if technique == "admin-equivalent":
            details[technique] = copy.deepcopy(ADMIN_EQUIVALENT_TECHNIQUE)
            continue
        entry = entries.get(technique)
        if entry is None:
            details[technique] = {"id": technique, "unknown": True}
            continue
        requires = entry.get("requires") or {}
        details[technique] = {
            "id": technique, "title": entry.get("title"), "provider": entry.get("provider"), "service": entry.get("service"),
            "summary": entry.get("summary"), "requires": copy.deepcopy(requires),
            "required_permissions": {"all_of": [_permission_text(r) for r in requires.get("all_of", [])],
                                     "any_of": [[_permission_text(r) for r in (group if isinstance(group, list) else [group])] for group in requires.get("any_of", [])]},
            "source": entry.get("source"), "source_revision": entry.get("source_revision"),
            "conditions": copy.deepcopy(entry.get("conditions") or []), "blockers": list(entry.get("blockers") or []),
            "severity": entry.get("severity"), "catalog_confidence": entry.get("confidence"),
            "mitigation": entry.get("mitigation"), "references": list(entry.get("references") or [])}
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
        checks = _string_list(checks, "checks")
        from .checks.catalog import manual_requirements
        known = {c.id for c in registry if c.provider == provider} | {c["id"] for c in ANALYSIS_CHECKS} | {c["id"] for c in manual_requirements() if c["provider"] == provider}
        if any(check not in known for check in checks):
            known |= {PRIVESC_CHECK_ID} | {t["id"] for t in privesc_techniques(provider)}
        if any(check not in known for check in checks):
            raise ValueError("unknown check ID for selected provider")
    if frameworks is not None:
        frameworks = [FRAMEWORK_ALIASES.get(value, value) for value in _string_list(frameworks, "frameworks")]
        from .checks.catalog import framework_catalog
        supported = {f for c in registry if c.provider == provider for f in c.frameworks} | {f for c in ANALYSIS_CHECKS for f in c["frameworks"]}
        supported.update(row["id"] for row in framework_catalog() if row["provider"] in (provider, "all"))
        if any(f not in supported for f in frameworks):
            raise ValueError("unsupported framework")
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
    options = connector.get("options", {})
    if "snapshot" in options:
        snapshot = validate(options["snapshot"])
        if snapshot["provider"] != connector["provider"]:
            raise ValueError("connector/snapshot provider mismatch")
        requested = connector.get("scopes", [])
        if requested and requested != snapshot["scopes"]:
            raise ValueError("connector/snapshot scope mismatch")
        return snapshot
    if options.get("demo"):
        from .demo import demo_snapshot
        return demo_snapshot(connector["provider"])
    from .collectors import collect_live
    requirements = plan_collection(request)
    snapshot = validate(collect_live(connector, requirements))
    snapshot["metadata"]["collection_plan"] = {"mode": "collect_all" if options.get("collect_all") else "explicit_inventories" if "inventories" in options else "full_default" if _full_selection(connector["provider"], *_selection(connector["provider"], request.get("categories"), request.get("checks"), request.get("frameworks"))) else "dependencies", "requirements": requirements,
        "categories": request.get("categories") or list(CATEGORIES), "checks": request.get("checks") or "all_selected", "frameworks": request.get("frameworks") or "all_selected"}
    return validate(seal(snapshot))


def _analysis_selection(provider, categories, checks, frameworks):
    from .analysis import ANALYSIS_CHECKS
    frameworks = [FRAMEWORK_ALIASES.get(value, value) for value in frameworks] if frameworks else None
    return [c for c in ANALYSIS_CHECKS if c["category"] in categories and c.get("provider") in (provider, "all")
        and (not checks or c["id"] in checks) and (not frameworks or set(c["frameworks"]).intersection(frameworks))]


def plan_collection(request):
    connector = _request(request)
    provider = connector["provider"]
    categories, checks = _selection(provider, request.get("categories"), request.get("checks"), request.get("frameworks"))
    from .collectors import supported_types
    from .analysis import REQUIRED_TYPES
    available = set(supported_types(provider))
    required = {kind for check in checks for kind in getattr(check, "dependencies", [check.kind])}
    # Extra facts required by cross-resource native predicates.
    if any(c.id == "k8s.network.namespace_policy_inventory" for c in checks):
        required.add("networkpolicy")
    analysis_selected = _analysis_selection(provider, categories, request.get("checks"), request.get("frameworks"))
    for category in {c["category"] for c in analysis_selected} | (set(categories) & {"network", "iam_graph"}):
        required.update(REQUIRED_TYPES.get(provider, {}).get(category, []))
    if _privesc_selected(provider, categories, request.get("checks"), request.get("frameworks")) is not None:
        required.update(REQUIRED_TYPES.get(provider, {}).get("privesc", []))
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
        return sorted(available)
    return sorted(required & available)


def _index(snapshot, inventory):
    index = defaultdict(list)
    for resource in inventory:
        index[resource["type"]].append(resource)
    collections = defaultdict(list)
    for collection in snapshot["collections"]:
        collections[collection["type"]].append(collection)
    index["collections"] = dict(collections)
    return dict(index)


def _finding(check, provider, scope, rid, service, status, evidence, frameworks=None):
    return {"id": digest([provider, scope, rid, check.id]), "category": check.category, "check_id": check.id,
        "title": check.title, "provider": provider, "service": service, "resource_id": rid, "scope": scope,
        "severity": check.severity, "status": status, "frameworks": list(check.frameworks if frameworks is None else frameworks),
        "evidence": evidence, "remediation": check.remediation}


def evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None, timings=None):
    """timings: optional dict that receives wall-clock timings; they never enter the deterministic report."""
    snapshot = validate(snapshot)
    provider = snapshot["provider"]
    selected_categories, selected = _selection(provider, categories, checks, frameworks)
    inventory = resources(snapshot)
    index = _index(snapshot, inventory)
    coverage, findings = [], []
    for collection in snapshot["collections"]:
        coverage.append({"level": "collection", "type": collection["type"], "scope": collection["scope"],
            "service": collection.get("service", collection["type"]), "status": collection["status"],
            "resource_count": len(collection["items"]), "reason": collection.get("error", {}).get("code", "")})
    scoped_indexes = {}
    by_scope = defaultdict(list)
    for resource in inventory:
        by_scope[(resource["type"], resource["scope"])].append(resource)
    def scoped_index(scope):
        if scope not in scoped_indexes:
            import re
            account = scope.split("/", 1)[0] if provider == "aws" else None
            if not account or not re.fullmatch(r"[0-9]{12}", account):
                account = None
            def relevant(collection):
                if collection["scope"] == scope:
                    return True
                return bool(account and collection.get("global") is True and collection.get("account_id") == account
                    and collection["scope"].split("/", 1)[0] == account
                    and all(item.get("AccountId") == account for item in collection["items"]))
            selected_collections = [c for c in snapshot["collections"] if relevant(c)]
            resource_scopes = {(c["type"], c["scope"]) for c in selected_collections}
            scoped_indexes[scope] = {kind: [r for r in rows if (r["type"], r["scope"]) in resource_scopes] for kind, rows in index.items() if kind != "collections"}
            scoped_indexes[scope]["collections"] = {kind: [c for c in rows if relevant(c)] for kind, rows in index["collections"].items()}
            context = {"provider": provider, "scope": scope, "_scope": scope, "created_at": snapshot["created_at"],
                "snapshot_id": snapshot["snapshot_id"], "metadata": copy.deepcopy(snapshot.get("metadata", {}))}
            if account:
                context["Account"] = account
            scoped_indexes[scope]["context"] = context
            scoped_indexes[scope]["_snapshot"] = context
        return scoped_indexes[scope]

    for check in selected:
        check_frameworks = list(check.frameworks)
        if getattr(check, "target", "resource") == "scope":
            for scope in snapshot["scopes"] or ["unknown"]:
                scoped = scoped_index(scope)
                incomplete = [{"type": kind, "status": "not_collected"} for kind in check.dependencies if not scoped["collections"].get(kind)]
                incomplete += [{"type": kind, "status": c["status"]} for kind in check.dependencies for c in scoped["collections"].get(kind, []) if c["status"] not in ("collected", "empty")]
                if incomplete:
                    status, evidence = "DENIED" if any(row["status"] == "denied" for row in incomplete) else "UNKNOWN", {"reason": "required scoped inventory incomplete", "dependencies": incomplete, "target": "scope"}
                else:
                    try:
                        status, evidence = check.evaluate(copy.deepcopy(scoped["context"]), scoped)
                        if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                            raise ValueError("invalid scoped check result")
                    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                        status, evidence = "UNKNOWN", {"reason": "missing or malformed scoped facts", "error_kind": type(exc).__name__}
                findings.append(_finding(check, provider, scope, "scope:" + scope, check.kind, status, evidence, check_frameworks))
                coverage.append({"level": "check", "check_id": check.id, "type": check.kind, "scope": scope,
                    "target": "scope", "status": "unknown" if status in ("UNKNOWN", "DENIED") else "manual" if status == "MANUAL" else "evaluated",
                    "by_status": {status: 1}, "reason": "Scoped presence/aggregate evaluation over collected facts."})
            continue
        collections = index["collections"].get(check.kind, [])
        # Global inventories may use native account/global scope; their explicit envelope is authoritative.
        if not collections:
            collections = [{"type": check.kind, "scope": scope, "service": check.kind, "status": "not_collected", "items": []} for scope in snapshot["scopes"] or ["unknown"]]
        for collection in collections:
            scope, collection_status = collection["scope"], collection["status"]
            scope_findings = []
            for resource in by_scope.get((check.kind, scope), []):
                # The rule index is scoped; foreign subscriptions/namespaces cannot satisfy a check.
                scoped = scoped_index(scope)
                try:
                    status, evidence = check.evaluate(copy.deepcopy(resource["data"]), scoped)
                    if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "EMPTY", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                        raise ValueError("invalid check result")
                except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                    status, evidence = "UNKNOWN", {"reason": "missing or malformed provider facts", "error_kind": type(exc).__name__}
                scope_findings.append(_finding(check, provider, scope, resource["id"], resource["service"], status, evidence, check_frameworks))
            unavailable = collection_status not in ("collected", "empty")
            if unavailable or not scope_findings:
                status = "DENIED" if collection_status == "denied" else "EMPTY" if collection_status == "empty" else "UNKNOWN"
                scope_findings.append(_finding(check, provider, scope, "inventory:" + check.kind, collection.get("service", check.kind), status,
                    {"collection_status": collection_status, "reason": collection.get("error", {}).get("code", "no collected resources"),
                     "semantics": "Inventory coverage, not a resource security pass."}, check_frameworks))
            findings.extend(scope_findings)
            counts = dict(Counter(f["status"] for f in scope_findings))
            check_status = "partial" if unavailable and collection_status == "partial" else "denied" if collection_status == "denied" else "unknown" if unavailable or counts.get("UNKNOWN") or counts.get("DENIED") else "empty" if collection_status == "empty" else "manual" if counts.get("MANUAL") else "evaluated"
            coverage.append({"level": "check", "check_id": check.id, "type": check.kind, "scope": scope,
                "status": check_status, "by_status": counts, "reason": collection.get("error", {}).get("code", "")})
    from .analysis import analysis_context
    from scripts.cloud_permission_risks import offline_rules
    with offline_rules(), analysis_context(snapshot):
        analysis_selected = _analysis_selection(provider, selected_categories, checks, frameworks)
        if analysis_selected:
            from .analysis import analyze_findings
            expected_ids = {c["id"] for c in analysis_selected}
            analyzed = [f for f in analyze_findings(snapshot, inventory, index) if f["check_id"] in expected_ids and f["category"] in selected_categories]
            findings.extend(analyzed)
            for check in analysis_selected:
                by_status = dict(Counter(f["status"] for f in analyzed if f["check_id"] == check["id"]))
                coverage.append({"level": "check", "check_id": check["id"], "type": "projection", "scope": "selected_scopes",
                    "status": "unknown" if by_status.get("UNKNOWN") else "manual" if by_status.get("MANUAL") else "evaluated",
                    "by_status": by_status, "reason": "Defensive review signals; no finding is not an effective-access pass."})
        graphs = {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [], "edges": []}}
        if "network" in selected_categories or "iam_graph" in selected_categories:
            from .analysis import build_graphs
            built = build_graphs(snapshot, inventory, index, max_nodes=max(500, len(inventory) * 100))
            for graph, category in (("network", "network"), ("iam", "iam_graph")):
                if category in selected_categories:
                    graphs[graph] = built[graph]
    privesc_stats = None
    graphs.setdefault("privesc", {"nodes": [], "edges": []})
    privesc_filter = _privesc_selected(provider, selected_categories, checks, frameworks)
    if privesc_filter is not None:
        privesc_findings, privesc_coverage, graphs["privesc"], privesc_stats, privesc_timing = _run_privesc(snapshot, privesc_filter)
        if timings is not None:
            timings["privesc"] = privesc_timing
        findings.extend(privesc_findings)
        coverage.extend(privesc_coverage)
    from .checks.catalog import manual_requirements
    requested_frameworks ={FRAMEWORK_ALIASES.get(value, value) for value in frameworks} if frameworks else None
    def manual_scopes(requirement):
        kinds = set(requirement.get("scope_kinds", []))
        if provider == "aws" and "account" in kinds:
            import re
            proven = {c.get("account_id") for c in snapshot["collections"] if c["type"] == "aws_account"
                and c["status"] == "collected" and c.get("global") is True and isinstance(c.get("account_id"), str)
                and re.fullmatch(r"[0-9]{12}", c["account_id"]) and any(item.get("Account") == c["account_id"] for item in c["items"])}
            return list(dict.fromkeys(scope.split("/", 1)[0] if scope.split("/", 1)[0] in proven else scope for scope in snapshot["scopes"]))
        return list(snapshot["scopes"])
    selected_manual = []
    if "hardening" in selected_categories:
        for requirement in manual_requirements():
            mapping_names = {entry.get(key) for entry in requirement["frameworks"] for key in ("framework", "framework_family", "framework_id")}
            mapping_names.add("HackTricks Cloud Best Practices")
            if requirement["provider"] != provider or (checks and requirement["id"] not in checks) or (requested_frameworks and not requested_frameworks.intersection(mapping_names)):
                continue
            selected_manual.append(copy.deepcopy(requirement))
            for scope in manual_scopes(requirement):
                findings.append({"id": digest([provider, scope, requirement["id"], "manual"]), "category": "hardening", "check_id": requirement["id"],
                    "title": requirement["title"], "provider": provider, "service": "manual_review", "resource_id": "scope:" + scope,
                    "scope": scope, "severity": "info", "status": "MANUAL", "automated": False,
                    "frameworks": ["HackTricks Cloud Best Practices"] + sorted({entry["framework"] for entry in requirement["frameworks"]}),
                    "evidence": {"question": requirement["question"], "source": requirement["source"], "revision": requirement["revision"], "reason": requirement["reason"], "automated": False},
                    "remediation": requirement["guidance"] or "Have the owner provide reviewed evidence for this requirement."})
                coverage.append({"level": "manual", "check_id": requirement["id"], "scope": scope, "status": "manual", "reason": "Human attestation required; no automated security assessment."})
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
    if frameworks:
        from .checks.catalog import framework_catalog
        requested_frameworks = {FRAMEWORK_ALIASES.get(value, value) for value in frameworks}
        selected_framework_versions = [copy.deepcopy(row) for row in framework_catalog() if row["id"] in requested_frameworks and row["provider"] in (provider, "all")]
        selected_native_ids = {c.id for c in selected}
        for row in selected_framework_versions:
            covered_ids = selected_native_ids.intersection(row["native_check_ids"])
            coverage.append({"level": "framework", "framework_id": row["id"], "framework_name": row["name"],
                "scope": "selected_scopes", "status": "unknown" if not covered_ids else "partial" if row["pending_source_checks"] else "evaluated",
                "selected_native_checks": len(covered_ids), "source_checks": row["source_checks"], "pending_source_checks": row["pending_source_checks"],
                "reason": "Pending upstream definitions are unimplemented; selected native predicates do not establish complete checklist coverage."})
    scope_coverage = snapshot.get("metadata", {}).get("scope_coverage", {})
    if snapshot.get("metadata", {}).get("intentional_partial") is True or (isinstance(scope_coverage, dict) and scope_coverage.get("status") not in (None, "collected", "complete")):
        coverage.append({"level": "scope", "scope": "requested_scopes", "status": "partial" if snapshot.get("metadata", {}).get("intentional_partial") else "unknown",
            "reason": scope_coverage.get("reason", "Explicit scope limit or incomplete discovery") if isinstance(scope_coverage, dict) else "Malformed scope coverage metadata"})
    counts = dict(Counter(f["status"] for f in findings))
    complete = bool(selected or analysis_selected or privesc_stats is not None) and all(c["status"] in ("empty", "evaluated") for c in coverage if c["level"] in ("check", "framework", "manual", "scope"))
    inventory_complete = all(c["status"] in ("collected", "empty") for c in coverage if c["level"] in ("collection", "scope"))
    report = {"schema_version": SCHEMA_VERSION, "snapshot_id": snapshot["snapshot_id"], "provider": provider,
        "scopes": list(snapshot["scopes"]), "created_at": snapshot["created_at"], "resources": inventory,
        "findings": sorted(findings, key=lambda f: (f["category"], f["check_id"], f["scope"], f["resource_id"])),
        "coverage": coverage, "framework_versions": selected_framework_versions, "snapshot_metadata": copy.deepcopy(snapshot.get("metadata", {})), "manual_requirements": selected_manual, "graphs": graphs, "stats": {"resource_count": len(inventory), "finding_count": len(findings),
            "check_count": len(selected) + len(analysis_selected), "manual_requirement_count": len(selected_manual), "by_status": counts, "by_severity": dict(Counter(f["severity"] for f in findings if f["status"] == "FAIL")),
            "coverage_complete": complete, "inventory_complete": inventory_complete, "categories": selected_categories,
            "limitations": ["Framework mappings retain reviewed source provenance; they are not compliance certification.", "Declared IAM relationships are not effective access.",
                "Network inventory relationships are not proven reachability.", "Upstream hardening catalogs have not all been ported; only selected native checks ran."]}}
    if privesc_stats is not None:
        report["stats"]["privesc"] = privesc_stats
        report["stats"]["check_count"] += 1
        report["stats"]["limitations"].append("Privilege-escalation paths are derived offline from collected policies and the technique catalog; they are not exploited or proven.")
    return report


def _run_privesc(snapshot, technique_filter):
    """Run the read-only privesc evaluator; an evaluator failure becomes coverage, never a crashed scan."""
    import time
    started = time.perf_counter()
    try:
        from . import privesc
        if technique_filter:
            entries = [e for e in privesc.catalog()["entries"] if e["id"] in technique_filter]
            result = privesc.analyze(snapshot, entries=entries)
        else:
            result = privesc.analyze(snapshot)
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


def run_scan(request):
    snapshot = collect_snapshot(request)
    timings = {}
    report = evaluate_snapshot(snapshot, request.get("categories"), request.get("checks"), request.get("frameworks"), timings=timings)
    if timings:
        report["timings"] = timings
    report["snapshot"] = snapshot
    return report


def diff_reports(before, after):
    """Compare stable finding IDs and full evidence; timestamp-only scan differences are ignored."""
    if before.get("provider") != after.get("provider"):
        raise ValueError("cannot diff reports across providers")
    if set(before.get("scopes", [])) != set(after.get("scopes", [])):
        raise ValueError("cannot diff reports across different scope selections")
    left = {f["id"]: f for f in before.get("findings", [])}
    right = {f["id"]: f for f in after.get("findings", [])}
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
