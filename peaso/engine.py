"""Public snapshot engine. Evaluation is deterministic and never calls a provider."""
from __future__ import annotations
import copy
from collections import Counter, defaultdict
from importlib import import_module
from .snapshot import SCHEMA_VERSION, PROVIDERS, digest, validate, resources, seal

CATEGORIES = ("hardening", "exposure", "least_privilege", "iam_graph", "network")
FRAMEWORK_ALIASES = {"hacktricks": "HackTricks Cloud Best Practices", "hacktricks_cloud_best_practices": "HackTricks Cloud Best Practices",
    "nist_800_53": "NIST 800-53", "nist": "NIST 800-53"}


def _registry():
    from .checks import CHECKS
    return list(CHECKS)


def get_catalog():
    from .analysis import ANALYSIS_CHECKS
    from .checks.catalog import coverage as upstream_coverage
    from .collectors import supported_types
    checks = [check.public() for check in _registry()] + copy.deepcopy(ANALYSIS_CHECKS)
    names = sorted({framework for check in checks for framework in check["frameworks"]})
    return {"schema_version": SCHEMA_VERSION, "providers": list(PROVIDERS), "categories": list(CATEGORIES),
        "inventories": {p: supported_types(p) for p in PROVIDERS}, "checks": checks, "upstream_coverage": upstream_coverage(), "frameworks": [{"id": next((k for k, v in FRAMEWORK_ALIASES.items() if v == name), name), "name": name} for name in names],
        "limitations": ["Native reviewed snapshot checks only; upstream catalogs are provenance, not migrated runtime coverage.",
                         "Framework mappings are thematic review guidance, not certification.", "Graphs describe declared relationships; effective access and reachability require separate validation."]}


catalog = get_catalog


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
        known = {c.id for c in registry if c.provider == provider} | {c["id"] for c in ANALYSIS_CHECKS}
        if any(check not in known for check in checks):
            raise ValueError("unknown check ID for selected provider")
    if frameworks is not None:
        frameworks = [FRAMEWORK_ALIASES.get(value, value) for value in _string_list(frameworks, "frameworks")]
        supported = {f for c in registry for f in c.frameworks} | {f for c in ANALYSIS_CHECKS for f in c["frameworks"]}
        if any(f not in supported for f in frameworks):
            raise ValueError("unsupported framework")
    selected = [c for c in registry if c.provider == provider and c.category in selected_categories
        and (checks is None or c.id in checks) and (frameworks is None or set(c.frameworks).intersection(frameworks))]
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
    snapshot["metadata"]["collection_plan"] = {"mode": "collect_all" if options.get("collect_all") else "explicit_inventories" if "inventories" in options else "dependencies", "requirements": requirements,
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
    collect_all = connector.get("options", {}).get("collect_all", False)
    if type(collect_all) is not bool:
        raise ValueError("collect_all must be a boolean")
    if collect_all and "inventories" in connector.get("options", {}):
        raise ValueError("collect_all and inventories are mutually exclusive")
    if collect_all:
        return sorted(available)
    inventories = connector.get("options", {}).get("inventories")
    if inventories is not None:
        if not isinstance(inventories, list) or any(kind not in available for kind in inventories):
            raise ValueError("inventories must be supported resource types")
        required = set(inventories)
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


def evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None):
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
    for check in selected:
        check_frameworks = list(check.frameworks)
        collections = index["collections"].get(check.kind, [])
        # Global inventories may use native account/global scope; their explicit envelope is authoritative.
        if not collections:
            collections = [{"type": check.kind, "scope": scope, "service": check.kind, "status": "not_collected", "items": []} for scope in snapshot["scopes"] or ["unknown"]]
        for collection in collections:
            scope, collection_status = collection["scope"], collection["status"]
            scope_findings = []
            for resource in by_scope.get((check.kind, scope), []):
                # The rule index is scoped; foreign subscriptions/namespaces cannot satisfy a check.
                if scope not in scoped_indexes:
                    scoped_indexes[scope] = {kind: [r for r in rows if r["scope"] == scope] for kind, rows in index.items() if kind != "collections"}
                    scoped_indexes[scope]["collections"] = {kind: [c for c in rows if c["scope"] == scope] for kind, rows in index["collections"].items()}
                scoped = scoped_indexes[scope]
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
    with analysis_context(snapshot):
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
    counts = dict(Counter(f["status"] for f in findings))
    complete = bool(selected or analysis_selected) and all(c["status"] in ("empty", "evaluated") for c in coverage if c["level"] == "check")
    inventory_complete = all(c["status"] in ("collected", "empty") for c in coverage if c["level"] == "collection")
    report = {"schema_version": SCHEMA_VERSION, "snapshot_id": snapshot["snapshot_id"], "provider": provider,
        "scopes": list(snapshot["scopes"]), "created_at": snapshot["created_at"], "resources": inventory,
        "findings": sorted(findings, key=lambda f: (f["category"], f["check_id"], f["scope"], f["resource_id"])),
        "coverage": coverage, "graphs": graphs, "stats": {"resource_count": len(inventory), "finding_count": len(findings),
            "check_count": len(selected) + len(analysis_selected), "by_status": counts, "by_severity": dict(Counter(f["severity"] for f in findings if f["status"] == "FAIL")),
            "coverage_complete": complete, "inventory_complete": inventory_complete, "categories": selected_categories,
            "limitations": ["Framework mappings retain reviewed source provenance; they are not compliance certification.", "Declared IAM relationships are not effective access.",
                "Network inventory relationships are not proven reachability.", "Upstream hardening catalogs have not all been ported; only selected native checks ran."]}}
    return report


def run_scan(request):
    snapshot = collect_snapshot(request)
    report = evaluate_snapshot(snapshot, request.get("categories"), request.get("checks"), request.get("frameworks"))
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
