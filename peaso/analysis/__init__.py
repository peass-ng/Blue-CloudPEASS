"""Offline defensive IAM, least-privilege, exposure, and network projections."""
from __future__ import annotations

from .common import FRAMEWORKS, RANK, analysis_context, finding, frameworks_for, node, source, with_analysis_context
from .iam import IAM_TYPES, azure_assignment_reviews, build_iam, review_findings
from .network import NETWORK_TYPES, build_network, exposure_findings
from .projection import collapse_unreferenced_definitions, expand_projected_node, filter_graph, page_graph, project_graph, stored_aggregate_members
from .reachability import REACHABILITY_TYPES, evaluate_reachability, evaluate_reachability_batch, evaluate_reachability_matrix, evaluate_reachability_grid, network_snapshot
from .internet_exposure import EXPOSURE_TYPES, annotate_network, federated_findings, internet_findings

REQUIRED_TYPES = {
    "aws": {"least_privilege": ["iam_user", "iam_group", "iam_role", "iam_policy", "access_analyzer"],
            "exposure": ["iam_role", "bucket", "security_group"],
            "network": ["vpc", "subnet", "network_interface", "instance", "security_group", "route_table", "network_acl",
                        "internet_gateway", "nat_gateway", "vpc_endpoint", "vpc_endpoint_service", "ec2_instance_connect_endpoint",
                        "ec2_client_vpn_endpoint", "vpc_peering", "transit_gateway", "transit_gateway_attachment",
                        "transit_gateway_route_table", "vpn_connection", "vpn_gateway", "network_firewall",
                        "network_firewall_policy", "network_firewall_rule_group",
                        "elastic_ip", "ec2_eip", "load_balancer", "classic_load_balancer", "target_group", "rds_instance", "rds_cluster",
                        "lambda_function", "eks_cluster"]},
    "gcp": {"least_privilege": ["iam_policy", "service_account", "iam_role", "recommendation", "insight"],
            "exposure": ["iam_policy", "bucket", "firewall"],
            "network": ["network", "subnetwork", "instance", "firewall", "firewall_policy", "route", "router",
                        "vpn_gateway", "vpn_tunnel", "forwarding_rule", "backend_service", "backend_bucket",
                        "url_map", "health_check", "address", "target_proxy", "instance_group",
                        "shared_vpc", "gke_cluster"]},
    "azure": {"least_privilege": ["role_assignment", "role_definition", "directory_user", "directory_group", "directory_service_principal"],
              "exposure": ["role_assignment", "storage_account", "nsg"],
              "network": ["vnet", "subnet", "vnet_peering", "nsg", "nic", "vm", "public_ip", "route_table",
                          "load_balancer", "application_gateway", "private_endpoint", "virtual_network_gateway",
                          "firewall_policy", "pod", "service"]},
    "k8s": {"least_privilege": ["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"],
            "exposure": ["rolebinding", "clusterrolebinding", "service", "networkpolicy"],
            "network": ["namespace", "pod", "service", "networkpolicy", "ingress", "node",
                        "endpointslice", "network_interface"]},
}
for _requirements in REQUIRED_TYPES.values():
    _requirements["iam_graph"] = list(_requirements["least_privilege"])
for _provider, _types in REACHABILITY_TYPES.items():
    REQUIRED_TYPES[_provider]["network"] = sorted(set(REQUIRED_TYPES[_provider]["network"]) | _types)
from .network_services import SERVICE_TYPES
from .network_catalog import CONTROL_TYPES
for _provider, _types in SERVICE_TYPES.items():
    REQUIRED_TYPES[_provider]["network"] = sorted(set(REQUIRED_TYPES[_provider]["network"]) | _types)
for _provider, _types in CONTROL_TYPES.items():
    REQUIRED_TYPES[_provider]["network"] = sorted(set(REQUIRED_TYPES[_provider]["network"]) | _types)
# Internet-to-asset exposure and federated-trust review (peaso.analysis.internet_exposure / trust).
for _provider, _types in EXPOSURE_TYPES.items():
    REQUIRED_TYPES[_provider]["exposure"] = sorted(set(REQUIRED_TYPES[_provider]["exposure"]) | set(_types))
# Inventories read by the catalog-driven privilege-escalation evaluator (peaso.privesc).
# These lists are a floor: privesc_required_types() adds every type the privesc models read (parsed from
# peaso/privesc/effective_permissions/<provider>.py), so the collection plan follows the evaluator.
REQUIRED_TYPES["aws"]["privesc"] = ["iam_user", "iam_group", "iam_role", "iam_policy", "scp_policy", "rcp_policy", "lambda_function", "instance",
                                    "glue_job", "redshift_cluster", "ssm_managed_instance", "ecs_cluster", "ecs_task_definition"]
REQUIRED_TYPES["gcp"]["privesc"] = ["organization", "folder", "project", "iam_policy", "iam_role", "service_account", "iam_deny_policy", "instance"]
REQUIRED_TYPES["azure"]["privesc"] = ["tenant", "management_group", "subscription", "resource_group", "role_assignment", "role_definition", "deny_assignment",
                                      "directory_user", "directory_group", "directory_service_principal", "directory_application", "directory_membership",
                                      "directory_role_assignment", "directory_role_definition", "resource_graph",
                                      "vm", "app_service", "aks_cluster", "storage_account", "vault", "sql_server"]
REQUIRED_TYPES["k8s"]["privesc"] = ["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount", "namespace", "pod", "node"]


from peaso.principal_exposure_requirements import REQUIRED_TYPES as _PRINCIPAL_EXPOSURE_TYPES
for _provider, _types in _PRINCIPAL_EXPOSURE_TYPES.items():
    # Filter names against provider support when constructing the collection plan.
    from peaso.collectors import supported_types as _supported_types
    for _category in ("least_privilege", "privesc"):
        REQUIRED_TYPES[_provider][_category] = sorted(set(REQUIRED_TYPES[_provider][_category]) | (_types & set(_supported_types(_provider))))


def privesc_required_types(provider):
    """Collection types the privesc evaluator needs for a provider: the floor above plus every supported
    type its model reads (see privesc_requirements). Strings that are not collection types are dropped."""
    from peaso.collectors import supported_types
    from .privesc_requirements import privesc_collection_types
    floor = set(REQUIRED_TYPES.get(provider, {}).get("privesc", []))
    return sorted(floor | (privesc_collection_types(provider) & set(supported_types(provider))))


ANALYSIS_CHECKS = [
    {"id": "analysis.grant_review", "category": "least_privilege", "title": "Review high-impact or broad declared grants", "severity": "high"},
    {"id": "analysis.inactive_identity", "category": "least_privilege", "title": "Review identity with no activity in the observed window", "severity": "low"},
    {"id": "analysis.principal_exposure", "category": "exposure", "title": "Review public or external principal declarations", "severity": "high"},
    {"id": "analysis.network_review", "category": "exposure", "title": "Review unrestricted network rule candidates", "severity": "high"},
    {"id": "analysis.coverage", "category": "least_privilege", "title": "Analysis inventory context incomplete", "severity": "info"},
    {"id": "analysis.internet_exposure", "category": "exposure", "title": "Asset reachable from the internet", "severity": "high"},
    {"id": "analysis.federated_trust", "category": "exposure", "title": "Federated (OIDC) trust is not pinned to a subject", "severity": "high"},
]
from .finding_clarity import HOW as _CLARITY_HOW, ACTION as _CLARITY_ACTION
for _check in ANALYSIS_CHECKS:
    from peaso.finding_types import type_for as _finding_type_for
    _check["finding_type"] = _finding_type_for(_check["id"])
    _check.update({"provider": "all", "type": "projection", "frameworks": frameworks_for(_check["id"]),
        "mapping": {"hacktricks": "Defensive identity and network review"} if frameworks_for(_check["id"]) else {},
        "remediation": _CLARITY_ACTION.get(_check["id"], "Review the recorded access declaration before changing it.")})
    if _check["id"] in _CLARITY_HOW:
        _check["description"] = _CLARITY_HOW[_check["id"]]


@with_analysis_context
def analyze_findings(snapshot, resources=None, index=None):
    if resources is None:
        from peaso.snapshot import resources as snapshot_resources
        resources = snapshot_resources(snapshot)
    results = []
    for resource in resources:
        try:
            results.extend(review_findings(snapshot, [resource]))
            results.extend(exposure_findings(snapshot, [resource]))
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            results.append(finding(snapshot, resource, "least_privilege", "analysis.coverage",
                "Malformed native fact requires review", "info",
                {"source": source(snapshot, resource, "data"), "reason": "malformed_native_fact", "risk_state": "unknown"}, status="UNKNOWN"))
    # Azure least-privilege review is per assignment (cross-resource: assignment -> definition by GUID).
    try:
        results.extend(azure_assignment_reviews(snapshot, resources))
    except (TypeError, AttributeError, KeyError, ValueError, IndexError):
        placeholder = {"id": "inventory:azure_assignment_reviews", "type": "inventory", "scope": (snapshot["scopes"] or ["global"])[0],
                       "provider": snapshot["provider"], "service": "iam", "data": {}}
        results.append(finding(snapshot, placeholder, "least_privilege", "analysis.coverage", "Assignment grant review failed on malformed facts", "info",
            {"reason": "malformed_native_fact", "risk_state": "unknown"}, status="UNKNOWN"))
    for derived_findings in (internet_findings, federated_findings):
        try:
            results.extend(derived_findings(snapshot, resources))
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            placeholder = {"id": "inventory:" + derived_findings.__name__, "type": "inventory", "scope": (snapshot["scopes"] or ["global"])[0],
                           "provider": snapshot["provider"], "service": "exposure", "data": {}}
            results.append(finding(snapshot, placeholder, "exposure", "analysis.internet_exposure", "Exposure analysis failed on malformed facts", "info",
                {"reason": "malformed_native_fact", "risk_state": "unknown"}, status="UNKNOWN"))
    # Unknown coverage never becomes a clean bill of health. Empty, completely
    # enumerated collections are not equivalent to missing/denied collections.
    expected = REQUIRED_TYPES[snapshot["provider"]]["least_privilege"]
    for scope in snapshot["scopes"]:
        # An account-global AWS inventory (IAM) is collected once for the account and covers every
        # regional scope of that account; only its absence or failure is a gap.
        account = scope.split("/", 1)[0] if snapshot["provider"] == "aws" else None
        present = {c["type"]: c for c in snapshot["collections"] if account and c.get("global") is True
                   and c.get("account_id") == account and c["scope"].split("/", 1)[0] == account}
        present.update({c["type"]: c for c in snapshot["collections"] if c["scope"] == scope})
        gaps =[{"type": kind, "status": present.get(kind, {}).get("status", "not_collected")}
                for kind in expected if present.get(kind, {}).get("status") not in {"collected", "empty"}]
        if gaps:
            placeholder = {"id": "inventory", "type": "inventory", "scope": scope,
                           "provider": snapshot["provider"], "service": "iam", "data": {}}
            results.append(finding(snapshot, placeholder, "least_privilege", "analysis.coverage",
                "Analysis inventory context incomplete", "info", {"gaps": gaps, "risk_state": "unknown"}, status="UNKNOWN"))
    return sorted(results, key=lambda f: (RANK[f["severity"]], f["check_id"], f["scope"], f["resource_id"]))


@with_analysis_context
def build_graphs(snapshot, resources, index=None, *, max_nodes=500, collapse_unreferenced=False):
    """collapse_unreferenced: the caller folds edge-less definition nodes (projection.collapse_unreferenced_definitions),
    so their IAM cards are not built."""
    from functools import partial
    from .projection import UNREFERENCED_DEFINITION_TYPES
    defer = frozenset(UNREFERENCED_DEFINITION_TYPES.get(snapshot.get("provider"), ())) if collapse_unreferenced else frozenset()
    graphs = {}
    for kind, builder in (("network", build_network), ("iam", partial(build_iam, defer_types=defer))):
        try:
            graph = builder(snapshot, resources)
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            # Malformed provider facts must not suppress the whole report or
            # turn lack of modeled relationships into a safe-access assertion.
            graph = {"nodes": [], "edges": [], "status": "partial", "uncertainty": "Some native facts are malformed; cross-resource associations may be incomplete"}
            merged_nodes, merged_edges = {}, {}
            for resource in resources:
                try:
                    partial = builder(snapshot, [resource])
                except (TypeError, AttributeError, KeyError, ValueError, IndexError):
                    partial = {"nodes": [node(resource)], "edges": []}
                    partial["nodes"][0]["evidence"]["analysis_status"] = "malformed"
                for current in partial["nodes"]:
                    evidence = current.get("evidence", {})
                    if current["id"] not in merged_nodes or evidence.get("native_resource") or evidence.get("native_resource_ref"):
                        merged_nodes[current["id"]] = current
                merged_edges.update({e["id"]: e for e in partial["edges"]})
            graph.update(nodes=list(merged_nodes.values()), edges=list(merged_edges.values()))
        if kind == "network":
            try:
                graph = annotate_network(graph, snapshot, resources)
            except (TypeError, AttributeError, KeyError, ValueError, IndexError):
                graph = {**graph, "status": "partial"}
        # max_nodes=None keeps the complete graph (the engine's report path) without a projection pass.
        graphs[kind] = project_graph(graph, max_nodes) if max_nodes is not None else {
            **graph, "projection": {"collapsed": False, "node_count": len(graph["nodes"]), "edge_count": len(graph["edges"])}}
    return graphs


def analyze(snapshot, categories=None):
    from peaso.snapshot import resources, validate
    snapshot = validate(snapshot, read_only=True)
    inventory = resources(snapshot)
    with analysis_context(snapshot):
        findings = analyze_findings(snapshot, inventory)
        graphs = build_graphs(snapshot, inventory)
    selected = set(categories) if categories is not None else {"least_privilege", "exposure", "iam_graph", "network"}
    return {"findings": [f for f in findings if f["category"] in selected],
            "graphs": {"network": graphs["network"] if "network" in selected else {"nodes": [], "edges": []},
                       "iam": graphs["iam"] if "iam_graph" in selected else {"nodes": [], "edges": []}},
            "resources": inventory}


__all__ = ["analyze", "analyze_findings", "analysis_context", "build_graphs", "collapse_unreferenced_definitions", "filter_graph", "project_graph", "page_graph", "expand_projected_node", "stored_aggregate_members", "ANALYSIS_CHECKS", "REQUIRED_TYPES", "privesc_required_types", "evaluate_reachability", "evaluate_reachability_batch", "evaluate_reachability_matrix", "evaluate_reachability_grid", "network_snapshot", "REACHABILITY_TYPES"]
