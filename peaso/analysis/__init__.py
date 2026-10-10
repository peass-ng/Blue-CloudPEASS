"""Offline defensive IAM, least-privilege, exposure, and network projections."""
from __future__ import annotations

from .common import FRAMEWORKS, RANK, analysis_context, finding, node, source, with_analysis_context
from .iam import IAM_TYPES, build_iam, review_findings
from .network import NETWORK_TYPES, build_network, exposure_findings
from .projection import filter_graph, project_graph

REQUIRED_TYPES = {
    "aws": {"least_privilege": ["iam_user", "iam_group", "iam_role", "iam_policy"],
            "exposure": ["iam_role", "bucket", "security_group"],
            "network": ["vpc", "subnet", "network_interface", "instance", "security_group", "route_table", "vpc_peering", "load_balancer"]},
    "gcp": {"least_privilege": ["iam_policy", "service_account", "iam_role"],
            "exposure": ["iam_policy", "bucket", "firewall"],
            "network": ["network", "subnetwork", "instance", "firewall", "route", "forwarding_rule", "backend_service"]},
    "azure": {"least_privilege": ["role_assignment", "role_definition", "directory_user", "directory_group", "directory_service_principal"],
              "exposure": ["role_assignment", "storage_account", "nsg"],
              "network": ["vnet", "nsg", "nic", "vm", "public_ip", "route_table", "load_balancer"]},
    "k8s": {"least_privilege": ["role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"],
            "exposure": ["rolebinding", "clusterrolebinding", "service", "networkpolicy"],
            "network": ["namespace", "pod", "service", "networkpolicy", "ingress", "node"]},
}
for _requirements in REQUIRED_TYPES.values():
    _requirements["iam_graph"] = list(_requirements["least_privilege"])

ANALYSIS_CHECKS = [
    {"id": "analysis.grant_review", "category": "least_privilege", "title": "Review high-impact or broad declared grants", "severity": "high"},
    {"id": "analysis.inactive_identity", "category": "least_privilege", "title": "Review identity with no activity in the observed window", "severity": "low"},
    {"id": "analysis.principal_exposure", "category": "exposure", "title": "Review public or external principal declarations", "severity": "high"},
    {"id": "analysis.network_review", "category": "exposure", "title": "Review unrestricted network rule candidates", "severity": "high"},
    {"id": "analysis.coverage", "category": "least_privilege", "title": "Analysis inventory context incomplete", "severity": "info"},
]
for _check in ANALYSIS_CHECKS:
    _check.update({"provider": "all", "type": "projection", "frameworks": list(FRAMEWORKS),
        "mapping": {"hacktricks": "Defensive identity and network review"},
        "remediation": "Review missing context with the owner before changing permissions or network policy."})


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
    # Unknown coverage never becomes a clean bill of health. Empty, completely
    # enumerated collections are not equivalent to missing/denied collections.
    expected = REQUIRED_TYPES[snapshot["provider"]]["least_privilege"]
    for scope in snapshot["scopes"]:
        present = {c["type"]: c for c in snapshot["collections"] if c["scope"] == scope}
        gaps = [{"type": kind, "status": present.get(kind, {}).get("status", "not_collected")}
                for kind in expected if present.get(kind, {}).get("status") not in {"collected", "empty"}]
        if gaps:
            placeholder = {"id": "inventory", "type": "inventory", "scope": scope,
                           "provider": snapshot["provider"], "service": "iam", "data": {}}
            results.append(finding(snapshot, placeholder, "least_privilege", "analysis.coverage",
                "Analysis inventory context incomplete", "info", {"gaps": gaps, "risk_state": "unknown"}, status="UNKNOWN"))
    return sorted(results, key=lambda f: (RANK[f["severity"]], f["check_id"], f["scope"], f["resource_id"]))


@with_analysis_context
def build_graphs(snapshot, resources, index=None, *, max_nodes=500):
    graphs = {}
    for kind, builder in (("network", build_network), ("iam", build_iam)):
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
                    if current["id"] not in merged_nodes or current.get("evidence", {}).get("native_resource"):
                        merged_nodes[current["id"]] = current
                merged_edges.update({e["id"]: e for e in partial["edges"]})
            graph.update(nodes=list(merged_nodes.values()), edges=list(merged_edges.values()))
        graphs[kind] = project_graph(graph, max_nodes)
    return graphs


def analyze(snapshot, categories=None):
    from peaso.snapshot import resources, validate
    snapshot = validate(snapshot)
    inventory = resources(snapshot)
    with analysis_context(snapshot):
        findings = analyze_findings(snapshot, inventory)
        graphs = build_graphs(snapshot, inventory)
    selected = set(categories) if categories is not None else {"least_privilege", "exposure", "iam_graph", "network"}
    return {"findings": [f for f in findings if f["category"] in selected],
            "graphs": {"network": graphs["network"] if "network" in selected else {"nodes": [], "edges": []},
                       "iam": graphs["iam"] if "iam_graph" in selected else {"nodes": [], "edges": []}},
            "resources": inventory}


__all__ = ["analyze", "analyze_findings", "analysis_context", "build_graphs", "filter_graph", "project_graph", "ANALYSIS_CHECKS", "REQUIRED_TYPES"]
