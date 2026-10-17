"""Offline network-only directive13 regressions; no evaluator or privilege hooks."""
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote

import pytest

from peaso.analysis.common import analysis_context, node_id
from peaso.analysis.internet_exposure import annotate_network
from peaso.analysis.network import build_network
from peaso.snapshot import make_snapshot, resources, validate


def native(kind, name, *, namespace="qa-net", cluster="cluster-a", **fields):
    namespace = "_cluster" if kind == "node" else namespace
    identity = "k8s://" + "/".join(quote(x, safe="") for x in (cluster, kind, namespace, name + "-uid"))
    return {"id": identity, "metadata": {"name": name, "uid": name + "-uid",
            **({"namespace": namespace} if namespace != "_cluster" else {})},
            "provenance": {"cluster_id": cluster, "namespace": namespace}, **fields}


def snapshot(facts, *, statuses=None, cluster="cluster-a"):
    return make_snapshot("k8s", sorted({scope for _, scope in facts}), [
        {"type": kind, "scope": scope, "status": (statuses or {}).get((kind, scope), "collected" if items else "empty"),
         "items": items} for (kind, scope), items in facts.items()],
        created_at="2026-10-10T00:00:00+00:00", metadata={"cluster_id": cluster} if cluster else {})


def project(snap, *, exposure=False):
    inventory = resources(snap)
    before = json.dumps(snap, sort_keys=True)
    with analysis_context(snap):
        graph = build_network(snap, inventory)
        if exposure:
            graph = annotate_network(graph, snap, inventory)
    assert json.dumps(snap, sort_keys=True) == before
    return graph


def matched_names(graph, selector):
    nodes = {n["id"]: n for n in graph["nodes"]}
    return {nodes[e["target"]]["label"] for e in graph["edges"]
            if e["type"] == "matches_pod" and e["source"] == selector["id"]}


def selector_for(graph, name):
    owner = next(n for n in graph["nodes"] if n["label"] == name)
    selected = next(e["target"] for e in graph["edges"]
                    if e["source"] == owner["id"] and e["type"] == "declared_selector")
    return next(n for n in graph["nodes"] if n["id"] == selected)


def pod(name, labels, **context):
    value = native("pod", name, **context)
    value["metadata"]["labels"] = labels
    return value


def test_service_path_reaches_only_exact_cluster_namespace_and_equality_match():
    service = native("service", "lb-open", spec={"type": "LoadBalancer", "selector": {"app": "front", "tier": "web"},
                     "ports": [{"port": 80, "targetPort": 8080}]})
    snap = snapshot({("service", "*"): [service], ("pod", "*"): [
        pod("app", {"app": "front", "tier": "web", "extra": "ok"}),
        pod("wrong-case", {"app": "Front", "tier": "web"}),
        pod("missing-label", {"app": "front"}),
        pod("wrong-ns", {"app": "front", "tier": "web"}, namespace="other"),
        pod("wrong-cluster", {"app": "front", "tier": "web"}, cluster="cluster-b")],
        ("pod", "qa-net"): [pod("wrong-scope", {"app": "front", "tier": "web"})]})
    graph = project(snap, exposure=True)
    selector = selector_for(graph, "lb-open")
    assert matched_names(graph, selector) == {"app"}
    assert selector["evidence"]["matched_pod_count"] == 1
    service_node = next(n for n in graph["nodes"] if n["label"] == "lb-open")
    assert any(e["type"] == "internet_exposure" and e["target"] == service_node["id"] for e in graph["edges"])
    match = next(e for e in graph["edges"] if e["type"] == "matches_pod")
    assert match["layer"] == "structural"
    assert match["evidence"]["reachability"] == "unknown"
    assert match["evidence"]["pod_source"]["path"] == "metadata.labels"
    assert "exposure" not in next(n for n in graph["nodes"] if n["label"] == "app")


@pytest.mark.parametrize("selector,expected", [
    ({"matchLabels": {"app": "front"}}, {"front", "both"}),
    ({"matchExpressions": [{"key": "app", "operator": "In", "values": ["front"]}]}, {"front", "both"}),
    ({"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["front"]}]}, {"back", "absent"}),
    ({"matchExpressions": [{"key": "app", "operator": "Exists"}]}, {"front", "both", "back"}),
    ({"matchExpressions": [{"key": "app", "operator": "DoesNotExist"}]}, {"absent"}),
    ({"matchLabels": {"app": "front"}, "matchExpressions": [{"key": "tier", "operator": "In", "values": ["web"]}]}, {"both"}),
    ({}, {"front", "both", "back", "absent"}),
    ({"matchLabels": {}, "matchExpressions": []}, {"front", "both", "back", "absent"}),
])
def test_networkpolicy_label_and_expression_semantics(selector, expected):
    policy = native("networkpolicy", "policy", spec={"podSelector": selector, "ingress": []})
    graph = project(snapshot({("networkpolicy", "*"): [policy], ("pod", "*"): [
        pod("front", {"app": "front"}), pod("both", {"app": "front", "tier": "web"}),
        pod("back", {"app": "back"}), pod("absent", {}),
        pod("other-ns", {"app": "front", "tier": "web"}, namespace="other"),
        pod("other-cluster", {"app": "front", "tier": "web"}, cluster="cluster-b")]}))
    assert matched_names(graph, selector_for(graph, "policy")) == expected
    assert not any(e["type"] == "rule_candidate" for e in graph["edges"])


def test_empty_service_does_not_alias_empty_policy_or_select_all_pods():
    snap = snapshot({("service", "*"): [native("service", "empty", spec={"selector": {}}),
                    native("service", "missing", spec={})],
                    ("networkpolicy", "*"): [native("networkpolicy", "all", spec={"podSelector": {}})],
                    ("pod", "*"): [pod("app", {})]})
    graph = project(snap)
    service, policy = selector_for(graph, "empty"), selector_for(graph, "all")
    assert service["id"] != policy["id"]
    assert matched_names(graph, service) == set()
    assert matched_names(graph, policy) == {"app"}
    assert service["evidence"]["matching_workloads"] == "no_automatic_selection"
    missing = next(n for n in graph["nodes"] if n["label"] == "missing")
    assert not any(e["source"] == missing["id"] and e["type"] == "declared_selector" for e in graph["edges"])


@pytest.mark.parametrize("selector", [
    None, [], {"app": "front"}, {"matchLabels": None}, {"matchLabels": {"app": 1}},
    {"matchExpressions": {}}, {"matchExpressions": [None]},
    {"matchExpressions": [{"key": "app", "operator": "Gt", "values": ["1"]}]},
    {"matchExpressions": [{"key": "app", "operator": ["In"], "values": ["front"]}]},
    {"matchExpressions": [{"key": "app", "operator": "In", "values": []}]},
    {"matchExpressions": [{"key": "app", "operator": "NotIn", "values": "front"}]},
    {"matchExpressions": [{"key": "app", "operator": "Exists", "values": ["front"]}]},
    {"matchExpressions": [{"key": "app", "operator": "DoesNotExist", "values": ["front"]}]},
    {"matchExpressions": [{"key": "app", "operator": "In", "values": ["front"], "unknown": True}]},
])
def test_unsupported_networkpolicy_selector_remains_unknown(selector):
    graph = project(snapshot({("networkpolicy", "*"): [native("networkpolicy", "policy", spec={"podSelector": selector})],
                              ("pod", "*"): [pod("app", {"app": "front"})]}))
    selected = selector_for(graph, "policy")
    assert selected["evidence"]["matching_workloads"] == "unknown"
    assert selected["evidence"]["reason"]
    assert selected["evidence"]["reachability"] == "unknown"
    assert matched_names(graph, selected) == set()


def test_selector_details_labels_shared_expansion_and_unmatched_evidence():
    graph = project(snapshot({("service", "*"): [
        native("service", "front", spec={"selector": {"app": "front"}}),
        native("service", "front-again", spec={"selector": {"app": "front"}}),
        native("service", "back", spec={"selector": {"app": "back"}})],
        ("pod", "*"): [pod("app", {"app": "front"})]}))
    front, back = selector_for(graph, "front"), selector_for(graph, "back")
    assert front["id"] == selector_for(graph, "front-again")["id"]
    assert front["label"] != back["label"]
    assert '"app":"front"' in front["label"]
    assert front["card"]["selector"] == front["evidence"]["selector"] == {"app": "front"}
    assert len([e for e in graph["edges"] if e["type"] == "matches_pod"]) == 1
    assert back["evidence"]["matched_pod_count"] == 0
    assert back["evidence"]["reachability"] == "unknown"


@pytest.mark.parametrize("gap", ["cluster", "namespace", "conflicting_cluster", "conflicting_namespace"])
def test_missing_or_conflicting_selector_context_never_defaults_to_namespace(gap):
    service = native("service", "service", spec={"selector": {"app": "front"}})
    if gap == "cluster":
        service.pop("id")
        service["provenance"].pop("cluster_id")
    elif gap == "namespace":
        service.pop("id")
        service["metadata"].pop("namespace")
        service["provenance"].pop("namespace")
    elif gap == "conflicting_cluster":
        service["provenance"]["cluster_id"] = "cluster-b"
    else:
        service["metadata"]["namespace"] = "other"
    graph = project(snapshot({("service", "*"): [service], ("pod", "*"): [pod("app", {"app": "front"})]}, cluster=None))
    selected = selector_for(graph, "service")
    assert selected["evidence"]["matching_workloads"] == "unknown"
    assert matched_names(graph, selected) == set()


def interface(owner, *, cluster=None, **fields):
    return {"id": owner["id"] + "/observed-addresses", "resource_id": owner["id"],
            "addresses": [{"ip": "10.0.0.1"}, {"ip": "2001:db8::1"}],
            "provenance": {"cluster_id": cluster or owner["provenance"]["cluster_id"],
                           "authoritative_interface_inventory": False}, **fields}


def test_interfaces_use_native_owners_and_preserve_overlapping_dual_stack_addresses():
    first, second, node = pod("first", {}), pod("second", {}), native("node", "worker")
    interfaces = [interface(owner) for owner in (first, second, node)]
    interfaces[-1]["addresses"] = [{"address": "10.0.0.1", "type": "InternalIP"},
                                  {"address": "2001:db8::1", "type": "InternalIP"},
                                  {"address": "worker", "type": "Hostname"}]
    snap = snapshot({("pod", "*"): [first, second], ("node", "*"): [node], ("network_interface", "*"): interfaces})
    graph = project(snap)
    ids = {r["data"]["id"]: node_id(r) for r in resources(snap)}
    for value in interfaces:
        current = next(n for n in graph["nodes"] if n["id"] == ids[value["id"]])
        assert current["evidence"]["addresses"] == current["card"]["addresses"] == value["addresses"]
        assert current["evidence"]["attachment"]["owner_node_id"] == ids[value["resource_id"]]
        assert current["evidence"]["authoritative_interface_inventory"] is False
        assert current["evidence"]["reachability"] == "unknown"
        assert any(e["type"] == "attached_interface" and e["source"] == ids[value["resource_id"]]
                   and e["target"] == current["id"] for e in graph["edges"])
    assert len({n["id"] for n in graph["nodes"] if n["type"] == "network_interface"}) == 3


@pytest.mark.parametrize("gap", ["missing_owner", "missing_id", "different_scope", "different_cluster", "conflicting_namespace", "name_only"])
def test_unresolved_interfaces_keep_addresses_and_explicit_reason(gap):
    owner = pod("app", {})
    value = interface(owner)
    scope = "*"
    if gap == "missing_owner":
        value["resource_id"] = value["resource_id"].replace("app-uid", "uncollected-uid")
    elif gap == "missing_id":
        value.pop("resource_id")
    elif gap == "different_scope":
        scope = "qa-net"
    elif gap == "different_cluster":
        value = interface(owner, cluster="cluster-b")
    elif gap == "conflicting_namespace":
        value["metadata"] = {"namespace": "other"}
    else:
        value["resource_id"] = "app"
    graph = project(snapshot({("pod", scope): [owner], ("network_interface", "*"): [value]}))
    current = next(n for n in graph["nodes"] if n["type"] == "network_interface")
    assert current["evidence"]["attachment"]["status"] == "unresolved"
    assert current["evidence"]["attachment"]["reason"]
    assert current["evidence"]["addresses"] == value["addresses"]
    assert not any(e["type"] == "attached_interface" and e["target"] == current["id"] for e in graph["edges"])


def test_partial_inventory_and_malformed_labels_preserve_uncertainty():
    snap = snapshot({("service", "*"): [native("service", "service", spec={"selector": {"app": "front"}})],
                     ("pod", "*"): [pod("valid", {"app": "front"}), pod("malformed", None)]},
                    statuses={("pod", "*"): "partial"})
    graph = project(snap)
    selected = selector_for(graph, "service")
    assert selected["evidence"]["pod_inventory_status"] == "partial"
    assert selected["evidence"]["matching_workloads"] == "partial"
    assert matched_names(graph, selected) == {"valid"}
    assert selected["evidence"]["reachability"] == "unknown"


@pytest.mark.parametrize("status", ["denied", "not_collected", "unknown"])
def test_unavailable_pod_inventory_is_unknown(status):
    graph = project(snapshot({("service", "*"): [native("service", "service", spec={"selector": {"app": "front"}})],
                              ("pod", "*"): []}, statuses={("pod", "*"): status}))
    selected = selector_for(graph, "service")
    assert selected["evidence"]["matching_workloads"] == "unknown"
    assert selected["evidence"]["reason"] == "pod_inventory_incomplete"
    assert matched_names(graph, selected) == set()


def test_unresolved_pod_context_does_not_link_or_hide_incomplete_matching():
    broken = pod("broken", {"app": "front"})
    broken["provenance"]["cluster_id"] = "conflicting-cluster"
    graph = project(snapshot({("service", "*"): [native("service", "service", spec={"selector": {"app": "front"}})],
                              ("pod", "*"): [broken, pod("valid", {"app": "front"})]}))
    selected = selector_for(graph, "service")
    assert selected["evidence"]["matching_workloads"] == "partial"
    assert selected["evidence"]["reason"] == "some_pod_context_is_unavailable_or_conflicting"
    assert matched_names(graph, selected) == {"valid"}


@pytest.mark.parametrize("selector", [None, [], {"app": True}, {"matchLabels": {"app": "front"}}])
def test_malformed_service_selector_never_becomes_a_policy_selector(selector):
    graph = project(snapshot({("service", "*"): [native("service", "service", spec={"selector": selector})],
                              ("pod", "*"): [pod("app", {"app": "front"})]}))
    selected = selector_for(graph, "service")
    assert selected["evidence"]["matching_workloads"] == "unknown"
    assert matched_names(graph, selected) == set()


def cloud_graph(provider, facts):
    snap = make_snapshot(provider, sorted({scope for _, scope in facts}), [
        {"type": kind, "scope": scope, "status": "collected", "items": items}
        for (kind, scope), items in facts.items()], created_at="2026-10-10T00:00:00+00:00")
    return project(snap)


def test_aws_attachment_policy_and_unresolved_scoped_reference_behavior_is_preserved():
    graph = cloud_graph("aws", {
        ("vpc", "account-a/region"): [{"VpcId": "vpc-a"}],
        ("subnet", "account-a/region"): [{"SubnetId": "subnet-a", "VpcId": "vpc-a"}],
        ("network_interface", "account-a/region"): [{"NetworkInterfaceId": "eni-a", "SubnetId": "subnet-a", "VpcId": "vpc-a", "Groups": [{"GroupId": "sg-a"}]}],
        ("instance", "account-a/region"): [{"InstanceId": "i-a", "NetworkInterfaces": [{"NetworkInterfaceId": "eni-a"}]}],
        ("security_group", "account-a/region"): [{"GroupId": "sg-a", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}],
        ("vpc_peering", "account-a/region"): [{"id": "peer-a", "AccepterVpcInfo": {"VpcId": "vpc-a", "OwnerId": "account-b", "Region": "region"}}]})
    iface = next(n for n in graph["nodes"] if n["native_id"] == "eni-a")
    subnet = next(n for n in graph["nodes"] if n["native_id"] == "subnet-a")
    assert iface["parent_id"] == subnet["id"]
    assert any(e["type"] == "attached_interface" and e["target"] == iface["id"] for e in graph["edges"])
    assert any(e["type"] == "protected_by" and e["source"] == iface["id"] for e in graph["edges"])
    remote = next(n for n in graph["nodes"] if n["type"] == "vpc" and n["scope"] == "account-b/region")
    assert remote["evidence"]["inventory_status"] == "reference_only"
    rule = next(e for e in graph["edges"] if e["type"] == "rule_candidate")
    assert rule["evidence"]["native_rule"]["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]
    assert rule["evidence"]["reachability"] == "unknown"
    assert "attachment" not in iface["evidence"]  # Native cloud behavior remains in its existing projection.


def test_azure_case_insensitive_native_association_and_parent_behavior_is_preserved():
    prefix = "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/"
    nic, subnet, nsg = prefix + "networkInterfaces/nic-a", prefix + "virtualNetworks/vnet-a/subnets/subnet-a", prefix + "networkSecurityGroups/nsg-a"
    graph = cloud_graph("azure", {
        ("nic", "subscription:sub-a"): [{"id": nic, "properties": {"networkSecurityGroup": {"id": nsg.upper()}, "ipConfigurations": [{"properties": {"subnet": {"id": subnet.upper()}}}]}}],
        ("vm", "subscription:sub-a"): [{"id": "vm-a", "properties": {"networkProfile": {"networkInterfaces": [{"id": nic.upper()}]}}}],
        ("subnet", "subscription:sub-a"): [{"id": subnet}],
        ("nsg", "subscription:sub-a"): [{"id": nsg, "properties": {"securityRules": [{"properties": {"access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "Internet", "priority": 200}}]}}]})
    current = next(n for n in graph["nodes"] if n["native_id"] == nic)
    target = next(n for n in graph["nodes"] if n["native_id"] == subnet)
    assert current["parent_id"] == target["id"]
    assert len([n for n in graph["nodes"] if n["type"] == "nic"]) == 1
    assert any(e["target"] == current["id"] and e["type"] == "associated_with" for e in graph["edges"])
    assert any(e["type"] == "rule_candidate" and e["evidence"]["reachability"] == "unknown" for e in graph["edges"])


def test_gcp_embedded_interface_shared_network_and_overlapping_scopes_are_preserved():
    host = "https://www.googleapis.com/compute/v1/projects/host/global/networks/shared"
    interface = {"name": "nic0", "network": host, "networkIP": "10.0.0.1", "ipv6Address": "2001:db8::1"}
    graph = cloud_graph("gcp", {
        ("network", "projects/host"): [{"selfLink": host, "name": "shared"}],
        ("network", "projects/service"): [{"selfLink": host.replace("/host/", "/service/"), "name": "shared"}],
        ("instance", "projects/service"): [{"name": "vm", "networkInterfaces": [interface]}]})
    networks = [n for n in graph["nodes"] if n["type"] == "network"]
    assert len(networks) == len({n["id"] for n in networks}) == 2
    current = next(n for n in graph["nodes"] if n["type"] == "network_interface")
    target = next(n for n in networks if n["scope"] == "projects/host")
    assert current["parent_id"] == target["id"]
    assert current["evidence"]["native_resource"] == interface
    assert target["provider_specific"]["network_scope"] == "global"
    assert any(e["type"] == "attached_interface" and e["target"] == current["id"] for e in graph["edges"])


def test_captured_native_k8s_snapshot_directive13_recheck():
    fixture = os.environ.get("K8S_NETWORK_QA_SNAPSHOT")
    if not fixture:
        pytest.skip("Set K8S_NETWORK_QA_SNAPSHOT to the immutable native directive13 snapshot")
    path = Path(fixture)
    original = path.read_bytes()
    assert hashlib.sha256(original).hexdigest() == "47fb2b55ceb6cd67199960a2b5fffb397d587b162f4a5b4520f5b801bf612783"
    snap = validate(json.loads(original))
    graph = project(snap, exposure=True)
    selected = selector_for(graph, "lb-open")
    assert matched_names(graph, selected) == {"app"}
    lb = next(n for n in graph["nodes"] if n["label"] == "lb-open")
    assert any(e["type"] == "internet_exposure" and e["target"] == lb["id"] for e in graph["edges"])
    interfaces = [n for n in graph["nodes"] if n["type"] == "network_interface"]
    assert len(interfaces) == 20
    for current in interfaces:
        assert current["evidence"]["attachment"]["status"] == "resolved"
        assert any(e["type"] == "attached_interface" and e["target"] == current["id"] for e in graph["edges"])
    selectors = [n for n in graph["nodes"] if n["type"] == "workload_selector"]
    assert len(selectors) == len({n["label"] for n in selectors}) == 5
    assert sum(n["evidence"]["matched_pod_count"] for n in selectors) == 6
    assert all(n["card"]["selector"] == n["evidence"]["selector"] for n in selectors)
    assert path.read_bytes() == original
