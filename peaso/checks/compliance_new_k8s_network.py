"""Two signed, per-policy Kubernetes ingress declaration checks.

These evaluate an observed NetworkPolicy allow rule. They do not establish CNI
support, effective policy union, selected Pod identity, or actual reachability.
"""
from __future__ import annotations

from ipaddress import ip_network

from . import register, result, unknown
from .facts import Unavailable, get, list_of_objects, optional
from .fixtures import CASES

IDS = ["k8s_networkpolicy_no_world_ingress", "k8s_networkpolicy_no_world_ssh_rdp"]
_DOC = "https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/"


def _selector(selector):
    if not isinstance(selector, dict) or set(selector) - {"matchLabels", "matchExpressions", "_coverage", "_provenance"}:
        raise Unavailable("malformed NetworkPolicy label selector")
    labels = optional(selector, "matchLabels", {}, dict)
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in labels.items()):
        raise Unavailable("malformed NetworkPolicy selector labels")
    for expression in list_of_objects(optional(selector, "matchExpressions", [], list)):
        operator = get(expression, "operator", str)
        key = get(expression, "key", str)
        values = optional(expression, "values", [], list)
        if (not key or operator not in ("In", "NotIn", "Exists", "DoesNotExist")
                or any(type(v) is not str for v in values)
                or (operator in ("In", "NotIn") and not values)
                or (operator in ("Exists", "DoesNotExist") and values)):
            raise Unavailable("malformed NetworkPolicy selector expression")


def _peer_world(peer):
    if not isinstance(peer, dict) or set(peer) - {"ipBlock", "podSelector", "namespaceSelector", "_coverage", "_provenance"}:
        raise Unavailable("malformed NetworkPolicy peer")
    if peer and not set(peer) - {"_coverage", "_provenance"}:
        raise Unavailable("incomplete NetworkPolicy peer")
    if not peer:
        # Kubernetes ValidateNetworkPolicyPeer rejects a peer with no selector
        # or ipBlock. The signed proposal's empty-peer interpretation needs
        # correction; an invalid object is not a proven all-source allow.
        raise Unavailable("empty NetworkPolicy peer has no valid selector")
    has_ip = "ipBlock" in peer
    if has_ip and set(peer) & {"podSelector", "namespaceSelector"}:
        raise Unavailable("NetworkPolicy ipBlock conflicts with selectors")
    if not has_ip:
        for field in set(peer) & {"podSelector", "namespaceSelector"}:
            _selector(get(peer, field, dict))
        return False
    block = get(peer, "ipBlock", dict)
    if set(block) - {"cidr", "except", "_coverage", "_provenance"}:
        raise Unavailable("malformed NetworkPolicy ipBlock")
    try:
        cidr = ip_network(get(block, "cidr", str), strict=False)
        exclusions = optional(block, "except", [], list)
        if any(type(value) is not str for value in exclusions):
            raise ValueError("non-string ipBlock exception")
        parsed = [ip_network(value, strict=False) for value in exclusions]
        if any(other.version != cidr.version or not other.subnet_of(cidr) or other.prefixlen <= cidr.prefixlen
               for other in parsed):
            raise ValueError("exception outside ipBlock")
    except ValueError as exc:
        raise Unavailable("malformed NetworkPolicy CIDR or exception") from exc
    return cidr.prefixlen == 0 and not parsed


def _world_source(rule):
    if set(rule) - {"from", "ports", "_coverage", "_provenance"}:
        raise Unavailable("malformed NetworkPolicy ingress rule")
    peers = optional(rule, "from", [], list)
    if not peers:
        return True  # Kubernetes documents an absent/empty from as all sources.
    found, uncertain = False, False
    for peer in peers:
        try:
            found = _peer_world(peer) or found
        except Unavailable:
            uncertain = True
    if uncertain and not found:
        raise Unavailable("unresolved NetworkPolicy source peer")
    return found


def _tcp_remote_admin(rule):
    ports = optional(rule, "ports", [], list)
    if not ports:
        return True, False  # Omitted/empty ports admit all destination ports.
    found, uncertain = False, False
    for entry in list_of_objects(ports):
        try:
            if set(entry) - {"port", "protocol", "endPort", "_coverage", "_provenance"}:
                raise Unavailable("malformed NetworkPolicy port entry")
            protocol = optional(entry, "protocol", "TCP", str)
            if protocol not in ("TCP", "UDP", "SCTP"):
                raise Unavailable("unrecognized NetworkPolicy port protocol")
            if "port" not in entry and "endPort" not in entry:
                found = found or protocol == "TCP"
                continue
            start = get(entry, "port")
            if isinstance(start, str):
                if not start or "endPort" in entry:
                    raise Unavailable("malformed named NetworkPolicy port")
                uncertain = uncertain or protocol == "TCP"
                continue
            if type(start) is not int or not 1 <= start <= 65535:
                raise Unavailable("malformed NetworkPolicy port")
            end = optional(entry, "endPort", start, int)
            if end < start or end > 65535:
                raise Unavailable("malformed NetworkPolicy port range")
            found = found or protocol == "TCP" and (start <= 22 <= end or start <= 3389 <= end)
        except Unavailable:
            uncertain = True
    if uncertain and not found:
        raise Unavailable("unresolved NetworkPolicy port entry")
    return found, uncertain


def _ingress_rules(item):
    spec = get(item, "spec", dict)
    types = get(spec, "policyTypes", list)
    if not types or any(t not in ("Ingress", "Egress") for t in types) or len(types) != len(set(types)):
        raise Unavailable("missing or malformed NetworkPolicy policyTypes")
    if "Ingress" not in types:
        return None
    return list_of_objects(get(spec, "ingress", list))


@register(IDS[0], "k8s", "network", "networkpolicy",
          "Observed NetworkPolicy ingress avoids omitted peers and unexcepted /0 IP blocks", "medium", "CM-6",
          "With the policy owner, replace an all-source ingress peer with reviewed Pod/namespace selectors or bounded CIDRs in the owned manifest; test expected traffic and roll back that manifest revision if required paths fail.",
          dependencies=["networkpolicy"])
def no_world_ingress(item, index):
    rules = _ingress_rules(item)
    if rules is None:
        return "NOT_APPLICABLE", {"reason": "observed policy does not select ingress"}
    world, uncertain = [], False
    for number, rule in enumerate(rules):
        try:
            if _world_source(rule):
                world.append(number)
        except Unavailable:
            uncertain = True
    if world:
        return result(True, all_source_rules=world,
                      semantics="Per-policy declared allow only; selected Pods, CNI enforcement and effective policy union unproved")
    if uncertain:
        return unknown("one or more ingress peer declarations malformed or unavailable")
    return result(False, assessed_rules=len(rules),
                  semantics="Per-policy declared allow only; selected Pods, CNI enforcement and effective policy union unproved")


@register(IDS[1], "k8s", "network", "networkpolicy",
          "Observed NetworkPolicy avoids omitted or /0-source TCP 22/3389 rules", "high", "CM-6",
          "With the policy owner, narrow the all-source ingress peer or remove TCP 22/3389 from the owned NetworkPolicy rule after workload review; test required administration paths and roll back the manifest revision if needed.",
          dependencies=["networkpolicy"])
def no_world_remote_admin(item, index):
    rules = _ingress_rules(item)
    if rules is None:
        return "NOT_APPLICABLE", {"reason": "observed policy does not select ingress"}
    broad, uncertain = [], False
    for number, rule in enumerate(rules):
        try:
            world = _world_source(rule)
            port, named_unknown = _tcp_remote_admin(rule)
            if world and port:
                broad.append(number)
            elif world and named_unknown:
                uncertain = True
        except Unavailable:
            uncertain = True
    if broad:
        return result(True, all_source_tcp_remote_admin_rules=broad,
                      semantics="Per-policy declared allow only; no actual service listener, CNI enforcement or reachability inferred")
    if uncertain:
        return unknown("one or more ingress peer/port declarations malformed or unresolved")
    return result(False, assessed_rules=len(rules),
                  semantics="Per-policy declared allow only; no actual service listener, CNI enforcement or reachability inferred")


CASES[IDS[0]] = {
    "pass": {"spec": {"policyTypes": ["Ingress"], "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}]}},
    "fail": {"spec": {"policyTypes": ["Ingress"], "ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]}},
    "missing": {"spec": {"policyTypes": ["Ingress"]}},
    "malformed": {"spec": {"policyTypes": ["Ingress"], "ingress": "bad"}},
}
CASES[IDS[1]] = {
    "pass": {"spec": {"policyTypes": ["Ingress"], "ingress": [{"from": [], "ports": [{"protocol": "TCP", "port": 443}]}]}},
    "fail": {"spec": {"policyTypes": ["Ingress"], "ingress": [{"from": [], "ports": [{"protocol": "TCP", "port": 22}]}]}},
    "missing": {"spec": {"policyTypes": ["Ingress"]}},
    "malformed": {"spec": {"policyTypes": ["Ingress"], "ingress": [{"from": [], "ports": "bad"}]}},
}
