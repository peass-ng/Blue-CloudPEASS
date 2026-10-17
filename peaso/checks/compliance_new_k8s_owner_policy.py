"""Signed owner-specific Kubernetes declaration checks over collected API facts.

The owner policy is a bounded, cluster-bound snapshot declaration. These
checks do not infer effective exposure, traffic flow, or RBAC authorization.
"""
from __future__ import annotations

from datetime import datetime

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, memoized
from .fixtures import CASES

LABEL_ID = "k8s_namespace_namespace_part_specific_label_set_07ecb6d791"
ROLE_ID = "k8s_namespace_has_rolebinding"
AUTHORIZED_ID = "k8s_service_loadbalancers_associated_authorized_namespace_rule_8b0a04d99f"
TYPE_ID = "k8s_service_services_type_specified_rule_parameter_86993f7594"
SELECTED_ID = "k8s_service_spec_type_loadbalancer"
IDS = (LABEL_ID, ROLE_ID, AUTHORIZED_ID, TYPE_ID, SELECTED_ID)
_SERVICE_TYPES = {"ClusterIP", "NodePort", "LoadBalancer", "ExternalName"}


def _validated_policy(index):
    context = index.get("context")
    if not isinstance(context, dict):
        raise Unavailable("snapshot context unavailable for owner policy")
    metadata = context.get("metadata")
    policy = metadata.get("compliance_policy") if isinstance(metadata, dict) else None
    if not isinstance(policy, dict) or policy.get("status") != "collected":
        raise Unavailable("owner policy unavailable or invalid")
    if not isinstance(policy.get("cluster_id"), str) or policy["cluster_id"] != metadata.get("cluster_id"):
        raise Unavailable("owner policy cluster identity unresolved")
    has_observed, has_age = "observed_at" in policy, "max_age_seconds" in policy
    if has_observed != has_age:
        raise Unavailable("owner policy expiry pair incomplete")
    if has_observed:
        at, age = policy["observed_at"], policy["max_age_seconds"]
        if not isinstance(at, str) or type(age) is not int or age <= 0 or not isinstance(context.get("created_at"), str):
            raise Unavailable("owner policy freshness unresolved")
        try:
            captured = datetime.fromisoformat(context["created_at"].replace("Z", "+00:00"))
            observed = datetime.fromisoformat(at.replace("Z", "+00:00"))
            if captured.tzinfo is None or captured.utcoffset() is None or observed.tzinfo is None or observed.utcoffset() is None:
                raise ValueError("timezone absent")
            elapsed = (captured - observed).total_seconds()
        except ValueError as exc:
            raise Unavailable("owner policy timestamp malformed") from exc
        if not 0 <= elapsed <= age:
            raise Unavailable("owner policy stale or future")
    return policy


def _policy(index, field):
    policy = memoized(index, ("owner_policy_validated",), lambda: _validated_policy(index))
    if field not in policy:
        raise Unavailable("owner policy parameter absent: " + field)
    if field in ("authorized_namespaces", "serviceType", "selected_loadbalancer_services") and (
            policy.get("service_type_conflict") is True
            or policy.get("serviceType") not in (None, "LoadBalancer") and policy.get("selected_loadbalancer_services")):
        raise Unavailable("owner Service type declarations conflict")
    return policy[field]


def _service_identity(item):
    namespace = get(item, "metadata.namespace", str)
    name = get(item, "metadata.name", str)
    uid = get(item, "metadata.uid", str)
    if not namespace or not name or not uid:
        raise Unavailable("Service namespace/name/UID missing")
    return namespace, name, uid


def _service_type(item):
    service_type = get(item, "spec.type", str)
    if service_type not in _SERVICE_TYPES:
        raise Unavailable("unrecognized Service type")
    return service_type


@register(LABEL_ID, "k8s", "hardening", "namespace", "Namespace has the owner-required label pair",
          "medium", "CM-6", "Review the namespace owner policy, then set the approved labels in the owned Namespace manifest and verify dependent selectors.",
          dependencies=["namespace"])
def namespace_labels(item, index):
    expected = _policy(index, "namespace_labels")
    if not isinstance(expected, dict) or set(expected) != {"required_key", "required_value", "master_label_key", "required_master_value"}:
        return unknown("owner label policy malformed")
    name = get(item, "metadata.name", str)
    meta = get(item, "metadata", dict)
    if "labels" in meta or "labels" in meta.get("_coverage", {}):
        labels = get(meta, "labels", dict)
    elif item.get("provenance", {}).get("evidence") == "read-only list":
        labels = {}  # Kubernetes full object LIST omits the map when unset.
    else:
        return unknown("Namespace labels missing from partial representation", namespace=name)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
        return unknown("Namespace labels malformed", namespace=name)
    mismatched = [key for key, value in ((expected["required_key"], expected["required_value"]),
                                         (expected["master_label_key"], expected["required_master_value"]))
                  if labels.get(key) != value]
    return result(bool(mismatched), namespace=name, mismatched_label_keys=sorted(set(mismatched)),
                  semantics="Declared Namespace labels only; selector operation not verified")


@register(ROLE_ID, "k8s", "least_privilege", "namespace", "Owner-selected Namespace has a RoleBinding",
          "medium", "AC-2", "Review intended namespace subjects and Roles with the owner; add an approved scoped RoleBinding only if its absence is unintended.",
          dependencies=["namespace", "rolebinding"])
def namespace_rolebinding(item, index):
    target = _policy(index, "target_namespace")
    if not isinstance(target, str) or not target:
        return unknown("owner target namespace malformed")
    name = get(item, "metadata.name", str)
    if name != target:
        return "NOT_APPLICABLE", {"reason": "Namespace is outside the owner-selected target", "target_namespace": target}

    def inventory():
        names = set()
        for binding in complete_items(index, "rolebinding"):
            namespace = get(binding, "metadata.namespace", str)
            binding_name = get(binding, "metadata.name", str)
            if not namespace or not binding_name:
                raise Unavailable("RoleBinding identity malformed")
            names.add((namespace, binding_name))
        return names

    names = memoized(index, ("owner_policy_rolebindings",), inventory)
    matched = sorted(binding_name for namespace, binding_name in names if namespace == target)
    return result(not matched, namespace=target, observed_rolebindings=matched,
                  semantics="RoleBinding presence only; subject, Role and effective authorization unassessed")


@register(AUTHORIZED_ID, "k8s", "network", "service", "LoadBalancer Service is in an owner-authorized Namespace",
          "medium", "SC-7", "Review the owner-approved namespace list and Service exposure; change the owned Service or approval policy only after traffic and compatibility review.",
          dependencies=["service"])
def authorized_loadbalancer_namespace(item, index):
    allowed = _policy(index, "authorized_namespaces")
    if not isinstance(allowed, list) or not allowed:
        return unknown("owner authorized namespace set malformed")
    def authorized_index():
        if any(not isinstance(value, str) or not value for value in allowed) or len(set(allowed)) != len(allowed):
            raise Unavailable("owner authorized namespace set malformed")
        return frozenset(allowed)
    authorized = memoized(index, ("owner_policy_authorized_namespaces",), authorized_index)
    namespace, name, uid = _service_identity(item)
    service_type = _service_type(item)
    if service_type != "LoadBalancer":
        return "NOT_APPLICABLE", {"reason": "Service is not a LoadBalancer declaration", "observed_type": service_type}
    return result(namespace not in authorized, namespace=namespace, service_name=name, service_uid=uid,
                  observed_type=service_type, authorized_namespace_count=len(authorized), policy_parameter="authorized_namespaces",
                  semantics="Service type and namespace declaration only; external reachability untested")


@register(TYPE_ID, "k8s", "network", "service", "Service declares its owner-required type",
          "medium", "CM-6", "Review the required Service type with its owner and change the owned manifest only after assessing availability and exposure impact.",
          dependencies=["service"])
def required_service_type(item, index):
    required = _policy(index, "serviceType")
    if required not in _SERVICE_TYPES or not isinstance(required, str):
        return unknown("owner required Service type malformed")
    namespace, name, uid = _service_identity(item)
    observed = _service_type(item)
    return result(observed != required, namespace=namespace, service_name=name, service_uid=uid,
                  observed_type=observed, required_type=required,
                  semantics="Service type declaration only; endpoint availability and reachability untested")


@register(SELECTED_ID, "k8s", "network", "service", "Owner-selected Service declares LoadBalancer type",
          "medium", "CM-6", "Confirm the owner-approved Service identity and intended external exposure before changing its type in the owned manifest.",
          target="scope", dependencies=["service"])
def selected_loadbalancer_type(item, index):
    selected = _policy(index, "selected_loadbalancer_services")
    if not isinstance(selected, list) or not selected:
        return unknown("owner selected Service set malformed")

    def selected_index():
        result = {}
        for row in selected:
            if not isinstance(row, dict):
                raise Unavailable("owner selected Service identity set malformed")
            key = (row.get("namespace"), row.get("name"))
            if not all(isinstance(value, str) and value for value in (*key, row.get("uid"))) or key in result:
                raise Unavailable("owner selected Service identity set malformed or duplicated")
            result[key] = row["uid"]
        return result
    selected_by_name = memoized(index, ("owner_policy_selected_service_identities",), selected_index)
    scope = get(item, "scope", str)
    if scope == "*":
        in_scope = selected_by_name
    else:
        in_scope = {key: uid for key, uid in selected_by_name.items() if key[0] == scope}
    outside_count = len(selected_by_name) - len(in_scope)

    def observed_index():
        observed = {}
        for service in complete_items(index, "service"):
            namespace, name, uid = _service_identity(service)
            key = (namespace, name)
            if scope != "*" and namespace != scope:
                raise Unavailable("Service inventory contains a foreign namespace")
            if key in observed:
                raise Unavailable("duplicate Service identity in complete inventory")
            observed[key] = (uid, service)
        return observed
    observed_by_name = memoized(index, ("owner_policy_services_by_identity",), observed_index)
    missing, changed, wrong, assessed = [], [], [], 0
    for (namespace, name), expected_uid in in_scope.items():
        identity = {"namespace": namespace, "name": name, "selected_uid": expected_uid}
        actual = observed_by_name.get((namespace, name))
        if actual is None:
            missing.append(identity)
        elif actual[0] != expected_uid:
            changed.append({**identity, "observed_uid": actual[0]})
        else:
            try:
                observed_type = _service_type(actual[1])
            except Unavailable:
                changed.append({**identity, "reason": "type_unknown"})
                continue
            assessed += 1
            if observed_type != "LoadBalancer":
                wrong.append({**identity, "observed_type": observed_type})
    counts = {"selected_count": len(selected_by_name), "assessed_count": assessed,
              "missing_count": len(missing), "changed_or_unreadable_count": len(changed),
              "wrong_type_count": len(wrong), "outside_scanned_scope_count": outside_count,
              "required_type": "LoadBalancer", "semantics": "Owner-selected Service declarations only; external reachability untested"}
    # Keep findings bounded for large owner selections. The exact owner set is
    # stored once in snapshot metadata and remains available for drilldown.
    if wrong:
        return result(True, **counts, wrong_type_examples=wrong[:20])
    if missing or changed or outside_count:
        return unknown("selected Service identities are missing, changed or outside scanned scope",
                       **counts, missing_examples=missing[:20], changed_examples=changed[:20])
    return result(False, **counts)


_CONTEXT = {"context": {"created_at": "2026-10-12T00:00:00Z", "metadata": {"cluster_id": "fixture",
            "compliance_policy": {"status": "collected", "cluster_id": "fixture", "observed_at": "2026-10-12T00:00:00Z",
                                  "max_age_seconds": 600, "namespace_labels": {"required_key": "team", "required_value": "platform",
                                  "master_label_key": "owner", "required_master_value": "core"}, "target_namespace": "apps",
                                  "authorized_namespaces": ["apps"], "serviceType": "LoadBalancer",
                                  "selected_loadbalancer_services": [{"namespace": "apps", "name": "web", "uid": "uid-web"}]}}}}
_SERVICE = {"metadata": {"namespace": "apps", "name": "web", "uid": "uid-web"}, "spec": {"type": "LoadBalancer"}}
CASES[LABEL_ID] = {"pass": {"metadata": {"name": "apps", "labels": {"team": "platform", "owner": "core"}}},
                   "fail": {"metadata": {"name": "apps", "labels": {"team": "other", "owner": "core"}}},
                   "missing": {"metadata": {"name": "apps"}}, "index": _CONTEXT}
CASES[ROLE_ID] = {"pass": {"metadata": {"name": "apps"}}, "fail": {"metadata": {"name": "apps"}},
                  "missing": {"metadata": {}}, "index": {**_CONTEXT,
                  "collections": {"rolebinding": [{"status": "collected"}]},
                  "rolebinding": [{"data": {"metadata": {"namespace": "apps", "name": "viewer"}}}]},
                  "pass_index": {**_CONTEXT,
                  "collections": {"rolebinding": [{"status": "collected"}]},
                  "rolebinding": [{"data": {"metadata": {"namespace": "apps", "name": "viewer"}}}]},
                  "fail_index": {**_CONTEXT,
                  "collections": {"rolebinding": [{"status": "empty"}]}, "rolebinding": []}}
CASES[AUTHORIZED_ID] = {"pass": _SERVICE,
                         "fail": {"metadata": {"namespace": "other", "name": "web", "uid": "uid-other"}, "spec": {"type": "LoadBalancer"}},
                         "missing": {"metadata": {"namespace": "apps", "name": "web", "uid": "uid-web"}}, "index": _CONTEXT}
CASES[TYPE_ID] = {"pass": _SERVICE,
                  "fail": {"metadata": {"namespace": "apps", "name": "web", "uid": "uid-web"}, "spec": {"type": "NodePort"}},
                  "missing": {"metadata": {"namespace": "apps", "name": "web", "uid": "uid-web"}}, "index": _CONTEXT}
CASES[SELECTED_ID] = {
    "pass": {"scope": "*"}, "fail": {"scope": "*"}, "missing": {"scope": "*"},
    "pass_index": {**_CONTEXT, "collections": {"service": [{"status": "collected"}]},
                   "service": [{"data": _SERVICE}]},
    "fail_index": {**_CONTEXT, "collections": {"service": [{"status": "collected"}]},
                   "service": [{"data": {"metadata": {"namespace": "apps", "name": "web", "uid": "uid-web"},
                                         "spec": {"type": "NodePort"}}}]},
    "missing_index": {**_CONTEXT, "collections": {"service": [{"status": "empty"}]}, "service": []},
}
