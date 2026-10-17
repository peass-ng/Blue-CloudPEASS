"""Additive central behavior cases for the three reviewed native IDs.

This module contains inert fixture data only. Import it from fixtures.py after
CASES is defined; never import a collector or a registry module here.
"""

from copy import deepcopy


def _k8s_row(kind, name, namespace="_cluster"):
    cluster = "fixture-cluster"
    return {
        "id": f"k8s://{cluster}/{kind}/{namespace}/{name}",
        "metadata": {"name": name, **({"namespace": namespace} if kind != "namespace" else {})},
        "provenance": {"cluster_id": cluster, "namespace": namespace, "uid": None},
    }


_K8S_NAMESPACE = _k8s_row("namespace", "apps")
_K8S_POLICY = _k8s_row("networkpolicy", "allow-health", "apps")


def _k8s_index(with_policy):
    scope = "*"
    namespace = deepcopy(_K8S_NAMESPACE)
    policies = [deepcopy(_K8S_POLICY)] if with_policy else []
    def page(kind, rows):
        return {"type": kind, "scope": scope, "status": "collected" if rows else "empty", "items": deepcopy(rows)}
    def wrapper(kind, row):
        return {"type": kind, "scope": scope, "provider": "k8s", "data": deepcopy(row)}
    return {
        "context": {"provider": "k8s", "scope": scope,
                    "metadata": {"cluster_id": "fixture-cluster", "compliance_policy": {
                        "status": "collected", "source": "operator-supplied",
                        "cluster_id": "fixture-cluster", "system_namespaces": ["kube-system"]}}},
        "collections": {"namespace": [page("namespace", [namespace])],
                        "networkpolicy": [page("networkpolicy", policies)]},
        "namespace": [wrapper("namespace", namespace)],
        "networkpolicy": [wrapper("networkpolicy", policy) for policy in policies],
    }


_PROJECT = "projects/fixture"
_ORGANIZATION = "organizations/34"
_PRINCIPAL = "user:auditor@example.test"
_OWNER_OPTION = "gcp_data_access_required_principals"


def _audit_config(service, log_type, exemptions=()):
    return {"service": service, "auditLogConfigs": [{"logType": log_type,
            "exemptedMembers": list(exemptions)}]}


def _gcp_item(project_configs, organization_configs):
    return {"name": _PROJECT,
            "effectiveAuditConfigs": [
                {"scope": _PROJECT, "auditConfigs": deepcopy(project_configs)},
                {"scope": _ORGANIZATION, "auditConfigs": deepcopy(organization_configs)}],
            "_coverage": {"effectiveAuditConfigs": {
                "status": "collected", "ancestry_known": True,
                "missing_scopes": [], "malformed_scopes": [],
                "source_requests": ["request:" + _ORGANIZATION, "request:" + _PROJECT]}}}


def _gcp_index(service):
    return {"context": {"provider": "gcp", "scope": _PROJECT, "metadata": {
                _OWNER_OPTION: [{"status": "approved", "scope": _PROJECT,
                                 "service": service, "source_ref": "owner-approved-fixture",
                                 "principals": [_PRINCIPAL]}]}},
            "collections": {"iam_policy": [{"type": "iam_policy", "scope": _PROJECT,
                                            "status": "collected", "items": []}]}}


_NEXT_CLUSTER = "fixture-cluster"
_NEXT_STAMP = "2026-10-13T20:00:00Z"


def _next_row(kind, name, namespace="apps", **facts):
    namespaced = kind in ("rolebinding", "pod")
    location = namespace if namespaced else "_cluster"
    return {"id": f"k8s://{_NEXT_CLUSTER}/{kind}/{location}/{name}",
            "metadata": {"name": name, **({"namespace": namespace} if namespaced else {})},
            "provenance": {"cluster_id": _NEXT_CLUSTER, "evidence": "read-only list"}, **facts}


def _next_index(rows, policy=None, states=None):
    """Collector-shaped complete pages and matching scoped wrappers."""
    scope = "*"
    context = {"provider": "k8s", "scope": scope, "created_at": _NEXT_STAMP,
               "metadata": {"cluster_id": _NEXT_CLUSTER, "compliance_policy": {
                   "status": "collected", "cluster_id": _NEXT_CLUSTER,
                   "observed_at": _NEXT_STAMP, "max_age_seconds": 300, **(policy or {})}}}
    index = {"context": context, "collections": {}}
    for kind, items in rows.items():
        state = (states or {}).get(kind, "collected" if items else "empty")
        index["collections"][kind] = [{"type": kind, "scope": scope, "status": state,
                                       "items": deepcopy(items)}]
        index[kind] = [{"type": kind, "scope": scope, "provider": "k8s", "data": deepcopy(item)}
                       for item in items]
    return index


def _next_response_policy(subject_kind="Group", subject_name="responders"):
    return {"allowed_namespaces": ["apps"], "required_subject_kind": subject_kind,
            "required_subject_name": subject_name, "required_role_kind": "ClusterRole",
            "required_role_name": "incident-reader"}


def _next_response_binding(subject_kind="Group", subject_name="responders"):
    return _next_row("rolebinding", "response", roleRef={
        "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "incident-reader"},
        subjects=[{"kind": subject_kind, "name": subject_name}])


def install(cases):
    """Install only these exact IDs; leave all existing cases and source tags intact."""
    cases["k8s.cis.namespace_has_networkpolicy"] = {
        "pass": deepcopy(_K8S_NAMESPACE), "pass_index": _k8s_index(True),
        "fail": deepcopy(_K8S_NAMESPACE), "fail_index": _k8s_index(False),
        "unknown": deepcopy(_K8S_NAMESPACE),
        "unknown_index": {**_k8s_index(True), "collections": {
            **_k8s_index(True)["collections"],
            "networkpolicy": [{"type": "networkpolicy", "scope": "*",
                               "status": "denied", "items": []}]}},
        "index": _k8s_index(True), "missing": {}, "malformed": None,
    }
    for check_id, service in (
        ("gcp_pci_iam_policy_ca1281da7ab2", "spanner.googleapis.com"),
        ("gcp_pci_iam_policy_9a8ce875703d", "pubsub.googleapis.com"),
    ):
        shared = _gcp_index(service)
        complete_types = [_audit_config(service, "DATA_WRITE")]
        inherited_read = [_audit_config("allServices", "DATA_READ")]
        cases[check_id] = {
            "pass": _gcp_item(complete_types, inherited_read),
            "fail": (_gcp_item([_audit_config(service, "DATA_READ")], [])
                     if service == "spanner.googleapis.com" else
                     _gcp_item(complete_types,
                               [_audit_config("allServices", "DATA_READ", [_PRINCIPAL])])),
            "unknown": _gcp_item(complete_types, inherited_read),
            "unknown_index": {**deepcopy(shared), "collections": {"iam_policy": [
                {"type": "iam_policy", "scope": _PROJECT, "status": "partial", "items": []}]}},
            "index": shared, "missing": {}, "malformed": None,
        }

        # Each behavior case carries the actual scoped policy source row. A
        # collected-but-empty envelope cannot authenticate the evaluated root.
        for label in ("pass", "fail"):
            bound = deepcopy(shared)
            bound["collections"]["iam_policy"][0]["items"] = [deepcopy(cases[check_id][label])]
            cases[check_id][label + "_index"] = bound

    # This rule has no PASS on complete observed RBAC inventory: absence of a
    # system:masters subject cannot rule out certificate/provider membership.
    masters_fail = _next_index({
        "clusterrolebinding": [], "rolebinding": [_next_row("rolebinding", "masters",
            subjects=[{"kind": "Group", "name": "system:masters"}])]}, {})
    masters_unknown = _next_index({"clusterrolebinding": [], "rolebinding": []}, {})
    cases["k8s.cis.avoid_use_of_system_masters_group"] = {
        "fail": deepcopy(masters_fail["context"]), "fail_index": masters_fail,
        "unknown": deepcopy(masters_unknown["context"]), "unknown_index": masters_unknown,
        "index": deepcopy(masters_unknown), "missing": {}, "malformed": None,
    }

    group_policy = _next_response_policy()
    response_pass = _next_index({"rolebinding": [_next_response_binding()],
                                 "clusterrolebinding": []}, group_policy)
    response_user = _next_index({"rolebinding": [_next_response_binding("User", "responder")],
                                 "clusterrolebinding": []},
                                _next_response_policy("User", "responder"))
    response_fail = _next_index({"rolebinding": [], "clusterrolebinding": []}, group_policy)
    response_unknown = _next_index({"rolebinding": [_next_response_binding("ServiceAccount", "responders")],
                                    "clusterrolebinding": []}, _next_response_policy("ServiceAccount"))
    response_incomplete = _next_index({"rolebinding": [_next_response_binding()],
                                       "clusterrolebinding": []}, group_policy,
                                      {"rolebinding": "partial"})
    cases["k8s_response_team_required_binding"] = {
        "pass": deepcopy(response_pass["context"]), "pass_index": response_pass,
        "pass_user": deepcopy(response_user["context"]), "pass_user_index": response_user,
        "fail": deepcopy(response_fail["context"]), "fail_index": response_fail,
        "unknown": deepcopy(response_unknown["context"]), "unknown_index": response_unknown,
        "unknown_incomplete": deepcopy(response_incomplete["context"]),
        "unknown_incomplete_index": response_incomplete,
        "index": deepcopy(response_pass), "missing": {}, "malformed": None,
    }

    pod_pass = _next_row("pod", "target", "apps")
    pod_fail = _next_row("pod", "target", "other")
    pod_policy = {"approved_namespaces": ["apps"]}
    pod_pass_index = _next_index({"pod": [pod_pass]}, pod_policy)
    pod_fail_index = _next_index({"pod": [pod_fail]}, pod_policy)
    pod_unknown_index = _next_index({"pod": [pod_pass]}, pod_policy, {"pod": "partial"})
    cases["k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b"] = {
        "pass": deepcopy(pod_pass), "pass_index": pod_pass_index,
        "fail": deepcopy(pod_fail), "fail_index": pod_fail_index,
        "unknown": deepcopy(pod_pass), "unknown_index": pod_unknown_index,
        "index": deepcopy(pod_pass_index), "missing": {}, "malformed": None,
    }
