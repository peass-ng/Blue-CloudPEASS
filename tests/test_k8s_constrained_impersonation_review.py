"""Constrained impersonation must add a right of the exact selected identity."""

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import (
    C, crb, crole, k8s_snap, node, pod, sa, user,
)


def _entry(technique):
    return next(item for item in privesc.catalog()["entries"] if item["id"] == technique)


def _run(technique, roles, bindings, *, sas=(), pods=(), nodes=()):
    return privesc.analyze(k8s_snap(clusterroles=roles, crbs=bindings, sas=sas, pods=pods, nodes=nodes),
                           entries=[_entry(technique)])


def test_user_mode_needs_authentication_group_and_matching_target_action():
    technique = "k8s-rbac-constrained-impersonation-user"
    identity = crole("identity", [{"apiGroups": ["authentication.k8s.io"], "resources": ["users"],
                                   "resourceNames": ["admin"], "verbs": ["impersonate:user-info"]}])
    action = crole("action", [{"apiGroups": [""], "resources": ["secrets"],
                               "verbs": ["impersonate-on:user-info:get"]}])
    target = crole("target", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    binds = [crb("identity-bind", "identity", user("dev")), crb("action-bind", "action", user("dev")),
             crb("target-bind", "target", user("admin"))]
    assert reached(_run(technique, [identity, action, target], binds), f"k8s:{C}:user:dev", technique)
    action["rules"][0]["resources"] = ["deployments"]
    assert reached(_run(technique, [identity, action, target], binds), f"k8s:{C}:user:dev", technique) == {}
    action["rules"][0]["resources"] = ["secrets"]
    identity["rules"][0]["apiGroups"] = [""]
    assert reached(_run(technique, [identity, action, target], binds), f"k8s:{C}:user:dev", technique) == {}


def test_serviceaccount_mode_joins_action_to_target_right_and_name():
    technique = "k8s-rbac-constrained-impersonation-serviceaccount"
    identity = crole("identity", [{"apiGroups": ["authentication.k8s.io"], "resources": ["serviceaccounts"],
                                   "resourceNames": ["worker"], "verbs": ["impersonate:serviceaccount"]}])
    action = crole("action", [{"apiGroups": [""], "resources": ["secrets"],
                               "verbs": ["impersonate-on:serviceaccount:get"]}])
    target = crole("target", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    binds = [crb("identity-bind", "identity", user("dev")), crb("action-bind", "action", user("dev")),
             crb("target-bind", "target", {"kind": "ServiceAccount", "name": "worker", "namespace": "a"})]
    output = _run(technique, [identity, action, target], binds, sas=[sa("worker", "a"), sa("other", "a")])
    assert set(reached(output, f"k8s:{C}:user:dev", technique)) == {f"k8s:{C}:sa:a:worker"}
    target["rules"][0]["verbs"] = ["list"]
    assert reached(_run(technique, [identity, action, target], binds, sas=[sa("worker", "a")]),
                   f"k8s:{C}:user:dev", technique) == {}


def test_arbitrary_node_mode_requires_action_on_pod_bound_to_exact_node():
    technique = "k8s-rbac-constrained-impersonation-node"
    identity = crole("identity", [{"apiGroups": ["authentication.k8s.io"], "resources": ["nodes"],
                                   "resourceNames": ["n1"], "verbs": ["impersonate:arbitrary-node"]}])
    action = crole("action", [{"apiGroups": [""], "resources": ["pods"],
                               "verbs": ["impersonate-on:arbitrary-node:get"]}])
    binds = [crb("identity-bind", "identity", user("dev")), crb("action-bind", "action", user("dev"))]
    result = _run(technique, [identity, action], binds, pods=[pod("p1", "a", "worker", node="n1")],
                  nodes=[node("n1"), node("n2")])
    assert set(reached(result, f"k8s:{C}:user:dev", technique)) == {f"k8s:{C}:node:n1"}
    action["rules"][0]["resources"] = ["deployments"]
    assert reached(_run(technique, [identity, action], binds, pods=[pod("p1", "a", "worker", node="n1")],
                        nodes=[node("n1")]), f"k8s:{C}:user:dev", technique) == {}
    action["rules"][0].update(resources=["serviceaccounts/token"], verbs=["impersonate-on:arbitrary-node:create"],
                               resourceNames=["worker"])
    assert set(reached(_run(technique, [identity, action], binds,
                            pods=[pod("p1", "a", "worker", node="n1")], nodes=[node("n1")]),
                       f"k8s:{C}:user:dev", technique)) == {f"k8s:{C}:node:n1"}
