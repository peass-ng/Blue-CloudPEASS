"""K8s workload-admission blockers evaluated by the model (MODEL_BLOCKERS["k8s"]): Pod Security Admission labels
(definitive 'blocked'), CEL admission policies, validating webhooks, Kyverno and Gatekeeper ('possibly_blocked':
edge kept as conditional with evidence), facts missing (annotated, not evaluated) and the lift of a blocker by a
k8s_admission_control technique (target.removes_blockers) reached directly or along a chain."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import MODEL_BLOCKERS, SELECTOR_KEYS

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import (C, DEV, PROV, crb, crole, k8s_entry, k8s_snap, meta, node, rb, sa,
                                                     user)

NODE = f"k8s:{C}:node:n1"
POD_CREATE = crole("pods", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])


def priv_pod(blocker="pivot_namespace_psa_enforce_baseline_or_restricted", eid="k8s-t-privpod"):
    return k8s_entry(eid, {"all_of": [{"verb": "create", "resource": "pods", "namespace": "{pivot.namespace}"}]},
                     {"kind": "k8s_node", "selector": {"k8s_node_schedulable": True}, "scope": "cluster"},
                     blockers=[blocker])


def ns_item(name, labels=None):
    return {"kind": "Namespace", "metadata": meta(name, labels=labels or {}), "provenance": PROV}


def snap(namespaces, bindings_ns=("a",), extra=(), clusterroles=(), crbs=(), sas=()):
    """dev may create pods in `bindings_ns`; namespaces: {name: labels} (replaces the default namespace items)."""
    base = k8s_snap(clusterroles=[POD_CREATE, *clusterroles], crbs=list(crbs), sas=list(sas),
                    rbs=[rb(f"r-{n}", n, "pods", user("dev")) for n in bindings_ns], nodes=[node("n1")],
                    namespaces=(), extra=list(extra))
    for col in base["collections"]:
        if col["type"] == "namespace":
            col["items"] = [ns_item(n, labels) for n, labels in namespaces.items()]
    return base


def finding(result, eid):
    return next(f for f in result["findings"] if f["check_id"] == eid)


RESTRICTED = {"pod-security.kubernetes.io/enforce": "restricted"}


def test_registry_lists_every_admission_blocker():
    assert {"pod_security_admission", "pivot_namespace_psa_enforce_baseline_or_restricted", "admission_policy",
            "admission_webhook", "kyverno_policy", "gatekeeper_constraint"} <= MODEL_BLOCKERS["k8s"]
    assert "not collected" not in SELECTOR_KEYS["openshift_namespace_has_sa_with_host_scc"][2]


# ------------------------------------------------------------------ Pod Security Admission (definitive)
def test_psa_enforce_on_the_only_pivot_namespace_blocks_with_evidence():
    e = priv_pod()
    result = privesc.analyze(snap({"a": RESTRICTED}), entries=[e])
    assert reached(result, DEV) == {}
    assert result["stats"]["blocked_reaches"] == 1
    record = result["stats"]["blocked"][0]
    assert record["technique"] == "k8s-t-privpod" and record["source"] == DEV and record["targets"] == [NODE]
    assert record["blockers"][0]["id"] == "pivot_namespace_psa_enforce_baseline_or_restricted"
    assert "namespace a enforces Pod Security 'restricted'" in record["blockers"][0]["evidence"]
    assert any(c["kind"] == "blocker" and c["status"] == "blocked" for c in result["coverage"])


def test_psa_baseline_blocks_privileged_and_privileged_level_does_not():
    assert reached(privesc.analyze(snap({"a": {"pod-security.kubernetes.io/enforce": "baseline"}}), entries=[priv_pod()]),
                   DEV) == {}
    got = privesc.analyze(snap({"a": {"pod-security.kubernetes.io/enforce": "privileged",
                                      "pod-security.kubernetes.io/warn": "restricted"}}), entries=[priv_pod()])
    assert reached(got, DEV) == {NODE: "derived"}
    assert got["stats"]["blocked"] == [] and "blockers_not_evaluated" not in finding(got, "k8s-t-privpod")["evidence"]


def test_attacker_picks_an_unenforced_pivot_namespace():
    got = privesc.analyze(snap({"a": RESTRICTED, "b": {}}, bindings_ns=("a", "b")), entries=[priv_pod()])
    assert reached(got, DEV) == {NODE: "derived"} and got["stats"]["blocked"] == []


def test_psa_without_namespace_inventory_is_annotated_not_dropped():
    got = privesc.analyze(snap({}), entries=[priv_pod("pod_security_admission")])
    assert reached(got, DEV) == {NODE: "derived"}
    assert "blocker_pod_security_admission_not_evaluated" in finding(got, "k8s-t-privpod")["evidence"]["conditions"]
    assert any(c["kind"] == "blocker" and c["status"] == "not_evaluated" for c in got["coverage"])


def test_psa_on_target_namespace_is_per_target():
    mount = crole("mount", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])
    e = k8s_entry("k8s-t-mount", {"all_of": [{"verb": "create", "resource": "pods", "namespace": "{target.namespace}"}]},
                  {"kind": "k8s_service_account", "selector": {}, "scope": "cluster"}, blockers=["pod_security_admission"])
    s = snap({"a": RESTRICTED, "b": {}}, clusterroles=[mount], crbs=[crb("m", "mount", user("dev"))],
             sas=[sa("x", "a"), sa("y", "b")])
    got = privesc.analyze(s, entries=[e])
    hit = reached(got, DEV)
    assert hit.get(f"k8s:{C}:sa:b:y") == "derived" and f"k8s:{C}:sa:a:x" not in hit
    assert [r["targets"] for r in got["stats"]["blocked"]] == [[f"k8s:{C}:sa:a:x"]]


# ------------------------------------------------------------------ lift along a chain
def lift_entry():
    return k8s_entry("k8s-t-relabel", {"all_of": [{"verb": "patch", "resource": "namespaces", "namespace": "*"}]},
                     {"kind": "k8s_admission_control", "selector": {"any_principal_in_scope": True}, "scope": "cluster",
                      "removes_blockers": ["pod_security_admission"]})


RELABEL = crole("relabel", [{"apiGroups": [""], "resources": ["namespaces"], "verbs": ["patch"]}])


def test_removes_blockers_lifts_a_blocked_reach_of_the_same_source():
    s = snap({"a": RESTRICTED}, clusterroles=[RELABEL], crbs=[crb("rl", "relabel", user("dev"))])
    got = privesc.analyze(s, entries=[priv_pod(), lift_entry()])
    assert reached(got, DEV, "k8s-t-privpod") == {NODE: "derived"}
    assert got["stats"]["blocked"] == []
    verdicts = finding(got, "k8s-t-privpod")["evidence"]["blocker_verdicts"]
    assert verdicts[0].startswith("blocker_pivot_namespace_psa_enforce_baseline_or_restricted_lifted_via_k8s-t-relabel")


def test_removes_blockers_lifts_through_an_impersonation_chain():
    imp = crole("imp", [{"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"]}])
    imp_entry = k8s_entry("k8s-t-imp", {"all_of": [{"verb": "impersonate", "resource": "serviceaccounts", "namespace": "*"}]},
                          {"kind": "k8s_service_account", "selector": {}, "scope": "cluster"})
    s = snap({"a": RESTRICTED, "ops": {}}, clusterroles=[RELABEL, imp], sas=[sa("lifter", "ops")],
             crbs=[crb("i", "imp", user("dev")),
                   crb("rl", "relabel", {"kind": "ServiceAccount", "name": "lifter", "namespace": "ops"})])
    got = privesc.analyze(s, entries=[priv_pod(), lift_entry(), imp_entry])
    assert reached(got, DEV, "k8s-t-privpod") == {NODE: "derived"}
    # Without the lifter the reach stays blocked and is reported.
    got = privesc.analyze(s, entries=[priv_pod(), imp_entry])
    assert reached(got, DEV, "k8s-t-privpod") == {} and got["stats"]["blocked"][0]["source"] == DEV


def test_lift_of_another_blocker_does_not_restore():
    other = k8s_entry("k8s-t-vapdel", {"all_of": [{"verb": "patch", "resource": "namespaces", "namespace": "*"}]},
                      {"kind": "k8s_admission_control", "selector": {"any_principal_in_scope": True}, "scope": "cluster",
                       "removes_blockers": ["admission_policy"]})
    s = snap({"a": RESTRICTED}, clusterroles=[RELABEL], crbs=[crb("rl", "relabel", user("dev"))])
    got = privesc.analyze(s, entries=[priv_pod(), other])
    assert reached(got, DEV, "k8s-t-privpod") == {} and len(got["stats"]["blocked"]) == 1


# ------------------------------------------------------------------ possibly blocked (kept, conditional)
def webhook_cfg(selector=None, rules=None, kind="ValidatingWebhookConfiguration"):
    hook = {"name": "validate.example.io", "failurePolicy": "Fail",
            "rules": rules or [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]}
    if selector is not None:
        hook["namespaceSelector"] = selector
    return {"kind": kind, "metadata": meta("policy-hooks"), "provenance": PROV, "webhooks": [hook]}


def test_validating_webhook_matching_the_namespace_downgrades_with_evidence():
    s = snap({"a": {"team": "x"}}, extra=[("admission_configuration", C, [webhook_cfg({"matchLabels": {"team": "x"}})])])
    got = privesc.analyze(s, entries=[priv_pod("admission_webhook")])
    assert reached(got, DEV) == {NODE: "conditional"}
    verdict = finding(got, "k8s-t-privpod")["evidence"]["blocker_verdicts"][0]
    assert verdict.startswith("blocker_admission_webhook_possibly_enforced: ValidatingWebhookConfiguration policy-hooks/validate.example.io")
    assert "failurePolicy Fail" in verdict


def test_webhook_not_matching_mutating_only_or_not_collected():
    for cfg in (webhook_cfg({"matchExpressions": [{"key": "team", "operator": "NotIn", "values": ["x"]}]}),
                webhook_cfg(rules=[{"apiGroups": ["apps"], "operations": ["CREATE"], "resources": ["deployments"]}]),
                webhook_cfg(kind="MutatingWebhookConfiguration")):
        got = privesc.analyze(snap({"a": {"team": "x"}}, extra=[("admission_configuration", C, [cfg])]),
                              entries=[priv_pod("admission_webhook")])
        assert reached(got, DEV) == {NODE: "derived"}, cfg
    got = privesc.analyze(snap({"a": {}}), entries=[priv_pod("admission_webhook")])
    assert "blocker_admission_webhook_not_evaluated" in finding(got, "k8s-t-privpod")["evidence"]["conditions"]


def vap(actions=("Deny",), resources=("pods",)):
    policy = {"kind": "ValidatingAdmissionPolicy", "metadata": meta("no-priv"), "provenance": PROV,
              "spec": {"matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE", "UPDATE"], "resources": list(resources)}]},
                       "validations": [{"expression": "true"}]}}
    binding = {"kind": "ValidatingAdmissionPolicyBinding", "metadata": meta("no-priv-b"), "provenance": PROV,
               "spec": {"policyName": "no-priv", "validationActions": list(actions)}}
    return [policy, binding]


def test_admission_policy_bound_with_deny_downgrades():
    got = privesc.analyze(snap({"a": {}}, extra=[("admission_policy", C, vap())]), entries=[priv_pod("admission_policy")])
    assert reached(got, DEV) == {NODE: "conditional"}
    assert "ValidatingAdmissionPolicy no-priv bound by no-priv-b" in finding(got, "k8s-t-privpod")["evidence"]["blocker_verdicts"][0]


def test_admission_policy_audit_only_absent_api_or_unrelated_resources_is_clear():
    for items in (vap(actions=("Audit", "Warn")), vap(resources=("configmaps",)), vap()[:1]):
        got = privesc.analyze(snap({"a": {}}, extra=[("admission_policy", C, items)]), entries=[priv_pod("admission_policy")])
        assert reached(got, DEV) == {NODE: "derived"}, items
    s = snap({"a": {}})
    s["collections"].append({"type": "admission_policy", "scope": C, "service": "kubernetes", "status": "not_collected",
                             "coverage_status": "not_applicable", "items": [],
                             "error": {"kind": "not_applicable", "code": "admission_policy_api_absent"}})
    got = privesc.analyze(s, entries=[priv_pod("admission_policy")])
    assert reached(got, DEV) == {NODE: "derived"}
    assert "conditions" not in finding(got, "k8s-t-privpod")["evidence"] or not any(
        "admission_policy" in c for c in finding(got, "k8s-t-privpod")["evidence"]["conditions"])


def discovery(*groups):
    return [("api_discovery", C, [{"kind": "APIGroupList", "provenance": PROV, "groups": [{"name": g} for g in groups]}])]


def test_policy_engines_from_api_discovery():
    got = privesc.analyze(snap({"a": {}}, extra=discovery("apps", "kyverno.io")), entries=[priv_pod("kyverno_policy")])
    assert reached(got, DEV) == {NODE: "conditional"}
    assert "Kyverno is installed (API groups kyverno.io)" in finding(got, "k8s-t-privpod")["evidence"]["blocker_verdicts"][0]
    got = privesc.analyze(snap({"a": {}}, extra=discovery("apps", "constraints.gatekeeper.sh")),
                          entries=[priv_pod("gatekeeper_constraint"), priv_pod("kyverno_policy", eid="k8s-t-kyv")])
    # One edge per (source, target): the techniques' own confidences are on their findings.
    assert finding(got, "k8s-t-privpod")["evidence"]["confidence"] == "conditional"
    assert "constraints.gatekeeper.sh" in finding(got, "k8s-t-privpod")["evidence"]["blocker_verdicts"][0]
    assert finding(got, "k8s-t-kyv")["evidence"]["confidence"] == "derived"
    assert "blocker_verdicts" not in finding(got, "k8s-t-kyv")["evidence"]
    got = privesc.analyze(snap({"a": {}}), entries=[priv_pod("gatekeeper_constraint")])
    assert "blocker_gatekeeper_constraint_not_evaluated" in finding(got, "k8s-t-privpod")["evidence"]["conditions"]


def test_lift_of_a_possibly_blocked_edge_is_not_needed_and_blocked_aliases_are_lifted():
    # possibly_blocked edges are already kept; a removes_blockers entry naming the alias lifts the PSA pivot blocker.
    alias = k8s_entry("k8s-t-alias", {"all_of": [{"verb": "patch", "resource": "namespaces", "namespace": "*"}]},
                      {"kind": "k8s_admission_control", "selector": {"any_principal_in_scope": True}, "scope": "cluster",
                       "removes_blockers": ["pivot_namespace_psa_enforce_baseline_or_restricted"]})
    s = snap({"a": RESTRICTED}, clusterroles=[RELABEL], crbs=[crb("rl", "relabel", user("dev"))])
    got = privesc.analyze(s, entries=[priv_pod("pod_security_admission"), alias])
    assert reached(got, DEV, "k8s-t-privpod") == {NODE: "derived"}


# ------------------------------------------------------------------ determinism (PYTHONHASHSEED)
_DETERMINISM_SCRIPT = r"""
import json, sys
from peaso import privesc
from tests.test_peaso_privesc_schema_ext_k8s import crole, k8s_snap, node, rb, sa, user
pods = crole("pods", [{"apiGroups": [""], "resources": ["pods", "pods/exec", "serviceaccounts/token"],
                       "verbs": ["create", "get", "list"]}])
names = [f"dev{i}" for i in range(40)]
snap = k8s_snap(clusterroles=[pods], namespaces=tuple(f"ns{i}" for i in range(40)),
                rbs=[rb(f"r{i}", f"ns{i}", "pods", user(n)) for i, n in enumerate(names)]
                    + [rb(f"s{i}", f"ns{i}", "pods", {"kind": "ServiceAccount", "name": "ci", "namespace": f"ns{i}"})
                       for i in range(40)],
                sas=[sa("ci", f"ns{i}") for i in range(40)], nodes=[node("n1"), node("n2")])
out = privesc.analyze(snap)
out["stats"].pop("timing_seconds", None)
sys.stdout.write(json.dumps(out, default=str))
"""


def test_privesc_output_does_not_depend_on_the_hash_seed():
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    runs = []
    for seed in ("0", "1"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(root)}
        done = subprocess.run([sys.executable, "-c", _DETERMINISM_SCRIPT], cwd=root, env=env, capture_output=True,
                              text=True, timeout=600)
        assert done.returncode == 0, done.stderr[-2000:]
        runs.append(done.stdout)
    assert runs[0]
    if runs[0] != runs[1]:  # short message (a full diff of two large JSON strings is slow and unreadable)
        at = next(i for i, (x, y) in enumerate(zip(runs[0], runs[1])) if x != y) if len(runs[0]) == len(runs[1]) else 0
        raise AssertionError(f"seed 0 vs 1 differ at char {at}: {runs[0][max(0, at - 80):at + 80]!r}")
