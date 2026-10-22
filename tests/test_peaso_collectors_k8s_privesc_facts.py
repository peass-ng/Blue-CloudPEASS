"""Kubernetes collector facts used by the privesc selectors: OpenShift SCCs, pod scheduling state, Secret metadata
(never data), admission controls (ValidatingAdmissionPolicy / bindings, webhooks, Kyverno / Gatekeeper presence,
Pod Security labels) and ClusterRole aggregation. Read-only fake API; denied reads stay denied/unknown."""
from __future__ import annotations

import io
import json
from types import SimpleNamespace

from peaso import privesc
from peaso.collectors import k8s
from peaso.privesc.schema import load_catalog

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import C, PROV, crole, k8s_snap, meta, node, rb, sa, user


def lst(items):
    return {"metadata": {"resourceVersion": "1"}, "items": items}


class Denied(Exception):
    status = 403


class FakeKube:
    """GET-only fake: path -> response (callable/exception/document). Records every path."""
    server = "https://fixture.invalid"

    def __init__(self, routes):
        self.routes, self.calls = routes, []
        self.api_client = SimpleNamespace(configuration=SimpleNamespace(host=self.server), call_api=self.call_api)

    def get_json(self, path, params=None):
        self.calls.append(path)
        assert "/secrets" not in path, "Secret objects must never be listed through get_json"
        value = self.routes.get(path)
        if value is None:
            error = RuntimeError("not found")
            error.status = 404
            raise error
        if isinstance(value, Exception):
            raise value
        return value

    def call_api(self, path, method, **kwargs):  # metadata-only negotiation for secret_metadata
        assert method == "GET"
        self.calls.append(path)
        accept = kwargs["header_params"]["Accept"]
        if "PartialObjectMetadataList" in accept:
            doc = {"kind": "PartialObjectMetadataList", "metadata": {"resourceVersion": "1"}, "items": [
                {"kind": "PartialObjectMetadata", "metadata": {"name": "prod-cluster", "namespace": "argocd", "uid": "u1",
                    "labels": {"argocd.argoproj.io/secret-type": "cluster"},
                    "annotations": {"kubectl.kubernetes.io/last-applied-configuration": '{"data":{"config":"INERT"}}'}}},
                {"kind": "PartialObjectMetadata", "metadata": {"name": "gcp-sa-key", "namespace": "apps", "uid": "u2"}}]}
        else:
            ns = path.split("/namespaces/")[1].split("/")[0]
            doc = {"kind": "Table", "metadata": {"resourceVersion": "1"},
                   "columnDefinitions": [{"name": "Name"}, {"name": "Type"}, {"name": "Data"}],
                   "rows": [{"cells": ["prod-cluster" if ns == "argocd" else "gcp-sa-key", "Opaque", 3]}]}
        stream = io.BytesIO(json.dumps(doc).encode())
        return SimpleNamespace(read=stream.read, close=lambda: None, release_conn=lambda: None)


def run(api, inventories):
    return k8s.collect({"provider": "k8s", "auth": {"cluster_id": C}, "options": {"inventories": inventories}}, api=api)


def row(snapshot, kind):
    return next(r for r in snapshot["collections"] if r["type"] == kind)


GROUPS_OPENSHIFT = {"groups": [{"name": "security.openshift.io", "versions": [{"groupVersion": "security.openshift.io/v1", "version": "v1"}]},
                               {"name": "admissionregistration.k8s.io", "versions": [
                                   {"groupVersion": "admissionregistration.k8s.io/v1", "version": "v1"},
                                   {"groupVersion": "admissionregistration.k8s.io/v1beta1", "version": "v1beta1"}]},
                               {"name": "kyverno.io", "versions": [{"groupVersion": "kyverno.io/v1", "version": "v1"}]},
                               {"name": "templates.gatekeeper.sh", "versions": [{"groupVersion": "templates.gatekeeper.sh/v1", "version": "v1"}]}]}
SCC = {"metadata": {"name": "hostaccess", "uid": "s1"}, "allowHostNetwork": True, "allowHostPID": True,
       "users": ["system:serviceaccount:ops:agent"], "groups": []}


# ------------------------------------------------------------------ OpenShift SCCs
def test_scc_listed_only_when_openshift_group_is_served_and_denial_is_not_empty():
    api = FakeKube({"/apis": GROUPS_OPENSHIFT, "/apis/security.openshift.io/v1/securitycontextconstraints": lst([SCC])})
    got = row(run(api, ["securitycontextconstraint"]), "securitycontextconstraint")
    assert got["status"] == "collected"
    assert got["items"][0]["users"] == ["system:serviceaccount:ops:agent"] and got["items"][0]["allowHostPID"] is True

    plain = FakeKube({"/apis": {"groups": [{"name": "apps", "versions": []}]}})
    got = row(run(plain, ["securitycontextconstraint"]), "securitycontextconstraint")
    assert got["coverage_status"] == "not_applicable" and got["error"]["code"] == "openshift_api_group_absent"
    assert not any("securitycontextconstraints" in p for p in plain.calls)

    denied = FakeKube({"/apis": GROUPS_OPENSHIFT, "/apis/security.openshift.io/v1/securitycontextconstraints": Denied()})
    assert row(run(denied, ["securitycontextconstraint"]), "securitycontextconstraint")["status"] == "denied"

    no_discovery = FakeKube({"/apis": Denied()})
    assert row(run(no_discovery, ["securitycontextconstraint"]), "securitycontextconstraint")["status"] == "unknown"


# ------------------------------------------------------------------ admission controls
def test_admission_policies_follow_resource_discovery_and_keep_kind():
    vap = {"metadata": {"name": "deny-privileged", "uid": "v1"}, "spec": {"failurePolicy": "Fail", "validations": [{"expression": "true"}]}}
    vapb = {"metadata": {"name": "deny-privileged-binding", "uid": "v2"}, "spec": {"policyName": "deny-privileged",
            "validationActions": ["Deny"], "matchResources": {"namespaceSelector": {}}}}
    map_ = {"metadata": {"name": "inject", "uid": "m1"}, "spec": {"failurePolicy": "Ignore"}}
    api = FakeKube({"/apis": GROUPS_OPENSHIFT,
        "/apis/admissionregistration.k8s.io/v1": {"resources": [{"name": "validatingadmissionpolicies"}, {"name": "validatingadmissionpolicybindings"},
                                                                {"name": "validatingwebhookconfigurations"}]},
        "/apis/admissionregistration.k8s.io/v1beta1": {"resources": [{"name": "mutatingadmissionpolicies"}, {"name": "validatingadmissionpolicies"}]},
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies": lst([vap]),
        "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings": lst([vapb]),
        "/apis/admissionregistration.k8s.io/v1beta1/mutatingadmissionpolicies": lst([map_])})
    snap = run(api, ["admission_policy", "api_discovery"])
    got = row(snap, "admission_policy")
    assert got["status"] == "collected"
    kinds = {i["metadata"]["name"]: (i["kind"], i["apiVersion"]) for i in got["items"]}
    assert kinds == {"deny-privileged": ("ValidatingAdmissionPolicy", "admissionregistration.k8s.io/v1"),
                     "deny-privileged-binding": ("ValidatingAdmissionPolicyBinding", "admissionregistration.k8s.io/v1"),
                     "inject": ("MutatingAdmissionPolicy", "admissionregistration.k8s.io/v1beta1")}
    # v1 wins over v1beta1 for the same resource; nothing unadvertised is listed.
    assert "/apis/admissionregistration.k8s.io/v1beta1/validatingadmissionpolicies" not in api.calls
    assert not any(p.endswith("mutatingadmissionpolicybindings") for p in api.calls)
    engines = row(snap, "api_discovery")["items"][0]["policy_engines"]
    assert engines == {"kyverno": ["kyverno.io"], "gatekeeper": ["templates.gatekeeper.sh"]}


def test_admission_policy_absent_denied_and_discovery_failure():
    absent = FakeKube({"/apis": {"groups": [{"name": "admissionregistration.k8s.io", "versions": [{"version": "v1"}]}]},
                       "/apis/admissionregistration.k8s.io/v1": {"resources": [{"name": "validatingwebhookconfigurations"}]}})
    got = row(run(absent, ["admission_policy"]), "admission_policy")
    assert got["coverage_status"] == "not_applicable" and got["error"]["code"] == "admission_policy_api_absent"

    denied = FakeKube({"/apis": {"groups": [{"name": "admissionregistration.k8s.io", "versions": [{"version": "v1"}]}]},
                       "/apis/admissionregistration.k8s.io/v1": {"resources": [{"name": "validatingadmissionpolicies"}]},
                       "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies": Denied()})
    got = row(run(denied, ["admission_policy"]), "admission_policy")
    assert got["status"] == "denied" and got.get("coverage_status") != "not_applicable"

    resource_denied = FakeKube({"/apis": {"groups": [{"name": "admissionregistration.k8s.io", "versions": [{"version": "v1"}]}]},
                                "/apis/admissionregistration.k8s.io/v1": Denied()})
    assert row(run(resource_denied, ["admission_policy"]), "admission_policy")["status"] == "denied"
    assert row(run(FakeKube({"/apis": Denied()}), ["admission_policy"]), "admission_policy")["status"] == "unknown"


def test_webhook_configurations_keep_kind_and_failure_policy():
    hook = {"metadata": {"name": "gatekeeper-validating", "uid": "w1"},
            "webhooks": [{"name": "v.gatekeeper.sh", "failurePolicy": "Ignore", "namespaceSelector": {}, "rules": []}]}
    api = FakeKube({"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations": lst([hook]),
                    "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations": lst([])})
    got = row(run(api, ["admission_configuration"]), "admission_configuration")
    assert got["status"] == "collected" and got["items"][0]["kind"] == "ValidatingWebhookConfiguration"
    assert got["items"][0]["webhooks"][0]["failurePolicy"] == "Ignore"


def test_namespace_pod_security_labels_are_retained():
    namespace = {"metadata": {"name": "apps", "uid": "n1", "labels": {"pod-security.kubernetes.io/enforce": "restricted",
                                                                      "pod-security.kubernetes.io/warn": "baseline"}}}
    got = row(run(FakeKube({"/api/v1/namespaces": lst([namespace])}), ["namespace"]), "namespace")
    assert got["items"][0]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"


# ------------------------------------------------------------------ pods, aggregation
def test_pending_pod_scheduling_state_and_aggregation_rule_survive_sanitization():
    pending = {"metadata": {"name": "job-x", "namespace": "ops", "uid": "p1"},
               "spec": {"serviceAccountName": "deployer", "containers": [{"name": "c", "env": [{"name": "TOKEN", "value": "INERT"}]}]},
               "status": {"phase": "Pending"}}
    running = {"metadata": {"name": "web", "namespace": "ops", "uid": "p2"},
               "spec": {"serviceAccountName": "web", "nodeName": "node-1", "containers": [{"name": "c"}]}, "status": {"phase": "Running"}}
    aggregated = {"metadata": {"name": "monitoring", "uid": "r1"},
                  "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {"rbac.example.com/aggregate-to-monitoring": "true"}}]}, "rules": []}
    api = FakeKube({"/api/v1/pods": lst([pending, running]),
                    "/apis/rbac.authorization.k8s.io/v1/clusterroles": lst([aggregated])})
    snap = run(api, ["pod", "clusterrole"])
    pods = {p["metadata"]["name"]: p for p in row(snap, "pod")["items"]}
    assert pods["job-x"]["status"]["phase"] == "Pending" and "nodeName" not in pods["job-x"]["spec"]
    assert pods["job-x"]["spec"]["serviceAccountName"] == "deployer"
    assert pods["web"]["spec"]["nodeName"] == "node-1"
    assert "INERT" not in json.dumps(snap)
    role = row(snap, "clusterrole")["items"][0]
    assert role["aggregationRule"]["clusterRoleSelectors"][0]["matchLabels"] == {"rbac.example.com/aggregate-to-monitoring": "true"}


# ------------------------------------------------------------------ Secret metadata
def test_secret_metadata_keeps_labels_and_type_never_data():
    api = FakeKube({})
    snap = run(api, ["secret_metadata"])
    got = row(snap, "secret_metadata")
    assert got["status"] == "collected"
    found = {i["metadata"]["name"]: i for i in got["items"]}
    assert found["prod-cluster"]["metadata"]["labels"] == {"argocd.argoproj.io/secret-type": "cluster"}
    assert found["prod-cluster"]["type"] == "Opaque" and found["gcp-sa-key"]["type"] == "Opaque"
    text = json.dumps(snap)
    assert "INERT" not in text and '"data"' not in text
    assert all(p.endswith("/secrets") for p in api.calls)  # only metadata-negotiated list paths


def test_operator_supplied_secret_metadata_keeps_type_and_rejects_values():
    entries = [{"metadata": {"name": "aws-creds", "namespace": "apps"}, "type": "Opaque"}]
    snap = k8s.collect({"provider": "k8s", "auth": {"cluster_id": C}, "options": {"inventories": ["secret_metadata"],
                        "metadata_evidence": {"secret_metadata": entries}}}, api=FakeKube({}))
    assert row(snap, "secret_metadata")["items"][0]["type"] == "Opaque"
    bad = k8s.collect({"provider": "k8s", "auth": {"cluster_id": C}, "options": {"inventories": ["secret_metadata"],
                       "metadata_evidence": {"secret_metadata": [{"metadata": {"name": "x"}, "data": {"k": "v"}}]}}}, api=FakeKube({}))
    assert row(bad, "secret_metadata")["status"] == "malformed" and row(bad, "secret_metadata")["items"] == []


# ------------------------------------------------------------------ evaluator: openshift_namespace_has_sa_with_host_scc
ENTRY_ID = "k8s-openshift-scc-via-namespace-sa"
DEV = f"k8s:{C}:user:dev"
OPENSHIFT = ("api_discovery", C, [{"provenance": PROV, "groups": [{"name": "security.openshift.io"}, {"name": "apps.openshift.io"}]}])


def scc(name, users=(), groups=(), host=True):
    return {"kind": "SecurityContextConstraints", "metadata": meta(name), "provenance": PROV,
            "allowHostNetwork": host, "allowPrivilegedContainer": host, "users": list(users), "groups": list(groups)}


def analyze(sccs, extra_roles=(), extra_bindings=(), sccs_collected=True):
    entry = next(e for e in load_catalog()["entries"] if e["id"] == ENTRY_ID)
    create = crole("pod-create", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])
    snap = k8s_snap(clusterroles=[create, *extra_roles], rbs=[rb("dev", "ops", "pod-create", user("dev")), *extra_bindings],
                    sas=[sa("agent", "ops"), sa("default", "ops")], namespaces=("ops", "web"),
                    nodes=[node("n1")], sccs=list(sccs) if sccs_collected else None, extra=[OPENSHIFT])
    return reached(privesc.analyze(snap, entries=[entry]), DEV, ENTRY_ID)


def test_host_scc_via_users_groups_and_rbac_use():
    target = f"k8s:{C}:node:n1"
    assert analyze([scc("hostaccess", users=["system:serviceaccount:ops:agent"])]).get(target) == "conditional"
    assert analyze([scc("hostaccess", groups=["system:serviceaccounts:ops"])]).get(target) == "conditional"
    # An SCC granted to another namespace, or a non-host SCC, gives nothing.
    assert target not in analyze([scc("hostaccess", users=["system:serviceaccount:web:agent"]),
                                  scc("restricted", groups=["system:authenticated"], host=False)])
    # RBAC `use` on the host SCC bound to an SA of the namespace.
    use = crole("use-hostaccess", [{"apiGroups": ["security.openshift.io"], "resources": ["securitycontextconstraints"],
                                    "resourceNames": ["hostaccess"], "verbs": ["use"]}])
    binding = rb("agent-scc", "ops", "use-hostaccess", {"kind": "ServiceAccount", "name": "agent", "namespace": "ops"})
    assert analyze([scc("hostaccess")], [use], [binding]).get(target) == "conditional"
    other = crole("use-other", [{"apiGroups": ["security.openshift.io"], "resources": ["securitycontextconstraints"],
                                 "resourceNames": ["restricted-v2"], "verbs": ["use"]}])
    assert target not in analyze([scc("hostaccess")], [other], [rb("x", "ops", "use-other", {"kind": "ServiceAccount", "name": "agent", "namespace": "ops"})])


def test_host_scc_not_collected_stays_unresolved():
    got = analyze([], sccs_collected=False)
    assert f"k8s:{C}:node:n1" not in got or got[f"k8s:{C}:node:n1"] == "unknown"
