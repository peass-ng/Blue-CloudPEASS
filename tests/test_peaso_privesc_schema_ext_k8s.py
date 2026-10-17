"""Schema v1.1 Kubernetes extensions requested by the catalog ledger (NEEDS SCHEMA): verb_prefix / resource_match,
chain-gated sources (source_reaches_kind), pending-pod / associated-node / namespace-absent / SCC-users selectors,
Secret-held cloud and remote-cluster credentials, admission-control blocker removal and aggregated ClusterRoles."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import default_outcome

from tests.test_peaso_privesc_schema_ext import entry, errors_of, reached, snapshot

C = "c1"
PROV = {"cluster_id": C}


def meta(name, ns=None, **extra):
    out = {"name": name, **extra}
    if ns:
        out["namespace"] = ns
    return out


def crole(name, rules, aggregation=None, labels=None):
    item = {"kind": "ClusterRole", "metadata": meta(name, labels=labels or {}), "provenance": PROV, "rules": rules}
    if aggregation:
        item["aggregationRule"] = {"clusterRoleSelectors": [{"matchLabels": aggregation}]}
    return item


def crb(name, role, subject):
    return {"kind": "ClusterRoleBinding", "metadata": meta(name), "provenance": PROV,
            "roleRef": {"kind": "ClusterRole", "name": role}, "subjects": [subject]}


def rb(name, ns, role, subject, kind="ClusterRole"):
    return {"kind": "RoleBinding", "metadata": meta(name, ns), "provenance": PROV,
            "roleRef": {"kind": kind, "name": role}, "subjects": [subject]}


def user(name):
    return {"kind": "User", "name": name}


def sa(name, ns):
    return {"kind": "ServiceAccount", "metadata": meta(name, ns), "provenance": PROV}


def ns(name):
    return {"kind": "Namespace", "metadata": meta(name), "provenance": PROV}


def pod(name, namespace, sa_name, node=None, phase="Running"):
    spec = {"serviceAccountName": sa_name, "containers": [{"name": "c", "image": "x"}]}
    if node:
        spec["nodeName"] = node
    return {"kind": "Pod", "metadata": meta(name, namespace), "provenance": PROV, "spec": spec, "status": {"phase": phase}}


def node(name):
    return {"kind": "Node", "metadata": meta(name), "provenance": PROV, "spec": {"providerID": "kind://docker/x/" + name}}


def secret(name, namespace, stype="Opaque", labels=None):
    return {"kind": "Secret", "type": stype, "metadata": meta(name, namespace, labels=labels or {}), "provenance": PROV}


def k8s_snap(*, clusterroles=(), crbs=(), rbs=(), sas=(), namespaces=("a",), pods=(), nodes=(), secrets=None, sccs=None,
             extra=()):
    cols = [("role", C, []), ("clusterrole", C, list(clusterroles)), ("rolebinding", C, list(rbs)),
            ("clusterrolebinding", C, list(crbs)), ("serviceaccount", C, list(sas)),
            ("namespace", C, [ns(n) for n in namespaces]), ("pod", C, list(pods)), ("node", C, list(nodes))]
    if secrets is not None:
        cols.append(("secret_metadata", C, list(secrets)))
    if sccs is not None:
        cols.append(("securitycontextconstraint", C, list(sccs)))
    return snapshot("k8s", cols + list(extra))


def k8s_entry(eid, requires, target, **extra):
    e = entry(eid, "k8s", requires, target, **extra)
    assert errors_of(e) == [], errors_of(e)
    return e


DEV, OPS = f"k8s:{C}:user:dev", f"k8s:{C}:user:ops"


# ------------------------------------------------------------------ verb_prefix / resource_match
def test_verb_prefix_with_any_resource_matches_constrained_impersonation_rules():
    rules = {"ci-list": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["impersonate-on:user-info:list"]}],
             "ci-node": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["impersonate-on:arbitrary-node:list"]}],
             "plain": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["list"]}],
             "imp": [{"apiGroups": ["authentication.k8s.io"], "resources": ["users"], "verbs": ["impersonate:user-info"]}]}
    roles = [crole(n, r) for n, r in rules.items()]
    binds = [crb("b1", "ci-list", user("dev")), crb("b2", "imp", user("dev")), crb("b3", "ci-node", user("ops")),
             crb("b4", "imp", user("ops")), crb("b5", "plain", user("eve")), crb("b6", "imp", user("eve")),
             crb("b7", "imp", user("admin-user"))]
    e = k8s_entry("k8s-t-constrained", {"all_of": [
        {"verb_prefix": "impersonate-on:user-info:", "resource_match": "any", "namespace": "*"},
        {"verb": "impersonate:user-info", "api_group": "authentication.k8s.io", "resource": "users",
         "resource_name": "{target.name}", "namespace": "*"}]},
        {"kind": "k8s_user", "selector": {"target_name_glob": "admin-*"}, "scope": "cluster"})
    result = privesc.analyze(k8s_snap(clusterroles=roles, crbs=binds), entries=[e])
    assert reached(result, DEV) == {f"k8s:{C}:user:admin-user": "derived"}
    assert reached(result, OPS) == {}               # other impersonation mode
    assert reached(result, f"k8s:{C}:user:eve") == {}  # plain verb, no impersonate-on


def test_verb_prefix_validation():
    base = {"kind": "k8s_cluster_admin", "selector": {"any_principal_in_scope": True}, "scope": "cluster"}
    bad = [{"verb": "get", "verb_prefix": "x:", "resource": "pods"}, {"verb_prefix": "impersonate-on:*", "resource_match": "any"},
           {"verb_prefix": "x:", "resource_match": "some"}, {"verb_prefix": "x:", "resource_match": "any", "resource": "pods"},
           {"verb_prefix": "x:"}, {"verb_prefix": "x:", "resource_match": "any", "subresource": "exec"}]
    for req in bad:
        assert errors_of(entry("k8s-t-bad", "k8s", {"all_of": [req]}, base)), req
    assert errors_of(entry("k8s-t-ok", "k8s", {"all_of": [{"verb_prefix": "x:", "resource_match": "any"}]}, base)) == []


# ------------------------------------------------------------------ pending pods / associated node
def test_pending_pod_and_associated_node_selectors():
    pods = [pod("p1", "a", "builder", phase="Pending"), pod("p2", "a", "web", node="n1"), pod("p3", "a", "batch", node="n2", phase="Pending")]
    sas = [sa("builder", "a"), sa("web", "a"), sa("batch", "a")]
    role = crole("bind", [{"apiGroups": [""], "resources": ["pods/binding"], "verbs": ["create"]},
                          {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]}])
    snap = k8s_snap(clusterroles=[role], crbs=[crb("b", "bind", user("dev")), crb("w", "bind", {"kind": "ServiceAccount", "name": "web", "namespace": "a"})],
                    sas=sas, pods=pods, nodes=[node("n1"), node("n2")])
    pending = k8s_entry("k8s-t-pending", {"all_of": [{"verb": "create", "resource": "pods", "subresource": "binding",
                                                      "namespace": "{target.namespace}"}]},
                        {"kind": "k8s_service_account", "selector": {"k8s_sa_used_by_pending_pod": True}, "scope": "cluster"})
    assoc = k8s_entry("k8s-t-assoc", {"all_of": [{"verb": "get", "resource": "nodes", "namespace": "*"}]},
                      {"kind": "k8s_node", "selector": {"k8s_node_hosting_pod_of_source": True}, "scope": "cluster"})
    result = privesc.analyze(snap, entries=[pending, assoc])
    assert reached(result, DEV, "k8s-t-pending") == {f"k8s:{C}:sa:a:builder": "derived"}   # p3 is scheduled
    assert reached(result, f"k8s:{C}:sa:a:web", "k8s-t-assoc") == {f"k8s:{C}:node:n1": "derived"}
    assert reached(result, DEV, "k8s-t-assoc") == {}   # not a service account: no associated node
    # pods not collected: unresolved, never derived
    snap2 = k8s_snap(clusterroles=[role], crbs=[crb("b", "bind", user("dev"))], sas=sas, nodes=[node("n1")])
    snap2["collections"] = [c for c in snap2["collections"] if c["type"] != "pod"]
    got = reached(privesc.analyze(snap2, entries=[pending], include_unknown=True), DEV)
    assert got and set(got.values()) == {"unknown"}


# ------------------------------------------------------------------ chain-gated sources
def test_source_reaches_kind_gates_on_the_graph_closure():
    role_pods = crole("pods", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}])
    role_del = crole("del", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["delete"]}])
    snap = k8s_snap(clusterroles=[role_pods, role_del],
                    crbs=[crb("a", "pods", user("dev")), crb("b", "del", user("dev")), crb("c", "del", user("ops"))],
                    sas=[sa("ctrl", "a")], nodes=[node("n1")])
    to_node = k8s_entry("k8s-t-to-node", {"all_of": [{"verb": "create", "resource": "pods", "namespace": "*"}]},
                        {"kind": "k8s_node", "selector": {"k8s_node_schedulable": True}, "scope": "cluster"})
    gated = k8s_entry("k8s-t-gated", {"all_of": [{"verb": "delete", "resource": "pods", "namespace": "{target.namespace}"}]},
                      {"kind": "k8s_service_account", "selector": {"k8s_sa_in_namespace": "a"}, "scope": "cluster"},
                      source_selector={"source_reaches_kind": "k8s_node"})
    result = privesc.analyze(snap, entries=[gated, to_node])
    assert reached(result, DEV, "k8s-t-gated") == {f"k8s:{C}:sa:a:ctrl": "derived"}
    assert reached(result, OPS, "k8s-t-gated") == {}
    finding = next(f for f in result["findings"] if f["check_id"] == "k8s-t-gated")
    assert "source_reaches_k8s_node_via_chain" in finding["evidence"]["conditions"]
    assert errors_of(entry("k8s-t-x", "k8s", gated["requires"], gated["target"], source_selector={"source_reaches_kind": "nope"}))


# ------------------------------------------------------------------ dangling namespaces / SCC users
def test_namespace_absent_and_scc_user_subjects():
    view = crole("power", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])
    create = crole("mk", [{"apiGroups": [""], "resources": ["namespaces", "serviceaccounts"], "verbs": ["create"]}])
    binds = [crb("ghost", "power", {"kind": "ServiceAccount", "name": "deployer", "namespace": "gone"}),
             crb("live", "power", {"kind": "ServiceAccount", "name": "absent", "namespace": "a"}),
             crb("mk", "mk", user("dev"))]
    scc = {"kind": "SecurityContextConstraints", "metadata": meta("privileged"), "provenance": PROV,
           "users": ["system:serviceaccount:b:runner", "system:serviceaccount:a:web"]}
    discovery = ("api_discovery", C, [{"provenance": PROV, "groups": [{"name": "security.openshift.io"}]}])
    snap = k8s_snap(clusterroles=[view, create], crbs=binds, sas=[sa("web", "a")], sccs=[scc], extra=[discovery])
    absent_ns = k8s_entry("k8s-t-nsabsent", {"all_of": [{"verb": "create", "resource": "namespaces", "namespace": "*"},
                                                        {"verb": "create", "resource": "serviceaccounts", "namespace": "*"}]},
                          {"kind": "k8s_service_account", "selector": {"k8s_sa_namespace_absent": True}, "scope": "cluster"})
    scc_users = k8s_entry("k8s-t-scc", {"all_of": [{"verb": "create", "resource": "serviceaccounts", "namespace": "*"}]},
                          {"kind": "k8s_service_account", "selector": {"k8s_sa_named_in_scc_users": True}, "scope": "cluster"})
    result = privesc.analyze(snap, entries=[absent_ns, scc_users])
    assert set(reached(result, DEV, "k8s-t-nsabsent")) == {f"k8s:{C}:sa:gone:deployer", f"k8s:{C}:sa:b:runner"}
    assert set(reached(result, DEV, "k8s-t-scc")) == {f"k8s:{C}:sa:b:runner", f"k8s:{C}:sa:a:web"}
    # Not OpenShift: no SCC targets at all.
    plain = k8s_snap(clusterroles=[view, create], crbs=binds, sas=[sa("web", "a")],
                     extra=[("api_discovery", C, [{"provenance": PROV, "groups": [{"name": "apps"}]}])])
    assert reached(privesc.analyze(plain, entries=[scc_users]), DEV) == {}


# ------------------------------------------------------------------ Secret-held credentials
def test_secret_held_cloud_and_remote_cluster_credentials():
    reader = crole("read", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    secrets = [secret("gcp-sa-key", "a"), secret("aws-creds", "a"), secret("web-tls", "a", "kubernetes.io/tls"),
               secret("app-config", "a"),
               secret("cluster-prod", "argocd", labels={"argocd.argoproj.io/secret-type": "cluster"}),
               secret("repo-x", "argocd", labels={"argocd.argoproj.io/secret-type": "repository"})]
    snap = k8s_snap(clusterroles=[reader], rbs=[rb("r", "a", "read", user("dev")), rb("r2", "argocd", "read", user("dev"))],
                    namespaces=("a", "argocd"), secrets=secrets)
    gcp = k8s_entry("k8s-t-secret-gcp", {"all_of": [{"verb": "get", "resource": "secrets", "namespace": "{target.namespace}",
                                                     "resource_name": "{target.name}"}]},
                    {"kind": "cloud_identity", "selector": {"k8s_secret_holds_cloud_credential": "gcp"}, "scope": "cluster"})
    anyp = k8s_entry("k8s-t-secret-any", gcp["requires"],
                     {"kind": "cloud_identity", "selector": {"k8s_secret_holds_cloud_credential": True}, "scope": "cluster"})
    remote = k8s_entry("k8s-t-remote", gcp["requires"],
                       {"kind": "k8s_remote_cluster", "selector": {"k8s_secret_holds_remote_cluster_credential": True},
                        "scope": "cluster"})
    result = privesc.analyze(snap, entries=[gcp, anyp, remote])
    assert reached(result, DEV, "k8s-t-secret-gcp") == {f"cloud:k8s_secret:{C}/a/gcp-sa-key": "conditional"}
    assert set(reached(result, DEV, "k8s-t-secret-any")) == {f"cloud:k8s_secret:{C}/a/gcp-sa-key", f"cloud:k8s_secret:{C}/a/aws-creds"}
    assert reached(result, DEV, "k8s-t-remote") == {f"k8s_remote_cluster:{C}/argocd/cluster-prod": "derived"}
    assert default_outcome(remote["target"]) == "credentials" and default_outcome(gcp["target"]) == "credentials"
    # secret metadata not collected: unresolved placeholders only
    blind = k8s_snap(clusterroles=[reader], rbs=[rb("r", "a", "read", user("dev"))])
    got = privesc.analyze(blind, entries=[gcp, remote])
    assert set(reached(got, DEV).values()) <= {"unknown"}
    assert errors_of(entry("k8s-t-x", "k8s", gcp["requires"], {"kind": "k8s_remote_cluster", "selector": {}, "scope": "cluster"}))
    assert errors_of(entry("k8s-t-x", "k8s", gcp["requires"],
                           {"kind": "cloud_identity", "selector": {"k8s_secret_holds_cloud_credential": "oracle"}}))


# ------------------------------------------------------------------ admission blocker removal
def test_admission_control_blocker_removal():
    role = crole("vap", [{"apiGroups": ["admissionregistration.k8s.io"], "resources": ["validatingadmissionpolicybindings"],
                          "verbs": ["delete"]}])
    snap = k8s_snap(clusterroles=[role], crbs=[crb("b", "vap", user("dev"))])
    e = k8s_entry("k8s-t-vap", {"all_of": [{"verb": "delete", "api_group": "admissionregistration.k8s.io",
                                            "resource": "validatingadmissionpolicybindings", "namespace": "*"}]},
                  {"kind": "k8s_admission_control", "selector": {"any_principal_in_scope": True}, "scope": "cluster",
                   "removes_blockers": ["admission_policy"]})
    result = privesc.analyze(snap, entries=[e])
    assert reached(result, DEV) == {f"k8s_admission_control:{C}": "derived"}
    finding = next(f for f in result["findings"] if f["check_id"] == "k8s-t-vap")
    assert finding["evidence"]["technique"]["outcome"] == "blocker_removal"
    assert finding["evidence"]["technique"]["removes_blockers"] == ["admission_policy"]
    target = dict(e["target"])
    for bad in ({**target, "removes_blockers": ["nope"]}, {k: v for k, v in target.items() if k != "removes_blockers"},
                {"kind": "k8s_cluster_admin", "selector": {"any_principal_in_scope": True}, "removes_blockers": ["admission_policy"]},
                {**target, "outcome": "identity"}):
        assert errors_of(entry("k8s-t-x", "k8s", e["requires"], bad)), bad


# ------------------------------------------------------------------ aggregated ClusterRoles
def test_source_bound_to_aggregated_clusterrole():
    assert next(e for e in privesc.catalog()["entries"] if e["id"] == "k8s-rbac-escalate-aggregating-clusterrole")["source_selector"] == {"source_bound_to_aggregated_clusterrole": "cluster"}
    agg = crole("monitoring", [], aggregation={"rbac.example.com/aggregate-to-monitoring": "true"})
    mk = crole("mk", [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["create"]}])
    snap = k8s_snap(clusterroles=[agg, mk], crbs=[crb("a", "monitoring", user("dev")), crb("m", "mk", user("dev")),
                                                  crb("m2", "mk", user("ops"))],
                    rbs=[rb("r", "a", "monitoring", user("ops"))])
    base = ({"all_of": [{"verb": "create", "api_group": "rbac.authorization.k8s.io", "resource": "clusterroles", "namespace": "*"}]},
            {"kind": "k8s_cluster_admin", "selector": {"any_principal_in_scope": True}, "scope": "cluster"})
    anyb = k8s_entry("k8s-t-agg", *base, source_selector={"source_bound_to_aggregated_clusterrole": True})
    cluster = k8s_entry("k8s-t-agg-c", *base, source_selector={"source_bound_to_aggregated_clusterrole": "cluster"})
    result = privesc.analyze(snap, entries=[anyb, cluster])
    assert reached(result, DEV, "k8s-t-agg") and reached(result, DEV, "k8s-t-agg-c")
    assert reached(result, OPS, "k8s-t-agg") and not reached(result, OPS, "k8s-t-agg-c")
    assert errors_of(entry("k8s-t-x", "k8s", *base, source_selector={"source_bound_to_aggregated_clusterrole": "ns"}))
