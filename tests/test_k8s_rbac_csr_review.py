"""CSR creation, approval, and retrieval must refer to one creatable request."""

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import C, crb, crole, k8s_snap, sa, user


IDS = ("k8s-rbac-csr-kube-apiserver-client-user",
       "k8s-rbac-csr-kube-apiserver-client-group",
       "k8s-rbac-csr-kube-apiserver-client-serviceaccount")


def test_csr_paths_include_direct_sa_subject_and_join_request_name():
    csr_rules = [
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"],
         "verbs": ["create", "get"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/approval"],
         "verbs": ["update"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["signers"],
         "resourceNames": ["kubernetes.io/kube-apiserver-client"], "verbs": ["approve"]},
    ]
    csr = crole("csr", csr_rules)
    target = crole("secrets", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    bindings = [crb("csr-bind", "csr", user("dev")),
                crb("user-bind", "secrets", user("admin")),
                crb("group-bind", "secrets", {"kind": "Group", "name": "operators"}),
                crb("sa-bind", "secrets", {"kind": "ServiceAccount", "name": "worker", "namespace": "a"})]
    entries = [item for item in privesc.catalog()["entries"] if item["id"] in IDS]

    def paths():
        result = privesc.analyze(k8s_snap(clusterroles=[csr, target], crbs=bindings,
                                         sas=[sa("worker", "a"), sa("unbound", "a")]), entries=entries)
        return {technique: reached(result, f"k8s:{C}:user:dev", technique) for technique in IDS}

    observed = paths()
    assert set(observed[IDS[0]]) == {f"k8s:{C}:user:admin"}
    assert set(observed[IDS[1]]) == {f"k8s:{C}:group:operators"}
    assert set(observed[IDS[2]]) == {f"k8s:{C}:sa:a:worker"}

    csr_rules[0] = {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"],
                    "verbs": ["create", "get"], "resourceNames": ["read-only"]}
    # create cannot be restricted by resourceNames; keep a separate create rule.
    csr_rules.append({"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"],
                      "verbs": ["create"]})
    csr_rules[1]["resourceNames"] = ["approve-only"]
    assert all(not value for value in paths().values())


def test_csr_paths_ignore_malformed_binding_subjects_without_losing_valid_targets():
    csr = crole("csr", [
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"],
         "verbs": ["create", "get"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/approval"],
         "verbs": ["update"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["signers"],
         "resourceNames": ["kubernetes.io/kube-apiserver-client"], "verbs": ["approve"]},
    ])
    target = crole("secrets", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    bindings = [
        crb("csr-bind", "csr", user("dev")),
        crb("empty-user", "secrets", {"kind": "User", "name": ""}),
        crb("empty-group", "secrets", {"kind": "Group", "name": ""}),
        crb("unknown-kind", "secrets", {"kind": "Robot", "name": "fake-admin"}),
        crb("sa-without-namespace", "secrets", {"kind": "ServiceAccount", "name": "worker"}),
        crb("valid-user", "secrets", user("admin")),
        crb("valid-group", "secrets", {"kind": "Group", "name": "operators"}),
    ]
    entries = [item for item in privesc.catalog()["entries"] if item["id"] in IDS]
    result = privesc.analyze(k8s_snap(clusterroles=[csr, target], crbs=bindings), entries=entries)

    assert set(reached(result, f"k8s:{C}:user:dev", IDS[0])) == {f"k8s:{C}:user:admin"}
    assert set(reached(result, f"k8s:{C}:user:dev", IDS[1])) == {f"k8s:{C}:group:operators"}
    assert not reached(result, f"k8s:{C}:user:dev", IDS[2])


def test_csr_group_already_held_by_source_is_not_escalation():
    csr = crole("csr", [
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"],
         "verbs": ["create", "get"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/approval"],
         "verbs": ["update"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["signers"],
         "resourceNames": ["kubernetes.io/kube-apiserver-client"], "verbs": ["approve"]},
    ])
    already_held = crole("already-held", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}])
    new_access = crole("new-access", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}])
    bindings = [
        crb("csr-bind", "csr", user("dev")),
        crb("authenticated-bind", "already-held", {"kind": "Group", "name": "system:authenticated"}),
        crb("operator-bind", "new-access", {"kind": "Group", "name": "operators"}),
    ]
    entries = [item for item in privesc.catalog()["entries"] if item["id"] in IDS]
    result = privesc.analyze(k8s_snap(clusterroles=[csr, already_held, new_access], crbs=bindings), entries=entries)

    assert set(reached(result, f"k8s:{C}:user:dev", IDS[1])) == {f"k8s:{C}:group:operators"}
