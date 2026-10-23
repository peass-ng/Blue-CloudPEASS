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
