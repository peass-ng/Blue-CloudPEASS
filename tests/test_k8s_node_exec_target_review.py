"""Exact running-container and named-pod joins for node escape by exec."""

from tests.test_peaso_privesc_audit_fixes import grant, k8s, kobj, real, reached
from peaso.privesc.effective_permissions.k8s import K8sModel, active_pod_escape_primitives


def _case(*, allowed="host", phase="Running", active="danger", init_only=False,
          host_mount=False, ephemeral=False):
    resource = "pods/ephemeralcontainers" if ephemeral else "pods/exec"
    verb = "patch" if ephemeral else "create"
    role, binding = grant("actor", "a", [{"apiGroups": [""], "resources": [resource],
                                           "resourceNames": [allowed], "verbs": [verb]}],
                          {"kind": "User", "name": "dev"})
    dangerous = {"name": "danger", "image": "x", "securityContext": {"privileged": True}}
    if host_mount:
        dangerous = {"name": "danger", "image": "x", "volumeMounts": [
            {"name": "host", "mountPath": "/host"}]}
    containers = [{"name": "safe", "image": "x"}]
    spec = {"nodeName": "n1", "serviceAccountName": "builder", "containers": containers,
            "volumes": ([{"name": "host", "hostPath": {"path": "/var/lib/kubelet/pki"}}]
                        if host_mount else [])}
    spec.setdefault("initContainers" if init_only else "containers", []).append(dangerous)
    host = kobj("Pod", "host", "a", spec=spec,
                status={"phase": phase, "containerStatuses": [{"name": active,
                                                                "state": {"running": {}}}]})
    safe = kobj("Pod", "safe", "a", spec={"nodeName": "n1", "serviceAccountName": "builder",
                                        "containers": [{"name": "safe", "image": "x"}]},
                status={"phase": "Running", "containerStatuses": [{"name": "safe",
                                                                      "state": {"running": {}}}]})
    snap = k8s([role], [binding])
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[host, safe], status="collected")
    return snap


def test_exec_requires_permission_on_exact_host_primitive_pod():
    ident = "k8s-nodes-exec-into-host-privileged-pod"
    assert reached(real(_case(allowed="safe"), ident), "k8s:c1:user:dev", ident) == {}
    assert reached(real(_case(allowed="host"), ident), "k8s:c1:user:dev", ident).get(
        "k8s:c1:node:n1") == "conditional"


def test_exec_requires_active_container_with_the_primitive():
    ident = "k8s-nodes-exec-into-host-privileged-pod"
    for snap in (_case(phase="Succeeded"), _case(active="safe"), _case(init_only=True, active="safe")):
        assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}


def test_exec_with_missing_pod_phase_stays_unknown():
    spec = {"containers": [{"name": "danger", "securityContext": {"privileged": True}}]}
    assert active_pod_escape_primitives(spec, {}) == ("pod_phase_not_collected", None)


def test_host_mount_exec_uses_exact_active_container():
    ident = "k8s-nodes-exec-into-host-mount-pod"
    assert reached(real(_case(host_mount=True, allowed="safe"), ident), "k8s:c1:user:dev", ident) == {}
    assert reached(real(_case(host_mount=True), ident), "k8s:c1:user:dev", ident).get(
        "k8s:c1:node:n1") == "conditional"
    assert reached(real(_case(host_mount=True, active="safe"), ident), "k8s:c1:user:dev", ident) == {}


def test_ephemeral_container_write_requires_named_running_pod():
    ident = "k8s-nodes-privileged-ephemeral-container"
    assert reached(real(_case(ephemeral=True, allowed="safe"), ident), "k8s:c1:user:dev", ident).get(
        "k8s:c1:node:n1") == "conditional"
    assert reached(real(_case(ephemeral=True, allowed="missing"), ident), "k8s:c1:user:dev", ident) == {}


def test_controller_patch_needs_an_existing_exactly_writable_controller():
    ident = "k8s-nodes-privileged-controller-create"
    role, binding = grant("actor", "a", [{"apiGroups": ["apps"], "resources": ["deployments"],
                                           "resourceNames": ["writable"], "verbs": ["patch"]}],
                          {"kind": "User", "name": "dev"})
    snap = k8s([role], [binding])
    deployments = [kobj("Deployment", "writable", "a")]
    snap["collections"].append({"type": "deployment", "scope": "*", "service": "deployment",
                                "status": "collected", "items": deployments, "error": None})
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident).get("k8s:c1:node:n1") == "conditional"
    deployments[0]["metadata"]["name"] = "other"
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}


def test_controller_create_needs_no_existing_controller():
    ident = "k8s-nodes-privileged-controller-create"
    role, binding = grant("actor", "a", [{"apiGroups": ["apps"], "resources": ["deployments"],
                                           "verbs": ["create"]}],
                          {"kind": "User", "name": "dev"})
    assert reached(real(k8s([role], [binding]), ident), "k8s:c1:user:dev", ident).get(
        "k8s:c1:node:n1") == "conditional"


def test_namespace_psa_relabel_requires_a_restrictive_label_to_relax():
    ident = "k8s-nodes-namespace-psa-relabel"
    role, binding = grant("actor", None, [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["a"],
         "verbs": ["patch"]}], {"kind": "User", "name": "dev"})
    snap = k8s([role], [binding])
    namespace = next(x for c in snap["collections"] if c["type"] == "namespace"
                     for x in c["items"] if x["metadata"]["name"] == "a")
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}
    namespace["metadata"]["labels"] = {"pod-security.kubernetes.io/enforce": "restricted"}
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident).get("k8s:c1:node:n1") == "conditional"


def test_new_namespace_pod_create_must_be_clusterwide():
    ident = "k8s-nodes-namespace-create-privileged-pod"
    namespaced, namespaced_binding = grant("pods", "a", [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}],
        {"kind": "User", "name": "dev"})
    global_role, global_binding = grant("namespace", None, [
        {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["create"]}],
        {"kind": "User", "name": "dev"})
    assert reached(real(k8s([namespaced, global_role], [namespaced_binding, global_binding]), ident),
                   "k8s:c1:user:dev", ident) == {}
    global_role["rules"].append({"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]})
    assert reached(real(k8s([namespaced, global_role], [namespaced_binding, global_binding]), ident),
                   "k8s:c1:user:dev", ident).get("k8s:c1:node:n1") == "conditional"


def test_hostpath_pv_path_joins_pv_pvc_and_pod_create_even_under_psa():
    ident = "k8s-nodes-hostpath-persistentvolume"
    global_role, global_binding = grant("pv", None, [
        {"apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["create"]}],
        {"kind": "User", "name": "dev"})
    local_role, local_binding = grant("pvc-pod", "a", [
        {"apiGroups": [""], "resources": ["persistentvolumeclaims", "pods"],
         "verbs": ["create"]}], {"kind": "User", "name": "dev"})
    snap = k8s([global_role, local_role], [global_binding, local_binding])
    ns = next(x for c in snap["collections"] if c["type"] == "namespace"
              for x in c["items"] if x["metadata"]["name"] == "a")
    ns["metadata"]["labels"] = {"pod-security.kubernetes.io/enforce": "restricted"}
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident).get("k8s:c1:node:n1") == "conditional"
    local_role["rules"][0]["resources"] = ["pods"]
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}


def test_nodes_proxy_targets_only_pods_on_named_node():
    ident = "k8s-nodes-nodes-proxy-pod-sas"
    role, binding = grant("proxy", None, [{"apiGroups": [""], "resources": ["nodes/proxy"],
                                           "resourceNames": ["n1"], "verbs": ["get"]}],
                          {"kind": "User", "name": "dev"})
    pod = kobj("Pod", "work", "a", spec={"nodeName": "n1", "serviceAccountName": "builder",
                                         "containers": [{"name": "c", "image": "x"}]},
               status={"phase": "Running", "containerStatuses": [{"name": "c", "state": {"running": {}}}]})
    snap = k8s([role], [binding])
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[pod], status="collected")
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident).get(
        "k8s:c1:sa:a:builder") == "conditional"
    role["rules"][0]["resourceNames"] = ["other"]
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}
    role["rules"][0]["resourceNames"] = ["n1"]
    pod["status"]["phase"] = "Succeeded"
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}


def test_nodes_proxy_node_routes_need_active_privilege_or_host_mount():
    role, binding = grant("proxy", None, [{"apiGroups": [""], "resources": ["nodes/proxy"],
                                           "resourceNames": ["n1"], "verbs": ["get"]}],
                          {"kind": "User", "name": "dev"})
    pod = kobj("Pod", "host", "a", spec={"nodeName": "n1", "serviceAccountName": "builder",
                                         "containers": [{"name": "c", "image": "x",
                                                         "securityContext": {"privileged": True}}]},
               status={"phase": "Running", "containerStatuses": [{"name": "c", "state": {"running": {}}}]})
    snap = k8s([role], [binding])
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[pod], status="collected")
    privileged = "k8s-nodes-nodes-proxy-node"
    mounted = "k8s-nodes-nodes-proxy-host-mount-node"
    assert reached(real(snap, privileged), "k8s:c1:user:dev", privileged).get(
        "k8s:c1:node:n1") == "conditional"
    assert reached(real(snap, mounted), "k8s:c1:user:dev", mounted) == {}
    pod["spec"]["containers"][0].pop("securityContext")
    pod["spec"]["volumes"] = [{"name": "host", "hostPath": {"path": "/var/lib/kubelet/pki"}}]
    pod["spec"]["containers"][0]["volumeMounts"] = [{"name": "host", "mountPath": "/host"}]
    assert reached(real(snap, mounted), "k8s:c1:user:dev", mounted).get(
        "k8s:c1:node:n1") == "conditional"
    assert reached(real(snap, privileged), "k8s:c1:user:dev", privileged) == {}


def test_node_token_request_joins_its_own_running_pods():
    ident = "k8s-nodes-node-mint-pod-sa-tokens"
    pod = kobj("Pod", "work", "a", spec={"nodeName": "n1", "serviceAccountName": "builder",
                                         "containers": [{"name": "c", "image": "x"}]},
               status={"phase": "Running"})
    snap = k8s()
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[pod], status="collected")
    source = "k8s:c1:node:n1"
    assert reached(real(snap, ident), source, ident).get("k8s:c1:sa:a:builder") == "conditional"
    pod["status"]["phase"] = "Succeeded"
    assert reached(real(snap, ident), source, ident) == {}
    pod["status"]["phase"] = "Pending"
    assert reached(real(snap, ident), source, ident).get("k8s:c1:sa:a:builder") == "conditional"
    pod["spec"]["nodeName"] = "other"
    assert reached(real(snap, ident), source, ident) == {}


def test_csr_kubelet_signer_requires_approval_and_exact_signer():
    ident = "k8s-nodes-csr-kubelet-client-signer"
    rules = [
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"],
         "verbs": ["create", "get"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/approval"],
         "verbs": ["update"]},
        {"apiGroups": ["certificates.k8s.io"], "resources": ["signers"],
         "resourceNames": ["kubernetes.io/kube-apiserver-client-kubelet"], "verbs": ["approve"]}]
    role, binding = grant("csr", None, rules, {"kind": "User", "name": "dev"})
    snap = k8s([role], [binding], groups=("certificates.k8s.io",))
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident).get("k8s:c1:node:n1") == "conditional"
    rules[2]["resourceNames"] = ["kubernetes.io/kube-apiserver-client"]
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}
    rules[2]["resourceNames"] = ["kubernetes.io/kube-apiserver-client-kubelet"]
    rules[1]["verbs"] = ["get"]
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}


def test_csr_autoapprove_requires_nodeclient_not_selfnodeclient():
    ident = "k8s-nodes-csr-nodeclient-autoapprove"
    rules = [{"apiGroups": ["certificates.k8s.io"], "resources": [
        "certificatesigningrequests", "certificatesigningrequests/nodeclient"],
        "verbs": ["create", "get"]}]
    role, binding = grant("bootstrap", None, rules, {"kind": "User", "name": "dev"})
    snap = k8s([role], [binding], groups=("certificates.k8s.io",))
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident).get("k8s:c1:node:n1") == "conditional"
    rules[0]["resources"][1] = "certificatesigningrequests/selfnodeclient"
    assert reached(real(snap, ident), "k8s:c1:user:dev", ident) == {}


def test_control_plane_node_path_is_conditional_and_label_scoped():
    ident = "k8s-nodes-control-plane-node"
    snap = k8s()
    node = next(x for c in snap["collections"] if c["type"] == "node" for x in c["items"])
    source = "k8s:c1:node:n1"
    assert reached(real(snap, ident), source, ident) == {}
    node["metadata"]["labels"] = {"node-role.kubernetes.io/control-plane": ""}
    assert reached(real(snap, ident), source, ident).get("k8s_cluster_admin:c1") == "conditional"


def test_replacement_pod_target_requires_a_real_replacing_controller():
    pod = kobj("Pod", "work", "a", meta={"ownerReferences": [{"kind": "ConfigMap",
                                                               "name": "x", "controller": True}]},
               spec={"serviceAccountName": "builder", "nodeName": "n1",
                     "containers": [{"name": "c", "image": "x"}]}, status={"phase": "Running"})
    snap = k8s()
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[pod], status="collected")
    model = K8sModel(snap)
    target = model.sas["k8s:c1:sa:a:builder"]
    assert model.selector("k8s_sa_used_by_controller_managed_pod", True, {target.id: target}, None) == {}
    pod["metadata"]["ownerReferences"] = [{"kind": "ReplicaSet", "name": "rs", "controller": True}]
    model = K8sModel(snap)
    target = model.sas["k8s:c1:sa:a:builder"]
    assert model.selector("k8s_sa_used_by_controller_managed_pod", True,
                          {target.id: target}, None) == {target.id: None}


def test_pending_pod_target_needs_unscheduled_live_pod():
    pod = kobj("Pod", "waiting", "a", spec={"serviceAccountName": "builder",
                                               "containers": [{"name": "c", "image": "x"}]},
               status={"phase": "Pending"})
    snap = k8s()
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[pod], status="collected")
    def selected():
        model = K8sModel(snap)
        target = model.sas["k8s:c1:sa:a:builder"]
        return model.selector("k8s_sa_used_by_pending_pod", True, {target.id: target}, None)
    assert selected() == {"k8s:c1:sa:a:builder": None}
    pod["spec"]["nodeName"] = "n1"
    assert selected() == {}
    pod["spec"].pop("nodeName")
    pod["status"].pop("phase")
    assert selected() == {"k8s:c1:sa:a:builder": ("unknown", "pending_pod_phase_not_collected")}
    pod["metadata"]["deletionTimestamp"] = "2026-10-22T00:00:00Z"
    assert selected() == {}


def test_pod_binding_path_requires_non_node_writer_and_controlled_node():
    ident = "k8s-nodes-pods-binding-pending-pod-to-controlled-node"
    pending = kobj("Pod", "waiting", "a", spec={"serviceAccountName": "ca",
                                                   "containers": [{"name": "c", "image": "x"}]},
                   status={"phase": "Pending"})
    node_role, node_binding = grant("node-bind", None, [{"apiGroups": [""],
        "resources": ["pods/binding"], "verbs": ["create"]}],
        {"kind": "Group", "name": "system:nodes"})
    snap = k8s([node_role], [node_binding])
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[pending], status="collected")
    assert reached(real(snap, ident), "k8s:c1:node:n1", ident) == {}
    source_role, source_binding = grant("user-bind", None, [
        {"apiGroups": [""], "resources": ["nodes/proxy"], "resourceNames": ["n1"], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["pods/binding"], "verbs": ["create"]}],
        {"kind": "User", "name": "dev"})
    next(c for c in snap["collections"] if c["type"] == "clusterrole")["items"].append(source_role)
    next(c for c in snap["collections"] if c["type"] == "clusterrolebinding")["items"].append(source_binding)
    host = kobj("Pod", "host", "a", spec={"nodeName": "n1", "serviceAccountName": "builder",
                                         "containers": [{"name": "c", "image": "x",
                                                         "securityContext": {"privileged": True}}]},
                status={"phase": "Running", "containerStatuses": [{"name": "c", "state": {"running": {}}}]})
    next(c for c in snap["collections"] if c["type"] == "pod")["items"].append(host)
    result = real(snap, "k8s-nodes-nodes-proxy-node", ident)
    assert reached(result, "k8s:c1:user:dev", ident).get("k8s:c1:sa:a:ca") == "conditional"
    source_role["rules"][1]["resourceNames"] = ["other"]
    result = real(snap, "k8s-nodes-nodes-proxy-node", ident)
    assert reached(result, "k8s:c1:user:dev", ident) == {}


def test_pending_pod_attraction_joins_pod_status_name_or_broad_node_write():
    pod = kobj("Pod", "waiting", "a", spec={"serviceAccountName": "builder",
                                               "containers": [{"name": "c", "image": "x"}]},
               status={"phase": "Pending"})
    role, binding = grant("status", "a", [{"apiGroups": [""], "resources": ["pods/status"],
                                           "resourceNames": ["other"], "verbs": ["patch"]}],
                          {"kind": "User", "name": "dev"})
    snap = k8s([role], [binding])
    next(c for c in snap["collections"] if c["type"] == "pod").update(items=[pod], status="collected")
    def selected():
        model = K8sModel(snap)
        model.current_entry = {"id": "k8s-nodes-attract-pending-pod-to-controlled-node"}
        target = model.sas["k8s:c1:sa:a:builder"]
        source = model.principals["k8s:c1:user:dev"]
        return model.selector("k8s_sa_used_by_pending_pod", True, {target.id: target}, source)
    assert selected() == {}
    role["rules"][0]["resourceNames"] = ["waiting"]
    assert selected() == {"k8s:c1:sa:a:builder": None}
    role["rules"][0]["resourceNames"] = ["other"]
    global_role, global_binding = grant("nodes", None, [{"apiGroups": [""],
        "resources": ["nodes/status"], "verbs": ["patch"]}], {"kind": "User", "name": "dev"})
    next(c for c in snap["collections"] if c["type"] == "clusterrole")["items"].append(global_role)
    next(c for c in snap["collections"] if c["type"] == "clusterrolebinding")["items"].append(global_binding)
    assert selected() == {"k8s:c1:sa:a:builder": None}
    global_role["rules"][0]["resourceNames"] = ["n1"]
    assert selected() == {"k8s:c1:sa:a:builder": (
        "conditional", "node_write_name_must_match_controlled_node")}
