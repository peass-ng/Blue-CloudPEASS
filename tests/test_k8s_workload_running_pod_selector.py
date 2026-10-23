"""A pod that has not started cannot expose a running container's authority."""

from peaso.privesc.effective_permissions.k8s import K8sModel
from peaso import privesc


def _snapshot(phase):
    pod = {"metadata": {"name": "app", "namespace": "team", "cluster_id": "c1"},
           "spec": {"serviceAccountName": "app"}, "status": {"phase": phase} if phase is not None else {}}
    sa = {"metadata": {"name": "app", "namespace": "team", "cluster_id": "c1"}}
    return {"provider": "k8s", "schema_version": 1, "scopes": ["c1"], "metadata": {},
            "collections": [
                {"type": kind, "scope": "c1", "status": "collected", "items": rows}
                for kind, rows in (("serviceaccount", [sa]), ("pod", [pod]))]}


def test_only_running_pod_has_live_container_authority():
    target = "k8s:c1:sa:team:app"
    for phase, expected in (("Running", {target: None}), ("Pending", {}),
                            ("Succeeded", {}), ("Failed", {}),
                            (None, {target: ("unknown", "pod_phase_not_collected")})):
        model = K8sModel(_snapshot(phase))
        candidates = {target: model.sas[target]}
        assert model.selector("k8s_sa_used_by_running_pod", True, candidates, None) == expected


def test_scc_missing_service_account_requires_host_scc_and_existing_namespace():
    base = _snapshot("Running")
    base["collections"] = [row for row in base["collections"] if row["type"] != "pod"]
    base["collections"].append({"type": "namespace", "scope": "c1", "status": "collected", "items": [
        {"metadata": {"name": "team", "cluster_id": "c1"}}]})
    base["collections"].append({"type": "securitycontextconstraint", "scope": "c1", "status": "collected", "items": [
        {"metadata": {"name": "host", "cluster_id": "c1"}, "allowPrivilegedContainer": True,
         "users": ["system:serviceaccount:team:missing", "system:serviceaccount:absent:ghost"]},
        {"metadata": {"name": "restricted", "cluster_id": "c1"},
         "users": ["system:serviceaccount:team:ordinary"]}]})
    model = K8sModel(base)
    candidates = model.targets_for("k8s_service_account", {"k8s_sa_missing_in_host_scc_users": True})
    selected = model.selector("k8s_sa_missing_in_host_scc_users", True, {n.id: n for n in candidates}, None)
    assert selected == {"k8s:c1:sa:team:missing": None}


def test_controller_patch_requires_existing_object_covered_by_resource_names():
    base = _snapshot("Running")
    base["collections"] += [
        {"type": "role", "scope": "c1", "status": "collected", "items": [
            {"kind": "Role", "metadata": {"name": "editor", "namespace": "team", "cluster_id": "c1"},
             "rules": [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch"],
                        "resourceNames": ["allowed"]}]}]},
        {"type": "rolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "RoleBinding", "metadata": {"name": "edit", "namespace": "team", "cluster_id": "c1"},
             "roleRef": {"kind": "Role", "name": "editor"},
             "subjects": [{"kind": "User", "name": "dev"}]}]},
        {"type": "deployment", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "other", "namespace": "team", "cluster_id": "c1"}}]},
    ]
    req = {"verb": "patch", "resource": "deployments", "api_group": "apps", "namespace": "team"}
    model = K8sModel(base)
    source = model.principals["k8s:c1:user:dev"]
    assert model.check(source, req, ("team", None, None)) is None
    base["collections"][-1]["items"].append({"metadata": {
        "name": "allowed", "namespace": "team", "cluster_id": "c1"}})
    model = K8sModel(base)
    source = model.principals["k8s:c1:user:dev"]
    assert model.check(source, req, ("team", None, None)).confidence == "derived"


def test_replacement_pod_target_requires_exact_trigger_grant():
    snap = _snapshot("Running")
    pod = snap["collections"][1]["items"][0]
    pod["metadata"]["ownerReferences"] = [
        {"kind": "ReplicaSet", "name": "rs", "controller": True}]
    snap["collections"] += [
        {"type": "role", "scope": "c1", "status": "collected", "items": [
            {"kind": "Role", "metadata": {"name": "replace", "namespace": "team", "cluster_id": "c1"},
             "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["delete"],
                        "resourceNames": ["other"]}]}]},
        {"type": "rolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "RoleBinding", "metadata": {"name": "replace", "namespace": "team", "cluster_id": "c1"},
             "roleRef": {"kind": "Role", "name": "replace"},
             "subjects": [{"kind": "User", "name": "dev"}]}]},
    ]
    def selected():
        model = K8sModel(snap)
        model.current_entry = {"id": "k8s-nodes-replacement-pod-to-controlled-node"}
        source = model.principals["k8s:c1:user:dev"]
        target = model.sas["k8s:c1:sa:team:app"]
        return model.selector("k8s_sa_used_by_controller_managed_pod", True,
                              {target.id: target}, source)
    assert selected() == {}
    snap["collections"][2]["items"][0]["rules"][0]["resourceNames"] = ["app"]
    assert selected() == {"k8s:c1:sa:team:app": None}
    pod["metadata"]["deletionTimestamp"] = "2026-10-22T00:00:00Z"
    assert selected() == {}


def test_attach_only_reaches_running_stdin_enabled_container():
    target = "k8s:c1:sa:team:app"
    for stdin, state, expected in (
        (False, {"running": {"startedAt": "now"}}, {}),
        (True, {"running": {"startedAt": "now"}},
         {target: ("conditional", "interactive_process_accepts_commands_not_verified")}),
        (True, {"waiting": {"reason": "CrashLoopBackOff"}},
         {target: ("unknown", "interactive_container_running_not_recorded")}),
    ):
        snap = _snapshot("Running")
        pod = snap["collections"][1]["items"][0]
        pod["spec"]["containers"] = [{"name": "main", "stdin": stdin}]
        pod["status"]["containerStatuses"] = [{"name": "main", "state": state}]
        model = K8sModel(snap)
        candidates = {target: model.sas[target]}
        assert model.selector("k8s_sa_used_by_interactive_pod", True, candidates, None) == expected


def test_mutating_admission_policy_requires_both_served_api_resources():
    target = "k8s:c1:sa:team:app"
    for advertised, expected in (
        (None, {target: ("unknown", "mutating_admission_api_discovery_not_collected")}),
        ([], {}),
        (["mutatingadmissionpolicies"], {}),
        (["mutatingadmissionpolicies", "mutatingadmissionpolicybindings"], {target: None}),
    ):
        snap = _snapshot("Running")
        discovery = {"groups": [{"name": "admissionregistration.k8s.io"}],
                     "provenance": {"cluster_id": "c1"}}
        if advertised is not None:
            discovery["admissionPolicyResources"] = advertised
        snap["collections"].append({"type": "api_discovery", "scope": "c1", "status": "collected",
                                    "items": [discovery]})
        model = K8sModel(snap)
        assert model.selector("k8s_mutating_admission_policy_served", True, {target: model.sas[target]},
                              model.sas[target]) == expected


def test_webhook_patch_requires_a_mutating_configuration_with_allowed_name():
    base = _snapshot("Running")
    base["collections"] += [
        {"type": "clusterrole", "scope": "c1", "status": "collected", "items": [
            {"kind": "ClusterRole", "metadata": {"name": "webhook-editor", "cluster_id": "c1"},
             "rules": [{"apiGroups": ["admissionregistration.k8s.io"],
                        "resources": ["mutatingwebhookconfigurations"], "verbs": ["patch"],
                        "resourceNames": ["allowed"]}]}]},
        {"type": "clusterrolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "ClusterRoleBinding", "metadata": {"name": "edit", "cluster_id": "c1"},
             "roleRef": {"kind": "ClusterRole", "name": "webhook-editor"},
             "subjects": [{"kind": "User", "name": "dev"}]}]},
        {"type": "admission_configuration", "scope": "c1", "status": "collected", "items": [
            {"kind": "ValidatingWebhookConfiguration", "metadata": {"name": "allowed", "cluster_id": "c1"}},
            {"kind": "MutatingWebhookConfiguration", "metadata": {"name": "other", "cluster_id": "c1"}}]},
    ]
    req = {"verb": "patch", "resource": "mutatingwebhookconfigurations",
           "api_group": "admissionregistration.k8s.io", "namespace": "*"}
    model = K8sModel(base)
    source = model.principals["k8s:c1:user:dev"]
    assert model.check(source, req, ("*", None, None)) is None
    base["collections"][-1]["items"].append({"kind": "MutatingWebhookConfiguration",
        "metadata": {"name": "allowed", "cluster_id": "c1"}})
    model = K8sModel(base)
    source = model.principals["k8s:c1:user:dev"]
    assert model.check(source, req, ("*", None, None)).confidence == "derived"


def test_websocket_get_exec_requires_old_version_or_explicit_disabled_gate():
    target = "k8s:c1:sa:team:app"
    for version, disabled, expected in (
        ("v1.34.7", False, {target: None}),
        ("v1.35.1", False, {target: ("unknown", "websocket_create_feature_gate_not_recorded")}),
        ("v1.35.1", True, {target: ("conditional", "api_server_websocket_create_gate_disabled")}),
    ):
        snap = _snapshot("Running")
        snap["collections"].append({"type": "api_discovery", "scope": "c1", "status": "collected",
                                    "items": [{"provenance": {"cluster_id": "c1"},
                                               "serverVersion": {"gitVersion": version}}]})
        if disabled:
            snap["collections"][1]["items"].append({
                "metadata": {"name": "api", "namespace": "kube-system", "cluster_id": "c1"},
                "spec": {"containers": [{"image": "registry.k8s.io/kube-apiserver:v1.35.1",
                                         "args": ["--feature-gates=AuthorizePodWebsocketUpgradeCreatePermission=false"]}]}})
        model = K8sModel(snap)
        assert model.selector("k8s_websocket_exec_get_usable", True, {target: model.sas[target]},
                              model.sas[target]) == expected


def test_pod_access_joins_exact_pod_name_to_its_service_account():
    snap = _snapshot("Running")
    token = {"name": "api-token", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}
    def pod(name, account):
        return {"metadata": {"name": name, "namespace": "team", "cluster_id": "c1"},
                "spec": {"serviceAccountName": account, "volumes": [token],
                         "containers": [{"name": "main", "stdin": True,
                                         "volumeMounts": [{"name": "api-token", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"}]}]},
                "status": {"phase": "Running", "containerStatuses": [
                    {"name": "main", "state": {"running": {"startedAt": "now"}}}]}}
    snap["collections"][0]["items"].append({"metadata": {"name": "other", "namespace": "team", "cluster_id": "c1"}})
    snap["collections"][1]["items"] = [pod("allowed", "app"), pod("denied", "other")]
    snap["collections"] += [
        {"type": "role", "scope": "c1", "status": "collected", "items": [
            {"kind": "Role", "metadata": {"name": "pod-access", "namespace": "team", "cluster_id": "c1"},
             "rules": [{"apiGroups": [""], "resources": ["pods", "pods/exec", "pods/attach",
                                                   "pods/ephemeralcontainers"],
                        "verbs": ["patch", "update", "create", "get"], "resourceNames": ["allowed"]}]}]},
        {"type": "rolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "RoleBinding", "metadata": {"name": "pod-access", "namespace": "team", "cluster_id": "c1"},
             "roleRef": {"kind": "Role", "name": "pod-access"},
             "subjects": [{"kind": "User", "name": "dev"}]}]},
    ]
    model = K8sModel(snap)
    source = model.principals["k8s:c1:user:dev"]
    targets = {node.id: node for node in model.sas.values()}
    for path in ("modify_image", "exec", "exec_get_websocket", "attach", "ephemeral_container"):
        reached = model.selector("k8s_pod_access_path", path, targets, source)
        assert "k8s:c1:sa:team:app" in reached
        assert "k8s:c1:sa:team:other" not in reached
    snap["collections"][1]["items"][0]["spec"]["volumes"] = []
    model = K8sModel(snap)
    reached = model.selector("k8s_pod_access_path", "exec", targets, model.principals[source.id])
    assert reached["k8s:c1:sa:team:app"] == ("unknown", "pod_service_account_token_volume_not_recorded")


def test_openshift_existing_run_level_namespace_reaches_nodes_without_namespace_write():
    snap = _snapshot("Running")
    snap["collections"] += [
        {"type": "role", "scope": "c1", "status": "collected", "items": [
            {"kind": "Role", "metadata": {"name": "pods", "namespace": "team", "cluster_id": "c1"},
             "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]}]},
        {"type": "rolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "RoleBinding", "metadata": {"name": "pods", "namespace": "team", "cluster_id": "c1"},
             "roleRef": {"kind": "Role", "name": "pods"}, "subjects": [{"kind": "User", "name": "dev"}]}]},
        {"type": "namespace", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "team", "cluster_id": "c1", "labels": {"openshift.io/run-level": "0"}}}]},
        {"type": "node", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "n1", "cluster_id": "c1"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]},
        {"type": "api_discovery", "scope": "c1", "status": "collected", "items": [
            {"provenance": {"cluster_id": "c1"}, "groups": [{"name": "security.openshift.io"}]}]},
    ]
    technique = "k8s-openshift-privileged-default-projects"
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == technique)
    def has_path():
        result = privesc.analyze(snap, entries=[entry])
        return any(edge["source"] == "k8s:c1:user:dev" and technique in edge["techniques"]
                   for edge in result["graph"]["edges"])
    assert has_path()
    snap["collections"][4]["items"][0]["metadata"]["labels"] = {}
    assert not has_path()


def test_openshift_fixed_project_must_exist_for_workload_creation():
    snap = _snapshot("Running")
    snap["collections"] += [
        {"type": "role", "scope": "c1", "status": "collected", "items": [
            {"kind": "Role", "metadata": {"name": "pods", "namespace": "openshift-infra", "cluster_id": "c1"},
             "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]}]},
        {"type": "rolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "RoleBinding", "metadata": {"name": "pods", "namespace": "openshift-infra", "cluster_id": "c1"},
             "roleRef": {"kind": "Role", "name": "pods"}, "subjects": [{"kind": "User", "name": "dev"}]}]},
        {"type": "namespace", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "team", "cluster_id": "c1"}}]},
    ]
    model = K8sModel(snap)
    source = model.principals["k8s:c1:user:dev"]
    candidates = {"node": object()}
    assert model.selector("openshift_namespace_without_scc", True, candidates, source) == {}
    snap["collections"][-1]["items"].append({"metadata": {"name": "openshift-infra", "cluster_id": "c1"}})
    model = K8sModel(snap)
    assert model.selector("openshift_namespace_without_scc", True, candidates, model.principals[source.id]) == {
        "node": None}


def test_namespace_label_write_path_excludes_already_labeled_namespace():
    snap = _snapshot("Running")
    snap["collections"].append({"type": "namespace", "scope": "c1", "status": "collected", "items": [
        {"metadata": {"name": "team", "cluster_id": "c1", "labels": {}}}]})
    model = K8sModel(snap)
    source = model.sas["k8s:c1:sa:team:app"]
    candidates = {"node": object()}
    assert model.selector("openshift_unlabeled_existing_namespace", True, candidates, source,
                          pivot=[{"pivot.namespace": "team"}]) == {"node": None}
    snap["collections"][-1]["items"][0]["metadata"]["labels"]["openshift.io/run-level"] = "0"
    model = K8sModel(snap)
    assert model.selector("openshift_unlabeled_existing_namespace", True, candidates, source,
                          pivot=[{"pivot.namespace": "team"}]) == {}


def test_openshift_new_labeled_namespace_requires_clusterwide_workload_creation():
    snap = _snapshot("Running")
    snap["collections"] += [
        {"type": "role", "scope": "c1", "status": "collected", "items": [
            {"kind": "ClusterRole", "metadata": {"name": "namespace-writer", "cluster_id": "c1"},
             "rules": [{"apiGroups": [""], "resources": ["namespaces", "pods"], "verbs": ["create"]}]}]},
        {"type": "rolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "ClusterRoleBinding", "metadata": {"name": "namespace-writer", "cluster_id": "c1"},
             "roleRef": {"kind": "ClusterRole", "name": "namespace-writer"},
             "subjects": [{"kind": "User", "name": "dev"}]}]},
        {"type": "node", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "n1", "cluster_id": "c1"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]},
        {"type": "api_discovery", "scope": "c1", "status": "collected", "items": [
            {"provenance": {"cluster_id": "c1"}, "groups": [{"name": "security.openshift.io"}]}]},
    ]
    technique = "k8s-openshift-run-level-label-new-namespace"
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == technique)
    def has_path():
        result = privesc.analyze(snap, entries=[entry])
        return any(edge["source"] == "k8s:c1:user:dev" and technique in edge["techniques"]
                   for edge in result["graph"]["edges"])
    assert has_path()
    snap["collections"][2]["items"][0]["rules"][0]["resources"] = ["namespaces"]
    assert not has_path()


def test_openshift_scc_use_accepts_namespace_binding_and_exact_host_scc():
    snap = _snapshot("Running")
    snap["collections"] += [
        {"type": "namespace", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "team", "cluster_id": "c1"}}]},
        {"type": "role", "scope": "c1", "status": "collected", "items": [
            {"kind": "Role", "metadata": {"name": "host-use", "namespace": "team", "cluster_id": "c1"},
             "rules": [{"apiGroups": ["security.openshift.io"], "resources": ["securitycontextconstraints"],
                        "verbs": ["use"], "resourceNames": ["host"]}]}]},
        {"type": "rolebinding", "scope": "c1", "status": "collected", "items": [
            {"kind": "RoleBinding", "metadata": {"name": "host-use", "namespace": "team", "cluster_id": "c1"},
             "roleRef": {"kind": "Role", "name": "host-use"},
             "subjects": [{"kind": "User", "name": "dev"}]}]},
        {"type": "securitycontextconstraint", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "host", "cluster_id": "c1"}, "allowPrivilegedContainer": True}]},
    ]
    model = K8sModel(snap)
    source = model.principals["k8s:c1:user:dev"]
    candidates = {"node": object()}
    assert model.selector("openshift_source_host_scc_path", True, candidates, source,
                          pivot=[{"pivot.namespace": "team"}]) == {"node": None}
    snap["collections"][-1]["items"][0]["allowPrivilegedContainer"] = False
    model = K8sModel(snap)
    assert model.selector("openshift_source_host_scc_path", True, candidates, model.principals[source.id],
                          pivot=[{"pivot.namespace": "team"}]) == {}
    snap["collections"][-1]["items"][0]["allowPrivilegedContainer"] = True
    snap["collections"][4]["items"] = []
    snap["collections"][-1]["items"][0]["users"] = ["dev"]
    model = K8sModel(snap)
    assert model.selector("openshift_source_host_scc_path", True, candidates, model.external_user("c1", "dev"),
                          pivot=[{"pivot.namespace": "team"}]) == {"node": None}


def test_openshift_service_account_host_scc_requires_existing_account_and_namespace():
    snap = _snapshot("Running")
    snap["collections"] += [
        {"type": "namespace", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "team", "cluster_id": "c1"}}]},
        {"type": "securitycontextconstraint", "scope": "c1", "status": "collected", "items": [
            {"metadata": {"name": "host", "cluster_id": "c1"}, "allowPrivilegedContainer": True,
             "users": ["system:serviceaccount:team:app"]}]},
        {"type": "api_discovery", "scope": "c1", "status": "collected", "items": [
            {"provenance": {"cluster_id": "c1"}, "groups": [{"name": "security.openshift.io"}]}]},
    ]
    model = K8sModel(snap)
    source = model.sas["k8s:c1:sa:team:app"]
    candidates = {"node": type("Target", (), {"attrs": {"cluster": "c1"}})()}
    assert model.selector("openshift_namespace_has_sa_with_host_scc", "{pivot.namespace}", candidates,
                          source, pivot=[{"pivot.namespace": "team"}]) == {"node": None}
    snap["collections"][0]["items"] = []
    model = K8sModel(snap)
    assert model.selector("openshift_namespace_has_sa_with_host_scc", "{pivot.namespace}", candidates,
                          model.external_user("c1", "dev"), pivot=[{"pivot.namespace": "team"}]) == {}
