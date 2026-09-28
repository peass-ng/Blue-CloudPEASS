import importlib.util
import json
from datetime import datetime, timezone

from bluepeass.k8s import _audit_permission_matches, analyze_snapshot, classify_permission, fetch_snapshot, read_audit_log
from bluepeass.normalize import normalize_k8s_cluster


def obj(name, namespace=None, **extra):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return {"metadata": metadata, **extra}


def snapshot():
    resources = {kind: [] for kind in (
        "clusterroles", "clusterrolebindings", "roles", "rolebindings", "serviceaccounts",
        "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "secrets",
    )}
    resources["roles"] = [
        obj("reader", "team-a", rules=[{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["deploy-key"]}]),
        obj("unbound", "team-a", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]),
    ]
    resources["clusterroles"] = [obj("pod-admin", rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}])]
    resources["rolebindings"] = [
        obj("sa-reader", "team-a", roleRef={"kind": "Role", "name": "reader"}, subjects=[{"kind": "Group", "name": "system:serviceaccounts:team-b"}]),
        obj("pod-admin-local", "team-b", roleRef={"kind": "ClusterRole", "name": "pod-admin"}, subjects=[{"kind": "ServiceAccount", "name": "runner", "namespace": "team-b"}]),
    ]
    resources["serviceaccounts"] = [obj("runner", "team-b"), obj("unused", "team-b")]
    resources["pods"] = [obj("job", "team-b", spec={"serviceAccountName": "runner"})]
    resources["secrets"] = [obj("legacy", "team-b", type="kubernetes.io/service-account-token", data={"token": "DO_NOT_OUTPUT"})]
    return {"context": "example", "resources": resources, "errors": []}


def test_rbac_scope_group_inheritance_sources_and_inventory():
    result = analyze_snapshot(snapshot())
    grants = {(p["principal"], p["scope"]): p for p in result["principals"]}
    inherited = grants[("serviceaccount:team-b/runner", "team-a")]
    secret = next(p for p in inherited["permissions"] if p["resource"] == "secrets")
    assert secret["risk"] == "critical"
    assert secret["resource_names"] == ["deploy-key"]
    assert secret["sources"][0]["via_group"] == "system:serviceaccounts:team-b"
    assert grants[("serviceaccount:team-b/runner", "team-b")]["permissions"][0]["risk"] == "critical"
    assert result["findings"]["service_accounts_without_workloads"] == ["team-b/unused"]
    assert result["findings"]["unused_custom_definitions"] == [{"kind": "roles", "scope": "team-a", "name": "unbound"}]
    assert result["coverage"]["unused_permissions_available"] is False
    assert "DO_NOT_OUTPUT" not in json.dumps(normalize_k8s_cluster(result))


def test_partial_read_does_not_claim_unused_or_dangling():
    data = snapshot()
    del data["resources"]["rolebindings"]
    del data["resources"]["deployments"]
    result = analyze_snapshot(data)
    assert result["findings"]["unused_custom_definitions"] == []
    assert result["findings"]["service_accounts_without_workloads"] == []
    assert result["coverage"]["missing"] == ["rolebindings", "deployments"]


def test_missing_role_read_is_unresolved_not_dangling():
    data = snapshot()
    del data["resources"]["clusterroles"]
    result = analyze_snapshot(data)
    assert len(result["findings"]["unresolved_bindings"]) == 1
    assert result["findings"]["dangling_bindings"] == []


def test_permission_classification_and_normalized_catalog():
    assert classify_permission({"api_group": "rbac.authorization.k8s.io", "resource": "clusterroles", "verb": "bind"})[0] == "critical"
    normalized = normalize_k8s_cluster(analyze_snapshot(snapshot()))
    assert normalized["scope"]["scope_type"] == "cluster"
    assert normalized["findings"]["principals_flagged"]
    assert normalized["findings"]["permission_catalog"]
    assert normalized["findings"]["group_memberships"]


def test_public_group_and_workload_identity():
    data = snapshot()
    data["resources"]["clusterrolebindings"] = [
        obj("public", roleRef={"kind": "ClusterRole", "name": "pod-admin"}, subjects=[{"kind": "Group", "name": "system:unauthenticated"}]),
    ]
    data["resources"]["serviceaccounts"][0]["metadata"]["annotations"] = {"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/test"}
    result = analyze_snapshot(data)
    assert any(p["principal"] == "user:system:anonymous" for p in result["findings"]["principals_flagged"])
    assert result["findings"]["workload_identity_trusts"][0]["service_account"] == "team-b/runner"
    assert result["findings"]["workloads_with_flagged_service_accounts"][0]["service_account"] == "team-b/runner"


def test_rolebinding_does_not_grant_cluster_scoped_or_api_path_rules():
    data = snapshot()
    data["resources"]["clusterroles"].append(obj("global", rules=[
        {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]},
        {"nonResourceURLs": ["/metrics"], "verbs": ["get"]},
    ]))
    data["resources"]["rolebindings"].append(obj("global-local", "team-b", roleRef={"kind": "ClusterRole", "name": "global"}, subjects=[{"kind": "ServiceAccount", "name": "runner", "namespace": "team-b"}]))
    result = analyze_snapshot(data)
    grants = next(p for p in result["principals"] if p["principal"] == "serviceaccount:team-b/runner" and p["scope"] == "team-b")
    assert all(p["resource"] not in {"nodes", "/metrics"} for p in grants["permissions"])


def test_namespaced_bind_on_clusterrole_is_retained():
    data = snapshot()
    data["discovery"] = {"namespaced": ["core:pods"], "cluster_scoped": ["core:nodes", "rbac.authorization.k8s.io:clusterroles"]}
    data["resources"]["clusterroles"].append(obj("grantor", rules=[
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "resourceNames": ["admin"], "verbs": ["bind"]},
        {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]},
    ]))
    data["resources"]["rolebindings"].append(obj("grantor-local", "team-b", roleRef={"kind": "ClusterRole", "name": "grantor"}, subjects=[{"kind": "User", "name": "alice"}]))
    result = analyze_snapshot(data)
    grants = next(p for p in result["principals"] if p["principal"] == "user:alice")
    assert [p["resource"] for p in grants["permissions"]] == ["clusterroles"]
    assert grants["permissions"][0]["risk"] == "critical"


def test_workload_creation_path_to_privileged_service_account():
    data = snapshot()
    data["resources"]["roles"].append(obj("creator", "team-b", rules=[
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
    ]))
    data["resources"]["rolebindings"].append(obj("creator-binding", "team-b", roleRef={"kind": "Role", "name": "creator"}, subjects=[{"kind": "User", "name": "alice"}]))
    paths = analyze_snapshot(data)["findings"]["workload_creation_paths_to_flagged_service_accounts"]
    assert any(path["principal"] == "user:alice" and path["service_account"] == "team-b/runner" and path["workload_resources"] == ["pods"] for path in paths)
    assert not any(path["principal"] == "user:alice" and path["service_account"] == "team-b/unused" for path in paths)


def test_fetch_snapshot_keeps_optional_read_error(monkeypatch):
    import subprocess

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if "api-resources" in command:
            output = "pods\nroles.rbac.authorization.k8s.io\n" if "--namespaced=true" in command else "nodes\nclusterroles.rbac.authorization.k8s.io\n"
            return subprocess.CompletedProcess(command, 0, output, "")
        if "secrets" in command:
            return subprocess.CompletedProcess(command, 1, "", "forbidden")
        return subprocess.CompletedProcess(command, 0, '{"items": []}', "")

    monkeypatch.setattr("bluepeass.k8s.subprocess.run", fake_run)
    data = fetch_snapshot(context="fixture")
    assert data["context"] == "fixture"
    assert data["errors"] == [{"resource": "secrets", "message": "forbidden"}]
    assert "secrets" not in data["resources"]
    assert "rbac.authorization.k8s.io:clusterroles" in data["discovery"]["cluster_scoped"]
    assert any(command[:3] == ["kubectl", "--context", "fixture"] for command in calls)
    assert any("--field-selector=type=kubernetes.io/service-account-token" in command for command in calls)


def test_legacy_token_last_used_and_invalid_labels():
    data = snapshot()
    secret = data["resources"]["secrets"][0]
    secret["metadata"]["labels"] = {
        "kubernetes.io/legacy-token-last-used": "2020-01-01",
        "kubernetes.io/legacy-token-invalid-since": "2021-01-01",
    }
    data["resources"]["serviceaccounts"][0]["secrets"] = [{"name": "legacy"}]
    result = analyze_snapshot(data, min_unused_days=90)
    token = result["findings"]["token_secrets"][0]
    assert token["auto_generated"] is True
    assert result["findings"]["inactive_token_secrets"][0]["days_since_last_use"] > 90
    assert result["findings"]["invalid_token_secrets"][0]["name"] == "legacy"


def test_fetched_secret_values_are_not_kept_in_snapshot(monkeypatch):
    import subprocess

    def fake_run(command, **kwargs):
        if "api-resources" in command:
            return subprocess.CompletedProcess(command, 0, "pods\nnodes\n", "")
        if "secrets" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps({"items": [obj("legacy", "team-b", type="kubernetes.io/service-account-token", data={"token": "DO_NOT_KEEP"})]}), "")
        return subprocess.CompletedProcess(command, 0, '{"items": []}', "")

    monkeypatch.setattr("bluepeass.k8s.subprocess.run", fake_run)
    data = fetch_snapshot(context="fixture")
    assert "DO_NOT_KEEP" not in json.dumps(data)


def test_audit_log_observation_respects_scope_and_resource_name(tmp_path):
    event = {
        "stage": "ResponseComplete",
        "stageTimestamp": datetime.now(timezone.utc).isoformat(),
        "verb": "get",
        "user": {"username": "system:serviceaccount:team-b:runner", "groups": ["system:serviceaccounts:team-b"]},
        "objectRef": {"apiGroup": "", "resource": "secrets", "namespace": "team-a", "name": "deploy-key"},
        "annotations": {"authorization.k8s.io/decision": "allow"},
    }
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text(json.dumps(event) + "\n")
    result = analyze_snapshot(snapshot(), audit_events=read_audit_log(str(audit_path)))
    unobserved = {(p["principal"], p["scope"]): p["permissions"] for p in result["findings"]["permissions_not_observed"]}
    assert ("serviceaccount:team-b/runner", "team-a") not in unobserved
    assert ("serviceaccount:team-b/runner", "team-b") in unobserved
    assert result["coverage"]["audit_activity"]["events_considered"] == 1
    assert result["coverage"]["unused_permissions_available"] is False


def test_audit_list_with_named_field_selector_counts_as_observed():
    event = {"verb": "list", "objectRef": {"apiGroup": "", "resource": "secrets"}, "requestURI": "/api/v1/namespaces/team-a/secrets?fieldSelector=metadata.name%3Ddeploy-key"}
    record = {"verb": "list", "api_group": "", "resource": "secrets", "resource_names": ["deploy-key"]}
    assert _audit_permission_matches(event, record)


def test_cli_offline_report(tmp_path):
    path = tmp_path / "snapshot.json"
    output = tmp_path / "report.json"
    path.write_text(json.dumps(snapshot()))
    spec = importlib.util.spec_from_file_location("blue_k8speas", "Blue-K8sPEAS.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--input-json", str(path), "--out-json", str(output), "--max-items", "1"]) == 0
    report = json.loads(output.read_text())
    assert report["provider"] == "k8s"
    assert report["targets"][0]["data"]["findings"]["principals_flagged"]
    assert "DO_NOT_OUTPUT" not in output.read_text()
