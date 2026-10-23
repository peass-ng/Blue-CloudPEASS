"""Config Connector IAM paths stay tied to one cluster, namespace and project."""
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_config_connector import candidates, select
from peaso.privesc.evaluator import Evaluator
from peaso import privesc


PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/kcc"
KCC = "kcc@demo-project1.iam.gserviceaccount.com"
ACTOR = "user:operator@example.com"
WRITE_ROLE = PROJECT + "/roles/kccwriter"


def envelope(kind, scope, rows):
    return {"type": kind, "scope": scope, "status": "collected" if rows else "empty", "items": rows}


def resource(metadata, **fields):
    return {"metadata": metadata, "provenance": {"cluster_id": CLUSTER}, **fields}


def fixture():
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", PROJECT, [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", PROJECT, [{"name": WRITE_ROLE, "includedPermissions": [
            "container.thirdPartyObjects.create", "container.thirdPartyObjects.update",
            "container.clusters.get"]}]),
        envelope("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": "roles/resourcemanager.projectIamAdmin", "members": ["serviceAccount:" + KCC]},
            {"role": WRITE_ROLE, "members": [ACTOR]}]}]),
        envelope("iam_deny_policy", PROJECT, []),
        envelope("service_account", PROJECT, [{"email": KCC, "projectId": "demo-project1"}]),
        envelope("gke_cluster", PROJECT, [{"name": "kcc", "location": "us-central1", "endpoint": "1.2.3.4",
                                           "masterAuthorizedNetworksConfig": {"enabled": False}}]),
    ]}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        envelope("configconnector", "*", [resource(
            {"name": "configconnector.core.cnrm.cloud.google.com"},
            spec={"mode": "namespaced"}, status={"healthy": True})]),
        envelope("configconnectorcontext", "*", [resource(
            {"name": "configconnectorcontext.core.cnrm.cloud.google.com", "namespace": "team-a"},
            spec={"googleServiceAccount": KCC}, status={"healthy": True})]),
        envelope("namespace", "*", [resource({"name": "team-a"})]),
        envelope("api_discovery", "*", [{"provenance": {"cluster_id": CLUSTER},
            "kccIAMPolicyMemberAdvertised": True, "kccIAMPolicyAdvertised": True,
            "kccIAMPartialPolicyAdvertised": True}]),
        envelope("kcc_iampolicy", "*", [resource({"name": "existing", "namespace": "team-a"},
            spec={"resourceRef": {"kind": "Project", "external": PROJECT}, "bindings": []})]),
        envelope("kcc_iampartialpolicy", "*", []),
    ]}
    return gcp, k8s


def evaluated(gcp, k8s):
    model = GcpModel(gcp)
    model.set_related([k8s])
    found = candidates(model)
    return model, found, select(model, found, model.principals[ACTOR])


def reaches(gcp, k8s):
    entry = next(row for row in privesc.catalog()["entries"] if row["id"] ==
                 "gcp-configcontroller-kcc-resource-write")
    model = GcpModel(gcp)
    model.set_related([k8s])
    return Evaluator(model, [entry], include_unknown=True, admin_scopes={}).run()


def test_create_and_existing_policy_update_are_bounded_to_same_project():
    model, found, selected = evaluated(*fixture())
    assert {node.attrs["kcc_operation"] for node in found.values()} == {"create", "update"}
    assert {node.attrs["kcc_resource_kind"] for node in found.values()} == {"IAMPolicyMember", "kcc_iampolicy"}
    assert all(node.scope == PROJECT and node.attrs["host_resource"] == CLUSTER and
               node.attrs["kcc_namespace"] == "team-a" and node.attrs["kcc_service_account"] == KCC
               for node in found.values())
    assert set(selected) == set(found)
    assert all(floor[0] == "conditional" for floor in selected.values())
    assert all(model.placeholder_values("target.host_resource", model.principals[ACTOR], node) == [CLUSTER]
               for node in found.values())


def test_missing_downstream_or_wrong_policy_target_cannot_create_update_path():
    gcp, k8s = fixture()
    gcp["collections"][2]["items"][0]["bindings"].pop(0)
    assert not evaluated(gcp, k8s)[1]
    gcp, k8s = fixture()
    k8s["collections"][4]["items"][0]["spec"]["resourceRef"]["external"] = "projects/other-project1"
    found = evaluated(gcp, k8s)[1]
    assert {node.attrs["kcc_operation"] for node in found.values()} == {"create"}


def test_missing_resource_kind_or_wrong_namespace_never_becomes_update_path():
    gcp, k8s = fixture()
    k8s["collections"][3]["items"][0]["kccIAMPolicyMemberAdvertised"] = False
    k8s["collections"][4]["items"][0]["metadata"]["namespace"] = "team-b"
    assert not evaluated(gcp, k8s)[1]


def test_unreachable_api_stays_unresolved_and_direct_control_is_not_escalation():
    gcp, k8s = fixture()
    gcp["collections"][5]["items"][0]["privateClusterConfig"] = {"enablePrivateEndpoint": True}
    _, found, selected = evaluated(gcp, k8s)
    assert found and all(floor[0] == "unknown" for floor in selected.values())
    gcp, k8s = fixture()
    gcp["collections"][2]["items"][0]["bindings"].append(
        {"role": "roles/resourcemanager.projectIamAdmin", "members": [ACTOR]})
    _, found, selected = evaluated(gcp, k8s)
    assert found and not selected


def test_wrong_cluster_or_unhealthy_controller_cannot_supply_identity():
    gcp, k8s = fixture()
    k8s["collections"][1]["items"][0]["provenance"]["cluster_id"] = "another-cluster"
    assert not evaluated(gcp, k8s)[1]
    gcp, k8s = fixture()
    k8s["collections"][1]["items"][0]["status"]["healthy"] = False
    assert not evaluated(gcp, k8s)[2]


def test_evaluator_requires_the_write_verb_for_each_collected_route():
    gcp, k8s = fixture()
    reached = reaches(gcp, k8s)
    assert len(reached) == 1 and len(reached[0].targets) == 2
    assert all(grant.confidence == "conditional" for grant in reached[0].targets.values())
    for permission, expected in (("container.thirdPartyObjects.create", "create"),
                                 ("container.thirdPartyObjects.update", "update")):
        gcp, k8s = fixture()
        gcp["collections"][1]["items"][0]["includedPermissions"] = [permission, "container.clusters.get"]
        reached = reaches(gcp, k8s)
        assert len(reached) == 1
        named = [tid for tid, grant in reached[0].targets.items()
                 if grant.confidence == "conditional"]
        assert len(named) == 1 and expected in named[0]


def test_evaluator_keeps_private_endpoint_as_unresolved():
    gcp, k8s = fixture()
    gcp["collections"][5]["items"][0]["privateClusterConfig"] = {"enablePrivateEndpoint": True}
    reached = reaches(gcp, k8s)
    assert len(reached) == 1
    assert all(target.startswith("unresolved:") and grant.confidence == "unknown"
               for target, grant in reached[0].targets.items())


def test_incomplete_deny_inventory_keeps_permissions_unresolved():
    gcp, k8s = fixture()
    gcp["collections"].pop(3)
    reached = reaches(gcp, k8s)
    assert len(reached) == 1
    assert all(target.startswith("unresolved:") and grant.confidence == "unknown"
               for target, grant in reached[0].targets.items())


def test_cluster_mode_uses_shared_identity_without_context_inventory():
    gcp, k8s = fixture()
    k8s["collections"][0]["items"][0]["spec"] = {"mode": "cluster", "googleServiceAccount": KCC}
    k8s["collections"].pop(1)
    reached = reaches(gcp, k8s)
    assert len(reached) == 1 and len(reached[0].targets) == 2


def test_missing_kcc_resource_discovery_is_visible_as_unresolved():
    gcp, k8s = fixture()
    for field in ("kccIAMPolicyMemberAdvertised", "kccIAMPolicyAdvertised",
                  "kccIAMPartialPolicyAdvertised"):
        k8s["collections"][3]["items"][0].pop(field)
    reached = reaches(gcp, k8s)
    assert len(reached) == 1
    assert all(target.startswith("unknown:") or target.startswith("unresolved:")
               for target in reached[0].targets)


def test_gcp_user_namespace_rbac_create_and_patch_are_exact():
    gcp, k8s = fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"] = ["container.clusters.get"]
    k8s["collections"].extend([
        envelope("role", "*", [resource(
            {"name": "project-policy-writer", "namespace": "team-a"},
            rules=[
                {"apiGroups": ["iam.cnrm.cloud.google.com"],
                 "resources": ["iampolicymembers"], "verbs": ["create"]},
                {"apiGroups": ["iam.cnrm.cloud.google.com"],
                 "resources": ["iampolicies"], "verbs": ["patch"]}])]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [resource(
            {"name": "operator-policy", "namespace": "team-a"},
            roleRef={"kind": "Role", "name": "project-policy-writer"},
            subjects=[{"kind": "User", "name": "operator@example.com"}])]),
        envelope("clusterrolebinding", "*", []),
    ])
    found = reaches(gcp, k8s)
    assert len(found) == 1
    assert len(found[0].targets) == 2
    assert any(":create:" in tid for tid in found[0].targets)
    assert any(":update:" in tid for tid in found[0].targets)
    assert all(grant.confidence == "conditional" for grant in found[0].targets.values())


def test_wrong_namespace_rbac_is_not_project_iam_control():
    gcp, k8s = fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"] = ["container.clusters.get"]
    k8s["collections"].extend([
        envelope("role", "*", [resource(
            {"name": "project-policy-writer", "namespace": "team-b"},
            rules=[{"apiGroups": ["iam.cnrm.cloud.google.com"],
                    "resources": ["iampolicymembers", "iampolicies"],
                    "verbs": ["create", "patch"]}])]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [resource(
            {"name": "operator-policy", "namespace": "team-b"},
            roleRef={"kind": "Role", "name": "project-policy-writer"},
            subjects=[{"kind": "User", "name": "operator@example.com"}])]),
        envelope("clusterrolebinding", "*", []),
    ])
    assert not evaluated(gcp, k8s)[2]


def test_named_kcc_project_reference_resolves_exact_ready_project():
    gcp, k8s = fixture()
    k8s["collections"][4]["items"][0]["spec"]["resourceRef"] = {
        "kind": "Project", "name": "managed-project"}
    project = resource(
        {"name": "managed-project", "namespace": "team-a", "generation": 1},
        spec={"resourceID": "demo-project1"},
        status={"number": "123456789", "observedGeneration": 1,
                "conditions": [{"type": "Ready", "status": "True"}]})
    k8s["collections"].append(envelope("kcc_project", "*", [project]))
    found = evaluated(gcp, k8s)[1]
    assert {node.attrs["kcc_operation"] for node in found.values()} == {"create", "update"}
    project["status"]["observedGeneration"] = 0
    assert {node.attrs["kcc_operation"] for node in evaluated(gcp, k8s)[1].values()} == {"create"}


def test_unresolved_named_project_reference_stays_visible():
    gcp, k8s = fixture()
    k8s["collections"][3]["items"][0]["kccIAMPolicyMemberAdvertised"] = False
    k8s["collections"][4]["items"][0]["spec"]["resourceRef"] = {
        "kind": "Project", "name": "managed-project"}
    gcp["collections"][1]["items"][0]["includedPermissions"] = [
        "container.thirdPartyObjects.update", "container.clusters.get"]
    found = reaches(gcp, k8s)
    assert found
    assert all(tid.startswith(("unknown:", "unresolved:")) for reach in found
               for tid in reach.targets)
