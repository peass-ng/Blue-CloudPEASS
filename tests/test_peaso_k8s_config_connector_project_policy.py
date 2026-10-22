"""In-cluster Config Connector project IAM grants stay tied to the exact policy."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.k8s import K8sModel
from peaso.privesc.effective_permissions.k8s_config_connector_project_policy import select, targets
from peaso.privesc.evaluator import Evaluator
from peaso.privesc.graph import GraphBuilder
from test_peaso_gcp_config_connector import CLUSTER, envelope, fixture as cloud_fixture


SOURCE = f"k8s:{CLUSTER}:sa:team-a:operator"


def fixture(*, namespace="team-a", verbs=("create", "patch"), resource_names=None):
    gcp, k8s = deepcopy(cloud_fixture())
    rule = {"apiGroups": ["iam.cnrm.cloud.google.com"],
            "resources": ["iampolicymembers", "iampolicies"], "verbs": list(verbs)}
    if resource_names is not None:
        rule["resourceNames"] = resource_names
    k8s["collections"].extend([
        envelope("serviceaccount", "*", [{
            "metadata": {"name": "operator", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER}}]),
        envelope("role", "*", [{"metadata": {"name": "policy-writer", "namespace": namespace},
                                  "provenance": {"cluster_id": CLUSTER}, "rules": [rule]}]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [{
            "metadata": {"name": "policy-writer", "namespace": namespace},
            "provenance": {"cluster_id": CLUSTER},
            "roleRef": {"kind": "Role", "name": "policy-writer"},
            "subjects": [{"kind": "ServiceAccount", "namespace": "team-a", "name": "operator"}]}]),
        envelope("clusterrolebinding", "*", []),
    ])
    return gcp, k8s


def evaluate(gcp, k8s):
    model = K8sModel(k8s)
    model.set_related([gcp])
    candidate = targets(model)
    source = model.principals[SOURCE]
    selected = select(model, candidate, source)
    entry = next(entry for entry in privesc.catalog()["entries"]
                 if entry["id"] == "k8s-configconnector-project-iam-grant")
    reaches = [reach for reach in Evaluator(model, [entry], include_unknown=True).run()
               if reach.source.id == SOURCE]
    return model, selected, reaches


def test_create_and_existing_policy_patch_reach_exact_project():
    model, selected, reaches = evaluate(*fixture())
    assert {target.attrs["kcc_operation"] for target in targets(model).values()} == {"create", "update"}
    assert len(selected) == 2 and all(verdict[0] == "conditional" for verdict in selected.values())
    assert len(reaches) == 1 and len(reaches[0].targets) == 2
    assert all(grant.confidence == "conditional" for grant in reaches[0].targets.values())
    graph = GraphBuilder(model)
    for reach in reaches:
        graph.add(reach)
    assert graph.findings and any(node.get("type") == "gcp_verified_authority"
                                  for node in graph.nodes.values())


def test_wrong_namespace_and_other_policy_name_do_not_reach_project():
    assert evaluate(*fixture(namespace="team-b"))[1:] == ({}, [])
    _, selected, reaches = evaluate(*fixture(verbs=("patch",), resource_names=["other-policy"]))
    assert not selected and not reaches
    _, selected, reaches = evaluate(*fixture(verbs=("patch",), resource_names=["existing"]))
    assert len(selected) == 1 and ":update:" in next(iter(selected))
    assert len(reaches) == 1 and len(reaches[0].targets) == 1


def test_controller_without_project_policy_rights_has_no_target():
    gcp, k8s = fixture()
    gcp["collections"][2]["items"][0]["bindings"].pop(0)
    assert evaluate(gcp, k8s)[1:] == ({}, [])


def test_verified_existing_workload_identity_control_is_not_new_gain():
    gcp, k8s = fixture()
    gcp["collections"][4]["items"].append({"email": "operator@demo-project1.iam.gserviceaccount.com",
                                               "projectId": "demo-project1",
                                               "iamPolicy": {"bindings": [{
                                                   "role": "roles/iam.workloadIdentityUser",
                                                   "members": ["serviceAccount:demo-project1.svc.id.goog[team-a/operator]"]}]}})
    gcp["collections"][2]["items"][0]["bindings"].append({
        "role": "roles/resourcemanager.projectIamAdmin",
        "members": ["serviceAccount:operator@demo-project1.iam.gserviceaccount.com"]})
    k8s["collections"][-5]["items"][0]["metadata"]["annotations"] = {
        "iam.gke.io/gcp-service-account": "operator@demo-project1.iam.gserviceaccount.com"}
    assert not evaluate(gcp, k8s)[1]


def test_unresolved_annotated_workload_identity_cannot_be_called_new_access():
    gcp, k8s = fixture()
    k8s["collections"][-5]["items"][0]["metadata"]["annotations"] = {
        "iam.gke.io/gcp-service-account": "uncollected@demo-project1.iam.gserviceaccount.com"}
    _, selected, reaches = evaluate(gcp, k8s)
    assert selected and all(verdict[0] == "unknown" for verdict in selected.values())
    assert len(reaches) == 1 and all(grant.confidence == "unknown"
                                     for grant in reaches[0].targets.values())


def test_incomplete_rbac_and_unhealthy_controller_never_claim_definite_access():
    gcp, k8s = fixture()
    k8s["collections"][-2]["status"] = "access_denied"
    _, selected, reaches = evaluate(gcp, k8s)
    assert all(verdict[0] == "unknown" for verdict in selected.values())
    assert len(reaches) == 1 and all(grant.confidence == "unknown"
                                     for grant in reaches[0].targets.values())
    gcp, k8s = fixture()
    k8s["collections"][1]["items"][0]["status"]["healthy"] = False
    assert not evaluate(gcp, k8s)[1]


def test_missing_related_gcp_snapshot_stays_unknown_for_gke_cluster():
    _, k8s = fixture()
    model = K8sModel(k8s)
    model.set_related([])
    entry = next(entry for entry in privesc.catalog()["entries"]
                 if entry["id"] == "k8s-configconnector-project-iam-grant")
    reaches = [reach for reach in Evaluator(model, [entry], include_unknown=True).run()
               if reach.source.id == SOURCE]
    assert len(reaches) == 1
    assert all(grant.confidence == "unknown" for grant in reaches[0].targets.values())


def test_duplicate_related_gcp_snapshots_do_not_create_a_definite_path():
    gcp, k8s = fixture()
    model = K8sModel(k8s)
    model.set_related([gcp, deepcopy(gcp)])
    entry = next(entry for entry in privesc.catalog()["entries"]
                 if entry["id"] == "k8s-configconnector-project-iam-grant")
    reaches = [reach for reach in Evaluator(model, [entry], include_unknown=True).run()
               if reach.source.id == SOURCE]
    assert len(reaches) == 1
    assert all(grant.confidence == "unknown" for grant in reaches[0].targets.values())
