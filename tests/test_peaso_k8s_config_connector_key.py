"""In-cluster RBAC reaches only a watched namespace and a usable Google key target."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.k8s import K8sModel
from peaso.privesc.effective_permissions.k8s_config_connector_key import select
from peaso.privesc.evaluator import Evaluator
from peaso.privesc.graph import GraphBuilder
from test_peaso_gcp_config_connector_key import TARGET, TARGET_ID, key_fixture
from test_peaso_gcp_config_connector import CLUSTER, KCC, PROJECT, envelope


SOURCE = f"k8s:{CLUSTER}:sa:team-a:operator"


def fixture(*, read_secret=False, upload_allowed=True, binding_namespace="team-a"):
    gcp, k8s = deepcopy(key_fixture())
    policies = gcp["collections"][-1]["items"]
    policies[1]["spec"]["rules"][0]["enforce"] = not upload_allowed
    rules = [{"apiGroups": ["iam.cnrm.cloud.google.com"],
              "resources": ["iamserviceaccountkeys"], "verbs": ["create"]}]
    if read_secret:
        rules.append({"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]})
    k8s["collections"].extend([
        envelope("serviceaccount", "*", [{
            "metadata": {"name": "operator", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER}}]),
        envelope("role", "*", [{
            "metadata": {"name": "key-creator", "namespace": binding_namespace},
            "provenance": {"cluster_id": CLUSTER}, "rules": rules}]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [{
            "metadata": {"name": "operator-key", "namespace": binding_namespace},
            "provenance": {"cluster_id": CLUSTER},
            "roleRef": {"kind": "Role", "name": "key-creator"},
            "subjects": [{"kind": "ServiceAccount", "namespace": "team-a", "name": "operator"}]}]),
        envelope("clusterrolebinding", "*", []),
    ])
    return gcp, k8s


def evaluate(gcp, k8s):
    model = K8sModel(k8s)
    model.set_related([gcp])
    target = next(sa for sa in model.targets("gcp_service_account") if sa.id == TARGET_ID)
    verdict = select(model, {TARGET_ID: target}, model.principals[SOURCE]).get(TARGET_ID)
    entry = next(row for row in privesc.catalog()["entries"]
                 if row["id"] == "k8s-configconnector-service-account-key")
    reaches = [reach for reach in Evaluator(model, [entry]).run()
               if reach.source.id == SOURCE]
    return verdict, reaches


def test_supplied_key_reaches_exact_google_service_account():
    verdict, reaches = evaluate(*fixture())
    assert verdict[0] == "conditional"
    assert "provided_public_key" in verdict[1]
    assert reaches and TARGET_ID in reaches[0].targets


def test_cross_cloud_graph_keeps_the_exact_google_target():
    gcp, k8s = fixture()
    model = K8sModel(k8s)
    model.set_related([gcp])
    entry = next(row for row in privesc.catalog()["entries"]
                 if row["id"] == "k8s-configconnector-service-account-key")
    reaches = Evaluator(model, [entry]).run()
    graph = GraphBuilder(model)
    for reach in reaches:
        graph.add(reach)
    assert len(graph.findings) == 1
    targets = [graph.nodes[edge["target"]] for edge in graph.edges.values()]
    assert any(TARGET_ID in target.get("members", []) for target in targets)


def test_wrong_namespace_does_not_reach_watched_controller():
    verdict, reaches = evaluate(*fixture(binding_namespace="team-b"))
    assert verdict is None
    assert reaches == []


def test_generated_key_requires_read_and_creation_policy():
    gcp, k8s = fixture(read_secret=True, upload_allowed=False)
    assert evaluate(gcp, k8s)[0][0] == "conditional"
    gcp["collections"][-1]["items"][0]["spec"]["rules"][0]["enforce"] = True
    assert evaluate(gcp, k8s)[0] is None


def test_missing_controller_permission_blocks_key_path():
    gcp, k8s = fixture()
    gcp["collections"][1]["items"][1]["includedPermissions"].remove("iam.serviceAccountKeys.create")
    assert evaluate(gcp, k8s)[0] is None


def test_disabled_target_and_unverified_policy_do_not_claim_a_key():
    gcp, k8s = fixture()
    gcp["collections"][4]["items"][1]["disabled"] = True
    assert evaluate(gcp, k8s)[0] is None
    gcp, k8s = fixture()
    gcp["collections"].pop()
    assert evaluate(gcp, k8s)[0][0] == "unknown"


def test_existing_workload_identity_access_is_not_a_new_target_gain():
    gcp, k8s = fixture()
    for collection in k8s["collections"]:
        if collection["type"] == "serviceaccount":
            collection["items"][0]["metadata"]["annotations"] = {
                "iam.gke.io/gcp-service-account": TARGET}
    gcp["collections"][4]["items"][1]["iamPolicy"] = {"bindings": [{
        "role": "roles/iam.workloadIdentityUser",
        "members": ["serviceAccount:demo-project1.svc.id.goog[team-a/operator]"]}]}
    assert evaluate(gcp, k8s)[0] is None
