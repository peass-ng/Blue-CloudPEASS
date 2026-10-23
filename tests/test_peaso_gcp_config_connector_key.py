"""The Config Connector key route needs one joined cluster and an exact target."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_config_connector_key import select
from peaso.privesc.evaluator import Evaluator
from test_peaso_gcp_config_connector import ACTOR, CLUSTER, KCC, PROJECT, WRITE_ROLE, envelope, fixture


TARGET = "target@demo-project1.iam.gserviceaccount.com"
TARGET_ID = "serviceAccount:" + TARGET
KEY_ROLE = PROJECT + "/roles/kcckeyadmin"


def key_fixture():
    gcp, k8s = deepcopy(fixture())
    gcp["collections"][1]["items"][0]["includedPermissions"] = [
        "container.thirdPartyObjects.create", "container.secrets.get", "container.clusters.get"]
    gcp["collections"][1]["items"].append({"name": KEY_ROLE, "includedPermissions": [
        "iam.serviceAccountKeys.create", "iam.serviceAccountKeys.get",
        "iam.serviceAccountKeys.list", "iam.serviceAccountKeys.delete"]})
    gcp["collections"][2]["items"][0]["bindings"].append({
        "role": KEY_ROLE, "members": ["serviceAccount:" + KCC]})
    gcp["collections"][4]["items"].append({"email": TARGET, "projectId": "demo-project1"})
    gcp["collections"].append(envelope("org_policy_effective", PROJECT, [{
        "constraint": "iam.disableServiceAccountKeyCreation", "spec": {"rules": [{"enforce": False}]}}, {
        "constraint": "iam.disableServiceAccountKeyUpload", "spec": {"rules": [{"enforce": True}]}}]))
    k8s["collections"][3]["items"][0]["kccIAMServiceAccountKeyAdvertised"] = True
    return gcp, k8s


def selected(gcp, k8s):
    model = GcpModel(gcp)
    model.set_related([k8s])
    return select(model, {TARGET_ID: model.sas[TARGET_ID]}, model.principals[ACTOR])


def reached(gcp, k8s):
    entry = next(row for row in privesc.catalog()["entries"] if row["id"] ==
                 "gcp-configcontroller-kcc-service-account-key")
    model = GcpModel(gcp)
    model.set_related([k8s])
    return Evaluator(model, [entry], include_unknown=True, admin_scopes={}).run()


def test_exact_key_route_is_conditional():
    gcp, k8s = key_fixture()
    assert selected(gcp, k8s)[TARGET_ID][0] == "conditional"
    edges = reached(gcp, k8s)
    assert len(edges) == 1 and TARGET_ID in edges[0].targets
    assert edges[0].targets[TARGET_ID].confidence == "conditional"


def test_resource_status_can_supply_key_without_secret_read():
    gcp, k8s = key_fixture()
    permissions = gcp["collections"][1]["items"][0]["includedPermissions"]
    permissions.remove("container.secrets.get")
    permissions.append("container.thirdPartyObjects.get")
    assert selected(gcp, k8s)[TARGET_ID][0] == "conditional"
    edges = reached(gcp, k8s)
    assert len(edges) == 1 and TARGET_ID in edges[0].targets


def test_missing_source_or_controller_permission_has_no_key_route():
    gcp, k8s = key_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("container.thirdPartyObjects.create")
    assert selected(gcp, k8s)[TARGET_ID][0] == "unknown"
    gcp, k8s = key_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("container.secrets.get")
    assert TARGET_ID not in selected(gcp, k8s)
    gcp, k8s = key_fixture()
    gcp["collections"][1]["items"][1]["includedPermissions"].remove("iam.serviceAccountKeys.create")
    assert TARGET_ID not in selected(gcp, k8s)


def test_effective_key_policy_and_network_require_evidence():
    gcp, k8s = key_fixture()
    gcp["collections"][-1]["items"][0]["spec"]["rules"][0]["enforce"] = True
    assert TARGET_ID not in selected(gcp, k8s)
    gcp, k8s = key_fixture()
    gcp["collections"].pop()
    assert selected(gcp, k8s)[TARGET_ID][0] == "unknown"
    gcp, k8s = key_fixture()
    gcp["collections"][5]["items"][0]["privateClusterConfig"] = {"enablePrivateEndpoint": True}
    assert selected(gcp, k8s)[TARGET_ID][0] == "unknown"


def test_exact_join_and_advertised_resource_are_required():
    gcp, k8s = key_fixture()
    k8s["collections"][1]["items"][0]["provenance"]["cluster_id"] = "another-cluster"
    assert TARGET_ID not in selected(gcp, k8s)
    gcp, k8s = key_fixture()
    k8s["collections"][3]["items"][0]["kccIAMServiceAccountKeyAdvertised"] = False
    assert TARGET_ID not in selected(gcp, k8s)
    gcp, k8s = key_fixture()
    gcp["collections"][4]["items"][1]["disabled"] = True
    assert TARGET_ID not in selected(gcp, k8s)


def test_direct_target_key_access_is_not_an_escalation():
    gcp, k8s = key_fixture()
    gcp["collections"][2]["items"][0]["bindings"].append({"role": KEY_ROLE, "members": [ACTOR]})
    assert TARGET_ID not in selected(gcp, k8s)


def test_uploaded_public_key_route_needs_no_secret_or_resource_read():
    gcp, k8s = key_fixture()
    permissions = gcp["collections"][1]["items"][0]["includedPermissions"]
    permissions.remove("container.secrets.get")
    policies = gcp["collections"][-1]["items"]
    policies[0]["spec"]["rules"][0]["enforce"] = True
    policies[1]["spec"]["rules"][0]["enforce"] = False
    result = selected(gcp, k8s)[TARGET_ID]
    assert result[0] == "conditional"
    assert "provided_public_key" in result[1]
    assert TARGET_ID in reached(gcp, k8s)[0].targets


def test_upload_policy_and_cluster_authentication_gate_positive_route():
    gcp, k8s = key_fixture()
    permissions = gcp["collections"][1]["items"][0]["includedPermissions"]
    permissions.remove("container.secrets.get")
    assert TARGET_ID not in selected(gcp, k8s)
    gcp["collections"][-1]["items"][1]["spec"]["rules"][0]["enforce"] = False
    permissions.remove("container.clusters.get")
    assert selected(gcp, k8s)[TARGET_ID][0] == "unknown"


def test_namespace_rbac_can_authorize_upload_without_gke_object_iam():
    gcp, k8s = key_fixture()
    permissions = gcp["collections"][1]["items"][0]["includedPermissions"]
    permissions.remove("container.thirdPartyObjects.create")
    permissions.remove("container.secrets.get")
    gcp["collections"][-1]["items"][1]["spec"]["rules"][0]["enforce"] = False
    k8s["collections"].extend([
        envelope("role", "*", [{
            "metadata": {"name": "key-creator", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER},
            "rules": [{"apiGroups": ["iam.cnrm.cloud.google.com"],
                       "resources": ["iamserviceaccountkeys"], "verbs": ["create"]}]}]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [{
            "metadata": {"name": "operator-key", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER},
            "roleRef": {"kind": "Role", "name": "key-creator"},
            "subjects": [{"kind": "User", "name": "operator@example.com"}]}]),
        envelope("clusterrolebinding", "*", []),
    ])
    result = selected(gcp, k8s)[TARGET_ID]
    assert result[0] == "conditional"
    assert "provided_public_key" in result[1]
    edges = reached(gcp, k8s)
    assert len(edges) == 1 and edges[0].targets[TARGET_ID].confidence == "conditional"


def test_rbac_in_a_different_namespace_is_not_a_proven_key_route():
    gcp, k8s = key_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"] = ["container.clusters.get"]
    gcp["collections"][-1]["items"][1]["spec"]["rules"][0]["enforce"] = False
    k8s["collections"].extend([
        envelope("role", "*", [{
            "metadata": {"name": "key-creator", "namespace": "team-b"},
            "provenance": {"cluster_id": CLUSTER},
            "rules": [{"apiGroups": ["iam.cnrm.cloud.google.com"],
                       "resources": ["iamserviceaccountkeys"], "verbs": ["create"]}]}]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [{
            "metadata": {"name": "operator-key", "namespace": "team-b"},
            "provenance": {"cluster_id": CLUSTER},
            "roleRef": {"kind": "Role", "name": "key-creator"},
            "subjects": [{"kind": "User", "name": "operator@example.com"}]}]),
        envelope("clusterrolebinding", "*", []),
    ])
    assert TARGET_ID not in selected(gcp, k8s)


def test_gcp_service_account_rbac_uses_its_verified_unique_id():
    gcp, k8s = key_fixture()
    source_email = "operator-sa@demo-project1.iam.gserviceaccount.com"
    source_id = "serviceAccount:" + source_email
    gcp["collections"][4]["items"].append({
        "email": source_email, "projectId": "demo-project1", "uniqueId": "123456789012345678901"})
    gcp["collections"][2]["items"][0]["bindings"] = [
        binding for binding in gcp["collections"][2]["items"][0]["bindings"]
        if ACTOR not in binding["members"]]
    gcp["collections"][1]["items"][0]["includedPermissions"] = ["container.clusters.get"]
    gcp["collections"][2]["items"][0]["bindings"].append({
        "role": WRITE_ROLE, "members": [source_id]})
    gcp["collections"][-1]["items"][1]["spec"]["rules"][0]["enforce"] = False
    k8s["collections"].extend([
        envelope("role", "*", [{
            "metadata": {"name": "key-creator", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER},
            "rules": [{"apiGroups": ["iam.cnrm.cloud.google.com"],
                       "resources": ["iamserviceaccountkeys"], "verbs": ["create"]}]}]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [{
            "metadata": {"name": "operator-key", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER},
            "roleRef": {"kind": "Role", "name": "key-creator"},
            "subjects": [{"kind": "User", "name": "123456789012345678901"}]}]),
        envelope("clusterrolebinding", "*", []),
    ])
    model = GcpModel(gcp)
    model.set_related([k8s])
    result = select(model, {TARGET_ID: model.sas[TARGET_ID]}, model.principals[source_id])
    assert result[TARGET_ID][0] == "conditional"


def test_unresolved_google_group_membership_keeps_rbac_route_unknown():
    gcp, k8s = key_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"] = ["container.clusters.get"]
    gcp["collections"][-1]["items"][1]["spec"]["rules"][0]["enforce"] = False
    k8s["collections"].extend([
        envelope("role", "*", [{
            "metadata": {"name": "key-creator", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER},
            "rules": [{"apiGroups": ["iam.cnrm.cloud.google.com"],
                       "resources": ["iamserviceaccountkeys"], "verbs": ["create"]}]}]),
        envelope("clusterrole", "*", []),
        envelope("rolebinding", "*", [{
            "metadata": {"name": "team-key", "namespace": "team-a"},
            "provenance": {"cluster_id": CLUSTER},
            "roleRef": {"kind": "Role", "name": "key-creator"},
            "subjects": [{"kind": "Group", "name": "security-team@example.com"}]}]),
        envelope("clusterrolebinding", "*", []),
    ])
    assert selected(gcp, k8s)[TARGET_ID][0] == "unknown"
