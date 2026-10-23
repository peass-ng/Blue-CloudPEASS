"""Config Management permission routes must reach only an exact fleet member."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_fleet_config_management import select
from peaso.privesc.evaluator import Evaluator
from test_peaso_gcp_config_delivery import delivery_fixture, FEATURE, MEMBERSHIP
from test_peaso_gcp_config_connector import ACTOR, CLUSTER, PROJECT, envelope


MEMBER_FEATURE = MEMBERSHIP + "/features/configmanagement"
ACTIONS = ["gkehub.features.create", "gkehub.features.update",
           "gkehub.membershipfeatures.create", "gkehub.membershipfeatures.update"]


def fixture():
    gcp, k8s = deepcopy(delivery_fixture())
    gcp["collections"][1]["items"][0]["includedPermissions"] = ACTIONS.copy()
    gcp["collections"][8]["items"][0]["resourceState"] = {"state": "ACTIVE"}
    gcp["collections"].append(envelope("fleet_membership_feature", PROJECT, [
        {"name": MEMBER_FEATURE, "lifecycleState": {"state": "ACTIVE"}}]))
    k8s["collections"][-1]["items"][0]["metadata"]["name"] = "root-sync"
    return gcp, k8s


def selected(gcp, k8s):
    model = GcpModel(gcp)
    model.set_related([k8s])
    target = model.cluster_entity(CLUSTER)
    return select(model, {target.id: target}, model.principals[ACTOR]).get(target.id)


def reached(gcp, k8s):
    entry = next(row for row in privesc.catalog()["entries"] if row["id"] ==
                 "gcp-gkehub-features-configmanagement")
    model = GcpModel(gcp)
    model.set_related([k8s])
    return Evaluator(model, [entry], include_unknown=True, admin_scopes={}).run()


def permissions(gcp, *actions):
    gcp["collections"][1]["items"][0]["includedPermissions"] = list(actions)


def test_feature_update_alone_reaches_exact_member():
    gcp, k8s = fixture()
    permissions(gcp, "gkehub.features.update")
    assert selected(gcp, k8s)[0] == "conditional"
    edges = reached(gcp, k8s)
    assert len(edges) == 1 and len(edges[0].targets) == 1
    assert next(iter(edges[0].targets.values())).confidence == "conditional"


def test_membership_feature_update_alone_reaches_exact_member():
    gcp, k8s = fixture()
    permissions(gcp, "gkehub.membershipfeatures.update")
    assert selected(gcp, k8s)[0] == "conditional"
    assert len(reached(gcp, k8s)) == 1


def test_create_and_update_follow_recorded_resource_existence():
    gcp, k8s = fixture()
    permissions(gcp, "gkehub.membershipfeatures.create")
    assert selected(gcp, k8s) is None
    gcp["collections"][-1]["items"].clear()
    assert selected(gcp, k8s)[0] == "conditional"
    permissions(gcp, "gkehub.membershipfeatures.update")
    assert selected(gcp, k8s) is None
    permissions(gcp, "gkehub.features.create")
    assert selected(gcp, k8s) is None
    gcp["collections"][8]["items"].clear()
    assert selected(gcp, k8s)[0] == "conditional"
    permissions(gcp, "gkehub.membershipfeatures.create")
    assert selected(gcp, k8s)[0] == "unknown"


def test_other_member_or_other_cluster_cannot_satisfy_exact_join():
    gcp, k8s = fixture()
    gcp["collections"][7]["items"][0]["endpoint"]["gkeCluster"]["resourceLink"] += "-other"
    assert selected(gcp, k8s) is None
    gcp, k8s = fixture()
    gcp["collections"][-1]["items"][0]["name"] = PROJECT + "/locations/global/memberships/other/features/configmanagement"
    permissions(gcp, "gkehub.membershipfeatures.update")
    assert selected(gcp, k8s) is None


def test_missing_inventory_and_restricted_reconciler_stay_unresolved():
    gcp, k8s = fixture()
    gcp["collections"][-1]["status"] = "access_denied"
    assert selected(gcp, k8s)[0] == "unknown"
    gcp, k8s = fixture()
    k8s["collections"][-1]["items"][0]["spec"] = {"override": {"roleRefs": [
        {"kind": "ClusterRole", "name": "limited"}]}}
    assert selected(gcp, k8s)[0] == "unknown"


def test_explicit_cluster_admin_override_is_still_admin():
    gcp, k8s = fixture()
    k8s["collections"][-1]["items"][0]["spec"] = {"override": {"roleRefs": [
        {"kind": "ClusterRole", "name": "cluster-admin"}]}}
    assert selected(gcp, k8s)[0] == "conditional"


def test_unrelated_role_permission_does_not_reach_this_member():
    gcp, k8s = fixture()
    permissions(gcp, "gkehub.features.update")
    gcp["collections"][2]["items"][0]["bindings"][1]["role"] = "roles/viewer"
    assert selected(gcp, k8s) is None


def test_resource_name_condition_is_checked_on_the_actual_api_resource():
    gcp, k8s = fixture()
    permissions(gcp, "gkehub.features.update")
    binding = gcp["collections"][2]["items"][0]["bindings"][1]
    binding["condition"] = {"expression": "resource.name == '" + FEATURE + "'"}
    assert selected(gcp, k8s)[0] == "conditional"
    binding["condition"] = {"expression": "resource.name == '" + MEMBER_FEATURE + "'"}
    assert selected(gcp, k8s) is None


def test_collected_project_number_alias_preserves_exact_membership_join():
    gcp, k8s = fixture()
    gcp["collections"][0]["items"][0]["name"] = "projects/123456789"
    gcp["collections"][7]["items"][0]["name"] = MEMBERSHIP.replace(PROJECT, "projects/123456789")
    gcp["collections"][8]["items"][0]["membershipSpecs"] = {
        MEMBERSHIP.replace(PROJECT, "projects/123456789"): {"configmanagement": {
            "configSync": {"enabled": True}}}}
    gcp["collections"][-1]["items"][0]["name"] = MEMBER_FEATURE.replace(PROJECT, "projects/123456789")
    permissions(gcp, "gkehub.membershipfeatures.update")
    assert selected(gcp, k8s)[0] == "conditional"
