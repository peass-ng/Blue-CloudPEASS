"""Config Delivery reaches only observed fleet members with Config Sync authority."""
from copy import deepcopy

from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_config_delivery import select
from peaso.privesc.evaluator import Evaluator
from peaso import privesc
from test_peaso_gcp_config_connector import ACTOR, CLUSTER, PROJECT, envelope, fixture, resource


MEMBERSHIP = PROJECT + "/locations/global/memberships/kcc"
FEATURE = PROJECT + "/locations/global/features/configmanagement"
AUTHORING = [
    "configdelivery.resourceBundles.create", "configdelivery.releases.create",
    "configdelivery.variants.create", "configdelivery.releases.update",
    "configdelivery.fleetPackages.create", "configdelivery.fleetPackages.update",
]


def delivery_fixture():
    gcp, k8s = deepcopy(fixture())
    gcp["collections"][1]["items"][0]["includedPermissions"] = AUTHORING.copy()
    gcp["collections"].extend([
        envelope("service_usage", PROJECT, [{"name": PROJECT +
            "/services/configdelivery.googleapis.com", "state": "ENABLED"}]),
        envelope("fleet_membership", PROJECT, [{"name": MEMBERSHIP, "labels": {"env": "prod"},
            "endpoint": {"gkeCluster": {"resourceLink": "//container.googleapis.com/" + CLUSTER}}}]),
        envelope("fleet_feature", PROJECT, [{"name": FEATURE,
            "membershipSpecs": {MEMBERSHIP: {"configmanagement": {"configSync": {"enabled": True}}}},
            "membershipStates": {MEMBERSHIP: {"state": {"code": "OK"}}}}]),
        envelope("config_delivery_fleet_package", PROJECT, [{"name": PROJECT +
            "/locations/us-central1/fleetPackages/existing", "target": {"fleet": {"project": PROJECT}}}]),
    ])
    k8s["collections"].append(envelope("configsync_rootsync", "*", [resource(
        {"name": "existing", "namespace": "config-management-system"}, spec={})]))
    return gcp, k8s


def selected(gcp, k8s):
    model = GcpModel(gcp)
    model.set_related([k8s])
    cluster = model.cluster_entity(CLUSTER)
    return select(model, {cluster.id: cluster}, model.principals[ACTOR]).get(cluster.id)


def reached(gcp, k8s):
    entry = next(row for row in privesc.catalog()["entries"] if row["id"] ==
                 "gcp-configdelivery-fleetpackage-publish")
    model = GcpModel(gcp)
    model.set_related([k8s])
    return Evaluator(model, [entry], include_unknown=True, admin_scopes={}).run()


def test_exact_fleet_member_with_default_reconciler_is_conditional():
    assert selected(*delivery_fixture())[0] == "conditional"
    edges = reached(*delivery_fixture())
    assert len(edges) == 1 and len(edges[0].targets) == 1
    assert next(iter(edges[0].targets.values())).confidence == "conditional"


def test_other_cluster_or_disabled_config_sync_has_no_claim():
    gcp, k8s = delivery_fixture()
    gcp["collections"][7]["items"][0]["endpoint"]["gkeCluster"]["resourceLink"] += "-other"
    assert selected(gcp, k8s) is None
    gcp, k8s = delivery_fixture()
    gcp["collections"][8]["items"][0]["membershipSpecs"][MEMBERSHIP]["configmanagement"]["configSync"]["enabled"] = False
    assert selected(gcp, k8s) is None


def test_new_package_uses_its_own_default_reconciler():
    gcp, k8s = delivery_fixture()
    k8s["collections"].pop()
    assert selected(gcp, k8s)[0] == "conditional"
    gcp, k8s = delivery_fixture()
    k8s["collections"][-1]["items"][0]["spec"] = {"override": {"roleRefs": [{"kind": "ClusterRole", "name": "limited"}]}}
    assert selected(gcp, k8s)[0] == "conditional"


def test_update_uses_only_the_matching_package_reconciler():
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.fleetPackages.create")
    assert selected(gcp, k8s)[0] == "conditional"
    k8s["collections"][-1]["items"][0]["spec"] = {
        "override": {"roleRefs": [{"kind": "ClusterRole", "name": "limited"}]}}
    k8s["collections"][-1]["items"].append(resource(
        {"name": "unrelated-default", "namespace": "config-management-system"}, spec={}))
    assert selected(gcp, k8s)[0] == "unknown"


def test_update_can_include_member_excluded_by_current_label_selector():
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.fleetPackages.create")
    gcp["collections"][9]["items"][0]["target"]["fleet"]["selector"] = {
        "matchLabels": {"env": "dev"}}
    k8s["collections"][-1]["items"].clear()
    assert selected(gcp, k8s)[0] == "conditional"
    gcp["collections"][9]["items"][0]["target"]["fleet"]["selector"] = {
        "matchLabels": {"env": "prod"}}
    assert selected(gcp, k8s)[0] == "unknown"


def test_update_requires_existing_package_but_create_does_not():
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.fleetPackages.create")
    gcp["collections"][9]["items"].clear()
    assert selected(gcp, k8s) is None
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.fleetPackages.update")
    gcp["collections"][9]["items"].clear()
    assert selected(gcp, k8s)[0] == "conditional"


def test_update_with_package_target_outside_fleet_stays_unresolved():
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.fleetPackages.create")
    gcp["collections"][9]["items"][0]["target"]["fleet"]["project"] = "projects/other-fleet"
    assert selected(gcp, k8s)[0] == "unknown"


def test_missing_authoring_permission_has_no_route():
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.variants.create")
    assert selected(gcp, k8s) is None


def test_disabled_or_unknown_config_delivery_api_is_not_a_cluster_admin_claim():
    gcp, k8s = delivery_fixture()
    gcp["collections"][6]["items"][0]["state"] = "DISABLED"
    assert selected(gcp, k8s) is None
    gcp, k8s = delivery_fixture()
    gcp["collections"].pop(6)
    assert selected(gcp, k8s)[0] == "unknown"


def test_fleet_default_enables_config_sync_without_membership_override():
    gcp, k8s = delivery_fixture()
    feature = gcp["collections"][8]["items"][0]
    feature.pop("membershipSpecs")
    feature["fleetDefaultMemberConfig"] = {"configmanagement": {"configSync": {"enabled": True}}}
    assert selected(gcp, k8s)[0] == "conditional"


def test_same_project_cluster_without_fleet_membership_is_not_a_target():
    gcp, k8s = delivery_fixture()
    gcp["collections"][5]["items"].append({"name": "unregistered", "location": "us-central1",
                                               "endpoint": "2.3.4.5"})
    model = GcpModel(gcp)
    model.set_related([k8s])
    other = model.cluster_entity(PROJECT + "/locations/us-central1/clusters/unregistered")
    member = model.cluster_entity(CLUSTER)
    found = select(model, {member.id: member, other.id: other}, model.principals[ACTOR])
    assert set(found) == {member.id}


def test_malformed_feature_or_reconciler_never_becomes_default_authority():
    gcp, k8s = delivery_fixture()
    gcp["collections"][8]["items"][0]["membershipSpecs"][MEMBERSHIP] = "broken"
    assert selected(gcp, k8s)[0] == "unknown"
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.fleetPackages.create")
    k8s["collections"][-1]["items"][0]["spec"] = {"override": "broken"}
    assert selected(gcp, k8s)[0] == "unknown"
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"].remove("configdelivery.fleetPackages.create")
    k8s["collections"][-1]["items"][0]["spec"] = {"override": {"roleRefs": []}}
    assert selected(gcp, k8s)[0] == "unknown"
    gcp, k8s = delivery_fixture()
    gcp["collections"][7]["items"][0]["endpoint"] = "broken"
    assert selected(gcp, k8s) is None


def test_numeric_project_aliases_join_only_the_same_fleet_member():
    gcp, k8s = delivery_fixture()
    gcp["collections"][0]["items"][0]["name"] = "projects/123456789012"
    numeric_member = MEMBERSHIP.replace("demo-project1", "123456789012")
    gcp["collections"][7]["items"][0]["name"] = numeric_member
    gcp["collections"][7]["items"][0]["endpoint"]["gkeCluster"]["resourceLink"] = (
        "//container.googleapis.com/" + CLUSTER.replace("demo-project1", "123456789012"))
    gcp["collections"][8]["items"][0]["name"] = FEATURE.replace("demo-project1", "123456789012")
    gcp["collections"][8]["items"][0]["membershipSpecs"] = {
        numeric_member: {"configmanagement": {"configSync": {"enabled": True}}}}
    gcp["collections"][8]["items"][0]["membershipStates"] = {
        numeric_member: {"state": {"code": "OK"}}}
    gcp["collections"][9]["items"][0]["target"]["fleet"]["project"] = "projects/123456789012"
    assert selected(gcp, k8s)[0] == "conditional"
