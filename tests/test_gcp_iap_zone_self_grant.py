"""A zone IAP policy grant needs a new permission on an exact VM in that zone."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_gcp_iap_instance_self_grant import case, PROJECT, RESOURCE, SOURCE, ZONE


ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-iap-tunnelzones-setiampolicy-zone-self-grant")


def zone_case():
    snap = case()
    snap["collections"][1]["items"][0]["includedPermissions"].append(
        "iap.tunnelZones.setIamPolicy")
    return snap


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_zone_policy_write_gains_new_access_on_exact_vm():
    assert reached(zone_case()) == [("gcp_verified_authority:possible-iap-zone-self-grant:" +
                                RESOURCE, "conditional")]
    snap = zone_case()
    snap["collections"][-2]["items"][0]["status"] = "TERMINATED"
    assert reached(snap)[0][1] == "conditional"


def test_inherited_access_or_wrong_zone_condition_blocks_definite_path():
    snap = zone_case()
    snap["collections"][-1]["items"][0]["iamPolicy"]["bindings"] = [
        {"role": "roles/iap.tunnelResourceAccessor", "members": [SOURCE]}]
    assert reached(snap) == []
    snap = zone_case()
    binding = snap["collections"][2]["items"][0]["bindings"][0]
    binding["condition"] = {"expression": 'resource.name == "' + ZONE + '"'}
    assert reached(snap)[0][1] == "conditional"
    binding["condition"] = {"expression": 'resource.name == "' +
                            PROJECT + '/iap_tunnel/zones/us-east1-b"'}
    assert reached(snap) == []


def test_missing_vm_or_policy_is_not_definite():
    snap = zone_case()
    snap["collections"][-2]["items"] = []
    snap["collections"][-2]["status"] = "empty"
    assert reached(snap) == []
    for level in (0, 1, 2):
        snap = deepcopy(zone_case())
        snap["collections"][-1]["items"][level]["_coverage"]["iamPolicy"]["status"] = "denied"
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_one_vm_already_accessible_does_not_hide_other_new_grant():
    snap = zone_case()
    second = deepcopy(snap["collections"][-2]["items"][0])
    second["name"] = "login2"
    second["selfLink"] = second["selfLink"].replace("login1", "login2")
    snap["collections"][-2]["items"].append(second)
    second_policy = deepcopy(snap["collections"][-1]["items"][2])
    second_policy["name"] = RESOURCE.replace("login1", "login2")
    second_policy["iamPolicy"]["bindings"] = [
        {"role": "roles/iap.tunnelResourceAccessor", "members": [SOURCE]}]
    snap["collections"][-1]["items"].append(second_policy)
    assert reached(snap) == [("gcp_verified_authority:possible-iap-zone-self-grant:" +
                              RESOURCE, "conditional")]
