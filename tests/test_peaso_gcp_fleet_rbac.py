"""Fleet RBAC paths must stay on the exact member and an admin-capable role."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_fleet_rbac import _grant, select
from peaso.privesc.evaluator import Evaluator
from test_peaso_gcp_config_delivery import (
    ACTOR, CLUSTER, MEMBERSHIP, PROJECT, delivery_fixture, envelope, resource,
)


ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-gkehub-rbacrolebindings-gateway")
SCOPE = PROJECT + "/locations/global/scopes/team-a"
BINDING = MEMBERSHIP + "/rbacrolebindings/operator"


def case(*, permissions=None, binding=False, scope=False):
    gcp, k8s = delivery_fixture()
    gcp["collections"][1]["items"][0]["includedPermissions"] = permissions or [
        "gkehub.rbacrolebindings.create", "container.clusters.get"]
    gcp["collections"][5]["items"][0]["privateClusterConfig"] = {
        "enablePrivateEndpoint": False}
    gcp["collections"][5]["items"][0]["status"] = "RUNNING"
    gcp["collections"][7]["items"][0]["state"] = {"code": "READY"}
    gcp["collections"].extend([
        envelope("fleet_member_rbac_binding", PROJECT,
                 [{"name": BINDING, "user": "other@example.com", "role": {
                     "customRole": "fleet-admin"}, "state": {"code": "READY"}}] if binding else []),
        envelope("fleet_scope", PROJECT, [{"name": SCOPE, "state": {"code": "READY"}}]
                 if scope else []),
        envelope("fleet_scope_member", PROJECT,
                 [{"scope": SCOPE, "membership": MEMBERSHIP}] if scope else []),
        envelope("fleet_scope_rbac_binding", PROJECT, []),
    ])
    k8s["collections"].append(envelope("clusterrole", "*", [resource(
        {"name": "fleet-admin"}, rules=[{"apiGroups": ["*"],
                                        "resources": ["*"], "verbs": ["*"]}])]))
    k8s["collections"].append(envelope("clusterrolebinding", "*", []))
    return gcp, k8s


def selected(gcp, k8s):
    model = GcpModel(gcp)
    model.set_related([k8s])
    target = model.cluster_entity(CLUSTER)
    return select(model, {target.id: target}, model.principals[ACTOR]).get(target.id)


def reached(gcp, k8s):
    model = GcpModel(gcp)
    model.set_related([k8s])
    return [edge for edge in Evaluator(model, [ENTRY], include_unknown=True,
                                       admin_scopes={}).run() if edge.source.id == ACTOR]


def test_exact_member_create_and_existing_binding_update():
    assert selected(*case())[0] == "conditional"
    assert len(reached(*case())) == 1
    update = case(permissions=["gkehub.rbacrolebindings.update",
                               "container.clusters.get"], binding=True)
    assert selected(*update)[0] == "conditional"
    assert len(reached(*update)) == 1
    assert selected(*case(permissions=["gkehub.rbacrolebindings.update",
                                       "container.clusters.get"])) is None


def test_scope_only_create_reaches_its_member():
    gcp, k8s = case(scope=True)
    gcp["collections"][1]["items"][0]["includedPermissions"] = ["container.clusters.get"]
    gcp["collections"][1]["items"].append({
        "name": PROJECT + "/roles/scopeRbacWriter",
        "includedPermissions": ["gkehub.rbacrolebindings.create"]})
    gcp["collections"][2]["items"][0]["bindings"].append({
        "role": PROJECT + "/roles/scopeRbacWriter", "members": [ACTOR],
        "condition": {"expression": "resource.name == '" + SCOPE + "'"}})
    model = GcpModel(gcp)
    assert _grant(model, model.principals[ACTOR],
                  "gkehub.rbacrolebindings.create", MEMBERSHIP) is None
    assert _grant(model, model.principals[ACTOR],
                  "gkehub.rbacrolebindings.create", SCOPE) == "derived"
    assert selected(gcp, k8s)[0] == "conditional"
    assert len(reached(gcp, k8s)) == 1
    gcp["collections"][12]["items"][0]["membership"] = (
        PROJECT + "/locations/global/memberships/another")
    assert selected(gcp, k8s) is None
    gcp["collections"][12]["items"].clear()
    gcp["collections"][12]["status"] = "denied"
    assert selected(gcp, k8s)[0] == "unknown"


def test_wrong_member_role_and_readiness_do_not_claim_admin():
    gcp, k8s = case()
    gcp["collections"][7]["items"][0]["endpoint"]["gkeCluster"]["resourceLink"] += "-other"
    assert selected(gcp, k8s) is None
    gcp, k8s = case()
    k8s["collections"][-2]["items"][0]["rules"] = [{
        "apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}]
    assert selected(gcp, k8s) is None
    gcp, k8s = case()
    gcp["collections"][7]["items"][0]["state"] = {"code": "DELETING"}
    assert selected(gcp, k8s) is None
    gcp, k8s = case()
    gcp["collections"][5]["items"][0]["status"] = "ERROR"
    assert selected(gcp, k8s)[0] == "unknown"


def test_missing_role_or_restricted_endpoint_stays_unresolved():
    gcp, k8s = case()
    k8s["collections"].pop(-2)
    assert selected(gcp, k8s)[0] == "unknown"
    gcp, k8s = case()
    gcp["collections"][5]["items"][0]["privateClusterConfig"] = {
        "enablePrivateEndpoint": True}
    assert selected(gcp, k8s)[0] == "unknown"


def test_existing_binding_must_belong_to_the_exact_member():
    gcp, k8s = case(permissions=["gkehub.rbacrolebindings.update",
                                  "container.clusters.get"], binding=True)
    gcp["collections"][10]["items"][0]["name"] = (
        PROJECT + "/locations/global/memberships/other/rbacrolebindings/operator")
    assert selected(gcp, k8s) is None


def test_gateway_needs_credentials_read_and_a_mutating_verb():
    gcp, k8s = case(permissions=["gkehub.rbacrolebindings.create",
                                  "gkehub.gateway.generateCredentials",
                                  "gkehub.gateway.get", "gkehub.gateway.post"])
    assert selected(gcp, k8s)[0] == "conditional"
    gcp["collections"][1]["items"][0]["includedPermissions"].remove(
        "gkehub.gateway.post")
    assert selected(gcp, k8s) is None or selected(gcp, k8s)[0] == "unknown"
    gcp["collections"][1]["items"][0]["includedPermissions"].append(
        "gkehub.gateway.stream")
    assert selected(gcp, k8s) is None or selected(gcp, k8s)[0] == "unknown"


def test_existing_admin_binding_is_not_a_new_privilege_gain():
    gcp, k8s = case()
    k8s["collections"][-1] = envelope("clusterrolebinding", "*", [resource(
        {"name": "already-admin"}, roleRef={"kind": "ClusterRole", "name": "fleet-admin"},
        subjects=[{"kind": "User", "name": ACTOR.removeprefix("user:")}])])
    assert selected(gcp, k8s) is None
    k8s["collections"][-1]["items"][0]["subjects"] = [
        {"kind": "Group", "name": "other-team"}]
    assert selected(gcp, k8s)[0] == "conditional"
