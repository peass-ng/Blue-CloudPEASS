"""Exact App Engine debug path joins and negative cases."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
EMAIL = "runtime@p1.iam.gserviceaccount.com"
VERSION = "apps/p1/services/default/versions/v1"
APP_INSTANCE = VERSION + "/instances/i1"
VM = "projects/p1/zones/us-central1-a/instances/gae-vm"
TECHNIQUE = "gcp-appengine-instances-enabledebug"


def snapshot(actions=("appengine.instances.enableDebug",), *, os_login=False, debug=False,
             ip=True, service_account=EMAIL):
    def row(kind, items, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": items, "error": None}
    binding = {"role": f"{PROJECT}/roles/source", "members": ["user:source@example.com"]}
    metadata = {"items": [{"key": "enable-oslogin", "value": str(os_login).lower()}]}
    vm = {"name": "gae-vm", "zone": "us-central1-a", "metadata": metadata,
          "networkInterfaces": [{"accessConfigs": [{"natIP": "34.1.2.3"}]}] if ip else []}
    cols = [
        row("project", [{"projectId": "p1", "name": "projects/123", "commonInstanceMetadata": metadata}]),
        row("iam_role", [{"name": f"{PROJECT}/roles/source", "includedPermissions": list(actions)}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [binding]}]),
        row("service_account", [{"email": EMAIL, "projectId": "p1", "iamPolicy": {"bindings": []}}]),
        row("app_engine_version", [{"name": VERSION, "env": "flex", "runtime": "python311",
                                     "servingStatus": "SERVING", "serviceAccount": service_account}]),
        row("app_engine_instance", [{"name": APP_INSTANCE, "vmName": "gae-vm", "vmZoneName": "us-central1-a",
                                      "vmStatus": "RUNNING", "vmDebugEnabled": debug}]),
        row("instance", [vm]), row("iam_deny_policy", [], "empty"),
        row("org_policy_effective", [{"constraint": "compute.requireOsLogin",
                                       "spec": {"rules": [{"enforce": False}]}}]),
    ]
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "collections": cols, "metadata": {}}


def outcome(snap):
    model = GcpModel(snap)
    source = model.principals["user:source@example.com"]
    target = model.sas["serviceAccount:" + EMAIL]
    direct = model.selector("gcp_appengine_instance_ssh_path", True, {target.id: target}, source)
    entry, = [e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE]
    reached = [r for r in Evaluator(model, [entry]).run() if r.source.id == source.id]
    return direct.get(target.id), reached


def test_debug_grant_on_exact_flexible_vm_is_conditional():
    verdict, reaches = outcome(snapshot())
    assert verdict[0] == "conditional"
    assert reaches


def test_wrong_vm_or_service_account_cannot_join():
    snap = snapshot()
    version = next(c for c in snap["collections"] if c["type"] == "app_engine_version")
    version["items"][0]["serviceAccount"] = "different@p1.iam.gserviceaccount.com"
    assert outcome(snap) == (None, [])


def test_os_login_requires_debug_mode_and_actas_on_runtime_sa():
    actions = ("compute.instances.osLogin", "iam.serviceAccounts.actAs")
    assert outcome(snapshot(actions, os_login=True, debug=False))[0] is None
    assert outcome(snapshot(actions, os_login=True, debug=True))[0][0] == "conditional"
    assert outcome(snapshot(actions[:1], os_login=True, debug=True))[0] is None


def test_debug_key_cannot_bypass_os_login():
    assert outcome(snapshot(os_login=True))[0] is None
    actions = ("appengine.instances.enableDebug", "compute.instances.osLogin", "iam.serviceAccounts.actAs")
    assert outcome(snapshot(actions, os_login=True))[0][0] == "conditional"


def test_private_vm_without_iap_is_not_reported_as_reachable():
    assert outcome(snapshot(ip=False))[0][0] == "unknown"


def test_missing_vm_inventory_is_unknown():
    snap = snapshot()
    collection = next(c for c in snap["collections"] if c["type"] == "instance")
    collection["items"] = []
    collection["status"] = "denied"
    assert outcome(snap)[0][0] == "unknown"


def test_unreadable_app_engine_instances_keep_attachment_unresolved():
    snap = snapshot()
    collection = next(c for c in snap["collections"] if c["type"] == "app_engine_instance")
    collection["items"] = []
    collection["status"] = "denied"
    model = GcpModel(snap)
    target = model.sas["serviceAccount:" + EMAIL]
    assert model.selector("attached_to_service", "appengine_version", {target.id: target}, None)[target.id][0] == "unknown"


def test_permission_on_another_instance_cannot_pair_with_reachable_vm():
    snap = snapshot()
    collection = next(c for c in snap["collections"] if c["type"] == "app_engine_instance")
    collection["items"].append({"name": VERSION + "/instances/i2", "vmName": "gae-vm-2",
                                "vmZoneName": "us-central1-a", "vmStatus": "RUNNING", "vmDebugEnabled": False})
    compute = next(c for c in snap["collections"] if c["type"] == "instance")
    compute["items"].append({"name": "gae-vm-2", "zone": "us-central1-a",
                             "networkInterfaces": [{"accessConfigs": [{"natIP": "34.1.2.4"}]}]})
    compute["items"][0]["networkInterfaces"] = []
    policy = next(c for c in snap["collections"] if c["type"] == "iam_policy")
    policy["items"][0]["name"] = APP_INSTANCE
    assert outcome(snap)[0][0] == "unknown"


def test_version_without_explicit_identity_uses_app_default_identity():
    snap = snapshot(service_account=None)
    snap["collections"].append({"type": "app_engine_application_identity", "scope": PROJECT,
                                "service": "appengine", "status": "collected", "error": None,
                                "items": [{"name": "apps/p1", "serviceAccount": EMAIL}]})
    assert outcome(snap)[0][0] == "conditional"


def test_missing_app_default_identity_cannot_assume_appspot_account():
    snap = snapshot(service_account=None)
    verdict, reaches = outcome(snap)
    assert verdict is None
    assert all(all(target_id.startswith("unresolved:") for target_id in reach.targets)
               for reach in reaches)
    model = GcpModel(snap)
    target = model.sas["serviceAccount:" + EMAIL]
    assert model.selector("attached_to_service", "appengine_version", {target.id: target}, None)[target.id][0] == "unknown"
