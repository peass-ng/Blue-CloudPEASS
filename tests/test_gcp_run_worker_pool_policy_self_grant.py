"""A worker pool IAM-policy writer only reaches a pinned SA through new update rights."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_audit_fixes import _GSA, _GDEF, _gcp_attached


PROJECT = "projects/p1"
SOURCE = "user:operator@example.com"
SERVICE = PROJECT + "/locations/us-central1/workerPools/api"


def model_for(*, ready=True, policy_collected=True, existing_update=False,
              act_as=True, wrong_service=False):
    policy_role = PROJECT + "/roles/policyWriter"
    update_role = PROJECT + "/roles/updater"
    roles = [{"name": policy_role, "includedPermissions": ["run.workerpools.setIamPolicy"]},
             {"name": update_role, "includedPermissions": ["run.workerpools.update"]}]
    bindings = ([{"role": policy_role, "members": [SOURCE]}] if not wrong_service else [])
    if existing_update:
        bindings.append({"role": update_role, "members": [SOURCE]})
    service = {"name": SERVICE, "template": {"serviceAccount": _GSA,
               "containers": [{"image": "example.invalid/api:1"}]},
               "terminalCondition": {"state": "CONDITION_SUCCEEDED" if ready else "CONDITION_FAILED"},
               "reconciling": False, "iamPolicy": {"bindings": bindings},
               "_coverage": {"iamPolicy": {"status": "collected" if policy_collected else "denied"}}}
    services = [service]
    if wrong_service:
        services.append({**service, "name": PROJECT + "/locations/us-central1/workerPools/other",
                         "template": {"serviceAccount": _GDEF,
                                      "containers": [{"image": "example.invalid/other:1"}]},
                         "iamPolicy": {"bindings": [{"role": policy_role, "members": [SOURCE]}]}})
    model, target = _gcp_attached([
        ("iam_role", PROJECT, roles, "collected"),
        ("iam_role_builtin", PROJECT,
         [{"name": "roles/run.developer", "includedPermissions": ["run.workerpools.update"]}], "collected"),
        ("cloudrun_worker_pool", PROJECT, services, "collected"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("policy_binding", PROJECT, [], "empty"),
        ("iam_deny_policy", PROJECT, [], "empty"),
    ])
    root_policy = next(c for c in model.snapshot["collections"] if c["type"] == "iam_policy")
    root_policy["items"][0]["bindings"] = (
        ([{"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}] if act_as else [])
        + ([{"role": policy_role, "members": [SOURCE]}] if not policy_collected else []))
    return GcpModel(model.snapshot), target


def test_policy_writer_can_add_missing_update_on_exact_ready_service():
    model, target = model_for()
    selected = model.selector("gcp_run_worker_pool_policy_update_path", True,
                              {target.id: target}, model.principals[SOURCE])
    assert selected[target.id] == ("conditional", "self_granted_cloud_run_service_update")
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-run-workerpools-setiampolicy-actas")
    assert any(reach.source.id == SOURCE and target.id in reach.targets
               for reach in Evaluator(model, [entry]).run())


def test_existing_update_right_or_wrong_service_adds_no_new_path():
    for options in ({"existing_update": True}, {"wrong_service": True}):
        model, target = model_for(**options)
        assert model.selector("gcp_run_worker_pool_policy_update_path", True,
                              {target.id: target}, model.principals[SOURCE]) == {}
    model, target = model_for(act_as=False)
    entry = next(e for e in privesc.catalog()["entries"]
                 if e["id"] == "gcp-run-workerpools-setiampolicy-actas")
    assert not any(reach.source.id == SOURCE and target.id in reach.targets
                   for reach in Evaluator(model, [entry]).run())


def test_policy_read_or_service_state_missing_is_unresolved():
    for options in ({"ready": False}, {"policy_collected": False}):
        model, target = model_for(**options)
        assert model.selector("gcp_run_worker_pool_policy_update_path", True,
                              {target.id: target}, model.principals[SOURCE])[target.id][0] == "unknown"
