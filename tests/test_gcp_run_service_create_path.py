"""A new Cloud Run service must be creatable in the target SA project."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_audit_fixes import _GSA, _gcp_attached


PROJECT = "projects/p1"
SOURCE = "user:operator@example.com"


def model_for(*, state="ENABLED", coverage="collected", create=True):
    role = PROJECT + "/roles/serviceCreator"
    model, target = _gcp_attached([
        ("iam_role", PROJECT, [{"name": role,
          "includedPermissions": ["iam.serviceAccounts.actAs"]
          + (["run.services.create"] if create else [])}], "collected"),
        ("service_usage", PROJECT,
         [{"name": PROJECT + "/services/run.googleapis.com", "state": state}]
         if coverage == "collected" else [], coverage),
        ("iam_deny_policy", PROJECT, [], "empty"),
    ])
    project_policy = next(c for c in model.snapshot["collections"] if c["type"] == "iam_policy")
    project_policy["items"][0]["bindings"] = [{"role": role, "members": [SOURCE]}]
    return GcpModel(model.snapshot), target


def test_service_create_uses_same_project_grant_and_enabled_api():
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-run-services-create-actas")
    model, target = model_for()
    assert any(reach.source.id == SOURCE and target.id in reach.targets
               for reach in Evaluator(model, [entry]).run())
    assert model.selector("gcp_run_service_create_path", True, {target.id: target},
                          model.principals[SOURCE]) == {target.id: None}


def test_disabled_or_uncollected_api_and_missing_create_permission():
    target_id = "serviceAccount:" + _GSA
    model, target = model_for(state="DISABLED")
    assert model.selector("gcp_run_service_create_path", True, {target.id: target},
                          model.principals[SOURCE]) == {}
    model, target = model_for(coverage="denied")
    assert model.selector("gcp_run_service_create_path", True, {target.id: target},
                          model.principals[SOURCE])[target_id][0] == "unknown"
    model, target = model_for(create=False)
    assert model.selector("gcp_run_service_create_path", True, {target.id: target},
                          model.principals[SOURCE]) == {}
