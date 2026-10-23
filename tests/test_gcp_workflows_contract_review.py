"""Workflows source and execution permissions must meet on the target identity."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_audit_fixes import snapshot


SA = "worker@p1.iam.gserviceaccount.com"
ACTOR = "user:dev@example.com"
FLOW = "projects/p1/locations/us-central1/workflows/flow"


def _result(ident, workflow_permissions, act_as=True, workflows=None):
    role = {"name": "projects/p1/roles/workflowWriter", "includedPermissions": workflow_permissions}
    sa_bindings = ([{"role": "roles/iam.serviceAccountUser", "members": [ACTOR]}]
                   if act_as else [])
    rows = [
        ("project", "projects/p1", [{"projectId": "p1", "name": "projects/123"}], "collected"),
        ("service_account", "projects/p1", [{"email": SA, "projectId": "p1",
            "name": f"projects/p1/serviceAccounts/{SA}",
            "iamPolicy": {"bindings": sa_bindings}}], "collected"),
        ("iam_role", "projects/p1", [role], "collected"),
        ("iam_policy", "projects/p1", [{"name": "projects/p1", "bindings": [
            {"role": role["name"], "members": [ACTOR]}]}], "collected"),
        ("workflows_workflow", "projects/p1", workflows or [],
         "collected" if workflows else "empty"),
    ]
    model = GcpModel(snapshot("gcp", rows))
    entry = next(item for item in privesc.catalog()["entries"] if item["id"] == ident)
    return {target: grant.confidence for reach in Evaluator(model, [entry]).run()
            if reach.source.id == ACTOR for target, grant in reach.targets.items()
            if not target.startswith("unresolved:")}


def test_create_workflow_requires_actas_deploy_and_execute_in_same_project():
    ident = "gcp-workflows-create-actas-execute"
    perms = ["workflows.workflows.create", "workflows.executions.create"]
    target = "serviceAccount:" + SA
    assert _result(ident, perms).get(target) == "conditional"
    assert target not in _result(ident, perms, act_as=False)
    assert target not in _result(ident, perms[:1])
    assert target not in _result(ident, perms[1:])


def test_update_attached_identity_needs_exact_existing_workflow_and_execute():
    ident = "gcp-workflows-update-actas"
    perms = ["workflows.workflows.update", "workflows.executions.create"]
    target = "serviceAccount:" + SA
    flow = [{"name": FLOW, "serviceAccount": SA, "state": "ACTIVE"}]
    assert _result(ident, perms, workflows=flow).get(target) == "conditional"
    assert target not in _result(ident, perms, workflows=[])
    assert target not in _result(ident, perms[:1], workflows=flow)
    assert target not in _result(ident, perms, act_as=False, workflows=flow)
