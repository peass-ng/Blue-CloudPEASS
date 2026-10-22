"""A token-only Grafana route needs an existing enabled ADMIN account in the same workspace."""

from pathlib import Path

import yaml

from peaso import privesc
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_facts_ext import _grafana_workspaces
from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, SCOPE, allow, aws_snap, col, edges, reached, user


TECHNIQUE = "aws-grafana-existing-admin-serviceaccount-token"
WORKSPACE_ID = "g-0123456789"
WORKSPACE_ARN = f"arn:aws:grafana:{REGION}:{ACCOUNT}:/workspaces/{WORKSPACE_ID}"
CATALOG = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/grafana.yaml"


def _entry():
    return next(row for row in yaml.safe_load(CATALOG.read_text()) if row["id"] == TECHNIQUE)


def _run(*, action="grafana:CreateWorkspaceServiceAccountToken", resource=WORKSPACE_ARN,
         workspace_status="ACTIVE", version="10.4", accounts_status="collected",
         accounts=None, include_unknown=False):
    if accounts is None:
        accounts = [{"id": "sa-admin", "grafanaRole": "ADMIN", "isDisabled": "false"}]
    workspace = {"id": WORKSPACE_ID, "Arn": WORKSPACE_ARN,
                 "status": workspace_status, "grafanaVersion": version}
    if accounts_status is not None:
        workspace["ServiceAccounts"] = {"collection_status": accounts_status, "items": accounts}
    snap = aws_snap([user("alice", allow(action, resource=resource))],
                    extra=[col("grafana_workspace", [workspace])])
    return privesc.analyze(snap, entries=[_entry()], include_unknown=include_unknown)


def test_token_only_permission_reaches_existing_enabled_admin_account():
    result = _run()
    assert reached(result, ALICE, TECHNIQUE) == {
        f"aws_service_plane_admin:grafana:{WORKSPACE_ARN}": "conditional"}


def test_wrong_permission_workspace_or_account_role_has_no_admin_edge():
    assert not edges(_run(action="grafana:CreateWorkspaceServiceAccount"), ALICE, TECHNIQUE)
    assert not edges(_run(resource=WORKSPACE_ARN.replace(WORKSPACE_ID, "g-aaaaaaaaaa")), ALICE, TECHNIQUE)
    assert not edges(_run(accounts=[{"id": "sa-viewer", "grafanaRole": "VIEWER", "isDisabled": "false"}]), ALICE, TECHNIQUE)
    assert not edges(_run(accounts=[{"id": "sa-admin", "grafanaRole": "ADMIN", "isDisabled": "true"}]), ALICE, TECHNIQUE)
    assert not edges(_run(workspace_status="DELETING"), ALICE, TECHNIQUE)
    assert not edges(_run(version="8.4"), ALICE, TECHNIQUE)


def test_missing_or_denied_service_account_inventory_is_unresolved():
    for status in (None, "denied", "partial"):
        result = _run(accounts_status=status, include_unknown=True)
        assert not reached(result, ALICE, TECHNIQUE)
        assert result["coverage"] or edges(result, ALICE, TECHNIQUE)
    result = _run(accounts=[{"id": "sa-admin", "grafanaRole": "ADMIN"}], include_unknown=True)
    assert not reached(result, ALICE, TECHNIQUE)


def test_collector_keeps_only_workspace_and_account_metadata():
    class Requests:
        def pages(self, _session, service, region, operation, _field, **params):
            assert service == "grafana" and region == REGION
            if operation == "list_workspaces":
                return ReadResult([{"id": WORKSPACE_ID, "status": "ACTIVE", "grafanaVersion": "10.4"}], "collected")
            assert operation == "list_workspace_service_accounts"
            assert params == {"workspaceId": WORKSPACE_ID}
            return ReadResult([{"id": "sa-admin", "name": "ops", "grafanaRole": "ADMIN",
                                "isDisabled": "false", "token": "must-not-be-recorded"}], "collected")

    result = _grafana_workspaces(Requests(), None, REGION, ACCOUNT)
    assert result.status == "collected"
    assert result.items[0]["Arn"] == WORKSPACE_ARN
    assert result.items[0]["ServiceAccounts"] == {"collection_status": "collected", "items": [
        {"id": "sa-admin", "name": "ops", "grafanaRole": "ADMIN", "isDisabled": "false"}]}
