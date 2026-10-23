"""Application Integration run-as paths require an exact observed integration."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
TARGET = "runtime@p1.iam.gserviceaccount.com"
VERSION = PROJECT + "/locations/us-central1/integrations/pay/versions/1"
TECHNIQUE = "gcp-appintegration-runas-sa-actas"


def snapshot(*, actions=("integrations.integrationVersions.create",
                         "integrations.integrationVersions.deploy",
                         "integrations.integrations.invoke",
                         "iam.serviceAccounts.actAs"),
             service="ENABLED", integration_status="collected", version=VERSION):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT], "metadata": {},
            "collections": [
                row("project", [{"projectId": "p1", "name": "projects/123"}]),
                row("iam_role", [{"name": PROJECT + "/roles/source",
                                  "includedPermissions": list(actions)}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": PROJECT + "/roles/source", "members": ["user:source@example.com"]}]}]),
                row("service_account", [{"email": TARGET, "projectId": "p1",
                                         "iamPolicy": {"bindings": []}}]),
                row("service_usage", [{"name": PROJECT + "/services/integrations.googleapis.com",
                                       "state": service}]),
                row("gcp_v4_workload_facts", [{"name": PROJECT, "scope": PROJECT,
                    "application_integration": {"status": integration_status,
                        "versions": [{"name": version, "state": "ACTIVE"}]}}]),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
            ]}


def outcome(snap):
    model = GcpModel(snap)
    source = model.principals["user:source@example.com"]
    target = model.sas["serviceAccount:" + TARGET]
    direct = model.selector("gcp_appintegration_run_as_path", True, {target.id: target}, source)
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = [reach for reach in Evaluator(model, [entry]).run()
               if reach.source.id == source.id]
    return direct.get(target.id), reaches


def test_authored_published_and_invoked_version_is_conditional():
    verdict, reaches = outcome(snapshot())
    assert verdict[0] == "conditional"
    assert "publish" in verdict[1]
    assert reaches


def test_draft_test_does_not_need_create_or_deploy():
    verdict, reaches = outcome(snapshot(actions=("integrations.integrations.invoke",
                                              "iam.serviceAccounts.actAs")))
    assert verdict[0] == "conditional"
    assert "draft_test" in verdict[1]
    assert reaches


def test_unproven_unattended_trigger_remains_unknown():
    verdict, reaches = outcome(snapshot(actions=("integrations.integrationVersions.create",
                                              "integrations.integrationVersions.deploy",
                                              "iam.serviceAccounts.actAs")))
    assert verdict[0] == "unknown"
    assert reaches


def test_disabled_service_cannot_run_integration():
    assert outcome(snapshot(service="DISABLED")) == (None, [])


def test_wrong_project_version_and_missing_region_inventory_stay_unresolved():
    assert outcome(snapshot(version=VERSION.replace("projects/p1", "projects/p2")))[0][0] == "unknown"
    assert outcome(snapshot(integration_status="unavailable"))[0][0] == "unknown"


def test_missing_actas_cannot_reach_target():
    snap = snapshot(actions=("integrations.integrations.invoke",))
    assert outcome(snap)[1] == []


def test_numeric_project_service_name_is_joined_to_verified_project_alias():
    snap = snapshot()
    service = next(c for c in snap["collections"] if c["type"] == "service_usage")
    service["items"][0]["name"] = "projects/123/services/integrations.googleapis.com"
    assert outcome(snap)[0][0] == "conditional"


def test_disabled_target_service_account_has_no_path():
    snap = snapshot()
    account = next(c for c in snap["collections"] if c["type"] == "service_account")
    account["items"][0]["disabled"] = True
    assert outcome(snap) == (None, [])


def test_prior_contract_remains_held():
    from peaso.privesc.versioned_catalog import _verified_prior
    old, _ = _verified_prior()
    model = GcpModel(snapshot())
    assert Evaluator(model, [old[TECHNIQUE]]).run() == []
    assert any(TECHNIQUE in row["reason"] for row in model.coverage)
