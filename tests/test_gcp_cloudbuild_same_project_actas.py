"""Cloud Build actAs needs a usable same-project service and exact target IAM."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
SA = "builder@p1.iam.gserviceaccount.com"
SOURCE = "user:caller@example.com"
TECHNIQUE = "gcp-cloudbuild-builds-create-custom-sa-actas"


def snapshot(*, service="ENABLED", service_status="collected", build=True,
             act_as=True, disabled=False, enable=False):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": records, "error": None}
    actions = (["cloudbuild.builds.create"] if build else [])
    if enable:
        actions.append("serviceusage.services.enable")
    service_rows = ([{"name": PROJECT + "/services/cloudbuild.googleapis.com", "state": service}]
                    if service is not None else [])
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/100"}]),
                row("iam_role", [
                    {"name": PROJECT + "/roles/buildSubmitter", "includedPermissions": actions},
                    {"name": PROJECT + "/roles/actAs", "includedPermissions":
                     ["iam.serviceAccounts.actAs"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": PROJECT + "/roles/buildSubmitter", "members": [SOURCE]}]}]),
                row("service_account", [{"email": SA, "projectId": "p1", "disabled": disabled,
                    "iamPolicy": {"bindings": ([{"role": PROJECT + "/roles/actAs", "members": [SOURCE]}]
                                              if act_as else [])}}]),
                row("service_usage", service_rows, service_status),
                row("iam_deny_policy", [], "empty"),
                row("service_perimeter", [], "empty"),
            ]}


def targets(snap):
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {tid: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for tid, grant in reach.targets.items()}


def test_enabled_api_and_exact_actas_reach_target():
    assert targets(snapshot()).get("serviceAccount:" + SA) == "derived"


def test_missing_build_or_actas_or_disabled_target_has_no_confirmed_path():
    for snap in (snapshot(build=False), snapshot(act_as=False), snapshot(disabled=True),
                 snapshot(service="DISABLED")):
        assert "serviceAccount:" + SA not in targets(snap)


def test_unknown_service_state_and_enable_rights_remain_unresolved():
    for snap in (snapshot(service=None), snapshot(service="UNKNOWN"),
                 snapshot(service_status="denied"), snapshot(service="DISABLED", enable=True)):
        result = targets(snap)
        assert "serviceAccount:" + SA not in result
        assert any(tid.startswith("unresolved:") and confidence == "unknown"
                   for tid, confidence in result.items())
