"""Six Azure content paths need exact, reviewed Entra credential holder evidence."""
from __future__ import annotations

import copy
import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, T, az


SOURCE = "u-alice"
TARGET = "sp-victim"
CASES = (
    ("azure-apim-gateway-config-credential", "Microsoft.ApiManagement/service", "Microsoft.ApiManagement/service/gateways/getConfiguration/action", True),
    ("azure-appconfig-snapshot-credential", "Microsoft.AppConfiguration/configurationStores", "Microsoft.AppConfiguration/configurationStores/snapshots/read", True),
    ("azure-automation-job-output-credential", "Microsoft.Automation/automationAccounts", "Microsoft.Automation/automationAccounts/jobs/output/read", False),
    ("azure-automation-runbook-source-credential", "Microsoft.Automation/automationAccounts", "Microsoft.Automation/automationAccounts/runbooks/content/read", False),
    ("azure-acr-layer-credential", "Microsoft.ContainerRegistry/registries", "Microsoft.ContainerRegistry/registries/pull/read", True),
    ("azure-storage-blob-content-credential", "Microsoft.Storage/storageAccounts", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", True),
)


_CATALOG = {entry["id"]: {k: v for k, v in entry.items() if k != "_file"}
            for entry in privesc.load_catalog()["entries"]}


def _entry(tid):
    return copy.deepcopy(_CATALOG[tid])


def _resource(rtype, name="one"):
    return f"{RG}/providers/{rtype}/{name}"


def _fact(tid, resource, action):
    fact = {"TechniqueId": tid, "SourceId": SOURCE, "TargetKind": "azure_service_principal",
            "TargetId": TARGET, "TargetScope": T, "CredentialSubjectId": TARGET,
            "CredentialKind": "entra_service_principal_client_secret", "CredentialUsable": True,
            "CredentialScope": resource, "AccessAction": action,
            "EvidenceRef": "reviewed-content-object-1", "Status": "verified", "VerifiedPreconditions": True}
    exact_content = {
        "azure-apim-gateway-config-credential": ("GatewayResourceId", "/gateways/gateway1", "GatewayConfiguration", "GatewayConfiguration"),
        "azure-appconfig-snapshot-credential": ("SnapshotName", "snapshot1", "SnapshotContent", "Snapshot"),
        "azure-automation-job-output-credential": ("JobResourceId", "/jobs/job1", "JobContent", "JobContent"),
        "azure-automation-runbook-source-credential": ("RunbookResourceId", "/runbooks/runbook1", "RunbookContent", "RunbookContent"),
        "azure-storage-blob-content-credential": ("BlobResourceId", "/blobServices/default/containers/container1/blobs/blob1", "BlobContent", "BlobContent"),
    }
    if tid in exact_content:
        field, value, prefix, subject = exact_content[tid]
        fact[field] = value if field == "SnapshotName" else resource + value
        fact[prefix + "ReadVerified"] = True
        fact["CredentialIn" + subject + "Verified"] = True
        fact[prefix + "EvidenceRef"] = "reviewed-content-object-1"
    return fact


def _run(tid, rtype, action, data_action, facts, *, assignment_scope=SUB,
         role_actions=None, target_inventory=True, graph_type=None, evidence_status="collected",
         second_resource=False):
    resource = _resource(rtype)
    acts = (["Microsoft.Automation/automationAccounts/jobs/read", action] if tid == "azure-automation-job-output-credential"
            else [action])
    role_actions = acts if role_actions is None else role_actions
    roles = {ROLE_ID: (([] if data_action else role_actions), (role_actions if data_action else []))}
    graph = [{"id": resource, "type": graph_type or rtype, "name": "one"}]
    if second_resource:
        graph.append({"id": _resource(rtype, "other"), "type": rtype, "name": "other"})
    extra = [] if evidence_status is None else [("azure_privesc_challenge_evidence", T, facts, evidence_status)]
    snap = az([(SOURCE, "User", assignment_scope, ROLE_ID)], roles=roles,
              sps=((TARGET,) if target_inventory else ()), graph=graph, extra=extra)
    return privesc.analyze(snap, entries=[_entry(tid)])


@pytest.mark.parametrize("tid,rtype,action,data_action", CASES)
def test_exact_inventoried_secret_subject_reaches_only_conditionally(tid, rtype, action, data_action):
    assert validate_entry(_entry(tid))[0] == []
    result = _run(tid, rtype, action, data_action, [_fact(tid, _resource(rtype), action)])
    assert reached(result, SOURCE, tid) == {TARGET: "conditional"}
    assert all(f["status"] != "FAIL" for f in result["findings"])


@pytest.mark.parametrize("tid,rtype,action,data_action", CASES)
def test_wrong_subject_scope_permission_or_usability_never_reaches_principal(tid, rtype, action, data_action):
    resource = _resource(rtype)
    fact = _fact(tid, resource, action)
    for changes in ({"CredentialSubjectId": "sp-other"}, {"TargetId": "sp-other"},
                    {"CredentialKind": "entra_oauth_access_token"}, {"CredentialUsable": False},
                    {"SourceId": "u-other"}, {"AccessAction": "Microsoft.Authorization/roleAssignments/write"},
                    {"TargetScope": "/tenants/other"}, {"Status": "disproven"}):
        result = _run(tid, rtype, action, data_action, [dict(fact, **changes)])
        assert TARGET not in reached(result, SOURCE, tid), (tid, changes)
    wrong_resource = _resource(rtype, "other")
    result = _run(tid, rtype, action, data_action, [dict(fact, CredentialScope=wrong_resource)],
                  assignment_scope=resource, second_resource=True)
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, rtype, action, data_action, [fact], role_actions=[])
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, rtype, action, data_action, [fact], target_inventory=False)
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, rtype, action, data_action, [fact], graph_type="Microsoft.Compute/virtualMachines")
    assert TARGET not in reached(result, SOURCE, tid)


@pytest.mark.parametrize("tid,rtype,action,data_action", CASES)
def test_conflict_or_missing_normal_scan_evidence_never_names_principal(tid, rtype, action, data_action):
    fact = _fact(tid, _resource(rtype), action)
    result = _run(tid, rtype, action, data_action, [fact, dict(fact, Status="disproven")])
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, rtype, action, data_action, [], evidence_status=None)
    assert TARGET not in reached(result, SOURCE, tid)


@pytest.mark.parametrize("tid,rtype,action,data_action", CASES)
def test_unreviewed_secret_read_creates_no_unknown_escalation_path(tid, rtype, action, data_action):
    resource = _resource(rtype)
    unverified = dict(_fact(tid, resource, action), CredentialUsable=False)
    for facts, status in (([], None), ([], "partial"), ([unverified], "collected")):
        result = _run(tid, rtype, action, data_action, facts, evidence_status=status)
        assert not [edge for edge in result["graph"]["edges"] if tid in edge.get("techniques", ())]

