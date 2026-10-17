"""Offline, directed authority checks for the project IAM alias."""
import copy

import pytest

from peaso.gcp_project_alias import AliasUnavailable, prove_project_alias
from peaso.checks.gcp_data_access import _native
from peaso.gcp_data_access_policy import OPTION

SCOPE = "projects/alias-demo"
NUMBER = "projects/123456789"
CHECK = "gcp_pci_iam_policy_ca1281da7ab2"
SERVICE = "spanner.googleapis.com"
CONFIG = [{"service": SERVICE, "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]
CRM = "https://cloudresourcemanager.googleapis.com"
CAI = "https://cloudasset.googleapis.com"

def request(ref, method, url, scope=SCOPE, query=None, body=None):
    row = {"id": ref, "scope": scope, "method": method, "url": url, "operation": "/" + url.split("/", 3)[3],
           "status": "collected", "http_status": 200, "query": query if query is not None else {}}
    if body is not None:
        row["request"] = body
    return row

def fixture(scope=SCOPE):
    project = {"name": NUMBER, "projectId": "alias-demo",
               "_provenance": {"scope": scope, "source_requests": ["project-get", "ancestry", "hydration"]}}
    direct = {"name": scope, "bindings": [], "auditConfigs": copy.deepcopy(CONFIG),
              "_provenance": {"scope": scope, "source_requests": ["direct"], "representation": "full"}}
    alias = {"name": "//cloudresourcemanager.googleapis.com/" + NUMBER,
             "assetType": "cloudresourcemanager.googleapis.com/Project", "project": NUMBER,
             "_provenance": {"scope": scope, "source_requests": ["cai-1", "cai-2"], "representation": "partial"}}
    projects = {"type": "project", "scope": scope, "status": "collected", "coverage_status": "collected",
                "source_requests": ["project-get", "ancestry", "hydration"], "items": [project]}
    policies = {"type": "iam_policy", "scope": scope, "status": "collected", "coverage_status": "collected",
                "source_requests": ["direct", "cai-1", "cai-2"], "items": [direct, alias]}
    ledger = [request("project-get", "GET", f"{CRM}/v3/{scope}", scope),
              request("ancestry", "POST", f"{CRM}/v1/{scope}:getAncestry", scope),
              request("hydration", "GET", "https://compute.googleapis.com/compute/v1/projects/alias-demo", scope),
              request("direct", "POST", f"{CRM}/v3/{scope}:getIamPolicy", scope,
                      body={"options": {"requestedPolicyVersion": 3}}),
              request("cai-1", "GET", f"{CAI}/v1/{scope}:searchAllIamPolicies", scope, {"pageSize": 100}),
              request("cai-2", "GET", f"{CAI}/v1/{scope}:searchAllIamPolicies", scope, {"pageSize": 100})]
    return projects, policies, ledger

def prove(projects, policies, ledger):
    return prove_project_alias(projects["scope"], projects, policies, ledger)

@pytest.mark.parametrize("scope", [SCOPE, NUMBER])
def test_binds_numeric_and_id_scope_with_original_positions_and_pages(scope):
    projects, policies, ledger = fixture(scope)
    peer = {"name": "//storage.googleapis.com/projects/_/buckets/example",
            "assetType": "storage.googleapis.com/Bucket",
            "_provenance": {"scope": scope, "source_requests": ["cai-2"], "representation": "partial"}}
    policies["items"].insert(0, peer)
    binding = prove(projects, policies, ledger)
    assert (binding.project_number, binding.direct_position, binding.alias_position) == ("123456789", 1, 2)
    assert "project-get" in binding.source_requests and "cai-2" in binding.source_requests

@pytest.mark.parametrize("change", [
    lambda p,i,l: p["items"][0].pop("projectId"),
    lambda p,i,l: p["items"][0].update(projectId="other-project"),
    lambda p,i,l: p["items"][0]["_coverage"].update(projectId={"status": "denied"}),
    lambda p,i,l: i["items"][1].update(auditConfigs=[]),
    lambda p,i,l: i["items"][1].update(auditConfigs=list(reversed(CONFIG + [{"service": "other", "auditLogConfigs": []}]))),
    lambda p,i,l: i["items"].append(copy.deepcopy(i["items"][1])),
    lambda p,i,l: l.__setitem__(0, {**l[0], "method": "POST"}),
    lambda p,i,l: l.__setitem__(0, {**l[0], "status": "denied"}),
    lambda p,i,l: l.__setitem__(3, {**l[3], "request": {"options": {"requestedPolicyVersion": 1}}}),
    lambda p,i,l: l.__setitem__(4, {**l[4], "query": {"pageSize": 100, "query": "project:other"}}),
    lambda p,i,l: l.__setitem__(5, {**l[5], "status": "partial"}),
])
def test_rejects_unproven_alias(change):
    projects, policies, ledger = fixture()
    projects["items"][0]["_coverage"] = {}
    change(projects, policies, ledger)
    with pytest.raises(AliasUnavailable):
        prove(projects, policies, ledger)

def test_ancestry_alone_cannot_prove_project_get():
    projects, policies, ledger = fixture()
    projects["items"][0]["_provenance"]["source_requests"].remove("project-get")
    with pytest.raises(AliasUnavailable):
        prove(projects, policies, ledger)

def test_native_direct_pass_alias_not_applicable_and_invalid_unknown():
    projects, policies, ledger = fixture()
    direct, alias = policies["items"]
    direct["effectiveAuditConfigs"] = [{"scope": SCOPE, "auditConfigs": copy.deepcopy(CONFIG)}]
    direct["_coverage"] = {"effectiveAuditConfigs": {"status": "collected", "ancestry_known": True,
                           "missing_scopes": [], "malformed_scopes": [], "source_requests": ["ancestry"]}}
    metadata = {"source_requests": ledger, OPTION: [{"status": "approved", "scope": SCOPE,
                "service": SERVICE, "source_ref": "owner-fixture", "principals": ["user:alice@example.com"]}]}
    index = {"context": {"scope": SCOPE, "metadata": metadata},
             "collections": {"project": [projects], "iam_policy": [policies]}}
    status, evidence = _native(direct, index, CHECK)
    assert status == "PASS"
    assert evidence["project_number"] == "123456789"
    assert "project-get" in evidence["project_alias_requests"]
    assert _native(alias, index, CHECK)[0] == "NOT_APPLICABLE"
    broken = copy.deepcopy(index)
    broken["context"]["metadata"]["source_requests"][0]["status"] = "denied"
    assert _native(direct, broken, CHECK)[0] == "UNKNOWN"

def test_native_retains_hierarchy_and_principal_gates():
    projects, policies, ledger = fixture()
    direct = policies["items"][0]
    direct["effectiveAuditConfigs"] = [{"scope": SCOPE, "auditConfigs": CONFIG}]
    direct["_coverage"] = {"effectiveAuditConfigs": {"status": "partial"}}
    index = {"context": {"scope": SCOPE, "metadata": {"source_requests": ledger}},
             "collections": {"project": [projects], "iam_policy": [policies]}}
    assert _native(direct, index, CHECK)[0] == "UNKNOWN"


def test_native_fail_keeps_alias_proof_and_extra_root_stays_unknown():
    projects, policies, ledger = fixture()
    direct = policies["items"][0]
    direct["effectiveAuditConfigs"] = [{"scope": SCOPE, "auditConfigs": []}]
    direct["_coverage"] = {"effectiveAuditConfigs": {"status": "collected", "ancestry_known": True,
                           "missing_scopes": [], "malformed_scopes": [], "source_requests": ["ancestry"]}}
    metadata = {"source_requests": ledger, OPTION: [{"status": "approved", "scope": SCOPE,
                "service": SERVICE, "source_ref": "owner-fixture", "principals": ["user:alice@example.com"]}]}
    index = {"context": {"scope": SCOPE, "metadata": metadata},
             "collections": {"project": [projects], "iam_policy": [policies]}}
    status, evidence = _native(direct, index, CHECK)
    assert status == "FAIL"
    assert evidence["project_number"] == "123456789"
    policies["items"].append({"name": "//cloudresourcemanager.googleapis.com/folders/77",
                              "assetType": "cloudresourcemanager.googleapis.com/Folder",
                              "_provenance": {"scope": SCOPE, "source_requests": ["folder"], "representation": "partial"}})
    assert _native(direct, index, CHECK)[0] == "UNKNOWN"


def test_unreadable_peer_type_cannot_be_excluded():
    projects, policies, ledger = fixture()
    policies["items"].append({"name": "//storage.googleapis.com/projects/_/buckets/example",
                              "assetType": "storage.googleapis.com/Bucket",
                              "_coverage": {"assetType": {"status": "denied"}},
                              "_provenance": {"scope": SCOPE, "source_requests": ["peer"], "representation": "partial"}})
    policies["source_requests"].append("peer")
    with pytest.raises(AliasUnavailable):
        prove(projects, policies, ledger)


def test_denied_unrelated_hydration_does_not_replace_project_get():
    projects, policies, ledger = fixture()
    ledger[2]["status"] = "denied"
    ledger[2]["http_status"] = 403
    projects["items"][0]["_coverage"] = {"computeConfig": {"status": "denied",
                                                        "source_requests": ["hydration"]}}
    assert prove(projects, policies, ledger).project_number == "123456789"


def test_partial_or_wrong_scope_envelope_never_binds():
    projects, policies, ledger = fixture()
    policies["coverage_status"] = "partial"
    with pytest.raises(AliasUnavailable):
        prove(projects, policies, ledger)
    policies["coverage_status"] = "collected"
    policies["scope"] = "projects/foreign"
    with pytest.raises(AliasUnavailable):
        prove(projects, policies, ledger)
