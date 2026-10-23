"""Historical table-key evidence stays archived; no active manual-only check runs."""
from __future__ import annotations

import copy
import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from peaso.privesc.versioned_catalog import _verified_reviewed_691_previous
from tests.test_peaso_privesc_schema_ext import reached, snapshot


SCOPE = "projects/p1"
SOURCE = "user:alice@corp.com"
TARGET = "serviceAccount:target@p1.iam.gserviceaccount.com"
OTHER = "serviceAccount:other@p1.iam.gserviceaccount.com"
CASES = (
    ("gcp-bigquery-table-row-credential", "bigquery.tables.getData",
     "projects/p1/datasets/d1/tables/keys"),
)
MANUAL_ONLY = {"gcp-bigquery-table-row-credential", "gcp-bigtable-row-credential"}


_CATALOG = _verified_reviewed_691_previous()


def test_table_key_paths_are_historical_manual_only():
    active = {entry["id"] for entry in privesc.load_catalog()["entries"]}
    assert MANUAL_ONLY.isdisjoint(active)
    assert MANUAL_ONLY <= set(_CATALOG)


def test_historical_bigtable_row_read_does_not_name_a_service_account():
    tid = "gcp-bigtable-row-credential"
    permission = "bigtable.tables.readRows"
    resource = "projects/p1/instances/i1/tables/keys"
    assert _entry(tid)["target"]["kind"] == "gcp_verified_authority"
    result = _run(tid, permission, resource, [_fact(tid, permission, resource)])
    assert TARGET not in reached(result, SOURCE, tid)


def _entry(tid):
    return copy.deepcopy({key: value for key, value in _CATALOG[tid].items() if key != "_file"})


def _fact(tid, permission, resource):
    return {"TechniqueId": tid, "SourceId": SOURCE, "TargetKind": "gcp_service_account",
            "TargetId": TARGET, "TargetScope": SCOPE,
            "CredentialKind": "gcp_service_account_private_key", "CredentialSubjectId": TARGET,
            "CredentialResource": resource, "AccessPermission": permission,
            "CredentialUsable": True, "EvidenceRef": "reviewed-table-cell-1",
            "Status": "verified", "VerifiedPreconditions": True}


def _run(tid, permission, resource, facts, *, grant_resource=None, grant_permission=None,
         sa_items=None):
    role = "projects/p1/roles/tableReader"
    sas = sa_items if sa_items is not None else [
        {"email": "target@p1.iam.gserviceaccount.com", "projectId": "p1"},
        {"email": "other@p1.iam.gserviceaccount.com", "projectId": "p1"}]
    snap = snapshot("gcp", [
        ("project", SCOPE, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", SCOPE, [{"name": grant_resource or resource,
                                "bindings": [{"role": role, "members": [SOURCE]}]}]),
        ("iam_role", SCOPE, [{"name": role, "includedPermissions": [grant_permission or permission]}]),
        ("service_account", SCOPE, sas),
        ("iam_deny_policy", SCOPE, [], "empty"),
        ("gcp_privesc_challenge_evidence", SCOPE, facts),
    ])
    return privesc.analyze(snap, entries=[_entry(tid)])


@pytest.mark.parametrize("tid,permission,resource", CASES)
def test_reviewed_private_key_reaches_only_inventoried_subject(tid, permission, resource):
    assert validate_entry(_entry(tid))[0] == []
    result = _run(tid, permission, resource, [_fact(tid, permission, resource)])
    assert reached(result, SOURCE, tid) == {TARGET: "conditional"}
    assert all(f["status"] != "FAIL" for f in result["findings"])


@pytest.mark.parametrize("tid,permission,resource", CASES)
def test_wrong_subject_resource_permission_or_usability_has_no_principal_edge(tid, permission, resource):
    fact = _fact(tid, permission, resource)
    other_resource = resource.replace("/tables/keys", "/tables/other")
    for change in ({"CredentialSubjectId": OTHER}, {"TargetId": OTHER},
                   {"CredentialKind": "gcp_oauth_access_token"}, {"CredentialUsable": False},
                   {"AccessPermission": "iam.serviceAccounts.actAs"},
                   {"SourceId": "user:eve@corp.com"}, {"Status": "disproven"}):
        result = _run(tid, permission, resource, [dict(fact, **change)])
        assert TARGET not in reached(result, SOURCE, tid), (tid, change)
    result = _run(tid, permission, resource, [dict(fact, CredentialResource=other_resource)])
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, permission, resource, [fact], grant_permission="iam.serviceAccounts.actAs")
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, permission, resource, [fact], sa_items=[])
    assert TARGET not in reached(result, SOURCE, tid)


@pytest.mark.parametrize("tid,permission,resource", CASES)
def test_disabled_sa_or_conflicting_review_does_not_reach(tid, permission, resource):
    fact = _fact(tid, permission, resource)
    disabled = [{"email": "target@p1.iam.gserviceaccount.com", "projectId": "p1", "disabled": True}]
    result = _run(tid, permission, resource, [fact], sa_items=disabled)
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, permission, resource, [fact, dict(fact, Status="disproven")])
    assert TARGET not in reached(result, SOURCE, tid)

