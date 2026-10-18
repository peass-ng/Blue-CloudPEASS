"""Native proof that CAI IAM policy ordering does not change project authority.

The imported fixture runs real Transport.request, collection, snapshot sealing, and
registered checks against an inert in-memory HTTP session.
"""

import copy

import pytest

from peaso.checks.gcp_data_access import CHECK_SERVICES
from test_peaso_gcp_project_alias_pipeline import (
    CAI_NAME, NUMBER, PRINCIPAL, SCOPE, Scenario, collect, direct_finding,
    findings, remake, status,
)


OTHER_MEMBERS = ["user:noise-one@example.test", "user:noise-two@example.test"]


def policy(*, exempt_service=None):
    return {
        "bindings": [
            {"role": "roles/viewer", "members": ["user:viewer-one@example.test", "user:viewer-two@example.test"],
             "condition": {"title": "reviewed", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}},
            {"role": "roles/logging.viewer", "members": ["user:log-one@example.test", "user:log-two@example.test"],
             "condition": {"title": "approved", "expression": "resource.name.startsWith('projects/')"}},
        ],
        "auditConfigs": [
            {"service": service, "auditLogConfigs": [
                {"logType": kind, "exemptedMembers":
                 [*OTHER_MEMBERS, *([PRINCIPAL] if exempt_service == service and kind == "DATA_READ" else [])]}
                for kind in ("DATA_READ", "DATA_WRITE")],
            }
            for service in CHECK_SERVICES.values()
        ],
    }


def reordered_view(direct):
    alias = copy.deepcopy(direct)
    alias["bindings"].reverse()
    for binding in alias["bindings"]:
        binding["members"].reverse()
    alias["auditConfigs"].reverse()
    for config in alias["auditConfigs"]:
        config["auditLogConfigs"].reverse()
        for row in config["auditLogConfigs"]:
            row["exemptedMembers"].reverse()
    return alias


def native_case(*, exempt_service=None, change=None):
    direct = policy(exempt_service=exempt_service)
    alias = reordered_view(direct)
    if change == "member":
        alias["bindings"][0]["members"][0] = "user:foreign@example.test"
    elif change == "condition":
        alias["bindings"][0]["condition"]["expression"] = "request.time > timestamp('2030-01-01T00:00:00Z')"
    elif change == "service":
        alias["auditConfigs"][0]["service"] = "allServices"
    elif change == "logtype":
        alias["auditConfigs"][0]["auditLogConfigs"][0]["logType"] = "ADMIN_READ"
    elif change == "exemption":
        alias["auditConfigs"][0]["auditLogConfigs"][0]["exemptedMembers"][0] = PRINCIPAL
    elif change == "duplicate_binding_member":
        alias["bindings"][0]["members"].append(alias["bindings"][0]["members"][0])
    elif change == "duplicate_audit_service":
        alias["auditConfigs"].append(copy.deepcopy(alias["auditConfigs"][0]))
    elif change == "duplicate_logtype":
        alias["auditConfigs"][0]["auditLogConfigs"].append(
            copy.deepcopy(alias["auditConfigs"][0]["auditLogConfigs"][0]))
    elif change == "duplicate_exemption":
        alias["auditConfigs"][0]["auditLogConfigs"][0]["exemptedMembers"].append(
            alias["auditConfigs"][0]["auditLogConfigs"][0]["exemptedMembers"][0])
    elif change == "malformed_binding":
        alias["bindings"][0]["members"] = "user:log-one@example.test"
    elif change == "malformed_audit":
        alias["auditConfigs"][0]["auditLogConfigs"][0]["exemptedMembers"] = "user:noise-one@example.test"
    assert direct != alias
    return Scenario(direct=direct, cai_policy=alias), direct, alias


def assert_raw_orders(snapshot, direct, alias):
    collection = next(row for row in snapshot["collections"] if row["type"] == "iam_policy" and row["scope"] == SCOPE)
    direct_rows = [row for row in collection["items"] if row["name"] == SCOPE]
    alias_rows = [row for row in collection["items"] if row["name"] == CAI_NAME]
    assert len(direct_rows) == len(alias_rows) == 1
    assert direct_rows[0]["bindings"] == direct["bindings"]
    assert direct_rows[0]["auditConfigs"] == direct["auditConfigs"]
    assert alias_rows[0]["bindings"] == alias["bindings"]
    assert alias_rows[0]["auditConfigs"] == alias["auditConfigs"]
    assert alias_rows[0]["project"] == f"projects/{NUMBER}"


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_equivalent_reordered_native_views_pass_without_rewriting_payload(check_id):
    case, direct, alias = native_case()
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert_raw_orders(snapshot, direct, alias)
    assert direct_finding(snapshot, check_id)["status"] == "PASS"
    assert status(snapshot, check_id) == {"PASS"}
    assert len([row for row in findings(snapshot, check_id) if row["status"] == "NOT_APPLICABLE"]) == 1


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_reordered_views_keep_explicit_required_principal_exemption_fail(check_id):
    case, direct, alias = native_case(exempt_service=CHECK_SERVICES[check_id])
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert_raw_orders(snapshot, direct, alias)
    assert direct_finding(snapshot, check_id)["status"] == "FAIL"
    assert status(snapshot, check_id) == {"FAIL"}
    assert len([row for row in findings(snapshot, check_id) if row["status"] == "NOT_APPLICABLE"]) == 1


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
@pytest.mark.parametrize("change", ["member", "condition", "service", "logtype", "exemption"])
def test_reordered_views_with_a_real_field_conflict_stay_unknown(check_id, change):
    case, direct, alias = native_case(change=change)
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    assert_raw_orders(snapshot, direct, alias)
    assert direct_finding(snapshot, check_id)["status"] == "UNKNOWN"
    assert status(snapshot, check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
@pytest.mark.parametrize("change", ["duplicate_binding_member", "duplicate_audit_service",
                                     "duplicate_logtype", "duplicate_exemption",
                                     "malformed_binding", "malformed_audit"])
def test_duplicate_or_malformed_projection_content_stays_unknown(check_id, change):
    case, direct, alias = native_case(change=change)
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    if change.startswith("malformed_"):
        envelope = next(row for row in snapshot["collections"] if row["type"] == "iam_policy" and row["scope"] == SCOPE)
        assert envelope["coverage_status"] == "partial"
        assert not any(row.get("name") == CAI_NAME for row in envelope["items"])
    else:
        assert_raw_orders(snapshot, direct, alias)
    assert direct_finding(snapshot, check_id)["status"] == "UNKNOWN"
    assert status(snapshot, check_id) == {"UNKNOWN"}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
@pytest.mark.parametrize("capture", ["partial_page", "denied_read", "unreadable_field"])
def test_reordered_view_with_incomplete_native_capture_stays_unknown(check_id, capture):
    case, direct, alias = native_case()
    if capture == "partial_page":
        case.cai_warning = True
    elif capture == "denied_read":
        case.cai_status = 403
    snapshot, _ = collect(case, owner_services=CHECK_SERVICES.values())
    if capture == "unreadable_field":
        collections = copy.deepcopy(snapshot["collections"])
        envelope = next(row for row in collections if row["type"] == "iam_policy" and row["scope"] == SCOPE)
        projection = next(row for row in envelope["items"] if row["name"] == CAI_NAME)
        projection.setdefault("_coverage", {})["auditConfigs"] = {"status": "partial"}
        snapshot = remake(snapshot, collections=collections)
    if capture != "denied_read":
        assert_raw_orders(snapshot, direct, alias)
    assert direct_finding(snapshot, check_id)["status"] == "UNKNOWN"
    assert status(snapshot, check_id) == {"UNKNOWN"}
