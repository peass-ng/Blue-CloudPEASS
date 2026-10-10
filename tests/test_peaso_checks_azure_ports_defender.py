"""Pinned Defender truth cases, subscription joins and complete absence evidence."""
import copy
import json
from pathlib import Path
import re

import pytest

from peaso.checks import CHECKS, azure_ports_defender as ports
from peaso.checks.fixtures import CASES
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGISTRY = {check.id: check for check in CHECKS}
REVIEWS = json.loads((Path(__file__).resolve().parent.parent / "peaso/rulepacks/reviewed_azure_ports_defender.json").read_text())
SQL_CASES = {row["source_review"]["query_id"]: row["source_review"]["status_case_sql"] for row in REVIEWS.values() if "query_id" in row["source_review"]}


@pytest.mark.parametrize("cid", ports.CHECK_IDS, ids=str)
def test_defender_pass_fail_missing_malformed_denied_and_purity(cid):
    check = REGISTRY[cid]
    cases = CASES[cid]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL")):
        item = copy.deepcopy(cases[label])
        index = copy.deepcopy(cases.get(label + "_index", {}))
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == expected
        assert (item, index) == before
    for item in ({}, None, [], {"collection_status": "denied"}):
        assert check.evaluate(item, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("query", ports.SOURCE_QUERIES, ids=str)
def test_isolated_pinned_status_cases_match_native_truth(query):
    duckdb = pytest.importorskip("duckdb")
    case = SQL_CASES[query]
    case = re.sub(r"\b\w+\.(\w+)\b", r"\1", case)
    case = re.sub(r"(data\s*->>\s*'[^']+')\s*=", r"(\1) =", case)
    cid = ports.SOURCE_QUERIES[query]
    for label, want_source, want_native in (("pass", "ok", "PASS"), ("fail", "alarm", "FAIL")):
        if query in ports.PLAN_RULES:
            sql = "SELECT " + case + " FROM (SELECT ? AS name, ? AS pricing_tier)"
            values = [ports.PLAN_RULES[query], "Standard" if label == "pass" else "Free"]
        elif query.endswith("_database"):
            tiers = {"CosmosDbs": "Standard", "OpenSourceRelationalDatabases": "Standard", "SqlServerVirtualMachines": "Standard", "SqlServers": "Standard"}
            if label == "fail":
                tiers.pop("CosmosDbs")
            sql = "SELECT " + case + " FROM (SELECT ?::JSON AS data)"
            values = [json.dumps(tiers)]
        else:
            sql = "SELECT " + case + " FROM (SELECT ? AS enabled)"
            values = [label == "pass"]
        with duckdb.connect(":memory:") as database:
            assert database.execute(sql, values).fetchone()[0] == want_source
        fixture = CASES[cid]
        assert REGISTRY[cid].evaluate(fixture[label], fixture.get(label + "_index", {}))[0] == want_native


@pytest.mark.parametrize("cid", [cid for cid in ports.CHECK_IDS if REGISTRY[cid].target == "scope"], ids=str)
@pytest.mark.parametrize("status", ["denied", "partial", "unknown", "malformed", "not_collected"])
def test_scope_dependency_failures_cannot_pass_or_fail(cid, status):
    check = REGISTRY[cid]
    kind = check.dependencies[0]
    index = {"collections": {kind: [{"type": kind, "scope": "/subscriptions/sub", "status": status, "items": []}]}, kind: []}
    assert check.evaluate({"scope": "/subscriptions/sub"}, index)[0] == "UNKNOWN"
    snapshot = make_snapshot("azure", ["/subscriptions/sub"], [{"type": kind, "scope": "/subscriptions/sub", "service": "Microsoft.Security", "status": status, "items": []}])
    report = evaluate_snapshot(snapshot, checks=[cid])
    expected = "DENIED" if status == "denied" else "UNKNOWN"
    assert {finding["status"] for finding in report["findings"]} == {expected}


def test_pricing_absence_does_not_report_empty_safe_configuration():
    cid = ports.SOURCE_QUERIES["securitycenter_azure_defender_on_for_server"]
    index = ports._fixture("security_pricing", [], status="empty")
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "UNKNOWN"
    snapshot = make_snapshot("azure", ["/subscriptions/sub"], [{"type": "security_pricing", "scope": "/subscriptions/sub", "service": "Microsoft.Security", "status": "empty", "items": []}])
    report = evaluate_snapshot(snapshot, checks=[cid])
    assert {finding["status"] for finding in report["findings"]} == {"UNKNOWN"}


def test_required_four_database_plans_can_fail_known_absence_after_complete_read():
    cid = ports.SOURCE_QUERIES["securitycenter_azure_defender_on_for_database"]
    index = ports._fixture("security_pricing", [], status="empty")
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "FAIL"
    index["collections"]["security_pricing"][0]["status"] = "partial"
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, index)[0] == "UNKNOWN"


def test_prowler_required_integration_and_sql_filtered_row_absence_are_distinct():
    index = ports._fixture("security_setting", [], status="empty")
    anchor = {"scope": "/subscriptions/sub"}
    assert REGISTRY["azure.port.defender_required_wdatp"].evaluate(anchor, index)[0] == "FAIL"
    assert REGISTRY[ports.SOURCE_QUERIES["securitycenter_wdatp_integration"]].evaluate(anchor, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("query", ports.PLAN_RULES, ids=str)
def test_foreign_subscription_pricing_never_fulfills_selected_scope(query):
    cid = ports.SOURCE_QUERIES[query]
    fixture = copy.deepcopy(CASES[cid]["pass_index"])
    fixture["security_pricing"][0]["data"]["id"] = fixture["security_pricing"][0]["data"]["id"].replace("/sub/", "/foreign/")
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, fixture)[0] == "UNKNOWN"


def test_duplicate_plan_identity_is_unknown_and_tenant_anchor_is_inapplicable():
    cid = ports.SOURCE_QUERIES["securitycenter_azure_defender_on_for_server"]
    rows = [ports._plan_row("VirtualMachines", "Standard"), ports._plan_row("VirtualMachines", "Free")]
    assert REGISTRY[cid].evaluate({"scope": "/subscriptions/sub"}, ports._fixture("security_pricing", rows))[0] == "UNKNOWN"
    assert REGISTRY[cid].evaluate({"scope": "/tenants/tenant"}, {})[0] == "NOT_APPLICABLE"


def test_contact_roles_state_and_severity_preserve_pinned_normalization():
    owner = REGISTRY["azure.port.defender_notify_owner_contact"]
    assert owner.evaluate({"properties": {"notificationsByRole": {"state": "On", "roles": ["Contributor"]}}}, {})[0] == "FAIL"
    assert owner.evaluate({"properties": {"notificationsByRole": {"state": "On", "roles": [123]}}}, {})[0] == "UNKNOWN"
    severity = REGISTRY["azure.port.defender_alert_severity_contact"]
    for value, expected in (("Low", "PASS"), ("Medium", "PASS"), ("High", "PASS"), ("Critical", "FAIL"), ("Unknown", "UNKNOWN")):
        assert severity.evaluate({"properties": {"notificationsSources": [{"sourceType": "Alert", "minimalSeverity": value}]}}, {})[0] == expected
    sources = [{"sourceType": "Alert", "minimalSeverity": "High"}, {"sourceType": "Alert", "minimalSeverity": "Critical"}]
    assert severity.evaluate({"properties": {"notificationsSources": sources}}, {})[0] == "FAIL"
