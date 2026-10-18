"""Truth fixtures for entity applicability, scope joins and literal predicates."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_relationships as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_metadata_truths(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    index = copy.deepcopy(CASES[cid].get("index", {}))
    before = copy.deepcopy((item, index))
    status, evidence = REGISTRY[cid].evaluate(item, index)
    assert status == wanted, evidence
    assert (item, index) == before




def test_instance_override_source_false_alarm_and_native_project_inheritance():
    cid = ports.REFERENCE_SPECS["compute_oslogin_metadata_precedence"]
    enabled = {"metadata": {"items": [{"key": "enable-oslogin", "value": "true"}]}}
    # SQL requires project flag first and alarms even when instance enables it.
    assert REGISTRY[cid].evaluate(enabled, {})[0] == "PASS"
    item = {"metadata": {"items": []}, "_provenance": {"scope": "projects/p"}}
    index = {"collections": {"project": [{"status": "collected"}]}, "project": [{"data": {"name": "projects/p", "commonInstanceMetadata": {"items": [{"key": "enable-oslogin", "value": "true"}]}}}]}
    assert REGISTRY[cid].evaluate(item, index)[0] == "PASS"
    index["collections"]["project"][0]["status"] = "denied"
    assert REGISTRY[cid].evaluate(item, index)[0] == "UNKNOWN"
    enabled["metadata"]["items"] *= 2
    assert REGISTRY[cid].evaluate(enabled, {})[0] == "UNKNOWN"


def test_ssl_default_is_not_strict_and_current_fips_policy_is_applicable():
    cid = ports.REFERENCE_SPECS["compute_ssl_policy_strict_declaration"]
    fixture = CASES[cid]
    assert "sslPolicy" not in fixture["fail"]  # SQL's ssl_policy IS NULL gives OK.
    assert REGISTRY[cid].evaluate(fixture["fail"], {})[0] == "FAIL"
    index = copy.deepcopy(fixture["index"])
    index["ssl_policy"][0]["data"]["profile"] = "FIPS_202205"
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "PASS"
    assert REGISTRY[cid].evaluate({"kind": "compute#targetHttpProxy"}, {})[0] == "NOT_APPLICABLE"
    index["collections"]["ssl_policy"][0]["status"] = "partial"
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"


def test_nondefault_url_map_backend_source_false_clean_and_ambiguous_join():
    cid = ports.REFERENCE_SPECS["compute_url_map_backend_logging"]
    fixture = CASES[cid]
    assert fixture["pass"]["defaultService"] == fixture["fail"]["defaultService"]  # SQL inspects default only.
    assert REGISTRY[cid].evaluate(fixture["fail"], fixture["index"])[0] == "FAIL"
    index = copy.deepcopy(fixture["index"])
    index["backend_service"].append(copy.deepcopy(index["backend_service"][0]))
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"
    assert REGISTRY[cid].evaluate({"name": "redirect", "defaultUrlRedirect": {}}, {})[0] == "NOT_APPLICABLE"


def test_no_contacts_is_required_configuration_failure_when_inventory_complete():
    cid = ports.REFERENCE_SPECS["organization_essential_contacts_complete"]
    index = {"collections": {"essential_contact": [{"status": "empty"}]}, "essential_contact": []}
    assert REGISTRY[cid].evaluate({"name": "organizations/o"}, index)[0] == "FAIL"
    # SQL inner-expands contacts/categories then groups; zero contacts emits zero rows.
    assert list(index["essential_contact"]) == []
    index["collections"]["essential_contact"][0]["status"] = "denied"
    assert REGISTRY[cid].evaluate({"name": "organizations/o"}, index)[0] == "UNKNOWN"


def test_access_approval_notifications_do_not_enable_enrollment():
    cid = ports.REFERENCE_SPECS["access_approval_explicit_enrollment"]
    item = {"name": "projects/p/accessApprovalSettings", "notificationEmails": []}
    assert item["notificationEmails"] is not None  # SQL classifies as enabled.
    assert REGISTRY[cid].evaluate(item, {})[0] == "FAIL"
    item["enrolledAncestor"] = True
    assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN"
