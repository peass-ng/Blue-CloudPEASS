"""Truth fixtures for entity applicability, scope joins and literal predicates."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_metadata as ports
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


def evaluate(query, item, index=None):
    return REGISTRY[ports.REFERENCE_SPECS[query]].evaluate(item, index or {})[0]


def test_dns_algorithm_and_enablement_are_separate_source_predicates():
    item = {"visibility": "public", "dnssecConfig": {"state": "off", "defaultKeySpecs": []}}
    assert evaluate("dns_managed_zone_dnssec_enabled", item) == "FAIL"
    assert evaluate("dns_managed_zone_key_signing_not_using_rsasha1", item) == "PASS"
    for query in ("dns_managed_zone_dnssec_enabled", "dns_managed_zone_key_signing_not_using_rsasha1", "dns_managed_zone_zone_signing_not_using_rsasha1"):
        assert evaluate(query, {"visibility": "private"}) == "NOT_APPLICABLE"
        assert evaluate(query, {"visibility": "public", "_coverage": {"dnssecConfig": {"status": "denied"}}}) == "UNKNOWN"


def test_transient_function_applicability_is_not_merged_with_all_functions():
    assert evaluate("function_active_vpc_connector", {"state": "DEPLOYING"}) == "NOT_APPLICABLE"
    assert evaluate("function_active_public_binding", {"state": "DEPLOYING"}) == "NOT_APPLICABLE"
    assert evaluate("cloudfunction_function_vpc_connector_enabled", {"state": "DEPLOYING"}) == "UNKNOWN"


def test_conditional_public_binding_preserves_conditions_without_effective_access_claim():
    cid = ports.REFERENCE_SPECS["cloudrun_service_restrict_public_access"]
    condition = {"expression": "request.time < timestamp('2026-01-01T00:00:00Z')"}
    item = {"iamPolicy": {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"], "condition": condition}]}}
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == "FAIL"
    assert evidence["public_bindings"][0]["condition"] == condition
    assert "not flattened" in evidence["semantics"]


def test_complete_project_key_join_uses_number_and_resists_crossproject_collision():
    cid = ports.REFERENCE_SPECS["project_no_api_key"]
    index = copy.deepcopy(CASES[cid]["index"])
    assert evaluate("project_no_api_key", {"projectId": "p", "name": "projects/123"}, index) == "PASS"
    index["api_key"].append({"data": {"name": "projects/123/locations/global/keys/k"}})
    assert evaluate("project_no_api_key", {"projectId": "p", "name": "projects/123"}, index) == "FAIL"
    index["collections"]["api_key"][0]["status"] = "partial"
    assert evaluate("project_no_api_key", {"projectId": "p", "name": "projects/123"}, index) == "UNKNOWN"


def test_elapsed_day_policy_differs_from_calendar_midnight_policy():
    item = {"createTime": "2026-07-12T00:00:00Z", "_provenance": {"collected_at": "2026-10-10T12:00:00Z"}}
    assert evaluate("api_key_elapsed_age_gt90", item) == "PASS"
    item["createTime"] = "2026-07-11T12:00:00Z"
    assert evaluate("api_key_elapsed_age_gt90", item) == "FAIL"
