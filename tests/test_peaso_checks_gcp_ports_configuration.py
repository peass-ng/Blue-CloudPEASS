"""Truth fixtures for entity applicability, scope joins and literal predicates."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_configuration as ports
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



@pytest.mark.parametrize("cid", list(ports.SQL_SPECS))
def test_default_policy_uses_source_fallback_and_engine_applicability(cid):
    spec = ports.SQL_SPECS[cid]
    source_status = "PASS" if spec["default"] in spec["allowed"] else "FAIL"
    item = {"databaseVersion": spec["engine"] + "_16", "settings": {"databaseFlags": []}}
    assert REGISTRY[cid].evaluate(item, {})[0] == source_status
    item["databaseVersion"] = "MYSQL_8_0"
    assert REGISTRY[cid].evaluate(item, {})[0] == "NOT_APPLICABLE"
    item["databaseVersion"] = spec["engine"] + "_16"
    item["settings"]["databaseFlags"] = [{"name": spec["flag"], "value": spec["allowed"][0]}] * 2
    assert REGISTRY[cid].evaluate(item, {})[0] == "UNKNOWN"


def test_gemini_disabled_state_and_exact_scope_no_fallback():
    cid = ports.REFERENCE_SPECS["apikeys_api_restricted_with_gemini_api"]
    fixture = CASES[cid]
    index = copy.deepcopy(fixture["index"])
    index["service_usage"][0]["data"]["state"] = "DISABLED"
    assert REGISTRY[cid].evaluate(fixture["fail"], index)[0] == "PASS"
    index["service_usage"][0]["data"]["name"] = "projects/unrelated/services/generativelanguage.googleapis.com"
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"
    index = copy.deepcopy(fixture["index"])
    index["collections"]["service_usage"][0]["status"] = "denied"
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"


def test_alloydb_explicit_flag_presence_is_distinct_from_postgresql_default():
    cid = ports.REFERENCE_SPECS["alloydb_instance_log_min_error_statement_database_flag_configured"]
    assert REGISTRY[cid].evaluate({"databaseFlags": {}}, {})[0] == "FAIL"
    assert REGISTRY[cid].evaluate({}, {})[0] == "UNKNOWN"
