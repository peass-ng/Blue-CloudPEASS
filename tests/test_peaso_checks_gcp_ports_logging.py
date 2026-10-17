"""Source cross-project counterexamples and complete native declaration joins."""
import copy
import re
import pytest
from peaso.checks import CHECKS, gcp_ports_logging as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_scoped_logging_truths(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    index = copy.deepcopy(CASES[cid].get("index", {}))
    before = copy.deepcopy((item, index))
    status, evidence = REGISTRY[cid].evaluate(item, index)
    assert status == wanted, evidence
    assert (item, index) == before


@pytest.mark.parametrize("query", list(ports.PATTERNS))
def test_pinned_source_scope_omission_counterexample(query):
    cid = ports.REFERENCE_SPECS[query]
    fixture = CASES[cid]
    index = copy.deepcopy(fixture["index"])
    metric = index["logging_metric"][0]["data"]
    alert = index["monitoring_alert_policy"][0]["data"]
    assert re.search(ports.PATTERNS[query], metric["filter"])
    # SQL joins m.filter and unqualified metric.type without alert project/metrics scope.
    alert["name"] = "projects/unrelated/alertPolicies/a"
    assert 'metric.type="' + metric["metricDescriptor"]["type"] + '"' in alert["conditions"][0]["conditionThreshold"]["filter"]
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "FAIL"
    index["collections"]["monitoring_alert_policy"][0]["status"] = "denied"
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", [ports.REFERENCE_SPECS[query] for query in ports.PATTERNS])
def test_disabled_metric_or_alert_and_incomplete_dependency_cannot_pass(cid):
    fixture = CASES[cid]
    for kind, field in (("logging_metric", "disabled"), ("monitoring_alert_policy", "enabled")):
        index = copy.deepcopy(fixture["index"])
        index[kind][0]["data"][field] = field == "disabled"
        assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "FAIL"
        index["collections"][kind][0]["status"] = "partial"
        assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"


def test_sink_source_false_clean_for_disabled_and_exclusion_declarations():
    cid = ports.REFERENCE_SPECS["logging_sink_all_entries_enabled"]
    fixture = CASES[cid]
    for change in ({"disabled": True}, {"exclusions": [{"filter": "severity>=ERROR"}]}):
        index = copy.deepcopy(fixture["index"])
        sink = index["log_sink"][0]["data"]
        sink.update(change)
        assert sink["filter"] == "" and sink["destination"]  # Pinned SQL says OK.
        assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "FAIL"


def test_dns_same_name_foreign_network_never_satisfies_qualified_attachment():
    cid = ports.REFERENCE_SPECS["compute_network_dns_logging_scoped"]
    fixture = CASES[cid]
    assert fixture["pass"]["selfLink"].split("networks/")[1] == fixture["fail"]["selfLink"].split("networks/")[1]
    assert REGISTRY[cid].evaluate(fixture["fail"], fixture["index"])[0] == "FAIL"


def test_sink_nonstorage_destination_is_not_applicable_and_ambiguous_bucket_unknown():
    cid = ports.REFERENCE_SPECS["logging_bucket_retention_policy_enabled"]
    assert REGISTRY[cid].evaluate({"destination": "bigquery.googleapis.com/projects/p/datasets/d"}, {})[0] == "NOT_APPLICABLE"
    fixture = CASES[cid]
    index = copy.deepcopy(fixture["index"])
    index["bucket"].append(copy.deepcopy(index["bucket"][0]))
    assert REGISTRY[cid].evaluate(fixture["pass"], index)[0] == "UNKNOWN"
