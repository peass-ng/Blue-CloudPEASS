"""Imported configuration facts are real evaluators, with separate collection gaps."""
import copy
import pytest
from peaso.checks import CHECKS, k8s_ports_reference_config as ports
from peaso.checks.fixtures import CASES
from peaso.collectors.k8s import collect
from tests.test_peaso_checks_k8s_ports_collection import API

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_reference_configuration_truth_and_immutable_inputs(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    original = copy.deepcopy(item)
    status, evidence = REGISTRY[cid].evaluate(item, {})
    assert status == wanted, evidence
    assert item == original


def test_reference_audit_threshold_equality_is_distinct_from_sql_minimum():
    check = REGISTRY[ports.REFERENCE_SPECS["apiserver_audit_log_maxage_set"]]
    item = copy.deepcopy(CASES[check.id]["pass"])
    item["spec"]["containers"][0]["_component_config"]["flags"]["audit-log-maxage"] = "31"
    assert check.evaluate(item, {})[0] == "FAIL"


def test_file_ownership_metadata_has_real_pass_fail_and_path_applicability():
    check = REGISTRY[ports.REFERENCE_SPECS["kubelet_config_yaml_ownership"]]
    assert check.evaluate({"path": "/var/lib/kubelet/config.yaml", "uid": 0, "gid": 0}, {})[0] == "PASS"
    assert check.evaluate({"path": "/var/lib/kubelet/config.yaml", "uid": 1000, "gid": 0}, {})[0] == "FAIL"
    assert check.evaluate({"path": "/other", "uid": 0, "gid": 0}, {})[0] == "NOT_APPLICABLE"


def test_missing_safe_file_source_is_collection_gap_without_host_reads():
    api = API(total_pages=1, page_items=0)
    result = collect({"provider": "k8s", "options": {"inventories": ["file_metadata"]},
                      "auth": {"cluster_id": "fixture"}}, api=api)
    assert result["collections"][0]["status"] == "unknown"
    assert result["collections"][0]["error"]["code"] == "manual_metadata_source_required"
    assert api.calls == []


def test_safe_supplied_metadata_provenance_does_not_claim_runtime_verification():
    api = API(total_pages=1, page_items=0)
    entry = {"path": "/var/lib/kubelet/config.yaml", "uid": 0, "gid": 0, "mode": 384}
    result = collect({"provider": "k8s", "options": {"inventories": ["file_metadata"], "metadata_evidence": {"file_metadata": [entry]}},
                      "auth": {"cluster_id": "fixture"}}, api=api)
    item = result["collections"][0]["items"][0]
    assert item["provenance"]["runtime_verified"] is False
    assert item["uid"] == 0
    assert api.calls == []


def test_metadata_import_rejects_contents_and_secret_values_without_any_api_call():
    api = API(total_pages=1, page_items=0)
    entry = {"path": "/etc/kubernetes/kubelet.conf", "contents": "INERT_VALUE"}
    result = collect({"provider": "k8s", "options": {"inventories": ["file_metadata"], "metadata_evidence": {"file_metadata": [entry]}},
                      "auth": {"cluster_id": "fixture"}}, api=api)
    assert result["collections"][0]["status"] == "malformed"
    assert result["collections"][0]["items"] == [] and api.calls == []


def test_nested_supplied_component_data_is_whitelisted_without_credentials():
    api = API(total_pages=1, page_items=0)
    entry = {"component": "kubelet", "configuration": {"readOnlyPort": 0,
        "authentication": {"anonymous": {"enabled": False}, "token": "INERT_PRIVATE_TOKEN"},
        "clientSecret": "INERT_PRIVATE_TOKEN"}}
    result = collect({"provider": "k8s", "options": {"inventories": ["component_configuration"],
        "metadata_evidence": {"component_configuration": [entry]}}, "auth": {"cluster_id": "fixture"}}, api=api)
    item = result["collections"][0]["items"][0]
    assert item["configuration"] == {"authentication": {"anonymous": {"enabled": False}}, "readOnlyPort": 0}
    assert api.calls == []
