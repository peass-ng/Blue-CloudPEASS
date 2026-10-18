"""Authoritative inheritance/default and exact metadata identity joins."""
import copy
import pytest
from peaso.checks.k8s_ports_automount import evaluate_token_automount


def facts(setting=None):
    pod = {"metadata": {"namespace": "apps"}, "spec": {"serviceAccountName": "app"}, "provenance": {"cluster_id": "c"}}
    account = {"metadata": {"namespace": "apps", "name": "app"}, "provenance": {"cluster_id": "c"}}
    if setting is not None:
        account["automountServiceAccountToken"] = setting
    return pod, {"collections": {"serviceaccount": [{"scope": "*", "status": "collected"}]}, "serviceaccount": [{"data": account}]}


@pytest.mark.parametrize("setting,wanted", [(False, "PASS"), (True, "FAIL"), (None, "FAIL")])
def test_inherited_setting_and_known_unset_default(setting, wanted):
    pod, index = facts(setting)
    before = copy.deepcopy((pod, index))
    assert evaluate_token_automount(pod, index)[0] == wanted
    assert (pod, index) == before


def test_pod_override_wins_and_default_serviceaccount_name_is_documented():
    pod, index = facts(True)
    pod["spec"]["automountServiceAccountToken"] = False
    assert evaluate_token_automount(pod, {})[0] == "PASS"
    pod["spec"] = {}
    index["serviceaccount"][0]["data"]["metadata"]["name"] = "default"
    assert evaluate_token_automount(pod, index)[0] == "FAIL"


@pytest.mark.parametrize("status", ["denied", "partial", "unknown", "malformed", "not_collected"])
def test_missing_or_incomplete_serviceaccount_inventory_never_infers_default(status):
    pod, index = facts(False)
    index["collections"]["serviceaccount"][0]["status"] = status
    assert evaluate_token_automount(pod, index)[0] == "UNKNOWN"
    assert evaluate_token_automount(pod, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("namespace", "other"), ("name", "other")])
def test_cross_namespace_name_collision_not_joined(field, value):
    pod, index = facts(False)
    index["serviceaccount"][0]["data"]["metadata"][field] = value
    assert evaluate_token_automount(pod, index)[0] == "UNKNOWN"


def test_cross_cluster_and_duplicate_metadata_are_not_authoritative_inheritance():
    pod, index = facts(False)
    index["serviceaccount"][0]["data"]["provenance"]["cluster_id"] = "foreign"
    assert evaluate_token_automount(pod, index)[0] == "UNKNOWN"
    pod, index = facts(False)
    index["serviceaccount"].append(copy.deepcopy(index["serviceaccount"][0]))
    assert evaluate_token_automount(pod, index)[0] == "UNKNOWN"


def test_malformed_and_denied_scalar_does_not_fall_back_to_true():
    pod, index = facts(False)
    account = index["serviceaccount"][0]["data"]
    account["automountServiceAccountToken"] = "false"
    assert evaluate_token_automount(pod, index)[0] == "UNKNOWN"
    account["automountServiceAccountToken"] = False
    account["_coverage"] = {"automountServiceAccountToken": {"status": "denied"}}
    assert evaluate_token_automount(pod, index)[0] == "UNKNOWN"
    assert evaluate_token_automount(None, index)[0] == "UNKNOWN"
