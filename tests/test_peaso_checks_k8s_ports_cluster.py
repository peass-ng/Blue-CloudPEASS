"""Scope completeness, namespace joins and legacy admission truth fixtures."""
import copy
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS, k8s_ports_cluster as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_cluster_predicates_have_available_truth_and_coverage_gaps(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    index = copy.deepcopy(CASES[cid].get("index", {}))
    original = copy.deepcopy((item, index))
    actual, evidence = REGISTRY[cid].evaluate(item, index)
    assert actual == wanted, evidence
    assert (item, index) == original


@pytest.mark.parametrize("dependency,state", [("resourcequota", "denied"), ("resourcequota", "partial"),
    ("resourcequota", "malformed"), ("resourcequota", "not_collected"), ("limitrange", "denied"), ("networkpolicy", "partial")])
def test_incomplete_inventory_never_proves_namespace_absence_or_presence(dependency, state):
    query = {"resourcequota": "namespace_resource_quota_cpu_limit", "limitrange": "namespace_limit_range_default_cpu_limit",
             "networkpolicy": "network_policy_default_deny_ingress"}[dependency]
    check = REGISTRY[ports.REFERENCE_SPECS[query]]
    fixture = CASES[check.id]
    index = copy.deepcopy(fixture["index"])
    index["collections"][dependency][0]["status"] = state
    assert check.evaluate(fixture["pass"], index)[0] == "UNKNOWN"


def test_complete_empty_inventory_can_fail_a_required_configuration_predicate():
    check = REGISTRY[ports.REFERENCE_SPECS["namespace_resource_quota_cpu_limit"]]
    index = {"collections": {"resourcequota": [{"scope": "*", "status": "empty"}]}, "resourcequota": []}
    assert check.evaluate({"metadata": {"name": "apps"}}, index)[0] == "FAIL"
    assert check.evaluate({"metadata": {"name": "apps"}}, {})[0] == "UNKNOWN"


def test_other_namespace_never_satisfies_required_configuration():
    check = REGISTRY[ports.REFERENCE_SPECS["network_policy_default_deny_ingress"]]
    index = copy.deepcopy(CASES[check.id]["index"])
    assert check.evaluate({"metadata": {"name": "other"}}, index)[0] == "FAIL"
    assert check.evaluate({"metadata": {"name": "apps"}}, index)[0] == "PASS"


def test_allow_rule_reference_is_per_policy_not_a_namespace_default_claim():
    check = REGISTRY[ports.REFERENCE_SPECS["network_policy_default_dont_allow_ingress"]]
    assert check.kind == "networkpolicy"
    assert check.evaluate({"spec": {"podSelector": {"matchLabels": {"app": "public"}}, "ingress": [{}]}}, {})[0] == "FAIL"


def test_legacy_psp_version_is_explicit_and_modern_replacement_guidance_survives():
    check = REGISTRY[ports.REFERENCE_SPECS["pod_security_policy_container_privilege_disabled"]]
    assert check.evaluate({"_provenance": {"kubernetes_version": "v1.25.0"}, "spec": {"privileged": False}}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"spec": {"privileged": False}}, {})[0] == "UNKNOWN"
