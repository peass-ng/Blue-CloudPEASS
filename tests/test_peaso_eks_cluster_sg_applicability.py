"""An EKS-created cluster SG ID is a versioned presence fact, not pod NetworkPolicy."""
import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude2_aws_b_compute as compute


CHECK = next(check for check in CHECKS if check.id == "aws.c2b.eks.cluster_security_group_present")


def evaluate(item):
    original = copy.deepcopy(item)
    status, evidence = CHECK.evaluate(item, {})
    assert item == original
    return status, evidence


def no_id(**fields):
    item = compute._eks(**fields)
    del item["Cluster"]["cluster"]["resourcesVpcConfig"]["clusterSecurityGroupId"]
    return item


def test_observed_id_passes_only_the_narrow_presence_fact():
    status, evidence = evaluate(compute._eks())
    assert status == "PASS"
    assert evidence["cluster_security_group_id"] == "sg-01234567"
    assert "NetworkPolicy were not evaluated" in evidence["observed_fact"]
    assert "NetworkPolicy" not in CHECK.title


@pytest.mark.parametrize("item", [
    no_id(),
    compute._eks({"clusterSecurityGroupId": ""}),
    compute._eks({"clusterSecurityGroupId": None}),
    compute._eks({"clusterSecurityGroupId": "sg-xyz"}),
    compute._eks({"clusterSecurityGroupId": ["sg-01234567"]}),
    compute._eks({"clusterSecurityGroupId": "sg-1"}),
])
def test_modern_missing_empty_or_malformed_id_is_unknown(item):
    assert evaluate(item)[0] == "UNKNOWN"


def test_denied_id_or_describe_cluster_is_unknown():
    item = compute._eks()
    item["Cluster"]["cluster"]["resourcesVpcConfig"]["_coverage"] = {
        "clusterSecurityGroupId": {"status": "denied"}
    }
    assert evaluate(item)[0] == "UNKNOWN"
    item = compute._eks()
    item["Cluster"] = {"collection_status": "denied"}
    assert evaluate(item)[0] == "UNKNOWN"


@pytest.mark.parametrize("version,platform", [
    ("1.13", "eks.7"), ("1.14", "eks.1"), ("1.14", "eks.2"),
])
def test_proven_legacy_model_is_not_applicable(version, platform):
    status, evidence = evaluate(no_id(version=version, platformVersion=platform))
    assert status == "NOT_APPLICABLE"
    assert "historical" in evidence["reason"]


@pytest.mark.parametrize("version,platform", [
    ("1.14", "eks.3"), ("1.14", "eks.4"), ("1.30", "eks.6"),
    ("v1.14", "eks.2"), ("1.14", "unknown"),
])
def test_boundary_modern_and_malformed_version_facts_do_not_prove_failure(version, platform):
    assert evaluate(no_id(version=version, platformVersion=platform))[0] == "UNKNOWN"


def test_missing_version_or_platform_does_not_guess_legacy_applicability():
    item = no_id()
    del item["Cluster"]["cluster"]["version"]
    assert evaluate(item)[0] == "UNKNOWN"
    item = no_id(version="1.14")
    del item["Cluster"]["cluster"]["platformVersion"]
    assert evaluate(item)[0] == "UNKNOWN"


def test_present_id_needs_no_creation_version_to_prove_its_presence():
    item = compute._eks()
    del item["Cluster"]["cluster"]["version"]
    assert evaluate(item)[0] == "PASS"


def test_no_recreation_guidance_or_false_failure_fixture():
    assert "recreate" not in CHECK.remediation.lower()
    from peaso.checks.fixtures import CASES
    assert CASES[CHECK.id]["fail_expect"] == "UNKNOWN"
    assert evaluate(copy.deepcopy(CASES[CHECK.id]["fail"]))[0] == "UNKNOWN"
