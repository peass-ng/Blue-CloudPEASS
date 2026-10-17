"""The parent status consumed by a guard must itself have readable coverage."""
from copy import deepcopy
import pytest
from peaso.checks import evaluate_check
from peaso.checks.fixtures import CASES

IDS = ("aws.ebs.encryption", "gcp.network.custom_subnets", "gcp.gke.secrets_encryption")

@pytest.mark.parametrize("check_id", IDS)
@pytest.mark.parametrize("fixture_status", ("pass", "fail"))
@pytest.mark.parametrize("coverage", ("absent", "collected", "denied", "not_collected", "partial", None, "empty"))
def test_parent_status_selected_authority(check_id, fixture_status, coverage):
    item = deepcopy(CASES[check_id][fixture_status])
    item["collection_status"] = "collected"
    if coverage != "absent":
        item["_coverage"] = {"collection_status": None if coverage is None else {"status": coverage}}
    expected = fixture_status.upper() if coverage in ("absent", "collected") else "UNKNOWN"
    assert evaluate_check(check_id, item)[0] == expected

@pytest.mark.parametrize("coverage,expected", [("empty", "PASS"), ("collected", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_absent_parent_marker_coverage_coherence(coverage, expected):
    item = deepcopy(CASES["aws.ebs.encryption"]["pass"])
    item["_coverage"] = {"collection_status": {"status": coverage}}
    assert evaluate_check("aws.ebs.encryption", item)[0] == expected

@pytest.mark.parametrize("marker", ["collected", "empty"])
def test_readable_parent_marker_preserves_native_value_boundary(marker):
    item = deepcopy(CASES["aws.ebs.encryption"]["pass"])
    item["collection_status"] = marker
    item["_coverage"] = {"collection_status": {"status": "collected"}}
    assert evaluate_check("aws.ebs.encryption", item)[0] == "PASS"

@pytest.mark.parametrize("check_id,provider,scope,kind", [("aws.ebs.encryption", "aws", "123456789012/us-east-1", "ebs_volume"), ("gcp.network.custom_subnets", "gcp", "project", "network"), ("gcp.gke.secrets_encryption", "gcp", "project", "gke_cluster")])
def test_unavailable_parent_status_through_sealed_snapshot(check_id, provider, scope, kind):
    from peaso.snapshot import make_snapshot
    from peaso.engine import evaluate_snapshot
    item = deepcopy(CASES[check_id]["pass"])
    item["collection_status"] = "collected"
    item["_coverage"] = {"collection_status": {"status": "denied"}}
    snapshot = make_snapshot(provider, [scope], [{"type": kind, "scope": scope, "status": "collected", "items": [item]}])
    findings = evaluate_snapshot(snapshot, checks=[check_id], include_not_applicable=True)["findings"]
    assert findings and {f["status"] for f in findings} == {"UNKNOWN"}, findings
