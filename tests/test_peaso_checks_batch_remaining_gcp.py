"""Source-bound GCP batch fixtures captured from the prior isolated family tests."""
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import batch_remaining_gcp  # noqa: F401
from peaso.checks.facts import MemoIndex


ROOT = Path(__file__).resolve().parents[1]
DISPOSITION = json.loads((ROOT / "tests/fixtures/batch_remaining_gcp_k8s/full-id-disposition.json").read_text())
CENTRAL = json.loads((ROOT / "tests/fixtures/batch_remaining_gcp_k8s/central-fixture-fragment.json").read_text())
FIXTURES = {check_id: {label: {"item": case[label], "index": case.get(label + "_index", case["index"])}
                       for label in ("pass", "fail", "unknown") if label in case}
            for check_id, case in CENTRAL.items()}
IDS = [row["id"] for row in DISPOSITION["ids"] if row["provider"] == "gcp" and row["disposition"] == "implemented"]


@pytest.mark.parametrize("check_id", IDS)
def test_gcp_native_identity_and_snapshot_outcomes(check_id):
    checks = [check for check in CHECKS if check.id == check_id]
    assert len(checks) == 1
    assert checks[0].provider == "gcp"
    if check_id == "gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d":
        scope = "projects/test-project"
        def evidence(enabled):
            row = {"name": "cluster", "controlPlaneEndpointsConfig": {"ipEndpointsConfig": {"enablePublicEndpoint": enabled}}}
            return {"collections": {"gke_cluster": [{"type": "gke_cluster", "scope": scope, "status": "collected", "items": [row]}]},
                    "gke_cluster": [{"type": "gke_cluster", "scope": scope, "data": row}],
                    "context": {"provider": "gcp", "scope": scope}}
        item = {"scope": scope}
        assert evaluate_check(check_id, item, evidence(False))[0] == "PASS"
        assert evaluate_check(check_id, item, evidence(True))[0] == "FAIL"
        assert evaluate_check(check_id, item, {})[0] == "UNKNOWN"
        return
    scenarios = FIXTURES[check_id]
    assert "unknown" in scenarios
    for expected, fixture in scenarios.items():
        assert evaluate_check(check_id, fixture["item"], fixture["index"])[0] == expected.upper(), (check_id, expected)


def test_gcp_unreachable_verdicts_are_not_fabricated():
    # The signed API-key predicate cannot PASS merely because a target service
    # is enabled; its use remains unobserved. Access Transparency counts can
    # provide partial positive evidence but no negative proof of access.
    assert set(FIXTURES["gcp.apikeys.active_service_restrictions"]) == {"fail", "unknown"}
    assert set(FIXTURES["gcp.logging.access_transparency_entries"]) == {"pass", "unknown"}


@pytest.mark.parametrize("check_id", IDS)
def test_gcp_central_case_fragment(check_id):
    case = CENTRAL[check_id]
    for label, expected in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN"),
                            ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        if label in case:
            index = case.get(label + "_index", case["index"])
            assert evaluate_check(check_id, case[label], index)[0] == expected, (check_id, label)
    assert evaluate_check(check_id, {"collection_status": "denied"}, case["index"])[0] == "UNKNOWN"


def test_gcp_workbench_inventory_validation_is_once_per_memo_index():
    class Counted(list):
        iterations = 0

        def __iter__(self):
            self.iterations += 1
            return super().__iter__()

    case = FIXTURES["gcp_workbench_approved_image"]["pass"]
    index = MemoIndex(case["index"])
    index["workbench_instance"] = Counted(index["workbench_instance"])
    assert evaluate_check("gcp_workbench_approved_image", case["item"], index)[0] == "PASS"
    first = index["workbench_instance"].iterations
    assert first > 0
    assert evaluate_check("gcp_workbench_approved_image", case["item"], index)[0] == "PASS"
    assert index["workbench_instance"].iterations == first


@pytest.mark.parametrize("family,expected", [("approved", "PASS"), ("unapproved", "FAIL")])
def test_collector_workbench_v2_image_reaches_native_verdict(family, expected):
    from tests.test_peaso_collectors_gcp import snapshot, collection

    scope = "projects/p-one"
    name = scope + "/locations/us-central1-a/instances/book"
    policy = {"status": "collected", "scope": scope,
              "approved_workbench_images": ["vm:images/family/approved"]}
    collected, _ = snapshot(["workbench_instance"], lambda request: {
        "instances": [{"name": name, "gceSetup": {"vmImage": {"project": "images", "family": family}}}]},
        compliance_policy=policy)
    envelope = collection(collected, "workbench_instance")
    item = envelope["items"][0]
    index = {"context": {"provider": "gcp", "scope": scope, "metadata": collected["metadata"]},
             "collections": {"workbench_instance": [envelope]},
             "workbench_instance": [{"scope": scope, "type": "workbench_instance", "data": item}]}
    assert evaluate_check("gcp_workbench_approved_image", item, index)[0] == expected
