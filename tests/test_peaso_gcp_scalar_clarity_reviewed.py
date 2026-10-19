from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.catalog import _base_description_for, description_for
from peaso.checks.facts import FIELD_SPECS
from peaso.checks.fixtures import CASES
from peaso.checks.gcp_scalar_clarity_reviewed import ROWS, description, remediation
from peaso.remediation import template


@pytest.mark.parametrize("cid", ROWS)
def test_scalar_copy_matches_strict_native_setting_and_preserves_contract(cid):
    check = next(c for c in CHECKS if c.id == cid)
    base = _base_description_for(cid)
    original = deepcopy(base)
    actual = description_for(cid)
    assert base == original
    assert {k: v for k, v in actual.items() if k != "description"} == {
        k: v for k, v in base.items() if k != "description"
    }
    assert FIELD_SPECS[cid]["path"] in " ".join(actual["evaluated"])
    for case, status in (("pass", "PASS"), ("fail", "FAIL"),
                         ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        assert check.evaluate(CASES[cid][case], {})[0] == status
    guidance = template(cid)
    assert guidance and len(guidance["steps"]) == 1 and guidance["references"]
    if cid in {"gcp.gke.secrets_encryption", "gcp.reviewed.compute.maintenance_migrate",
               "gcp.reviewed.compute.confidential_computing", "gcp.reviewed.loadbalancer.backend_logging"}:
        assert guidance["cli"] == [] and not guidance.get("iac")


def test_stale_source_or_remediation_rejected():
    cid = next(iter(ROWS))
    with pytest.raises(ValueError):
        description(cid, {"description": "changed upstream"})
    with pytest.raises(ValueError):
        remediation(cid, {"steps": ["changed action"]})


def test_application_encryption_does_not_claim_plaintext_storage():
    text = description_for("gcp.gke.secrets_encryption")["description"]
    assert "separate from Google’s default storage encryption" in text
    assert "hardware and workload support are not evaluated" in description_for(
        "gcp.reviewed.compute.maintenance_migrate")["description"]
