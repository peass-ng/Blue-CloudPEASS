"""Registered provider cases retain their native results and hosted evidence."""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.provider_content_native_cases_20261021 import IDS, native_case


@pytest.mark.parametrize("check_id", sorted(IDS))
@pytest.mark.parametrize("branch,expected", (("pass", "PASS"), ("fail", "FAIL"),
                                            ("unknown", "UNKNOWN"), ("missing", "UNKNOWN"),
                                            ("malformed", "UNKNOWN")))
def test_normal_registered_native_cases(check_id, branch, expected):
    check, = (entry for entry in CHECKS if entry.id == check_id)
    case = native_case(check_id)
    registered = CASES[check_id]
    assert registered[branch] == case[branch]
    item = deepcopy(registered[branch])
    index = deepcopy(registered.get(branch + "_index", registered["index"]))
    before = deepcopy((item, index))
    status, evidence = check.evaluate(item, index)
    assert status == expected, (check_id, branch, evidence)
    assert isinstance(evidence, dict)
    assert (item, index) == before


@pytest.mark.parametrize("check_id", sorted(IDS))
def test_hosted_observation_uses_actual_native_result(check_id):
    from peaso.server.evidence_static import evidence_summary, verify_closure

    verify_closure()
    check, = (entry for entry in CHECKS if entry.id == check_id)
    case = CASES[check_id]
    status, evidence = check.evaluate(deepcopy(case["fail"]), deepcopy(case["fail_index"]))
    text = evidence_summary({"provider": check.provider, "check_id": check_id,
                             "status": status, "evidence": evidence})
    assert text and not text.startswith("Observed evidence:")
    assert "sha256:" not in text


def test_native_case_loader_is_closed_and_returns_independent_snapshots():
    first = native_case("azure.review.acr.selected_image_high_critical_vulnerabilities")
    first["pass"].clear()
    assert native_case("azure.review.acr.selected_image_high_critical_vulnerabilities")["pass"]
    with pytest.raises(ValueError, match="unrecognized provider native case"):
        native_case("other.provider.image")
