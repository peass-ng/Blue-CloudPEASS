"""Packaged native ACR and standalone Artifact Registry reproduction cases."""
from copy import deepcopy

import pytest


IDS = (
    "azure.review.acr.selected_image_high_critical_vulnerabilities",
    "gcp.review.artifact_image.selected_image_vulnerabilities",
)


@pytest.mark.parametrize("check_id", IDS)
def test_registered_native_cases_have_real_evaluator_outcomes(check_id):
    from peaso.checks import CHECKS
    from peaso.checks.provider_content_native_cases_20261021 import native_case

    case = native_case(check_id)
    check, = (entry for entry in CHECKS if entry.id == check_id)
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"),
                           ("unknown", "UNKNOWN"), ("missing", "UNKNOWN")):
        item = deepcopy(case[name])
        index = deepcopy(case[name + "_index"])
        original_item, original_index = deepcopy(item), deepcopy(index)
        result, evidence = check.evaluate(item, index)
        assert result == expected, (check_id, name, evidence)
        assert item == original_item and index == original_index
        assert isinstance(evidence, dict)


def test_native_case_loader_is_closed_and_returns_independent_snapshots():
    from peaso.checks.provider_content_native_cases_20261021 import native_case

    with pytest.raises(ValueError):
        native_case("other.provider.image")
    first = native_case(IDS[0])
    first["pass"].clear()
    assert native_case(IDS[0])["pass"]
