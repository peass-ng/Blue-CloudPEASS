"""Current Functions runtime must use the same finite guard as its admission."""
from copy import deepcopy
import inspect

import pytest

from peaso import gcp_function_secret_page_source_20261020 as page_source
from peaso import gcp_private_source_successor_20261021 as current_source
from peaso.checks import CHECKS
from peaso.checks import gcp_function_secret_partial_page_20261020 as consumer
from peaso.checks.fixtures import CASES

CHECK_ID = 'gcp.review.function.literal_environment_secret_indicators'


def test_registered_runtime_uses_current_admission_validator():
    check, = [c for c in CHECKS if c.id == CHECK_ID]
    assert inspect.unwrap(check.evaluate) is consumer.evaluate
    assert page_source.reviewed_inputs is current_source.reviewed_inputs
    for branch, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        case = CASES[CHECK_ID]
        status, _ = check.evaluate(deepcopy(case[branch]),
            deepcopy(case.get(branch + '_index', case['index'])))
        assert status == expected


def test_replaced_page_validator_binding_is_rejected(monkeypatch):
    monkeypatch.setattr(page_source, 'reviewed_inputs', lambda root=None: None)
    with pytest.raises(RuntimeError, match='runtime source alias replaced'):
        current_source.reviewed_inputs()


def test_replaced_native_producer_callable_is_rejected(monkeypatch):
    from peaso.collectors import gcp_function_secret_pairs_20261020 as producer
    monkeypatch.setattr(producer, 'project_response', lambda *args, **kwargs: {})
    with pytest.raises((RuntimeError, ValueError)):
        current_source.reviewed_inputs()
