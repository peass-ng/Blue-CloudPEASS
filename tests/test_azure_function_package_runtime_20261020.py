"""Historical local runtime and its current admitted native successor."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.shared_admission_epoch_compatibility_20261020 import azure_predecessor_tree
from tests import test_azure_function_package_source_20261020 as native


def test_all_original_local_runtime_assertions_in_exact_predecessor(tmp_path):
    predecessor = azure_predecessor_tree(tmp_path / 'azure-local-predecessor')
    bootstrap = '''
import json, sys
from tests.shared_admission_epoch_compatibility_20261020 import historical_ast_format
with historical_ast_format() as observations:
    import pytest
    code = pytest.main(['-q', 'tests/test_azure_function_package_runtime_20261020.py', '--tb=short'])
    print('historical_ast_format_evidence=' + json.dumps(observations, sort_keys=True))
sys.exit(code)
'''
    result = subprocess.run([sys.executable, '-c', bootstrap],
        cwd=predecessor, text=True, capture_output=True, timeout=240)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'passed' in result.stdout and 'failed' not in result.stdout
    print('retained local Azure runtime: ' + result.stdout.strip())


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from native.offline.__wrapped__(monkeypatch)


@pytest.mark.parametrize('hit,partial,status', [(False, False, 'PASS'), (True, False, 'FAIL'),
    (False, True, 'UNKNOWN'), (True, True, 'FAIL')])
def test_current_admitted_native_both_scanners_same_evidence(monkeypatch, hit, partial, status):
    from tests import test_azure_function_package_integrated_20261020 as current
    current.test_actual_engine_native_and_both_detectors(monkeypatch, hit, partial, status)


@pytest.mark.parametrize('operation', native.source.OPERATIONS)
def test_current_admitted_native_denied_is_unknown(monkeypatch, operation):
    from tests import test_azure_function_package_integrated_20261020 as current
    current.test_actual_engine_denied_native_is_unknown(monkeypatch, operation)


def test_current_admitted_saved_positive_negative_and_unknown():
    from peaso.checks import azure_function_package_integration_admission_20261020 as admission
    from peaso.checks import azure_function_package_integrated_consumer_20261020 as consumer
    from peaso.checks import CHECKS
    receipt, cases = admission.reviewed_inputs()
    registered, = [check for check in CHECKS if check.id == consumer.DECLARATION['id']]
    statuses = set()
    for case in cases:
        item, index = admission.native_case(case)
        status, evidence = registered.evaluate(item, index)
        assert status == case['expected_status']
        statuses.add(status)
    assert {'PASS', 'FAIL', 'UNKNOWN'} <= statuses
