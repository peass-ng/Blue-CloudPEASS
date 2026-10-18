"""Invalid extreme quantities cannot crash the original admitted Pod check."""
import importlib.util
from pathlib import Path
import pytest
from peaso.checks import evaluate_check
from peaso.checks.compliance_new_sw25_facts import LIMITS_ID
from tests.compliance_draft_isolation import staged_registry

def fixture():
    path = Path(__file__).with_name('test_peaso_compliance_new_sw25.py')
    spec = importlib.util.spec_from_file_location('_quantity_fixture', path)
    module = importlib.util.module_from_spec(spec)
    with staged_registry(('compliance_new_sw25',)):
        spec.loader.exec_module(module)
    return module

@pytest.mark.parametrize('location', ['container', 'policy'])
def test_extreme_quantity_returns_unknown(location):
    module = fixture()
    index = module.fixture(LIMITS_ID)
    if location == 'container':
        module.data(index, 'pod')['spec']['containers'][0]['resources']['limits']['cpu'] = '1e1000000'
    else:
        index['context']['metadata']['sw25_policy'][LIMITS_ID]['maxCpu'] = '1e1000000'
    assert evaluate_check(LIMITS_ID, {'scope': module.SCOPE}, index)[0] == 'UNKNOWN'

@pytest.mark.parametrize('quantity,expected', [('500m','PASS'), ('2','FAIL')])
def test_normal_cpu_quantity_keeps_original_polarity(quantity, expected):
    module = fixture()
    index = module.fixture(LIMITS_ID)
    module.data(index, 'pod')['spec']['containers'][0]['resources']['limits']['cpu'] = quantity
    assert evaluate_check(LIMITS_ID, {'scope': module.SCOPE}, index)[0] == expected

def test_oversized_exponent_is_unknown():
    module = fixture()
    index = module.fixture(LIMITS_ID)
    index['context']['metadata']['sw25_policy'][LIMITS_ID]['maxCpu'] = '1e' + '9' * 5000
    assert evaluate_check(LIMITS_ID, {'scope': module.SCOPE}, index)[0] == 'UNKNOWN'
