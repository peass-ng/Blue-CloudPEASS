"""Normal registry cases remain reproducible through the installed wrappers."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.provider_content_native_cases_20261021 import IDS

@pytest.mark.parametrize('check_id', sorted(IDS))
@pytest.mark.parametrize('branch,expected', [('pass','PASS'),('fail','FAIL'),('unknown','UNKNOWN'),('missing','UNKNOWN'),('malformed','UNKNOWN')])
def test_normal_registered_native_cases(check_id, branch, expected):
    check = next(check for check in CHECKS if check.id == check_id)
    case = CASES[check_id]
    item = deepcopy(case[branch])
    index = deepcopy(case.get(branch+'_index', case['index']))
    before = deepcopy((item, index))
    status, _ = check.evaluate(item, index)
    assert status == expected
    assert (item, index) == before

@pytest.mark.parametrize('check_id', sorted(IDS))
def test_hosted_observation_uses_actual_native_result(check_id):
    from peaso.server.evidence_static import evidence_summary, verify_closure
    verify_closure()
    check = next(check for check in CHECKS if check.id == check_id)
    case = CASES[check_id]
    status, evidence = check.evaluate(deepcopy(case['fail']), deepcopy(case['fail_index']))
    text = evidence_summary({'provider':check.provider,'check_id':check_id,'status':status,'evidence':evidence})
    assert text and not text.startswith('Observed evidence:')
    assert 'sha256:' not in text
