"""Transactional successor admission of the exact existing Functions check."""
from copy import deepcopy
import inspect
import json

from . import gcp_function_secret_paired_review_20261020 as consumer
from . import gcp_function_secret_review_20261019 as predecessor
from peaso.gcp_function_secret_pair_source_20261020 import reviewed_inputs as source_inputs


def reviewed_inputs(root=None):
    from pathlib import Path
    receipt = source_inputs(root)
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    cases = json.loads((root / receipt['cases']).read_bytes())
    if set(cases) != {predecessor.CHECK_ID} or receipt['declaration'] != consumer.DECLARATION:
        raise RuntimeError('Functions paired native case identity changed')
    case = cases[predecessor.CHECK_ID]
    for branch in ('pass', 'fail', 'partial', 'asymmetric', 'unknown', 'missing', 'malformed'):
        status, evidence = consumer._evaluate(deepcopy(case[branch]),
            deepcopy(case.get(branch + '_index', case['index'])))
        expected = {'pass': 'PASS', 'fail': 'FAIL', 'partial': 'FAIL', 'asymmetric': 'FAIL'}.get(branch, 'UNKNOWN')
        if status != expected or branch in ('partial', 'asymmetric') and evidence.get('complete') is not False:
            raise RuntimeError('Functions paired native case changed: ' + branch)
    return receipt, cases


def _signature(check):
    return {'provider': check.provider, 'category': check.category, 'kind': check.kind,
        'title': check.title, 'severity': check.severity, 'control': check.control,
        'remediation': check.remediation, 'target': check.target,
        'dependencies': check.dependencies, 'allow_incomplete_failure': check.allow_incomplete_failure}


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES
    from .gcp_function_secret_paired_source_successor_20261020 import reviewed_delta
    from pathlib import Path
    receipt, cases = reviewed_inputs()
    root = Path(__file__).resolve().parents[2]
    archive = reviewed_delta(root, receipt)
    ident = predecessor.CHECK_ID
    found = [check for check in CHECKS if check.id == ident]
    if ident in CHECK_ALIASES or ident in CHECK_ALIASES.values() or len(found) != 1:
        raise RuntimeError('Functions paired registration collision')
    check = found[0]
    if _signature(check) != archive['legacy_registration']:
        raise RuntimeError('Functions paired registration metadata changed')
    if inspect.unwrap(check.evaluate) is consumer.evaluate:
        if CASES.get(ident) != cases[ident]:
            raise RuntimeError('Functions paired installed CASES changed')
        return
    if (inspect.unwrap(check.evaluate) is not predecessor.evaluate
            or CASES.get(ident) != archive['legacy_cases'][ident]):
        raise RuntimeError('Functions paired exact predecessor registration changed')
    before, old_case = tuple(CHECKS), deepcopy(CASES[ident])
    position = CHECKS.index(check)
    declaration = consumer.DECLARATION
    try:
        CHECKS.remove(check)
        register(ident, 'gcp', declaration['category'], declaration['kind'], declaration['title'],
            declaration['severity'], check.control, declaration['remediation'],
            dependencies=check.dependencies, allow_incomplete_failure=check.allow_incomplete_failure)(consumer.evaluate)
        replacement = CHECKS.pop()
        CHECKS.insert(position, replacement)
        CASES[ident] = deepcopy(cases[ident])
    except Exception:
        CHECKS[:] = before
        CASES[ident] = old_case
        raise
