"""Atomic existing-ID successor for native partial-page positive preservation."""
from copy import deepcopy
import gzip
import inspect
import json
from pathlib import Path

from . import gcp_function_secret_partial_page_20261020 as consumer
from . import gcp_function_secret_paired_review_20261020 as paired
from . import gcp_function_secret_review_20261019 as original
from .gcp_function_secret_paired_admission_20261020 import _signature
from peaso.gcp_function_secret_page_source_20261020 import reviewed_inputs as source_inputs


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    receipt = source_inputs(root)
    if receipt['declaration'] != consumer.DECLARATION:
        raise RuntimeError('Functions partial-page declaration changed')
    cases = json.loads((root / receipt['cases']).read_bytes())
    if set(cases) != {original.CHECK_ID}:
        raise RuntimeError('Functions partial-page case identity changed')
    case = cases[original.CHECK_ID]
    for branch in ('pass', 'fail', 'partial', 'asymmetric', 'unknown', 'missing', 'malformed',
                   'partial_inventory', 'partial_inventory_clean'):
        status, evidence = consumer._evaluate(deepcopy(case[branch]),
            deepcopy(case.get(branch + '_index', case['index'])))
        expected = {'pass': 'PASS', 'fail': 'FAIL', 'partial': 'FAIL', 'asymmetric': 'FAIL',
                    'partial_inventory': 'FAIL'}.get(branch, 'UNKNOWN')
        if status != expected:
            raise RuntimeError('Functions partial-page native branch changed: ' + branch)
        if branch == 'partial_inventory' and (evidence.get('complete') is not False or evidence.get('incomplete') is not True):
            raise RuntimeError('Functions partial-page coverage claim changed')
    return receipt, cases


def install():
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES
    receipt, cases = reviewed_inputs()
    root = Path(__file__).resolve().parents[2]
    old = json.loads((root / 'peaso/checks/gcp_function_secret_paired_admission_20261020.json').read_bytes())
    archive = json.loads(gzip.decompress((root / old['predecessors']['path']).read_bytes()))
    paired_cases = json.loads((root / old['cases']).read_bytes())
    ident = original.CHECK_ID
    found = [check for check in CHECKS if check.id == ident]
    if ident in CHECK_ALIASES or ident in CHECK_ALIASES.values() or len(found) != 1:
        raise RuntimeError('Functions partial-page registration collision')
    check = found[0]
    if _signature(check) != archive['legacy_registration']:
        raise RuntimeError('Functions partial-page metadata changed')
    function = inspect.unwrap(check.evaluate)
    if function is consumer.evaluate:
        if CASES.get(ident) != cases[ident]:
            raise RuntimeError('Functions partial-page installed CASES changed')
        return
    expected = (archive['legacy_cases'][ident] if function is original.evaluate
                else paired_cases[ident] if function is paired.evaluate else None)
    if expected is None or CASES.get(ident) != expected:
        raise RuntimeError('Functions partial-page predecessor changed')
    before, old_case, position = tuple(CHECKS), deepcopy(CASES[ident]), CHECKS.index(check)
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
