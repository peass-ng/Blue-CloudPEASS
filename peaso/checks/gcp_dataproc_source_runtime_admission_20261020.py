"""Atomic admission of two immutable reviewed Dataproc referenced-source controls."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

RECEIPT_SHA256 = '7c8989576f2068d6868b6e51bba8e8d265aaa33b70d63fb0e84b6ab8e3dd8e0c'
CHECK_IDS = ('gcp.review.dataproc.selected_job_referenced_source_secret_indicators', 'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators')


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks/gcp_dataproc_source_runtime_admission_20261020.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Dataproc source admission receipt changed')
    receipt = json.loads(raw)
    from .gcp_dataproc_referenced_source_proposal_20261020 import validate_proposal
    validate_proposal()
    if (receipt.get('schema_version') != 1 or receipt.get('module') != 'gcp_dataproc_referenced_source_secret_review_20261020'
            or tuple(row['id'] for row in receipt['checks']) != CHECK_IDS):
        raise RuntimeError('Dataproc source admission identities changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Dataproc source reviewed source changed')
    fixture = receipt['fixture']; path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Dataproc source native fixture changed')
    cases = json.loads(path.read_text()); declarations = []
    if set(cases) != {row['id'] for row in receipt['checks']}:
        raise RuntimeError('Dataproc source native identities changed')
    module = importlib.import_module('.' + receipt['module'], __package__)
    if tuple(row['id'] for row in module.DECLARATIONS) != CHECK_IDS:
        raise RuntimeError('Dataproc source metadata changed')
    for row in receipt['checks']:
        function_name = row['evaluate'].rsplit(':', 1)[1]
        function = getattr(module, function_name)
        metadata, = [d for d in module.DECLARATIONS if d['id'] == row['id']]
        if (function is not getattr(module, function_name) or function is not inspect.unwrap(function)
                or function.__name__ != function_name or function.__module__ != module.__name__
                or any(metadata.get(key) != row.get(key) for key in metadata)
                or function.__globals__.get('_evaluate') is not module._evaluate
                or hashlib.sha256(inspect.getsource(function).encode()).hexdigest() != row['predicate_sha256']
                or hashlib.sha256(inspect.getsource(module._evaluate).encode()).hexdigest() != row['reachable_helper_sha256']):
            raise RuntimeError('Dataproc source evaluator identity changed')
        case = cases[row['id']]
        if not {'pass','pass_index','fail','fail_index','unknown','unknown_index','missing','malformed','index'} <= set(case):
            raise RuntimeError('Dataproc source native branches missing')
        for branch in ('pass', 'fail', 'unknown'):
            if function(case[branch], case[branch + '_index'])[0] != branch.upper():
                raise RuntimeError('Dataproc source native branch changed')
        for branch in ('missing', 'malformed'):
            if function(case[branch], case['index'])[0] != 'UNKNOWN':
                raise RuntimeError('Dataproc source malformed native branch changed')
        declarations.append((metadata, function))
    return receipt, cases, declarations


def _signature(check):
    return (check.provider, check.category, check.kind, check.title, check.severity, check.control,
        check.remediation, tuple(check.dependencies), check.allow_incomplete_failure)


def install():
    from . import CHECKS, register
    from .fixtures import CASES
    receipt, cases, declarations = reviewed_inputs()
    for metadata, function in declarations:
        ident = metadata['id']; matches = [c for c in CHECKS if c.id == ident]
        expected = ('gcp', metadata['category'], metadata['kind'], metadata['title'], metadata['severity'],
            'security_configuration', metadata['remediation'], tuple(metadata['dependencies']), True)
        if len(matches) > 1 or matches and (inspect.unwrap(matches[0].evaluate) is not function or _signature(matches[0]) != expected):
            raise RuntimeError('Dataproc source registration collision')
        if ident in CASES and CASES[ident] != cases[ident]:
            raise RuntimeError('Dataproc source native fixture collision')
    before = tuple(CHECKS); previous = {ident: deepcopy(CASES[ident]) for ident in cases if ident in CASES}
    try:
        for metadata, function in declarations:
            ident = metadata['id']
            if not any(c.id == ident for c in CHECKS):
                register(ident, 'gcp', metadata['category'], metadata['kind'], metadata['title'], metadata['severity'],
                    'security_configuration', metadata['remediation'], dependencies=metadata['dependencies'],
                    allow_incomplete_failure=True)(function)
            CASES[ident] = deepcopy(cases[ident])
    except Exception:
        CHECKS[:] = before
        for ident in cases:
            if ident in previous: CASES[ident] = previous[ident]
            else: CASES.pop(ident, None)
        raise
