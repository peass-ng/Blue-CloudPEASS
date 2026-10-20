"""Atomic two-control admission of reviewed native ML environment/code source consumers."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

RECEIPT_SHA256 = '3063d0b70cc51cf84fa5f262dc640622f369943cab0e9ed1ff88bd357bb5bcc3'
CHECK_IDS = (
    'azure.review.machine_learning.selected_environment_conda_secret_indicators',
    'azure.review.machine_learning.selected_code_file_secret_indicators',
)


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks/azure_ml_asset_secrets_admission_20261020.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure ML assets admission receipt changed')
    receipt = json.loads(raw)
    if (receipt.get('schema_version') != 1 or receipt.get('module') != 'azure_ml_selected_asset_secret_review_20261020'
            or tuple(row['id'] for row in receipt['checks']) != CHECK_IDS):
        raise RuntimeError('Azure ML assets admission identities changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Azure ML assets reviewed source changed')
    fixture = receipt['fixture']; path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Azure ML assets native fixture changed')
    cases = json.loads(path.read_text()); declarations = []
    if set(cases) != {row['id'] for row in receipt['checks']}:
        raise RuntimeError('Azure ML assets native identities changed')
    module = importlib.import_module('.' + receipt['module'], __package__)
    if tuple(row['id'] for row in module.DECLARATIONS) != CHECK_IDS:
        raise RuntimeError('Azure ML assets metadata changed')
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
            raise RuntimeError('Azure ML assets evaluator identity changed')
        case = cases[row['id']]
        if not {'pass','pass_index','fail','fail_index','unknown','unknown_index','missing','malformed','index'} <= set(case):
            raise RuntimeError('Azure ML assets native branches missing')
        for branch in ('pass', 'fail', 'unknown'):
            if function(case[branch], case[branch + '_index'])[0] != branch.upper():
                raise RuntimeError('Azure ML assets native branch changed')
        for branch in ('missing', 'malformed'):
            if function(case[branch], case['index'])[0] != 'UNKNOWN':
                raise RuntimeError('Azure ML assets malformed native branch changed')
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
        expected = ('azure', metadata['category'], metadata['kind'], metadata['title'], metadata['severity'],
            'security_configuration', metadata['remediation'], tuple(metadata['dependencies']), True)
        if len(matches) > 1 or matches and (inspect.unwrap(matches[0].evaluate) is not function or _signature(matches[0]) != expected):
            raise RuntimeError('Azure ML assets registration collision')
        if ident in CASES and CASES[ident] != cases[ident]:
            raise RuntimeError('Azure ML assets native fixture collision')
    before = tuple(CHECKS); previous = {ident: deepcopy(CASES[ident]) for ident in cases if ident in CASES}
    try:
        for metadata, function in declarations:
            ident = metadata['id']
            if not any(c.id == ident for c in CHECKS):
                register(ident, 'azure', metadata['category'], metadata['kind'], metadata['title'], metadata['severity'],
                    'security_configuration', metadata['remediation'], dependencies=metadata['dependencies'],
                    allow_incomplete_failure=True)(function)
            CASES[ident] = deepcopy(cases[ident])
    except Exception:
        CHECKS[:] = before
        for ident in cases:
            if ident in previous: CASES[ident] = previous[ident]
            else: CASES.pop(ident, None)
        raise
