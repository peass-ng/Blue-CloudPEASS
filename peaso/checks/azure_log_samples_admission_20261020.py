"""Atomic admission of exact two reviewed native log-sample consumers."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

RECEIPT_SHA256 = '64124b5c0ae4c82b6e9abd9bbae9832ddb43cb9cc3696abc0850f5d0c9f12c6a'
PROFILES = ('workspace', 'application')


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw = (root / 'peaso/checks/azure_log_samples_admission_20261020.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure log sample admission receipt changed')
    receipt = json.loads(raw)
    if (receipt.get('schema_version') != 1 or receipt.get('module') != 'azure_selected_log_sample_secret_review_20261020'
            or tuple(row['profile'] for row in receipt['checks']) != PROFILES):
        raise RuntimeError('Azure log sample admission identities changed')
    for name, digest in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Azure log sample reviewed source changed')
    fixture = receipt['fixture']; path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Azure log sample native fixture changed')
    cases = json.loads(path.read_text()); declarations = []
    if set(cases) != {row['id'] for row in receipt['checks']}:
        raise RuntimeError('Azure log sample native identities changed')
    module = importlib.import_module('.' + receipt['module'], __package__)
    if len(module.DECLARATIONS) != 2:
        raise RuntimeError('Azure log sample metadata changed')
    for row in receipt['checks']:
        profile = row['profile']; function = module.EVALUATORS[profile]
        metadata, = [d for d in module.DECLARATIONS if d['id'] == row['id']]
        function_name = row['evaluate'].rsplit(':', 1)[1]
        if (function is not getattr(module, function_name) or function is not inspect.unwrap(function)
                or function.__name__ != function_name or function.__module__ != module.__name__
                or any(metadata.get(key) != row.get(key) for key in metadata)
                or function.__globals__.get('_evaluate') is not module._evaluate
                or hashlib.sha256(inspect.getsource(function).encode()).hexdigest() != row['predicate_sha256']
                or hashlib.sha256(inspect.getsource(module._evaluate).encode()).hexdigest() != row['reachable_helper_sha256']):
            raise RuntimeError('Azure log sample evaluator identity changed')
        case = cases[row['id']]
        if not {'pass','pass_index','fail','fail_index','unknown','unknown_index','missing','malformed','index'} <= set(case):
            raise RuntimeError('Azure log sample native branches missing')
        for branch in ('pass', 'fail', 'unknown'):
            if function(case[branch], case[branch + '_index'])[0] != branch.upper():
                raise RuntimeError('Azure log sample native branch changed')
        for branch in ('missing', 'malformed'):
            if function(case[branch], case['index'])[0] != 'UNKNOWN':
                raise RuntimeError('Azure log sample malformed native branch changed')
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
            raise RuntimeError('Azure log sample registration collision')
        if ident in CASES and CASES[ident] != cases[ident]:
            raise RuntimeError('Azure log sample native fixture collision')
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
