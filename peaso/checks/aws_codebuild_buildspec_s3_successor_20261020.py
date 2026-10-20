"""Retain the exact S3 guard and fixture, admitting only new AWS collector branches."""
import hashlib
import importlib
import inspect
import json
from pathlib import Path
from types import FunctionType
from . import aws_s3_selected_source_admission_20261020 as original
from . import aws_codebuild_buildspec_shared_successor_20261020 as successor


def reviewed_inputs():
    root = Path(__file__).resolve().parents[2]
    receipt = json.loads((root / 'peaso/checks' / original.RECEIPT).read_bytes())
    successor.reviewed_delta(root)
    for name, digest in receipt['source_hashes'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('Selected S3 unchanged source changed')
    for expected in receipt['callables']:
        function = importlib.import_module(expected['module'])
        for name in expected['qualname'].split('.'):
            function = getattr(function, name)
        if expected['module'] == 'peaso.collectors.aws' and expected['qualname'] == 'collect':
            successor.check_aws(function, expected)
        elif original.proof(function) != expected:
            raise RuntimeError('Selected S3 unchanged callable changed')
    from peaso.collectors import aws_s3_selected_source_secret_indicators as producer
    if original.schema(producer) != receipt['producer_schema']:
        raise RuntimeError('Selected S3 producer schema changed')
    for binding in receipt['bindings']:
        left = importlib.import_module(binding['module'])
        right = importlib.import_module(binding['origin_module'])
        if getattr(left, binding['name']) is not getattr(right, binding['origin_name']):
            raise RuntimeError('Selected S3 unchanged imported binding changed')
    fixture = receipt['fixture']
    path = (root / fixture['path']).resolve()
    if not path.is_relative_to(root / 'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest() != fixture['sha256']:
        raise RuntimeError('Selected S3 packaged native fixture changed')
    cases = json.loads(path.read_bytes())
    from .aws_s3_selected_source_secret_review_20261020 import CHECK, evaluate
    if set(cases) != {CHECK}:
        raise RuntimeError('Selected S3 native identities changed')
    for branch in ('pass', 'fail', 'unknown'):
        if evaluate(cases[CHECK][branch], cases[CHECK][branch + '_index'])[0] != branch.upper():
            raise RuntimeError('Selected S3 native branch changed')
    return cases


def install():
    # Preserve the original install function object, bytecode and module globals.
    namespace = dict(vars(original), reviewed_inputs=reviewed_inputs)
    clone = FunctionType(original.install.__code__, namespace, original.install.__name__,
                         original.install.__defaults__, original.install.__closure__)
    return clone()


_FUNCTIONS = {'reviewed_inputs': reviewed_inputs, 'install': install}
