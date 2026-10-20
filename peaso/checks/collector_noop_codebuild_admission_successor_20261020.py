"""Preserve CodeBuild admission across only the explicit AWS command delta."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
import types
from pathlib import Path
from . import aws_codebuild_buildspec_runtime_admission_20261020 as original
runtime, consumer = original.runtime, original.consumer
RECEIPT, RECEIPT_SHA256, CASES = original.RECEIPT, original.RECEIPT_SHA256, original.CASES
_GRANT_CLASS, _TOKEN = original._GRANT_CLASS, original._TOKEN
_self = original._self
HISTORICAL_REVIEWED_INPUTS = original._FUNCTIONS[original.__name__ + ':reviewed_inputs']
_HISTORICAL = HISTORICAL_REVIEWED_INPUTS

BINDINGS = ('runtime', 'consumer', 'RECEIPT', 'RECEIPT_SHA256', 'CASES', '_GRANT_CLASS', '_TOKEN', '_self')


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    from . import collector_noop_authorization_shared_successor_20261020 as shared
    shared.verify_authorization_successors(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('CodeBuild admission receipt changed')
    receipt = json.loads(raw)
    if (receipt['declaration'] != consumer.DECLARATION or consumer.runtime is not runtime
            or runtime._Grant is not _GRANT_CLASS or runtime._TOKEN is not _TOKEN):
        raise RuntimeError('CodeBuild admission metadata/binding changed')
    for name, row in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('CodeBuild package source escaped')
        data = shared.predecessor_producer_bytes(name, path.read_bytes(), root)
        if row['normalization'] == 'self':
            data = _self(data)
        if name == 'peaso/collectors/aws.py':
            from . import aws_workload_command_shared_successor_20261020 as successor
            delta = successor.reviewed_delta(root)['file_deltas'][name]
            text = data.decode()
            for addition in delta['exact_additions']:
                if text.count(addition) != 1:
                    raise RuntimeError('CodeBuild AWS command addition changed')
                text = text.replace(addition, '', 1)
            data = text.encode()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('CodeBuild reviewed source changed:' + name)
    proof = shared
    compiled = {}
    for qualified, row in receipt['functions'].items():
        module_name, attribute = qualified.split(':')
        owner = importlib.import_module(module_name)
        function = owner
        for part in attribute.split('.'):
            function = getattr(function, part)
        if qualified == original.__name__ + ':reviewed_inputs':
            if function not in (_HISTORICAL, reviewed_inputs):
                raise RuntimeError('CodeBuild reviewed successor replaced')
            function = _HISTORICAL
        if qualified in original._FUNCTIONS and function is not original._FUNCTIONS[qualified]:
            raise RuntimeError('CodeBuild executing function replaced')
        proof._check_function(function, row, root, compiled)
    scanning = importlib.import_module('peaso.secret_scanning')
    from .aws_s3_selected_source_admission_20261020 import schema
    if (schema(runtime.source) != receipt['producer_schema']
            or any(getattr(runtime, name) != value for name, value in receipt['runtime_constants'].items())
            or runtime.scan_content is not scanning.scan_content
            or runtime._fingerprint is not scanning._fingerprint
            or runtime.source._fingerprint is not scanning._fingerprint
            or runtime.source.scan_content is not scanning.scan_content
            or runtime.source.merge_leaks is not scanning.merge_leaks
            or runtime.source.response_size is not runtime.configuration.response_size
            or consumer.predecessor.merge_leaks is not scanning.merge_leaks
            or runtime.configuration is not importlib.import_module('peaso.collectors.aws_selected_configuration_secret_indicators')
            or runtime.source is not importlib.import_module('peaso.collectors.aws_codebuild_buildspec_source_20261020')
            or consumer.predecessor is not importlib.import_module('peaso.checks.aws_codebuild_buildspec_source_20261020')):
        raise RuntimeError('CodeBuild imported helper replaced')
    path = root / 'peaso/checks' / CASES
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != receipt['cases_sha256']:
        raise RuntimeError('CodeBuild native cases changed')
    cases = json.loads(raw)
    if set(cases) != {runtime.CHECK}:
        raise RuntimeError('CodeBuild native case identity changed')
    if receipt['native_cases_required']:
        case = cases[runtime.CHECK]
        for branch in ('pass', 'fail', 'unknown', 'malformed', 'partial'):
            status, evidence = consumer.evaluate(deepcopy(case[branch]), deepcopy(case[branch + '_index']))
            expected = {'pass': 'PASS', 'fail': 'FAIL', 'partial': 'FAIL'}.get(branch, 'UNKNOWN')
            if status != expected or branch == 'partial' and evidence.get('complete') is not False:
                raise RuntimeError('CodeBuild native branch changed')
    return receipt, cases



def install():
    if original.reviewed_inputs not in (_HISTORICAL, reviewed_inputs):
        raise RuntimeError('CodeBuild admission successor replaced')
    original.reviewed_inputs = reviewed_inputs
    return original.install()


_FUNCTIONS = {__name__ + ':' + name: fn for name, fn in tuple(globals().items())
              if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
