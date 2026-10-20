"""Package-only, source-bound, transactional admission of the inline control."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import re
import types
from . import aws_codebuild_buildspec_runtime_consumer_20261020 as consumer
from peaso.collectors import aws_codebuild_buildspec_runtime_20261020 as runtime

RECEIPT = 'aws_codebuild_buildspec_runtime_admission_20261020.json'
CASES = 'aws_codebuild_buildspec_runtime_cases_20261020.json'
RECEIPT_SHA256 = '6b6c150dd87005a13a8832a747f06667e08771aa78951b9cdccc8d32af639c39'
_GRANT_CLASS, _TOKEN = runtime._Grant, runtime._TOKEN


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('CodeBuild admission self binding changed')
    return value


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
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
        data = path.read_bytes()
        if row['normalization'] == 'self':
            data = _self(data)
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('CodeBuild reviewed source changed:' + name)
    from . import k8s_selected_metadata_runtime_admission_20261020 as proof
    compiled = {}
    for qualified, row in receipt['functions'].items():
        module_name, attribute = qualified.split(':')
        owner = importlib.import_module(module_name)
        function = owner
        for part in attribute.split('.'):
            function = getattr(function, part)
        if qualified in _FUNCTIONS and function is not _FUNCTIONS[qualified]:
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
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases = reviewed_inputs()
    d = consumer.DECLARATION
    found = [c for c in CHECKS if c.id == runtime.CHECK]
    if runtime.CHECK in CHECK_ALIASES or runtime.CHECK in CHECK_ALIASES.values() or len(found) > 1:
        raise RuntimeError('CodeBuild registration collision')
    if found:
        if (inspect.unwrap(found[0].evaluate) is not consumer.evaluate or found[0].kind != runtime.KIND
                or found[0].dependencies != d['dependencies'] or not found[0].allow_incomplete_failure
                or store.get(runtime.CHECK) != cases[runtime.CHECK]):
            raise RuntimeError('CodeBuild registration replaced')
        return
    if runtime.CHECK in store:
        raise RuntimeError('CodeBuild native CASES collision')
    before = tuple(CHECKS)
    try:
        register(runtime.CHECK, 'aws', d['category'], runtime.KIND, d['title'], 'high',
            'security_configuration', d['remediation'], dependencies=d['dependencies'],
            allow_incomplete_failure=True)(consumer.evaluate)
        store[runtime.CHECK] = deepcopy(cases[runtime.CHECK])
    except Exception:
        CHECKS[:] = before
        store.pop(runtime.CHECK, None)
        raise


_FUNCTIONS = {__name__ + ':' + name: fn for name, fn in tuple(globals().items())
    if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
