"""Source-bound registration of the existing bounded ECS/Batch native reader."""
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import re
import types
from . import aws_workload_command_runtime_consumer_20261020 as consumer
from peaso.collectors import aws_workload_command_runtime_20261020 as runtime
from peaso import secret_scanning as scanning

RECEIPT = 'aws_workload_command_runtime_admission_20261020.json'
RECEIPT_SHA256 = '9ee649b70eff37a76b7b6ea8f48627530a0d493ec792d63b95fa05ac03868449'
_GRANT, _TOKEN = runtime._Grant, runtime._TOKEN


def _self(raw):
    value, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('AWS command admission self binding changed')
    return value


def reviewed_inputs():
    root = Path(__file__).resolve().parents[2]
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('AWS command admission receipt changed')
    receipt = json.loads(raw)
    for name, row in receipt['sources'].items():
        path = (root / name).resolve()
        data = path.read_bytes()
        if row['normalization'] == 'self':
            data = _self(data)
        if not path.is_relative_to(root / 'peaso') or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('AWS command admission source changed: ' + name)
    from . import k8s_selected_metadata_runtime_admission_20261020 as proof
    compiled = {}
    for qualified, row in receipt['functions'].items():
        module_name, name = qualified.split(':')
        function = importlib.import_module(module_name)
        for part in name.split('.'):
            function = getattr(function, part)
        if qualified == runtime.source.__name__ + ':reviewed_sources':
            if function not in (runtime._HISTORICAL_REVIEWED_SOURCES, runtime.reviewed_sources):
                raise RuntimeError('AWS command source successor replaced')
            function = runtime._HISTORICAL_REVIEWED_SOURCES
        if qualified in _FUNCTIONS and function is not _FUNCTIONS[qualified]:
            raise RuntimeError('AWS command admission callable replaced')
        try:
            proof._check_function(function, row, root, compiled)
        except RuntimeError as exc:
            raise RuntimeError('AWS command executing callable changed: ' + qualified) from exc
    actual_schema = {name: getattr(runtime.source, name) for name in receipt['producer_schema'] if name != 'SCOPE'}
    actual_schema['SCOPE'] = {'pattern': runtime.source.SCOPE.pattern, 'flags': runtime.source.SCOPE.flags}
    if actual_schema != receipt['producer_schema']:
        raise RuntimeError('AWS command bounded native schema changed')
    if (receipt['declaration'] != consumer.DECLARATION or runtime._Grant is not _GRANT
            or runtime._TOKEN is not _TOKEN
            or runtime.source is not importlib.import_module('peaso.collectors.aws_workload_command_source_20261020')
            or consumer.predecessor is not importlib.import_module('peaso.checks.aws_workload_command_source_20261020')
            or runtime.source._fingerprint is not scanning._fingerprint
            or runtime.source.scan_content is not scanning.scan_content
            or runtime.source.merge_leaks is not scanning.merge_leaks
            or consumer.predecessor.merge_leaks is not scanning.merge_leaks):
        raise RuntimeError('AWS command admission imported binding changed')
    return receipt


def install():
    from . import CHECKS, CHECK_ALIASES, register
    reviewed_inputs()
    declaration = consumer.DECLARATION
    if runtime.CHECK in CHECK_ALIASES or runtime.CHECK in CHECK_ALIASES.values():
        raise RuntimeError('AWS command registration alias collision')
    found = [check for check in CHECKS if check.id == runtime.CHECK]
    if found:
        if (len(found) != 1 or inspect.unwrap(found[0].evaluate) is not consumer.evaluate
                or found[0].kind != runtime.KIND or found[0].dependencies != [runtime.KIND]
                or not found[0].allow_incomplete_failure):
            raise RuntimeError('AWS command registration replaced')
        return
    register(runtime.CHECK, 'aws', declaration['category'], runtime.KIND, declaration['title'], 'high',
        'security_configuration', declaration['remediation'], dependencies=[runtime.KIND],
        allow_incomplete_failure=True)(consumer.evaluate)
    runtime.install_source_successor()


_FUNCTIONS = {__name__ + ':' + name: fn for name, fn in tuple(globals().items())
    if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
