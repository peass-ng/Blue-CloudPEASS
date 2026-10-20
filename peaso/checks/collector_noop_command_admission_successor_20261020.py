"""Exact command admission owner for absent-selector no-op authorization."""
import hashlib, importlib, inspect, json
from pathlib import Path
import types
from . import aws_workload_command_runtime_admission_20261020 as original
BINDINGS = ('runtime', 'consumer', 'scanning', 'RECEIPT', 'RECEIPT_SHA256', '_GRANT', '_TOKEN', '_self')
runtime = original.runtime
consumer = original.consumer
scanning = original.scanning
RECEIPT = original.RECEIPT
RECEIPT_SHA256 = original.RECEIPT_SHA256
_GRANT = original._GRANT
_TOKEN = original._TOKEN
_self = original._self
HISTORICAL_REVIEWED_INPUTS = original._FUNCTIONS[original.__name__ + ':reviewed_inputs']


def reviewed_inputs():
    root = Path(__file__).resolve().parents[2]
    from . import collector_noop_authorization_shared_successor_20261020 as shared
    shared.verify_authorization_successors(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('AWS command admission receipt changed')
    receipt = json.loads(raw)
    for name, row in receipt['sources'].items():
        path = (root / name).resolve()
        data = shared.predecessor_producer_bytes(name, path.read_bytes(), root)
        if row['normalization'] == 'self':
            data = _self(data)
        if not path.is_relative_to(root / 'peaso') or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('AWS command admission source changed: ' + name)
    proof = shared
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
        if qualified == original.__name__ + ':reviewed_inputs':
            if function not in (HISTORICAL_REVIEWED_INPUTS, reviewed_inputs):
                raise RuntimeError('No-op command canonical entrypoint changed')
            function = HISTORICAL_REVIEWED_INPUTS
        if qualified in original._FUNCTIONS and function is not original._FUNCTIONS[qualified]:
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
    from . import collector_noop_authorization_shared_successor_20261020 as shared
    shared.verify_authorization_successors(Path(__file__).resolve().parents[2])
    previous = original.reviewed_inputs
    original.reviewed_inputs = reviewed_inputs
    namespace = dict(vars(original), reviewed_inputs=reviewed_inputs)
    clone = types.FunctionType(original.install.__code__, namespace, original.install.__name__,
                               original.install.__defaults__, original.install.__closure__)
    try:
        return clone()
    except Exception:
        original.reviewed_inputs = previous
        raise


_FUNCTIONS = {__name__ + ':' + name: fn for name, fn in tuple(globals().items())
              if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
