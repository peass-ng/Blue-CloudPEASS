"""Exact package admission successor; historical code and receipt stay canonical."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import types
from . import azure_function_package_integration_admission_20261020 as original

BINDINGS = ('consumer', 'runtime', 'owner', 'RECEIPT', 'RECEIPT_SHA256', 'CASES', '_GRANT', '_TOKEN', '_SHARED', '_EXPECTED', '_ADMITTED', '_UNION', '_ASSERTIONS', '_READER', '_self', 'native_case', '_bindings', '_EXECUTING')
consumer = original.consumer
runtime = original.runtime
owner = original.owner
RECEIPT = original.RECEIPT
RECEIPT_SHA256 = original.RECEIPT_SHA256
CASES = original.CASES
_GRANT = original._GRANT
_TOKEN = original._TOKEN
_SHARED = original._SHARED
_EXPECTED = original._EXPECTED
_ADMITTED = original._ADMITTED
_UNION = original._UNION
_ASSERTIONS = original._ASSERTIONS
_READER = original._READER
_self = original._self
native_case = original.native_case
_bindings = original._bindings
_EXECUTING = original._EXECUTING
_INSTALLED = original._INSTALLED


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    from . import native_admission_cpu_shared_successor_20261020 as shared
    shared.verify_package_successor(root)
    raw = (root / 'peaso/checks' / RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise RuntimeError('Azure package admission receipt changed')
    receipt = json.loads(raw)
    if (receipt['declaration'] != consumer.DECLARATION or runtime._Grant is not _GRANT
            or runtime._TOKEN is not _TOKEN or consumer.owner is not owner
            or runtime._SHARED is not _SHARED or owner._EXPECTED is not _EXPECTED
            or owner._Admitted is not _ADMITTED
            or runtime.predecessor._Union is not _UNION or owner._Assertions is not _ASSERTIONS
            or runtime.predecessor._NATIVE_COLLECT is not runtime.source.collect
            or runtime.predecessor.source is not runtime.source
            or runtime.exporter.source is not runtime.source
            or consumer.predecessor.portable is not runtime.predecessor.contract):
        raise RuntimeError('Azure package runtime binding changed')
    for actual, canonical in ((runtime.source, 'peaso.collectors.azure_function_package_source_20261020'),
            (runtime.predecessor, 'peaso.collectors.azure_function_package_runtime_20261020'),
            (runtime.exporter, 'peaso.collectors.azure_function_package_portable_20261020'),
            (consumer.predecessor, 'peaso.checks.azure_function_package_runtime_consumer_20261020'),
            (runtime.index_owner, 'peaso.azure_function_package_index_20261020'),
            (owner.contract, 'peaso.azure_function_package_portable_20261020'),
            (runtime.source.storage, 'peaso.collectors.azure_selected_storage_secret_indicators'),
            (runtime.source.settings, 'peaso.collectors.azure_app_settings_secret_indicators')):
        if actual is not importlib.import_module(canonical):
            raise RuntimeError('Azure package imported module changed')
    if importlib.import_module('peaso.collectors.azure')._Reader is not _READER:
        raise RuntimeError('Azure package native reader replaced')
    from . import azure_function_package_shared_successor_20261020 as shared
    shared.reviewed_delta(root)
    for name, row in receipt['sources'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root / 'peaso'):
            raise RuntimeError('Azure package source escaped package')
        data = path.read_bytes()
        if row['normalization'] == 'self':
            data = _self(data)
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise RuntimeError('Azure package source changed:' + name)
    proof = shared
    compiled = {}
    current = _bindings()
    if set(current) != set(_EXECUTING) or any(current[k] is not value for k, value in _EXECUTING.items()):
        raise RuntimeError('Azure package imported callable binding changed')
    for qualified, row in receipt['functions'].items():
        module_name, attribute = qualified.split(':')
        function = importlib.import_module(module_name)
        for part in attribute.split('.'):
            function = getattr(function, part)
        if function is not _EXECUTING.get(qualified):
            raise RuntimeError('Azure package callable replaced:' + qualified)
        proof._check_function(function, row, root, compiled)
    scanning = importlib.import_module('peaso.secret_scanning')
    storage = runtime.source.storage
    if (storage.scan_content is not scanning.scan_content
            or storage.merge_leaks is not scanning.merge_leaks
            or runtime.source._fingerprint is not scanning._fingerprint
            or runtime.predecessor._fingerprint is not scanning._fingerprint):
        raise RuntimeError('Azure package scanner binding changed')
    raw = (root / 'peaso/checks' / CASES).read_bytes()
    if hashlib.sha256(raw).hexdigest() != receipt['cases_sha256']:
        raise RuntimeError('Azure package native cases changed')
    cases = json.loads(raw)
    if len(cases) != 9:
        raise RuntimeError('Azure package native branch set changed')
    for case in cases:
        item, index = native_case(case)
        status, evidence = consumer.evaluate(item, index)
        if status != case['expected_status']:
            raise RuntimeError('Azure package native branch changed')
    return receipt, cases



def install():
    """Reuse sealed installation with only its admitted reviewed-input entrypoint."""
    global _INSTALLED
    from . import native_admission_cpu_shared_successor_20261020 as shared
    shared.verify_package_successor(Path(__file__).resolve().parents[2])
    if _INSTALLED is not original._INSTALLED:
        raise RuntimeError('Native CPU package installation state changed')
    namespace = dict(vars(original), reviewed_inputs=reviewed_inputs)
    clone = types.FunctionType(original.install.__code__, namespace, original.install.__name__,
                               original.install.__defaults__, original.install.__closure__)
    try:
        return clone()
    finally:
        original._INSTALLED = namespace['_INSTALLED']
        _INSTALLED = original._INSTALLED


_FUNCTIONS = {__name__ + ':' + name: fn for name, fn in tuple(globals().items())
              if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}
