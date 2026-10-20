"""Transactional package-only admission; unchanged native sources stay bound."""
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import re
import types
from . import azure_function_package_integrated_consumer_20261020 as consumer
from peaso.collectors import azure_function_package_integration_20261020 as runtime
from peaso import azure_function_package_index_20261020 as owner

RECEIPT = 'azure_function_package_integration_admission_20261020.json'
RECEIPT_SHA256 = '4875a73474106124b0347f9e676b2faf801c2cb0585e514a72f46daf6c4f0612'
CASES = 'azure_function_package_integration_cases_20261020.json'
_GRANT, _TOKEN = runtime._Grant, runtime._TOKEN
_SHARED, _EXPECTED, _ADMITTED = runtime._SHARED, owner._EXPECTED, owner._Admitted
_UNION, _ASSERTIONS = runtime.predecessor._Union, owner._Assertions
_READER = importlib.import_module('peaso.collectors.azure')._Reader
_INSTALLED = None


def _self(raw):
    result, count = re.subn(rb"(?m)^RECEIPT_SHA256 = '[0-9a-f]{64}'$", b"RECEIPT_SHA256 = '" + b'0' * 64 + b"'", raw)
    if count != 1:
        raise RuntimeError('Azure package admission self changed')
    return result


def native_case(case):
    snapshot, expected = deepcopy(case['snapshot']), deepcopy(case['expected_index_context'])
    package = deepcopy(snapshot)
    snapshot['metadata'][owner.EXPORT] = {k: package[k] for k in ('created_at', 'snapshot_id')}
    scope = expected['scopes'][0]
    index = {'context': {'provider': 'azure', 'scope': scope, 'metadata': snapshot['metadata']},
             'collections': {runtime.KIND: snapshot['collections']}}
    with owner.owner_admission(expected):
        owner.attach(index, snapshot, scope)
    return snapshot['collections'][0]['items'][0], index


def reviewed_inputs(root=None):
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
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
    proof = shared.original
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
    global _INSTALLED
    from . import CHECKS, CHECK_ALIASES, register
    from .fixtures import CASES as store
    receipt, cases = reviewed_inputs()
    d = consumer.DECLARATION
    found = [c for c in CHECKS if c.id == runtime.CHECK]
    if runtime.CHECK in CHECK_ALIASES or runtime.CHECK in CHECK_ALIASES.values() or len(found) > 1:
        raise RuntimeError('Azure package registration collision')
    # Native witnesses are admitted by this owner boundary, never by context
    # recovered from a user-supplied snapshot or index.
    selected = {c['name']: native_case(c) for c in cases}
    fixtures = {}
    for branch, name in (('pass', 'clean'), ('fail', 'positive'), ('unknown', 'denied')):
        fixtures[branch], fixtures[branch + '_index'] = selected[name]
    fixtures.update(missing={}, malformed={}, index={})
    if found:
        check = found[0]
        fields = ('id', 'provider', 'category', 'kind', 'title', 'severity', 'control', 'remediation', 'allow_incomplete_failure')
        if (inspect.unwrap(check.evaluate) is not consumer.evaluate or check.evaluate is not _INSTALLED
                or any(getattr(check, key) != d[key] for key in fields)
                or check.target != 'resource' or check.dependencies != d['dependencies']
                or runtime.CHECK not in store):
            raise RuntimeError('Azure package registration replaced')
        for branch in ('pass', 'fail', 'unknown'):
            if found[0].evaluate(store[runtime.CHECK][branch], store[runtime.CHECK][branch + '_index'])[0] != branch.upper():
                raise RuntimeError('Azure package CASES replaced')
        return
    if runtime.CHECK in store:
        raise RuntimeError('Azure package CASES collision')
    before = tuple(CHECKS)
    try:
        register(runtime.CHECK, 'azure', d['category'], runtime.KIND, d['title'], d['severity'],
                 d['control'], d['remediation'], dependencies=d['dependencies'],
                 allow_incomplete_failure=True)(consumer.evaluate)
        store[runtime.CHECK] = fixtures
        _INSTALLED = CHECKS[-1].evaluate
    except Exception:
        CHECKS[:] = before
        store.pop(runtime.CHECK, None)
        raise


def _bindings():
    result = dict(_FUNCTIONS)
    modules = (runtime, runtime.predecessor, runtime.source, runtime.exporter,
               runtime.predecessor.contract, runtime.source.storage, consumer,
               consumer.predecessor, owner, importlib.import_module('peaso.secret_scanning'),
               importlib.import_module('peaso.azure_function_package_provenance_20261020'),
               importlib.import_module('peaso.collectors'), importlib.import_module('peaso.collectors.bulk_evidence'))
    modules += tuple(importlib.import_module('peaso.collectors.' + name) for name in (
        'azure_function_settings_runtime_hooks_20261020', 'azure_ml_selected_asset_secret_indicators',
        'azure_databricks_notebook_secret_indicators', 'azure_ml_selected_job_secret_indicators',
        'azure_selected_log_sample_secret_indicators', 'azure_selected_declaration_secret_indicators',
        'azure_selected_secret_integration_20261020', 'azure_selected_configuration_secret_indicators',
        'azure_devops_selected_content_secret_indicators', 'azure_acr_image_secret_indicators',
        'azure_app_settings_secret_indicators', 'azure_function_settings_declarations_20261020',
        'aws_package_content_indicators'))
    for module in modules:
        for name, value in tuple(vars(module).items()):
            if (isinstance(value, types.FunctionType) or callable(value) and hasattr(value, '__wrapped__')) and inspect.unwrap(value).__module__ == module.__name__:
                result[module.__name__ + ':' + name] = value
            elif isinstance(value, type) and value.__module__ == module.__name__:
                for member, function in vars(value).items():
                    if isinstance(function, types.FunctionType):
                        result[module.__name__ + ':' + name + '.' + member] = function
    from peaso.collectors import azure
    for name in ('__init__', 'call', 'check_cancelled'):
        result['peaso.collectors.azure:_Reader.' + name] = getattr(azure._Reader, name)
    return result


_FUNCTIONS = {__name__ + ':' + name: fn for name, fn in tuple(globals().items())
              if isinstance(fn, types.FunctionType) and fn.__globals__ is globals()}

_EXECUTING = _bindings()
