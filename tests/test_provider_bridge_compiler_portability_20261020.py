"""Exact compiler parity and live checks after admission-local compiled reuse."""
import hashlib
import inspect
from pathlib import Path
import sys
import types

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = '''\
def decorate(*, flag):
    def wrapper(function):
        return function
    return wrapper

@decorate(flag=True)
def selected(value=1, *, flag=True):
    return value if flag else 0

def outer(value):
    def inner(extra=2):
        return value + extra
    return inner

class Container:
    @staticmethod
    async def pending(value=None):
        return value

def branches(value):
    try:
        if value:
            class Nested:
                @staticmethod
                async def pending(extra=2):
                    return extra
    except Exception:
        def recover():
            return None
    match value:
        case _:
            def fallback():
                return value
'''


@pytest.fixture(scope='module')
def bridge():
    from peaso.checks import azure_jit_parent_type_shared_successor_20261020
    return azure_jit_parent_type_shared_successor_20261020


def consumed(rows):
    return [(record['qualname'], record['source_sha256'], code) for record, code in rows]


def test_compiler_preserves_decorated_nested_async_class_and_defaults(bridge):
    raw = SOURCE.encode()
    expected = bridge.original.proof._compiled_source(raw, 'compiler-parity.py', sys.flags.optimize)
    actual = bridge._compiled_source(raw, 'compiler-parity.py', sys.flags.optimize)
    assert consumed(actual) == consumed(expected)
    assert {record['qualname'] for record, _ in actual} == {
        'decorate', 'decorate.<locals>.wrapper', 'selected', 'outer',
        'outer.<locals>.inner', 'Container.pending',
        'branches', 'branches.<locals>.Nested.pending',
        'branches.<locals>.recover', 'branches.<locals>.fallback',
    }


@pytest.mark.parametrize('relative', [
    'peaso/checks/azure_jit_parent_type_shared_successor_20261020.py',
    'peaso/engine.py', 'peaso/collectors/aws.py',
])
def test_current_real_source_consumed_records_match_historical_compiler(bridge, relative):
    path = ROOT / relative
    raw = path.read_bytes()
    expected = bridge.original.proof._compiled_source(raw, str(path), sys.flags.optimize)
    assert consumed(bridge._compiled_source(raw, str(path), sys.flags.optimize)) == consumed(expected)


@pytest.fixture(params=[False, True], ids=['local', 'transaction'])
def warmed(bridge, tmp_path, monkeypatch, request):
    root = tmp_path.resolve()
    path = root / 'sample.py'
    path.write_text(SOURCE)
    module = types.ModuleType('provider_bridge_compiler_sample')
    module.__file__ = str(path)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(SOURCE, str(path), 'exec'), vars(module))
    function = module.selected
    row = dict(path='sample.py', qualname='selected',
               sha256=hashlib.sha256(inspect.getsource(function).encode()).hexdigest(),
               defaults=[1], kwdefaults={'flag': True})
    compiled = {}
    token = bridge._COMPILED_TRANSACTION.set(bridge._transaction_compiler()) if request.param else None
    try:
        bridge._check_function(function, row, root, compiled)
        bridge._check_function(function, row, root, compiled)
        assert len(compiled) == (0 if request.param else 1)
        yield function, row, root, compiled
    finally:
        if token is not None:
            bridge._COMPILED_TRANSACTION.reset(token)


@pytest.mark.parametrize('mutation', ['code', 'defaults', 'kwdefaults', 'globals', 'receipt', 'source'])
def test_warm_local_compilation_still_rejects_changed_inputs(bridge, warmed, mutation):
    function, row, root, compiled = warmed
    if mutation == 'code':
        function.__code__ = function.__code__.replace(co_consts=(None, 987))
    elif mutation == 'defaults':
        function.__defaults__ = (2,)
    elif mutation == 'kwdefaults':
        function.__kwdefaults__ = {'flag': False}
    elif mutation == 'globals':
        function = types.FunctionType(function.__code__, dict(function.__globals__),
                                      function.__name__, function.__defaults__)
        function.__kwdefaults__ = {'flag': True}
    elif mutation == 'receipt':
        row = dict(row, sha256='0' * 64)
    else:
        (root / 'sample.py').write_text(SOURCE.replace('else 0', 'else 7'))
    with pytest.raises(RuntimeError, match='executing callable changed'):
        bridge._check_function(function, row, root, compiled)


@pytest.mark.parametrize('name', ['_compiled_source', '_check_function', '_transaction_compiler'])
@pytest.mark.parametrize('mutation', ['identity', 'code'])
def test_bridge_independently_rejects_optimization_helper_tampering(bridge, monkeypatch, name, mutation):
    bridge._verify_bridge(ROOT)
    if mutation == 'identity':
        monkeypatch.setattr(bridge, name, lambda *args, **kwargs: None)
    else:
        monkeypatch.setattr(getattr(bridge, name), '__code__', (lambda *args, **kwargs: None).__code__)
    with pytest.raises(RuntimeError, match='callable'):
        bridge._verify_bridge(ROOT)


@pytest.mark.parametrize('mutation', ['code', 'hash', 'forged_signature'])
def test_transaction_cache_artifact_poisoning_is_rejected(bridge, mutation):
    raw = SOURCE.encode()
    key = ('cache-poison.py', hashlib.sha256(raw).hexdigest(), sys.flags.optimize)
    compiler = bridge._transaction_compiler()
    compiler(key, raw, 'selected')
    cache = inspect.getclosurevars(compiler).nonlocals['cache']
    poisoned = []
    for record, signature in cache[key]:
        if record[0] == 'selected':
            if mutation == 'hash':
                record = (record[0], '0' * 64, record[2])
            else:
                record = (record[0], record[1], record[2].replace(co_consts=(None, 987)))
                if mutation == 'forged_signature':
                    # An attacker-controlled checksum cannot replace the
                    # independent transaction signature.
                    signature = hashlib.sha256(record[2].co_code).digest()
        poisoned.append((record, signature))
    cache[key] = tuple(poisoned)
    with pytest.raises(RuntimeError, match='cache artifact changed'):
        compiler(key, raw, 'selected')


def test_transaction_integrity_is_independent_of_external_code_references(bridge):
    raw = SOURCE.encode()
    key = ('cache-reference.py', hashlib.sha256(raw).hexdigest(), sys.flags.optimize)
    compiler = bridge._transaction_compiler()
    retained = compiler(key, raw, 'selected')
    assert compiler(key, raw, 'selected') == retained


@pytest.mark.parametrize('mutation', ['alias', 'live_code', 'receipt_binding'])
def test_warm_real_bridge_still_rechecks_live_and_receipt_bindings(bridge, monkeypatch, mutation):
    token = bridge._COMPILED_TRANSACTION.set(bridge._transaction_compiler())
    try:
        bridge.reviewed_delta(ROOT)
        from peaso.collectors import aws
        if mutation == 'alias':
            monkeypatch.setattr(aws, 'collect', lambda *args, **kwargs: None)
        elif mutation == 'live_code':
            monkeypatch.setattr(aws.collect, '__code__', (lambda *args, **kwargs: None).__code__)
        else:
            monkeypatch.setattr(bridge, 'RECEIPT_SHA256', '0' * 64)
        with pytest.raises(RuntimeError):
            bridge.reviewed_delta(ROOT)
    finally:
        bridge._COMPILED_TRANSACTION.reset(token)


def test_bundle_compilation_context_is_released_on_success_and_failure(bridge, monkeypatch):
    # The genuine cold import has already completed a successful install wave.
    assert bridge._COMPILED_TRANSACTION.get() is None
    from peaso.checks import aws_workload_command_runtime_admission_20261020 as commands

    def refuse():
        assert bridge._COMPILED_TRANSACTION.get() is not None
        raise RuntimeError('deliberate preflight refusal')

    monkeypatch.setattr(commands, 'reviewed_inputs', refuse)
    with pytest.raises(RuntimeError, match='deliberate preflight refusal'):
        bridge.install_bundle()
    assert bridge._COMPILED_TRANSACTION.get() is None
