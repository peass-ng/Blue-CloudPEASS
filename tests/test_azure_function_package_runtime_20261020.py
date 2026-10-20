"""Local owner entrypoints, original native HTTP and actual offline dual scanners."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from peaso import azure_function_package_portable_20261020 as portable
from peaso.collectors import azure_function_package_runtime_20261020 as runtime
from peaso.collectors import azure_function_package_source_20261020 as source
from peaso.checks import azure_function_package_runtime_consumer_20261020 as consumer
from tests import test_azure_function_package_source_20261020 as native

ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / 'peaso/checks/azure_function_package_runtime_cases_20261020.json'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    yield from native.offline.__wrapped__(monkeypatch)


def prepare(options=None, named=None, scopes=None, **kw):
    return runtime.prepare(native.options() if options is None else options,
        [native.SCOPE] if scopes is None else scopes,
        [source.CHECK] if named is None else named,
        **{'customer_context_id': 'customer-context', 'credential_context_id': 'credential-context',
           'tenant_id': native.TENANT, 'principal_id': native.PRINCIPAL, **kw})


def capture_runtime(monkeypatch, *, surfaces=None, other_matches=(), **kw):
    target = kw.get('t') or native.target()
    plan = prepare(native.options(target))
    planned = runtime.selection_context(plan)
    expected = None
    events = ['prepared', 'expected_retained']
    # Reuse the existing full fake native HTTP fixture without duplicating a
    # transport. Its outer entrypoint delegates to the new runtime; runtime
    # retains the original collect callable and actual scanner/parser/helper calls.
    def entry(reader, transport, scopes, options, named_checks, **context):
        nonlocal expected
        def auth():
            events.append('auth')
            return transport
        pending = runtime.collect(plan, auth)
        expected = runtime.captured_context(pending, expected_selection_context=planned)
        if other_matches:
            runtime.retain_union(pending, other_matches)
        return pending
    with monkeypatch.context() as scoped:
        scoped.setattr(source, 'collect', entry)
        pending, trace = native.capture(scoped, **kw)
        events.append('captured')
        safe = runtime.finalize_union(pending, surfaces={} if surfaces is None else surfaces)
    assert events == ['prepared', 'expected_retained', 'auth', 'captured']
    assert all(c.closed for c in trace.connections) and all(r.closed for r in trace.responses)
    return safe, expected, trace


def evaluate(snapshot, expected):
    index = consumer.build_index(snapshot, scope=native.SCOPE, expected_index_context=expected)
    item = index['collections'][portable.KIND][0]['items'][0]
    return consumer.evaluate(item, index, expected_index_context=expected)


def external(snapshot, expected, tmp_path):
    path = tmp_path / 'input.json'
    path.write_text(json.dumps([snapshot, expected]))
    # -I loads just the stdlib portable contract and pure new consumer. It does
    # not import peaso.checks.__init__ or rely on inherited registry/key state.
    code = '''
import importlib.util, json, pathlib, socket, subprocess, sys, types
def blocked(*a, **kw):
    raise AssertionError('pure consumer attempted network or execution')
socket.create_connection = socket.getaddrinfo = blocked
subprocess.Popen = subprocess.run = blocked
peaso = types.ModuleType('peaso'); peaso.__path__ = []
sys.modules['peaso'] = peaso
for name, path in [('peaso.azure_function_package_portable_20261020', sys.argv[1]), ('runtime_consumer', sys.argv[2])]:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module; spec.loader.exec_module(module)
    if name.startswith('peaso.'):
        peaso.azure_function_package_portable_20261020 = module
snapshot, expected = json.loads(pathlib.Path(sys.argv[3]).read_text())
index = module.build_index(snapshot, scope=expected['scopes'][0], expected_index_context=expected)
item = index['collections'][module.KIND][0]['items'][0]
result = module.evaluate(item, index, expected_index_context=expected)
assert 'peaso.secret_scanning' not in sys.modules
assert not any(n.startswith(('peaso.collectors', 'peaso.checks')) for n in sys.modules)
print(json.dumps(result))
'''
    process = subprocess.run([sys.executable, '-I', '-c', code, portable.__file__, consumer.__file__, str(path)],
        capture_output=True, text=True, timeout=20, env={'PATH': os.defpath})
    assert process.returncode == 0, process.stderr
    return json.loads(process.stdout)


@pytest.mark.parametrize('hit', [False, True])
@pytest.mark.parametrize('versioned', [False, True])
@pytest.mark.parametrize('hosting', ['function', 'app_service'])
def test_actual_native_both_scanners_runtime_json(monkeypatch, hit, versioned, hosting, tmp_path):
    safe, expected, trace = capture_runtime(monkeypatch, hit=hit, t=native.target(versioned), hosting=hosting)
    snapshot = safe['package_snapshot']
    result = evaluate(snapshot, expected)
    assert result[0] == ('FAIL' if hit else 'PASS') and result[1]['complete'] is True
    assert external(snapshot, expected, tmp_path) == json.loads(json.dumps(result))
    assert [c[0] for c in trace.calls] == list(source.OPERATIONS)
    for part in result[1]['parts']:
        assert {e['engine']: e['status'] for e in part['engines']} == {'kingfisher': 'complete', 'trufflehog': 'complete'}
    if hit:
        assert {d['engine'] for leak in result[1]['secret_leaks'] for d in leak['detectors']} == set(portable.VERSIONS)
    assert result[1]['cloud_authenticity'] == 'not_established'
    assert result[1]['runtime_bytes'] == result[1]['continuous_immutability'] == 'unknown'
    assert result[1]['credential_validation'] == 'not_attempted'
    for private in (native.SECRET, native.SAS, native.SITE, 'function.zip', 'WEBSITE_RUN_FROM_PACKAGE', 'Authorization', 'Bearer '):
        assert private not in json.dumps([safe, expected, result])


@pytest.mark.parametrize('operation', source.OPERATIONS)
def test_denied_actual_native(monkeypatch, operation):
    def fault(op, response):
        if op == operation:
            response.status = 403
        return response
    safe, expected, _ = capture_runtime(monkeypatch, fault=fault)
    assert evaluate(safe['package_snapshot'], expected)[0] == 'UNKNOWN'


@pytest.mark.parametrize('reference', ['1', '@Microsoft.KeyVault(SecretUri=private)',
    'https://foreign.example/a.zip', 'https://sourceaccount.blob.core.windows.net/packages/other.zip'])
def test_reference_never_fetches_arbitrary_blob(monkeypatch, reference):
    safe, expected, trace = capture_runtime(monkeypatch, reference=reference)
    assert evaluate(safe['package_snapshot'], expected)[0] == 'UNKNOWN'
    assert not any(c[1].endswith('.blob.core.windows.net') for c in trace.calls)


@pytest.mark.parametrize('case', ['etag', 'reference', 'truncated', 'wrong_tenant', 'wrong_account'])
def test_changed_source_and_unbound_native(monkeypatch, case):
    def fault(op, response):
        if case == 'etag' and op == 'properties_after':
            response.headers['ETag'] = '"changed"'
        if case == 'reference' and op == 'settings_after':
            data = json.loads(response.stream.getvalue())
            data['properties']['WEBSITE_RUN_FROM_PACKAGE'] += 'changed'
            return native.Response(data)
        if case == 'truncated' and op == 'content':
            response.headers['Content-Length'] = str(int(response.headers['Content-Length']) + 1)
        if (case, op) in [('wrong_tenant', 'subscription'), ('wrong_account', 'account')]:
            data = json.loads(response.stream.getvalue())
            if case == 'wrong_tenant':
                data['tenantId'] = native.PRINCIPAL
            else:
                data['id'] = data['id'].replace(native.SCOPE, native.OTHER)
            return native.Response(data)
        return response
    safe, expected, _ = capture_runtime(monkeypatch, fault=fault, hit=True)
    assert evaluate(safe['package_snapshot'], expected)[0] == 'UNKNOWN'


@pytest.mark.parametrize('hit,status', [(False, 'UNKNOWN'), (True, 'FAIL')])
def test_partial_native_archive(monkeypatch, hit, status):
    safe, expected, _ = capture_runtime(monkeypatch, raw=native.package(hit, ('nested.zip', b'PKbad')))
    result = evaluate(safe['package_snapshot'], expected)
    assert result[0] == status and result[1]['complete'] is False


@pytest.mark.parametrize('options,named', [({}, []), ({'content_secret_scans': False}, [source.CHECK]),
    (native.options(), []), (native.options(), ['*']), (native.options(), [source.KIND]),
    (native.options(), ['framework:cis']), (native.options(), [portable.KIND]),
    ({**native.options(), '_content_secret_scan_kinds': [source.KIND]}, [])])
def test_default_off_before_auth(options, named):
    assert prepare(options, named) is None


@pytest.mark.parametrize('case', ['bool', 'empty', 'foreign_scope', 'slot', 'url', 'duplicate',
    'blob_extra', 'not_zip', 'scope_case', 'shared', 'shared_disabled', 'provider',
    'customer', 'credential', 'tenant', 'principal', 'grant', 'plan'])
def test_invalid_selection_rejected_before_auth(case):
    options, scopes, kw = native.options(), [native.SCOPE], {}
    target = options[source.OPTION][0]
    if case == 'bool': options['content_secret_scans'] = 'true'
    elif case == 'empty': options[source.OPTION] = []
    elif case == 'foreign_scope': scopes = [native.OTHER]
    elif case == 'slot': target['site_resource_id'] += '/slots/production'
    elif case == 'url': target['blob']['object'] = 'https://example.com/package.zip'
    elif case == 'duplicate': options[source.OPTION] *= 2
    elif case == 'blob_extra': target['blob']['sas'] = 'private'
    elif case == 'not_zip': target['blob']['format'] = 'text'
    elif case == 'scope_case': scopes = [native.SCOPE.replace('subscriptions', 'SUBSCRIPTIONS')]
    elif case == 'shared': kw['shared_service_account'] = True
    elif case == 'shared_disabled':
        kw['shared_service_account'] = True
        options['content_secret_scans'] = False
    elif case == 'provider': kw['provider'] = 'aws'
    elif case in ('customer', 'credential'): kw[case + '_context_id'] = ''
    elif case in ('tenant', 'principal'): kw[case + '_id'] = 'bad'
    else: options[case] = {'authorized': True}
    with pytest.raises(runtime.Invalid):
        prepare(options, scopes=scopes, **kw)


def test_supplied_disabled_malformed_selection_still_rejected():
    with pytest.raises(runtime.Invalid):
        prepare({'content_secret_scans': False, source.OPTION: [{'site_resource_id': '*'}]}, [])


def test_plan_is_opaque_one_use_and_not_a_user_grant():
    plan = prepare()
    expected = runtime.selection_context(plan)
    with pytest.raises(runtime.Invalid): deepcopy(plan)
    calls = []
    for forged in ({'authorized': True}, runtime._Handle(), None):
        with pytest.raises(runtime.Invalid): runtime.collect(forged, lambda: calls.append('auth'))
    assert not calls
    runtime.discard(plan)
    with pytest.raises(runtime.Invalid): runtime.collect(plan, lambda: calls.append('auth'))
    assert not calls and expected['customer_context_id'] == 'customer-context'


def test_plan_copies_selectors_and_expected_context():
    opts = native.options()
    plan = prepare(opts)
    expected = runtime.selection_context(plan)
    opts[source.OPTION].clear()
    expected['targets'].clear()
    assert len(runtime.selection_context(plan)['targets']) == 1
    runtime.discard(plan)


def test_runtime_calls_original_callable_and_native_capture_uuid(monkeypatch):
    assert runtime._NATIVE_COLLECT.__module__ == source.__name__
    original_uuid = source.uuid4
    planned = prepare()
    independent = runtime.selection_context(planned)
    assert 'capture' not in independent
    runtime.discard(planned)
    safe, expected, _ = capture_runtime(monkeypatch)
    assert source.uuid4 is original_uuid
    assert safe['package_snapshot']['metadata'][portable.KIND]['index_context']['capture'] == expected['capture']


def test_concurrent_plans_have_distinct_native_captures(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    plans = [prepare(), prepare()]
    independent = [runtime.selection_context(plan) for plan in plans]
    captured = []
    def entry(reader, transport, scopes, options, named_checks, **context):
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = list(pool.map(lambda plan: runtime.collect(plan, lambda: transport), plans))
        for handle, expected_selection in zip(pending, independent):
            expected = runtime.captured_context(handle, expected_selection_context=expected_selection)
            wrong = deepcopy(expected_selection)
            wrong['customer_context_id'] = 'another-customer'
            with pytest.raises(runtime.Invalid, match='independent_selection_context_required'):
                runtime.captured_context(handle, expected_selection_context=wrong)
            safe = runtime.finalize_union(handle, surfaces={})
            with pytest.raises(runtime.Invalid): runtime.finalize_union(handle, surfaces={})
            captured.append((safe, expected))
        return None
    with monkeypatch.context() as scoped:
        scoped.setattr(source, 'collect', entry)
        native.capture(scoped)
    assert len({expected['capture'] for _, expected in captured}) == 2
    for safe, expected in captured:
        assert evaluate(safe['package_snapshot'], expected)[0] == 'PASS'


@pytest.mark.parametrize('hit,status', [(False, 'UNKNOWN'), (True, 'FAIL')])
def test_unavailable_second_detector_preserves_partial(monkeypatch, hit, status):
    import io
    import zipfile
    from peaso import secret_scanning
    def unavailable(): raise RuntimeError('offline detector unavailable')
    monkeypatch.setattr(secret_scanning, '_trufflehog', unavailable)
    # A first-member detector failure stops archive inspection. Put the tested
    # secret in that first scanned member so FAIL is based on observed data.
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        archive.writestr('main.py', 'TOKEN=' + native.SECRET if hit else 'mode=ready')
    safe, expected, _ = capture_runtime(monkeypatch, raw=out.getvalue())
    result = evaluate(safe['package_snapshot'], expected)
    assert result[0] == status and result[1]['complete'] is False


def test_auth_failure_consumes_plan_and_hides_exception():
    plan = prepare()
    def auth(): raise RuntimeError(native.SECRET)
    with pytest.raises(runtime.Invalid, match='^runtime_capture_rejected$'):
        runtime.collect(plan, auth)
    with pytest.raises(runtime.Invalid, match='invalid_or_consumed'):
        runtime.collect(plan, auth)


def test_source_gate_before_auth(monkeypatch, tmp_path):
    plan = prepare()
    binding = tmp_path / 'binding.json'
    binding.write_text(json.dumps({'status': 'unregistered_local_only', 'sources': {'peaso/secret_scanning.py': '0' * 64}}))
    monkeypatch.setattr(runtime, 'BINDING', binding)
    calls = []
    with pytest.raises(runtime.Invalid): runtime.collect(plan, lambda: calls.append('auth'))
    assert not calls


def test_fork_inherited_plan_rejected_before_auth(monkeypatch):
    plan = prepare()
    parent_pid = runtime.os.getpid()
    monkeypatch.setattr(runtime.os, 'getpid', lambda: parent_pid + 1)
    calls = []
    with pytest.raises(runtime.Invalid): runtime.collect(plan, lambda: calls.append('auth'))
    assert not calls


def test_mixed_metadata_union_scrubs_keys_values_options_errors_cache(monkeypatch):
    surfaces = {'collections': [{'label': 'prefix ' + native.SECRET + ' suffix'}],
        'metadata': {native.SECRET: [native.SECRET, 'healthy']},
        'options': {source.OPTION: [native.target()], 'alias': native.SECRET}, 'errors': [{'message': native.SECRET}],
        'cache': {'response': native.SECRET}, 'pending_writes': [native.SECRET]}
    before = deepcopy(surfaces)
    safe, expected, _ = capture_runtime(monkeypatch, hit=True, surfaces=surfaces,
                                      other_matches=('another-secret-value',))
    assert surfaces == before
    assert native.SECRET not in json.dumps(safe)
    assert source.OPTION not in safe['surfaces']['options'] and native.SITE not in json.dumps(safe)
    assert safe['surfaces']['metadata']['[redacted]'] == ['[redacted]', 'healthy']
    assert evaluate(safe['package_snapshot'], expected)[0] == 'FAIL'


@pytest.mark.parametrize('surfaces,other', [({'a': 'x' * (8 * 1024 * 1024 + 1)}, ()),
    ({}, ('x' * 65537,)), ({'abc': 1, 'xyz': 2}, ('abc', 'xyz')),
    ({'bad': object()}, ()), ({'bad': float('nan')}, ()), ({'deep': [[[[[[]]]]]]}, ())])
def test_union_bounds_fail_closed(monkeypatch, surfaces, other):
    if 'deep' in surfaces:
        value = []
        for _ in range(35): value = [value]
        surfaces = {'deep': value}
    with pytest.raises(runtime.Invalid, match='content_union_redaction_incomplete'):
        capture_runtime(monkeypatch, surfaces=surfaces, other_matches=other)


@pytest.mark.parametrize('field', ['capture', 'customer_context_id', 'credential_context_id', 'tenant_id', 'principal'])
def test_independent_context_rejects_replay(monkeypatch, field):
    safe, expected, _ = capture_runtime(monkeypatch)
    snapshot = safe['package_snapshot']
    index = consumer.build_index(snapshot, scope=native.SCOPE, expected_index_context=expected)
    item = index['collections'][portable.KIND][0]['items'][0]
    expected[field] = 'wrong-context'
    assert consumer.evaluate(item, index, expected_index_context=expected)[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ['item', 'collections', 'provider', 'scope', 'snapshot', 'metadata_context_only'])
def test_index_rejects_unbound_or_divergent_slices(monkeypatch, case):
    safe, expected, _ = capture_runtime(monkeypatch)
    index = consumer.build_index(safe['package_snapshot'], scope=native.SCOPE, expected_index_context=expected)
    item = deepcopy(index['collections'][portable.KIND][0]['items'][0])
    if case == 'item': item['complete'] = False
    elif case == 'collections': index['collections'][portable.KIND][0]['items'] *= 2
    elif case == 'provider': index['context']['provider'] = 'aws'
    elif case == 'scope': index['context']['scope'] = native.OTHER
    elif case == 'snapshot': index['package_snapshot']['metadata'][portable.KIND]['receipts'].reverse()
    else: expected = {}
    assert consumer.evaluate(item, index, expected_index_context=expected)[0] == 'UNKNOWN'


def test_saved_cases_exact_local_source_binding_and_declaration(tmp_path):
    cases = json.loads(CASES_PATH.read_text())
    assert cases['declaration'] == consumer.DECLARATION == runtime.DECLARATION
    assert cases['status'] == 'unregistered_local_only'
    assert cases['source_hashes'] == runtime.reviewed_sources()
    for case in cases['cases']:
        result = evaluate(case['snapshot'], case['expected_index_context'])
        assert result[0] == case['expected_status']
        assert external(case['snapshot'], case['expected_index_context'], tmp_path) == json.loads(json.dumps(result))
