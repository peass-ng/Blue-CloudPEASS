"""Parent native ARM HTTP -> existing shared _Reader -> successor/public engine."""
from copy import deepcopy
import base64
import io
import json
import socket
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from peaso import checks
from peaso.collectors import azure
from peaso.collectors import azure_nsp_query_cmk_runtime_20261020 as runtime
from peaso.collectors import azure_nsp_query_cmk_metadata_proposal_20261020 as native
from peaso.checks import azure_nsp_query_cmk_runtime_review_20261020 as consumer
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import make_snapshot
from tests.test_azure_nsp_query_cmk_metadata_proposal_20261020 import (
    NativeHTTP, SCOPE, SUB, OTHER, ACCOUNT, CANARY, nsp_mode, query_mode)

TENANT = '22222222-2222-2222-2222-222222222222'
FOREIGN_TENANT = '33333333-3333-3333-3333-333333333333'
claims = base64.urlsafe_b64encode(json.dumps({'tid': TENANT, 'aud': azure.ARM}).encode()).decode().rstrip('=')
TOKEN = 'eyJhbGciOiJub25lIn0.' + claims + '.INERT_FIXTURE_SIGNATURE'


class ParentHTTP(NativeHTTP):
    def __init__(self):
        super().__init__()
        self.token = TOKEN
        self.put(SCOPE, '2022-12-01', {'id': SCOPE, 'subscriptionId': SUB,
            'displayName': 'Native fixture subscription', 'state': 'Enabled', 'tenantId': TENANT})
        self.on_metadata = None

    def open(self, request, timeout):
        parsed = urlsplit(request.full_url);query = parse_qs(parsed.query)
        assert request.get_method() == 'GET' and request.data is None
        assert parsed.scheme == 'https' and parsed.netloc == 'management.azure.com'
        assert request.get_header('Authorization') == 'Bearer ' + self.token and timeout == 20
        assert set(query) <= {'api-version', '$skipToken'}
        key = (parsed.path.casefold(), query['api-version'][0], query.get('$skipToken', [None])[0])
        assert key in self.routes, key
        self.calls.append({'method': 'GET', 'host': parsed.netloc, 'path': parsed.path,
                           'api_version': key[1], 'page': key[2] is not None})
        if parsed.path != SCOPE and self.on_metadata:
            self.on_metadata()
        value = self.routes[key]
        if isinstance(value, int):
            raise HTTPError(request.full_url, value, CANARY, {}, io.BytesIO(CANARY.encode()))
        response = io.BytesIO(value if isinstance(value, bytes) else json.dumps(value).encode())
        response.status = self.status
        return response


@pytest.fixture(autouse=True)
def offline_successor_bridge(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError('network/DNS/auth forbidden')
    for owner, names in ((socket, ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex')),
                         (socket.socket, ('connect', 'connect_ex', 'sendto')), (azure, ('credential_for',))):
        for name in names: monkeypatch.setattr(owner, name, blocked)
    # Production successor is installed; no test-only replacement registry.
    for declaration, function in zip(consumer.DECLARATIONS, (consumer.nsp, consumer.query)):
        rows = [c for c in checks.CHECKS if c.id == declaration['id']]
        assert len(rows) == 1 and rows[0].evaluate.__wrapped__ is function
    yield


def parent(monkeypatch, http, options=None):
    monkeypatch.setattr(azure, 'build_opener', lambda *args: http)
    reader = azure._Reader({'max_calls': 40, 'max_resources': 64, 'max_pages': 8,
                            'collection_deadline_seconds': 120, 'retries': 0, 'concurrency': 4, **(options or {})})
    transport = azure.AzureTransport({'method': 'token', 'arm_token': TOKEN, 'tenant_id': TENANT})
    credential = uuid4().hex
    reader.run([runtime.subscription_job(reader, transport, SCOPE, credential_context_id=credential,
                                         customer_context_id='scan-local:' + credential)])
    metadata = {**reader.metadata(), **runtime.parent_metadata_from_inventory(reader, transport, [SCOPE],
        credential_context_id=credential, customer_context_id='scan-local:' + credential)}
    for collection in reader.collections:
        stamp = {key: metadata[key] for key in ('credential_context_id', 'customer_context_id')}
        collection['_provenance'] = dict(stamp)
        for item in collection['items']: item.setdefault('_provenance', {}).update(stamp)
    return reader, transport, metadata


def capture(monkeypatch, kind=native.NSP_KIND, mode='enforced', options=None, preflight=None):
    http = ParentHTTP();(nsp_mode if kind == native.NSP_KIND else query_mode)(http, mode)
    reader, transport, metadata = parent(monkeypatch, http, options)
    transport_id = transport.ai_context_id
    original_parent = deepcopy(metadata);parent_items = deepcopy(reader.collections)
    if preflight: preflight(metadata, transport)
    result = runtime.collect_into(reader, transport, [SCOPE], [kind], parent_metadata=metadata)
    # Adapter never writes parent metadata, transport identity or old collections.
    assert transport.ai_context_id == transport_id and reader.collections[0] == parent_items[0]
    if preflight is None: assert metadata == original_parent
    assert not set(result) - {runtime.METADATA_KEY}
    metadata.update(result)
    metadata.update(reader.metadata())  # Parent collector publishes its final shared accounting.
    snapshot = make_snapshot('azure', [SCOPE], reader.collections, metadata=metadata)
    check = consumer.IDS[0] if kind == native.NSP_KIND else consumer.IDS[1]
    findings = evaluate_snapshot(snapshot, checks=[check], include_not_applicable=True)['findings']
    assert CANARY not in json.dumps(snapshot) + json.dumps(findings)
    assert TOKEN not in json.dumps(snapshot)
    assert reader.budget.calls == len(http.calls)
    return {f['status'] for f in findings}, snapshot, http, reader, transport


NATIVE_CASES = [
    (native.NSP_KIND, 'enforced', 'PASS'), (native.NSP_KIND, 'learning', 'FAIL'), (native.NSP_KIND, 'audit', 'FAIL'),
    (native.NSP_KIND, 'transition', 'UNKNOWN'), (native.NSP_KIND, 'issues_boolean', 'UNKNOWN'),
    (native.NSP_KIND, 'issues_omitted', 'UNKNOWN'), (native.NSP_KIND, 'foreign_profile', 'UNKNOWN'),
    (native.NSP_KIND, 'unsupported_protected', 'UNKNOWN'), (native.NSP_KIND, 'profile_denied', 'DENIED'),
    (native.NSP_KIND, 'association_partial', 'UNKNOWN'), (native.NSP_KIND, 'empty_associations', 'EMPTY'),
    (native.NSP_KIND, 'detail_race', 'UNKNOWN'), (native.NSP_KIND, 'duplicate_protected', 'UNKNOWN'),
    (native.QUERY_KIND, 'cmk', 'PASS'), (native.QUERY_KIND, 'provider', 'FAIL'),
    (native.QUERY_KIND, 'table_service_key', 'FAIL'), (native.QUERY_KIND, 'no_links', 'NOT_APPLICABLE'),
    (native.QUERY_KIND, 'other_links', 'NOT_APPLICABLE'), (native.QUERY_KIND, 'table_key_missing', 'UNKNOWN'),
    (native.QUERY_KIND, 'version_omitted', 'PASS'), (native.QUERY_KIND, 'version_null', 'UNKNOWN'),
    (native.QUERY_KIND, 'foreign_account', 'UNKNOWN'), (native.QUERY_KIND, 'sibling_account_response', 'UNKNOWN'),
    (native.QUERY_KIND, 'empty_query_accounts', 'UNKNOWN'), (native.QUERY_KIND, 'denied_storage', 'DENIED'),
    (native.QUERY_KIND, 'partial_links', 'UNKNOWN'), (native.QUERY_KIND, 'malformed_list', 'UNKNOWN'),
    (native.QUERY_KIND, 'two_workspaces_cache', 'PASS'),
]


@pytest.mark.parametrize('kind,mode,want', NATIVE_CASES)
def test_parent_bound_native_http_reader_public_engine(monkeypatch, kind, mode, want, record_property):
    from tests.test_azure_nsp_query_cmk_production_20261020 import capture as production_capture
    actual, snapshot, http = production_capture(monkeypatch, kind, mode)
    record_property('actual', ','.join(sorted(actual)))
    assert actual == {want}
    for collection in snapshot['collections'][1:]:
        assert collection['_provenance']['credential_context_id'] == snapshot['metadata']['credential_context_id']
        for item in collection['items']:
            assert item['_capture']['credential_context_id'] != item['_capture']['runtime']['transport_context_id']
            assert all(r['credential_context_id'] == snapshot['metadata']['credential_context_id'] for r in item['_capture']['reads'])


PARENT_FIELDS = ['credential_context_id', 'customer_context_id', 'tenant_id', 'tenant_verified', 'context_binding', 'subscription_tenants']


@pytest.mark.parametrize('field', PARENT_FIELDS)
@pytest.mark.parametrize('mutation', ['missing', 'foreign'])
def test_invalid_parent_fails_before_first_adapter_read(monkeypatch, field, mutation):
    def change(metadata, transport):
        if mutation == 'missing': metadata.pop(field)
        else: metadata[field] = {'other': FOREIGN_TENANT} if field == 'subscription_tenants' else False if field == 'tenant_verified' else 'foreign'
    actual, _, http, _, _ = capture(monkeypatch, preflight=change)
    assert actual == {'UNKNOWN'} and len(http.calls) == 1


POSITIONS = [('parent', key) for key in PARENT_FIELDS] + [
    (position, key) for position in ('namespace', 'collection', 'item', 'marker')
    for key in ('credential_context_id', 'customer_context_id', 'tenant_id', 'capture_id', 'transport_context_id')]


@pytest.mark.parametrize('kind', native.KINDS)
@pytest.mark.parametrize('position,field', POSITIONS)
@pytest.mark.parametrize('mutation', ['missing', 'conflict'])
def test_parent_namespace_item_collection_context_tampering_unresolved(monkeypatch, kind, position, field, mutation):
    _, snapshot, _, _, _ = capture(monkeypatch, kind, 'enforced' if kind == native.NSP_KIND else 'cmk')
    collections = deepcopy(snapshot['collections']);metadata = deepcopy(snapshot['metadata'])
    envelope = collections[1];item = envelope['items'][0]
    targets = {'parent': metadata, 'namespace': metadata[runtime.METADATA_KEY]['bindings'][0],
               'collection': envelope['_provenance'], 'item': item['_provenance'], 'marker': item['_capture']['runtime']}
    target = targets[position]
    if mutation == 'missing': target.pop(field)
    else: target[field] = {'foreign': 'value'} if field == 'subscription_tenants' else False if field == 'tenant_verified' else 'foreign'
    changed = make_snapshot('azure', [SCOPE], collections, metadata=metadata)
    check = consumer.IDS[0] if kind == native.NSP_KIND else consumer.IDS[1]
    assert {f['status'] for f in evaluate_snapshot(changed, checks=[check])['findings']} == {'UNKNOWN'}


@pytest.mark.parametrize('field', ['operation', 'method', 'path', 'api_version', 'credential_context_id', 'scope'])
def test_source_receipt_conflict_never_delegates_clean(monkeypatch, field):
    _, snapshot, _, _, _ = capture(monkeypatch)
    collections = deepcopy(snapshot['collections'])
    collections[1]['items'][0]['_capture']['reads'][-1][field] = 'foreign'
    changed = make_snapshot('azure', [SCOPE], collections, metadata=snapshot['metadata'])
    assert {f['status'] for f in evaluate_snapshot(changed, checks=[consumer.IDS[0]])['findings']} == {'UNKNOWN'}


def test_jobs_bind_parent_before_first_read_and_do_not_mutate_transport(monkeypatch):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    original_id = transport.ai_context_id
    planned, bindings = runtime.jobs(reader, transport, [SCOPE], native.KINDS, parent_metadata=metadata)
    assert len(http.calls) == 1 and all(b['credential_context_id'] == metadata['credential_context_id'] for b in bindings)
    assert len({b['capture_id'] for b in bindings}) == 1
    reader.run(planned);patch = runtime.finish(reader, bindings)
    assert transport.ai_context_id == original_id
    assert len(http.calls) == 9 and sum(call['path'] == ACCOUNT for call in http.calls) == 1
    assert set(patch) == {runtime.METADATA_KEY}


@pytest.mark.parametrize('options', [{'max_calls': 2}, {'max_resources': 1}])
def test_existing_reader_call_limit_and_resource_limit_are_shared(monkeypatch, options):
    actual, snapshot, http, reader, _ = capture(monkeypatch, options=options)
    assert actual == {'UNKNOWN'} and len(http.calls) == reader.budget.calls == snapshot['metadata']['calls']
    if 'max_calls' in options: assert len(http.calls) == 2


def test_no_new_reader_or_budget_created(monkeypatch):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    existing_budget = reader.budget
    monkeypatch.setattr(azure._Reader, '__init__', lambda *a, **kw: pytest.fail('must reuse parent reader'))
    result = runtime.collect_into(reader, transport, [SCOPE], [native.NSP_KIND], parent_metadata=metadata)
    assert reader.budget is existing_budget and result[runtime.METADATA_KEY]['bindings']


def test_context_change_during_authenticated_read_unresolved(monkeypatch):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    http.on_metadata = lambda: setattr(transport, 'verified_tenant', FOREIGN_TENANT)
    patch = runtime.collect_into(reader, transport, [SCOPE], [native.NSP_KIND], parent_metadata=metadata)
    snapshot = make_snapshot('azure', [SCOPE], reader.collections, metadata={**metadata, **patch})
    assert {f['status'] for f in evaluate_snapshot(snapshot, checks=[consumer.IDS[0]])['findings']} == {'UNKNOWN'}


def test_namespace_collision_is_rejected_without_overwrite(monkeypatch):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    metadata[runtime.METADATA_KEY] = {'foreign': True}
    with pytest.raises(RuntimeError, match='namespace'): runtime.collect_into(reader, transport, [SCOPE], native.KINDS, parent_metadata=metadata)
    assert metadata[runtime.METADATA_KEY] == {'foreign': True} and len(http.calls) == 1


def test_original_predicate_delegation_does_not_change_snapshot(monkeypatch):
    _, snapshot, _, _, _ = capture(monkeypatch)
    before = deepcopy(snapshot)
    evaluate_snapshot(snapshot, checks=[consumer.IDS[0]])
    assert snapshot == before and 'proposal_schema' not in snapshot['metadata']


@pytest.mark.parametrize('mutation', ['duplicate', 'foreign_kind', 'foreign_scope', 'conflicting_capture', 'schema_conflict'])
def test_namespace_ambiguity_or_schema_conflict_unresolved(monkeypatch, mutation):
    _, snapshot, _, _, _ = capture(monkeypatch)
    metadata = deepcopy(snapshot['metadata']);bindings = metadata[runtime.METADATA_KEY]['bindings']
    if mutation == 'schema_conflict': metadata['proposal_schema'] = 'foreign-schema'
    else:
        extra = deepcopy(bindings[0])
        if mutation == 'foreign_kind': extra['kind'] = 'foreign-kind'
        if mutation == 'foreign_scope': extra['scope'] = SCOPE.replace(SUB, OTHER)
        if mutation == 'conflicting_capture': extra['kind'] = native.QUERY_KIND;extra['capture_id'] = '0' * 32
        bindings.append(extra)
    changed = make_snapshot('azure', [SCOPE], snapshot['collections'], metadata=metadata)
    assert {f['status'] for f in evaluate_snapshot(changed, checks=[consumer.IDS[0]])['findings']} == {'UNKNOWN'}


def test_unknown_kinds_do_not_trigger_metadata_reads(monkeypatch):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    assert runtime.collect_into(reader, transport, [SCOPE], ['storage_account'], parent_metadata=metadata) == {}
    assert len(http.calls) == 1


def test_finish_rejects_existing_conflicting_stamp(monkeypatch):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    planned, bindings = runtime.jobs(reader, transport, [SCOPE], [native.NSP_KIND], parent_metadata=metadata)
    reader.run(planned);reader.collections[1]['_provenance'] = {'foreign': True}
    with pytest.raises(RuntimeError, match='provenance conflict'): runtime.finish(reader, bindings)


@pytest.mark.parametrize('check,kind', zip(consumer.IDS, native.KINDS))
def test_named_public_planner_requests_actual_subscription_dependency(monkeypatch, check, kind):
    required = plan_collection({'connector': {'provider': 'azure', 'scopes': [SUB],
        'auth': {'method': 'token', 'arm_token': TOKEN}}, 'checks': [check]})
    assert set(required) == {kind, 'subscription'}


@pytest.mark.parametrize('mutation', ['absent', 'denied', 'partial', 'foreign_id', 'foreign_tenant', 'disabled', 'missing_state', 'duplicate'])
def test_invalid_native_subscription_cannot_bootstrap_parent_context(monkeypatch, mutation):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    env = reader.collections[0];item = env['items'][0]
    if mutation == 'absent': reader.collections.clear()
    if mutation in ('denied', 'partial'): env['status'] = mutation
    if mutation == 'foreign_id': item['id'] = SCOPE.replace(SUB, OTHER)
    if mutation == 'foreign_tenant': item['tenantId'] = FOREIGN_TENANT
    if mutation == 'disabled': item['state'] = 'Disabled'
    if mutation == 'missing_state': item.pop('state')
    if mutation == 'duplicate': env['items'].append(deepcopy(item))
    with pytest.raises(runtime.ContextUnavailable):
        runtime.parent_metadata_from_inventory(reader, transport, [SCOPE],
            credential_context_id=metadata['credential_context_id'], customer_context_id=metadata['customer_context_id'])
    assert len(http.calls) == 1


@pytest.mark.parametrize('mode', ['denied', 'http206', 'duplicate_tenant', 'foreign_id', 'foreign_tenant', 'missing_state', 'disabled'])
def test_actual_subscription_http_rejects_untrusted_parent_before_adapter_reads(monkeypatch, mode):
    http = ParentHTTP();body = http.get(SCOPE, runtime.SUBSCRIPTION_VERSION)
    if mode == 'denied': http.put(SCOPE, runtime.SUBSCRIPTION_VERSION, 403)
    if mode == 'http206': http.status = 206
    if mode == 'duplicate_tenant':
        http.put(SCOPE, runtime.SUBSCRIPTION_VERSION, json.dumps(body).replace(
            '"tenantId": "' + TENANT + '"', '"tenantId": "' + FOREIGN_TENANT + '", "tenantId": "' + TENANT + '"').encode())
    if mode == 'foreign_id': body['id'] = SCOPE.replace(SUB, OTHER)
    if mode == 'foreign_tenant': body['tenantId'] = FOREIGN_TENANT
    if mode == 'missing_state': body.pop('state')
    if mode == 'disabled': body['state'] = 'Disabled'
    monkeypatch.setattr(azure, 'build_opener', lambda *a: http)
    reader = azure._Reader({'retries': 0, 'concurrency': 1, 'max_calls': 10})
    transport = azure.AzureTransport({'method': 'token', 'arm_token': TOKEN, 'tenant_id': TENANT})
    credential = uuid4().hex;customer = 'scan-local:' + credential
    reader.run([runtime.subscription_job(reader, transport, SCOPE,
        credential_context_id=credential, customer_context_id=customer)])
    with pytest.raises(runtime.ContextUnavailable):
        runtime.parent_metadata_from_inventory(reader, transport, [SCOPE],
            credential_context_id=credential, customer_context_id=customer)
    # Invalid dependency stays unresolved; no guessed tenant mapping is supplied.
    metadata = {'credential_context_id': credential, 'customer_context_id': customer,
                'context_binding': 'scan_local', 'tenant_id': TENANT, 'tenant_verified': bool(transport.verified_tenant)}
    patch = runtime.collect_into(reader, transport, [SCOPE], [native.NSP_KIND], parent_metadata=metadata)
    snapshot = make_snapshot('azure', [SCOPE], reader.collections, metadata={**metadata, **patch})
    assert {f['status'] for f in evaluate_snapshot(snapshot, checks=[consumer.IDS[0]])['findings']} == {'UNKNOWN'}
    assert len(http.calls) == 1


@pytest.mark.parametrize('max_calls,want', [(100, 'PASS'), (12, 'UNKNOWN')])
def test_nine_selected_subscriptions_use_shared_budget_without_truncation(monkeypatch, max_calls, want):
    http = ParentHTTP();template = deepcopy(http.routes);http.routes.clear()
    scopes = ['/subscriptions/' + f'{i:08x}-1111-1111-1111-111111111111' for i in range(1, 10)]
    for scope in scopes:
        sub = scope.rsplit('/', 1)[-1]
        for (path, version, token), body in template.items():
            http.put(path.replace(SUB, sub), version,
                     json.loads(json.dumps(body).replace(SUB, sub)), token)
    monkeypatch.setattr(azure, 'build_opener', lambda *a: http)
    reader = azure._Reader({'retries': 0, 'concurrency': 1, 'max_calls': max_calls, 'max_resources': 100})
    transport = azure.AzureTransport({'method': 'token', 'arm_token': TOKEN, 'tenant_id': TENANT})
    credential = uuid4().hex;customer = 'scan-local:' + credential
    reader.run([runtime.subscription_job(reader, transport, scope,
        credential_context_id=credential, customer_context_id=customer) for scope in scopes])
    metadata = runtime.parent_metadata_from_inventory(reader, transport, scopes,
        credential_context_id=credential, customer_context_id=customer)
    patch = runtime.collect_into(reader, transport, scopes, [native.NSP_KIND], parent_metadata=metadata)
    for c in reader.collections:
        c.setdefault('_provenance', {}).update(credential_context_id=credential, customer_context_id=customer)
        for item in c['items']: item.setdefault('_provenance', {}).update(credential_context_id=credential, customer_context_id=customer)
    snapshot = make_snapshot('azure', scopes, reader.collections, metadata={**metadata, **patch, **reader.metadata()})
    report = evaluate_snapshot(snapshot, checks=[consumer.IDS[0]])
    findings = report['findings']
    assert {f['status'] for f in findings} == {want}
    if want == 'PASS': assert len(findings) == 9
    else: assert set(findings[0]['evidence']['scopes']) == set(scopes)
    assert len([c for c in report['coverage'] if c.get('level') == 'collection' and c['type'] == native.NSP_KIND]) == 9
    assert len([c for c in snapshot['collections'] if c['type'] == native.NSP_KIND]) == 9
    assert reader.budget.calls == len(http.calls) <= max_calls


def test_unselected_kinds_ignore_historical_scope_limit_and_wildcard(monkeypatch):
    http = ParentHTTP();reader, transport, metadata = parent(monkeypatch, http)
    assert runtime.collect_into(reader, transport, ['*'] * 9, ['storage_account'], parent_metadata=metadata) == {}
    assert len(http.calls) == 1
