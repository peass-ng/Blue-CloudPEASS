"""Provider-owned fixtures for the read-only compliance collection wave."""
import json
import pytest

from peaso.collectors.gcp import ReadError
from tests.test_peaso_collectors_gcp import snapshot, collection

SCOPE = 'projects/p-one'
KEY = SCOPE + '/locations/global/keyRings/r/cryptoKeys/k'


def test_kms_versions_pages_parent_join_and_conflicts():
    def resolve(request):
        url = request['url']
        if url.endswith('/keyRings'):
            return {'keyRings': [{'name': KEY.rsplit('/cryptoKeys/', 1)[0]}]}
        if url.endswith('/cryptoKeys'):
            return {'cryptoKeys': [{'name': KEY}]}
        if url.endswith(':getIamPolicy'):
            return {}
        if url.endswith('/cryptoKeyVersions'):
            page = request['params'].get('pageToken')
            return {'cryptoKeyVersions': [{'name': KEY + '/cryptoKeyVersions/' + ('2' if page else '1'),
                    'state': 'ENABLED', 'algorithm': 'GOOGLE_SYMMETRIC_ENCRYPTION'}],
                    **({} if page else {'nextPageToken': 'more'})}
        return {}
    result, transport = snapshot(['kms_key', 'kms_key_version'], resolve, kms_locations=['global'])
    rows = collection(result, 'kms_key_version')
    assert rows['coverage_status'] == 'collected' and len(rows['items']) == 2
    assert all(row['_provenance']['scope'] == SCOPE for row in rows['items'])
    assert sum(r['url'].endswith('/cryptoKeyVersions') for r in transport.requests) == 2


def test_sql_users_reused_and_composite_hosts_and_secrets_removed():
    def resolve(request):
        if request['url'].endswith('/instances'):
            return {'items': [{'name': 'db', 'databaseVersion': 'MYSQL_8_0',
                             'settings': {'passwordValidationPolicy': {'enablePasswordPolicy': True,
                                                                       'failedAttemptsCheck': True}}}]}
        assert request['url'].endswith('/db/users')
        return {'items': [{'name': 'root', 'host': host, 'type': 'BUILT_IN', 'password': 'never-retain'}
                          for host in ('%', 'localhost')]}
    result, transport = snapshot(['sql_instance', 'sql_user'], resolve)
    users = collection(result, 'sql_user')
    assert len(users['items']) == 2 and users['coverage_status'] == 'collected'
    instance = collection(result, 'sql_instance')['items'][0]
    assert instance['usersList']['status'] == 'collected'
    assert instance['usersList']['instance'] == 'db'
    assert [x['name'] for x in instance['usersList']['items']] == ['root', 'root']
    assert len(transport.requests) == 2
    assert 'never-retain' not in json.dumps(result)


@pytest.mark.parametrize('kind,key,option', [
    ('logging_bucket', 'buckets', 'logging_locations'),
    ('certificate', 'certificates', 'certificate_locations'),
    ('cloud_asset', 'results', None),
    ('service_usage', 'services', None),
    ('autoscaler', 'items', 'autoscaler_regions'),
])
@pytest.mark.parametrize('mode,expected', [('complete', 'collected'), ('empty', 'empty'),
    ('paginated', 'collected'), ('error', 'denied'), ('partial', 'partial'),
    ('repeated', 'partial'), ('malformed', 'malformed'), ('limit', 'partial')])
def test_project_inventories_complete_empty_pagination_failures(kind, key, option, mode, expected):
    def resolve(request):
        if request['url'].endswith('/aggregated/instanceGroupManagers'):
            return {}
        assert request['method'] == 'GET'
        if mode == 'error' or mode == 'partial' and request['params'].get('pageToken'):
            raise ReadError('denied', 'fixture_denial')
        if mode == 'malformed':
            return {key: [42]}
        if mode == 'empty':
            return {key: []}
        page = request['params'].get('pageToken')
        row = {'name': f'{SCOPE}/locations/global/{key}/' + ('two' if page else 'one'),
               'retentionDays': 365, 'expireTime': '2030-01-01T00:00:00Z',
               'managed': {'state': 'ACTIVE'}, 'assetType': 'compute.googleapis.com/Instance',
               'location': 'global', 'state': 'ENABLED'}
        more = mode in ('paginated', 'partial', 'repeated', 'limit') and (not page or mode == 'repeated')
        return {key: [row], **({'nextPageToken': 'more'} if more else {})}
    options = {option: ['global']} if option else {}
    if mode == 'limit':
        options['max_pages'] = 1
    result, transport = snapshot([kind], resolve, **options)
    envelope = collection(result, kind)
    assert envelope['coverage_status'] == expected
    assert envelope['scope'] == SCOPE
    if expected == 'collected':
        assert len(envelope['items']) == (2 if mode == 'paginated' else 1)
        assert all(x['_provenance']['source_requests'] for x in envelope['items'])
    if kind == 'cloud_asset' and envelope['items']:
        assert envelope['items'][0]['labels'] == {}
    if kind == 'service_usage':
        assert all('filter' not in r['params'] and r['params']['pageSize'] <= 200 for r in transport.requests)


def test_sql_failed_child_remains_unknown_and_partial_user_inventory():
    def resolve(request):
        if request['url'].endswith('/instances'):
            return {'items': [{'name': 'a', 'databaseVersion': 'POSTGRES_15'},
                              {'name': 'b', 'databaseVersion': 'MYSQL_8_0'}]}
        if '/b/users' in request['url']:
            raise ReadError('denied', 'fixture_denial')
        return {'items': [{'name': 'reader', 'type': 'CLOUD_IAM_USER'}]}
    result, _ = snapshot(['sql_instance', 'sql_user'], resolve)
    assert collection(result, 'sql_user')['coverage_status'] == 'partial'
    instances = collection(result, 'sql_instance')['items']
    assert next(x for x in instances if x['name'] == 'b')['usersList']['status'] == 'denied'


def test_https_reuses_aggregated_inventory_and_unique_policy_reads():
    policy = SCOPE + '/locations/global/serverTlsPolicies/p'
    def resolve(request):
        if request['url'].endswith('/aggregated/targetHttpsProxies'):
            return {'items': {'regions/europe-west1': {'targetHttpsProxies': [
                {'name': 'https', 'serverTlsPolicy': policy}]}}}
        if request['url'].endswith('/serverTlsPolicies/p'):
            return {'name': policy, 'mtlsPolicy': {'clientValidationMode': 'REJECT_INVALID'}}
        return {}
    result, transport = snapshot(['target_proxy', 'target_https_proxy', 'server_tls_policy'], resolve)
    row = collection(result, 'target_https_proxy')['items'][0]
    assert row['_provenance']['representation'] == 'full'
    assert row['_aggregated_scope'] == 'regions/europe-west1'
    assert collection(result, 'server_tls_policy')['coverage_status'] == 'collected'
    assert sum(r['url'].endswith('/aggregated/targetHttpsProxies') for r in transport.requests) == 1


@pytest.mark.parametrize('kind', ['logging_bucket', 'certificate', 'autoscaler'])
def test_unresolved_location_coverage_is_unavailable(kind):
    result, _ = snapshot([kind], lambda _: {})
    assert collection(result, kind)['coverage_status'] == 'unavailable'


def test_owner_policy_is_preserved_explicitly_and_snapshot_has_capture_time():
    policy = {'status': 'collected', 'scope': SCOPE, 'approved_locations': []}
    result, _ = snapshot(['cloud_asset'], lambda _: {}, sw09_policy=policy, MinRetentionTime=400)
    assert result['metadata']['sw09_policy'] == policy
    assert result['metadata']['MinRetentionTime'] == 400 and result['created_at']


@pytest.mark.parametrize('policy', [{'status': 'collected', 'scope': 'projects/foreign'},
    {'status': 'collected', 'scope': SCOPE, 'approved_locations': ['global', 'global']}])
def test_owner_policy_validation(policy):
    with pytest.raises(ValueError):
        snapshot(['cloud_asset'], lambda _: {}, sw09_policy=policy)


@pytest.mark.parametrize('mode,expected', [('empty', 'empty'), ('denied', 'denied'),
    ('partial', 'partial'), ('conflict', 'partial'), ('foreign', 'malformed'),
    ('parent_partial', 'unavailable')])
def test_kms_versions_failure_and_empty_semantics(mode, expected):
    def resolve(request):
        url = request['url']
        page = request['params'].get('pageToken')
        if url.endswith('/keyRings'):
            return {'keyRings': [{'name': KEY.rsplit('/cryptoKeys/', 1)[0]}]}
        if url.endswith('/cryptoKeys'):
            if page:
                raise ReadError('denied', 'fixture_denial')
            return {'cryptoKeys': [{'name': KEY}],
                    **({'nextPageToken': 'more'} if mode == 'parent_partial' else {})}
        if url.endswith(':getIamPolicy'):
            return {}
        if mode == 'empty':
            return {}
        if mode == 'denied' or mode == 'partial' and page:
            raise ReadError('denied', 'fixture_denial')
        name = KEY + '/cryptoKeyVersions/1' if mode != 'foreign' else 'projects/foreign/versions/1'
        return {'cryptoKeyVersions': [{'name': name, 'state': 'DISABLED' if page else 'ENABLED'}],
                **({'nextPageToken': 'more'} if mode in ('partial', 'conflict') and not page else {})}
    result, transport = snapshot(['kms_key_version'], resolve, kms_locations=['global'])
    assert collection(result, 'kms_key_version')['coverage_status'] == expected
    if mode == 'parent_partial':
        assert not any(r['url'].endswith('/cryptoKeyVersions') for r in transport.requests)


@pytest.mark.parametrize('mode,expected', [('empty', 'empty'), ('denied', 'denied'),
    ('paginated', 'collected'), ('partial', 'partial')])
def test_sql_users_empty_pagination_denial(mode, expected):
    def resolve(request):
        if request['url'].endswith('/instances'):
            return {'items': [{'name': 'db', 'databaseVersion': 'MYSQL_8_0'}]}
        page = request['params'].get('pageToken')
        if mode == 'denied' or mode == 'partial' and page:
            raise ReadError('denied', 'fixture_denial')
        if mode == 'empty':
            return {}
        return {'items': [{'name': 'second' if page else 'first', 'host': '%', 'type': 'BUILT_IN'}],
                **({'nextPageToken': 'more'} if not page else {})}
    result, _ = snapshot(['sql_instance', 'sql_user'], resolve)
    assert collection(result, 'sql_user')['coverage_status'] == expected
    if mode == 'empty':
        assert collection(result, 'sql_instance')['items'][0]['usersList']['status'] == 'collected'


@pytest.mark.parametrize('mode,expected', [('empty', 'empty'), ('denied', 'denied'),
    ('partial', 'partial'), ('paginated', 'collected')])
def test_https_proxy_collection_and_policy_failure(mode, expected):
    policy = SCOPE + '/locations/global/serverTlsPolicies/p'
    def resolve(request):
        if request['url'].endswith('/serverTlsPolicies/p'):
            raise ReadError('denied', 'fixture_denial')
        if request['url'].endswith('/aggregated/targetHttpsProxies'):
            page = request['params'].get('pageToken')
            if mode == 'denied' or mode == 'partial' and page:
                raise ReadError('denied', 'fixture_denial')
            if mode == 'empty':
                return {}
            return {'items': {'global': {'targetHttpsProxies': [
                {'name': 'two' if page else 'one', 'serverTlsPolicy': policy}]}},
                **({'nextPageToken': 'more'} if not page else {})}
        return {}
    result, _ = snapshot(['target_proxy', 'target_https_proxy', 'server_tls_policy'], resolve)
    # An incomplete supporting proxy inventory prevents a complete alias assertion.
    alias = collection(result, 'target_https_proxy')
    assert alias['coverage_status'] == ('unavailable' if mode in ('denied', 'partial') else expected)
    assert collection(result, 'target_proxy')['coverage_status'] == expected
    assert collection(result, 'server_tls_policy')['coverage_status'] == (
        'empty' if mode == 'empty' else 'denied' if mode == 'paginated' else 'unavailable')


def test_two_locations_retains_success_when_other_location_denied():
    def resolve(request):
        if '/locations/blocked/' in request['url']:
            raise ReadError('denied', 'fixture_denial')
        return {'buckets': [{'name': SCOPE + '/locations/global/buckets/b', 'retentionDays': 365}]}
    result, _ = snapshot(['logging_bucket'], resolve, logging_locations=['global', 'blocked'])
    assert collection(result, 'logging_bucket')['coverage_status'] == 'partial'


def test_artifact_cleanup_fields_are_full_and_owner_records_match_evaluator():
    def resolve(request):
        if request['url'].endswith(':getIamPolicy'):
            return {}
        return {'repositories': [{'name': SCOPE + '/locations/global/repositories/r',
            'cleanupPolicies': {'cleanup': {'action': 'DELETE', 'condition': {'olderThan': '86400s'}}},
            'cleanupPolicyDryRun': False}]}
    topology = [{'kind': 'network', 'name': 'self-link'}]
    roster = [{'resource': SCOPE, 'role': 'roles/viewer', 'principal': 'user:owner@example.com', 'approved': True}]
    result, _ = snapshot(['artifact_repository'], resolve, artifactregistry_locations=['global'],
        sw09_policy={'status': 'collected', 'scope': SCOPE, 'topology_register': topology, 'approved_iam_roster': roster})
    row = collection(result, 'artifact_repository')['items'][0]
    assert row['_provenance']['representation'] == 'full' and row['cleanupPolicyDryRun'] is False
    assert result['metadata']['sw09_policy']['topology_register'] == topology


def test_server_tls_policy_partial_and_deduplicated_refs():
    def resolve(request):
        url = request['url']
        if url.endswith('/aggregated/targetHttpsProxies'):
            return {'items': {'global': {'targetHttpsProxies': [
                {'name': str(i), 'serverTlsPolicy': SCOPE + '/locations/global/serverTlsPolicies/' + policy}
                for i, policy in enumerate(('a', 'a', 'b'))]}}}
        if url.endswith('/serverTlsPolicies/a'):
            return {'name': SCOPE + '/locations/global/serverTlsPolicies/a',
                    'mtlsPolicy': {'clientValidationMode': 'REJECT_INVALID'}}
        if url.endswith('/serverTlsPolicies/b'):
            raise ReadError('denied', 'fixture_denial')
        return {}
    result, transport = snapshot(['server_tls_policy'], resolve)
    assert collection(result, 'server_tls_policy')['coverage_status'] == 'partial'
    assert sum(r['url'].endswith('/serverTlsPolicies/a') for r in transport.requests) == 1


def test_location_discovery_follows_pages_before_listing_each_location():
    def resolve(request):
        if request['url'].endswith('/locations'):
            page = request['params'].get('pageToken')
            return {'locations': [{'locationId': 'europe-west1' if page else 'global'}],
                    **({} if page else {'nextPageToken': 'more'})}
        location = request['url'].split('/locations/')[1].split('/')[0]
        return {'buckets': [{'name': SCOPE + '/locations/' + location + '/buckets/b', 'retentionDays': 400}]}
    result, transport = snapshot(['logging_bucket'], resolve)
    assert collection(result, 'logging_bucket')['coverage_status'] == 'collected'
    assert len(collection(result, 'logging_bucket')['items']) == 2 and len(transport.requests) == 4


def test_foreign_location_identity_fails_closed():
    result, _ = snapshot(['certificate'], lambda _: {'certificates': [{'name': 'projects/foreign/locations/global/certificates/c'}]},
                         certificate_locations=['global'])
    assert collection(result, 'certificate')['coverage_status'] == 'malformed'
