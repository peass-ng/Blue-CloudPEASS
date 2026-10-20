"""Independent native response tests supplementing 133 directed prior proofs.

The SQL flag declarations use actual native engine versions and API list shapes;
no CASES or SQL_SPECS are imported as native positive evidence.
"""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate
from tests.test_peaso_collectors_gcp import FixtureTransport, connector
from tests.test_gcp_metadata_final_batch_review_20261020 import forbid_network_auth

SCOPE = 'projects/review-project'
SQL_LIST = 'https://sqladmin.googleapis.com/sql/v1beta4/projects/review-project/instances'
VERSIONS = {'POSTGRES': 'POSTGRES_16', 'MYSQL': 'MYSQL_8_0', 'SQLSERVER': 'SQLSERVER_2019_STANDARD'}

# Explicit reviewed source-policy variants; API flag omission is tested separately
# from current database runtime defaults. These are full native instance objects.
FLAGS = []
def flag(cid, engine, name, good, bad, absent, forbidden=False):
    FLAGS.append({'id': cid, 'engine': engine, 'flag': name, 'good': good, 'bad': bad, 'absent': absent, 'forbidden': forbidden})

for name in ('log_checkpoints', 'log_duration', 'log_hostname', 'log_lock_waits'):
    suffix = 'configured' if name == 'log_hostname' else 'on'
    flag('gcp.ports.sql_instance_postgresql_' + name + '_database_flag_' + suffix, 'POSTGRES', name, 'on', 'off', 'FAIL')
for name in ('log_executor_stats', 'log_parser_stats', 'log_planner_stats', 'log_statement_stats'):
    flag('gcp.ports.sql_instance_postgresql_' + name + '_database_flag_off', 'POSTGRES', name, 'off', 'on', 'FAIL')
for suffix, name, good, bad in [
    ('log_error_verbosity_database_flag_default_or_stricter', 'log_error_verbosity', 'verbose', 'terse'),
    ('log_min_duration_statement_database_flag_disabled', 'log_min_duration_statement', '-1', '0'),
    ('log_min_error_statement_database_flag_configured', 'log_min_error_statement', 'error', None),
    ('log_min_messages_database_flag_error', 'log_min_messages', 'warning', 'debug1'),
    ('log_temp_files_database_flag_0', 'log_temp_files', '0', '-1'),
]:
    flag('gcp.ports.sql_instance_postgresql_' + suffix, 'POSTGRES', name, good, bad, 'FAIL')
for name in ('contained database authentication', 'cross db ownership chaining', 'external scripts enabled', 'remote access'):
    flag('gcp.ports.sql_instance_sql_' + name.replace(' ', '_') + '_database_flag_off', 'SQLSERVER', name, 'off', 'on', 'FAIL')
flag('gcp.ports.sql_instance_sql_3625_trace_database_flag_on', 'SQLSERVER', '3625 (trace flag)', 'on', 'off', 'FAIL')
flag('gcp.ports.sql_instance_sql_user_connections_database_flag_configured', 'SQLSERVER', 'user connections', '0', None, 'FAIL')
flag('gcp.ports.sql_instance_sql_user_options_database_flag_not_configured', 'SQLSERVER', 'user options', None, '1', 'PASS', True)
for suffix, name, good, bad, absent in [
    ('pg_min_duration', 'log_min_duration_statement', '-1', '0', 'PASS'),
    ('pg_min_error', 'log_min_error_statement', 'error', 'panic', 'PASS'),
    ('pg_min_messages', 'log_min_messages', 'warning', 'debug1', 'FAIL'),
]:
    flag('gcp.ports.reference_sql_' + suffix, 'POSTGRES', name, good, bad, absent)
for name in ('contained database authentication', 'cross db ownership chaining', 'external scripts enabled', 'remote access'):
    flag('gcp.ports.reference_sqlserver_' + name.replace(' ', '_'), 'SQLSERVER', name, 'off', 'on', 'FAIL' if name == 'remote access' else 'PASS')
for suffix, name, good, bad, absent in [('trace3625', '3625 (trace flag)', 'on', 'off', 'FAIL'), ('user_connections', 'user connections', '0', '10', 'PASS'), ('user_options', 'user options', None, '1', 'PASS')]:
    flag('gcp.ports.reference_sqlserver_' + suffix, 'SQLSERVER', name, good, bad, absent)
for suffix, engine, name, good, bad in [
    ('mysql_local_infile', 'MYSQL', 'local_infile', 'off', 'on'),
    ('mysql_skip_show_database', 'MYSQL', 'skip_show_database', 'on', 'off'),
    ('postgres_log_connections', 'POSTGRES', 'log_connections', 'on', 'off'),
    ('postgres_log_disconnections', 'POSTGRES', 'log_disconnections', 'on', 'off'),
    ('postgres_log_statement', 'POSTGRES', 'log_statement', 'ddl', 'none'),
    ('postgres_log_error_verbosity', 'POSTGRES', 'log_error_verbosity', 'default', 'terse'),
    ('postgres_pgaudit', 'POSTGRES', 'cloudsql.enable_pgaudit', 'on', 'off'),
]:
    flag('gcp.reviewed.sql.' + suffix, engine, name, good, bad, 'UNKNOWN')


def collect_sql(item, *, denied=False, partial=False):
    original = deepcopy(item)
    def resolve(request):
        parsed = urlsplit(request['url'])
        assert request['method'] == 'GET' and parsed.scheme == 'https'
        assert parsed.hostname == 'sqladmin.googleapis.com' and not parsed.query and not parsed.fragment
        if request['url'] == SQL_LIST:
            if denied or partial and (request.get('params') or {}).get('pageToken'):
                raise gcp.ReadError('denied', 'permission_denied', http_status=403)
            return {'kind': 'sql#instancesList', 'items': [deepcopy(item)], **({'nextPageToken': 'next-page'} if partial else {})}
        assert request['url'] == SQL_LIST + '/native-db/users'
        return {'kind': 'sql#usersList', 'items': []}
    class Transport(FixtureTransport):
        def request(self, method, url, **kwargs):
            try: return super().request(method, url, **kwargs)
            finally: self.evidence[-1]['scope'] = kwargs['scope']
    api = Transport(resolve)
    captured = gcp.GCPCollector(connector(['sql_instance'], scopes=[SCOPE], metrics_scopes=False), transport=api).collect()
    assert validate(captured) == captured and item == original
    return captured, api


def sql_item(spec, scenario):
    value = spec['bad'] if scenario == 'bad' else spec['good']
    flags = [] if value is None or scenario == 'omitted' else [{'name': spec['flag'], 'value': value}]
    if scenario == 'duplicate': flags = [{'name': spec['flag'], 'value': spec['good'] or '0'}] * 2
    version = VERSIONS[spec['engine']]
    if scenario == 'other-engine': version = 'MYSQL_8_0' if spec['engine'] != 'MYSQL' else 'POSTGRES_16'
    item = {'kind': 'sql#instance', 'name': 'native-db', 'project': 'review-project', 'region': 'us-central1',
            'databaseVersion': version, 'instanceType': 'CLOUD_SQL_INSTANCE', 'settings': {'databaseFlags': flags}}
    if scenario == 'denied-field': item['settings']['_coverage'] = {'databaseFlags': {'status': 'denied'}}
    return item


@pytest.mark.parametrize('spec', FLAGS, ids=[x['id'] for x in FLAGS])
@pytest.mark.parametrize('scenario', ['good', 'bad', 'omitted', 'denied', 'denied-field', 'duplicate', 'other-engine', 'partial'])
def test_native_sql_flag_configuration(spec, scenario):
    captured, api = collect_sql(sql_item(spec, scenario), denied=scenario == 'denied', partial=scenario == 'partial')
    before = deepcopy(captured)
    rows = evaluate_snapshot(captured, checks=[spec['id']])['findings']
    assert before == captured
    resources = [r for r in rows if 'native_resource_id' in r]
    expected = {'good': 'PASS', 'bad': 'FAIL', 'omitted': spec['absent'], 'denied': 'DENIED', 'denied-field': 'UNKNOWN', 'duplicate': 'UNKNOWN', 'other-engine': 'NOT_APPLICABLE', 'partial': 'PASS'}[scenario]
    if scenario == 'denied': assert not resources and rows[0]['status'] == expected, rows
    else: assert len(resources) == 1 and resources[0]['status'] == expected, rows
    if scenario == 'partial': assert any(r['status'] == 'UNKNOWN' and r['evidence'].get('collection_status') == 'partial' for r in rows), rows


@pytest.mark.parametrize('cid', ['gcp.ports.reference_sql_ssl_connections', 'gcp.ports.sql_instance_require_ssl_enabled'])
@pytest.mark.parametrize('mode,legacy,expected', [
    ('ENCRYPTED_ONLY', False, 'PASS'), ('ALLOW_UNENCRYPTED_AND_ENCRYPTED', False, 'FAIL'),
    ('TRUSTED_CLIENT_CERTIFICATE_REQUIRED', True, 'PASS'), ('ENCRYPTED_ONLY', True, 'UNKNOWN'),
    ('FUTURE_MODE', None, 'UNKNOWN'), (None, None, 'UNKNOWN'),
])
def test_native_ssl_mode_and_legacy_combination(cid, mode, legacy, expected):
    config = {}
    if mode is not None: config['sslMode'] = mode
    if legacy is not None: config['requireSsl'] = legacy
    item = {'kind': 'sql#instance', 'name': 'native-db', 'project': 'review-project', 'databaseVersion': 'POSTGRES_16', 'settings': {'ipConfiguration': config}}
    captured, api = collect_sql(item)
    rows = evaluate_snapshot(captured, checks=[cid])['findings']
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


def collect_native_service(kind, item, *, denied=False):
    if kind == 'bigquery_dataset':
        endpoint = 'https://bigquery.googleapis.com/bigquery/v2/' + SCOPE + '/datasets'
        routes = {endpoint: {'datasets': [{'datasetReference': {'projectId': 'review-project', 'datasetId': 'native_dataset'}}]},
                  endpoint + '/native_dataset': {'id': 'review-project:native_dataset', 'datasetReference': {'projectId': 'review-project', 'datasetId': 'native_dataset'}, **deepcopy(item)}}
        target = endpoint + '/native_dataset'
    elif kind == 'workload_identity_provider':
        pool = SCOPE + '/locations/global/workloadIdentityPools/native-pool'
        endpoint = 'https://iam.googleapis.com/v1/' + SCOPE + '/locations/global/workloadIdentityPools'
        routes = {endpoint: {'workloadIdentityPools': [{'name': pool, 'state': 'ACTIVE'}]},
                  'https://iam.googleapis.com/v1/' + pool + '/providers': {'workloadIdentityPoolProviders': [
                      {'name': pool + '/providers/native', 'state': 'ACTIVE', 'attributeMapping': {'google.subject': 'assertion.sub'}, **deepcopy(item)}]}}
        target = 'https://iam.googleapis.com/v1/' + pool + '/providers'
    elif kind == 'secret':
        name = SCOPE + '/secrets/native-secret'
        endpoint = 'https://secretmanager.googleapis.com/v1/' + SCOPE + '/secrets'
        routes = {endpoint: {'secrets': [{'name': name, 'replication': {'automatic': {}}, **deepcopy(item)}]},
                  'https://secretmanager.googleapis.com/v1/' + name + ':getIamPolicy': {'bindings': []}}
        target = endpoint
    else: raise AssertionError(kind)
    def resolve(request):
        parsed = urlsplit(request['url'])
        assert request['method'] == 'GET' and parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        assert request['url'] in routes, request['url']
        if denied and request['url'] == target: raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        if request['url'].endswith('/native_dataset'):
            assert request['params'] == {'accessPolicyVersion': 3, 'datasetView': 'FULL'}
        return deepcopy(routes[request['url']])
    class Transport(FixtureTransport):
        def request(self, method, url, **kwargs):
            try: return super().request(method, url, **kwargs)
            finally: self.evidence[-1]['scope'] = kwargs['scope']
    api = Transport(resolve)
    captured = gcp.GCPCollector(connector([kind], scopes=[SCOPE], metrics_scopes=False), transport=api).collect()
    assert validate(captured) == captured
    return captured, api


DATASET_DOMAINS = [
    ('gcp.claude.bigquery_dataset.no_gmail_access', {'userByEmail': 'operator@gmail.com'}, 'FAIL'),
    ('gcp.claude.bigquery_dataset.no_gmail_access', {'userByEmail': 'operator@notgmail.com'}, 'PASS'),
    ('gcp.claude.bigquery_dataset.no_gmail_access', {'userByEmail': 'operator@corp.example'}, 'PASS'),
    ('gcp.claude.bigquery_dataset.no_googlegroups_access', {'groupByEmail': 'operators@googlegroups.com'}, 'FAIL'),
    ('gcp.claude.bigquery_dataset.no_googlegroups_access', {'groupByEmail': 'operators@corp.example'}, 'PASS'),
]
@pytest.mark.parametrize('cid,entry,expected', DATASET_DOMAINS, ids=[r[0] + '-' + next(iter(r[1].values())) for r in DATASET_DOMAINS])
def test_native_dataset_consumer_domain_principal_shape(cid, entry, expected):
    captured, api = collect_native_service('bigquery_dataset', {'access': [{'role': 'READER', **entry}]})
    rows = evaluate_snapshot(captured, checks=[cid])['findings']
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


WIF = 'gcp.claude.workload_identity_provider.multi_tenant_condition'
@pytest.mark.parametrize('condition,expected', [
    ("assertion.repository_owner == 'review-owner'", 'PASS'),
    ('true', 'FAIL'),
    ("assertion.repository_owner == 'review-owner' || true", 'FAIL'),
    ('', 'FAIL'),
])
def test_native_multi_tenant_condition_does_not_accept_tautology(condition, expected):
    captured, api = collect_native_service('workload_identity_provider', {'oidc': {'issuerUri': 'https://token.actions.githubusercontent.com'}, 'attributeCondition': condition})
    rows = evaluate_snapshot(captured, checks=[WIF])['findings']
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


@pytest.mark.parametrize('kind,cid', [('bigquery_dataset', 'gcp.claude.bigquery_dataset.no_gmail_access'), ('workload_identity_provider', WIF), ('secret', 'gcp.claude.secret.rotation_90_days')])
def test_service_native_read_denial_never_passes(kind, cid):
    captured, api = collect_native_service(kind, {}, denied=True)
    rows = evaluate_snapshot(captured, checks=[cid])['findings']
    assert rows and all(row['status'] in ('UNKNOWN', 'DENIED') for row in rows), rows


def test_secret_rotation_read_does_not_invent_input_only_period():
    captured, api = collect_native_service('secret', {'rotation': {'nextRotationTime': '2026-11-01T00:00:00Z'}, 'topics': [{'name': SCOPE + '/topics/rotate'}]})
    rows = evaluate_snapshot(captured, checks=['gcp.claude.secret.rotation_90_days'])['findings']
    assert len(rows) == 1 and rows[0]['status'] == 'UNKNOWN', rows


ALLOY = [
    ('gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter', 'log_error_verbosity', 'verbose', 'terse'),
    ('gcp.ports.alloydb_instance_log_min_messages_database_flag_error', 'log_min_messages', 'warning', 'debug1'),
    ('gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured', 'log_min_error_statement', 'error', None),
    ('gcp.ports.alloydb_cluster_encrypted_with_cmk', None, 'CUSTOMER_MANAGED_ENCRYPTION', 'GOOGLE_DEFAULT_ENCRYPTION'),
]


@pytest.mark.parametrize('cid,flag_name,good,bad', ALLOY, ids=[r[0] for r in ALLOY])
@pytest.mark.parametrize('scenario', ['good', 'bad', 'omitted', 'denied', 'wrong-shape'])
def test_native_alloydb_map_and_encryption_enum(cid, flag_name, good, bad, scenario):
    cluster = SCOPE + '/locations/us-central1/clusters/native'
    endpoint = 'https://alloydb.googleapis.com/v1/' + SCOPE + '/locations/us-central1/clusters'
    value = bad if scenario == 'bad' else good
    native_cluster = {'name': cluster, 'state': 'READY', 'databaseVersion': 'POSTGRES_16'}
    native_instance = {'name': cluster + '/instances/primary', 'instanceType': 'PRIMARY', 'state': 'READY'}
    if flag_name:
        if scenario != 'omitted':
            native_instance['databaseFlags'] = [] if scenario == 'wrong-shape' else ({} if value is None else {flag_name: value})
    elif scenario != 'omitted':
        native_cluster['encryptionInfo'] = {'encryptionType': 'FUTURE_TYPE' if scenario == 'wrong-shape' else value}
    target = endpoint + '/native/instances' if flag_name else endpoint
    routes = {endpoint: {'clusters': [native_cluster]}, endpoint + '/native/instances': {'instances': [native_instance]}}
    def resolve(request):
        parsed = urlsplit(request['url'])
        assert request['method'] == 'GET' and parsed.scheme == 'https' and parsed.hostname == 'alloydb.googleapis.com'
        assert not parsed.query and not parsed.fragment and request['url'] in routes
        assert 'databaseFlags' in request['params']['fields'] if request['url'].endswith('/instances') else 'encryptionInfo' in request['params']['fields']
        if scenario == 'denied' and request['url'] == target:
            raise gcp.ReadError('denied', 'permission_denied', http_status=403)
        return deepcopy(routes[request['url']])
    class Transport(FixtureTransport):
        def request(self, method, url, **kwargs):
            try: return super().request(method, url, **kwargs)
            finally: self.evidence[-1]['scope'] = kwargs['scope']
    api = Transport(resolve)
    kind = 'alloydb_instance' if flag_name else 'alloydb_cluster'
    captured = gcp.GCPCollector(connector([kind], scopes=[SCOPE], metrics_scopes=False, alloydb_locations=['us-central1']), transport=api).collect()
    assert validate(captured) == captured
    rows = evaluate_snapshot(captured, checks=[cid])['findings']
    expected = {'good': 'PASS', 'bad': 'FAIL', 'omitted': 'UNKNOWN', 'denied': 'DENIED', 'wrong-shape': 'UNKNOWN'}[scenario]
    assert len(rows) == 1 and rows[0]['status'] == expected, rows


@pytest.mark.parametrize('mode,expected', [('fixable', 'FAIL'), ('no_fix', 'PASS'), ('report_denied', 'UNKNOWN'),
                                         ('nanosecond_future', 'UNKNOWN'), ('foreign_project_metadata', 'UNKNOWN'), ('report_partial', 'UNKNOWN')])
def test_native_osconfig_assessment_engine_projection(mode, expected):
    from tests.test_gcp_os_security_update_review_20261019 import native_case
    captured, _, _, _, _ = native_case(mode)
    rows = evaluate_snapshot(captured, checks=['gcp.compute.os_config_fixable_vulnerabilities'])['findings']
    resources = [row for row in rows if 'native_resource_id' in row]
    assert len(resources) == 1 and resources[0]['status'] == expected, rows
