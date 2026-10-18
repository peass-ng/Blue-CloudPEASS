"""Documented location-scoped SQL LTR GETs reach the real CSPM evaluator."""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure, azure_sql_ltr_native as native, collect_live
from tests.test_peaso_azure_bulk_native import Transport, SCOPE, SUB, SQL, parent, routes
from tests.test_peaso_azure_sql_ltr_counterexample import CHECK, verdict

DATABASE = parent(SQL, 'Microsoft.Sql/servers/databases', {'status': 'Online'})
DATABASE['location'] = 'westeurope'
PATH = (SCOPE + '/providers/Microsoft.Sql/locations/westeurope/longTermRetentionServers/server'
        '/longTermRetentionDatabases/db/longTermRetentionBackups')


def backup(redundancy='Geo'):
    return parent(PATH + '/guid;131637960820000000;Hot', native.NATIVE_TYPE, {
        'serverName': 'server', 'databaseName': 'db', 'databaseDeletionTime': None,
        'backupStorageRedundancy': redundancy, 'unexpectedContent': 'private-marker'})


@pytest.mark.parametrize('mutation', ['foreign_subscription', 'foreign_location', 'foreign_server',
                                    'foreign_database', 'wrong_type', 'deleted', 'parent_shape',
                                    'wrong_server_property', 'wrong_database_property', 'duplicate'])
def test_native_projector_rejects_foreign_or_ambiguous_backup(mutation):
    row = backup()
    if mutation == 'foreign_subscription': row['id'] = row['id'].replace(SUB, 'foreign')
    if mutation == 'foreign_location': row['id'] = row['id'].replace('westeurope', 'eastus')
    if mutation == 'foreign_server': row['id'] = row['id'].replace('/server/', '/another/')
    if mutation == 'foreign_database': row['id'] = row['id'].replace('/db/', '/another/')
    if mutation == 'wrong_type': row['type'] = 'Microsoft.Sql/servers/databases'
    if mutation == 'deleted': row['properties']['databaseDeletionTime'] = '2026-01-01T00:00:00Z'
    if mutation == 'parent_shape': row['id'] = SQL + '/longTermRetentionBackups/copy'
    if mutation == 'wrong_server_property': row['properties']['serverName'] = 'foreign'
    if mutation == 'wrong_database_property': row['properties']['databaseName'] = 'foreign'
    with pytest.raises(ValueError):
        native.project([row, deepcopy(row)] if mutation == 'duplicate' else [row], DATABASE)


@pytest.mark.parametrize('location', [None, '', '../west', 'https://foreign'])
def test_missing_or_unsafe_native_location_never_guesses_endpoint(location):
    db = {**DATABASE, 'location': location}
    with pytest.raises(ValueError): native.binding(db)


@pytest.mark.parametrize('mode,expected', [('Geo', 'PASS'), ('GeoZone', 'PASS'),
                                         ('Local', 'FAIL'), ('Zone', 'FAIL'),
                                         ('denied', 'DENIED'), ('unknown', 'UNKNOWN'),
                                         ('empty', 'UNKNOWN'), ('foreign', 'UNKNOWN'),
                                         ('paged', 'PASS'), ('duplicate_pages', 'UNKNOWN'),
                                         ('partial', 'UNKNOWN'), ('missing_location', 'UNKNOWN'),
                                         ('native_zero', 'FAIL'), ('native_weekly', 'PASS'),
                                         ('invalid_duration', 'UNKNOWN')])
def test_public_collect_live_uses_native_route_and_engine(monkeypatch, mode, expected):
    server = SQL.rsplit('/databases/', 1)[0]
    responses = routes('sql_server', server, {})
    responses[server + '/databases'] = {'value': [deepcopy(DATABASE)]}
    if mode == 'missing_location': responses[server + '/databases']['value'][0].pop('location')
    responses[SQL + '/backupLongTermRetentionPolicies'] = {'value': [parent(
        SQL + '/backupLongTermRetentionPolicies/default',
        'Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies',
        {'weeklyRetention': 'P1W', 'monthlyRetention': 'P0M', 'yearlyRetention': 'P0Y'})]}
    if mode in ('native_zero', 'native_weekly', 'invalid_duration'):
        policy = responses[SQL + '/backupLongTermRetentionPolicies']['value'][0]['properties']
        policy.update(monthlyRetention='PT0S', yearlyRetention='PT0S')
        policy['weeklyRetention'] = {'native_zero': 'PT0S', 'native_weekly': 'P2W',
                                    'invalid_duration': 'PT1S'}[mode]
    row = backup(mode if mode in ('Geo', 'GeoZone', 'Local', 'Zone') else 'Geo' if mode.startswith('native_') or mode == 'invalid_duration' else 'unrecognized')
    if mode == 'foreign': row['id'] = row['id'].replace('/db/', '/different/')
    responses[PATH] = (azure.AzureReadError('denied', 403) if mode == 'denied'
                       else {'value': [] if mode == 'empty' else [row]})
    if mode in ('paged', 'duplicate_pages', 'partial'):
        first = backup()
        second = deepcopy(first)
        if mode == 'paged': second['id'] += '-second'
        def pages(query):
            if 'page' not in query:
                return {'value': [first], 'nextLink': azure.ARM + PATH + '?api-version=2023-08-01&page=2'}
            if mode == 'partial': raise azure.AzureReadError('denied', 403)
            return {'value': [second]}
        responses[PATH] = pages

    class ReadOnlyTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            assert body is None
            assert urlsplit(url).path != SQL + '/longTermRetentionBackups'
            return super().request(url, body=body, audience=audience)

    transport = ReadOnlyTransport(responses)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=transport))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}},
                            ['sql_database', 'sql_database_ltr_policy', 'sql_ltr_backup'])
    assert verdict(snapshot) == expected
    assert any(urlsplit(url).path == PATH and 'databaseState=Live' in url for url in transport.calls) == (mode != 'missing_location')
    assert 'private-marker' not in str(snapshot)


def test_native_projection_keeps_real_id_and_database_binding():
    row = backup()
    projected = native.project([row], DATABASE)[0]
    assert projected['id'] == row['id']
    assert projected['parent_id'] == SQL
    assert projected['_provenance']['request_path'] == PATH
    assert 'unexpectedContent' not in projected['properties']


@pytest.mark.parametrize('mutation', ['foreign_database', 'foreign_read_binding'])
def test_engine_cannot_rebind_native_geo_copy_to_another_database(mutation):
    from peaso.snapshot import make_snapshot
    copy = native.project([backup()], DATABASE)[0]
    if mutation == 'foreign_database':
        copy['id'] = copy['id'].replace('/db/', '/another/')
        copy['properties']['databaseName'] = 'another'
    else:
        copy['_provenance']['request_path'] += '-another'
    policy = parent(SQL + '/backupLongTermRetentionPolicies/default',
                    'Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies',
                    {'weeklyRetention': 'P1W', 'monthlyRetention': 'P0M', 'yearlyRetention': 'P0Y'})
    snapshot = make_snapshot('azure', [SCOPE], [
        {'type': 'sql_database', 'scope': SCOPE, 'status': 'collected', 'items': [deepcopy(DATABASE)]},
        {'type': 'sql_database_ltr_policy', 'scope': SCOPE, 'status': 'collected', 'items': [policy]},
        {'type': 'sql_ltr_backup', 'scope': SCOPE, 'status': 'collected', 'items': [copy]},
    ])
    assert verdict(snapshot) == 'UNKNOWN'


def test_short_term_backup_checks_do_not_enumerate_long_term_copy_history(monkeypatch):
    from tests.test_peaso_azure_bulk_native import fixture
    from peaso.engine import evaluate_snapshot
    responses, _, _ = fixture('sql_backup_short_term_policy')
    class ShortTermTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            assert body is None
            assert '/longTermRetentionBackups' not in url
            return super().request(url, body=body, audience=audience)
    transport = ShortTermTransport(responses)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=transport))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SUB], 'options': {'retries': 0}},
                            ['sql_database', 'sql_backup_short_term_policy'])
    check = 'azure_recovery_vault_10_3_3_1_1f42f66'
    findings = evaluate_snapshot(snapshot, checks=[check])['findings']
    assert len(findings) == 1 and findings[0]['status'] == 'PASS'
    assert any('backupShortTermRetentionPolicies' in url for url in transport.calls)
