"""Native retention violations do not require unrelated restore-point history."""
import pytest

from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_bulk_native import Transport, SCOPE, SUB, SQL, fixture

CHECK = 'azure_recovery_vault_10_3_3_8_26e08d7'


def verdict(snapshot):
    findings = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)['findings']
    assert len(findings) == 1
    return findings[0]['status']


def capture(days, *, history='not_collected', primary='collected', policy='collected', minimum=14):
    return make_snapshot('azure', [SCOPE], [
        {'type': 'sql_database', 'scope': SCOPE, 'status': primary,
         'items': [{'id': SQL, 'properties': {'status': 'Online'}}] if primary != 'denied' else []},
        {'type': 'sql_backup_short_term_policy', 'scope': SCOPE, 'status': policy,
         'items': [{'id': SQL + '/backupShortTermRetentionPolicies/default',
                    'properties': {'retentionDays': days}}] if policy != 'denied' else []},
        {'type': 'sql_restore_point', 'scope': SCOPE, 'status': history, 'items': []},
    ], metadata={'compliance_policy': {'sw31': {'minRetentionDays': minimum, 'backupWindowDays': 7}}})


@pytest.mark.parametrize('days,history,expected', [
    (0, 'not_collected', 'FAIL'), (7, 'not_collected', 'FAIL'),
    (7, 'denied', 'FAIL'), (14, 'not_collected', 'UNKNOWN'),
    (14, 'denied', 'DENIED'), (True, 'not_collected', 'UNKNOWN'),
])
def test_retention_violation_survives_missing_history(days, history, expected):
    assert verdict(capture(days, history=history)) == expected


@pytest.mark.parametrize('field,state,expected', [
    ('primary', 'partial', 'UNKNOWN'), ('primary', 'denied', 'DENIED'),
    ('policy', 'partial', 'UNKNOWN'), ('policy', 'denied', 'DENIED'),
])
def test_incomplete_authoritative_retention_never_proves_failure(field, state, expected):
    assert verdict(capture(0, **{field: state})) == expected


@pytest.mark.parametrize('minimum', [True, -1])
def test_invalid_requirements_cannot_create_failure(minimum):
    assert verdict(capture(0, minimum=minimum)) == 'UNKNOWN'


def test_actual_readonly_collection_reports_known_bad_retention(monkeypatch):
    routes, path, rows = fixture('sql_backup_short_term_policy')
    rows[0]['properties']['retentionDays'] = 0
    routes[SQL + '/restorePoints'] = azure.AzureReadError('denied', 403)

    class ReadOnlyTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            assert body is None
            return super().request(url, body=body, audience=audience)

    transport = ReadOnlyTransport(routes)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=transport))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SUB], 'options': {
        'retries': 0, 'compliance_policy': {'sw31': {'minRetentionDays': 14}}}},
        ['sql_database', 'sql_backup_short_term_policy', 'sql_restore_point'])
    assert verdict(snapshot) == 'FAIL'
    assert any('/restorePoints' in url for url in transport.calls)
