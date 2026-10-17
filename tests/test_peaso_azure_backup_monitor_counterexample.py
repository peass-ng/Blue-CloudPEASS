"""Known backup failure must survive missing independent monitoring records."""
from datetime import datetime, timedelta, timezone

import pytest

from peaso.collectors import azure, collect_live
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_bulk_native import Transport, SCOPE, SUB, BASE, parent, routes

CHECK = 'azure_c5_ops_07_01b'
VAULT = BASE + 'Microsoft.RecoveryServices/vaults/vault'
ITEM = VAULT + '/backupFabrics/Azure/protectionContainers/container/protectedItems/item'


def review():
    return {'requiredBackupItemIds': [ITEM], 'ops06MaxAgeDays': 30}


def properties(mode):
    now = datetime.now(timezone.utc)
    result = {'lastBackupStatus': 'Failed' if mode == 'failed' else 'Completed',
              'protectionState': 'ProtectionStopped' if mode == 'stopped' else 'Protected',
              'lastRecoveryPoint': (now - timedelta(days=60 if mode == 'old' else 1)).isoformat()}
    if mode == 'unknown': result.pop('lastRecoveryPoint')
    return result


def verdict(snapshot):
    rows = [f for f in evaluate_snapshot(snapshot, checks=[CHECK])['findings'] if f['check_id'] == CHECK]
    assert len(rows) == 1
    return rows[0]['status']


@pytest.mark.parametrize('mode,monitoring,expected', [
    ('failed', 'not_collected', 'FAIL'), ('old', 'not_collected', 'FAIL'),
    ('stopped', 'not_collected', 'FAIL'), ('failed', 'denied', 'FAIL'),
    ('healthy', 'not_collected', 'UNKNOWN'), ('healthy', 'denied', 'DENIED'),
    ('unknown', 'not_collected', 'UNKNOWN'),
])
def test_backup_violation_precedes_unavailable_monitoring(mode, monitoring, expected):
    snapshot = make_snapshot('azure', [SCOPE], [
        {'type': 'backup_protected_item', 'scope': SCOPE, 'status': 'collected',
         'items': [{'id': ITEM, 'properties': properties(mode)}]},
        {'type': 'backup_job', 'scope': SCOPE, 'status': 'not_collected', 'items': []},
        {'type': 'backup_monitor_evidence', 'scope': SCOPE, 'status': monitoring, 'items': []},
    ], metadata={'compliance_policy': {'sw31': review()}})
    assert verdict(snapshot) == expected


@pytest.mark.parametrize('primary,expected', [('partial', 'UNKNOWN'), ('denied', 'DENIED')])
def test_incomplete_backup_source_never_becomes_a_proven_failure(primary, expected):
    snapshot = make_snapshot('azure', [SCOPE], [
        {'type': 'backup_protected_item', 'scope': SCOPE, 'status': primary,
         'items': [{'id': ITEM, 'properties': properties('failed')}] if primary == 'partial' else []},
    ], metadata={'compliance_policy': {'sw31': review()}})
    assert verdict(snapshot) == expected


def test_actual_readonly_backup_collector_to_engine(monkeypatch):
    class ReadOnlyTransport(Transport):
        def request(self, url, *, body=None, audience=azure.ARM):
            assert body is None
            return super().request(url, body=body, audience=audience)

    responses = routes('recovery_vault', VAULT, {})
    responses[VAULT + '/backupProtectedItems'] = {'value': [
        parent(ITEM, 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems', properties('failed'))]}
    api = ReadOnlyTransport(responses)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=api))
    capture = collect_live({'provider': 'azure', 'scopes': [SUB], 'options': {
        'retries': 0, 'compliance_policy': {'sw31': review()}}},
        ['backup_protected_item', 'backup_job', 'backup_monitor_evidence'])
    assert verdict(capture) == 'FAIL'
    assert api.calls
