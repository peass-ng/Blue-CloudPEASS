"""A retained backup failure survives unrelated truncated backup inventory."""
from copy import deepcopy
import pytest
from peaso.checks import evaluate_check
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
S = '/subscriptions/sub'
BACKUP = S + '/resourceGroups/rg/providers/Microsoft.RecoveryServices/vaults/v/backupProtectedItems/i'


def backup():
    return {'id': BACKUP, 'properties': {'lastRecoveryPoint': '2026-10-10T00:00:00Z',
        'lastBackupStatus': 'Completed', 'protectionState': 'Protected'}}


def one(**kinds):
    return {kind: [(S, rows)] for kind, rows in kinds.items()}


def index(collections, policy):
    return {'context': {'provider': 'azure', 'scope': S, 'created_at': '2026-10-12T00:00:00Z',
            'metadata': {'compliance_policy': {'sw31': policy}}},
        'collections': {kind: [{'scope': scope, 'status': 'collected', 'items': deepcopy(rows)}
            for scope, rows in batches] for kind, batches in collections.items()},
        **{kind: [{'scope': scope, 'data': deepcopy(row)} for scope, rows in batches for row in rows]
           for kind, batches in collections.items()}}

CIDS = ('azure.other.backup_freshness_14_days', 'azure.other.backup_freshness_30_days', 'azure_c5_ops_07_01b')


def facts(mode):
    row = backup()
    if mode == 'failed': row['properties']['lastBackupStatus'] = 'Failed'
    if mode == 'stale': row['properties']['lastRecoveryPoint'] = '2026-08-01T00:00:00Z'
    if mode == 'stopped': row['properties']['protectionState'] = 'ProtectionStopped'
    policy = {'requiredBackupItemIds': [BACKUP], 'ops06MaxAgeDays': 14}
    out = index(one(backup_protected_item=[row]), policy)
    out['collections']['backup_protected_item'][0]['status'] = 'partial'
    return out


@pytest.mark.parametrize('cid', CIDS)
@pytest.mark.parametrize('mode,expected', [('failed', 'FAIL'), ('stale', 'FAIL'), ('healthy', 'UNKNOWN')])
def test_retained_failure_can_disprove_but_partial_success_cannot_certify(cid, mode, expected):
    before = facts(mode)
    copy = deepcopy(before)
    assert evaluate_check(cid, {'scope': S}, before)[0] == expected
    assert before == copy


@pytest.mark.parametrize('cid,expected', [(CIDS[0], 'UNKNOWN'), (CIDS[1], 'FAIL'), (CIDS[2], 'FAIL')])
def test_stopped_protection_only_disproves_controls_requiring_active_protection(cid, expected):
    assert evaluate_check(cid, {'scope': S}, facts('stopped'))[0] == expected


@pytest.mark.parametrize('mutation', ['foreign_scope', 'duplicate_id', 'different_wrapper', 'denied', 'foreign_reference'])
def test_partial_counterexample_still_requires_trustworthy_bound_observation(mutation):
    out = facts('failed')
    envelope = out['collections']['backup_protected_item'][0]
    if mutation == 'foreign_scope': envelope['scope'] = '/subscriptions/other'
    elif mutation == 'duplicate_id':
        envelope['items'].append(deepcopy(envelope['items'][0]))
        out['backup_protected_item'].append(deepcopy(out['backup_protected_item'][0]))
    elif mutation == 'different_wrapper': out['backup_protected_item'][0]['data']['properties']['lastBackupStatus'] = 'Completed'
    elif mutation == 'denied': envelope['status'] = 'denied'
    else:
        envelope['items'][0]['parent_id'] = '/subscriptions/other/vaults/v'
        out['backup_protected_item'][0]['data']['parent_id'] = '/subscriptions/other/vaults/v'
    assert evaluate_check(CIDS[0], {'scope': S}, out)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', CIDS)
def test_engine_retains_scoped_failure_with_partial_primary_and_unavailable_monitor_history(cid):
    out = facts('failed')
    collections = [{'type': 'backup_protected_item', 'scope': S, 'status': 'partial',
                    'items': out['collections']['backup_protected_item'][0]['items']}]
    if cid == CIDS[2]:
        collections += [{'type': kind, 'scope': S, 'status': 'denied', 'items': []}
                        for kind in ('backup_job', 'backup_monitor_evidence')]
    snapshot = make_snapshot('azure', [S], collections,
        metadata=out['context']['metadata'], created_at=out['context']['created_at'])
    findings = evaluate_snapshot(snapshot, checks=[cid])['findings']
    assert findings and {finding['status'] for finding in findings} == {'FAIL'}


@pytest.mark.parametrize('mutation', ['collection_type', 'wrapper_type', 'wrapper_provider'])
def test_partial_counterexample_rejects_explicit_collection_or_wrapper_authority_conflict(mutation):
    out = facts('failed')
    if mutation == 'collection_type': out['collections']['backup_protected_item'][0]['type'] = 'unrelated'
    elif mutation == 'wrapper_type': out['backup_protected_item'][0]['type'] = 'unrelated'
    else: out['backup_protected_item'][0]['provider'] = 'aws'
    assert evaluate_check(CIDS[0], {'scope': S}, out)[0] == 'UNKNOWN'
