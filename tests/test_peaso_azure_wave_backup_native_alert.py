"""A duplicate service proof must not be hidden by dictionary overwrite."""
import copy

from peaso.checks import evaluate_check


SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
BASE = SCOPE + '/resourceGroups/rg/providers'
SERVICE = BASE + '/Microsoft.Sql/servers/sql/databases/app'
GROUP = BASE + '/Microsoft.Insights/actionGroups/ag'
CID = 'azure.other.database_backup_alert'


def _facts(proofs):
    kinds = {
        'database_backup_service': [{'id': SERVICE}],
        'database_backup_alert_evidence': proofs,
        'monitor_action_group': [{'id': GROUP}],
    }
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                         'metadata': {'compliance_policy': {'sw33': {
                             'status': 'collected', 'scope': SCOPE,
                             'backupAlerts': {'responseWindowMinutes': 10}}}}},
             'collections': {}}
    for kind, rows in kinds.items():
        index['collections'][kind] = [{'type': kind, 'scope': SCOPE,
                                       'status': 'collected' if rows else 'empty',
                                       'items': rows}]
        index[kind] = [{'type': kind, 'scope': SCOPE, 'data': row} for row in rows]
    return index


def _proof(suffix, status='passed'):
    signal = {'observable': True, 'testStatus': status,
              'alertDelayMinutes': 5, 'actionGroupId': GROUP,
              'alertLogId': 'log-' + suffix, 'actionDelivered': True}
    return {'id': SERVICE + '/backupAlertEvidence/' + suffix,
            'serviceId': SERVICE,
            'signals': {key: copy.deepcopy(signal)
                        for key in ('disabled', 'paused', 'scheduledFailure')}}


def test_single_complete_service_proof_passes():
    from tests.test_peaso_azure_database_alert_delivery_binding import observed
    status, evidence = evaluate_check(CID, {}, observed())
    assert status == 'PASS', evidence


def test_duplicate_service_proof_is_unknown_for_ambiguous_join():
    status, evidence = evaluate_check(
        CID, {}, _facts([_proof('failed', 'failed'), _proof('passed')]))
    assert status == 'UNKNOWN', (status, evidence)
    assert evidence.get('reason') == 'duplicate backup alert service evidence', evidence
