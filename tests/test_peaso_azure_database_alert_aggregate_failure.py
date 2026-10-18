"""Registered backup alert aggregation preserves decisive failures and global proof guards."""
import copy

import pytest

from peaso.checks import evaluate_check
from tests.test_peaso_azure_database_alert_delivery_binding import observed


CID = 'azure.other.database_backup_alert'
SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
BASE = SCOPE + '/resourceGroups/rg/providers'
A = BASE + '/Microsoft.Sql/servers/sql/databases/a'
B = BASE + '/Microsoft.Sql/servers/sql/databases/b'
FOREIGN = BASE + '/Microsoft.Sql/servers/sql/databases/foreign'
GROUP = BASE + '/Microsoft.Insights/actionGroups/ag'


def proof(service, *, failed=False, suffix='one'):
    row = copy.deepcopy(observed()['collections']['database_backup_alert_evidence'][0]['items'][0])
    row['id'] = service + '/backupAlertEvidence/' + suffix
    row['serviceId'] = service
    for signal in row['signals'].values():
        signal['triggerObservation']['serviceId'] = service
        signal['deliveryObservation']['serviceId'] = service
        for delivery in signal['deliveryObservation']['deliveries']:
            delivery['serviceId'] = service
    if failed:
        row['signals']['paused']['testStatus'] = 'failed'
    return row


def facts(services, proofs):
    index = observed()
    for kind, rows in (('database_backup_service', [{'id': service} for service in services]),
                       ('database_backup_alert_evidence', proofs)):
        index['collections'][kind][0]['status'] = 'collected' if rows else 'empty'
        index['collections'][kind][0]['items'] = rows
        index[kind] = [{'type': kind, 'scope': SCOPE, 'data': row} for row in rows]
    return index


@pytest.mark.parametrize('order', [(A, B), (B, A)])
def test_proven_failed_test_survives_other_service_missing_proof(order):
    failed_proof = proof(A, failed=True)
    if order[0] == B:
        failed_proof['signals']['scheduledFailure']['testStatus'] = 'unresolved'
    status, evidence = evaluate_check(CID, {}, facts(order, [failed_proof]))
    assert status == 'FAIL', evidence
    assert (A.casefold(), 'paused', 'alert test failed') in evidence['failed_signals']
    assert B.casefold() in evidence['unresolved_services']
    if order[0] == B:
        assert (A.casefold(), 'scheduledFailure') in evidence['unresolved_signals']


def test_missing_only_remains_unknown_with_identity():
    status, evidence = evaluate_check(CID, {}, facts((A, B), [proof(A)]))
    assert status == 'UNKNOWN', evidence
    assert B.casefold() in evidence['unresolved_services']


def test_foreign_proof_is_global_unknown_even_with_failure():
    status, evidence = evaluate_check(CID, {}, facts((A, B), [proof(A, failed=True), proof(FOREIGN)]))
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'foreign backup alert evidence'


def test_duplicate_service_proof_is_global_unknown_even_with_failure():
    status, evidence = evaluate_check(CID, {}, facts((A, B), [proof(A, failed=True), proof(A, suffix='two'), proof(B)]))
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'duplicate backup alert service evidence'


def test_partial_proof_collection_is_global_unknown_even_with_failure():
    index = facts((A, B), [proof(A, failed=True), proof(B)])
    index['collections']['database_backup_alert_evidence'][0]['status'] = 'partial'
    status, evidence = evaluate_check(CID, {}, index)
    assert status == 'UNKNOWN', evidence
