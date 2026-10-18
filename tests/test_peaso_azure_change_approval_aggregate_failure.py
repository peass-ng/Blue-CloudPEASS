"""Registered change approval keeps decisive failures and global evidence guards."""
import copy

import pytest

from peaso.checks import evaluate_check


CID = 'azure.other.change_approval_trace'
SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
BASE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts'
WHEN = '2026-10-10T12:00:00Z'


def event(suffix):
    return {'id': SCOPE + '/providers/Microsoft.Insights/eventtypes/management/values/' + suffix,
            'eventTimestamp': WHEN, 'operationName': {'value': 'Microsoft.Storage/storageAccounts/write'},
            'status': {'value': 'Succeeded'}, 'resourceId': BASE + '/' + suffix,
            'correlationId': suffix, 'caller': 'user'}


def approval(suffix, *, status='Pending', proof='one'):
    return {'id': SCOPE + '/approvalRecords/' + suffix + proof,
            'correlationId': suffix, 'resourceId': BASE + '/' + suffix,
            'ticketId': 'T-' + suffix, 'approver': 'owner', 'status': status,
            'approvedAt': '2026-10-09T12:00:00Z'}


def facts(events, approvals):
    rows = {'activity_log': events,
            'activity_log_coverage': [{'id': SCOPE,
                                       'retainedFrom': '2026-10-01T00:00:00Z',
                                       'collectedThrough': '2026-10-12T00:00:00Z'}],
            'change_approval_record': approvals}
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                         'metadata': {'compliance_policy': {'sw33': {
                             'status': 'collected', 'scope': SCOPE,
                             'changeApproval': {'windowStart': '2026-10-01T00:00:00Z',
                                                'windowEnd': '2026-10-12T00:00:00Z'}}}}},
             'collections': {}}
    for kind, items in rows.items():
        index['collections'][kind] = [{'type': kind, 'scope': SCOPE,
                                       'status': 'collected' if items else 'empty', 'items': items}]
        index[kind] = [{'type': kind, 'scope': SCOPE, 'data': item} for item in items]
    return index


@pytest.mark.parametrize('order', [('a', 'b'), ('b', 'a')])
def test_missing_approval_failure_survives_other_pending_ticket(order):
    status, evidence = evaluate_check(CID, {}, facts([event(x) for x in order], [approval('b')]))
    assert status == 'FAIL', evidence
    assert event('a')['id'] in evidence['changes_without_predating_approval']
    assert event('b')['id'] in evidence['unresolved_changes']


def test_pending_ticket_only_is_unknown_with_identity():
    status, evidence = evaluate_check(CID, {}, facts([event('b')], [approval('b')]))
    assert status == 'UNKNOWN', evidence
    assert event('b')['id'] in evidence['unresolved_changes']


def test_ambiguous_approval_join_is_global_unknown_with_missing_approval():
    status, evidence = evaluate_check(CID, {}, facts([event('a'), event('b')],
                                                 [approval('b'), approval('b', proof='two')]))
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'ambiguous change approval join'
    foreign = event('a')
    foreign['resourceId'] = '/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a'
    status, evidence = evaluate_check(CID, {}, facts([foreign, event('b')], [approval('b')]))
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'foreign change event resource'


def test_partial_approval_inventory_is_global_unknown_with_missing_approval():
    index = facts([event('a')], [])
    index['collections']['change_approval_record'][0]['status'] = 'partial'
    status, evidence = evaluate_check(CID, {}, index)
    assert status == 'UNKNOWN', evidence


def test_native_query_ending_at_inclusive_review_end_is_unknown_with_missing_approval():
    index = facts([event('a')], [])
    index['collections']['activity_log'][0]['queryWindow'] = {
        'start': '2026-10-01T00:00:00Z', 'end': '2026-10-12T00:00:00Z',
        'endExclusive': True}
    status, evidence = evaluate_check(CID, {}, index)
    assert status == 'UNKNOWN', evidence
    assert evidence['reason'] == 'Activity Log query window does not cover review window'
