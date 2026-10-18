"""Registered SW25 original-contract delivery evidence boundaries."""

import json

import pytest
from pathlib import Path

from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

GATEWAY_ID = 'azure.other.gateway_backend_health_alert'
REPORT_ID = 'azure_c5_ops_17_02b'


def _capture(cid):
    case = json.loads((Path(__file__).parent / 'fixtures/bulk_pending_behavior.json').read_text())[cid]
    index = case['pass_index']
    collections = [collection for envelopes in index['collections'].values() for collection in envelopes]
    return index, collections


def _registered_status(cid, index, collections):
    snapshot = make_snapshot('azure', [index['context']['scope']], collections,
                             metadata=index['context']['metadata'], created_at=index['context']['created_at'])
    findings = evaluate_snapshot(snapshot, checks=[cid])['findings']
    return next(finding['status'] for finding in findings if finding['check_id'] == cid)


@pytest.mark.parametrize('delivery,expected', [
    ('2026-10-12T10:07:00Z', 'PASS'),
    ('2026-10-12T10:07:01Z', 'FAIL'),
    ('2026-10-12T10:15:00Z', 'FAIL'),
])
def test_gateway_delivery_respects_approved_latency(delivery, expected):
    index, collections = _capture(GATEWAY_ID)
    assert _registered_status(GATEWAY_ID, index, collections) == 'PASS'
    health = next(collection for collection in collections if collection['type'] == 'gateway_health_evidence')
    health['items'][0]['windows'][0]['alertEvaluations'][0]['deliveredAt'] = delivery
    assert _registered_status(GATEWAY_ID, index, collections) == expected


@pytest.mark.parametrize('mutation,expected', [
    ('deadline', 'PASS'),
    ('late', 'FAIL'),
    ('wrong_receiver', 'FAIL'),
    ('foreign_event', 'UNKNOWN'),
])
def test_critical_delivery_joins_exact_event_recipient_and_instant(mutation, expected):
    index, collections = _capture(REPORT_ID)
    delivery = next(c for c in collections if c['type'] == 'failure_delivery_record')['items'][0]
    if mutation == 'deadline':
        delivery['deliveredAt'] = '2026-10-12T10:35:00Z'
    elif mutation == 'late':
        delivery['deliveredAt'] = '2026-10-12T10:35:01Z'
    elif mutation == 'wrong_receiver':
        delivery['receiverId'] = 'unapproved-receiver'
    else:
        delivery['eventId'] = 'other-event'
    assert _registered_status(REPORT_ID, index, collections) == expected
