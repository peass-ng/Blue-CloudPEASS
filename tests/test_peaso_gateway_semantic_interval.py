"""Invalid parser intervals cannot establish a functioning gateway alert."""
import pytest

from tests.compliance_draft_isolation import staged_registry
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot


@pytest.fixture
def gateway():
    with staged_registry(['compliance_new_sw25']):
        from tests.test_peaso_compliance_new_sw25 import fixture, data, SCOPE, NOW
        from peaso.checks.compliance_new_sw25_facts import GATEWAY_ID
        yield fixture(GATEWAY_ID), data, SCOPE, NOW, GATEWAY_ID


def check(gateway, interval):
    index, data, scope, now, cid = gateway
    data(index, 'gateway_alert_semantics')['evaluationFrequencySeconds'] = interval
    collections = [c for envelopes in index['collections'].values() for c in envelopes]
    snapshot = make_snapshot('azure', [scope], collections,
        metadata=index['context']['metadata'], created_at=now)
    findings = evaluate_snapshot(snapshot, checks=[cid])['findings']
    return next(f['status'] for f in findings if f['check_id'] == cid)


@pytest.mark.parametrize('interval', [0, -1, -60, True, None, '60', 60.0])
def test_invalid_interval_is_unknown(gateway, interval):
    assert check(gateway, interval) == 'UNKNOWN'


def test_actual_valid_interval_keeps_pass(gateway):
    assert check(gateway, 60) == 'PASS'


def test_valid_interval_slower_than_owner_latency_remains_fail(gateway):
    assert check(gateway, 180) == 'FAIL'


@pytest.mark.parametrize('interval', [float('inf'), float('nan')])
def test_nonfinite_interval_is_rejected_at_snapshot_boundary(gateway, interval):
    with pytest.raises(ValueError, match='JSON compliant'):
        check(gateway, interval)
