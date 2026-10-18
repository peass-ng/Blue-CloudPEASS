"""A known violation never turns incomplete absence evidence into a pass."""
from dataclasses import replace

import pytest

from peaso import engine
from peaso.checks import CHECKS
from peaso.snapshot import make_snapshot


@pytest.mark.parametrize('enabled,observed,missing,expected,called', [
    (False, 'FAIL', 'not_collected', 'UNKNOWN', False),
    (True, 'FAIL', 'not_collected', 'FAIL', True),
    (True, 'PASS', 'not_collected', 'UNKNOWN', True),
    (True, 'NOT_APPLICABLE', 'not_collected', 'UNKNOWN', True),
    (True, 'FAIL', 'denied', 'FAIL', True),
    (True, 'PASS', 'denied', 'DENIED', True),
    (True, 'exception', 'not_collected', 'UNKNOWN', True),
    (True, 'malformed', 'not_collected', 'UNKNOWN', True),
])
def test_only_opted_in_conclusive_failure_overrides_incomplete_inventory(
        monkeypatch, enabled, observed, missing, expected, called):
    original = next(check for check in CHECKS if check.id == 'aws.rds.encryption')
    evaluations = []

    def evaluate(item, index):
        evaluations.append(True)
        if observed == 'exception':
            raise ValueError('fixture unavailable')
        if observed == 'malformed':
            return 'FAIL', None
        return observed, {'observed_violation': True}

    check = replace(original, target='scope', declared_dependencies=('rds_instance', 'vpc'),
                    evaluate=evaluate, allow_incomplete_failure=enabled)
    monkeypatch.setattr(engine, '_registry', lambda: [check])
    scope = '123456789012/eu-west-1'
    snapshot = make_snapshot('aws', [scope], [
        {'type': 'rds_instance', 'scope': scope, 'status': 'empty', 'items': []},
        {'type': 'vpc', 'scope': scope, 'status': missing, 'items': []},
    ])
    result = engine.evaluate_snapshot(snapshot, checks=[check.id])
    finding, = (row for row in result['findings'] if row['check_id'] == check.id)
    assert finding['status'] == expected
    assert bool(evaluations) is called
    assert check.dependencies == ['rds_instance', 'vpc']
    if expected == 'FAIL':
        assert finding['evidence']['incomplete_dependencies'] == [{'type': 'vpc', 'status': missing}]
