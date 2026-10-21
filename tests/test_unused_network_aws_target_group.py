"""Native ELB association observations retain scope and incomplete-data boundaries."""
from copy import deepcopy

import pytest

from peaso import unused_network_aws as subject
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = 'aws.network.target_group_has_load_balancer'


def case():
    return deepcopy(CASES[CID])


@pytest.mark.parametrize('name,expected', [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')])
def test_bound_native_cases_and_normal_engine(name, expected):
    fixture = case()
    item, index = fixture[name], fixture[name + '_index']
    check = next(c for c in CHECKS if c.id == CID)
    assert check.category == 'hardening'
    assert check.evaluate(item, index)[0] == expected
    snapshot = make_snapshot('aws', [index['context']['scope']], index['collections']['target_group'], created_at='2026-10-21T20:00:00Z')
    report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[CID])
    assert report['findings'][0]['status'] == expected
    assert len(report['findings'][0]['evidence']['summary'].splitlines()) == 3


def test_positive_reference_survives_partial_but_absence_does_not():
    for name, expected in [('pass', 'PASS'), ('fail', 'UNKNOWN')]:
        fixture = case()
        index = fixture[name + '_index']
        index['collections']['target_group'][0]['status'] = 'partial'
        assert subject.target_group(fixture[name], index)[0] == expected


@pytest.mark.parametrize('change', ['foreign_target', 'foreign_lb', 'wrong_service', 'duplicate', 'projection_mismatch'])
def test_foreign_or_unbound_evidence_cannot_decide(change):
    fixture = case()
    item, index = fixture['pass'], fixture['pass_index']
    if change == 'foreign_target':
        item['TargetGroupArn'] = item['TargetGroupArn'].replace('123456789012', '999999999999')
    elif change == 'foreign_lb':
        item['LoadBalancerArns'] = [item['LoadBalancerArns'][0].replace('us-east-1', 'us-west-2')]
        index['target_group'][0]['data'] = deepcopy(item)
        index['collections']['target_group'][0]['items'] = [deepcopy(item)]
    elif change == 'wrong_service':
        index['collections']['target_group'][0]['service'] = 'ec2'
    elif change == 'duplicate':
        index['collections']['target_group'][0]['items'].append(deepcopy(item))
    else:
        index['target_group'][0]['data']['TargetGroupArn'] = 'different'
    assert subject.target_group(item, index)[0] == 'UNKNOWN'
