"""A verified priority mismatch survives an unrelated incomplete ACL row.

These offline rows assert association/completeness for individual ACLs. They do
not claim that native FMS has supplied a complete policy-managed ACL universe.
"""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from tests.test_peaso_fms_multi_acl_priority import case, CONTROL, RULES


@pytest.mark.parametrize('scenario,expected', [
    ('bad_then_incomplete', 'FAIL'),
    ('incomplete_then_bad', 'FAIL'),
    ('bad_second_and_incomplete_first', 'FAIL'),
    ('two_bad_acls', 'FAIL'),
    ('good_then_incomplete', 'UNKNOWN'),
    ('incomplete_then_good', 'UNKNOWN'),
    ('other_policy_only', 'UNKNOWN'),
    ('foreign_account_with_bad', 'UNKNOWN'),
    ('foreign_region_with_bad', 'UNKNOWN'),
    ('duplicate_arn_with_bad', 'UNKNOWN'),
    ('two_good_acls', 'PASS'),
])
def test_observed_priority_violation_and_unavailable_peer(scenario, expected):
    policy, rows, index = case()
    if scenario in {'bad_then_incomplete', 'incomplete_then_bad',
                    'foreign_account_with_bad', 'foreign_region_with_bad', 'duplicate_arn_with_bad'}:
        rows[0]['Rules'][1]['Priority'] = 3
    if scenario == 'bad_second_and_incomplete_first':
        rows[1]['Rules'][1]['Priority'] = 3
        rows[0]['complete'] = False
    elif scenario == 'two_bad_acls':
        for row in rows:
            row['Rules'][1]['Priority'] = 3
    elif scenario in {'bad_then_incomplete', 'incomplete_then_bad',
                      'good_then_incomplete', 'incomplete_then_good'}:
        rows[1]['complete'] = False
    elif scenario == 'other_policy_only':
        for row in rows:
            row['PolicyId'] = 'different-policy'
    elif scenario == 'foreign_account_with_bad':
        rows[1]['WebACLArn'] = rows[1]['WebACLArn'].replace('123456789012', '999999999999')
    elif scenario == 'foreign_region_with_bad':
        rows[1]['WebACLArn'] = rows[1]['WebACLArn'].replace('us-east-1', 'us-west-2')
    elif scenario == 'duplicate_arn_with_bad':
        rows[1]['WebACLArn'] = rows[0]['WebACLArn']
    if scenario in {'incomplete_then_bad', 'incomplete_then_good'}:
        rows.reverse()
        index['fms_web_acl_rules'].reverse()
    status, evidence = evaluate_check(CONTROL, policy, index)
    assert status == expected
    if status == 'FAIL':
        assert evidence['noncompliant_web_acl_arns']
    if status == 'PASS':
        assert all(row['Rules'] == deepcopy(RULES) for row in rows)
