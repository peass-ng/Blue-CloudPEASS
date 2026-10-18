"""All completely associated WebACLs of one FMS policy require approved order.

These offline fixtures assume association/completeness. They do not attest a
real managed FMS universe or provide a native ownership collector.
"""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check

CONTROL = 'aws.pci.fms.web_acl_rule_priority'
SCOPE = '123456789012/us-east-1'
ACL = 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/main/abcdef'
SECOND = 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/other/abcdef2'
RULES = [{'Name': 'first', 'Priority': 1}, {'Name': 'second', 'Priority': 2}]


def case():
    policy = {'PolicyId': 'p-1', 'SecurityServiceType': 'WAFV2'}
    rows = [{'PolicyId': 'p-1', 'WebACLArn': arn, 'complete': True, 'Rules': deepcopy(RULES)} for arn in (ACL, SECOND)]
    native = {'fms_policy': [policy], 'fms_web_acl_rules': rows}
    index = {'context': {'provider': 'aws', 'scope': SCOPE,
        'metadata': {'approved_fms_rule_priorities': {'p-1': deepcopy(RULES)}}},
        'collections': {kind: [{'type': kind, 'scope': SCOPE, 'status': 'collected', 'items': values}] for kind, values in native.items()},
        **{kind: [{'type': kind, 'scope': SCOPE, 'data': value} for value in values] for kind, values in native.items()}}
    return policy, rows, index


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('mode,expected', [('valid', 'PASS'), ('second_bad', 'FAIL'), ('first_bad', 'FAIL')])
def test_every_complete_policy_acl_is_evaluated_independent_of_order(reverse, mode, expected):
    policy, rows, index = case()
    if mode == 'second_bad': rows[1]['Rules'][1]['Priority'] = 1
    if mode == 'first_bad': rows[0]['Rules'][1]['Priority'] = 3
    if reverse:
        rows.reverse()
        index['fms_web_acl_rules'].reverse()
    assert evaluate_check(CONTROL, policy, index)[0] == expected


@pytest.mark.parametrize('mode', [
    'duplicate_arn', 'foreign_account', 'foreign_region', 'wrong_resource_type', 'foreign_policy_only',
    'incomplete_acl', 'malformed_complete', 'missing_complete', 'missing_rules', 'malformed_priority',
    'partial_inventory', 'zero_acls', 'bad_and_incomplete', 'bad_and_foreign',
])
@pytest.mark.parametrize('reverse', [False, True])
def test_ambiguous_foreign_or_incomplete_acl_inventory_verdict(mode, reverse):
    policy, rows, index = case()
    if mode == 'duplicate_arn': rows[1]['WebACLArn'] = ACL
    elif mode == 'foreign_account': rows[1]['WebACLArn'] = SECOND.replace('123456789012', '999999999999')
    elif mode == 'foreign_region': rows[1]['WebACLArn'] = SECOND.replace('us-east-1', 'us-west-2')
    elif mode == 'wrong_resource_type': rows[1]['WebACLArn'] = SECOND.replace('/webacl/', '/ipset/')
    elif mode == 'foreign_policy_only':
        for row in rows: row['PolicyId'] = 'p-other'
    elif mode == 'incomplete_acl': rows[1]['complete'] = False
    elif mode == 'malformed_complete': rows[1]['complete'] = 1
    elif mode == 'missing_complete': rows[1].pop('complete')
    elif mode == 'missing_rules': rows[1].pop('Rules')
    elif mode == 'malformed_priority': rows[1]['Rules'][1]['Priority'] = '2'
    elif mode == 'partial_inventory': index['collections']['fms_web_acl_rules'][0]['status'] = 'partial'
    elif mode == 'zero_acls': rows.clear(); index['fms_web_acl_rules'].clear()
    elif mode in ('bad_and_incomplete', 'bad_and_foreign'):
        rows[0]['Rules'][1]['Priority'] = 1
        if mode == 'bad_and_incomplete': rows[1]['complete'] = False
        else: rows[1]['WebACLArn'] = SECOND.replace('123456789012', '999999999999')
    if reverse:
        rows.reverse()
        index['fms_web_acl_rules'].reverse()
    # A verified mismatch remains decisive when a separate ACL lacks detail.
    expected = 'FAIL' if mode == 'bad_and_incomplete' else 'UNKNOWN'
    assert evaluate_check(CONTROL, policy, index)[0] == expected


@pytest.mark.parametrize('kind', ['WAF', 'DNS_FIREWALL', 'SHIELD_ADVANCED'])
def test_non_wafv2_policy_remains_not_applicable(kind):
    policy, _, index = case()
    policy['SecurityServiceType'] = kind
    assert evaluate_check(CONTROL, policy, index)[0] == 'NOT_APPLICABLE'


def test_multi_acl_evidence_is_stable_and_identifies_the_noncompliant_acl():
    policy, rows, index = case()
    rows[1]['Rules'][1]['Priority'] = 1
    status, evidence = evaluate_check(CONTROL, policy, index)
    assert status == 'FAIL'
    assert evidence['noncompliant_web_acl_arns'] == [SECOND]
    assert evidence['web_acl_arns'] == sorted([ACL, SECOND])
    assert set(evidence['observed_by_web_acl']) == {ACL, SECOND}
