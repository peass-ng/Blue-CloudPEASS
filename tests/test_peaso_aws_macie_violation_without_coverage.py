"""Conclusive authorized detection precedes absence/whole-scan coverage proof."""
from copy import deepcopy

import pytest

from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = '123456789012'
REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + REGION
BUCKET = 'arn:aws:s3:::authorized-bucket'
CHECK = 'aws.pci.s3.sensitive_auth_data_findings'


def finding(archived=False, names=None):
    return {'id': 'known-finding', 'accountId': ACCOUNT, 'region': REGION,
            'archived': archived, 's3Object': {'bucketArn': BUCKET},
            'customIdentifierNames': ['CVV'] if names is None else names}


def decision(rows, coverage='missing', finding_status='collected', policy=None):
    collections = [{'type': 'macie_finding', 'scope': SCOPE, 'status': finding_status,
                    'items': [] if finding_status == 'denied' else rows}]
    if coverage != 'missing':
        collections.append({'type': 'macie_scan_coverage', 'scope': SCOPE,
                            'status': coverage, 'items': []})
    metadata = {'parameters': policy if policy is not None else {
        'prohibited_auth_identifier_names': ['CVV'], 'authorized_macie_bucket_arns': [BUCKET]}}
    snapshot = make_snapshot('aws', [SCOPE], collections, metadata=metadata)
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize('coverage', ['missing', 'denied', 'not_collected', 'partial'])
def test_fully_valid_active_prohibited_finding_is_fail_without_scan_coverage(coverage):
    result = decision([finding()], coverage)
    assert result['status'] == 'FAIL'
    assert result['evidence']['active_prohibited_finding_ids'] == ['known-finding']
    assert 'coverage unverified' in result['evidence']['semantics']


@pytest.mark.parametrize('coverage', ['missing', 'denied'])
@pytest.mark.parametrize('mode', ['archived', 'nonprohibited', 'empty'])
def test_absence_or_inactive_findings_cannot_pass_without_full_coverage(coverage, mode):
    rows = [] if mode == 'empty' else [finding(archived=mode == 'archived', names=['OTHER'] if mode == 'nonprohibited' else None)]
    result = decision(rows, coverage, finding_status='empty' if not rows else 'collected')
    assert result['status'] in ({'UNKNOWN', 'DENIED'} if coverage == 'denied' else {'UNKNOWN'})


@pytest.mark.parametrize('mode', ['foreign_account', 'foreign_region', 'foreign_bucket',
                                  'invalid_names', 'duplicate', 'partial', 'denied'])
def test_missing_coverage_never_bypasses_finding_authority_or_completeness(mode):
    rows = [finding()]
    state = 'collected'
    if mode in {'partial', 'denied'}: state = mode
    else:
        second = deepcopy(rows[0]); second['id'] = 'invalid-second-finding'
        if mode == 'foreign_account': second['accountId'] = '999999999999'
        elif mode == 'foreign_region': second['region'] = 'us-east-1'
        elif mode == 'foreign_bucket': second['s3Object']['bucketArn'] = 'arn:aws:s3:::not-authorized'
        elif mode == 'invalid_names': second['customIdentifierNames'] = [True]
        elif mode == 'duplicate': second['id'] = rows[0]['id']
        rows.append(second)
    assert decision(rows, finding_status=state)['status'] in ({'UNKNOWN', 'DENIED'} if state == 'denied' else {'UNKNOWN'})


def test_known_finding_still_requires_explicit_owner_authorized_bucket_policy():
    assert decision([finding()], policy={'prohibited_auth_identifier_names': ['CVV']})['status'] == 'UNKNOWN'
