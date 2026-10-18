"""Confirmed native locations survive unrelated incomplete service inventories."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.checks import CHECKS
from peaso.collectors import aws, aws_region_data_native as native
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = '123456789012'
CONTROL = 'aws_account_non_eu_resource_region_detected'


def capture(region='us-east-1', failure=None, recovery_arn=None, resource_kind='s3'):
    """Execute the actual producer; all typed SDK-read interfaces are inert."""
    class Session:
        def get_partition_for_region(self, name):
            assert name in ('us-east-1', 'eu-west-1')
            return 'aws'
    now = datetime.now(timezone.utc)
    owner = native.normalize({'compliance_parameters': {'aws_data_regions': {
        'scope': ACCOUNT + '/global', 'authorized_by': 'approved-owner', 'document_id': 'approved-EU-regions',
        'observed_at': (now - timedelta(minutes=1)).isoformat(),
        'expires_at': (now + timedelta(hours=1)).isoformat(), 'approved_region_names': ['eu-west-1']}}})
    class Reads:
        audited_regions_by_account = {ACCOUNT: [region]}
        observed_at = now
        data_regions_policy = owner
        def __init__(self): self.calls = []
        def detail(self, session, service, where, operation, **kwargs):
            assert (service, operation) in native.READ_ACTIONS
            self.calls.append((service, operation))
            if (service, operation) == ('sts', 'get_caller_identity'):
                assert kwargs == {}
                return {'collection_status': 'collected', 'Account': ACCOUNT,
                        'Arn': 'arn:aws:iam::' + ACCOUNT + ':user/inert-reader'}
            assert (service, operation) == ('s3', 'get_bucket_location')
            assert kwargs == {'Bucket': 'owned-bucket', 'ExpectedBucketOwner': ACCOUNT}
            return {'collection_status': 'collected', 'LocationConstraint': region}
        def pages(self, session, service, where, operation, field, **kwargs):
            assert (service, operation) in native.READ_ACTIONS or (service, operation) == ('ec2', 'describe_regions')
            self.calls.append((service, operation))
            if operation == 'describe_regions':
                assert kwargs == {'AllRegions': True}
                return aws.ReadResult([{'RegionName': region, 'OptInStatus': 'opt-in-not-required'}], 'collected')
            if operation == 'list_buckets':
                assert kwargs == {'MaxBuckets': 1000}
                return aws.ReadResult([{'Name': 'owned-bucket'}], 'collected') if resource_kind == 's3' else aws.ReadResult([], 'empty')
            if operation == 'describe_volumes' and resource_kind == 'ebs':
                return aws.ReadResult([{'VolumeId': 'vol-0123456789abcdef0'}], 'collected')
            failed_operation = 'describe_db_instances' if resource_kind == 's3' else 'list_tables'
            if operation == failed_operation and failure:
                return aws.ReadResult([], failure, {'code': 'inert_' + failure})
            if operation == 'list_backup_vaults' and recovery_arn:
                return aws.ReadResult([{'BackupVaultName': 'owned',
                    'BackupVaultArn': 'arn:aws:backup:' + region + ':' + ACCOUNT + ':backup-vault:owned'}], 'collected')
            if operation == 'list_recovery_points_by_backup_vault':
                assert kwargs == {'BackupVaultName': 'owned', 'BackupVaultAccountId': ACCOUNT}
                return aws.ReadResult([{'RecoveryPointArn': recovery_arn,
                    'BackupVaultArn': 'arn:aws:backup:' + region + ':' + ACCOUNT + ':backup-vault:owned'}], 'collected')
            return aws.ReadResult([], 'empty')
    reads = Reads()
    bundle = native._compute(reads, Session(), region, ACCOUNT)
    collections = []
    for kind, result in bundle.items():
        # Mirror the actual AWS global append projection, retaining the real
        # producer's proofs, status and failure cause without manufacturing any.
        rows = [{**aws._safe(row), 'AccountId': ACCOUNT} for row in result.items]
        collection = {'type': kind, 'scope': ACCOUNT + '/global', 'service': native.SPECS[kind][0],
            'global': True, 'account_id': ACCOUNT, 'status': result.status, 'items': rows}
        if result.error: collection['error'] = deepcopy(result.error)
        collections.append(collection)
    snapshot = make_snapshot('aws', [ACCOUNT + '/' + region], collections,
        metadata=native.owner_metadata(owner, [ACCOUNT + '/' + region]), created_at=now.isoformat())
    return snapshot, reads


def status(snapshot):
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CONTROL])['findings'] if f['check_id'] == CONTROL]
    assert len(findings) == 1
    return findings[0]['status']


def evidence(snapshot):
    return next(c for c in snapshot['collections'] if c['type'] == 'aws_data_resource')


def reseal(snapshot):
    return make_snapshot('aws', snapshot['scopes'], snapshot['collections'], metadata=snapshot['metadata'], created_at=snapshot['created_at'])


def test_complete_native_counterexample_does_not_require_negative_universe_coverage():
    snapshot, _ = capture()
    snapshot['collections'] = [c for c in snapshot['collections'] if c['type'] != 'aws_data_resource_coverage']
    assert evidence(snapshot)['status'] == 'collected'
    assert status(reseal(snapshot)) == 'FAIL'
    check = next(c for c in CHECKS if c.id == CONTROL)
    assert check.allow_incomplete_failure is True
    assert set(check.dependencies) == set(native.KINDS)


@pytest.mark.parametrize('failure', ['denied', 'timeout', 'not_collected'])
def test_actual_native_partial_bundle_preserves_confirmed_outside_eu_location(failure):
    snapshot, reads = capture(failure=failure)
    resources = evidence(snapshot)
    assert resources['status'] == 'partial' and len(resources['items']) == 1
    assert resources['error']['cause_status'] == failure
    assert ('rds', 'describe_db_instances') in reads.calls
    assert status(snapshot) == 'FAIL'


@pytest.mark.parametrize('failure,expected', [('denied', 'DENIED'), ('timeout', 'UNKNOWN'), ('not_collected', 'UNKNOWN')])
def test_safe_native_partial_bundle_never_passes(failure, expected):
    snapshot, _ = capture(region='eu-west-1', failure=failure)
    assert status(snapshot) == expected


@pytest.mark.parametrize('mode', [
    'wrong_account', 'arn_account', 'arn_region', 'arn_type', 'id_mismatch', 'wrong_service', 'unknown_native_type',
    'missing_proof', 'not_readonly', 'wrong_catalog', 'not_location', 'owner_scope', 'owner_expired',
    'owner_names', 'owner_missing', 'foreign_envelope', 'false_global', 'wrong_envelope_service',
])
def test_partial_rows_need_native_owner_scope_and_location_authority(mode):
    snapshot, _ = capture(failure='timeout')
    collection = evidence(snapshot)
    row = collection['items'][0]
    owner = snapshot['metadata']['aws_data_region_owner']
    if mode == 'wrong_account': row['AccountId'] = '999999999999'
    elif mode in ('arn_account', 'arn_region', 'arn_type'):
        row['NativeType'], row['Service'] = 'describe_volumes', 'ec2_volume'
        rid = 'arn:aws:ec2:us-east-1:' + ACCOUNT + ':volume/vol-0123456789abcdef0'
        if mode == 'arn_account': rid = rid.replace(ACCOUNT, '999999999999')
        if mode == 'arn_region': rid = rid.replace('us-east-1', 'us-west-2')
        if mode == 'arn_type': rid = rid.replace('volume/vol-', 'instance/i-')
        row['id'] = row['ResourceId'] = rid
    elif mode == 'id_mismatch': row['id'] += '-other'
    elif mode == 'wrong_service': row['Service'] = 'rds'
    elif mode == 'unknown_native_type': row['NativeType'] = 'external_claim'
    elif mode == 'missing_proof': row.pop('_provenance')
    elif mode == 'not_readonly': row['_provenance']['read_only'] = 1
    elif mode == 'wrong_catalog': row['_provenance']['catalog_version'] = 'unreviewed'
    elif mode == 'not_location': row['_provenance']['location_only'] = False
    elif mode == 'owner_scope': owner['scope'] = '999999999999/global'
    elif mode == 'owner_expired': owner['expires_at'] = owner['observed_at']
    elif mode == 'owner_names': owner['approved_region_names'] = ['eu-central-1']
    elif mode == 'owner_missing': snapshot['metadata'].pop('aws_data_region_owner')
    elif mode == 'foreign_envelope': collection['account_id'] = '999999999999'
    elif mode == 'false_global': collection['global'] = False
    elif mode == 'wrong_envelope_service': collection['service'] = 'external'
    assert status(reseal(snapshot)) == 'UNKNOWN'


@pytest.mark.parametrize('region,expected', [('eu-west-1', 'PASS'), ('us-east-1', 'FAIL')])
def test_existing_complete_native_bundle_keeps_prior_verdicts(region, expected):
    snapshot, _ = capture(region=region)
    coverage = next(c for c in snapshot['collections'] if c['type'] == 'aws_data_resource_coverage')
    assert coverage['status'] == 'collected' and len(coverage['items']) == 7
    assert status(snapshot) == expected


@pytest.mark.parametrize('arn', [
    'arn:aws:rds:eu-west-1:' + ACCOUNT + ':snapshot:owned',
    'arn:aws:dynamodb:eu-west-1:' + ACCOUNT + ':table/owned/backup/owned',
    'arn:aws:ec2:eu-west-1::snapshot/snap-0123456789abcdef0',
])
def test_complete_native_recovery_point_alias_does_not_break_existing_pass(arn):
    snapshot, _ = capture(region='eu-west-1', recovery_arn=arn)
    assert evidence(snapshot)['status'] == 'collected'
    assert status(snapshot) == 'PASS'


@pytest.mark.parametrize('region,failure,expected', [
    ('us-east-1', 'denied', 'FAIL'), ('us-east-1', 'timeout', 'FAIL'),
    ('eu-west-1', 'denied', 'DENIED'),
])
def test_actual_native_ebs_location_before_other_service_failure(region, failure, expected):
    snapshot, _ = capture(region=region, failure=failure, resource_kind='ebs')
    row = evidence(snapshot)['items'][0]
    assert row['NativeType'] == 'describe_volumes' and row['Service'] == 'ec2_volume'
    assert evidence(snapshot)['status'] == 'partial'
    assert status(snapshot) == expected
