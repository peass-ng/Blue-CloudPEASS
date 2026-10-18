# Historical fixture contracts; current native admission is tested separately.
"""Scoped Macie finding authority through SDK stubs and the registered engine."""
from copy import deepcopy
import json

import pytest

from test_peaso_aws_bulk_inventory import sdk
from tests.test_peaso_aws_macie_findings_native import finding, ACCOUNT, REGION, BUCKET, CHECK, LIST_ARGS
from peaso.collectors import aws, aws_macie_findings_native as native
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = ACCOUNT + '/' + REGION
POLICY = {'prohibited_auth_identifier_names': ['prohibited-auth'],
          'authorized_macie_bucket_arns': [BUCKET]}


def capture(sdk, mode='bound'):
    session, add = sdk
    stub = add('macie2')
    raw = finding()
    raw['classificationDetails'].update(originType='SENSITIVE_DATA_DISCOVERY_JOB',
                                        jobId='a' * 32,
                                        jobArn=f'arn:aws:macie2:{REGION}:{ACCOUNT}:classification-job/' + 'a' * 32)
    raw['resourcesAffected']['s3Object'].update(key='private/object.csv', versionId='v1', eTag='etag-1')
    raw.update(createdAt='2026-10-12T09:00:00Z', updatedAt='2026-10-12T09:00:00Z')
    if mode == 'missing_key': raw['resourcesAffected']['s3Object'].pop('key')
    elif mode == 'missing_revision':
        raw['resourcesAffected']['s3Object'].pop('versionId')
        raw['resourcesAffected']['s3Object'].pop('eTag')
    elif mode == 'foreign_job':
        raw['classificationDetails']['jobArn'] = raw['classificationDetails']['jobArn'].replace(ACCOUNT, '999999999999')
    elif mode == 'missing_origin': raw['classificationDetails'].pop('originType')
    elif mode == 'future_timestamp': raw['updatedAt'] = '2099-01-01T00:00:00Z'
    elif mode == 'skipped': raw['classificationDetails']['result']['status']['code'] = 'SKIPPED'
    elif mode == 'foreign_account': raw['accountId'] = '999999999999'
    stub.add_response('list_findings', {'findingIds': [] if mode == 'empty' else ['finding1']}, LIST_ARGS)
    if mode == 'detail_error':
        stub.add_client_error('get_findings', 'AccessDeniedException', http_status_code=403,
                              expected_params={'findingIds': ['finding1']})
    elif mode != 'empty':
        stub.add_response('get_findings', {'findings': [raw]}, {'findingIds': ['finding1']})
    requests = aws.Requests({'retries': 0})
    read = native.collect(requests, session, REGION, ACCOUNT)
    cached = []
    for value in requests._cache.values():
        try:
            cached.append(value.result() if hasattr(value, 'result') else value)
        except Exception:
            continue  # Failed reads never enter the source projection.
    assert 'private/object.csv' not in json.dumps(cached)
    assert 'private/object.csv' not in json.dumps(read.items)
    stub.assert_no_pending_responses()
    return read


def verdict(read):
    snapshot = make_snapshot('aws', [SCOPE], [
        {'type': 'macie_finding', 'scope': SCOPE, 'service': 'macie2',
         'status': read.status, 'items': read.items}], metadata={'parameters': POLICY})
    rows = [item for item in evaluate_snapshot(snapshot, checks=[CHECK])['findings']
            if item['check_id'] == CHECK]
    assert len(rows) == 1
    return rows[0]


def test_native_sdk_positive_finding_with_invalid_source_operation_cannot_fail(sdk):
    read = capture(sdk)
    assert read.status == 'collected'
    read = deepcopy(read)
    read.items[0]['_provenance']['source_operation'] = 'operator:unverified'
    assert verdict(read)['status'] == 'UNKNOWN'


def test_native_sdk_bound_active_hit_is_fail_without_full_scan_coverage(sdk):
    read = capture(sdk)
    assert read.status == 'collected'
    row = read.items[0]
    assert row['s3Object']['objectIdentitySha256'] and 'key' not in row['s3Object']
    assert row['classificationOrigin']['jobArn'].endswith('/' + 'a' * 32)
    assert verdict(read)['status'] == 'FAIL'


@pytest.mark.parametrize('mode', ['missing_key', 'missing_revision', 'foreign_job',
                                  'missing_origin', 'future_timestamp', 'skipped',
                                  'foreign_account', 'detail_error', 'empty'])
def test_missing_or_foreign_native_binding_never_proves_violation_or_cleanliness(sdk, mode):
    read = capture(sdk, mode)
    assert verdict(read)['status'] in {'UNKNOWN', 'DENIED'}


def test_native_object_identity_digest_tampering_is_unavailable(sdk):
    read = capture(sdk)
    read.items[0]['s3Object']['objectIdentitySha256'] = 'not-a-digest'
    assert verdict(read)['status'] == 'UNKNOWN'
