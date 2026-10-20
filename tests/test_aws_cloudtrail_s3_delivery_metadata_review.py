"""Native SDK metadata, bounded delivery correlation, and the registered control."""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
import json

import boto3
from botocore.stub import Stubber
import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.collectors import aws
from peaso.collectors import aws_cloudtrail_s3_delivery_metadata as native
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = 'aws_cloudtrail_s3_siem_delivery'
ACCOUNT = '123456789012'
HOME = 'us-east-1'
BUCKET_REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + HOME
ARN = 'arn:aws:cloudtrail:us-east-1:123456789012:trail/main'
BUCKET = 'native-trail-bucket'
ORG = 'o-1234567890'
PREFIX = 'audit/AWSLogs/' + ORG + '/' + ACCOUNT + '/CloudTrail/' + HOME + '/'
KEY = PREFIX + '2026/10/11/123456789012_CloudTrail_us-east-1_20261011T2300Z_0123456789abcdef.json.gz'
NOW = '2026-10-12T00:00:00+00:00'
FRESH = datetime(2026, 10, 11, 23, tzinfo=timezone.utc)
OLD = datetime(2026, 10, 1, tzinfo=timezone.utc)
SECRET = 'synthetic-unrelated-owner-name'


def trail():
    return {'TrailARN': ARN, 'Name': 'main', 'HomeRegion': HOME, 'IsOrganizationTrail': True,
            'IsMultiRegionTrail': True, 'S3BucketName': BUCKET, 'S3KeyPrefix': 'audit'}


def observed(marker, *, delivery=FRESH, error=''):
    row = trail()
    row.update({'SourceRegion': HOME, 'AccountId': ACCOUNT, '_provenance': {'operation': 'cloudtrail:DescribeTrails',
                'native_response_complete': True}, 'Status': {'LatestDeliveryError': error,
                'LatestDeliveryTime': native.timestamp(delivery)}, native.MARKER: marker})
    return row


def index(row):
    envelope = {'type': 'cloudtrail_account_inventory', 'scope': ACCOUNT + '/global',
                'global': True, 'account_id': ACCOUNT, 'status': 'collected', 'items': [row]}
    return {'context': {'provider': 'aws', 'scope': SCOPE, 'created_at': NOW},
            'collections': {'cloudtrail_account_inventory': [envelope]},
            'cloudtrail_account_inventory': [{'data': row}]}


def status(row):
    facts = index(row)
    return evaluate_check(CID, facts['context'], facts)[0]


def list_response(*, key=KEY, modified=FRESH, more=False, empty=False):
    rows = [] if empty else [{'Key': key, 'LastModified': modified, 'Size': 5,
                            'ETag': 'unrelated-etag', 'Owner': {'DisplayName': SECRET, 'ID': 'owner-id'}}]
    return {'Name': BUCKET, 'Prefix': PREFIX, 'KeyCount': len(rows), 'IsTruncated': more,
            'Contents': rows, **({'NextContinuationToken': 'next-page'} if more else {}),
            'ResponseMetadata': {'HTTPStatusCode': 200, 'HTTPHeaders': {'unrelated': SECRET}}}


def marker():
    return {'collection_status': 'collected', 'TrailARN': ARN, 'AccountId': ACCOUNT, 'HomeRegion': HOME,
            'Bucket': BUCKET, 'BucketRegion': BUCKET_REGION, 'ExpectedBucketOwner': ACCOUNT,
            'S3KeyPrefix': 'audit', 'OrganizationId': ORG, 'Prefix': PREFIX,
            'source_operation': 's3:ListObjectsV2', 'listing_complete': True,
            'Contents': [{'Key': KEY, 'LastModified': native.timestamp(FRESH)}],
            '_provenance': {'profile': native.PROFILE, 'read_only': True,
                'identity_operation': 'sts:GetCallerIdentity', 'organization_operation': 'organizations:DescribeOrganization',
                'describe_operation': 'cloudtrail:DescribeTrails', 'native_destination_unique': True,
                'scope': 'unique_destination_account_region_object_metadata_correlation', 'siem_receipt_verified': False}}


@pytest.mark.parametrize('mode,expected', [('fresh', 'PASS'), ('old_objects', 'FAIL'), ('empty', 'FAIL'),
    ('delivery_error', 'FAIL'), ('stale_delivery', 'FAIL'), ('missing', 'UNKNOWN'), ('denied', 'UNKNOWN'),
    ('partial', 'UNKNOWN'), ('foreign', 'UNKNOWN'), ('overbroad', 'UNKNOWN'), ('ambiguous', 'UNKNOWN'),
    ('missing_error', 'UNKNOWN'), ('missing_time', 'UNKNOWN')])
def test_registered_consumer_bound_positive_negative_and_unavailable_cases(mode, expected):
    data = marker()
    row = observed(data, error='AccessDenied' if mode == 'delivery_error' else '',
                   delivery=OLD if mode == 'stale_delivery' else FRESH)
    if mode == 'old_objects':
        data['Contents'][0]['LastModified'] = native.timestamp(OLD)
    if mode == 'empty':
        data.update(collection_status='empty', Contents=[])
    if mode == 'missing':
        row.pop(native.MARKER)
    if mode in ('denied', 'partial'):
        data['collection_status'] = mode
    if mode == 'foreign':
        data['AccountId'] = '999999999999'
    if mode == 'overbroad':
        data['Prefix'] = 'audit/AWSLogs/'
    if mode == 'ambiguous':
        data['_provenance']['native_destination_unique'] = False
    if mode == 'missing_error':
        row['Status'].pop('LatestDeliveryError')
    if mode == 'missing_time':
        row['Status'].pop('LatestDeliveryTime')
    assert status(row) == expected


@pytest.mark.parametrize('field,value', [('TrailARN', ARN + '-foreign'), ('Bucket', 'foreign-bucket'),
    ('HomeRegion', 'eu-west-1'), ('ExpectedBucketOwner', '999999999999'), ('S3KeyPrefix', ''),
    ('listing_complete', False), ('OrganizationId', 'o-foreign123'), ('BucketRegion', ''),
    ('source_operation', 's3:GetObject')])
def test_foreign_or_incomplete_native_bindings_cannot_pass(field, value):
    data = marker()
    data[field] = value
    assert status(observed(data)) == 'UNKNOWN'


@pytest.mark.parametrize('bad_key', [KEY.replace(ACCOUNT, '999999999999'), KEY.replace('CloudTrail/', 'CloudTrail-Digest/'),
    KEY.replace('/us-east-1/', '/eu-west-1/'), KEY.replace('/2026/10/11/', '/2026/99/11/'),
    PREFIX + 'unrelated.json', 'arbitrary-private-object'])
def test_pre_cache_projector_rejects_foreign_or_non_log_paths(bad_key):
    with pytest.raises(aws.ReadFailure):
        native.project_response(list_response(key=bad_key), 's3', 'list_objects_v2',
            {'Bucket': BUCKET, 'ExpectedBucketOwner': ACCOUNT, 'Prefix': PREFIX, 'MaxKeys': 1000})


def test_projector_omits_unrelated_metadata_and_normalizes_datetime():
    safe = native.project_response(list_response(), 's3', 'list_objects_v2',
        {'Bucket': BUCKET, 'ExpectedBucketOwner': ACCOUNT, 'Prefix': PREFIX, 'MaxKeys': 1000})
    assert safe['Contents'] == [{'Key': KEY, 'LastModified': '2026-10-11T23:00:00+00:00'}]
    assert SECRET not in json.dumps(safe) and 'Owner' not in safe['Contents'][0]
    assert 'Name' not in safe and 'ResponseMetadata' not in safe
    for bad in (datetime(2026, 10, 11), 123.0, True, None, 'not-a-time'):
        with pytest.raises(ValueError):
            native.timestamp(bad)


@pytest.mark.parametrize('mode,expected', [('fresh', 'PASS'), ('empty', 'FAIL'), ('old', 'FAIL'),
    ('denied', 'UNKNOWN'), ('cross_account', 'UNKNOWN'), ('partial', 'UNKNOWN'),
    ('foreign', 'UNKNOWN'), ('malformed', 'UNKNOWN'), ('ambiguous', 'UNKNOWN'), ('prefix_omitted', 'PASS'),
    ('paginated', 'PASS'), ('incomplete_trails', 'UNKNOWN')])
def test_real_sdk_enrichment_cache_and_registered_snapshot_consumer(mode, expected):
    assert 'peaso.collectors.aws_cloudtrail_s3_delivery_metadata' in aws.EXTENSION_MODULES
    assert native.READ_ACTIONS <= aws.READ_ACTIONS
    check = next(c for c in CHECKS if c.id == CID)
    assert 'bucket' not in check.dependencies
    session = boto3.Session(aws_access_key_id='fixture', aws_secret_access_key='fixture', region_name=HOME)
    requests = aws.Requests({'retry_attempts': 1, 'max_pages': 2 if mode == 'paginated' else 1, 'max_resources': 10})
    clients = {}
    with ExitStack() as stack:
        for service, region in [('sts', HOME), ('organizations', HOME), ('cloudtrail', HOME), ('s3', HOME), ('s3', BUCKET_REGION)]:
            client = session.client(service, region_name=region)
            requests._clients[(id(session), service, region)] = client
            clients[(service, region)] = stack.enter_context(Stubber(client))
        clients[('sts', HOME)].add_response('get_caller_identity', {'Account': ACCOUNT,
            'Arn': 'arn:aws:iam::123456789012:root', 'UserId': 'fixture'}, {})
        clients[('organizations', HOME)].add_response('describe_organization', {'Organization': {'Id': ORG}}, {})
        raw_trail = trail()
        listing = list_response(empty=mode == 'empty', modified=OLD if mode == 'old' else FRESH,
                                more=mode in ('partial', 'paginated'))
        prefix = PREFIX
        if mode == 'prefix_omitted':
            raw_trail.pop('S3KeyPrefix')
            prefix = PREFIX.removeprefix('audit/')
            listing['Prefix'] = prefix
            listing['Contents'][0]['Key'] = KEY.removeprefix('audit/')
        native_trails = [raw_trail]
        if mode == 'ambiguous':
            native_trails.append({**raw_trail, 'TrailARN': ARN + '-second', 'Name': 'second'})
        if mode == 'incomplete_trails':
            other = {**raw_trail, 'TrailARN': ARN + '-second', 'Name': 'second'}
            other.pop('IsOrganizationTrail')
            native_trails.append(other)
        clients[('cloudtrail', HOME)].add_response('describe_trails', {'trailList': native_trails}, {'includeShadowTrails': True})
        if mode not in ('ambiguous', 'incomplete_trails'):
            location_args = {'Bucket': BUCKET, 'ExpectedBucketOwner': ACCOUNT}
            if mode == 'cross_account':
                clients[('s3', HOME)].add_client_error('get_bucket_location', 'AccessDenied', expected_params=location_args)
            else:
                clients[('s3', HOME)].add_response('get_bucket_location', {'LocationConstraint': 'EU',
                    'ResponseMetadata': {'HTTPStatusCode': 200}}, location_args)
                args = {'Bucket': BUCKET, 'ExpectedBucketOwner': ACCOUNT, 'Prefix': prefix, 'MaxKeys': 10}
                if mode == 'denied':
                    clients[('s3', BUCKET_REGION)].add_client_error('list_objects_v2', 'AccessDenied', expected_params=args)
                else:
                    if mode == 'foreign':
                        listing['Contents'][0]['Key'] = KEY.replace(ACCOUNT, '999999999999')
                    if mode == 'malformed':
                        listing.pop('IsTruncated')
                    clients[('s3', BUCKET_REGION)].add_response('list_objects_v2', listing, args)
                    if mode == 'paginated':
                        clients[('s3', BUCKET_REGION)].add_response('list_objects_v2', list_response(empty=True),
                            {**args, 'MaxKeys': 9, 'ContinuationToken': 'next-page'})
        row = native.ENRICHERS['cloudtrail'](requests, session, HOME, [deepcopy(raw_trail)])[0]
        row.update({key: value for key, value in observed({}).items() if key in ('SourceRegion', 'AccountId', '_provenance', 'Status')})
        assert status(row) == expected
        snapshot = make_snapshot('aws', [SCOPE], [{'type': 'cloudtrail_account_inventory', 'scope': ACCOUNT + '/global',
            'global': True, 'account_id': ACCOUNT, 'service': 'cloudtrail', 'status': 'collected', 'items': [row]}], created_at=NOW)
        report = evaluate_snapshot(snapshot, checks=[CID])
        findings = [f for f in report['findings'] if f['check_id'] == CID]
        assert len(findings) == 1 and findings[0]['status'] == expected
        for future in requests._cache.values():
            if future.exception() is None:
                assert SECRET not in json.dumps(future.result(), default=str)
        assert SECRET not in json.dumps(snapshot, default=str)
        for stub in clients.values():
            stub.assert_no_pending_responses()


def test_non_organization_trails_make_no_requests_and_have_no_delivery_marker():
    requests = aws.Requests({'retry_attempts': 1, 'max_calls': 1})
    row = {**trail(), 'IsOrganizationTrail': False}
    assert native.enrich(requests, object(), HOME, [row]) == [row]
    assert requests.calls == 0


def test_shared_call_budget_exhaustion_discards_stale_delivery_marker():
    requests = aws.Requests({'retry_attempts': 1, 'max_calls': 1})
    requests.calls = 1
    row = observed(marker())
    updated = native.enrich(requests, object(), HOME, [row])[0]
    assert updated[native.MARKER] == {'collection_status': 'not_collected'}
    assert status(updated) == 'UNKNOWN'
    assert requests.calls == 1


def test_unknown_timestamp_future_and_legacy_bucket_witness_never_pass():
    data = marker()
    row = observed(data)
    row['Status']['LatestDeliveryTime'] = '2026-10-13T00:00:00Z'
    assert status(row) == 'UNKNOWN'
    data['Contents'][0]['LastModified'] = datetime(2026, 10, 11)
    assert status(observed(data)) == 'UNKNOWN'
    row = observed({})
    assert status(row) == 'UNKNOWN'
