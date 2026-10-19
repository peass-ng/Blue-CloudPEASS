"""Bounded S3 delivery metadata, never log content or SIEM receipt evidence.

Organization keys have no trail ID. A complete native DescribeTrails inventory
must uniquely correlate the destination; otherwise even fresh objects are
ambiguous. Pagination covers the exact organization/account/home-Region prefix,
and hitting any page/item/call budget leaves UNKNOWN, never a negative claim.
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html
"""
from copy import deepcopy
from datetime import datetime, timezone
import re

PROFILE = 'aws-cloudtrail-s3-delivery-metadata-v1'
MARKER = 'CloudTrailS3DeliveryObjects'
PROJECTION_OPERATIONS = frozenset({('s3', 'get_bucket_location'), ('s3', 'list_objects_v2')})
READ_ACTIONS = set(PROJECTION_OPERATIONS) | {('sts', 'get_caller_identity'),
    ('organizations', 'describe_organization'), ('cloudtrail', 'describe_trails')}
MAX_PAGES = 4
MAX_ITEMS = 4000
REGION = r'[a-z]{2}(?:-[a-z]+)+-[0-9]'
ARN = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):cloudtrail:(' + REGION + r'):([0-9]{12}):trail/[^/]+')
PREFIX = re.compile(r'(?P<base>.*)AWSLogs/(?P<org>o-[a-z0-9]{10,32})/(?P<account>[0-9]{12})/CloudTrail/(?P<region>' + REGION + r')/')


def timestamp(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError('delivery_timestamp_invalid') from None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('delivery_timestamp_invalid')
    return value.astimezone(timezone.utc).isoformat()


def key_prefix(value):
    # Do not silently broaden a native prefix by stripping slashes.
    if not isinstance(value, str) or len(value) > 200 or value.startswith('/') or value.endswith('/'):
        raise ValueError('delivery_prefix_unsupported')
    return value + '/' if value else ''


def valid_key(key, prefix):
    match = PREFIX.fullmatch(prefix)
    if not match or not isinstance(key, str) or not key.startswith(prefix):
        return False
    suffix = key[len(prefix):]
    pattern = (r'([0-9]{4})/([0-9]{2})/([0-9]{2})/' + match['account'] + r'_CloudTrail_'
               + re.escape(match['region']) + r'_([0-9]{8}T[0-9]{4}Z)_[A-Za-z0-9]{16}\.json\.gz')
    obj = re.fullmatch(pattern, suffix)
    if not obj:
        return False
    try:
        delivered = datetime.strptime(obj[4], '%Y%m%dT%H%MZ')
    except ValueError:
        return False
    return delivered.strftime('%Y/%m/%d') == '/'.join(obj.groups()[:3])


def project_response(response, service, operation, arguments):
    """Profile-separated allowlist runs before shared Future/cache insertion."""
    from .aws import ReadFailure
    try:
        if ((service, operation) not in PROJECTION_OPERATIONS or not isinstance(response, dict)
                or re.fullmatch(r'[0-9]{12}', arguments.get('ExpectedBucketOwner', '')) is None
                or not isinstance(response.get('ResponseMetadata'), dict)
                or type(response['ResponseMetadata'].get('HTTPStatusCode')) is not int
                or response['ResponseMetadata']['HTTPStatusCode'] != 200):
            raise ValueError('delivery_response_unbound')
        if operation == 'get_bucket_location':
            location = response.get('LocationConstraint')
            if location not in (None, 'EU') and (not isinstance(location, str) or re.fullmatch(REGION, location) is None):
                raise ValueError('delivery_bucket_location_invalid')
            return {'LocationConstraint': location, '_metadata_projection': PROFILE}
        prefix = arguments.get('Prefix')
        binding = PREFIX.fullmatch(prefix) if isinstance(prefix, str) else None
        if (not binding or binding['account'] != arguments['ExpectedBucketOwner']
                or response.get('Name') != arguments.get('Bucket') or response.get('Prefix') != prefix
                or type(response.get('IsTruncated')) is not bool or response.get('CommonPrefixes')
                or arguments.get('Delimiter') or response.get('EncodingType')):
            raise ValueError('delivery_listing_binding_invalid')
        rows = response.get('Contents', [])
        if (not isinstance(rows, list) or type(response.get('KeyCount')) is not int
                or response['KeyCount'] != len(rows) or len(rows) > arguments['MaxKeys']):
            raise ValueError('delivery_listing_shape_invalid')
        selected = []
        for row in rows:
            if not isinstance(row, dict) or not valid_key(row.get('Key'), prefix):
                raise ValueError('delivery_object_path_invalid')
            selected.append({'Key': row['Key'], 'LastModified': timestamp(row.get('LastModified'))})
        token = response.get('NextContinuationToken')
        if (response['IsTruncated'] and (not isinstance(token, str) or not token)
                or not response['IsTruncated'] and token):
            raise ValueError('delivery_listing_continuation_invalid')
        return {'Contents': selected, 'IsTruncated': response['IsTruncated'],
                **({'NextContinuationToken': token} if token else {}), '_metadata_projection': PROFILE}
    except (ValueError, TypeError, KeyError):
        raise ReadFailure('malformed', 'cloudtrail_s3_delivery_metadata_invalid') from None


def _detail(requests, session, service, region, operation, **arguments):
    from .aws import ReadFailure
    response = requests.detail(session, service, region, operation, **arguments)
    if response.get('collection_status') != 'collected':
        raise ReadFailure(response.get('collection_status', 'malformed'), 'cloudtrail_delivery_native_read_unavailable')
    return response


def _native_destination(requests, session, region, trail):
    """Native complete trail response proves optional prefix absence and uniqueness."""
    response = _detail(requests, session, 'cloudtrail', region, 'describe_trails', includeShadowTrails=True)
    rows = response.get('trailList')
    if not isinstance(rows, list):
        raise ValueError('delivery_trails_unavailable')
    target = [row for row in rows if isinstance(row, dict) and row.get('TrailARN') == trail.get('TrailARN')]
    if len(target) != 1:
        raise ValueError('delivery_trail_identity_ambiguous')
    source = target[0]
    for field in ('TrailARN', 'HomeRegion', 'S3BucketName', 'IsOrganizationTrail'):
        if source.get(field) != trail.get(field):
            raise ValueError('delivery_native_destination_mismatch')
    prefix = source.get('S3KeyPrefix', '')
    key_prefix(prefix)
    if trail.get('S3KeyPrefix', '') != prefix:
        raise ValueError('delivery_native_prefix_mismatch')
    matches = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('TrailARN'), str) or row['TrailARN'] in seen:
            raise ValueError('delivery_trail_inventory_malformed')
        seen.add(row['TrailARN'])
        row_arn = ARN.fullmatch(row['TrailARN'])
        if (not row_arn or row.get('HomeRegion') != row_arn[2]
                or type(row.get('IsOrganizationTrail')) is not bool
                or type(row.get('IsMultiRegionTrail')) is not bool
                or not isinstance(row.get('S3BucketName'), str)):
            raise ValueError('delivery_trail_inventory_malformed')
        key_prefix(row.get('S3KeyPrefix', ''))
        if (row.get('IsOrganizationTrail') is True and row.get('S3BucketName') == source['S3BucketName']
                and row.get('S3KeyPrefix', '') == prefix
                and (row.get('HomeRegion') == region or row.get('IsMultiRegionTrail') is True)):
            matches.append(row['TrailARN'])
    if matches != [source['TrailARN']]:
        raise ValueError('delivery_trail_destination_ambiguous')
    return prefix


def _collect(requests, session, region, trail):
    arn = trail.get('TrailARN')
    match = ARN.fullmatch(arn) if isinstance(arn, str) else None
    home = trail.get('HomeRegion')
    if not match or match[2] != home or home != region:
        raise ValueError('delivery_trail_home_binding_invalid')
    identity = _detail(requests, session, 'sts', region, 'get_caller_identity')
    account = identity.get('Account')
    if (not isinstance(account, str) or re.fullmatch(r'[0-9]{12}', account) is None
            or not isinstance(identity.get('Arn'), str) or identity['Arn'].split(':')[4] != account):
        raise ValueError('delivery_caller_identity_invalid')
    organization = _detail(requests, session, 'organizations', region, 'describe_organization').get('Organization')
    org = organization.get('Id') if isinstance(organization, dict) else None
    if not isinstance(org, str) or re.fullmatch(r'o-[a-z0-9]{10,32}', org) is None:
        raise ValueError('delivery_organization_identity_invalid')
    source_prefix = _native_destination(requests, session, home, trail)
    bucket = trail.get('S3BucketName')
    if (not isinstance(bucket, str) or re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket) is None
            or bucket.endswith('--x-s3')):
        raise ValueError('delivery_bucket_name_invalid')
    location = _detail(requests, session, 's3', home, 'get_bucket_location', Bucket=bucket,
                       ExpectedBucketOwner=account, _metadata_profile=PROFILE)
    selected = location.get('LocationConstraint')
    bucket_region = 'us-east-1' if selected is None else 'eu-west-1' if selected == 'EU' else selected
    prefix = key_prefix(source_prefix) + 'AWSLogs/' + org + '/' + account + '/CloudTrail/' + home + '/'
    proof = {'profile': PROFILE, 'read_only': True, 'identity_operation': 'sts:GetCallerIdentity',
             'organization_operation': 'organizations:DescribeOrganization',
             'describe_operation': 'cloudtrail:DescribeTrails', 'native_destination_unique': True,
             'scope': 'unique_destination_account_region_object_metadata_correlation', 'siem_receipt_verified': False}
    marker = {'collection_status': 'partial', 'TrailARN': arn, 'AccountId': account, 'HomeRegion': home,
              'Bucket': bucket, 'BucketRegion': bucket_region, 'ExpectedBucketOwner': account,
              'S3KeyPrefix': source_prefix, 'OrganizationId': org, 'Prefix': prefix,
              'source_operation': 's3:ListObjectsV2', 'listing_complete': False, 'Contents': [], '_provenance': proof}
    max_pages = min(requests.max_pages or MAX_PAGES, MAX_PAGES)
    max_items = min(requests.max_items or MAX_ITEMS, MAX_ITEMS)
    token, seen_tokens, seen_keys = None, set(), set()
    for _page in range(max_pages):
        remaining = max_items - len(marker['Contents'])
        if remaining <= 0:
            return marker
        args = {'Bucket': bucket, 'ExpectedBucketOwner': account, 'Prefix': prefix, 'MaxKeys': min(1000, remaining)}
        if token:
            args['ContinuationToken'] = token
        try:
            response = requests.call(session, 's3', bucket_region, 'list_objects_v2', _metadata_profile=PROFILE, **args)
        except Exception as exc:
            from .aws import _failure
            marker['collection_status'] = 'partial' if marker['Contents'] else _failure(exc).status
            return marker
        for row in response['Contents']:
            if row['Key'] in seen_keys:
                return marker
            seen_keys.add(row['Key'])
            marker['Contents'].append(row)
        if not response['IsTruncated']:
            marker.update(collection_status='collected' if marker['Contents'] else 'empty', listing_complete=True)
            return marker
        token = response['NextContinuationToken']
        if token in seen_tokens:
            return marker
        seen_tokens.add(token)
    return marker


def enrich(requests, session, region, items):
    from .aws import _failure
    result = []
    for item in items:
        row = deepcopy(item)
        if row.get('IsOrganizationTrail') is True:
            row.pop(MARKER, None)
            try:
                row[MARKER] = _collect(requests, session, region, row)
                # Native DescribeTrails above proved this optional omission.
                row.setdefault('S3KeyPrefix', row[MARKER]['S3KeyPrefix'])
            except Exception as exc:
                row[MARKER] = {'collection_status': 'malformed' if isinstance(exc, (ValueError, TypeError, KeyError, IndexError)) else _failure(exc).status}
        result.append(row)
    return result


ENRICHERS = {'cloudtrail': enrich}
