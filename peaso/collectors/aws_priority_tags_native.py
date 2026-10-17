"""Four-family native inventory and tags; never an inventory of tagged-only IDs.

Source coverage describes completed native reads, not owner classification or
universal account coverage. S3 resources are emitted only in their measured home
Region. Missing/denied tag evidence never becomes an empty map.
"""
import re

SOURCE_KINDS = ('instance', 'bucket', 'rds_db_instance', 'lambda_function')
SPECS = {'aws_tagged_resource': ('ec2', 'describe_instances', 'Reservations[].Instances[]')}
NATIVE_IDS = {'aws_tagged_resource': 'ResourceArn'}
READ_ACTIONS = {('ec2', 'describe_tags'), ('lambda', 'list_tags')}


def project_tag_response(response, *, service):
    """Redact tag credentials before cache without losing native continuation."""
    from .aws import ReadFailure, _safe, _CONTINUATION_KEYS
    if not isinstance(response, dict) or service not in ('ec2', 'lambda'):
        raise ReadFailure('malformed', 'native_tag_response_invalid')
    if '_coverage' in response:
        raise ReadFailure('malformed', 'native_tag_evidence_already_redacted')
    raw = response.get('Tags')
    if service == 'ec2':
        if not isinstance(raw, list) or any(not isinstance(row, dict) or '_coverage' in row for row in raw):
            raise ReadFailure('malformed', 'native_tag_array_missing')
        projected = {'Tags': [{key: row[key] for key in ('Key', 'Value', 'ResourceId', 'ResourceType') if key in row} for row in raw]}
    else:
        if not isinstance(raw, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in raw.items()):
            raise ReadFailure('malformed', 'native_tag_map_missing')
        projected = {'Tags': raw}
    # Apply credential redaction only to the actual tag subtree. Opaque native
    # NextToken is necessary for the existing paginator, never tag evidence.
    result = _safe(projected)
    if service == 'lambda' and not set(raw) <= set(result.get('Tags', {})):
        raise ReadFailure('malformed', 'native_tag_keys_removed_by_redaction')
    for key in _CONTINUATION_KEYS:
        if key not in response:
            continue
        value = response[key]
        if service != 'ec2' or key != 'NextToken' or not isinstance(value, str) or not value.strip() or len(value) > 16384:
            raise ReadFailure('malformed', 'native_tag_cursor_invalid')
        result['NextToken'] = value
    return result


def _tags(raw):
    if not isinstance(raw, list):
        raise ValueError('native tag array unavailable')
    tags = {}
    for row in raw:
        if (not isinstance(row, dict) or '_coverage' in row or not isinstance(row.get('Key'), str) or not row['Key']
                or not isinstance(row.get('Value'), str) or row['Key'] in tags):
            raise ValueError('native tag identity ambiguous')
        tags[row['Key']] = row['Value']
    return tags


def collect(requests, session, region, account):
    from .aws import ReadFailure, ReadResult
    partition = session.get_partition_for_region(region)
    prefix = 'arn:'+partition+':'
    seen, output = set(), []

    def inventory(service, operation, expression, **params):
        read = requests.pages(session, service, region, operation, expression, **params)
        if read.status not in ('collected', 'empty'):
            raise ReadFailure(read.status, (read.error or {}).get('code', 'tag_source_inventory_incomplete'))
        return read.items

    def emit(arn, source, tags, operations):
        from .aws import _safe
        if _safe({'Tags': tags}).get('Tags') != tags:
            raise ValueError('native tag evidence changed by snapshot redaction')
        if not isinstance(arn, str) or arn in seen:
            raise ValueError('duplicate native tagged resource')
        seen.add(arn)
        output.append({'ResourceArn': arn, 'SourceKind': source, 'AccountId': account,
                       'Region': region, 'Tags': tags, '_provenance': {
                           'read_only': True, 'source_operations': operations,
                           'boundary': 'Four enumerated resource families in this selected Region; S3 measured home Region only'}})

    try:
        instances = inventory('ec2', 'describe_instances', 'Reservations[].Instances[]')
        indexed = {}
        for row in instances:
            ident = row.get('InstanceId') if isinstance(row, dict) else None
            if not isinstance(ident, str) or not re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})', ident) or ident in indexed:
                raise ValueError('native instance identity invalid')
            indexed[ident] = {}
        # A complete tag listing joined to ALL described instances proves a
        # genuinely empty tag map without dropping never-tagged instances.
        for row in inventory('ec2', 'describe_tags', 'Tags', Filters=[{'Name': 'resource-type', 'Values': ['instance']}]):
            if (not isinstance(row, dict) or row.get('ResourceType') != 'instance'
                    or row.get('ResourceId') not in indexed):
                raise ValueError('tag belongs to unenumerated instance')
            target = indexed[row['ResourceId']]
            single = _tags([row])
            if set(single) & set(target):
                raise ValueError('duplicate instance tag key')
            target.update(single)
        for ident, tags in indexed.items():
            emit(prefix+'ec2:'+region+':'+account+':instance/'+ident, 'instance', tags,
                 ['ec2:DescribeInstances', 'ec2:DescribeTags'])

        databases = inventory('rds', 'describe_db_instances', 'DBInstances')
        for row in databases:
            arn = row.get('DBInstanceArn') if isinstance(row, dict) else None
            name = row.get('DBInstanceIdentifier') if isinstance(row, dict) else None
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,62}', name)
                    or arn != prefix+'rds:'+region+':'+account+':db:'+name):
                raise ValueError('foreign native database identity')
            emit(arn, 'rds_db_instance', _tags(row.get('TagList')), ['rds:DescribeDBInstances'])

        functions = inventory('lambda', 'list_functions', 'Functions')
        for row in functions:
            arn = row.get('FunctionArn') if isinstance(row, dict) else None
            name = row.get('FunctionName') if isinstance(row, dict) else None
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name)
                    or arn != prefix+'lambda:'+region+':'+account+':function:'+name):
                raise ValueError('foreign or version-qualified function')
            detail = requests.call(session, 'lambda', region, 'list_tags', Resource=arn)
            tags = detail.get('Tags') if isinstance(detail, dict) else None
            if not isinstance(tags, dict) or any(not isinstance(k, str) or not k or not isinstance(v, str) for k, v in tags.items()):
                raise ValueError('native Lambda tag map unavailable')
            emit(arn, 'lambda_function', tags, ['lambda:ListFunctions', 'lambda:ListTags'])

        buckets = inventory('s3', 'list_buckets', 'Buckets')
        bucket_names = set()
        for row in buckets:
            name = row.get('Name') if isinstance(row, dict) else None
            if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,62}', name) or name in bucket_names:
                raise ValueError('invalid duplicate native bucket')
            bucket_names.add(name)
            location = requests.call(session, 's3', region, 'get_bucket_location', Bucket=name, ExpectedBucketOwner=account)
            if not isinstance(location, dict):
                raise ValueError('bucket home Region unavailable')
            if 'LocationConstraint' not in location and location.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
                raise ValueError('bucket home Region unavailable')
            # A successful empty us-east-1 XML LocationConstraint is omitted by
            # botocore's actual REST-XML parser; retain the HTTP200 proof.
            home = location.get('LocationConstraint')
            home = 'us-east-1' if home is None else 'eu-west-1' if home == 'EU' else home
            if not isinstance(home, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+', home):
                raise ValueError('bucket home Region malformed')
            if home != region:
                continue
            try:
                response = requests.call(session, 's3', home, 'get_bucket_tagging', Bucket=name, ExpectedBucketOwner=account)
                tags = _tags(response.get('TagSet') if isinstance(response, dict) else None)
            except ReadFailure as exc:
                if exc.code != 'NoSuchTagSet':
                    raise
                tags = {}
            emit(prefix+'s3:::'+name, 'bucket', tags,
                 ['s3:ListBuckets', 's3:GetBucketLocation', 's3:GetBucketTagging'])
        return ReadResult(output, 'collected' if output else 'empty')
    except ReadFailure as exc:
        return ReadResult([], exc.status, {'code': exc.code})
    except (ValueError, TypeError, AttributeError):
        return ReadResult([], 'malformed', {'code': 'native_priority_tag_binding_invalid'})


FETCHERS = {'aws_tagged_resource': collect}
