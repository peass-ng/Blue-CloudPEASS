"""Scoped Macie finding metadata, projected before the shared response cache.

Never reads object content, sensitive-data samples, occurrence locations, custom
identifier definitions or classification result files. Finding enumeration is
not proof that the authorized bucket/object scan universe was fully examined.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

KIND = 'macie_finding'
SPECS = {KIND: ('macie2', 'list_findings', 'findingIds')}
NATIVE_IDS = {KIND: 'id'}
READ_ACTIONS = {('macie2', 'list_findings'), ('macie2', 'get_findings')}
MAX_FINDINGS = 1000
PROJECTION = 'macie-finding-metadata-v2'
OBJECT_IDENTITY = 'sha256-json-bucket-key-version-v1'


def _invalid():
    from .aws import ReadFailure
    raise ReadFailure('malformed', 'macie_finding_metadata_invalid')


def _id(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value))



def _object_binding(obj, bucket_arn):
    """Project one native object identity without retaining its plaintext key."""
    if not isinstance(obj, dict):
        return None
    key, version, etag = obj.get('key'), obj.get('versionId'), obj.get('eTag')
    if (not isinstance(key, str) or not key or len(key.encode('utf-8')) > 1024
            or (version is not None and (not isinstance(version, str) or not version or len(version) > 1024))
            or (etag is not None and (not isinstance(etag, str) or not etag or len(etag) > 256))
            or (version is None and etag is None)):
        return None
    canonical = json.dumps([bucket_arn, key, version, etag], ensure_ascii=False,
                           separators=(',', ':')).encode('utf-8')
    return {'objectIdentitySha256': hashlib.sha256(canonical).hexdigest(),
            'identityAlgorithm': OBJECT_IDENTITY,
            **({'versionId': version} if version is not None else {}),
            **({'eTag': etag} if etag is not None else {})}


def _origin_binding(details, partition, region, account):
    if not isinstance(details, dict):
        return None
    origin, job_id, job_arn = details.get('originType'), details.get('jobId'), details.get('jobArn')
    if origin == 'AUTOMATED_SENSITIVE_DATA_DISCOVERY':
        return {'originType': origin} if job_id is None and job_arn is None else None
    if origin == 'SENSITIVE_DATA_DISCOVERY_JOB':
        expected = f'arn:{partition}:macie2:{region}:{account}:classification-job/{job_id}'
        if (isinstance(job_id, str) and re.fullmatch(r'[a-fA-F0-9]{32}', job_id)
                and job_arn == expected):
            return {'originType': origin, 'jobId': job_id, 'jobArn': job_arn}
    return None



def _finding_time(value, observed):
    if value is None:
        return None, True
    if not isinstance(value, str):
        return None, False
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None, False
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed > observed + timedelta(minutes=5):
        return None, False
    return parsed.astimezone(timezone.utc).isoformat(), True


def project_response(response):
    """Runs inside Requests before any Future/cache receives GetFindings data."""
    if not isinstance(response, dict) or not isinstance(response.get('findings'), list) or len(response['findings']) > 50:
        _invalid()
    rows, seen = [], set()
    for finding in response['findings']:
        if not isinstance(finding, dict) or not _id(finding.get('id')) or finding['id'] in seen:
            _invalid()
        seen.add(finding['id'])
        if type(finding.get('sample')) is not bool:
            _invalid()
        if finding['sample']:
            rows.append({'id': finding['id'], 'sample': True})
            continue
        account, region, partition = finding.get('accountId'), finding.get('region'), finding.get('partition')
        if (not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account)
                or not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]', region)
                or partition not in {'aws', 'aws-cn', 'aws-us-gov'}
                or type(finding.get('archived')) is not bool or finding.get('category') not in {'CLASSIFICATION', 'POLICY'}):
            _invalid()
        resources = finding.get('resourcesAffected')
        bucket = resources.get('s3Bucket') if isinstance(resources, dict) else None
        if (not isinstance(bucket, dict) or not isinstance(bucket.get('name'), str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket['name'])
                or bucket.get('arn') != f"arn:{partition}:s3:::{bucket['name']}"):
            _invalid()
        obj = resources.get('s3Object')
        if obj is not None and (not isinstance(obj, dict) or obj.get('bucketArn', bucket['arn']) != bucket['arn']):
            _invalid()
        object_binding = _object_binding(obj, bucket['arn'])
        observed = datetime.now(timezone.utc)
        created_at, created_valid = _finding_time(finding.get('createdAt'), observed)
        updated_at, updated_valid = _finding_time(finding.get('updatedAt'), observed)
        time_valid = created_valid and updated_valid and (created_at is None or updated_at is None or created_at <= updated_at)
        origin_binding = None
        names, bindings, complete = [], [], True
        verified, reported_total, classification_status = False, None, 'UNKNOWN'
        if finding['category'] == 'CLASSIFICATION':
            details = finding.get('classificationDetails')
            origin_binding = _origin_binding(details, partition, region, account)
            result = details.get('result') if isinstance(details, dict) else None
            status = result.get('status') if isinstance(result, dict) else None
            custom = result.get('customDataIdentifiers') if isinstance(result, dict) else None
            complete = isinstance(status, dict) and status.get('code') == 'COMPLETE'
            if isinstance(status, dict) and status.get('code') in {'COMPLETE', 'PARTIAL', 'SKIPPED'}:
                classification_status = status['code']
            # An omitted detector block is not promoted to a verified empty set.
            if not isinstance(custom, dict) or not isinstance(custom.get('detections'), list):
                complete = False
            else:
                total = custom.get('totalCount')
                if type(total) is not int or total < 0 or len(custom['detections']) > 1000:
                    _invalid()
                reported_total = total
                count, identifiers = 0, set()
                for detector in custom['detections']:
                    if not isinstance(detector, dict):
                        _invalid()
                    name, arn, occurrences = detector.get('name'), detector.get('arn'), detector.get('count')
                    if (not isinstance(name, str) or not 1 <= len(name) <= 128 or any(ord(c) < 32 for c in name)
                            or not isinstance(arn, str) or not re.fullmatch(
                                f'arn:{partition}:macie2:{region}:{account}:custom-data-identifier/[A-Za-z0-9_-]{{1,128}}', arn)
                            or arn in identifiers or name in names or type(occurrences) is not int or occurrences <= 0):
                        _invalid()
                    identifiers.add(arn); names.append(name); bindings.append({'name': name, 'arn': arn, 'count': occurrences}); count += occurrences
                complete = complete and count == total
                verified = classification_status in {'COMPLETE', 'PARTIAL'} and count == total
            complete = complete and object_binding is not None and origin_binding is not None and time_valid
        rows.append({'id': finding['id'], 'sample': False, 'accountId': account, 'region': region,
                     'partition': partition, 'archived': finding['archived'],
                     's3Object': {'bucketArn': bucket['arn'], **(object_binding or {})},
                     'classificationOrigin': origin_binding or {}, 'customIdentifierNames': sorted(names),
                     '_classification_metadata_complete': complete,
                     'detected_identifiers_verified': verified,
                     '_provenance': {'source_operation': 'macie2:ListFindings+GetFindings', 'read_only': True,
                                     'metadata_projection': PROJECTION, 'category': finding['category'],
                                     'classification_status': classification_status, 'custom_identifier_total_count': reported_total,
                                     'custom_identifier_bindings': bindings,
                                     'object_content_or_occurrences_retained': False,
                                     'scan_coverage_established': False,
                                     'observed_at': observed.isoformat(), 'finding_time_verified': time_valid,
                                     **({'finding_created_at': created_at} if created_at is not None else {}),
                                     **({'finding_updated_at': updated_at} if updated_at is not None else {})}})
    return {'findings': rows, '_metadata_projection': PROJECTION}


def collect(requests, session, region, account):
    from .aws import ReadResult
    full = getattr(requests, 'collect_all', False) is True
    listing = requests.pages(session, 'macie2', region, 'list_findings', 'findingIds',
                             _page_limit=None if full else 32, maxResults=50,
                             findingCriteria={'criterion': {'accountId': {'eq': [account]}, 'region': {'eq': [region]}}})
    if listing.status not in {'collected', 'empty'}:
        return ReadResult([], listing.status, listing.error)
    identifiers = listing.items
    if (not isinstance(identifiers, list) or (not full and len(identifiers) > MAX_FINDINGS)
            or any(not _id(value) for value in identifiers) or len(set(identifiers)) != len(identifiers)):
        return ReadResult([], 'malformed', {'code': 'macie_finding_inventory_invalid_or_limited'})
    rows, incomplete = [], False
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    for offset in range(0, len(identifiers), 50):
        batch = identifiers[offset:offset + 50]
        response = requests.detail(session, 'macie2', region, 'get_findings', findingIds=batch)
        if response.get('collection_status') != 'collected':
            return ReadResult(rows, 'partial' if rows else response.get('collection_status', 'unknown'),
                              response.get('error', {'code': 'macie_finding_details_unavailable'}))
        findings = response.get('findings')
        if (response.get('_metadata_projection') != PROJECTION or not isinstance(findings, list)
                or len(findings) != len(batch) or {row.get('id') for row in findings} != set(batch)):
            return ReadResult(rows, 'partial' if rows else 'malformed', {'code': 'macie_finding_details_identity_mismatch'})
        for row in findings:
            if row['sample']:
                continue
            if (row['accountId'], row['region'], row['partition']) != (account, region, partition):
                return ReadResult(rows, 'partial' if rows else 'malformed', {'code': 'macie_finding_foreign_scope'})
            row = dict(row)
            incomplete |= not row.pop('_classification_metadata_complete')
            row['_provenance'] = {**row['_provenance'], 'audited_scope': account + '/' + region}
            rows.append(row)
    return ReadResult(rows, 'partial' if incomplete else 'collected' if rows else 'empty',
                      {'code': 'macie_classification_metadata_incomplete'} if incomplete else None)


FETCHERS = {KIND: collect}
