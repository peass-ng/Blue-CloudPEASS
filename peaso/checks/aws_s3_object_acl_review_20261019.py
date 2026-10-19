"""Sampled current-object ACL predicate, pending central admission.

Prowler 1783527c1147f584f30b60f2d7ccc8a53b4a63b7 samples only when opt-in,
reports any Group URI without checking Permission, and makes a sampling error
MANUAL before inspecting known public objects. This corrected bounded predicate
retains proven grants on partial samples, honors BOE/IgnorePublicAcls, and never
turns an incomplete private sample into a bucket-wide safety claim. Bucket-level
Steampipe policy/ACL controls do not inspect individual current-object ACLs.
"""
from __future__ import annotations

import copy
import re

from . import result, unknown
from .facts import Unavailable, get
from .aws_a_facts import complete_items

CHECK_ID = 'aws.review.s3.sampled_object_acl_public_grants'
SOURCE_URL = ('https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/'
              'prowler/providers/aws/services/s3/s3_bucket_object_public/s3_bucket_object_public.py')
SOURCE_SHA256 = '0b483a90926f81e3b23b5559eb9efadfe4b0841cdc6b211f98b87e4d20b13eaa'
PUBLIC = {'http://acs.amazonaws.com/groups/global/AllUsers',
          'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}
PERMISSIONS = {'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'}
SEMANTICS = ('Sampled current object ACLs only; no unseen objects, historical versions, bucket-policy '
             'access, intended website approval or anonymous reachability assessment.')


def _field(row, name, expected):
    if not isinstance(row, dict) or name not in row:
        raise Unavailable('sample field missing: ' + name)
    coverage = row.get('_coverage', {})
    if not isinstance(coverage, dict):
        raise Unavailable('sample field coverage malformed')
    if name in coverage:
        marker = coverage[name]
        if not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty'):
            raise Unavailable('sample field unavailable: ' + name)
    value = row[name]
    if name in coverage and coverage[name]['status'] == 'empty' and not (
            value is None or value == '' or value == [] or value == {}):
        raise Unavailable('empty sample field coverage contradicts retained value: ' + name)
    if (type(value) is not expected if expected in (str, int, bool) else not isinstance(value, expected)):
        raise Unavailable('sample field malformed: ' + name)
    return value


def _ownership(item):
    detail = get(item, 'OwnershipControls', dict)
    if detail.get('collection_status') == 'empty':
        if (get(detail, 'absent', bool) and
                get(detail, 'error.code', str) == 'OwnershipControlsNotFoundError' and 'OwnershipControls' not in detail):
            return False
        raise Unavailable('ownership absence not authenticated')
    if get(detail, 'collection_status', str) != 'collected':
        raise Unavailable('ownership configuration unreadable')
    rules = get(detail, 'OwnershipControls.Rules', list)
    if len(rules) != 1:
        raise Unavailable('ownership rules malformed')
    mode = get(rules[0], 'ObjectOwnership', str)
    if mode not in ('BucketOwnerEnforced', 'BucketOwnerPreferred', 'ObjectWriter'):
        raise Unavailable('ownership mode unrecognized')
    return mode == 'BucketOwnerEnforced'


def _ignore(detail, *, complete_response=False):
    if detail.get('collection_status') == 'empty':
        if (get(detail, 'absent', bool) and
                get(detail, 'error.code', str) == 'NoSuchPublicAccessBlockConfiguration' and
                'PublicAccessBlockConfiguration' not in detail):
            return False
        raise Unavailable('public-block absence not authenticated')
    if ('collection_status' in detail and get(detail, 'collection_status', str) != 'collected') or (
            'collection_status' not in detail and not complete_response):
        raise Unavailable('public-block configuration unreadable')
    return get(detail, 'PublicAccessBlockConfiguration.IgnorePublicAcls', bool)


def _account_ignore(index, account):
    rows = complete_items(index, 's3_account_public_access_block', get(index, 'context.scope', str))
    if not rows:
        envelopes = index['collections']['s3_account_public_access_block']
        if all(envelope.get('status') == 'empty' and
               get(envelope, 'error.code', str) == 'NoSuchPublicAccessBlockConfiguration' for envelope in envelopes):
            return False
        raise Unavailable('account public-block absence lacks documented not-found proof')
    if len(rows) != 1:
        raise Unavailable('account public-block response not unique')
    row = rows[0]
    if ('AccountId' in row or 'AccountId' in row.get('_coverage', {})) and get(row, 'AccountId', str) != account:
        raise Unavailable('account public-block identity differs from bucket scope')
    # _single keeps successful SDK response fields raw; its complete collection
    # envelope authenticates this read rather than a synthetic detail marker.
    return _ignore(row, complete_response=True)


def _overrides(item, index, account):
    """One proven true override suffices; all false need complete evidence."""
    values, unresolved = {}, []
    for key, operation in (
        ('BucketOwnerEnforced', lambda: _ownership(item)),
        ('bucket_IgnorePublicAcls', lambda: _ignore(get(item, 'PublicAccessBlock', dict))),
        ('account_IgnorePublicAcls', lambda: _account_ignore(index, account)),
    ):
        try:
            values[key] = operation()
        except (Unavailable, ValueError, TypeError, KeyError, AttributeError):
            unresolved.append(key)
    return values, unresolved


def evaluate(item, index):
    try:
        name = get(item, 'Name', str)
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'aws':
            raise Unavailable('AWS provider context unavailable')
        scope = get(context, 'scope', str)
        match = re.fullmatch(r'([0-9]{12})/(?:global|[a-z]{2}(?:-[a-z0-9]+)+-\d+)', scope)
        if match is None:
            raise Unavailable('bucket account scope unavailable or contradictory')
        account = match[1]
        if ('AccountId' in item or 'AccountId' in item.get('_coverage', {})) and get(item, 'AccountId', str) != account:
            raise Unavailable('bucket account scope unavailable or contradictory')
        # Do not call get() on intentionally partial sample containers: preserve
        # independently validated positive object-grant evidence within them.
        if 'ObjectAclSample' in item.get('_coverage', {}):
            _field(item, 'ObjectAclSample', dict)
        sample = item.get('ObjectAclSample')
        if not isinstance(sample, dict) or _field(sample, 'bucket', str) != name:
            raise Unavailable('object ACL sample missing or for another bucket')
        if _field(sample, 'scope', str) != 'sampled_current_object_acls_only':
            raise Unavailable('object ACL sample scope unrecognized')
        status = _field(sample, 'collection_status', str)
        if status not in ('collected', 'partial', 'empty'):
            raise Unavailable('object ACL sample unreadable: ' + status)
        limit = _field(sample, 'limit', int)
        objects = _field(sample, 'objects', list)
        count = _field(sample, 'sampled_count', int)
        complete = _field(sample, 'listing_complete', bool)
        truncated = _field(sample, 'truncated', bool)
        errors = _field(sample, 'errors', list)
        if (not 1 <= limit <= 20 or count != len(objects) or not 0 <= count <= limit or
                complete and truncated or status == 'empty' and count != 0):
            raise Unavailable('object ACL sample count or completion contradictory')
        from peaso.collectors.aws_s3_object_acl_review_20261019 import bucket_region
        if _field(sample, 'region', str) != bucket_region(item):
            raise Unavailable('object ACL sample Region differs from verified bucket location')
        public, seen, unreadable = [], set(), status == 'partial' or bool(errors)
        for obj in objects:
            key = _field(obj, 'Key', str)
            if not key or key in seen or len(key.encode('utf-8')) > 1024:
                raise Unavailable('object sample key missing, duplicated or malformed')
            seen.add(key)
            state = _field(obj, 'collection_status', str)
            if state not in ('collected', 'partial'):
                unreadable = True
                continue
            grants = _field(obj, 'Grants', list)
            if not grants:
                unreadable = True
            unreadable |= state == 'partial'
            for grant in grants:
                try:
                    permission = get(grant, 'Permission', str)
                    kind = get(grant, 'Grantee.Type', str)
                    if permission not in PERMISSIONS or kind not in ('Group', 'CanonicalUser', 'AmazonCustomerByEmail'):
                        raise Unavailable('ACL permission or grantee type unrecognized')
                    if kind == 'Group':
                        uri = get(grant, 'Grantee.URI', str)
                        if uri in PUBLIC:
                            public.append({'Key': key, 'Permission': permission, 'Grantee': {'Type': kind, 'URI': uri}})
                except (Unavailable, TypeError, ValueError, KeyError, AttributeError):
                    unreadable = True
        overrides, unresolved = _overrides(item, index, account)
        evidence = {'bucket': name, 'sampled_count': count, 'listing_complete': complete,
                    'truncated': truncated, 'public_grants': public,
                    'acl_overrides': overrides, 'unresolved_overrides': unresolved,
                    'unseen_objects_assessed': False, 'semantics': SEMANTICS}
        if any(overrides.values()):
            return 'NOT_APPLICABLE', {**evidence, 'observed': 'Object ACL grants are disabled or ignored by a proven ownership/Public Access Block setting.'}
        if public and not unresolved:
            return result(True, **evidence, observed=f'{len(public)} public ACL grant(s) found across {count} sampled object(s); bucket-wide access is unassessed.')
        if public:
            return unknown('public ACL grants observed but ownership or IgnorePublicAcls evidence is unresolved', **evidence,
                           observed='Public ACL grants were sampled; unreadable ownership/Public Access Block settings prevent an exposure verdict.')
        if status == 'empty' and count == 0 and complete and not truncated:
            return 'EMPTY', {**evidence, 'observed': 'A complete current-object listing returned no objects; no object ACLs were assessed.'}
        if count == 0 or unreadable or not complete or truncated or status != 'collected':
            return unknown('private or empty partial sample does not establish other objects are private', **evidence,
                           observed=f'No public grant proved in {count} sampled object(s); incomplete sampling leaves other objects unassessed.')
        return result(False, **evidence, observed=f'No public ACL grants in {count} sampled current object(s); versions, policies and other access paths remain unassessed.')
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
        return unknown(str(exc), observed='Object ACL sampling evidence is missing, unreadable or malformed; no safety verdict is available.', semantics=SEMANTICS)


DECLARATIONS = [{'id': CHECK_ID, 'provider': 'aws', 'kind': 'bucket', 'category': 'exposure',
                 'severity': 'medium', 'control': 'AC-3', 'target': 'resource',
                 'dependencies': ['bucket', 's3_account_public_access_block'],
                 'allow_incomplete_failure': True,
                 'title': 'Sampled S3 current objects have no non-ignored public ACL grants',
                 'remediation': 'Review each sampled public grant against intended publishing; remove unintended grants or disable ACLs with BucketOwnerEnforced.',
                 'evaluator': 'evaluate'}]
ADMISSION_DATA = {'schema_version': 1, 'checks': [{
    'spec': {'id': CHECK_ID, 'provider': 'aws', 'resource_kind': 'bucket',
             'data_source': 'Location, ObjectAclSample, OwnershipControls, PublicAccessBlock, s3_account_public_access_block',
             'predicate': 'FAIL on a proven AllUsers/AuthenticatedUsers ACL permission in the sampled current objects when ACLs and both IgnorePublicAcls overrides are proven false, even if other sample reads are partial. Proven true override is NOT_APPLICABLE. Incomplete private/missing sample is UNKNOWN. Complete empty list is EMPTY; complete readable private sample PASS is sampled evidence only.',
             'severity': 'medium', 'category': 'exposure', 'title': DECLARATIONS[0]['title'],
             'description': 'Reads at most 20 current-object ACLs per global bucket. Reports exact sampled key/group/permission; never retrieves contents or asserts bucket-wide public safety. Intended public websites require contextual review.',
             'remediation_hint': DECLARATIONS[0]['remediation']},
    'description': {'description': 'Samples current-object ACL metadata for public group grants; no complete bucket-policy, historic version or anonymous access assessment.',
                    'evaluated': ['ObjectAclSample', 'Location', 'OwnershipControls', 'PublicAccessBlock', 's3_account_public_access_block'],
                    'pass_when': 'Complete readable sample/listing has no public object ACL grant; statement applies only to sampled current objects.',
                    'fail_when': 'A sampled ACL grants a recognized permission to AllUsers/AuthenticatedUsers and ownership plus bucket/account IgnorePublicAcls are proven non-suppressing; other partial sample reads do not discard this evidence.',
                    'not_applicable_when': 'BucketOwnerEnforced or bucket/account IgnorePublicAcls is proven enabled; unknown suppression remains UNKNOWN for public grants.'},
    'sources': [{'url': SOURCE_URL, 'sha256': SOURCE_SHA256}], 'requirements': [],
    'review_notes': 'PARTIAL/corrected source association to prowler.aws.s3_bucket_object_public; bounded sample, permission validation, override handling and positive evidence on partial reads differ from Prowler. Initial checklist mappings empty pending review.',
    'function': 'peaso.checks.aws_s3_object_acl_review_20261019:evaluate'}]}


def _fixture(public=False):
    account, name = '123456789012', 'sample-review-bucket'
    grant = {'Permission': 'READ', 'Grantee': {'Type': 'Group', 'URI': sorted(PUBLIC)[0]}} if public else {
        'Permission': 'FULL_CONTROL', 'Grantee': {'Type': 'CanonicalUser'}}
    item = {'Name': name, 'Location': {'collection_status': 'collected', 'LocationConstraint': None},
            'OwnershipControls': {'collection_status': 'collected', 'OwnershipControls': {'Rules': [{'ObjectOwnership': 'BucketOwnerPreferred'}]}},
            'PublicAccessBlock': {'collection_status': 'collected', 'PublicAccessBlockConfiguration': {'IgnorePublicAcls': False}},
            'ObjectAclSample': {'collection_status': 'collected', 'bucket': name, 'region': 'us-east-1',
                                'scope': 'sampled_current_object_acls_only', 'limit': 20, 'sampled_count': 1,
                                'listing_complete': True, 'truncated': False,
                                'objects': [{'Key': 'example.txt', 'collection_status': 'collected', 'Grants': [grant]}], 'errors': []}}
    row = {'AccountId': account, 'PublicAccessBlockConfiguration': {'IgnorePublicAcls': False}}
    envelopes = {'bucket': [{'type': 'bucket', 'status': 'collected', 'global': True, 'account_id': account,
                             'scope': account + '/global', 'items': [item]}],
                 's3_account_public_access_block': [{'type': 's3_account_public_access_block', 'status': 'collected',
                    'global': True, 'account_id': account, 'scope': account + '/global', 'items': [row]}]}
    return item, {'context': {'provider': 'aws', 'scope': account + '/global', 'Account': account},
                  'collections': envelopes, 'bucket': [{'data': item}], 's3_account_public_access_block': [{'data': row}]}


_PASS, _PASS_INDEX = _fixture()
_FAIL, _FAIL_INDEX = _fixture(True)
RUNTIME_CASES = {CHECK_ID: {'pass': copy.deepcopy(_PASS), 'fail': copy.deepcopy(_FAIL),
                           'pass_index': copy.deepcopy(_PASS_INDEX), 'fail_index': copy.deepcopy(_FAIL_INDEX),
                           'missing': {}, 'malformed': None}}
