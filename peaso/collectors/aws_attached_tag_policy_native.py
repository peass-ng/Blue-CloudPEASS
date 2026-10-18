"""Finite literal TAG_POLICY digests before shared response caching.

DescribePolicy has no target account parameter. The digest binds the full native
policy ARN (including management account and organization), ID and tag key. The
collector separately proves attachment to the audited account's ancestor path.
"""
import hashlib
import json
import re

PROJECTION = 'attached-tag-policy-digests-v1'
DOMAIN = 'peaso:aws:organizations:attached-tag-policy:finite-value:v1'
ARN = re.compile(r'arn:(aws(?:-[a-z0-9-]+)?):organizations::[0-9]{12}:policy/o-[a-z0-9]{10,32}/tag_policy/(p-[a-zA-Z0-9_]{8,128})')


def invalid():
    from .aws import ReadFailure
    raise ReadFailure('malformed', 'attached_tag_policy_projection_invalid')


def value_digest(arn, identifier, key, value):
    return hashlib.sha256(json.dumps([DOMAIN, arn, identifier, key, value],
        ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def project_response(response):
    from .aws_organizations_native import _policy, _literal_tags
    policy = response.get('Policy') if isinstance(response, dict) else None
    summary = policy.get('PolicySummary') if isinstance(policy, dict) else None
    if not isinstance(summary, dict) or summary.get('Type') != 'TAG_POLICY':
        invalid()
    identifier, arn = summary.get('Id'), summary.get('Arn')
    match = ARN.fullmatch(arn) if isinstance(arn, str) else None
    if match is None or match[2] != identifier or summary.get('AwsManaged', False) is not False:
        invalid()
    try:
        document = _policy(policy.get('Content'))
        tags = _literal_tags(document)
        unrestricted = [definition['tag_key']['@@assign'] for definition in document['tags'].values()
                        if 'tag_value' not in definition]
    except (ValueError, TypeError, KeyError):
        invalid()
    assignments = [{'TagKey': key, 'ConstraintKind': 'finite',
        'ValueDigests': sorted(value_digest(arn, identifier, key, value) for value in values)}
        for key, values in tags.items()]
    assignments += [{'TagKey': key, 'ConstraintKind': 'unrestricted', 'ValueDigests': []}
                    for key in unrestricted]
    return {'_metadata_projection': PROJECTION, 'Policy': {'PolicySummary': {
        'Id': identifier, 'Arn': arn, 'Type': 'TAG_POLICY', 'AwsManaged': False},
        'TagValueDigests': sorted(assignments, key=lambda entry: entry['TagKey'])}}


def validate_assignments(assignments):
    if not isinstance(assignments, list):
        invalid()
    seen = set()
    for entry in assignments:
        if not isinstance(entry, dict) or set(entry) != {'TagKey', 'ConstraintKind', 'ValueDigests'}:
            invalid()
        key, kind, digests = entry['TagKey'], entry['ConstraintKind'], entry['ValueDigests']
        if (not isinstance(key, str) or not key or key in seen or kind not in {'finite', 'unrestricted'}
                or not isinstance(digests, list)
                or any(not isinstance(d, str) or re.fullmatch(r'[0-9a-f]{64}', d) is None for d in digests)
                or sorted(set(digests)) != digests or kind == 'unrestricted' and digests):
            invalid()
        seen.add(key)
    return assignments
