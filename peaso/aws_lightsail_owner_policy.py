"""Explicit Lightsail management-policy criteria, never observed IAM evidence."""
import copy
from datetime import datetime
import re

NAMESPACE = 'aws_lightsail_bucket_iam'
AUTHORITY = {'status', 'scope', 'observed_at', 'max_age_seconds'}
PARAMETERS = {'iam_required_lightsail_bucket_arns', 'approved_lightsail_principals', 'approved_lightsail_actions'}
MAX_AGE = 365 * 86400
# Resource support from AWS Lightsail Service Authorization Reference (2026-10-15).
# These names describe observed policy statements. No write action is executed.
BUCKET_ACTIONS = frozenset(('CreateBucketAccessKey', 'DeleteBucket', 'DeleteBucketAccessKey',
    'SetResourceAccessForBucket', 'TagResource', 'UntagResource', 'UpdateBucket', 'UpdateBucketBundle'))
SCOPE = r'([0-9]{12})/([a-z]{2}(?:-[a-z]+)+-[0-9])'


def normalize(options):
    parent = options.get('compliance_parameters')
    if not isinstance(parent, dict) or NAMESPACE not in parent:
        return None
    raw = parent[NAMESPACE]
    def invalid():
        raise ValueError('invalid Lightsail IAM owner criteria')
    if (not isinstance(raw, dict) or set(raw) != AUTHORITY | {'parameters'}
            or raw['status'] != 'collected' or not isinstance(raw['scope'], str)
            or not re.fullmatch(SCOPE, raw['scope'])):
        invalid()
    account, region = raw['scope'].split('/')
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    if type(raw['max_age_seconds']) is not int or not 1 <= raw['max_age_seconds'] <= MAX_AGE:
        invalid()
    stamp = raw['observed_at']
    if not isinstance(stamp, str) or not 1 <= len(stamp) <= 64:
        invalid()
    try:
        parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            invalid()
    except (ValueError, OverflowError):
        invalid()
    values = raw['parameters']
    if not isinstance(values, dict) or set(values) != PARAMETERS:
        invalid()
    def strings(key, bound):
        rows = values[key]
        if (not isinstance(rows, list) or not 1 <= len(rows) <= bound
                or any(not isinstance(x, str) or not 1 <= len(x) <= 2048 for x in rows)
                or len(set(rows)) != len(rows)):
            invalid()
        return rows
    buckets = strings('iam_required_lightsail_bucket_arns', 1000)
    prefix = 'arn:' + partition + ':lightsail:' + region + ':' + account + ':Bucket/'
    if any(not re.fullmatch(re.escape(prefix) + r'[A-Za-z0-9][A-Za-z0-9-]{0,127}', x) for x in buckets):
        invalid()
    principals = strings('approved_lightsail_principals', 1000)
    iam = 'arn:' + partition + ':iam::' + account + ':'
    if any(not re.fullmatch(re.escape(iam) + r'(?:user|role)/[A-Za-z0-9+=,.@_/-]{1,512}', x) for x in principals):
        invalid()
    actions = strings('approved_lightsail_actions', len(BUCKET_ACTIONS))
    supported = {'lightsail:' + x.casefold() for x in BUCKET_ACTIONS}
    if (any(x.casefold() not in supported for x in actions)
            or len({x.casefold() for x in actions}) != len(actions)):
        invalid()
    # Bulk enrichment later merges raw and derived flat policies. Disallow a
    # competing authority now, including matching values, rather than rebind it.
    legacy = options.get('compliance_policy')
    if isinstance(legacy, dict) and (AUTHORITY | PARAMETERS | {'parameters'}).intersection(legacy):
        invalid()
    return copy.deepcopy(raw)


def bind_scopes(owner, scopes):
    if owner is not None and scopes != [owner['scope']]:
        raise ValueError('Lightsail IAM criteria require one exact selected account/region')


def owner_metadata(owner, observed_at):
    """Keep supplied approval time; stale/future declarations cannot prove PASS."""
    if owner is None:
        return None
    result = {k: copy.deepcopy(owner[k]) for k in AUTHORITY}
    result.update(copy.deepcopy(owner['parameters']))
    approved = datetime.fromisoformat(owner['observed_at'].replace('Z', '+00:00'))
    now = datetime.fromisoformat(observed_at.replace('Z', '+00:00')) if isinstance(observed_at, str) else observed_at
    if not 0 <= (now - approved).total_seconds() <= owner['max_age_seconds']:
        result['status'] = 'unknown'
        result['owner_authority_status'] = 'stale_or_future'
    return result


def merge_metadata(metadata, projected):
    if projected is None:
        return
    prior = metadata.get('compliance_policy', {})
    if not isinstance(prior, dict):
        raise ValueError('ambiguous Lightsail owner policy')
    if any(k in prior and prior[k] != v for k, v in projected.items()):
        raise ValueError('conflicting Lightsail flat owner authority or criteria')
    metadata['compliance_policy'] = {**copy.deepcopy(prior), **copy.deepcopy(projected)}
