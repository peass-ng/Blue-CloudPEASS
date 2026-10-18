"""Metadata-only IAM policy attachment identities and own-account metric names."""
from __future__ import annotations

import hashlib
import json
import re

SPECS = {'iam_identity': ('iam', 'get_account_authorization_details', None),
         'cloudwatch_metric': ('cloudwatch', 'list_metrics', 'Metrics')}
GLOBAL_TYPES = {'iam_identity'}
NATIVE_IDS = {'iam_identity': 'Arn', 'cloudwatch_metric': 'id'}
READ_ACTIONS = {('iam', 'get_account_authorization_details'), ('cloudwatch', 'list_metrics')}


def _result(rows=(), status=None, code=None):
    from .aws import ReadResult
    rows = list(rows)
    return ReadResult(rows, status or ('collected' if rows else 'empty'), {'code': code} if code else None)


def _partition(region):
    return 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'


def identities(requests, session, region, account):
    rows, seen = [], set()
    partition = _partition(region)
    for kind, expression, label in [('USER', 'UserDetailList', 'user'), ('GROUP', 'GroupDetailList', 'group'),
                                     ('ROLE', 'RoleDetailList', 'role')]:
        # Exclude thousands of managed policy definitions: only these three
        # identity families and their attachment metadata are needed. All
        # three views share the same cached pages, without usage-report jobs.
        read = requests.pages(session, 'iam', region, 'get_account_authorization_details', expression,
                              Filter=['User', 'Group', 'Role'], MaxItems=1000)
        if read.status not in ('collected', 'empty'):
            return _result(rows, 'partial' if rows else read.status,
                           (read.error or {}).get('code', 'iam_identity_read_incomplete'))
        for item in read.items:
            arn = item.get('Arn') if isinstance(item, dict) else None
            if (not isinstance(arn, str) or arn in seen or not re.fullmatch(
                    'arn:' + re.escape(partition) + ':iam::' + re.escape(account) + ':' + label + '/.+', arn)):
                return _result(rows, 'partial' if rows else 'malformed', 'iam_identity_arn_invalid')
            attached = item.get('AttachedManagedPolicies', [])
            if not isinstance(attached, list):
                return _result(rows, 'partial' if rows else 'malformed', 'iam_policy_attachments_malformed')
            policies, policy_ids = [], set()
            for policy in attached:
                policy_arn = policy.get('PolicyArn') if isinstance(policy, dict) else None
                if (not isinstance(policy_arn, str) or policy_arn in policy_ids or not re.fullmatch(
                        'arn:' + re.escape(partition) + ':iam::(?:aws|' + re.escape(account) + '):policy/.+', policy_arn)):
                    return _result(rows, 'partial' if rows else 'malformed', 'iam_attached_policy_arn_invalid')
                policy_ids.add(policy_arn)
                policies.append({'PolicyArn': policy_arn})
            seen.add(arn)
            rows.append({'Arn': arn, 'IdentityType': kind, 'AttachedManagedPolicies': policies,
                '_provenance': {'source_operation': 'GetAccountAuthorizationDetails', 'read_only': True,
                    'native_response_complete': True, 'optional_fields_complete': ['AttachedManagedPolicies'],
                    'usage_reports_generated': False}})
    return _result(rows)


def metrics(requests, session, region, account):
    read = requests.pages(session, 'cloudwatch', region, 'list_metrics', 'Metrics', IncludeLinkedAccounts=False)
    rows, seen = [], set()
    for item in read.items:
        if not isinstance(item, dict):
            return _result(rows, 'partial' if rows else 'malformed', 'cloudwatch_metric_malformed')
        namespace, name = item.get('Namespace'), item.get('MetricName')
        dimensions = item.get('Dimensions', [])
        if (not isinstance(namespace, str) or not 1 <= len(namespace) <= 255
                or not isinstance(name, str) or not 1 <= len(name) <= 255
                or not isinstance(dimensions, list) or len(dimensions) > 30):
            return _result(rows, 'partial' if rows else 'malformed', 'cloudwatch_metric_identity_invalid')
        normalized, dimension_names = [], set()
        for dimension in dimensions:
            if (not isinstance(dimension, dict) or not isinstance(dimension.get('Name'), str)
                    or not dimension['Name'] or dimension['Name'] in dimension_names
                    or not isinstance(dimension.get('Value'), str) or not dimension['Value']):
                return _result(rows, 'partial' if rows else 'malformed', 'cloudwatch_metric_dimensions_invalid')
            dimension_names.add(dimension['Name'])
            normalized.append({'Name': dimension['Name'], 'Value': dimension['Value']})
        normalized.sort(key=lambda row: row['Name'])
        identity = json.dumps([namespace, name, normalized], sort_keys=True, separators=(',', ':'))
        if identity in seen:
            return _result(rows, 'partial' if rows else 'malformed', 'cloudwatch_metric_duplicate_identity')
        seen.add(identity)
        rows.append({'id': 'cloudwatch-metric:' + hashlib.sha256(identity.encode()).hexdigest(),
            'Namespace': namespace, 'MetricName': name, 'Dimensions': normalized,
            '_provenance': {'source_operation': 'ListMetrics', 'read_only': True,
                'include_linked_accounts': False, 'semantics': 'metric metadata; values and ingestion freshness unassessed'}})
    if read.status not in ('collected', 'empty'):
        return _result(rows, 'partial' if rows else read.status,
                       (read.error or {}).get('code', 'cloudwatch_metric_listing_incomplete'))
    return _result(rows)


FETCHERS = {'iam_identity': identities, 'cloudwatch_metric': metrics}
