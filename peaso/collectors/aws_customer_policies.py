"""Complete customer-managed IAM default policy documents, attached or not."""
from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor


def collect(requests, session, region, account):
    from .aws import ReadResult, _policy
    inventory = requests.pages(session, 'iam', region, 'list_policies', 'Policies', Scope='Local', OnlyAttached=False)
    seen, rows, malformed = set(), [], False
    for item in inventory.items:
        if not isinstance(item, dict):
            malformed = True
            continue
        arn, version = item.get('Arn'), item.get('DefaultVersionId')
        if (not isinstance(arn, str) or not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::'+re.escape(account)+r':policy/.+', arn)
                or arn in seen or not isinstance(version, str) or not re.fullmatch(r'v[1-9][0-9]*(?:\.[A-Za-z0-9-]*)?', version)):
            malformed = True
            continue
        seen.add(arn)
        rows.append(dict(item))
    def read(row):
        detail = requests.detail(session, 'iam', region, 'get_policy_version', PolicyArn=row['Arn'], VersionId=row['DefaultVersionId'])
        version = detail.get('PolicyVersion', {})
        valid = (detail.get('collection_status') == 'collected' and isinstance(version, dict)
                 and version.get('VersionId') == row['DefaultVersionId'] and version.get('IsDefaultVersion') is True
                 and 'Document' in version)
        detail_status = detail.get('collection_status')
        row['DefaultDocument'] = {'collection_status': 'collected' if valid else
                                  'partial' if detail_status == 'collected' else detail_status or 'partial',
                                  'VersionId': row['DefaultVersionId']}
        if not valid and isinstance(detail.get('error'), dict):
            row['DefaultDocument']['error'] = detail['error']
        if valid:
            row['DefaultDocument']['Document'] = _policy(version['Document'])
        row['_provenance'] = {'operation': 'iam:ListPolicies', 'managed_scope': 'Local', 'only_attached': False,
                              'account_id': account, 'default_operation': 'iam:GetPolicyVersion'}
        return row, valid
    with ThreadPoolExecutor(max_workers=min(8, requests.workers)) as pool:
        results = list(pool.map(read, rows))
    items = [row for row, _ in results]
    complete = inventory.status in ('collected', 'empty') and not malformed and all(ok for _, ok in results)
    status = ('collected' if items else 'empty') if complete else (
        'partial' if items else inventory.status if inventory.status not in ('collected', 'empty') else 'not_collected')
    cause = inventory.error if isinstance(inventory.error, dict) else {}
    return ReadResult(items, status, None if complete else {
        'code': cause.get('code') or 'customer_policy_inventory_incomplete',
        'cause_status': cause.get('cause_status', inventory.status)})
