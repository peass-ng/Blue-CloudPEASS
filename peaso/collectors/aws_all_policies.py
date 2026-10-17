"""All managed IAM default documents, including unattached AWS policies."""
from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor


def collect(requests, session, region, account):
    from .aws import ReadResult, _policy
    inventory = requests.pages(session, 'iam', region, 'list_policies', 'Policies', Scope='All', OnlyAttached=False)
    seen = set()
    malformed = False
    rows = []
    for item in inventory.items:
        arn, version = item.get('Arn'), item.get('DefaultVersionId')
        if (not isinstance(arn, str) or not re.fullmatch(r'arn:(aws|aws-cn|aws-us-gov):iam::(?:'+re.escape(account)+r'|aws):policy/.+', arn)
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
        row['DefaultDocument'] = {'collection_status': 'collected' if valid else 'partial',
                                  'VersionId': row['DefaultVersionId']}
        if valid:
            row['DefaultDocument']['Document'] = _policy(version['Document'])
        row['_provenance'] = {'operation': 'iam:ListPolicies', 'managed_scope': 'All', 'only_attached': False,
                              'account_id': account, 'default_operation': 'iam:GetPolicyVersion'}
        return row, valid
    with ThreadPoolExecutor(max_workers=min(8, requests.workers)) as pool:
        results = list(pool.map(read, rows))
    items = [row for row, _ in results]
    complete = inventory.status in ('collected', 'empty') and not malformed and all(ok for _, ok in results)
    return ReadResult(items, ('collected' if items else 'empty') if complete else ('partial' if items else 'not_collected'),
                      None if complete else {'code': 'all_managed_policy_inventory_incomplete'})
