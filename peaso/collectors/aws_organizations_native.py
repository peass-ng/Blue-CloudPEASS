"""Account-bound Organizations policy evidence through shared native reads.

SCP rows contain every observed attachment on a complete account-to-root path;
this is not an IAM allow decision. Management accounts are explicitly exempt.
Tag rows describe attached literal policies, not tag presence or merged policy
semantics. Unsupported merge operators remain unavailable.
"""
from __future__ import annotations

import json
import re

SPECS = {
    'aws_organization_account': ('organizations', 'list_accounts', 'Accounts'),
    'organization_effective_scp': ('organizations', 'list_policies_for_target', 'Policies'),
    'organization_tag_policy': ('organizations', 'list_policies_for_target', 'Policies'),
    'organization_resource_policy': ('organizations', 'describe_resource_policy', None),
}
GLOBAL_TYPES = set(SPECS) - {'aws_organization_account'}
NATIVE_IDS = {'organization_effective_scp': 'TargetAccountId', 'organization_tag_policy': 'Id',
              'organization_resource_policy': 'Id', 'aws_organization_account': 'Id'}
READ_ACTIONS = {('organizations', operation) for operation in (
    'describe_organization', 'list_accounts', 'list_parents', 'list_policies_for_target',
    'describe_policy', 'describe_resource_policy')}
_OK = ('collected', 'empty')


def _result(items=(), status=None, code=None):
    from .aws import ReadResult
    return ReadResult(list(items), status or ('collected' if items else 'empty'), {'code': code} if code else None)


def _failure(read):
    return _result([], read.status, (read.error or {}).get('code', 'organization_read_incomplete'))


def _organization(requests, session, region):
    response = requests.detail(session, 'organizations', region, 'describe_organization')
    if response.get('collection_status') not in _OK:
        return None, _result([], response.get('collection_status', 'unknown'),
                             response.get('error', {}).get('code', 'organization_read_incomplete'))
    org = response.get('Organization')
    owner = org.get('MasterAccountId') if isinstance(org, dict) else None
    if (not isinstance(org, dict) or not re.fullmatch(r'o-[a-z0-9]{10,32}', str(org.get('Id', '')))
            or not re.fullmatch(r'\d{12}', str(owner))):
        return None, _result([], 'malformed', 'organization_identity_invalid')
    partition = 'aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-') else 'aws'
    expected_arns = {
        'Arn': f"arn:{partition}:organizations::{owner}:organization/{org['Id']}",
        'MasterAccountArn': f"arn:{partition}:organizations::{owner}:account/{org['Id']}/{owner}",
    }
    if any(name in org and (not isinstance(org[name], str) or org[name] != expected)
           for name, expected in expected_arns.items()):
        return None, _result([], 'malformed', 'organization_arn_identity_invalid')
    return {**org, '_partition': partition}, None


def _policy(content):
    if not isinstance(content, (str, dict)):
        raise ValueError('organization_policy_content_invalid')
    if isinstance(content, str):
        if len(content) > 1_000_000:
            raise ValueError('organization_policy_content_oversized')
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError('organization_policy_duplicate_key')
                out[key] = value
            return out
        content = json.loads(content, object_pairs_hook=unique)
    if not isinstance(content, dict):
        raise ValueError('organization_policy_document_invalid')
    return content


def account_identities(requests, session, region, account):
    """Native account identities, projected into the requesting regional scope.

    Organizations ARNs are global and retained as native provenance rather than
    relabelled as regional resource ARNs. No workload/environment classification
    or cross-account reachability is inferred from account membership.
    """
    if not isinstance(account, str) or not re.fullmatch(r'\d{12}', account):
        return _result([], 'malformed', 'organization_audited_account_invalid')
    org, failure = _organization(requests, session, region)
    if failure:
        return failure
    accounts = requests.pages(session, 'organizations', region, 'list_accounts', 'Accounts')
    if accounts.status not in _OK:
        return _failure(accounts)
    rows, seen = [], set()
    try:
        for member in accounts.items:
            if not isinstance(member, dict):
                raise ValueError('organization_account_identity_invalid')
            identifier = member.get('Id')
            if not isinstance(identifier, str) or not re.fullmatch(r'\d{12}', identifier) or identifier in seen:
                raise ValueError('organization_account_identity_invalid')
            arn = member.get('Arn')
            expected = (f"arn:{org['_partition']}:organizations::{org['MasterAccountId']}:"
                        f"account/{org['Id']}/{identifier}")
            if arn != expected:
                raise ValueError('organization_account_arn_invalid')
            state = member.get('State') if 'State' in member else member.get('Status')
            if state not in {'ACTIVE', 'SUSPENDED', 'PENDING_CLOSURE', 'PENDING_ACTIVATION', 'CLOSED'}:
                raise ValueError('organization_account_state_invalid')
            seen.add(identifier)
            rows.append({'Id': identifier, 'AccountId': account, 'Region': region,
                         'OrganizationId': org['Id'], 'ManagementAccountId': org['MasterAccountId'],
                         'State': state, '_provenance': {
                             'source_operation': 'DescribeOrganization+ListAccounts',
                             'read_only': True, 'native_arn': arn,
                             'semantics': 'account identity only; workload classification and boundary links unassessed'}})
        if account not in seen or org['MasterAccountId'] not in seen:
            raise ValueError('organization_account_membership_incomplete')
    except (ValueError, TypeError, KeyError) as exc:
        code = str(exc) if isinstance(exc, ValueError) else 'organization_account_evidence_malformed'
        return _result(rows, 'partial' if rows else 'malformed', code)
    return _result(rows)


def _policy_summary(summary, org, kind, identifier):
    if (not isinstance(summary, dict) or summary.get('Id') != identifier
            or summary.get('Type') != kind or not re.fullmatch(r'p-[a-zA-Z0-9_]{8,128}', str(identifier))):
        return False
    service_type = {'SERVICE_CONTROL_POLICY': 'service_control_policy', 'TAG_POLICY': 'tag_policy'}[kind]
    arn = summary.get('Arn')
    if summary.get('AwsManaged') is True:
        return (kind == 'SERVICE_CONTROL_POLICY' and identifier == 'p-FullAWSAccess'
                and isinstance(arn, str) and bool(re.fullmatch(
                    'arn:' + re.escape(org['_partition']) + r':organizations::aws:policy/service_control_policy/p-FullAWSAccess', arn)))
    return isinstance(arn, str) and bool(re.fullmatch(
        'arn:' + re.escape(org['_partition']) + r':organizations::' + re.escape(org['MasterAccountId'])
        + r':policy/' + re.escape(org['Id']) + '/' + service_type + '/' + re.escape(identifier), arn))


def effective_scp(requests, session, region, account):
    from .aws import _scp_policies, _organization_parents
    org, failure = _organization(requests, session, region)
    if failure:
        return failure
    accounts = requests.pages(session, 'organizations', region, 'list_accounts', 'Accounts')
    if accounts.status not in _OK:
        return _failure(accounts)
    rows, seen = [], set()
    try:
        for member in accounts.items:
            identifier = member.get('Id') if isinstance(member, dict) else None
            if not isinstance(identifier, str) or not re.fullmatch(r'\d{12}', identifier) or identifier in seen:
                raise ValueError('organization_account_identity_invalid')
            seen.add(identifier)
            state = member.get('State') or member.get('Status')
            if state not in ('ACTIVE', 'SUSPENDED', 'PENDING_CLOSURE', 'PENDING_ACTIVATION', 'CLOSED'):
                raise ValueError('organization_account_state_invalid')
            if state != 'ACTIVE':
                continue
            if identifier == org['MasterAccountId']:
                rows.append({'AccountId': account, 'TargetAccountId': identifier, 'Policies': [], 'ScpApplicable': False,
                             'OrganizationId': org['Id'], 'Complete': True,
                             '_provenance': {'source_operation': 'DescribeOrganization', 'read_only': True,
                                             'reason': 'SCPs do not restrict the management account'}})
                continue
            parents = _organization_parents(requests, session, region, identifier)
            if parents.status not in _OK:
                return _result(rows, 'partial' if rows else parents.status,
                               (parents.error or {}).get('code', 'organization_parent_incomplete'))
            if not parents.items or parents.items[-1].get('ParentType') != 'ROOT':
                raise ValueError('organization_account_root_path_unavailable')
            read = _scp_policies(requests, session, region, identifier)
            if read.status not in _OK:
                return _result(rows, 'partial' if rows else read.status,
                               (read.error or {}).get('code', 'organization_scp_incomplete'))
            policies = []
            for entry in read.items:
                detail = entry.get('Detail', {}).get('Policy', {})
                if (entry.get('InheritanceComplete') is not True
                        or not _policy_summary(detail.get('PolicySummary'), org, 'SERVICE_CONTROL_POLICY', entry.get('Id'))):
                    raise ValueError('organization_scp_policy_identity_invalid')
                content = _policy(detail.get('Content'))
                statements = content.get('Statement')
                if isinstance(statements, dict):
                    content = {**content, 'Statement': [statements]}
                elif not isinstance(statements, list):
                    raise ValueError('organization_scp_statement_invalid')
                policies.append({'Id': entry['Id'], 'Content': content,
                                 'Attachments': entry['Attachments']})
            rows.append({'AccountId': account, 'TargetAccountId': identifier, 'OrganizationId': org['Id'], 'Policies': policies,
                'ScpApplicable': True, 'Complete': True,
                'ParentPath': parents.items[-1]['ParentPath'],
                '_provenance': {'source_operation': 'ListPoliciesForTarget+DescribePolicy+ListParents',
                                'read_only': True, 'complete_account_to_root_path': True}})
        if account not in seen:
            raise ValueError('audited_account_absent_from_organization')
    except (ValueError, TypeError, KeyError) as exc:
        code = str(exc) if isinstance(exc, ValueError) and str(exc).startswith('organization_') else 'organization_evidence_malformed'
        return _result(rows, 'partial' if rows else 'malformed', code)
    return _result(rows)


def _literal_tags(document):
    tags = document.get('tags')
    if not isinstance(tags, dict):
        raise ValueError('organization_tag_schema_invalid')
    def assigned(value):
        # AWS's documented child-control metadata does not change this document's
        # literal assignment. This is not an effective inheritance calculation.
        lock = '@@operators_allowed_for_child_policies'
        if not isinstance(value, dict) or '@@assign' not in value or set(value) - {'@@assign', lock}:
            raise ValueError('organization_tag_merge_semantics_unsupported')
        if lock in value:
            operators = value[lock]
            if (not isinstance(operators, list) or not operators
                    or any(not isinstance(operator, str) for operator in operators)
                    or len(set(operators)) != len(operators)
                    or operators not in (['@@none'], ['@@all']) and
                       not set(operators) <= {'@@assign', '@@append', '@@remove'}):
                raise ValueError('organization_tag_merge_semantics_unsupported')
        return value['@@assign']
    output, seen, logical_seen = {}, set(), set()
    for logical, definition in tags.items():
        if not isinstance(logical, str) or not logical or logical.casefold() in logical_seen:
            raise ValueError('organization_tag_logical_identity_invalid')
        logical_seen.add(logical.casefold())
        if not isinstance(definition, dict):
            raise ValueError('organization_tag_definition_invalid')
        key = assigned(definition.get('tag_key'))
        if not isinstance(key, str) or not key or key in seen or logical.casefold() != key.casefold():
            raise ValueError('organization_tag_merge_semantics_unsupported')
        seen.add(key)
        # Omitted tag_value is documented as unrestricted, including no value.
        # It contributes no finite allowed-value constraint to this document.
        # Explicit null or unresolved inheritance operators are not omissions.
        if 'tag_value' not in definition:
            continue
        values = assigned(definition['tag_value'])
        if (not isinstance(values, list) or any(not isinstance(v, str) or not v or '*' in v for v in values)
                or len(values) != len(set(values))):
            raise ValueError('organization_tag_merge_semantics_unsupported')
        output[key] = values
    return output


def tag_policies(requests, session, region, account):
    from .aws import _organization_parents, ReadFailure
    org, failure = _organization(requests, session, region)
    if failure:
        # DescribeOrganization's exact native code proves this credential
        # account is standalone. It has no Organizations TAG_POLICY attached;
        # no inference is made from error messages or from unreadable metadata.
        if (failure.error or {}).get('code') == 'AWSOrganizationsNotInUseException':
            return _result([], 'empty', 'AWSOrganizationsNotInUseException')
        return failure
    parents = _organization_parents(requests, session, region, account)
    if parents.status not in _OK:
        return _failure(parents)
    if not parents.items or parents.items[-1].get('ParentType') != 'ROOT':
        return _result([], 'malformed', 'organization_account_root_path_unavailable')
    targets = [account] + [parent['ParentId'] for parent in parents.items]
    rows = {}
    for target in targets:
        read = requests.pages(session, 'organizations', region, 'list_policies_for_target', 'Policies',
                              TargetId=target, Filter='TAG_POLICY')
        if read.status not in _OK:
            return _result(rows.values(), 'partial' if rows else read.status,
                           (read.error or {}).get('code', 'organization_tag_attachments_incomplete'))
        seen = set()
        for summary in read.items:
            identifier = summary.get('Id') if isinstance(summary, dict) else None
            if identifier in seen or not _policy_summary(summary, org, 'TAG_POLICY', identifier):
                return _result(rows.values(), 'partial' if rows else 'malformed', 'organization_tag_identity_invalid')
            seen.add(identifier)
            if identifier not in rows:
                detail = requests.detail(session, 'organizations', region, 'describe_policy', PolicyId=identifier)
                if detail.get('collection_status') not in _OK:
                    return _result(rows.values(), 'partial' if rows else detail.get('collection_status', 'unknown'),
                                   detail.get('error', {}).get('code', 'organization_tag_detail_incomplete'))
                policy = detail.get('Policy', {})
                if not _policy_summary(policy.get('PolicySummary'), org, 'TAG_POLICY', identifier):
                    return _result(rows.values(), 'partial' if rows else 'malformed', 'organization_tag_detail_identity_invalid')
                try:
                    from .aws_attached_tag_policy_native import PROJECTION, validate_assignments
                    if detail.get('_metadata_projection') != PROJECTION or 'Content' in policy:
                        raise ValueError('unprojected_tag_policy')
                    assignments = validate_assignments(policy.get('TagValueDigests'))
                except (ValueError, TypeError, ReadFailure):
                    return _result(rows.values(), 'partial' if rows else 'malformed', 'organization_tag_merge_semantics_unsupported')
                rows[identifier] = {'Id': identifier, 'PolicyType': 'TAG_POLICY', 'AttachedToAccountPath': True,
                    'AccountId': account, 'Complete': True, 'TagValueDigests': assignments,
                    'NativePolicyArn': policy['PolicySummary']['Arn'], '_metadata_projection': PROJECTION,
                    'AttachmentTargetIds': [],
                    '_provenance': {'source_operation': 'ListPoliciesForTarget+DescribePolicy+ListParents',
                                    'read_only': True, 'semantics': 'literal attached policy; tag presence and effective merge unassessed'}}
            rows[identifier]['AttachmentTargetIds'].append(target)
    return _result(rows.values())


def resource_policy(requests, session, region, account):
    org, failure = _organization(requests, session, region)
    if failure:
        return failure
    response = requests.detail(session, 'organizations', region, 'describe_resource_policy',
                               absent=('ResourcePolicyNotFoundException',))
    if response.get('collection_status') == 'empty' and response.get('error', {}).get('code') == 'ResourcePolicyNotFoundException':
        return _result([{'Id': 'resource-policy:' + org['Id'], 'Content': {'Statement': []},
            'OrganizationId': org['Id'], '_provenance': {'source_operation': 'DescribeResourcePolicy',
            'read_only': True, 'absence_verified': True}}])
    if response.get('collection_status') not in _OK:
        return _result([], response.get('collection_status', 'unknown'),
                       response.get('error', {}).get('code', 'organization_resource_policy_unavailable'))
    policy = response.get('ResourcePolicy')
    try:
        summary = policy.get('ResourcePolicySummary') if isinstance(policy, dict) else None
        arn = summary.get('Arn') if isinstance(summary, dict) else None
        if (not isinstance(summary, dict) or not isinstance(summary.get('Id'), str)
                or not re.fullmatch(r'rp-[a-zA-Z0-9_]{8,128}', summary.get('Id', ''))
                or not isinstance(arn, str) or not re.fullmatch('arn:' + re.escape(org['_partition']) + r':organizations::'
                    + re.escape(org['MasterAccountId']) + ':resourcepolicy/' + re.escape(org['Id']) + '/' + re.escape(summary['Id']), arn)):
            raise ValueError('resource policy identity')
        content = _policy(policy.get('Content'))
        if isinstance(content.get('Statement'), dict):
            content = {**content, 'Statement': [content['Statement']]}
        elif not isinstance(content.get('Statement'), list):
            raise ValueError('resource policy statements')
    except (ValueError, TypeError):
        return _result([], 'malformed', 'organization_resource_policy_malformed')
    return _result([{'Id': summary['Id'], 'Arn': arn, 'Content': content, 'OrganizationId': org['Id'],
                    '_provenance': {'source_operation': 'DescribeResourcePolicy', 'read_only': True}}])


FETCHERS = {'organization_effective_scp': effective_scp, 'organization_tag_policy': tag_policies,
            'organization_resource_policy': resource_policy, 'aws_organization_account': account_identities}

# The environment projection deliberately remains partial until the complete
# cross-service workload and effective boundary universe is independently known.
from . import aws_environment_boundaries_native as _environment
SPECS.update(_environment.SPECS)
NATIVE_IDS.update(_environment.NATIVE_IDS)
READ_ACTIONS.update(_environment.READ_ACTIONS)
FETCHERS.update(_environment.FETCHERS)

from . import aws_macie_findings_native as _macie_findings
SPECS.update(_macie_findings.SPECS)
NATIVE_IDS.update(_macie_findings.NATIVE_IDS)
READ_ACTIONS.update(_macie_findings.READ_ACTIONS)
FETCHERS.update(_macie_findings.FETCHERS)
