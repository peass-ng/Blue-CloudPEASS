"""Unregistered Lambda role declared-policy pattern check; no effective access claim.

Uses complete native Lambda inventory and own-account GAAD role/default-policy
JSON. No SCP, boundary, session policy, trust, execution or escalation analysis.
The exact literal pattern is a deliberately narrow subset of the pinned Prowler
policy helper; its NotAction/NotResource and broader resource logic is not reused.
"""
from __future__ import annotations

import copy
import re

from . import result, unknown
from .facts import Unavailable, get, list_of_objects, optional
from .aws_a_facts import api_optional, complete_items
from .aws_bedrock_review_20261019 import _documents, _policy_document

CHECK_ID = 'aws.review.lambda.execution_role_policy_admin_grants'
OPERATION = 'iam:GetAccountAuthorizationDetails'
SOURCE_URL = ('https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/'
              'prowler/providers/aws/services/iam/lib/policy.py')
SOURCE_SHA256 = 'a589d9d90e80287b1491ac8cb7d98ebffd2bad9ae27a897cb2e3d023436f8cc3'
OFFICIAL_DOCS = [
    'https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html',
    'https://docs.aws.amazon.com/lambda/latest/api/API_FunctionConfiguration.html',
]
SEMANTICS = ('Declared literal Allow Action=* or *:* with Resource=* only. Conditions remain visible as a boolean; '
             'Deny does not subtract a declared pattern. No effective access, boundary, SCP, session-policy, '
             'privilege-escalation or NotAction/NotResource expansion assessment.')


def _lambda_member(item, index, scope):
    envelopes = get(get(index, 'collections', dict), 'lambda_function', list)
    if not envelopes:
        raise Unavailable('Lambda inventory not collected')
    members = []
    for envelope in list_of_objects(envelopes):
        if (get(envelope, 'type', str) != 'lambda_function' or get(envelope, 'scope', str) != scope
                or optional(envelope, 'global', False, bool) or get(envelope, 'status', str) not in ('collected', 'empty')):
            raise Unavailable('Lambda inventory incomplete or foreign')
        batch = list_of_objects(get(envelope, 'items', list))
        if envelope['status'] == 'empty' and batch:
            raise Unavailable('contradictory empty Lambda inventory')
        if ('account_id' in envelope or 'account_id' in envelope.get('_coverage', {})) and get(envelope, 'account_id', str) != scope.split('/')[0]:
            raise Unavailable('Lambda collection account mismatch')
        members.extend(batch)
    arn = get(item, 'FunctionArn', str)
    matches = [row for row in members if get(row, 'FunctionArn', str) == arn]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable('Lambda membership missing, stale or ambiguous')


def _iam_inventory(index, kind, account):
    envelopes = get(get(index, 'collections', dict), kind, list)
    if not envelopes:
        raise Unavailable('IAM inventory missing')
    for envelope in list_of_objects(envelopes):
        if (get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != account + '/global'
                or get(envelope, 'status', str) not in ('collected', 'empty')
                or optional(envelope, 'global', True, bool) is not True):
            raise Unavailable('IAM inventory incomplete or foreign')
        if ('account_id' in envelope or 'account_id' in envelope.get('_coverage', {})) and get(envelope, 'account_id', str) != account:
            raise Unavailable('IAM inventory account mismatch')
    rows = complete_items(index, kind, account + '/global')
    for row in rows:
        if ('AccountId' in row or 'AccountId' in row.get('_coverage', {})) and get(row, 'AccountId', str) != account:
            raise Unavailable('IAM native row account mismatch')
    return rows


def _attached_defaults(role, policies, account, partition):
    """Add native version-ID/partition checks around the reused document join."""
    attached = list_of_objects(api_optional(role, 'AttachedManagedPolicies', list, [], operation=OPERATION))
    for attachment in attached:
        arn = get(attachment, 'PolicyArn', str)
        if re.fullmatch(r'arn:' + re.escape(partition) + r':iam::(?:aws|' + account + r'):policy/.+', arn) is None:
            raise Unavailable('managed attachment partition/account mismatch')
        matches = [row for row in policies if get(row, 'Arn', str) == arn]
        if len(matches) != 1:
            raise Unavailable('managed policy missing or ambiguous')
        policy = matches[0]
        default_id = get(policy, 'DefaultVersionId', str)
        versions = list_of_objects(get(policy, 'PolicyVersionList', list))
        version_ids = [get(row, 'VersionId', str) for row in versions]
        if len(version_ids) != len(set(version_ids)) or any(re.fullmatch(r'v[1-9][0-9]*', value) is None for value in version_ids):
            raise Unavailable('managed policy version identity ambiguous')
        defaults = [row for row in versions if get(row, 'IsDefaultVersion', bool)]
        if (re.fullmatch(r'v[1-9][0-9]*', default_id) is None or len(defaults) != 1
                or get(defaults[0], 'VersionId', str) != default_id):
            raise Unavailable('managed default version identity unresolved')


def evaluate(item, index):
    try:
        if get(index, 'context.provider', str) != 'aws':
            raise Unavailable('AWS context unavailable')
        scope = get(index, 'context.scope', str)
        match = re.fullmatch(r'([0-9]{12})/([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)', scope)
        if match is None:
            raise Unavailable('Lambda account/Region scope unavailable')
        account, region = match.groups()
        context = get(index, 'context', dict)
        if ('Account' in context or 'Account' in context.get('_coverage', {})) and get(context, 'Account', str) != account:
            raise Unavailable('conflicting account context')
        if ('AccountId' in item or 'AccountId' in item.get('_coverage', {})) and get(item, 'AccountId', str) != account:
            raise Unavailable('Lambda native row account mismatch')
        arn = get(item, 'FunctionArn', str)
        name = get(item, 'FunctionName', str)
        function = re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):lambda:' + re.escape(region) + ':' + account
                                + r':function:([A-Za-z0-9_-]{1,64})(?::[A-Za-z0-9_$-]+)?', arn)
        if function is None or function[2] != name:
            raise Unavailable('native Lambda identity mismatch')
        partition = function[1]
        _lambda_member(item, index, scope)
        role_arn = get(item, 'Role', str)
        role_match = re.fullmatch(r'arn:' + re.escape(partition) + ':iam::' + account + r':role/(.+)', role_arn)
        if role_match is None:
            raise Unavailable('execution role is foreign or malformed')
        # The pure predicate enforces completeness even without the engine's
        # dependency gate, including the empty managed-policy inventory case.
        roles = _iam_inventory(index, 'iam_role', account)
        policies = _iam_inventory(index, 'iam_policy', account)
        matching_roles = [row for row in roles if get(row, 'Arn', str) == role_arn]
        if len(matching_roles) != 1:
            raise Unavailable('execution role missing or ambiguous')
        role = matching_roles[0]
        role_name = get(role, 'RoleName', str)
        if (re.fullmatch(r'[A-Za-z0-9_+=,.@-]{1,64}', role_name) is None
                or role_name != role_match[1].rsplit('/', 1)[-1]):
            raise Unavailable('execution role name mismatch')
        _attached_defaults(role, policies, account, partition)
        documents = _documents(role, index, account, 'RolePolicyList')
        patterns, statement_count, not_action, not_resource = [], 0, 0, 0
        for document_number, document in enumerate(documents):
            statements = get(_policy_document(document), 'Statement')
            statements = [statements] if isinstance(statements, dict) else list_of_objects(statements)
            for statement_number, statement in enumerate(statements):
                effect = get(statement, 'Effect', str)
                condition = optional(statement, 'Condition', None, dict)
                actions = optional(statement, 'Action', None)
                resources = optional(statement, 'Resource', None)
                # Validate denied optional alternative selectors too; retain
                # counts only, never arbitrary policy/condition content.
                negative_action = optional(statement, 'NotAction', None)
                negative_resource = optional(statement, 'NotResource', None)
                for selectors in (actions, negative_action):
                    if selectors is not None:
                        values = [selectors] if isinstance(selectors, str) else selectors
                        if any(re.fullmatch(r'(?:\*|[A-Za-z0-9*?-]+:[A-Za-z0-9*?]+)', value) is None for value in values):
                            raise Unavailable('malformed IAM action selector syntax')
                statement_count += 1
                not_action += negative_action is not None
                not_resource += negative_resource is not None
                if effect != 'Allow' or actions is None or resources is None:
                    continue
                actions = [actions] if isinstance(actions, str) else actions
                resources = [resources] if isinstance(resources, str) else resources
                if any(action in ('*', '*:*') for action in actions) and '*' in resources:
                    patterns.append({'document_number': document_number, 'statement_number': statement_number,
                                     'condition_present': condition is not None})
        evidence = {'function_arn': arn, 'role_arn': role_arn, 'documents_reviewed': len(documents),
                    'statements_reviewed': statement_count, 'declared_admin_patterns': patterns,
                    'not_action_statements_unexpanded': not_action, 'not_resource_statements_unexpanded': not_resource,
                    'semantics': SEMANTICS}
        return result(bool(patterns), **evidence, observed=(
            f'Declared literal administrator patterns: {len(patterns)} statement(s); effective access is unassessed.' if patterns else
            'No literal administrator Allow pattern in complete execution-role documents; effective access is unassessed.'))
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError, IndexError):
        return unknown('complete same-account Lambda/role/default-policy evidence is unavailable or ambiguous',
                       observed='Execution-role policy evidence is incomplete or unbound; no declared-pattern verdict.', semantics=SEMANTICS)


DECLARATIONS = [{
    'id': CHECK_ID, 'provider': 'aws', 'kind': 'lambda_function', 'target': 'resource',
    'dependencies': ['lambda_function', 'iam_role', 'iam_policy'], 'category': 'least_privilege', 'severity': 'high',
    'control': 'AC-6', 'title': 'Lambda execution-role policies avoid literal administrator Allow patterns',
    'remediation': 'Review broad declared grants and their conditions, replace wildcard action/resource selectors with workload permissions, and assess effective access separately.',
    'evaluator': 'evaluate', 'official_docs': OFFICIAL_DOCS,
}]
ADMISSION_DATA = {'schema_version': 1, 'checks': [{
    'spec': {'id': CHECK_ID, 'provider': 'aws', 'resource_kind': 'lambda_function',
             'data_source': 'Complete native lambda_function inventory plus own-account GAAD iam_role inline documents and attached iam_policy default versions',
             'predicate': 'FAIL when a complete bound execution-role document declares Allow with literal Action * or *:* and Resource *. Conditions are reported as present, not evaluated. Complete narrow/empty documents PASS; unreadable, missing, foreign, ambiguous or incomplete joins UNKNOWN.',
             'severity': 'high', 'category': 'least_privilege', 'title': DECLARATIONS[0]['title'],
             'description': 'Inspects declared identity-policy patterns of the native Lambda execution role using complete account-bound IAM metadata. This does not establish effective administrator access or cancel a grant pattern because of Deny, boundaries or SCPs.',
             'remediation_hint': DECLARATIONS[0]['remediation']},
    'description': {'description': 'Checks a Lambda execution role for a narrowly defined literal wildcard administrator policy pattern in its inline and attached default JSON documents.',
                    'evaluated': ['FunctionArn', 'FunctionName', 'Role', 'complete Lambda membership', 'GAAD RolePolicyList', 'AttachedManagedPolicies', 'PolicyVersionList default Document and version identifiers'],
                    'pass_when': 'Complete uniquely joined role documents contain no Allow statement combining literal * or *:* Action with * Resource; this is only a negative result for that pattern.',
                    'fail_when': 'A complete role-policy set contains that literal Allow pattern; condition presence is retained as a boolean and does not imply the condition is satisfied.',
                    'not_applicable_when': 'No implicit non-applicability: missing roles, documents, default versions or collection evidence yield UNKNOWN.'},
    'sources': [{'url': SOURCE_URL, 'sha256': SOURCE_SHA256}], 'requirements': [],
    'review_notes': 'New metadata-backed declared-pattern control, not an implementation of legacy EffectiveAdminAccess and not equivalent to Prowler check_admin_access: no NotAction/NotResource expansion, resource-pattern broadening, effective-access or escalation proof. Pinned helper is reference material only; official IAM/Lambda API references accompany the declaration. No invented upstream source ID or inherited checklist mapping.',
    'function': 'peaso.checks.aws_lambda_role_policy_review_20261019:evaluate',
}]}


def _fixture(admin=False):
    account, region = '123456789012', 'us-east-1'
    role_arn = f'arn:aws:iam::{account}:role/review'
    function = {'FunctionName': 'review', 'FunctionArn': f'arn:aws:lambda:{region}:{account}:function:review', 'Role': role_arn}
    role = {'RoleName': 'review', 'Arn': role_arn, 'AccountId': account, 'RolePolicyList': [{'PolicyName': 'review', 'PolicyDocument': {
        'Statement': [{'Effect': 'Allow', 'Action': '*' if admin else 'logs:CreateLogStream', 'Resource': '*'}]}}],
        'AttachedManagedPolicies': [], '_provenance': {'operation': OPERATION, 'native_response_complete': True}}
    index = {'context': {'provider': 'aws', 'scope': account+'/'+region, 'Account': account}, 'collections': {}}
    for kind, rows, global_type in [('lambda_function', [function], False), ('iam_role', [role], True), ('iam_policy', [], True)]:
        index['collections'][kind] = [{'type': kind, 'status': 'collected' if rows else 'empty', 'scope': account+'/global' if global_type else account+'/'+region,
            'account_id': account, 'global': global_type, 'items': rows}]
        index[kind] = [{'data': row} for row in rows]
    return function, index


_PASS, _PASS_INDEX = _fixture()
_FAIL, _FAIL_INDEX = _fixture(True)
RUNTIME_CASES = {CHECK_ID: {'pass': copy.deepcopy(_PASS), 'fail': copy.deepcopy(_FAIL),
                           'pass_index': copy.deepcopy(_PASS_INDEX), 'fail_index': copy.deepcopy(_FAIL_INDEX),
                           'missing': {}, 'malformed': None}}
