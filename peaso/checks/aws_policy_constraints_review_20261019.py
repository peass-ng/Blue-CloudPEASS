"""Reviewed offline policy predicates pending coordinator admission.

Importing this module does not register checks or change catalogs. The two
declarations intentionally describe bounded configuration evidence, not effective
access under SCPs, resource policies, certificate trust, or workload approval.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
import hashlib
import json
import re

from . import result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects

REVISION = '1783527c1147f584f30b60f2d7ccc8a53b4a63b7'
SECRETS_ID = 'aws.review.secretsmanager.explicit_principal_deny'
ROLES_ID = 'aws.review.rolesanywhere.session_policy_constraints'
_ACCOUNT = re.compile(r'^([0-9]{12})/([a-z0-9-]+)$')
_ARN = re.compile(r'^arn:(aws(?:-[a-z0-9-]+)?):([^:]+):([^:]*):([0-9]{12}):(.+)$')
_POLICY_ARN = re.compile(r'^arn:(aws(?:-[a-z0-9-]+)?):iam::([0-9]{12}|aws):policy/(.+)$')
_ACTION = re.compile(r'^(?:\*|[a-zA-Z0-9*?]+:[a-zA-Z0-9*?]+)$')
_PROBES = ('iam:CreateRole', 's3:GetObject', 'ec2:RunInstances', 'kms:Decrypt', 'sts:AssumeRole')
_LIMIT = ('Configuration evidence only; SCPs, RCPs, resource-based grants, role trust, '
          'certificate acceptance and workload authorization are not evaluated.')


def _strings(value):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
        raise Unavailable('expected nonempty string or string array')
    return values


def _iam_resource_match(value, pattern):
    # IAM globs support * and ?, not shell character classes such as [abc].
    regex = re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.')
    return re.fullmatch(regex, value) is not None


def _document(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError) as exc:
            raise Unavailable('policy JSON is malformed') from exc
    guard(value)
    if not isinstance(value, dict):
        raise Unavailable('policy is not an object')
    statements = get(value, 'Statement')
    statements = [statements] if isinstance(statements, dict) else statements
    statements = list_of_objects(statements)
    if not statements:
        raise Unavailable('policy contains no statements')
    for statement in statements:
        guard(statement)
        if get(statement, 'Effect', str) not in ('Allow', 'Deny'):
            raise Unavailable('policy effect invalid')
        for positive, inverse in (('Action', 'NotAction'), ('Resource', 'NotResource')):
            if (positive in statement) == (inverse in statement):
                raise Unavailable('policy needs one of ' + positive + '/' + inverse)
            values = _strings(get(statement, positive if positive in statement else inverse))
            if positive == 'Action' and any(not _ACTION.fullmatch(v) for v in values):
                raise Unavailable('policy action syntax unsupported')
        if 'Condition' in statement:
            _condition(get(statement, 'Condition', dict))
    return statements


def _condition(value):
    """Normalize case-insensitive keys without changing or copying secret values."""
    guard(value)
    normalized = {}
    for operator, entries in value.items():
        if operator == '_coverage':
            continue
        if not isinstance(operator, str) or not isinstance(entries, dict):
            raise Unavailable('condition operator malformed')
        normalized[operator] = {}
        for key in entries:
            if key == '_coverage':
                continue
            if not isinstance(key, str) or key.lower() in normalized[operator]:
                raise Unavailable('condition keys duplicate or malformed')
            normalized[operator][key.lower()] = _strings(get(entries, key))
    return normalized


def _identity(item, index, field, service):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'aws':
        raise Unavailable('AWS context unavailable')
    scope = _ACCOUNT.fullmatch(get(context, 'scope', str))
    arn = get(item, field, str)
    match = _ARN.fullmatch(arn)
    if not scope or not match or match[2] != service or match[3] != scope[2] or match[4] != scope[1]:
        raise Unavailable('resource ARN does not match assessed account and Region')
    if not match[5].startswith('secret:' if service == 'secretsmanager' else 'profile/'):
        raise Unavailable('resource ARN type differs from assessed resource')
    return arn, match[1], scope[1]


def _secrets_explicit_principal_deny(item, index):
    """Require the canonical unconditional-otherwise Deny except concrete IAM ARNs.

    PASS proves this configuration guardrail exists; it does not approve its
    exceptions. Unsupported conditional/inverted Denies remain UNKNOWN rather
    than being treated as a missing guardrail. A known absent policy FAILs.
    """
    try:
        arn, partition, account = _identity(item, index, 'ARN', 'secretsmanager')
        detail = get(item, 'Policy', dict)
        if get(detail, 'collection_status', str) != 'collected':
            raise Unavailable('GetResourcePolicy was not collected')
        # Successful GetResourcePolicy may omit ResourcePolicy when unset.
        if 'ResourcePolicy' not in detail:
            coverage = detail.get('_coverage', {}).get('ResourcePolicy')
            if coverage is not None and (not isinstance(coverage, dict) or coverage.get('status') != 'empty'):
                raise Unavailable('resource policy omission has contradictory coverage')
            return result(True, resource=arn, reason='successful GetResourcePolicy has no resource policy', semantics=_LIMIT)
        statements = _document(get(detail, 'ResourcePolicy'))
        unsupported = False
        for statement in statements:
            if statement['Effect'] != 'Deny':
                continue
            if any(key in statement for key in ('NotAction', 'NotResource', 'NotPrincipal')):
                unsupported = True
                continue
            principal = get(statement, 'Principal')
            universal = principal == '*' or principal == {'AWS': '*'} or principal == {'AWS': ['*']}
            if not universal:
                continue
            if not {'*', 'secretsmanager:*'}.intersection(v.lower() for v in _strings(get(statement, 'Action'))):
                continue
            resources = _strings(get(statement, 'Resource'))
            if not any(value == '*' or _iam_resource_match(arn, value) for value in resources):
                continue
            condition = _condition(get(statement, 'Condition', dict)) if 'Condition' in statement else {}
            if not condition:
                # Deny-everyone is restrictive but is not the intended exception guardrail.
                unsupported = True
                continue
            if set(condition) not in ({'StringNotEquals'}, {'ArnNotEquals'}):
                unsupported = True
                continue
            values = next(iter(condition.values()))
            if set(values) != {'aws:principalarn'}:
                unsupported = True
                continue
            exceptions = values['aws:principalarn']
            pattern = re.compile(r'^arn:' + re.escape(partition) + r':iam::' + account + r':(?:role|user)/[^*?\s]+$')
            if not all(pattern.fullmatch(value) for value in exceptions):
                unsupported = True
                continue
            return result(False, resource=arn, guardrail='explicit_deny_except_concrete_same_account_iam_arns',
                          exception_count=len(exceptions), exceptions_approved=False, semantics=_LIMIT)
        if unsupported:
            return unknown('Deny uses a shape outside the bounded canonical PrincipalArn guardrail', resource=arn, semantics=_LIMIT)
        return result(True, resource=arn, reason='no canonical PrincipalArn exception Deny covers all Secrets Manager actions on this secret', semantics=_LIMIT)
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
        return unknown(str(exc), semantics=_LIMIT)


def _full_access(documents):
    """Three-valued all-actions/all-resources classification without an IAM catalog.

    Universal unconditional Allow proves full access only when no Deny can
    constrain it. A missing witness action proves not-full; intricate glob
    unions, inversions and conditional boundaries remain unresolved. Policies
    are merged so a Deny in one document constrains every other document.
    """
    statements = [statement for document in documents for statement in _document(document)]
    if any('Principal' in statement or 'NotPrincipal' in statement for statement in statements):
        raise Unavailable('identity/session policy must not contain a Principal')
    unconditional_all = False
    possible_denies = False
    possible_allows = []
    for statement in statements:
        conditional = bool(statement.get('Condition'))
        inverse = 'NotAction' in statement or 'NotResource' in statement
        actions = _strings(statement.get('Action', statement.get('NotAction')))
        resources = _strings(statement.get('Resource', statement.get('NotResource')))
        if statement['Effect'] == 'Deny':
            # A concrete action denied at every resource is enough to refute
            # an all-actions/all-resources grant, even with other broad Allows.
            if not conditional and not inverse and '*' in resources and any(
                    any(fnmatchcase(action.lower(), pattern.lower()) for pattern in actions) for action in _PROBES):
                return False
            possible_denies = True
        else:
            possible_allows.append(statement)
            if not conditional and not inverse and '*' in actions and '*' in resources:
                unconditional_all = True
    if unconditional_all:
        return None if possible_denies else True
    if not possible_allows:
        return False
    # Resource-specific and conditional grants cannot prove administrator
    # rights but may still grant a witness. Include them when refuting rights.
    for action in _PROBES:
        def could_allow(statement):
            patterns = _strings(statement.get('Action', statement.get('NotAction')))
            matches = any(fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns)
            return not matches if 'NotAction' in statement else matches
        if not any(could_allow(statement) for statement in possible_allows):
            return False
    return None


def _managed_document(arn, policies, partition, account):
    match = _POLICY_ARN.fullmatch(arn)
    if not match or match[1] != partition or match[2] not in ('aws', account):
        raise Unavailable('managed policy ARN outside assessed partition/account')
    if match[2] == 'aws' and match[3] == 'AdministratorAccess':
        return {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}
    policy = policies.get(arn)
    if policy is None:
        raise Unavailable('referenced managed policy not collected')
    versions = [v for v in list_of_objects(get(policy, 'PolicyVersionList', list))
                if get(v, 'IsDefaultVersion', bool)]
    if len(versions) != 1:
        raise Unavailable('managed policy default version not unique')
    return get(versions[0], 'Document')


def _inventory(index, kind, partition, account):
    out = {}
    for value in complete_items(index, kind):
        arn = get(value, 'Arn', str)
        match = _POLICY_ARN.fullmatch(arn) if kind == 'iam_policy' else _ARN.fullmatch(arn)
        valid = (match and match[1] == partition and
                 (match[2] in (account, 'aws') if kind == 'iam_policy' else
                  match[2] == 'iam' and match[3] == '' and match[4] == account and match[5].startswith('role/')))
        if not valid or arn in out:
            raise Unavailable('IAM dependency ARN is foreign, malformed or duplicated')
        out[arn] = value
    return out


def _role_optional(role, field, default):
    if field in role or field in role.get('_coverage', {}):
        return get(role, field)
    provenance = get(role, '_provenance', dict)
    if (get(provenance, 'operation', str) == 'iam:GetAccountAuthorizationDetails' and
            get(provenance, 'native_response_complete', bool)):
        return default
    raise Unavailable('IAM optional omission lacks complete response provenance: ' + field)


def _role_status(role, policies, partition, account):
    documents = []
    for attached in list_of_objects(get(role, 'AttachedManagedPolicies', list)):
        documents.append(_managed_document(get(attached, 'PolicyArn', str), policies, partition, account))
    for inline in list_of_objects(_role_optional(role, 'RolePolicyList', [])):
        documents.append(get(inline, 'PolicyDocument'))
    status = _full_access(documents)
    if status is False:
        return False
    boundary = _role_optional(role, 'PermissionsBoundary', None)
    if boundary is None:
        return status
    boundary_status = _full_access([_managed_document(get(boundary, 'PermissionsBoundaryArn', str), policies, partition, account)])
    return False if boundary_status is False else None if boundary_status is None else status


def _rolesanywhere_session_constraints(item, index):
    """Assess session scoping versus known identity+boundary administrator grants."""
    try:
        arn, partition, account = _identity(item, index, 'profileArn', 'rolesanywhere')
        if not get(item, 'enabled', bool):
            return result(False, resource=arn, reason='profile disabled', semantics=_LIMIT)
        managed = get(item, 'managedPolicyArns', list)
        if any(not isinstance(value, str) for value in managed):
            raise Unavailable('managed session policy list malformed')
        inline = get(item, 'SessionPolicy')
        if inline is not None and not isinstance(inline, (dict, str)):
            raise Unavailable('session policy malformed')
        policies = _inventory(index, 'iam_policy', partition, account) if managed else {}
        session_documents = [] if inline is None else [inline]
        session_documents += [_managed_document(value, policies, partition, account) for value in managed]
        if session_documents:
            session_full = _full_access(session_documents)
            if session_full is None:
                return unknown('session-policy all-access classification unresolved', resource=arn, semantics=_LIMIT)
            if session_full is False:
                return result(False, resource=arn, reason='session policy set provably does not grant all actions on all resources', semantics=_LIMIT)
        roles = _strings(get(item, 'roleArns', list))
        role_inventory = _inventory(index, 'iam_role', partition, account)
        if not policies:
            policies = _inventory(index, 'iam_policy', partition, account)
        statuses = {}
        for role_arn in roles:
            try:
                if role_arn not in role_inventory:
                    raise Unavailable('referenced role not in complete inventory')
                statuses[role_arn] = _role_status(role_inventory[role_arn], policies, partition, account)
            except Unavailable:
                statuses[role_arn] = None
        privileged = [role for role, status in statuses.items() if status is True]
        if privileged:
            return result(True, resource=arn, administrative_role_count=len(privileged),
                          reason='profile session policy set is unscoped and a referenced role has universal identity+boundary grants', semantics=_LIMIT)
        if any(status is None for status in statuses.values()):
            return unknown('referenced role identity or permissions-boundary classification unresolved', resource=arn, semantics=_LIMIT)
        return result(False, resource=arn, reason='no referenced role has universal identity+boundary grants', semantics=_LIMIT)
    except (Unavailable, ValueError, TypeError, KeyError, AttributeError) as exc:
        return unknown(str(exc), semantics=_LIMIT)


def secrets_explicit_principal_deny(item, index):
    status, evidence = _secrets_explicit_principal_deny(item, index)
    if status == 'PASS':
        observed = ('Secret policy denies Secrets Manager access except ' +
                    str(evidence['exception_count']) + ' concrete same-account IAM role/user ARN(s).')
    elif status == 'FAIL':
        observed = ('Successful secret policy read returned no resource policy.' if
                    evidence.get('reason') == 'successful GetResourcePolicy has no resource policy' else
                    'Secret policy has no canonical Deny covering all Secrets Manager actions except concrete same-account IAM principals.')
    else:
        observed = 'Secret policy guardrail could not be determined: ' + evidence['reason'] + '.'
    return status, {**evidence, 'observed': observed}


def rolesanywhere_session_constraints(item, index):
    status, evidence = _rolesanywhere_session_constraints(item, index)
    if status == 'FAIL':
        observed = ('Enabled Roles Anywhere profile has ' + str(evidence['administrative_role_count']) +
                    ' role(s) with universal identity and boundary grants and no restricting session-policy set.')
    elif status == 'PASS':
        observed = 'Roles Anywhere profile: ' + evidence['reason'] + '.'
    else:
        observed = 'Roles Anywhere session restriction could not be determined: ' + evidence['reason'] + '.'
    return status, {**evidence, 'observed': observed}


DECLARATIONS = [
    {'id': SECRETS_ID, 'provider': 'aws', 'category': 'hardening', 'kind': 'secret',
     'title': 'Secret policy explicitly denies access except concrete same-account IAM roles or users',
     'severity': 'high', 'control': 'AC-3', 'target': 'resource', 'dependencies': ['secret'],
     'remediation': 'Review intended readers and apply a tested resource-policy Deny that covers this secret and excludes only concrete intended IAM role or user ARNs.',
     'evaluator': 'secrets_explicit_principal_deny'},
    {'id': ROLES_ID, 'provider': 'aws', 'category': 'least_privilege', 'kind': 'rolesanywhere_profile',
     'title': 'Enabled Roles Anywhere profile scopes sessions on roles with universal identity and boundary grants',
     'severity': 'high', 'control': 'AC-6', 'target': 'resource',
     'dependencies': ['rolesanywhere_profile', 'iam_role', 'iam_policy'],
     'remediation': 'Restrict the combined session-policy permissions or remove universal grants from referenced IAM roles; separately verify certificate trust and organization policies.',
     'evaluator': 'rolesanywhere_session_constraints'},
]
SOURCE_MAPPINGS = {
    SECRETS_ID: {'source_id': 'prowler.aws.secretsmanager_has_restrictive_resource_policy',
                 'upstream_evaluator_sha256': '2ba3b358984b909b5459a9aa5be252e9112e2853812c7d872450788db032b212',
                 'decision': 'PARTIAL', 'reason': 'Corrected canonical PrincipalArn Deny subset only; unsupported dual Null/ArnLike/service/org-specific shapes remain UNKNOWN. No approval of exception principals is inferred.'},
    ROLES_ID: {'source_id': 'prowler.aws.rolesanywhere_profile_restricts_session_permissions',
               'upstream_evaluator_sha256': 'e2911a5f51900f3aa0f37a70eac3cc400c91bd1773f7f39e73cbf5faa8b545b1',
               'decision': 'PARTIAL', 'reason': 'Preserves disabled/scoped/unscoped-plus-admin decisions on provable policy sets; intricate action glob unions, inverted or conditional policies may remain UNKNOWN without a complete AWS action catalog.'},
}
for _cid, _mapping in SOURCE_MAPPINGS.items():
    _source_check = _mapping['source_id'].split('.')[-1]
    _service = 'secretsmanager' if _cid == SECRETS_ID else 'rolesanywhere'
    _mapping.update(repository='prowler-cloud/prowler', revision=REVISION,
                    source='https://github.com/prowler-cloud/prowler/blob/' + REVISION +
                    '/prowler/providers/aws/services/' + _service + '/' + _source_check + '/' + _source_check + '.py')

SPECS = {declaration['id']: {**declaration, 'source_mapping': SOURCE_MAPPINGS[declaration['id']],
                            'semantics': _LIMIT, 'cloud_calls_at_evaluation': 0,
                            'admission_status': 'pending_coordinator_registration_and_catalog_mapping'}
         for declaration in DECLARATIONS}
SPECS[SECRETS_ID]['predicate'] = (
    'Successful GetResourcePolicy with no policy FAILs. PASS only for a Deny covering Principal *, '
    'all Secrets Manager actions and this secret, with only StringNotEquals/ArnNotEquals '
    'aws:PrincipalArn concrete same-account IAM role/user exceptions. Unsupported/inverted/extra '
    'conditions, malformed/denied reads remain UNKNOWN. PASS does not approve the exceptions.')
SPECS[ROLES_ID]['predicate'] = (
    'Disabled profiles PASS. Merge all inline+managed session policies with explicit Deny precedence. '
    'A proven non-universal session set PASSes. An enabled unscoped profile FAILs if a referenced role '
    'has proven unconditional universal identity grants and an absent or universal permissions boundary. '
    'Provably nonuniversal roles PASS. Unresolved documents, dependencies, conditional/inverted/glob '
    'policy outcomes or unproven optional omissions remain UNKNOWN. This is not effective-access proof.')
SPEC_SHA256 = {cid: hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
               for cid, spec in SPECS.items()}

_DESCRIPTION = {
    SECRETS_ID: {
        'description': 'Checks a canonical secret resource-policy Deny excluding only concrete same-account IAM roles/users. A passing shape does not establish that those exceptions are approved or that secrets are inaccessible through every other mechanism.',
        'evaluated': ['ARN', 'Policy.collection_status', 'Policy.ResourcePolicy.Statement'],
        'pass_when': 'A universal Principal Deny covers all Secrets Manager actions and this secret, with only a StringNotEquals/ArnNotEquals PrincipalArn exception list of concrete same-account roles/users.',
        'fail_when': 'A successful policy read proves no resource policy or no canonical covering Deny, with no unsupported potentially relevant Deny shape.',
        'not_applicable_when': 'No automatic applicability exclusion; unreadable or unsupported policy evidence remains UNKNOWN.',
    },
    ROLES_ID: {
        'description': 'Checks Roles Anywhere session-policy constraints against proven universal IAM identity and permissions-boundary grants. Policies are combined with Deny precedence. This does not prove effective session access under organization or resource-based policies.',
        'evaluated': ['profileArn', 'enabled', 'SessionPolicy', 'managedPolicyArns', 'roleArns',
                      'iam_role.AttachedManagedPolicies', 'iam_role.RolePolicyList',
                      'iam_role.PermissionsBoundary', 'iam_policy.PolicyVersionList'],
        'pass_when': 'Profile is disabled, the combined session-policy set provably lacks universal grants, or every referenced role provably lacks universal identity+boundary grants.',
        'fail_when': 'An enabled unscoped profile references at least one role with proven universal identity grants and an absent or universal permissions boundary.',
        'not_applicable_when': 'No automatic applicability exclusion; unresolved policy semantics or incomplete dependencies remain UNKNOWN.',
    },
}
ADMISSION_DATA = {'schema_version': 1, 'checks': [
    {'spec': {
        'id': declaration['id'], 'provider': 'aws', 'resource_kind': declaration['kind'],
        'data_source': ', '.join(_DESCRIPTION[declaration['id']]['evaluated']),
        'predicate': SPECS[declaration['id']]['predicate'],
        'severity': declaration['severity'], 'category': declaration['category'],
        'title': declaration['title'], 'description': _DESCRIPTION[declaration['id']]['description'],
        'remediation_hint': declaration['remediation'],
    }, 'description': _DESCRIPTION[declaration['id']],
     'sources': [{'url': SOURCE_MAPPINGS[declaration['id']]['source'],
                  'sha256': SOURCE_MAPPINGS[declaration['id']]['upstream_evaluator_sha256']}],
     'requirements': [],
     'review_notes': SOURCE_MAPPINGS[declaration['id']]['reason'] +
                     ' Starts thematic-only; coordinator must independently admit any original checklist requirement as PARTIAL.',
     'function': 'peaso.checks.aws_policy_constraints_review_20261019:' + declaration['evaluator']}
    for declaration in DECLARATIONS
]}

# Production-native fixture data for the coordinator's central CASES admission.
# These are inert API-shaped examples, not imports from the test suite.
_FIXTURE_ACCOUNT = '123456789012'
_FIXTURE_SCOPE = _FIXTURE_ACCOUNT + '/us-east-1'
_FIXTURE_ROLE = 'arn:aws:iam::' + _FIXTURE_ACCOUNT + ':role/Example'
_FIXTURE_SECRET = 'arn:aws:secretsmanager:us-east-1:' + _FIXTURE_ACCOUNT + ':secret:example-abc123'
_FIXTURE_PROFILE = 'arn:aws:rolesanywhere:us-east-1:' + _FIXTURE_ACCOUNT + ':profile/11111111-2222-3333-4444-555555555555'


def _runtime_index(resources):
    index = {'context': {'provider': 'aws', 'scope': _FIXTURE_SCOPE,
                         'Account': _FIXTURE_ACCOUNT, 'created_at': '2026-10-19T00:00:00+00:00'},
             'collections': {}}
    for kind, rows in resources.items():
        index['collections'][kind] = [{'provider': 'aws', 'type': kind, 'scope': _FIXTURE_SCOPE,
                                       'status': 'collected' if rows else 'empty'}]
        index[kind] = [{'provider': 'aws', 'type': kind, 'scope': _FIXTURE_SCOPE,
                        'id': row.get('Arn') or row.get('ARN') or row.get('profileArn'), 'data': row}
                       for row in rows]
    return index


_FIXTURE_SECRET_PASS = {'ARN': _FIXTURE_SECRET, 'Policy': {'collection_status': 'collected', 'ResourcePolicy': {
    'Statement': [{'Effect': 'Deny', 'Principal': '*', 'Action': 'secretsmanager:*', 'Resource': '*',
                   'Condition': {'StringNotEquals': {'aws:PrincipalArn': _FIXTURE_ROLE}}}]}}}
_FIXTURE_SECRET_FAIL = {'ARN': _FIXTURE_SECRET, 'Policy': {'collection_status': 'collected'}}
_FIXTURE_PROFILE_BASE = {'profileArn': _FIXTURE_PROFILE, 'enabled': True, 'roleArns': [_FIXTURE_ROLE],
                         'managedPolicyArns': [], 'SessionPolicy': None}
_FIXTURE_PROFILE_PASS = {**_FIXTURE_PROFILE_BASE, 'SessionPolicy': {'Statement': [
    {'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}]}}
_FIXTURE_ROLE_DATA = {'Arn': _FIXTURE_ROLE, 'AttachedManagedPolicies': [], 'RolePolicyList': [
    {'PolicyName': 'Example', 'PolicyDocument': {'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}],
    '_provenance': {'operation': 'iam:GetAccountAuthorizationDetails', 'native_response_complete': True}}
RUNTIME_CASES = {
    SECRETS_ID: {'pass': _FIXTURE_SECRET_PASS, 'fail': _FIXTURE_SECRET_FAIL,
                 'pass_index': _runtime_index({'secret': [_FIXTURE_SECRET_PASS]}),
                 'fail_index': _runtime_index({'secret': [_FIXTURE_SECRET_FAIL]}),
                 'missing': {}, 'malformed': None},
    ROLES_ID: {'pass': _FIXTURE_PROFILE_PASS, 'fail': _FIXTURE_PROFILE_BASE,
               'pass_index': _runtime_index({'rolesanywhere_profile': [_FIXTURE_PROFILE_PASS],
                                             'iam_role': [_FIXTURE_ROLE_DATA], 'iam_policy': []}),
               'fail_index': _runtime_index({'rolesanywhere_profile': [_FIXTURE_PROFILE_BASE],
                                             'iam_role': [_FIXTURE_ROLE_DATA], 'iam_policy': []}),
               'missing': {}, 'malformed': None},
}
