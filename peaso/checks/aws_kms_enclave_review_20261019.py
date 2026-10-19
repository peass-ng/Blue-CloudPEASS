"""Unregistered KMS enclave predicates, awaiting coordinator catalog admission.

Read-only native snapshot configuration only; no AWS requests or key material.
Reviewed against Prowler Apache-2.0 source revision below. The Deny proof is
intentionally stricter than upstream (resource and additional-condition checks).
"""
from fnmatch import fnmatchcase
import re
from .facts import Unavailable, get, optional

REVISION = '1783527c1147f584f30b60f2d7ccc8a53b4a63b7'
PREFIX = 'kms:recipientattestation:'
SENSITIVE = {'kms:decrypt', 'kms:derivesharedsecret', 'kms:generatedatakey',
             'kms:generatedatakeypair', 'kms:generaterandom'}
DOCS = ['https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html',
        'https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html']
BASE_OPS = {'StringEquals', 'StringEqualsIgnoreCase', 'StringLike'}
ACCOUNT_KEYS = {'aws:principalaccount', 'aws:sourceaccount', 'aws:principalorgid',
                'aws:principalorgpaths', 'aws:resourceaccount'}


def strings(value):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
        raise Unavailable('expected nonempty policy strings')
    return values


def condition(statement):
    value = optional(statement, 'Condition', {}, dict)
    if any(not isinstance(k, str) or not isinstance(v, dict) or not v for k, v in value.items()):
        raise Unavailable('malformed condition block')
    for block in value.values():
        for key, val in block.items():
            if not isinstance(key, str) or not key:
                raise Unavailable('malformed condition key')
            strings(val)
    return value


def sensitive_actions(statement):
    if ('Action' in statement) == ('NotAction' in statement):
        raise Unavailable('expected exactly one Action or NotAction')
    negate = 'NotAction' in statement
    patterns = strings(get(statement, 'NotAction' if negate else 'Action'))
    if any(not re.fullmatch(r'[A-Za-z0-9:*?]+', pattern) for pattern in patterns):
        raise Unavailable('malformed action pattern')
    matched = {action for action in SENSITIVE if any(fnmatchcase(action, pattern.lower()) for pattern in patterns)}
    return SENSITIVE - matched if negate else matched


def restrictive(value):
    return all('*' not in v and '?' not in v and '${' not in v for v in strings(value))


def attestation_keys(statement):
    value = condition(statement)
    guards = {key.lower() for key, val in value.get('Null', {}).items()
              if any(v.lower() == 'false' for v in strings(val))}
    result = set()
    for operator, block in value.items():
        base = operator.split(':')[-1]
        if base not in BASE_OPS or operator not in BASE_OPS | {'ForAllValues:' + base, 'ForAnyValue:' + base}:
            continue
        for key, val in block.items():
            key = key.lower()
            if key.startswith(PREFIX) and restrictive(val):
                if not operator.startswith('ForAllValues:') or key in guards:
                    result.add(key)
    return result


def deployment_bound(statement):
    keys = attestation_keys(statement)
    if {PREFIX + pcr for pcr in ('pcr3', 'pcr4', 'pcr8')} & keys:
        return True
    return bool(keys) and any(key.lower() in ACCOUNT_KEYS and restrictive(val)
        for op, block in condition(statement).items() if op in {'StringEquals', 'StringEqualsIgnoreCase', 'ArnEquals'}
        for key, val in block.items())


def _statements(item):
    metadata = get(item, 'Metadata.KeyMetadata', dict)
    manager = get(metadata, 'KeyManager', str)
    if manager not in ('AWS', 'CUSTOMER'):
        raise Unavailable('unrecognized key manager')
    if manager == 'AWS':
        return None, 'AWS-managed key'
    state = get(metadata, 'KeyState', str)
    if state not in {'Enabled', 'Disabled', 'PendingDeletion', 'PendingImport', 'Unavailable', 'Creating', 'Updating', 'PendingReplicaDeletion'}:
        raise Unavailable('unrecognized key state')
    if state != 'Enabled':
        return None, 'key is not Enabled'
    policy = get(item, 'Policy.Policy', dict)
    statements = get(policy, 'Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        raise Unavailable('malformed policy statements')
    # Validate every statement before any PASS/FAIL so malformed evidence is not
    # accidentally skipped. Actual authorization simulation remains out of scope.
    for statement in statements:
        if get(statement, 'Effect', str) not in ('Allow', 'Deny'):
            raise Unavailable('unrecognized statement effect')
        sensitive_actions(statement)
        condition(statement)
        if 'Resource' not in statement or 'NotResource' in statement:
            raise Unavailable('unresolved policy resource selector')
        strings(get(statement, 'Resource'))
        if 'Principal' not in statement or 'NotPrincipal' in statement:
            raise Unavailable('unresolved policy principal selector')
        principal = get(statement, 'Principal')
        if isinstance(principal, dict):
            if not principal:
                raise Unavailable('empty principal')
            for value in principal.values():
                strings(value)
        else:
            strings(principal)
    description = optional(metadata, 'Description', '', str)
    # A policy reference is evidence of enclave applicability even when its
    # value/operator does not actually enforce attestation.
    observed = 'enclave' in description.lower() or any(key.lower().startswith(PREFIX)
        for s in statements for block in condition(s).values() for key in block)
    if not observed:
        # Existing collector does not yet provide these inventories. Their
        # absence cannot establish the absence of upstream applicability.
        unavailable = []
        for field in ('Tags', 'Aliases'):
            try:
                rows = get(item, field, list)
                for row in rows:
                    if field == 'Tags':
                        key, val = get(row, 'TagKey', str), get(row, 'TagValue', str)
                        observed |= 'enclave' in key.lower() or 'enclave' in val.lower()
                    else:
                        observed |= 'enclave' in get(row, 'AliasName', str).removeprefix('alias/').lower()
            except Unavailable as exc:
                unavailable.append(str(exc))
        if not observed:
            if unavailable:
                raise Unavailable('; '.join(unavailable))
            return None, 'complete description, policy, tags and aliases show no enclave signal'
    return statements, None


def _covers(deny, allow, actions):
    """True = proved absent-attestation Deny; None = possible but not proved."""
    if not actions <= sensitive_actions(deny):
        return False
    principal = deny['Principal']
    everyone = principal == '*' or isinstance(principal, dict) and '*' in strings(principal.get('AWS', ['<none>']))
    if not everyone:
        return None
    resources = strings(deny['Resource'])
    if '*' not in resources and not set(strings(allow['Resource'])) <= set(resources):
        return None
    blocks = condition(deny)
    # Multiple blocks/keys are ANDed. An extra source/account/context condition
    # prevents proving the Deny applies to every missing-attestation request.
    if len(blocks) != 1:
        return None
    operator, block = next(iter(blocks.items()))
    if len(block) != 1:
        return None
    key, value = next(iter(block.items()))
    if not key.lower().startswith(PREFIX):
        return None
    if operator == 'Null' and any(v.lower() == 'true' for v in strings(value)):
        return True
    if operator in {'StringNotEqualsIfExists', 'StringNotEqualsIgnoreCaseIfExists'}:
        return True
    return None


def evaluate(mode, item, index=None):
    """Return native (status, evidence), conservative on unavailable evidence."""
    try:
        statements, reason = _statements(item)
        if statements is None:
            return 'NOT_APPLICABLE', {'reason': reason}
        allows = [s for s in statements if s['Effect'] == 'Allow' and sensitive_actions(s)]
        if mode == 'deployment':
            applicable = [s for s in allows if attestation_keys(s)]
            if not applicable:
                return 'UNKNOWN', {'reason': 'no sensitive attested Allow; evaluate attestation enforcement first'}
            bad = [s for s in applicable if not deployment_bound(s)]
        elif mode == 'enforced':
            bad = [s for s in allows if not attestation_keys(s)]
        elif mode == 'bypass':
            bad, unresolved = [], False
            for allow in allows:
                if attestation_keys(allow):
                    continue
                uncovered, maybe = False, False
                for action in sensitive_actions(allow):
                    covered = [_covers(deny, allow, {action}) for deny in statements if deny['Effect'] == 'Deny']
                    if True in covered:
                        continue
                    if None in covered:
                        maybe = True
                    else:
                        uncovered = True
                if uncovered:
                    bad.append(allow)
                elif maybe:
                    unresolved = True
            if not bad and unresolved:
                return 'UNKNOWN', {'reason': 'Deny action/principal/resource/condition coverage cannot be proved'}
        else:
            raise ValueError('unknown enclave predicate')
        return ('FAIL' if bad else 'PASS'), {'violating_statement_sids': [s.get('Sid', '<unnamed>') for s in bad],
            'sensitive_allow_statements': len(allows), 'scope': 'enclave key policy configuration; not effective access or KMS grants'}
    except Unavailable as exc:
        return 'UNKNOWN', {'reason': str(exc)}


def enforced(item, index=None):
    return evaluate('enforced', item, index)


def no_bypass(item, index=None):
    return evaluate('bypass', item, index)


def deployment_binding(item, index=None):
    return evaluate('deployment', item, index)


SPECS = [
    {'id': 'aws.review.kms.enclave_attestation_enforced', 'upstream_id': 'kms_key_enclave_attestation_not_enforced',
     'title': 'Enclave KMS key requires attestation on sensitive policy Allows', 'severity': 'high', 'evaluate': enforced,
     'evaluated': ['Metadata.KeyMetadata', 'Policy.Policy.Statement', 'Tags', 'Aliases'],
     'pass_when': 'Every sensitive Allow has a restrictive attestation binding.',
     'fail_when': 'A sensitive Allow lacks a restrictive attestation binding.',
     'remediation': 'Bind sensitive Allow statements to reviewed enclave measurements; preserve key administration separately.'},
    {'id': 'aws.review.kms.enclave_no_bypass', 'upstream_id': 'kms_key_enclave_attestation_bypassable_path',
     'title': 'Enclave KMS key policy has no unattested sensitive Allow path', 'severity': 'high', 'evaluate': no_bypass,
     'evaluated': ['Metadata.KeyMetadata', 'Policy.Policy.Statement', 'Tags', 'Aliases'],
     'pass_when': 'Every sensitive Allow requires attestation or has a proven covering missing-attestation Deny.',
     'fail_when': 'A sensitive Allow lacks attestation and no possibly covering Deny exists.',
     'remediation': 'Require attestation for sensitive Allows or add a universally covering missing-attestation Deny; review additional Deny conditions.'},
    {'id': 'aws.review.kms.enclave_deployment_binding', 'upstream_id': 'kms_key_enclave_attestation_no_deployment_binding',
     'title': 'Attested KMS sensitive Allows bind an enclave deployment context', 'severity': 'info', 'evaluate': deployment_binding,
     'evaluated': ['Metadata.KeyMetadata', 'Policy.Policy.Statement', 'Tags', 'Aliases'],
     'pass_when': 'Every sensitive attested Allow binds PCR3, PCR4, PCR8 or a fixed account/org condition.',
     'fail_when': 'A sensitive attested Allow lacks deployment-context binding.',
     'remediation': 'Review deployment intent and bind the parent role, instance or signing certificate; image PCR0/1/2 alone identify software.'},
]
for _spec in SPECS:
    _spec.update(provider='aws', kind='kms_key', category='hardening', control='SC-12', target='resource',
        dependencies=['kms_key'], revision=REVISION, repository='prowler-cloud/prowler', license='Apache-2.0', official_docs=DOCS,
        source=f"https://github.com/prowler-cloud/prowler/blob/{REVISION}/prowler/providers/aws/services/kms/{_spec['upstream_id']}/{_spec['upstream_id']}.py",
        not_applicable_when='AWS-managed or non-Enabled key, or complete applicability inventory has no enclave signal.',
        unknown_when='Policy or applicability evidence unavailable/malformed; deployment predicate has no attested sensitive Allows; ambiguous covering Deny.')


# Serializable supervisor intake; functions are named separately from signed specs.
ADMISSION_DATA = {'schema_version': 1,
 'checks': [{'spec': {'id': 'aws.review.kms.enclave_attestation_enforced',
                      'provider': 'aws',
                      'resource_kind': 'kms_key',
                      'data_source': 'Metadata.KeyMetadata, Policy.Policy.Statement, Tags, Aliases',
                      'predicate': 'A sensitive Allow lacks a restrictive attestation binding. UNKNOWN: '
                                   'Policy or applicability evidence unavailable/malformed; deployment '
                                   'predicate has no attested sensitive Allows; ambiguous covering Deny.',
                      'severity': 'high',
                      'category': 'hardening',
                      'title': 'Enclave KMS key requires attestation on sensitive policy Allows',
                      'description': 'Enclave KMS key requires attestation on sensitive policy Allows. '
                                     'Applies only to enabled customer-managed keys with observed enclave '
                                     'policy, description, tag or alias evidence. Evaluates configuration; '
                                     'does not prove effective access, running enclaves, trusted builds or '
                                     'grant safety.',
                      'remediation_hint': 'Bind sensitive Allow statements to reviewed enclave measurements; '
                                          'preserve key administration separately.'},
             'description': {'description': 'Enclave KMS key requires attestation on sensitive policy '
                                            'Allows. Evaluates key policy configuration on observed enclave '
                                            'keys; incomplete evidence stays UNKNOWN.',
                             'evaluated': ['Metadata.KeyMetadata',
                                           'Policy.Policy.Statement',
                                           'Tags',
                                           'Aliases'],
                             'pass_when': 'Every sensitive Allow has a restrictive attestation binding.',
                             'fail_when': 'A sensitive Allow lacks a restrictive attestation binding.',
                             'not_applicable_when': 'AWS-managed or non-Enabled key, or complete '
                                                    'applicability inventory has no enclave signal.'},
             'sources': [{'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/kms/kms_key_enclave_attestation_not_enforced/kms_key_enclave_attestation_not_enforced.py',
                          'sha256': '5a694396ee010d852279c69f1e6c5d51f7f12652e19f5a84612d6a1aab08cd6e'},
                         {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/kms/lib/enclave.py',
                          'sha256': 'b46d9083c3ac400a965916f1c07e32c6151658339e53d778df6ed289a6514a70'}],
             'requirements': [],
             'review_notes': 'Upstream compliance edges remain in parity artifact. Native admission starts '
                             'thematic-only, pending individual requirement review. Deny proof additionally '
                             'checks resource/principal/additional conditions and accepts union of '
                             'individually covering Denies; malformed evidence stays UNKNOWN.',
             'function': 'peaso.checks.aws_kms_enclave_review_20261019:enforced'},
            {'spec': {'id': 'aws.review.kms.enclave_no_bypass',
                      'provider': 'aws',
                      'resource_kind': 'kms_key',
                      'data_source': 'Metadata.KeyMetadata, Policy.Policy.Statement, Tags, Aliases',
                      'predicate': 'A sensitive Allow lacks attestation and no possibly covering Deny '
                                   'exists. UNKNOWN: Policy or applicability evidence unavailable/malformed; '
                                   'deployment predicate has no attested sensitive Allows; ambiguous '
                                   'covering Deny.',
                      'severity': 'high',
                      'category': 'hardening',
                      'title': 'Enclave KMS key policy has no unattested sensitive Allow path',
                      'description': 'Enclave KMS key policy has no unattested sensitive Allow path. Applies '
                                     'only to enabled customer-managed keys with observed enclave policy, '
                                     'description, tag or alias evidence. Evaluates configuration; does not '
                                     'prove effective access, running enclaves, trusted builds or grant '
                                     'safety.',
                      'remediation_hint': 'Require attestation for sensitive Allows or add a universally '
                                          'covering missing-attestation Deny; review additional Deny '
                                          'conditions.'},
             'description': {'description': 'Enclave KMS key policy has no unattested sensitive Allow path. '
                                            'Evaluates key policy configuration on observed enclave keys; '
                                            'incomplete evidence stays UNKNOWN.',
                             'evaluated': ['Metadata.KeyMetadata',
                                           'Policy.Policy.Statement',
                                           'Tags',
                                           'Aliases'],
                             'pass_when': 'Every sensitive Allow requires attestation or has a proven '
                                          'covering missing-attestation Deny.',
                             'fail_when': 'A sensitive Allow lacks attestation and no possibly covering Deny '
                                          'exists.',
                             'not_applicable_when': 'AWS-managed or non-Enabled key, or complete '
                                                    'applicability inventory has no enclave signal.'},
             'sources': [{'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/kms/kms_key_enclave_attestation_bypassable_path/kms_key_enclave_attestation_bypassable_path.py',
                          'sha256': '2a58e0a21f6d9b1f69f491e7c54750796f7a6d987e2f4798a9f0e8daa6df130c'},
                         {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/kms/lib/enclave.py',
                          'sha256': 'b46d9083c3ac400a965916f1c07e32c6151658339e53d778df6ed289a6514a70'}],
             'requirements': [],
             'review_notes': 'Upstream compliance edges remain in parity artifact. Native admission starts '
                             'thematic-only, pending individual requirement review. Deny proof additionally '
                             'checks resource/principal/additional conditions and accepts union of '
                             'individually covering Denies; malformed evidence stays UNKNOWN.',
             'function': 'peaso.checks.aws_kms_enclave_review_20261019:no_bypass'},
            {'spec': {'id': 'aws.review.kms.enclave_deployment_binding',
                      'provider': 'aws',
                      'resource_kind': 'kms_key',
                      'data_source': 'Metadata.KeyMetadata, Policy.Policy.Statement, Tags, Aliases',
                      'predicate': 'A sensitive attested Allow lacks deployment-context binding. UNKNOWN: '
                                   'Policy or applicability evidence unavailable/malformed; deployment '
                                   'predicate has no attested sensitive Allows; ambiguous covering Deny.',
                      'severity': 'info',
                      'category': 'hardening',
                      'title': 'Attested KMS sensitive Allows bind an enclave deployment context',
                      'description': 'Attested KMS sensitive Allows bind an enclave deployment context. '
                                     'Applies only to enabled customer-managed keys with observed enclave '
                                     'policy, description, tag or alias evidence. Evaluates configuration; '
                                     'does not prove effective access, running enclaves, trusted builds or '
                                     'grant safety.',
                      'remediation_hint': 'Review deployment intent and bind the parent role, instance or '
                                          'signing certificate; image PCR0/1/2 alone identify software.'},
             'description': {'description': 'Attested KMS sensitive Allows bind an enclave deployment '
                                            'context. Evaluates key policy configuration on observed enclave '
                                            'keys; incomplete evidence stays UNKNOWN.',
                             'evaluated': ['Metadata.KeyMetadata',
                                           'Policy.Policy.Statement',
                                           'Tags',
                                           'Aliases'],
                             'pass_when': 'Every sensitive attested Allow binds PCR3, PCR4, PCR8 or a fixed '
                                          'account/org condition.',
                             'fail_when': 'A sensitive attested Allow lacks deployment-context binding.',
                             'not_applicable_when': 'AWS-managed or non-Enabled key, or complete '
                                                    'applicability inventory has no enclave signal.'},
             'sources': [{'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/kms/kms_key_enclave_attestation_no_deployment_binding/kms_key_enclave_attestation_no_deployment_binding.py',
                          'sha256': '87d26891de87e402456da7f69c0ceba9aca29cb57424620b836b5568aff74cdd'},
                         {'url': 'https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/kms/lib/enclave.py',
                          'sha256': 'b46d9083c3ac400a965916f1c07e32c6151658339e53d778df6ed289a6514a70'}],
             'requirements': [],
             'review_notes': 'Upstream compliance edges remain in parity artifact. Native admission starts '
                             'thematic-only, pending individual requirement review. Deny proof additionally '
                             'checks resource/principal/additional conditions and accepts union of '
                             'individually covering Denies; malformed evidence stays UNKNOWN.',
             'function': 'peaso.checks.aws_kms_enclave_review_20261019:deployment_binding'}]}
