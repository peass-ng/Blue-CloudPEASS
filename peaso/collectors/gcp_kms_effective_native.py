"""Complete KMS IAM closure for unconditional direct user/SA assignments.

Role permissions come from IAM roles.get. Final access comes from the v3beta
read-only Troubleshooter, which includes allow, deny and PAB policies. Groups,
domains, public/federated identities and conditional cryptographic grants are
unresolved rather than counted as one person or silently omitted.
"""
import re
from urllib.parse import quote


def _error(code):
    from .gcp import ReadError
    return ReadError('unavailable', code)


def _local_policy(row):
    if row.get('_coverage', {}).get('iamPolicy', {}).get('status') != 'collected':
        raise _error('kms_local_iam_unavailable')
    policy = row.get('iamPolicy')
    if not isinstance(policy, dict):
        raise _error('kms_local_iam_malformed')
    return policy


def _collect(collector, scope):
    from .gcp_compliance_wave import complete_parent
    from .gcp_storage_acl_native import _root_policies
    keys = complete_parent(collector, 'kms_key', scope)
    if not keys['items']:
        for request in keys['source_requests']:
            yield [], request
        return
    roots = _root_policies(collector, scope)
    rings = complete_parent(collector, 'kms_key_ring', scope)
    ring_index = {r.get('name'): r for r in rings['items']}
    if len(ring_index) != len(rings['items']):
        raise _error('kms_duplicate_ring')
    roles = {}
    requests = set(keys['source_requests']) | set(rings['source_requests'])
    for _, policy in roots:
        requests.update(policy.get('_provenance', {}).get('source_requests', []))
    for request in sorted(requests):
        yield [], request
    for key in keys['items']:
        name = key.get('name')
        if (not isinstance(name, str) or not re.fullmatch(re.escape(scope) +
                r'/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+', name)
                or key.get('keyRing') != name.rsplit('/cryptoKeys/', 1)[0]):
            raise _error('kms_key_identity_unresolved')
        ring = ring_index.get(key['keyRing'])
        if ring is None:
            raise _error('kms_ring_join_unresolved')
        policies = [p for _, p in roots] + [_local_policy(ring), _local_policy(key)]
        for row in (ring, key):
            for request in row['_coverage']['iamPolicy'].get('source_requests', []):
                yield [], request
        candidates = {}
        for policy in policies:
            bindings = policy.get('bindings')
            if not isinstance(bindings, list):
                raise _error('kms_policy_bindings_unavailable')
            for binding in bindings:
                if not isinstance(binding, dict):
                    raise _error('kms_binding_malformed')
                role, members = binding.get('role'), binding.get('members')
                if (not isinstance(role, str) or not re.fullmatch(
                        r'(?:roles/[A-Za-z0-9_.]+|(?:projects|organizations)/[A-Za-z0-9._:-]+/roles/[A-Za-z0-9_.]+)', role)
                        or not isinstance(members, list) or any(not isinstance(m, str) or not m for m in members)
                        or len(members) != len(set(members))):
                    raise _error('kms_binding_identity_unresolved')
                if role not in roles:
                    if len(roles) >= 128:
                        raise _error('kms_role_resolution_bound')
                    role_data, rid = collector.read('https://iam.googleapis.com/v1/' + quote(role, safe='/'), scope)
                    yield [], rid
                    permissions = role_data.get('includedPermissions') if isinstance(role_data, dict) else None
                    if (not isinstance(role_data, dict) or role_data.get('name') != role or role_data.get('deleted') is True
                            or not isinstance(permissions, list) or any(not isinstance(p, str) for p in permissions)):
                        raise _error('kms_role_permissions_unresolved')
                    roles[role] = {p for p in permissions if p.startswith('cloudkms.cryptoKeyVersions.useTo')}
                permissions = roles[role]
                if not permissions:
                    continue
                if 'condition' in binding:
                    raise _error('kms_conditional_crypto_grant_unresolved')
                for member in members:
                    if not re.fullmatch(r'(?:user|serviceAccount):[^\s:@/]+@[^\s:@/]+', member):
                        raise _error('kms_group_public_or_federated_crypto_grant_unresolved')
                    candidates.setdefault(member, set()).update(permissions)
                    if len(candidates) > 256:
                        raise _error('kms_principal_resolution_bound')
        effective = []
        for principal, permissions in sorted(candidates.items()):
            granted = False
            for permission in sorted(permissions):
                access = {'principal': principal.split(':', 1)[1],
                          'fullResourceName': '//cloudkms.googleapis.com/' + name, 'permission': permission}
                value, rid = collector.read('https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot',
                                            scope, method='POST', body={'accessTuple': access})
                yield [], rid
                answer = value.get('accessTuple') if isinstance(value, dict) else None
                state = value.get('overallAccessState') if isinstance(value, dict) else None
                if (not isinstance(answer, dict) or any(answer.get(k) != v for k, v in access.items())
                        or not isinstance(value.get('pabPolicyExplanation'), dict)
                        or state not in ('CAN_ACCESS', 'CANNOT_ACCESS')):
                    raise _error('kms_effective_access_unknown_or_foreign')
                granted |= state == 'CAN_ACCESS'
            if granted:
                effective.append(principal)
        row = {'name': name, 'resolutionComplete': True, 'principals': effective,
               'semantics': 'Complete inherited and key-local direct unconditional grants with native role permissions and v3beta allow/deny/PAB evaluation',
               'policyScopes': [node for node, _ in roots] + [key['keyRing'], name]}
        for request in keys['source_requests'][-1:]:
            yield [row], request


def collect(collector):
    if 'kms_effective_use' not in collector.needed:
        return
    collector.run_jobs([('kms_effective_use', scope, 'cloudkms', lambda scope=scope: _collect(collector, scope))
                        for scope in collector.scopes if scope.startswith('projects/')])
