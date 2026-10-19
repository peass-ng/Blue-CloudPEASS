"""Brief non-AWS identity observations from actual projection schemas.

Recorded bindings and claims remain declarations; no effective access or CEL
policy enforcement is inferred by this presentation-only helper.
"""

def _text(value):
    return isinstance(value, str) and 0 < len(value) <= 320 and all(ord(c) >= 32 for c in value)


def evidence_summary(finding):
    if not isinstance(finding, dict):
        return None
    provider, cid, e = finding.get('provider'), finding.get('check_id'), finding.get('evidence')
    if provider not in ('gcp', 'azure', 'k8s') or not isinstance(e, dict):
        return None
    if finding.get('status') not in ('PASS', 'FAIL', 'MANUAL', 'UNKNOWN'):
        return None
    if cid == 'analysis.federated_trust' and provider == 'gcp':
        issuer, condition = e.get('issuer'), e.get('attribute_condition')
        if not _text(issuer) or 'attribute_condition' not in e:
            return None
        if condition is None or condition == '':
            return f'The workload identity provider for {issuer} declares no attribute condition limiting token exchange.'
        if _text(condition):
            return 'The workload identity provider declares an attribute condition; its CEL logic still requires review.'
        return None
    if cid == 'analysis.federated_trust' and provider == 'azure':
        issuer, subject, expression = e.get('issuer'), e.get('subject'), e.get('claims_matching_expression')
        if not _text(issuer):
            return None
        if _text(subject):
            return f'The federated credential declares subject “{subject}” for issuer {issuer}.'
        value = expression.get('value') if isinstance(expression, dict) else expression
        if _text(value):
            if e.get('wildcard_expression') is True and '*' in value:
                return 'The federated credential declares a wildcard claims expression that leaves the tenant or repository owner unrestricted.'
            return 'The federated credential declares a claims-matching expression instead of a fixed subject.'
        if subject is None and expression is None and e.get('reason') == 'subject not collected':
            return 'The federated credential has no collected subject or claims-matching expression.'
        return None
    if cid != 'analysis.principal_exposure':
        return None
    entries = e.get('principals')
    if not isinstance(entries, list) or not entries or any(not isinstance(row, dict) for row in entries):
        return None
    for row in entries:
        identity, native = row.get('principal'), row.get('native_grant')
        if not _text(identity) or not isinstance(native, dict):
            continue
        classification = row.get('classification')
        if provider == 'gcp':
            members, role = native.get('members'), native.get('role')
            if not isinstance(members, list) or any(not _text(v) for v in members) or identity not in members or not _text(role):
                continue
            if classification == 'public' and identity in ('allUsers', 'allAuthenticatedUsers'):
                audience = 'anyone, including unauthenticated callers' if identity == 'allUsers' else 'all authenticated Google identities'
                qualifier = ' with a recorded condition' if isinstance(native.get('condition'), dict) and native['condition'] else ''
                return f'The IAM binding grants {role} to {audience}{qualifier}; effective access is not established.'
        elif provider == 'azure':
            tenant = native.get('tenantId')
            if native.get('principalId') != identity:
                continue
            if classification == 'external' and _text(tenant) and tenant == row.get('external_scope_id'):
                return f'The role assignment names a principal from external tenant {tenant}; effective access is not established.'
        elif provider == 'k8s':
            if native.get('name') != identity or native.get('kind') not in ('User', 'Group'):
                continue
            if classification == 'public' and identity in ('system:unauthenticated', 'system:anonymous'):
                return 'The RBAC binding explicitly includes unauthenticated subjects; effective access is not established.'
            if classification == 'everyone_authenticated' and identity == 'system:authenticated':
                return 'The RBAC binding explicitly includes every authenticated subject; effective access is not established.'
    return None
