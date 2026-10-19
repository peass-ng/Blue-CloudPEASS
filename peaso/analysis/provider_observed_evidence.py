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
        if 'attribute_condition' not in e:return None
        if not _text(issuer):
            account=e.get('aws_account')
            if isinstance(account,str) and len(account)==12 and account.isascii() and account.isdigit():
                if condition is None or condition=='':
                    return f'The provider names AWS account {account} with no attribute condition. This may widen token exchange; IAM bindings still govern access.'
                if _text(condition):
                    return f'The provider names AWS account {account} and an attribute condition. Its matching logic and effective token exchange still need review.'
            if issuer is None and account is None:
                return 'No OIDC issuer or AWS account was recorded for the workload identity provider. Its token trust boundary and usable access cannot be assessed.'
            return None
        if condition is None or condition == '':
            return f'Issuer {issuer} has no attribute condition, so its token holders may exchange tokens. IAM grants and provider-side claims still affect access.'
        if _text(condition):
            return 'The workload identity provider declares an attribute condition to limit token exchange; its CEL logic and effective IAM access still need review.'
        return None
    if cid == 'analysis.federated_trust' and provider == 'azure':
        issuer, subject, expression = e.get('issuer'), e.get('subject'), e.get('claims_matching_expression')
        if not _text(issuer):
            return None
        if _text(subject):
            return f'The credential trusts subject “{subject}” from {issuer}. This limits declared token identity; audience and assigned permissions still affect access.'
        value = expression.get('value') if isinstance(expression, dict) else expression
        if _text(value):
            if e.get('wildcard_expression') is True and '*' in value:
                return 'The federated credential uses a wildcard claim that leaves the tenant or repository owner unrestricted. This may admit unintended token holders; assigned permissions remain separate.'
            return 'The federated credential selects token holders through a claims expression instead of a fixed subject. Its matching logic and effective permissions still need review.'
        if subject is None and expression is None and e.get('reason') == 'subject not collected':
            return 'No subject or claims expression was collected for the federated credential. The admitted token identities and effective access remain undetermined.'
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
                return f'The binding grants {role} to {identity} ({audience}){qualifier}. This may admit unintended callers; other policies still affect access.'
            if classification in ('external','unknown'):
                from .common import principal_scope
                scope=principal_scope('gcp',identity)
                if classification=='external' and scope and scope==row.get('external_scope_id'):
                    return f'The binding grants {role} to {identity}, outside the trusted project scope. This can extend access beyond the project; conditions and other policies still apply.'
                if classification=='unknown':
                    return f'The binding grants {role} to {identity}, whose trust boundary could not be resolved. Ownership and usable access remain undetermined.'
        elif provider == 'azure':
            tenant = native.get('tenantId')
            if native.get('principalId') != identity:
                continue
            if classification == 'external' and _text(tenant) and tenant == row.get('external_scope_id'):
                return f'Principal {identity} has a role assignment from external tenant {tenant}. This extends the declared trust boundary; effective role permissions still need review.'
            if classification=='unknown':
                return f'A role assignment names principal {identity}, but its tenant ownership is unresolved. The trust boundary and effective role permissions remain undetermined.'
        elif provider == 'k8s':
            if native.get('name') != identity or native.get('kind') not in ('User', 'Group'):
                continue
            if classification == 'public' and identity in ('system:unauthenticated', 'system:anonymous'):
                return f'The RBAC binding includes {identity} (unauthenticated callers). This can expose its role permissions without login; role scope and other controls still need review.'
            if classification == 'everyone_authenticated' and identity == 'system:authenticated':
                return 'The RBAC binding includes system:authenticated (every logged-in identity). This broadens who receives its role permissions; role scope and other controls still need review.'
            if classification=='unknown':
                return f'The RBAC binding names {native["kind"]} {identity}, whose ownership was not resolved. The intended trust boundary and usable role access need review.'
    return None
