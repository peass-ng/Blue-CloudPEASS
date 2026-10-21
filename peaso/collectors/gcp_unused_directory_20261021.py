"""Read-only per-user login metadata, isolated from existing Directory projections."""
from copy import deepcopy
from urllib.parse import quote
import re

from peaso.gcp_directory_usage_contract import KIND, FIELDS, USERS


def collect(collector):
    from .gcp import ReadError
    # Native pool names commonly contain project numbers while selection uses
    # project IDs. Reuse the existing exact CRM proof; never infer an alias.
    for scope, pool in collector.items('workload_identity_pool') + collector.items('iam_role'):
        name = pool.get('name')
        match = re.fullmatch(r'projects/([^/]+)/(?:locations/global/workloadIdentityPools|roles)/[^/?#]+', name or '')
        if scope.startswith('projects/') and match and match[1] != scope.split('/')[1]:
            try:
                collector._data_project_binding(scope, require_alias=True)
            except ReadError as exc:
                pool.setdefault('_coverage', {})['_projectIdentity'] = {'status': exc.status, 'error': exc.error}
    if KIND not in collector.needed:
        return
    scopes = sorted({scope for scope, _ in collector.items('workspace_user')})
    if not scopes:
        scopes = collector.scopes[:1]
    for scope in scopes:
        def rows(scope=scope):
            parent = collector.collections.get(('workspace_user', scope))
            if not parent or parent.get('status') not in ('collected', 'empty', 'partial'):
                raise ReadError('unavailable', 'directory_user_inventory_unavailable')
            def individual(user):
                uid, customer = user.get('id'), user.get('customerId')
                if not isinstance(uid, str) or not uid or not isinstance(customer, str):
                    raise ReadError('malformed', 'directory_user_identity_missing')
                record = {'name': f'customers/{customer}/users/{uid}/loginActivity',
                    'user_id': uid, 'directory_customer': customer, 'user_name': user.get('name')}
                # Disabled accounts are explicit applicability, with no extra read.
                if user.get('suspended') is True or user.get('archived') is True:
                    return None
                try:
                    detail, ref = collector.read(USERS+'/'+quote(uid, safe=''), scope,
                        params={'projection': 'full', 'viewType': 'admin_view', 'fields': FIELDS})
                    if (not isinstance(detail, dict) or detail.get('id') != uid or detail.get('customerId') != customer
                            or not isinstance(detail.get('primaryEmail'), str)
                            or detail['primaryEmail'].casefold() != str(user.get('primaryEmail', '')).casefold()):
                        record.update(status='malformed', error={'code': 'directory_user_detail_identity_mismatch'})
                    else:
                        record.update(status='collected', detail={key: deepcopy(detail[key]) for key in FIELDS.split(',') if key in detail})
                    return record, ref
                except ReadError as exc:
                    record.update(status=exc.status, error=exc.error)
                    # Before-HTTP budget failures have no request ID: retain the
                    # parent identity proof without asserting a successful GET.
                    ref = exc.request_id if getattr(exc, 'request_id', None) else user['_provenance']['source_requests'][0]
                    return record, ref
            for result in collector.parallel(individual, parent['items']):
                if result is not None:
                    record, ref = result
                    yield [record], ref
        collector.add(KIND, scope, 'workspace-directory', rows)


def known_role_aliases(collector, role_scopes, known):
    """Avoid re-fetching one listed role under a second proven project alias."""
    from .gcp import ReadError
    listed = {}
    for scope, role in collector.items('iam_role'):
        match = re.fullmatch(r'projects/([^/]+)/roles/([A-Za-z0-9_.]+)', role.get('name', ''))
        if match and scope.startswith('projects/'):
            listed.setdefault((scope, match[2]), []).append(match[1])
    aliases = set()
    for name, scopes in role_scopes.items():
        match = re.fullmatch(r'projects/([^/]+)/roles/([A-Za-z0-9_.]+)', name)
        if not match:
            continue
        for scope in scopes:
            owners = listed.get((scope, match[2]), [])
            if (scope, name) in known or not owners:
                continue
            # Distinct textual project IDs cannot alias the same project.
            if all(not owner.isdecimal() and not match[1].isdecimal() and owner != match[1] for owner in owners):
                continue
            try:
                binding = collector._data_project_binding(scope, require_alias=True)
            except ReadError:
                continue
            proven = {binding['project_id'], binding['project_number']}
            if match[1] in proven and any(owner in proven for owner in owners):
                aliases.update((scope, 'projects/'+owner+'/roles/'+match[2]) for owner in proven)
    return aliases
