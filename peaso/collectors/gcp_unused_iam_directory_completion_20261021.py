"""Per-project, read-only Workspace customer binding for Directory IAM review.

This is an opt-in replacement for the workspace_user portion of
GCPCollector.workspace_directory; it does not expand Directory authority.
"""
from __future__ import annotations

from copy import deepcopy
import re

CRM = 'https://cloudresourcemanager.googleapis.com/v3/'
USERS = 'https://admin.googleapis.com/admin/directory/v1/users'
USER_FIELDS = ('id,customerId,primaryEmail,isAdmin,isDelegatedAdmin,suspended,archived,'
               'isEnrolledIn2Sv,isEnforcedIn2Sv,recoveryEmail')
CUSTOMER = re.compile(r'C[A-Za-z0-9_-]+\Z')
PARENT = re.compile(r'(?:folders|organizations)/[1-9][0-9]*\Z')
PROJECT = re.compile(r'projects/[A-Za-z0-9_-]+\Z')


def bind_project(collector, scope):
    """Return independently read CRM ancestry or an explicit per-scope error."""
    from .gcp import ReadError
    result = {'status': 'unknown', 'scope': scope, 'chain': [], 'reason': 'directory_binding_unavailable'}
    if not isinstance(scope, str) or not PROJECT.fullmatch(scope):
        result['reason'] = 'directory_project_scope_invalid'
        return result
    current, seen = scope, set()
    try:
        for _ in range(32):
            if current in seen:
                raise ReadError('malformed', 'directory_hierarchy_cycle')
            seen.add(current)
            row, ref = collector.read(CRM + current, scope)
            if not isinstance(row, dict) or row.get('name') is None:
                raise ReadError('malformed', 'directory_hierarchy_response')
            name = row['name']
            if current == scope:
                token = scope.split('/', 1)[1]
                if (not isinstance(name, str) or not re.fullmatch(r'projects/[1-9][0-9]*', name)
                        or token not in (name.split('/', 1)[1], row.get('projectId'))):
                    raise ReadError('malformed', 'directory_project_identity_mismatch')
            elif name != current:
                raise ReadError('malformed', 'directory_hierarchy_identity_mismatch')
            parent = row.get('parent')
            result['chain'].append({'requested': current, 'name': name,
                                    'projectId': row.get('projectId'), 'parent': parent,
                                    'directoryCustomerId': row.get('directoryCustomerId'),
                                    'source_request': ref})
            if current.startswith('organizations/'):
                customer = row.get('directoryCustomerId')
                if not isinstance(customer, str) or not CUSTOMER.fullmatch(customer):
                    raise ReadError('unavailable', 'organization_directory_customer_unavailable')
                result.update(status='collected', reason='', organization=current, customer=customer)
                return result
            if not isinstance(parent, str) or not PARENT.fullmatch(parent):
                raise ReadError('unavailable', 'directory_project_parent_unavailable')
            current = parent
        raise ReadError('unavailable', 'directory_hierarchy_depth_limit')
    except ReadError as exc:
        result.update(status=exc.status, reason=exc.error.get('code', 'directory_binding_unavailable'))
        return result


def collect_users(collector):
    """List only Directory customers proven for each selected project.

    A failure in one project produces that project's unavailable collection. The
    same customer may be read for two projects because each finding must carry
    its own project-bound CRM request chain and collection scope.
    """
    from .gcp import ReadError
    if 'workspace_user' not in collector.needed:
        return
    selected = collector.options.get('workspace_customers', collector.options.get('cloud_identity_customers', []))
    if not isinstance(selected, list) or any(not isinstance(c, str) or not CUSTOMER.fullmatch(c) for c in selected):
        raise ValueError('Workspace customers must be explicit customer IDs for project-bound user review')
    for scope in sorted(s for s in collector.scopes if s.startswith('projects/')):
        # The core Directory group/customer reads need the same selected-project
        # ancestry. Reuse its validated receipts when there is one project;
        # keep independent per-project binding for multi-scope scans.
        shared = getattr(collector, 'workspace_project_binding', None)
        binding = (shared() if len(collector.scopes) == 1 and collector.scopes[0] == scope
                   and callable(shared) else bind_project(collector, scope))

        def rows(scope=scope, binding=binding):
            if binding['status'] != 'collected':
                raise ReadError(binding['status'], binding['reason'])
            customer = binding['customer']
            if selected and customer not in selected:
                raise ReadError('unavailable', 'project_directory_customer_not_selected')
            seen = set()
            params = {'customer': customer, 'projection': 'full', 'viewType': 'admin_view',
                      'fields': 'users(' + USER_FIELDS + '),nextPageToken'}
            for items, ref in collector.pages(USERS, scope, key='users', params=params, page_size_key='maxResults'):
                output = []
                for user in items:
                    uid = user.get('id') if isinstance(user, dict) else None
                    if (not isinstance(uid, str) or not uid or uid in seen
                            or user.get('customerId') != customer):
                        raise ReadError('malformed', 'directory_user_identity_missing_duplicate_or_foreign')
                    seen.add(uid)
                    output.append({**user, 'name': f'customers/{customer}/workspace_user/{uid}',
                                   'directoryCustomer': customer, '_directoryBinding': deepcopy(binding),
                                   'scopeSelection': 'CRM-bound selected project; read-only Directory API',
                                   '_coverage': {'directoryProjection': {'status': 'collected',
                                       'fields': USER_FIELDS.split(','), 'source_requests': [ref],
                                       'projection': 'full', 'viewType': 'admin_view'}}})
                yield output, ref

        collector.add('workspace_user', scope, 'workspace-directory', rows)
