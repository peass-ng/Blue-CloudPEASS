"""Native-only successor for the signed SW52 predicate; no registry hook changes."""
import re
from . import result, unknown
from .facts import Unavailable, complete_items, get, guard

def _scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'gcp':
        raise Unavailable('GCP snapshot authority unavailable')
    scope = get(context, 'scope', str)
    if not re.fullmatch(r'(projects|folders|organizations)/[A-Za-z0-9._-]+', scope):
        raise Unavailable('malformed GCP scope')
    return scope


def _rows(index, kind):
    scope = _scope(index)
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('missing or ambiguous collection: ' + kind)
    envelope = envelopes[0]
    if get(envelope, 'type', str) != kind or get(envelope, 'scope', str) != scope:
        raise Unavailable('foreign collection: ' + kind)
    status = get(envelope, 'status', str)
    if status not in ('collected', 'empty'):
        raise Unavailable('incomplete collection: ' + kind)
    native = get(envelope, 'items', list)
    if any(not isinstance(row, dict) for row in native) or (status == 'empty') != (len(native) == 0):
        raise Unavailable('malformed collection: ' + kind)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    if len(rows) != len(native) or len(wrappers) != len(native):
        raise Unavailable('inconsistent collection projection: ' + kind)
    for wrapper, row, original in zip(wrappers, rows, native):
        if (get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str) != scope or row != original):
            raise Unavailable('foreign or inconsistent projection: ' + kind)
    return rows


def _member(item, index, kind):
    rows = _rows(index, kind)
    if sum(row == item for row in rows) != 1:
        raise Unavailable('resource is not uniquely in scoped inventory: ' + kind)
    return rows


def _policy(index, field, typ=list):
    policy = get(index, 'context.metadata.sw52', dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str) != _scope(index):
        raise Unavailable('scoped operator policy unavailable')
    value = get(policy, field, typ)
    if typ is list and (any(not isinstance(x, str) or not x for x in value) or len(value) != len(set(value))):
        raise Unavailable('malformed operator policy list: ' + field)
    return value


def _list(row, path):
    values = get(row, path, list)
    if any(not isinstance(value, dict) for value in values):
        raise Unavailable('malformed object list: ' + path)
    return values


def _bindings(policy):
    return _list(policy, 'bindings')


def _identity(row):
    return get(row, 'name', str)


def _iam_members(binding):
    members = get(binding, 'members', list)
    if any(not isinstance(value, str) or not value for value in members):
        raise Unavailable('malformed IAM member')
    return members



def super_admin_separation(item, index):
    _member(item, index, 'workspace_role_assignment')
    scope = _scope(index)
    native = get(index, 'context.metadata.sw52_native', dict).get(scope)
    if not isinstance(native, dict) or native.get('status') != 'collected' or native.get('scope') != scope:
        return unknown('native project hierarchy and Directory binding unavailable')
    names = get(native, 'iam_policy_resource_names', list)
    org = get(native, 'organization', str)
    customer = get(native, 'directory_customer', str)
    hierarchy_requests = get(native, 'hierarchy_source_requests', dict)
    if (not names or names[0] != scope or names[-1] != org or
            not re.fullmatch(r'organizations/[1-9][0-9]*', org) or
            not re.fullmatch(r'C[A-Za-z0-9_-]+', customer) or
            any(not re.fullmatch(r'folders/[1-9][0-9]*', name) for name in names[1:-1]) or
            len(names) != len(set(names)) or
            get(native, 'iam_policy_levels', list) != [name.split('/', 1)[0][:-1] for name in names] or
            set(hierarchy_requests) != set(names[:-1]) or
            any(not isinstance(value, list) or not value for value in hierarchy_requests.values()) or
            not get(native, 'ancestry_source_requests', list) or
            not get(native, 'organization_source_requests', list)):
        return unknown('native hierarchy provenance incomplete')
    role_id = get(item, 'roleId', str)
    roles = [role for role in _rows(index, 'workspace_role') if get(role, 'roleId', str) == role_id]
    if len(roles) != 1:
        return unknown('role assignment cannot be resolved')
    if not get(roles[0], 'isSuperAdminRole', bool):
        return 'NOT_APPLICABLE', {'reason': 'assignment is not a super-admin role'}
    if (get(item, 'directoryCustomer', str) != customer or
            get(roles[0], 'directoryCustomer', str) != customer):
        return unknown('Workspace role assignment belongs to a different Directory customer')
    user_id = get(item, 'assignedTo', str)
    users = [user for user in _rows(index, 'workspace_user') if get(user, 'id', str) == user_id]
    if len(users) != 1:
        return unknown('super-admin user identity cannot be resolved')
    if (get(users[0], 'directoryCustomer', str) != customer or
            get(users[0], 'customerId', str) != customer):
        return unknown('Workspace user belongs to a different Directory customer')
    email = get(users[0], 'primaryEmail', str).lower()
    if not re.fullmatch(r'[^@\s]+@[^@\s]+', email):
        return unknown('Workspace user email unavailable')
    _rows(index, 'group')
    _rows(index, 'group_membership')
    current_policies = _rows(index, 'iam_policy')
    requests = get(native, 'iam_policy_source_requests', dict)
    selected = get(native, 'iam_policy_roots', list)
    if len(selected) != len(names) or set(requests) != set(names):
        return unknown('super-admin IAM policy projection incomplete')
    for name, root in zip(names, selected):
        if (get(root, 'origin_scope', str) != name or get(root, 'name', str) != name or
                get(root, 'representation', str) != 'full' or
                not isinstance(requests.get(name), list) or not requests[name] or
                get(root, 'source_requests', list) != requests[name] or
                not get(root, 'collection_source_requests', list)):
            return unknown('super-admin IAM root identity or provenance incomplete')
        _bindings(root)
    project_roots = [row for row in current_policies if row.get('name') == scope and
                     row.get('_provenance', {}).get('representation') == 'full']
    if (len(project_roots) != 1 or
            get(project_roots[0], 'bindings', list) != get(selected[0], 'bindings', list) or
            not set(requests[scope]) <= set(get(project_roots[0], '_provenance.source_requests', list))):
        return unknown('project IAM root projection inconsistent with scoped inventory')
    findings = []
    unresolved = []
    for document in selected:
        for binding in _bindings(document):
            role = get(binding, 'role', str)
            if role not in ('roles/owner', 'roles/editor') and not role.endswith(('Admin', 'admin')):
                continue
            members = {member.lower() for member in _iam_members(binding)}
            direct = 'user:' + email in members or bool({'allusers', 'allauthenticatedusers'} & members)
            indirect = any(member.startswith(('group:', 'domain:', 'principalset:', 'principal:')) for member in members)
            if direct or indirect:
                if 'condition' in binding:
                    unresolved.append(role + ':conditional')
                elif direct:
                    findings.append(role)
                else:
                    unresolved.append(role + ':indirect')
    if unresolved:
        return unknown('effective administrative grants unresolved', roles=sorted(set(unresolved)),
            direct_conflicting_roles=sorted(set(findings)))
    return result(bool(findings), principal=email, conflicting_roles=sorted(set(findings)),
        organization=org, directory_customer=customer, iam_policy_resource_names=names)
