"""Signed GCP compliance predicates over scoped, complete snapshot facts."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import re

from . import CHECKS, register as _native_register, result, unknown
from .facts import Unavailable, complete_items, get, guard

SPECS = {'gcp_cloud_armor_waf_enabled': {'provider': 'gcp',
                                 'resource_kind': 'security_policy',
                                 'category': 'network',
                                 'severity': 'high',
                                 'title': 'Public backend has no web application filtering',
                                 'remediation_hint': 'Attach a Cloud Armor policy containing an enabled '
                                                     'evaluatePreconfiguredWaf expression to each public '
                                                     'backend.',
                                 'proposed_spec_sha256': '26ddc0e84e87442459f99dea96b95243ae4300a3af7561aefb1d5f2ea7e6b9cc'},
 'gcp.identity.non_service_account_mfa': {'provider': 'gcp',
                                          'resource_kind': 'workspace_user',
                                          'category': 'hardening',
                                          'severity': 'high',
                                          'title': 'Non-service Google Cloud users lack enforced two-step '
                                                   'verification',
                                          'remediation_hint': 'Require and enroll two-step verification for '
                                                              'each active Workspace user with Cloud IAM '
                                                              'access in the Admin console.',
                                          'proposed_spec_sha256': 'd47e76135cb7322aa96d9e23d0e171e07074319572a55831b6459d88b0942d32'},
 'gcp.identity.super_admin_recovery_group': {'provider': 'gcp',
                                             'resource_kind': 'workspace_user',
                                             'category': 'hardening',
                                             'severity': 'high',
                                             'title': 'Super-admin recovery email belongs to a multi-person '
                                                      'group',
                                             'remediation_hint': "Set each super admin's recoveryEmail to a "
                                                                 'Directory group containing at least two '
                                                                 'active recovery operators.',
                                             'proposed_spec_sha256': '8f5ee8597513ce09dc640f45a7526530863dfb721884c30976bfbd061594cfa6'},
 'gcp_c5_sbom': {'provider': 'gcp',
                 'resource_kind': 'artifact_repository',
                 'category': 'secure_development',
                 'severity': 'medium',
                 'title': 'Deployed image has an SBOM',
                 'remediation_hint': 'Publish an SBOM_REFERENCE Artifact Analysis occurrence for each '
                                     'deployed Artifact Registry image digest.',
                 'proposed_spec_sha256': '769d35633a8c0bce6be2c9458165676852e80a0182e1a1b27dc3d200544e5359'},
 'gcp_lb_server_header_rewrite': {'provider': 'gcp',
                                  'resource_kind': 'url_map',
                                  'category': 'network',
                                  'severity': 'medium',
                                  'title': 'Load balancer does not rewrite Server header',
                                  'remediation_hint': 'Set replace=true for the Server response header with '
                                                      'value lb on every route of the public URL map.',
                                  'proposed_spec_sha256': '4fdaa30bde498f7d1c541e786f2368cf81f14affd07b6beb6072de7f73438b9b'},
 'gcp_pci_url_map_9ed56c323a05': {'provider': 'gcp',
                                  'resource_kind': 'url_map',
                                  'category': 'encryption',
                                  'severity': 'medium',
                                  'title': 'HTTP load balancer frontends redirect to HTTPS',
                                  'remediation_hint': 'Set urlMaps.defaultUrlRedirect.httpsRedirect=true and '
                                                      'equivalent redirects for every HTTP path '
                                                      'matcher/route.',
                                  'proposed_spec_sha256': '9c176e93f19b1f35d7e0345178da2542aff2f7cfae01f5acb1c5c1ac7726a2c8'},
 'gcp_c5_log_event_fields': {'provider': 'gcp',
                             'resource_kind': 'log_entry',
                             'category': 'logging',
                             'severity': 'medium',
                             'title': 'Audit event timestamp and actor fields',
                             'remediation_hint': 'Ensure the audit producer supplies '
                                                 'protoPayload.authenticationInfo.principalEmail and a valid '
                                                 'timestamp; investigate malformed events.',
                             'proposed_spec_sha256': '0dee7707ea39dbf03e9aaa91e7fe3991039a2caaa405feb758037aa1d6e54180'},
 'gcp_c5_security_event_route': {'provider': 'gcp',
                                 'resource_kind': 'monitoring_alert_policy',
                                 'category': 'incident_detection',
                                 'severity': 'medium',
                                 'title': 'Security event notification route',
                                 'remediation_hint': 'Link each approved security log metric to an enabled '
                                                     'Monitoring alert policy and enabled verified '
                                                     'notification channel.',
                                 'proposed_spec_sha256': 'f6d8b9e6973e05d1e01e26300cc1eadf8cf636efd32a9d4b4da196f32fc3b3a4'},
 'gcp_c5_secret_access': {'provider': 'gcp',
                          'resource_kind': 'secret',
                          'category': 'identity',
                          'severity': 'medium',
                          'title': 'Credential secret access restriction',
                          'remediation_hint': 'Remove allUsers and unapproved secretAccessor IAM bindings '
                                              'from credential secrets, including inherited grants.',
                          'proposed_spec_sha256': '2313cbb4186e8f35aea97c05621f9ab9149d23464f41132ec4a79c9efdbe5bb1'},
 'gcp.identity.super_admin_separation': {'provider': 'gcp',
                                         'resource_kind': 'workspace_role_assignment',
                                         'category': 'least_privilege',
                                         'severity': 'high',
                                         'title': 'Workspace super admins are separate from routine Google '
                                                  'Cloud administrators',
                                         'remediation_hint': 'Remove roles/owner, roles/editor and '
                                                             'administrative IAM bindings for Workspace '
                                                             'super admins; use separate routine-admin '
                                                             'identities.',
                                         'proposed_spec_sha256': '91e8d5cbe97be325cc288584e091a335f3f70367ec79c0de9c1b74cbfb2630fa'},
 'gcp.orgpolicy.central_constraints': {'provider': 'gcp',
                                       'resource_kind': 'org_policy_effective',
                                       'category': 'hardening',
                                       'severity': 'medium',
                                       'title': 'Organization policies enforce centralized constraints',
                                       'remediation_hint': 'Set the required Org Policy constraints at the '
                                                           'organization or folder; correct descendant '
                                                           'exceptions and allowedValues.',
                                       'proposed_spec_sha256': '1acf8aa9b49281416b5289764a7cf98bce26993f820a008e35db42e7cf08d8df'},
 'gcp.network.private_service_connect_google_apis': {'provider': 'gcp',
                                                     'resource_kind': 'forwarding_rule',
                                                     'category': 'network',
                                                     'severity': 'medium',
                                                     'title': 'VPCs use Private Service Connect for Google '
                                                              'APIs',
                                                     'remediation_hint': 'Create a Google APIs Private '
                                                                         'Service Connect forwarding rule in '
                                                                         'each required VPC and point '
                                                                         'required private DNS A records at '
                                                                         'its IP.',
                                                     'proposed_spec_sha256': 'a717f4090611be6eae3657d3c82a09c5bcf1431d7d8f6cec426864d7cae5bf47'},
 'gcp_cloudbuild_private_pool': {'provider': 'gcp',
                                 'resource_kind': 'worker_pool',
                                 'category': 'network',
                                 'severity': 'high',
                                 'title': 'Cloud Build worker pool is reachable outside approved network',
                                 'remediation_hint': 'Set privatePoolV1Config.networkConfig.peeredNetwork to '
                                                     'an approved VPC on enabled Cloud Build worker pools.',
                                 'proposed_spec_sha256': '1a63d653ef2162412671bb096e5c9075101c2d5e38909e3cd58a89886f5e504f'},
 'gcp_source_repo_access_restricted': {'provider': 'gcp',
                                       'resource_kind': 'source_repository',
                                       'category': 'identity',
                                       'severity': 'high',
                                       'title': 'Source repository permits unapproved access',
                                       'remediation_hint': 'Remove allUsers/allAuthenticatedUsers and '
                                                           'principals outside approved_developers from '
                                                           'repository IAM bindings.',
                                       'proposed_spec_sha256': 'ffd64fae6f133c699a42943f0ddfaad5d3a4fefc225a507ead8685fe15e6b985'}}
SPEC_SHA256 = {key: value["proposed_spec_sha256"] for key, value in SPECS.items()}


def register(check_id, dependencies, *, target='resource'):
    """Use native safe wrapper while retaining the signed category verbatim."""
    spec = SPECS[check_id]
    native = spec['category'] if spec['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'
    def decorate(fn):
        _native_register(check_id, 'gcp', native, spec['resource_kind'], spec['title'],
                         spec['severity'], 'CM-6', spec['remediation_hint'],
                         dependencies=dependencies, target=target)(fn)
        position = next(i for i, check in enumerate(CHECKS) if check.id == check_id)
        CHECKS[position] = replace(CHECKS[position], category=spec['category'])
        return fn
    return decorate


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


def _super_admin_ids(index):
    roles = _rows(index, 'workspace_role')
    role_ids = {get(role, 'roleId', str) for role in roles if get(role, 'isSuperAdminRole', bool)}
    if len(role_ids) != sum(get(role, 'isSuperAdminRole', bool) for role in roles):
        raise Unavailable('duplicate super-admin role')
    assignments = _rows(index, 'workspace_role_assignment')
    return {get(a, 'assignedTo', str) for a in assignments if get(a, 'roleId', str) in role_ids}


def _full_omitted(row, field, default, *, full=False):
    guard(row)
    if field in row:
        return get(row, field)
    if (full or row.get('_representation') == 'full') and field not in row.get('_coverage', {}):
        return default
    raise Unavailable('missing field without full representation: ' + field)


@register('gcp.identity.non_service_account_mfa', ['workspace_user', 'iam_policy'])
def non_service_account_mfa(item, index):
    _member(item, index, 'workspace_user')
    email = get(item, 'primaryEmail', str).lower()
    if not email or get(item, 'suspended', bool):
        return 'NOT_APPLICABLE', {'reason': 'suspended or no active human identity'}
    if get(item, 'identityProvider', str) != 'workspace' or not get(item, 'inDomain', bool):
        return unknown('external or unsupported identity provider')
    policies = _rows(index, 'iam_policy')
    principals = set()
    for policy in policies:
        for binding in _bindings(policy):
            principals.update(_iam_members(binding))
    if 'user:' + email not in principals:
        if not _policy(index, 'principal_expansion_complete', bool):
            return unknown('human IAM principal expansion incomplete')
        expanded = _policy(index, 'effective_iam_user_emails')
        if email not in expanded:
            return 'NOT_APPLICABLE', {'reason': 'user has no Cloud IAM access in complete principal expansion'}
    enrolled = get(item, 'isEnrolledIn2Sv', bool)
    return result(not enrolled, principal=email, isEnrolledIn2Sv=enrolled)


@register('gcp.identity.super_admin_recovery_group', ['workspace_user', 'workspace_role', 'workspace_role_assignment', 'group', 'group_membership'])
def super_admin_recovery_group(item, index):
    _member(item, index, 'workspace_user')
    email = get(item, 'primaryEmail', str).lower()
    if get(item, 'suspended', bool) or get(item, 'id', str) not in _super_admin_ids(index):
        return 'NOT_APPLICABLE', {'reason': 'user is not an active assigned super admin'}
    recovery_value = _full_omitted(item, 'recoveryEmail', '')
    if not isinstance(recovery_value, str):
        return unknown('malformed recovery email')
    recovery = recovery_value.lower()
    groups = _rows(index, 'group')
    members = _rows(index, 'group_membership')
    matched = [group for group in groups if get(group, 'email', str).lower() == recovery]
    if not recovery or not matched:
        return result(True, principal=email, recovery_email=recovery, reason='missing or non-group recovery address')
    if len(matched) != 1:
        return unknown('ambiguous Directory group identity')
    group_id = get(matched[0], 'id', str)
    active = set()
    for member in members:
        if get(member, 'groupId', str) != group_id:
            continue
        status = get(member, 'status', str)
        if status not in ('ACTIVE', 'INACTIVE', 'SUSPENDED'):
            return unknown('unrecognized Directory group member status')
        if status == 'ACTIVE':
            member_email = get(member, 'email', str).lower()
            if not member_email or member_email in active:
                return unknown('malformed or duplicate active group member')
            active.add(member_email)
    return result(len(active) < 2, principal=email, recovery_email=recovery, active_member_count=len(active))


@register('gcp.identity.super_admin_separation', ['workspace_role_assignment', 'workspace_role', 'workspace_user', 'iam_policy', 'group_membership'])
def super_admin_separation(item, index):
    _member(item, index, 'workspace_role_assignment')
    role_id = get(item, 'roleId', str)
    roles = [role for role in _rows(index, 'workspace_role') if get(role, 'roleId', str) == role_id]
    if len(roles) != 1:
        return unknown('role assignment cannot be resolved')
    if not get(roles[0], 'isSuperAdminRole', bool):
        return 'NOT_APPLICABLE', {'reason': 'assignment is not a super-admin role'}
    user_id = get(item, 'assignedTo', str)
    users = [user for user in _rows(index, 'workspace_user') if get(user, 'id', str) == user_id]
    if len(users) != 1:
        return unknown('super-admin user identity cannot be resolved')
    email = get(users[0], 'primaryEmail', str).lower()
    # A complete group expansion is required even though this predicate grades direct grants.
    _rows(index, 'group_membership')
    policy = _policy(index, 'iam_policy_levels', list)
    if not {'project', 'folder', 'organization'} <= set(policy):
        return unknown('IAM policy level coverage incomplete')
    hierarchy = _policy(index, 'iam_policy_resource_names')
    if not hierarchy or _scope(index) not in hierarchy:
        return unknown('super-admin IAM hierarchy unavailable')
    all_policies = _rows(index, 'iam_policy')
    selected = [document for document in all_policies if get(document, 'name', str) in hierarchy]
    if len(selected) != len(hierarchy) or {get(document, 'name', str) for document in selected} != set(hierarchy):
        return unknown('super-admin IAM policy read incomplete')
    findings = []
    for document in selected:
        for binding in _bindings(document):
            role = get(binding, 'role', str)
            if (role in ('roles/owner', 'roles/editor') or role.endswith(('Admin', 'admin'))) and 'user:' + email in _iam_members(binding):
                findings.append(role)
    return result(bool(findings), principal=email, conflicting_roles=sorted(set(findings)))


@register('gcp.orgpolicy.central_constraints', ['org_policy_effective'], target='scope')
def central_constraints(item, index):
    if get(item, 'scope', str) != _scope(index):
        return unknown('scope subject does not match snapshot')
    required = _policy(index, 'required_constraints', dict)
    if not required:
        return unknown('required constraint catalogue is empty')
    constraints = _rows(index, 'org_policy_effective')
    seen = set()
    failures = []
    for name, config in required.items():
        if not isinstance(name, str) or not isinstance(config, dict) or get(config, 'type', str) not in ('boolean', 'list'):
            return unknown('malformed required constraint policy')
        rows = [row for row in constraints if get(row, 'constraint', str) == name]
        if len(rows) != 1:
            return unknown('required effective policy missing or ambiguous', constraint=name)
        row = rows[0]
        rules = _list(row, 'spec.rules')
        if not rules:
            return unknown('effective policy has no evaluable rules')
        if config['type'] == 'boolean':
            for rule in rules:
                if get(rule, 'enforce', bool) is False:
                    failures.append(name)
        else:
            approved = get(config, 'allowedValues', list)
            if any(not isinstance(value, str) for value in approved):
                return unknown('malformed approved values')
            for rule in rules:
                values = get(rule, 'values.allowedValues', list)
                if any(not isinstance(value, str) for value in values):
                    return unknown('malformed effective values')
                if any(value not in approved for value in values):
                    failures.append(name)
        seen.add(name)
    return result(bool(failures), violated_constraints=sorted(set(failures)))


@register('gcp.network.private_service_connect_google_apis', ['forwarding_rule', 'dns_record'], target='scope')
def private_service_connect_google_apis(item, index):
    if get(item, 'scope', str) != _scope(index):
        return unknown('scope subject does not match snapshot')
    networks = _policy(index, 'required_vpcs')
    hostnames = _policy(index, 'required_google_api_hostnames')
    if not networks or not hostnames:
        return unknown('required VPC or hostname policy is empty')
    rules = _rows(index, 'forwarding_rule')
    records = _rows(index, 'dns_record')
    missing = []
    for network in networks:
        psc = [rule for rule in rules if get(rule, 'network', str) == network and
               (get(rule, 'target', str) in ('all-apis', 'vpc-sc') or
                get(rule, 'target', str).endswith(('/all-apis', '/vpc-sc')))]
        if not psc:
            missing.append((network, 'PSC forwarding rule'))
            continue
        addresses = {get(rule, 'IPAddress', str) for rule in psc}
        for hostname in hostnames:
            matches = [record for record in records if get(record, 'name', str).rstrip('.') == hostname.rstrip('.') and
                       get(record, 'network', str) == network and get(record, 'type', str) == 'A']
            if not matches or not any(address in get(record, 'rrdatas', list) for record in matches for address in addresses):
                missing.append((network, hostname))
    return result(bool(missing), missing_routes=missing)

@register('gcp_cloud_armor_waf_enabled', ['security_policy', 'backend_service'])
def cloud_armor_waf_enabled(item, index):
    _member(item, index, 'security_policy')
    policy_name = get(item, 'selfLink', str)
    backends = _rows(index, 'backend_service')
    associated = [backend for backend in backends if get(backend, 'securityPolicy', str) == policy_name]
    if not associated:
        return 'NOT_APPLICABLE', {'reason': 'policy is not attached to a backend'}
    public = [backend for backend in associated if get(backend, 'internetFacing', bool)]
    if not public:
        return 'NOT_APPLICABLE', {'reason': 'no associated internet-facing backend'}
    rules = _list(item, 'rules')
    has_waf = any(get(rule, 'action', str) == 'deny' and
                  'evaluatePreconfiguredWaf' in get(rule, 'match.expr.expression', str) for rule in rules)
    return result(not has_waf, policy=policy_name, public_backends=[get(b, 'name', str) for b in public])


@register('gcp_cloudbuild_private_pool', ['worker_pool'])
def cloudbuild_private_pool(item, index):
    _member(item, index, 'worker_pool')
    state = get(item, 'state', str)
    if state == 'DELETED':
        return 'NOT_APPLICABLE', {'reason': 'worker pool is deleted'}
    if state != 'RUNNING':
        return unknown('unrecognized worker pool state')
    approved = _policy(index, 'approved_worker_networks')
    config = get(item, 'privatePoolV1Config.networkConfig', dict)
    network = _full_omitted(config, 'peeredNetwork', '', full=item.get('_representation') == 'full')
    if not isinstance(network, str):
        return unknown('malformed worker peered network')
    return result(not network or network not in approved, worker_pool=_identity(item), peered_network=network)


@register('gcp_source_repo_access_restricted', ['source_repository'])
def source_repo_access_restricted(item, index):
    _member(item, index, 'source_repository')
    approved = set(_policy(index, 'approved_developers'))
    bindings = _bindings(get(item, 'iamPolicy', dict))
    unauthorized = []
    for binding in bindings:
        role = get(binding, 'role', str)
        if role not in ('roles/source.reader', 'roles/source.writer', 'roles/source.admin', 'roles/owner', 'roles/editor'):
            if role.startswith(('projects/', 'organizations/')) and '/roles/' in role:
                return unknown('custom repository role permissions unavailable', role=role)
            continue
        unauthorized.extend(member for member in _iam_members(binding)
                            if member in ('allUsers', 'allAuthenticatedUsers') or member not in approved)
    return result(bool(unauthorized), repository=_identity(item), unauthorized_members=sorted(set(unauthorized)))


@register('gcp_c5_secret_access', ['secret', 'iam_policy'])
def c5_secret_access(item, index):
    _member(item, index, 'secret')
    credential_names = _policy(index, 'credential_secrets')
    if _identity(item) not in credential_names:
        return 'NOT_APPLICABLE', {'reason': 'secret is not classified as a credential'}
    approved = set(_policy(index, 'approved_secret_readers'))
    inherited = _rows(index, 'iam_policy')
    parents = _policy(index, 'complete_iam_policy_levels')
    if not {'project', 'folder', 'organization'} <= set(parents):
        return unknown('inherited IAM policy level unavailable')
    hierarchy = _policy(index, 'iam_policy_resource_names')
    if not hierarchy or _scope(index) not in hierarchy:
        return unknown('scoped IAM hierarchy unavailable')
    selected = [policy for policy in inherited if get(policy, 'name', str) in hierarchy]
    if len(selected) != len(hierarchy) or {get(policy, 'name', str) for policy in selected} != set(hierarchy):
        return unknown('inherited IAM policy read incomplete')
    bindings = _bindings(get(item, 'iamPolicy', dict))
    for policy in selected:
        bindings.extend(_bindings(policy))
    unauthorized = []
    for binding in bindings:
        role = get(binding, 'role', str)
        if role not in ('roles/secretmanager.secretAccessor', 'roles/secretmanager.admin', 'roles/owner', 'roles/editor'):
            if role.startswith(('projects/', 'organizations/')) and '/roles/' in role:
                return unknown('custom secret role permissions unavailable', role=role)
            continue
        unauthorized.extend(member for member in _iam_members(binding)
                            if member in ('allUsers', 'allAuthenticatedUsers') or member not in approved)
    return result(bool(unauthorized), secret=_identity(item), unauthorized_members=sorted(set(unauthorized)))


@register('gcp_c5_sbom', ['artifact_repository', 'artifact_image', 'sbom_occurrence', 'deployed_image'])
def c5_sbom(item, index):
    _member(item, index, 'artifact_repository')
    repo = _identity(item)
    images = _rows(index, 'artifact_image')
    deployed = _rows(index, 'deployed_image')
    occurrences = _rows(index, 'sbom_occurrence')
    deployed_digests = {get(row, 'digest', str) for row in deployed if get(row, 'repository', str) == repo}
    image_rows = [row for row in images if get(row, 'repository', str) == repo]
    image_digests = {get(row, 'digest', str): get(row, 'uri', str) for row in image_rows}
    if len(image_digests) != len(image_rows):
        return unknown('duplicate image digest identity')
    if any(digest not in uri for digest, uri in image_digests.items()):
        return unknown('image URI does not bind its digest')
    if not deployed_digests <= set(image_digests):
        return unknown('deployment-to-image digest join incomplete')
    sbom_uris = {get(row, 'resourceUri', str) for row in occurrences
                 if get(row, 'kind', str) == 'SBOM_REFERENCE' and get(row, 'noteName', str)}
    missing = sorted(digest for digest in deployed_digests if image_digests[digest] not in sbom_uris)
    return result(bool(missing), repository=repo, missing_sbom_digests=missing)


@register('gcp_c5_log_event_fields', ['log_entry'])
def c5_log_event_fields(item, index):
    _member(item, index, 'log_entry')
    if get(item, 'eventClass', str) != 'authenticated_audit':
        return unknown('exempt or system event cannot be classified by this predicate')
    timestamp = _full_omitted(item, 'timestamp', '')
    if not isinstance(timestamp, str):
        return unknown('malformed audit timestamp')
    try:
        parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        valid_time = parsed.tzinfo is not None
    except ValueError:
        valid_time = False
    method = get(item, 'protoPayload.methodName', str)
    payload = get(item, 'protoPayload', dict)
    auth = _full_omitted(payload, 'authenticationInfo', {}, full=item.get('_representation') == 'full')
    if not isinstance(auth, dict):
        return unknown('malformed authentication info')
    principal = _full_omitted(auth, 'principalEmail', '', full=item.get('_representation') == 'full')
    if not isinstance(principal, str):
        return unknown('malformed audit principal')
    if not method:
        return unknown('authenticated audit action method unavailable')
    return result(not valid_time or not principal.strip(), timestamp=timestamp, method=method, principal=principal)


@register('gcp_c5_security_event_route', ['monitoring_alert_policy', 'logging_metric', 'monitoring_notification_channel'], target='scope')
def c5_security_event_route(item, index):
    if get(item, 'scope', str) != _scope(index):
        return unknown('scope subject does not match snapshot')
    required = _policy(index, 'approved_security_event_metrics')
    metrics = _rows(index, 'logging_metric')
    policies = _rows(index, 'monitoring_alert_policy')
    channels = _rows(index, 'monitoring_notification_channel')
    metric_names = {get(metric, 'name', str) for metric in metrics}
    if len(metric_names) != len(metrics):
        return unknown('duplicate Logging metric name')
    if not required:
        return unknown('approved event catalogue is empty')
    channel_map = {get(channel, 'name', str): get(channel, 'enabled', bool) for channel in channels}
    if len(channel_map) != len(channels):
        return unknown('duplicate notification channel name')
    missing = []
    for metric in required:
        if metric not in metric_names:
            missing.append(metric)
            continue
        matched = []
        for policy in policies:
            if not get(policy, 'enabled', bool):
                continue
            for condition in _list(policy, 'conditions'):
                filt = get(condition, 'conditionThreshold.filter', str)
                if re.search(r'user/' + re.escape(metric.rsplit('/', 1)[-1]) + r'(?=[\s"\']|$)', filt):
                    matched.append(policy)
                    break
        if not any(any(channel_map.get(name) is True for name in get(policy, 'notificationChannels', list)) for policy in matched):
            missing.append(metric)
    return result(bool(missing), unrouted_metrics=missing)


def _server_rewrite(action):
    return any(get(row, 'headerName', str).lower() == 'server' and get(row, 'headerValue', str) == 'lb'
               and get(row, 'replace', bool) for row in _optional_objects(action, 'responseHeadersToAdd'))


def _optional_object(row, field):
    guard(row)
    if field not in row:
        if field in row.get('_coverage', {}):
            raise Unavailable('optional route field unreadable: ' + field)
        return {}
    return get(row, field, dict)


def _optional_objects(row, field):
    guard(row)
    if field not in row:
        if field in row.get('_coverage', {}):
            raise Unavailable('optional route list unreadable: ' + field)
        return []
    return _list(row, field)


@register('gcp_lb_server_header_rewrite', ['url_map'])
def lb_server_header_rewrite(item, index):
    _member(item, index, 'url_map')
    if not get(item, 'internetFacing', bool):
        return 'NOT_APPLICABLE', {'reason': 'URL map is not public'}
    if get(item, 'routeCoverageComplete', bool) is not True:
        return unknown('URL map route coverage incomplete')
    routes = _list(item, 'effectiveRoutes')
    if not routes:
        return unknown('complete public URL map has no route projection')
    ids = [get(route, 'routeId', str) for route in routes]
    if len(ids) != len(set(ids)):
        return unknown('duplicate effective URL map route')
    missing = [route_id for route_id, action in zip(ids, routes) if not _server_rewrite(action)]
    return result(bool(missing), url_map=_identity(item), unrewritten_route_indexes=missing)


def _redirect(route):
    guard(route)
    if 'httpsRedirect' not in route:
        if 'httpsRedirect' in route.get('_coverage', {}):
            raise Unavailable('redirect field unreadable')
        return False
    return get(route, 'httpsRedirect', bool)


@register('gcp_pci_url_map_9ed56c323a05', ['url_map', 'target_proxy', 'forwarding_rule'])
def pci_url_map_redirect(item, index):
    _member(item, index, 'url_map')
    url = get(item, 'selfLink', str)
    proxies = _rows(index, 'target_proxy')
    frontends = _rows(index, 'forwarding_rule')
    proxy_urls = {get(proxy, 'selfLink', str) for proxy in proxies}
    if len(proxy_urls) != len(proxies):
        return unknown('duplicate target proxy identity')
    if any(('targetHttpProxies/' in get(frontend, 'target', str) or get(frontend, 'target', str).startswith('http-proxy:'))
           and get(frontend, 'target', str) not in proxy_urls for frontend in frontends):
        return unknown('HTTP frontend target proxy unresolved')
    http_proxies = [proxy for proxy in proxies if get(proxy, 'proxyType', str) == 'HTTP' and get(proxy, 'urlMap', str) == url]
    attached = [frontend for frontend in frontends if any(get(frontend, 'target', str) == get(proxy, 'selfLink', str) for proxy in http_proxies)]
    if not attached:
        return 'NOT_APPLICABLE', {'reason': 'no HTTP frontend targets this URL map'}
    if get(item, 'routeCoverageComplete', bool) is not True:
        return unknown('URL map path/default route coverage incomplete')
    routes = [_optional_object(item, 'defaultUrlRedirect')]
    for matcher in _optional_objects(item, 'pathMatchers'):
        routes.append(_optional_object(matcher, 'defaultUrlRedirect'))
        for rule in _optional_objects(matcher, 'pathRules'):
            routes.append(_optional_object(rule, 'urlRedirect'))
        for rule in _optional_objects(matcher, 'routeRules'):
            routes.append(_optional_object(rule, 'urlRedirect'))
    unredirected = [i for i, route in enumerate(routes) if not _redirect(route)]
    return result(bool(unredirected), url_map=url, unredirected_routes=unredirected)
