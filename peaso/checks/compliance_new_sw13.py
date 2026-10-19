"""Signed Azure compliance predicates, second-wave sw13.

All reads are offline. External review, runtime, TLS and restore observations
are explicit scope-bound snapshot evidence, never inferred from ARM metadata.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from itertools import product
import ipaddress
import math
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, omitted, list_of_objects

SPECS = {'azure.cis.exclusionary_device_code_flow_policy_considered': {'category': 'hardening',
                                                               'proposed_spec_sha256': '91e03ff3270962b481569dc1a8977f98c6cf4dddba66c2a8c0538217aa2b2fd1',
                                                               'provider': 'azure',
                                                               'remediation_hint': 'Review the '
                                                                                   'device-code-flow risk '
                                                                                   'and permitted '
                                                                                   'exceptions, record the '
                                                                                   'decision, then configure '
                                                                                   'and validate an enabled '
                                                                                   'Conditional Access block '
                                                                                   'policy for unapproved '
                                                                                   'users/apps.',
                                                               'resource_kind': 'conditional_access_policy',
                                                               'severity': 'medium',
                                                               'title': 'Ensure that an exclusionary Device '
                                                                        'code flow policy is considered'},
 'azure.cis.exclusionary_geographic_access_policy_considered': {'category': 'identity',
                                                                'proposed_spec_sha256': '3d2d125ff1c9b7c1c1470a7b96a7db4855f4e6e2ab225a5e3a930a9ab6107eed',
                                                                'provider': 'azure',
                                                                'remediation_hint': 'In Entra admin center > '
                                                                                    'Protection > '
                                                                                    'Conditional Access, '
                                                                                    'create an enabled Block '
                                                                                    'access policy for all '
                                                                                    'users and all cloud '
                                                                                    'apps, including the '
                                                                                    'named locations for '
                                                                                    'prohibited countries; '
                                                                                    'remove unintended '
                                                                                    'exclusions after '
                                                                                    'emergency-account '
                                                                                    'review.',
                                                                'resource_kind': 'conditional_access_policy',
                                                                'severity': 'medium',
                                                                'title': 'Block sign-ins from prohibited '
                                                                         'geographic locations'},
 'azure.cis.multifactor_authentication_policy_exists_administrative_groups': {'category': 'identity',
                                                                              'proposed_spec_sha256': '09a9e57424d4ef7b9661f849edaaf6ae9a6022c8c067ce13b8588fe5f89d2223',
                                                                              'provider': 'azure',
                                                                              'remediation_hint': 'In Entra '
                                                                                                  'admin '
                                                                                                  'center > '
                                                                                                  'Protection '
                                                                                                  '> '
                                                                                                  'Conditional '
                                                                                                  'Access, '
                                                                                                  'create '
                                                                                                  'enabled '
                                                                                                  'MFA or '
                                                                                                  'MFA-strength '
                                                                                                  'policies '
                                                                                                  'for every '
                                                                                                  'privileged '
                                                                                                  'role; '
                                                                                                  'cover all '
                                                                                                  'required '
                                                                                                  'apps and '
                                                                                                  'client '
                                                                                                  'types, '
                                                                                                  'remove '
                                                                                                  'bypass '
                                                                                                  'exclusions, '
                                                                                                  'and '
                                                                                                  'verify '
                                                                                                  'effective '
                                                                                                  'coverage '
                                                                                                  'with What '
                                                                                                  'If.',
                                                                              'resource_kind': 'conditional_access_policy',
                                                                              'severity': 'high',
                                                                              'title': 'Ensure that A '
                                                                                       'Multi-factor '
                                                                                       'Authentication '
                                                                                       'Policy Exists for '
                                                                                       'Administrative '
                                                                                       'Groups'},
 'azure.cis.multifactor_authentication_policy_exists_users': {'category': 'identity',
                                                              'proposed_spec_sha256': '59d8b7a3114c873fe6099522331ab97c88b3d8594413cdb85453713a565c282e',
                                                              'provider': 'azure',
                                                              'remediation_hint': 'Azure portal > Entra ID > '
                                                                                  'Protection > Conditional '
                                                                                  'Access: create or amend '
                                                                                  'enabled MFA policies '
                                                                                  'covering the uncovered '
                                                                                  'users, apps and client '
                                                                                  'types; inspect all '
                                                                                  'exclusions and What If '
                                                                                  'results.',
                                                              'resource_kind': 'conditional_access_policy',
                                                              'severity': 'high',
                                                              'title': 'Enabled Entra users are covered by '
                                                                       'MFA policy'},
 'azure.cis.multifactor_authentication_risky_sign_ins': {'category': 'identity',
                                                         'proposed_spec_sha256': 'd6fa976f6eeebab32c6e836462738a6b09ef3509efde547b1764302170789d5f',
                                                         'provider': 'azure',
                                                         'remediation_hint': 'Entra admin center > '
                                                                             'Protection > Conditional '
                                                                             'Access: create or update '
                                                                             'risk-based policies covering '
                                                                             'medium and high sign-in risk '
                                                                             'for all scoped users and apps '
                                                                             'with Require multifactor '
                                                                             'authentication; review every '
                                                                             'exclusion and condition.',
                                                         'resource_kind': 'conditional_access_policy',
                                                         'severity': 'high',
                                                         'title': 'Require MFA for medium and high risk '
                                                                  'sign-ins'},
 'azure.gap.appservice_web_app_use_virtual_service_endpoint': {'category': 'network',
                                                               'proposed_spec_sha256': 'bc222da83ef8002acf9840a965ee791adce150474f6766bf9ff76ee55ffe1d85',
                                                               'provider': 'azure',
                                                               'remediation_hint': 'Enable Microsoft.Web '
                                                                                   'service endpoint on an '
                                                                                   'approved subnet; App '
                                                                                   'Service > Networking > '
                                                                                   'Access restrictions: add '
                                                                                   'an Allow rule for that '
                                                                                   'subnet with effective '
                                                                                   'priority and block '
                                                                                   'unapproved access.',
                                                               'resource_kind': 'app_service',
                                                               'severity': 'medium',
                                                               'title': 'Web app allows inbound traffic from '
                                                                        'an approved service endpoint '
                                                                        'subnet'},
 'azure.gap.recovery_service_vault_encrypted_with_cmk': {'category': 'encryption',
                                                         'proposed_spec_sha256': '0ecf726707784b7235da3e0637ae3276c6f0e23ba1ca140f8a92f947fa96f799',
                                                         'provider': 'azure',
                                                         'remediation_hint': 'Azure portal > Recovery '
                                                                             'Services vault > Properties > '
                                                                             'Encryption Settings: assign a '
                                                                             'managed identity, grant it Key '
                                                                             'Vault key permissions, and '
                                                                             'select a customer-managed key.',
                                                         'resource_kind': 'recovery_vault',
                                                         'severity': 'high',
                                                         'title': 'Encrypt Recovery Services backup data '
                                                                  'with a customer key'},
 'azure.other.backup_immutability_30': {'category': 'recovery',
                                        'proposed_spec_sha256': '4b82b0fe2220652cb7e2428ecf41256a2cef4e6b106e2026f4e95132dc2dab9f',
                                        'provider': 'azure',
                                        'remediation_hint': 'Recovery Services vault > Properties > Security '
                                                            'Settings: enable and lock immutable vault; edit '
                                                            'each assigned backup policy to retain daily '
                                                            'recovery points at least 30 days.',
                                        'resource_kind': 'recovery_vault',
                                        'severity': 'high',
                                        'title': 'Protected vault backups are immutable and retained at '
                                                 'least 30 days'},
 'azure.other.backup_restore_evidence': {'category': 'recovery',
                                         'proposed_spec_sha256': '71b86444c5adea24436991134075ccb4bd8e84320e458132f604a92de7ab578e',
                                         'provider': 'azure',
                                         'remediation_hint': 'Azure portal > Backup center > Backup jobs: '
                                                             'Run and document a restore test for each '
                                                             'critical workload within the approved '
                                                             'interval.',
                                         'resource_kind': 'recovery_vault',
                                         'severity': 'high',
                                         'title': 'Test restoration of critical protected workloads'},
 'azure.other.endpoint_certificate_trust': {'category': 'encryption',
                                            'proposed_spec_sha256': 'd7295bd47f3d8b867d2fec1909887cdd849f67ec2592109059dcb81cad500f61',
                                            'provider': 'azure',
                                            'remediation_hint': 'Renew or replace invalid certificates and '
                                                                'bind them to every exposed TLS endpoint; '
                                                                'validate live hostname, expiry and full '
                                                                'trust chain.',
                                            'resource_kind': 'app_service',
                                            'severity': 'high',
                                            'title': 'Use valid approved TLS certificates on exposed '
                                                     'endpoints'},
 'azure.other.security_event_correlation': {'category': 'monitoring',
                                            'proposed_spec_sha256': '773f7b9e70dde647d9eabba21117b1bf44cd07fb963eec142c17f0f4d6c16b39',
                                            'provider': 'azure',
                                            'remediation_hint': 'Azure Monitor > Alerts: deploy the approved '
                                                                'multi-table scheduled query with bounded '
                                                                'window and enabled action group at each '
                                                                'required workspace scope.',
                                            'resource_kind': 'scheduled_query_rule',
                                            'severity': 'medium',
                                            'title': 'Correlate configured security event sources'},
 'azure_app_service_app_function_latest_runtime_version_f50215a': {'category': 'hardening',
                                                                   'proposed_spec_sha256': '19f5adf59781a6dbe99c66ed090dfa265d1ddf6b5adb0b297c5df9ad24a9483c',
                                                                   'provider': 'azure',
                                                                   'remediation_hint': 'Set the approved '
                                                                                       'Function App '
                                                                                       'runtime, role, '
                                                                                       'timeout and memory '
                                                                                       'values for its '
                                                                                       'hosting model; '
                                                                                       'verify deployed '
                                                                                       'configuration '
                                                                                       'against '
                                                                                       'expectedFunctionSettings.',
                                                                   'resource_kind': 'app_service',
                                                                   'severity': 'medium',
                                                                   'title': 'Function App runtime and scale '
                                                                            'settings match approved values'},
 'azure_c5_iam_03_01ac': {'category': 'hardening',
                          'proposed_spec_sha256': 'a57826856b179400eb41877be2f58aa011ff8367ba508bc136f4011048fe9190',
                          'provider': 'azure',
                          'remediation_hint': 'Configure Identity Protection risk detection or equivalent '
                                              'sign-in monitoring, route alerts to authorized responders, '
                                              'and verify timely delivery using incident records.',
                          'resource_kind': 'conditional_access_policy',
                          'severity': 'medium',
                          'title': 'Notify authorized personnel of suspicious authentication events'},
 'azure_recovery_vault_10_3_3_2_5313a3c': {'category': 'recovery',
                                           'proposed_spec_sha256': '04a3462eb5cde387b9c6a024ed28470f40df7216f64772c23e32acdf79b67404',
                                           'provider': 'azure',
                                           'remediation_hint': 'In Recovery Services vault > Backup '
                                                               'policies, edit each workload policy schedule '
                                                               'and retention tiers to meet the approved '
                                                               'minimum frequency and days.',
                                           'resource_kind': 'recovery_vault',
                                           'severity': 'medium',
                                           'title': 'an Azure Backup policy has a backup rule that satisfies '
                                                    'the required frequency and retention period'},
 'azure_recovery_vault_10_3_3_3_45b190e': {'category': 'recovery',
                                           'proposed_spec_sha256': 'b84f4015f949d8f12a573e29c8e105d88a7400c83b0146727737bfd4315b7e3c',
                                           'provider': 'azure',
                                           'remediation_hint': 'Azure portal > Recovery Services vault > '
                                                               'Backup policies: increase workload-specific '
                                                               'retention to at least minRetentionDays, then '
                                                               'verify recovery-point expiry after a backup.',
                                           'resource_kind': 'recovery_vault',
                                           'severity': 'medium',
                                           'title': 'Azure Backup recovery points meet minimum retention'}}

IDS = tuple(SPECS)
EVALUATORS = {}
_ACCEPTED_CATEGORIES = {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'}


def signed(cid, *dependencies, target='resource'):
    """Preserve the signed category with the legacy registry validator."""
    meta = SPECS[cid]
    def decorate(fn):
        register(cid, meta['provider'], meta['category'] if meta['category'] in _ACCEPTED_CATEGORIES else 'hardening',
                 meta['resource_kind'], meta['title'], meta['severity'], 'CM-6', meta['remediation_hint'],
                 dependencies=[meta['resource_kind'], *dependencies], target=target)(fn)
        position = next(i for i, check in enumerate(CHECKS) if check.id == cid)
        CHECKS[position] = replace(CHECKS[position], category=meta['category'])
        EVALUATORS[cid] = CHECKS[position].evaluate
        return fn
    return decorate


def text(value):
    if not isinstance(value, str) or not value.strip():
        raise Unavailable('empty or malformed string')
    return value


def strings(value, *, nonempty=False):
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value) or len(set(value)) != len(value):
        raise Unavailable('malformed or duplicate string list')
    if nonempty and not value:
        raise Unavailable('empty required scope')
    return value


def instant(value):
    try:
        stamp = datetime.fromisoformat(text(value).replace('Z', '+00:00'))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError('timezone missing')
        return stamp
    except ValueError as exc:
        raise Unavailable('invalid observation timestamp') from exc


def number(value, *, positive=True):
    if type(value) is not int or (value <= 0 if positive else value < 0):
        raise Unavailable('invalid integer bound')
    return value


def scope(index):
    context = get(index, 'context', dict)
    if get(context, 'provider', str) != 'azure':
        raise Unavailable('foreign provider')
    return text(get(context, 'scope', str))


def now(index):
    return instant(get(index, 'context.created_at', str))


def bound(rid, index):
    """ARM identity belongs to the evaluated subscription/resource scope."""
    rid, owner = text(rid), scope(index)
    if not rid.startswith('/subscriptions/') or not (rid.casefold() == owner.casefold() or rid.casefold().startswith(owner.rstrip('/').casefold() + '/')):
        raise Unavailable('malformed or foreign ARM identity')
    if not re.fullmatch(r'/subscriptions/[^/]+/(?:[^/]+/)*[^/]+', rid):
        raise Unavailable('malformed ARM identity')
    return rid.casefold()


def inventory(index, kind, *, parent=None, graph=False):
    rows = complete_items(index, kind)
    owner = scope(index)
    envelopes = get(index, 'collections', dict)[kind]
    for env in envelopes:
        es = text(get(env, 'scope', str))
        if not (es.casefold() == owner.casefold() or es.casefold().startswith(owner.rstrip('/').casefold() + '/')):
            raise Unavailable('foreign collection scope: ' + kind)
        if get(env, 'type', str) != kind:
            raise Unavailable('foreign collection kind')
    resources = get(index, kind, list)
    if len(resources) != len(rows):
        raise Unavailable('resource projection inconsistent')
    native_types = {'app_service': 'Microsoft.Web/sites', 'recovery_vault': 'Microsoft.RecoveryServices/vaults',
                    'scheduled_query_rule': 'Microsoft.Insights/scheduledQueryRules',
                    'action_group': 'Microsoft.Insights/actionGroups',
                    'subnet': 'Microsoft.Network/virtualNetworks/[^/]+/subnets'}
    ids = set()
    for wrapped, row in zip(resources, rows):
        rs = text(get(wrapped, 'scope', str))
        if not (rs.casefold() == owner.casefold() or rs.casefold().startswith(owner.rstrip('/').casefold() + '/')):
            raise Unavailable('foreign resource envelope')
        rid = text(get(row, 'id', str))
        if graph:
            if not owner.startswith('/tenants/'):
                raise Unavailable('tenant scope unresolved')
            tenant = get(row, '_provenance.tenant_id', str)
            if tenant.casefold() != owner.removeprefix('/tenants/').casefold():
                raise Unavailable('foreign Graph tenant')
        else:
            bound(rid, index)
            if kind in native_types and not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/' + native_types[kind] + r'/[^/]+', rid, re.I):
                raise Unavailable('foreign native resource kind')
        if rid.casefold() in ids:
            raise Unavailable('duplicate resource identity: ' + kind)
        ids.add(rid.casefold())
        if not graph and 'parent_id' in row:
            declared_parent = text(get(row, 'parent_id', str))
            bound(declared_parent, index)
            if not rid.casefold().startswith(declared_parent.rstrip('/').casefold() + '/'):
                raise Unavailable('resource identity conflicts with declared parent')
        if parent is not None and not rid.casefold().startswith(parent.rstrip('/').casefold() + '/'):
            # Cross-vault rows are valid in subscription-wide collections; filter below.
            continue
    # Require projection to agree with complete envelope payloads when supplied.
    if all('items' in env for env in envelopes):
        expected = [r for env in envelopes for r in list_of_objects(get(env, 'items', list))]
        if sorted(repr(r) for r in expected) != sorted(repr(r) for r in rows):
            raise Unavailable('collection payload differs from resource projection')
    if parent is not None:
        return [r for r in rows if r['id'].casefold().startswith(parent.rstrip('/').casefold() + '/')]
    return rows


def target(item, index, kind, *, graph=False):
    rid = text(get(item, 'id', str))
    rows = inventory(index, kind, graph=graph)
    matches = [row for row in rows if row['id'].casefold() == rid.casefold()]
    if len(matches) != 1 or matches[0] != item:
        raise Unavailable('target not in complete inventory')
    return rid


def policy(index, cid):
    """Dated authorized policy, bound to the exact evaluated scope and check."""
    root = get(index, 'context.metadata.compliance_policy.sw13', dict)
    if get(root, 'status', str) != 'collected' or get(root, 'scope', str).casefold() != scope(index).casefold():
        raise Unavailable('policy missing or foreign scope')
    text(get(root, 'authorized_by', str))
    text(get(root, 'document_id', str))
    if not instant(get(root, 'observed_at', str)) <= now(index) <= instant(get(root, 'expires_at', str)):
        raise Unavailable('policy stale or future')
    return get(root, 'checks.' + cid.replace('.', '|'), dict)


def observations(index, kind, *, parent=None, graph=False):
    rows = inventory(index, kind, parent=parent, graph=graph)
    for row in rows:
        if get(row, 'scope', str).casefold() != scope(index).casefold():
            raise Unavailable('foreign observation scope')
        if get(row, '_provenance.read_only', bool) is not True:
            raise Unavailable('observation provenance unresolved')
        provenance = get(row, '_provenance', dict)
        metadata = get(index, 'context.metadata', dict)
        for field in ('credential_context_id', 'customer_context_id', 'tenant_id'):
            if field not in provenance:
                continue
            observed = text(get(provenance, field, str))
            if field == 'tenant_id' and graph:
                authoritative = scope(index).removeprefix('/tenants/')
            else:
                authoritative = text(get(metadata, field, str))
            if (observed.casefold() if field == 'tenant_id' else observed) != (authoritative.casefold() if field == 'tenant_id' else authoritative):
                raise Unavailable('observation capture binding differs: ' + field)
    return rows


def keyed(row, key, expected=None):
    get({'mapping': row}, 'mapping', dict)
    if key not in row:
        raise Unavailable('missing mapping key: ' + key)
    selected = {'value': row[key]}
    if key in row.get('_coverage', {}):
        selected['_coverage'] = {'value': row['_coverage'][key]}
    return get(selected, 'value', expected)


def one(rows, field, value):
    matches = [r for r in rows if get(r, field, str).casefold() == value.casefold()]
    if len(matches) != 1:
        raise Unavailable('missing or ambiguous joined fact: ' + field)
    return matches[0]


def current(row, index):
    text(get(row, 'document_id', str))
    text(get(row, 'authorized_by', str))
    start, end = instant(get(row, 'observed_at', str)), instant(get(row, 'expires_at', str))
    if end < start:
        raise Unavailable('malformed validity interval')
    if start > now(index):
        raise Unavailable('future-dated evidence')
    return now(index) <= end


# Conditional Access: enumerate an approved exhaustive partition, then evaluate
# every raw policy against each concrete user/app/client/context combination.
# Unsupported conditions cannot become a negative match (a false gap).
ADMIN = 'azure.cis.multifactor_authentication_policy_exists_administrative_groups'
USERS = 'azure.cis.multifactor_authentication_policy_exists_users'
RISK = 'azure.cis.multifactor_authentication_risky_sign_ins'
DEVICE = 'azure.cis.exclusionary_device_code_flow_policy_considered'
GEO = 'azure.cis.exclusionary_geographic_access_policy_considered'
CA_DEPS = ('directory_user', 'conditional_access_principal', 'conditional_access_partition',
           'named_location', 'authentication_strength', 'directory_security_defaults')


def ca_inputs(item, index, cid):
    target(item, index, 'conditional_access_policy', graph=True)
    rules = inventory(index, 'conditional_access_policy', graph=True)
    users = inventory(index, 'directory_user', graph=True)
    principals = observations(index, 'conditional_access_principal', graph=True)
    p = policy(index, cid)
    mode = get(p, 'userScope', str)
    if mode not in ('all', 'designated', 'administrative'):
        raise Unavailable('user designation unresolved')
    if cid == ADMIN and mode != 'administrative':
        raise Unavailable('administrative scope required')
    if mode == 'all':
        selected = [u['id'] for u in users if get(u, 'accountEnabled', bool)]
    elif mode == 'designated':
        selected = strings(get(p, 'designatedUsers', list))
    else:
        groups = strings(get(p, 'designatedGroups', list))
        roles = strings(get(p, 'designatedRoles', list))
        if not groups and not roles:
            # An explicitly empty, approved designated scope is valid.
            selected = []
        else:
            selected = []
            for user in users:
                profile = one(principals, 'userId', user['id'])
                if not current(profile, index) or get(profile, 'membershipComplete', bool) is not True or get(profile, 'pimResolved', bool) is not True:
                    raise Unavailable('administrative membership incomplete')
                gs = strings(get(profile, 'groupIds', list))
                rs = strings(get(profile, 'roleTemplateIds', list))
                if set(gs) & set(groups) or set(rs) & set(roles):
                    selected.append(user['id'])
    profiles = []
    for uid in selected:
        user = one(users, 'id', uid)
        if not get(user, 'accountEnabled', bool):
            continue
        profile = one(principals, 'userId', uid)
        strings(get(profile, 'groupIds', list))
        strings(get(profile, 'roleTemplateIds', list))
        if get(profile, 'membershipComplete', bool) is not True or get(profile, 'pimResolved', bool) is not True:
            raise Unavailable('group/PIM membership unresolved')
        if not current(profile, index):
            raise Unavailable('principal resolution stale')
        profiles.append(profile)
    partition = one(observations(index, 'conditional_access_partition', graph=True), 'checkId', cid)
    if not current(partition, index) or get(partition, 'exhaustive', bool) is not True:
        raise Unavailable('context partition incomplete')
    if set(strings(get(partition, 'userIds', list))) != {r['userId'] for r in profiles}:
        raise Unavailable('context partition user scope mismatch')
    domains = get(partition, 'domains', dict)
    axes = ('application', 'clientAppType', 'location', 'platform', 'device', 'signInRisk', 'userRisk', 'authenticationFlow')
    values = []
    for axis in axes:
        text(get(partition, 'partitionProof.' + axis, str))
        entries = list_of_objects(get(domains, axis, list))
        if not entries:
            raise Unavailable('empty context domain')
        names = [text(get(e, 'value', str)) for e in entries]
        if len(names) != len(set(names)):
            raise Unavailable('duplicate context partition')
        allowed = {'clientAppType': {'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'},
                   'platform': {'android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'unknown'},
                   'signInRisk': {'none', 'low', 'medium', 'high'}, 'userRisk': {'none', 'low', 'medium', 'high'},
                   'authenticationFlow': {'ordinary', 'deviceCodeFlow', 'authenticationTransfer'}}
        if axis in allowed and set(names) - allowed[axis]:
            raise Unavailable('unsupported context partition value')
        values.append(entries)
    required_apps = strings(get(p, 'requiredApplications', list), nonempty=True)
    required_clients = strings(get(p, 'requiredClientAppTypes', list), nonempty=True)
    if set(required_apps) != {e['value'] for e in values[0]} or set(required_clients) != {e['value'] for e in values[1]}:
        raise Unavailable('app/client partition does not cover required scope')
    if cid == RISK:
        if get(p, 'riskLicensingConfirmed', bool) is not True or {e['value'] for e in values[5]} != {'medium', 'high'}:
            raise Unavailable('risk scope or licensing unresolved')
    contexts = [dict(zip(axes, combo)) for combo in product(*values)]
    locations = inventory(index, 'named_location', graph=True)
    strengths = inventory(index, 'authentication_strength', graph=True)
    defaults = inventory(index, 'directory_security_defaults', graph=True)
    if len(defaults) != 1:
        raise Unavailable('security defaults state unresolved')
    default_enabled = get(defaults[0], 'isEnabled', bool)
    return p, rules, profiles, contexts, locations, strengths, default_enabled


def ca_match(rule, principal, context, locations):
    state = get(rule, 'state', str)
    if state not in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'):
        raise Unavailable('unrecognized Conditional Access policy state')
    if state == 'disabled':
        return False
    if state == 'enabledForReportingButNotEnforced':
        raise Unavailable('report-only Conditional Access policy')
    c = get(rule, 'conditions', dict)
    def documented_empty(value, field):
        marker = value.get('_coverage', {}).get(field)
        return (isinstance(marker, dict) and marker.get('status') == 'empty'
                and marker.get('reason') == 'documented_optional_api_omission')
    def validate_selectors(value):
        # Coverage-only restrictions are not an absence claim. Only an explicit
        # documented empty omission can supply an empty optional selector.
        for field in set(value) | set(value.get('_coverage', {})):
            if not isinstance(field, str):
                raise Unavailable('malformed Conditional Access selector field')
            if field.startswith('_'):
                continue
            if field in value:
                keyed(value, field)
            elif not documented_empty(value, field):
                raise Unavailable('Conditional Access selector coverage unresolved')
    def selected(value, field, expected, empty):
        if field not in value and documented_empty(value, field):
            return empty
        return get(value, field, expected)
    validate_selectors(c)
    supported = {'users', 'applications', 'clientAppTypes', 'locations', 'platforms', 'devices',
                 'signInRiskLevels', 'userRiskLevels', 'authenticationFlows'}
    if any(k not in supported and not k.startswith('_') and v not in (None, [], {}) for k, v in c.items()):
        raise Unavailable('unmodeled Conditional Access condition')
    users = get(c, 'users', dict)
    validate_selectors(users)
    def selector(field):
        return strings(selected(users, field, list, []))
    uid = get(principal, 'userId', str)
    groups = set(strings(get(principal, 'groupIds', list)))
    roles = set(strings(get(principal, 'roleTemplateIds', list)))
    include, exclude = False, False
    for field, identity in (('Users', {uid}), ('Groups', groups), ('Roles', roles)):
        inc = selector('include' + field)
        exc = selector('exclude' + field)
        if field == 'Users' and any(v in ('GuestsOrExternalUsers',) for v in inc + exc):
            raise Unavailable('guest condition unresolved')
        include |= 'All' in inc or bool(set(inc) & identity)
        exclude |= 'All' in exc or bool(set(exc) & identity)
    if any(k not in {prefix + field for prefix in ('include', 'exclude') for field in ('Users', 'Groups', 'Roles')} and v not in (None, [], {}) and not k.startswith('_') for k, v in users.items()):
        raise Unavailable('unmodeled user condition')
    checks = [include and not exclude]
    apps = get(c, 'applications', dict)
    validate_selectors(apps)
    if any(k not in {'includeApplications', 'excludeApplications'} and v not in (None, [], {}) and not k.startswith('_') for k, v in apps.items()):
        raise Unavailable('unmodeled application condition')
    inc = strings(get(apps, 'includeApplications', list))
    exc = strings(selected(apps, 'excludeApplications', list, []))
    if any(v in {'Office365', 'MicrosoftAdminPortals'} for v in inc + exc):
        raise Unavailable('unexpanded application bundle')
    app = context['application']['value']
    checks.append(('All' in inc or app in inc) and not ('All' in exc or app in exc))
    clients = strings(get(c, 'clientAppTypes', list), nonempty=True)
    checks.append('all' in clients or context['clientAppType']['value'] in clients)
    loc = selected(c, 'locations', None, None)
    if loc is not None:
        if not isinstance(loc, dict):
            raise Unavailable('malformed location condition')
        def location_match(ids):
            hits = []
            for lid in ids:
                if lid == 'All':
                    hits.append(True)
                elif lid == 'AllTrusted':
                    hits.append(get(context['location'], 'isTrusted', bool))
                else:
                    named = one(locations, 'id', lid)
                    if keyed(named, '@odata.type', str) != '#microsoft.graph.countryNamedLocation':
                        raise Unavailable('IP/GPS location semantics unresolved')
                    if get(named, 'countryLookupMethod', str) != 'clientIpAddress':
                        raise Unavailable('country lookup semantics unresolved')
                    countries = strings(get(named, 'countriesAndRegions', list))
                    country = get(context['location'], 'country', str)
                    hits.append(country in countries or (country == 'unknown' and get(named, 'includeUnknownCountriesAndRegions', bool)))
            return any(hits)
        checks.append(location_match(strings(get(loc, 'includeLocations', list))) and not location_match(strings(get(loc, 'excludeLocations', list))))
    platform = selected(c, 'platforms', None, None)
    if platform is not None:
        inc = strings(get(platform, 'includePlatforms', list))
        exc = strings(get(platform, 'excludePlatforms', list))
        value = context['platform']['value']
        checks.append(('all' in inc or value in inc) and not ('all' in exc or value in exc))
    if selected(c, 'devices', None, None) is not None:
        raise Unavailable('device filters unsupported; needs a resolved partition evaluator')
    for field, axis in (('signInRiskLevels', 'signInRisk'), ('userRiskLevels', 'userRisk')):
        risks = strings(selected(c, field, list, []))
        checks.append(not risks or context[axis]['value'] in risks)
    flows = selected(c, 'authenticationFlows', None, None)
    if flows is not None:
        flow = get(flows, 'transferMethods', str)
        if flow not in ('deviceCodeFlow', 'authenticationTransfer'):
            raise Unavailable('unknown authentication flow condition')
        checks.append(context['authenticationFlow']['value'] == flow)
    return all(checks)


def grant(rule, strengths, context):
    g = get(rule, 'grantControls', dict)
    controls = strings(get(g, 'builtInControls', list))
    operator = get(g, 'operator', str)
    if operator not in ('AND', 'OR'):
        raise Unavailable('grant operator unresolved')
    known = {'block', 'mfa', 'compliantDevice', 'domainJoinedDevice', 'approvedApplication',
             'compliantApplication', 'passwordChange'}
    if set(controls) - known:
        raise Unavailable('unsupported grant alternative')
    if strings(get(g, 'customAuthenticationFactors', list)) or strings(get(g, 'termsOfUse', list)):
        raise Unavailable('custom or terms-of-use grant unresolved')
    strength = get(g, 'authenticationStrength')
    mfa = ['mfa' == c for c in controls]
    if strength is not None:
        sid = text(get(strength, 'id', str))
        detail = one(strengths, 'id', sid)
        combos = strings(get(detail, 'allowedCombinations', list), nonempty=True)
        # Supported combinations from Graph authenticationStrengthPolicy.
        multifactor = {'password,microsoftAuthenticatorPush', 'password,softwareOath', 'password,hardwareOath',
                      'password,sms', 'password,voice', 'fido2', 'windowsHelloForBusiness',
                      'x509CertificateMultiFactor', 'deviceBasedPush'}
        single = {'password', 'sms', 'voice', 'x509CertificateSingleFactor', 'email'}
        if set(combos) - multifactor - single:
            raise Unavailable('authentication strength method semantics unresolved')
        requires = get(detail, 'requirementsSatisfied', str)
        if requires not in ('mfa', 'none') or (requires == 'mfa') != all(c in multifactor for c in combos):
            raise Unavailable('authentication-strength MFA claim semantics conflict')
        mfa.append(requires == 'mfa')
    if not mfa:
        raise Unavailable('empty grant controls')
    if 'block' in controls:
        if controls != ['block'] or strength is not None:
            raise Unavailable('conflicting block/grant controls')
        return True, False, False
    allowed = []
    for control in controls:
        if control == 'mfa':
            allowed.append(False)
        elif control == 'compliantDevice':
            allowed.append(get(context['device'], 'isCompliant', bool))
        elif control == 'domainJoinedDevice':
            allowed.append(get(context['device'], 'isHybridJoined', bool))
        elif control == 'approvedApplication':
            allowed.append(get(context['application'], 'isApproved', bool))
        elif control == 'compliantApplication':
            allowed.append(get(context['application'], 'isCompliant', bool))
        else:
            raise Unavailable('password-change grant reachability unresolved')
    if strength is not None:
        allowed.append(not mfa[-1])
    return False, (any(mfa) if operator == 'AND' else all(mfa)), (all(allowed) if operator == 'AND' else any(allowed))


def ca_coverage(rules, profiles, contexts, locations, strengths, *, block=False, default_proof=None, unproved_mfa=None):
    gaps = []
    for principal, context in product(profiles, contexts):
        enforced = False
        blocked = False
        reachable_without_mfa = True
        for rule in rules:
            if ca_match(rule, principal, context, locations):
                is_block, is_mfa, allowed = grant(rule, strengths, context)
                blocked |= is_block
                enforced |= is_mfa
                reachable_without_mfa &= allowed
        if default_proof is not None:
            # Security defaults has conditional MFA semantics. Its state alone
            # never establishes exhaustive MFA; a context-bound proof is required.
            entries = list_of_objects(get(default_proof, 'contexts', list))
            match = [e for e in entries if get(e, 'userId', str) == principal['userId'] and get(e, 'state', dict) == {k: v['value'] for k, v in context.items()}]
            if len(match) != 1:
                raise Unavailable('security defaults context proof incomplete')
            enforced |= get(match[0], 'mfaRequired', bool)
        if not block and not enforced and (blocked or not reachable_without_mfa) and unproved_mfa is not None:
            unproved_mfa.append({'userId': principal['userId'], 'context': {k: v['value'] for k, v in context.items()}})
        if not (blocked if block else blocked or enforced or not reachable_without_mfa):
            gaps.append({'userId': principal['userId'], 'context': {k: v['value'] for k, v in context.items()}})
    return gaps


def native_mfa_direct_user_scope(selected, enabled_ids):
    """Bounded Graph direct-user selector; None means unsupported, never a gap."""
    if any(value not in (None, [], {}) for key, value in selected.items()
            if key not in ('includeUsers', 'excludeUsers') and not key.startswith('_')):
        return None
    try:
        included = strings(get(selected, 'includeUsers', list))
        excluded = get(selected, 'excludeUsers')
        excluded = [] if excluded is None else strings(excluded)
    except Unavailable:
        return None
    guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    if any(not re.fullmatch(guid, value, re.I) for value in excluded):
        return None
    if included == ['All']:
        covered = enabled_ids
    elif included and all(re.fullmatch(guid, value, re.I) for value in included):
        covered = enabled_ids & {value.casefold() for value in included}
    else:
        return None
    return covered - {value.casefold() for value in excluded}


def native_mfa_group_members(index, group_id):
    """Accept only the exact completed native transitive-user projection."""
    kind = 'conditional_access_group_membership'
    expected_scope = scope(index).rstrip('/') + '/groups/' + group_id
    envelopes = [env for env in get(index, 'collections', dict).get(kind, [])
                 if get(env, 'scope', str).casefold() == expected_scope.casefold()]
    # Completeness belongs to this exact requested group. An unrelated group
    # failure cannot invalidate an independently complete MFA policy proof.
    own_index = {'context': get(index, 'context', dict),
                 'collections': {kind: envelopes},
                 kind: [wrapped for wrapped in index.get(kind, [])
                        if get(wrapped, 'scope', str).casefold() == expected_scope.casefold()]}
    rows = inventory(own_index, kind, graph=True)
    row = one(rows, 'group_id', group_id)
    if (len(envelopes) != 1 or get(envelopes[0], 'status', str) != 'collected'
            or get(envelopes[0], 'service', str) != 'Microsoft.Graph'
            or get(envelopes[0], 'items', list) != [row]
            or get(row, 'id', str).casefold() != group_id):
        raise Unavailable('native group source or reference binding unresolved')
    proof = get(row, '_provenance', dict)
    expected = {
        'requested_group_id': group_id,
        'source_operation': 'Groups_TransitiveMembers_List',
        'endpoint': '/v1.0/groups/' + group_id + '/transitiveMembers',
        'group_metadata_endpoint': '/v1.0/groups/' + group_id + '?$select=id,visibility,groupTypes,membershipRuleProcessingState',
        'representation': 'complete_transitive_user_ids',
    }
    if (get(proof, 'tenant_verified', bool) is not True
            or get(proof, 'read_only', bool) is not True
            or any(get(proof, key, str) != value for key, value in expected.items())):
        raise Unavailable('native group authority or projection unresolved')
    members = strings(get(row, 'user_ids', list))
    guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    if (any(not re.fullmatch(guid, value, re.I) for value in members)
            or members != sorted({value.casefold() for value in members})):
        raise Unavailable('native group user identities unresolved')
    return set(members)


def native_mfa_user_group_scope(selected, enabled_ids, index):
    """Native includes minus exclusions; unavailable groups cannot be empty."""
    allowed = {'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups'}
    if any(value not in (None, [], {}) for key, value in selected.items()
            if key not in allowed and not key.startswith('_')):
        return None
    try:
        groups = {}
        for key in ('includeGroups', 'excludeGroups'):
            value = get(selected, key)
            groups[key] = [] if value is None else strings(value)
        if not any(groups.values()):
            return native_mfa_direct_user_scope(selected, enabled_ids)
        included = strings(get(selected, 'includeUsers', list))
        excluded = get(selected, 'excludeUsers')
        excluded = [] if excluded is None else strings(excluded)
        guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
        if any(not re.fullmatch(guid, value, re.I)
               for value in excluded + groups['includeGroups'] + groups['excludeGroups']):
            return None
        if included == ['All']:
            covered = set(enabled_ids)
        elif all(re.fullmatch(guid, value, re.I) for value in included):
            covered = enabled_ids & {value.casefold() for value in included}
        else:
            return None
        # A complete include group cannot justify an unread exclusion group.
        include_members, exclude_members = set(), set()
        for group_id in groups['includeGroups']:
            include_members.update(native_mfa_group_members(index, group_id.casefold()))
        for group_id in groups['excludeGroups']:
            exclude_members.update(native_mfa_group_members(index, group_id.casefold()))
        return ((covered | include_members) & enabled_ids) - (
            {value.casefold() for value in excluded} | exclude_members)
    except Unavailable:
        return None


def native_mfa_risk_licensed_users(index, users):
    """Current native user entitlement, never a tenant SKU or owner assertion."""
    from ..collectors.azure_conditional_access_risk_native import P2_SERVICE_PLAN_ID
    kind = 'conditional_access_risk_entitlement'
    rows = inventory(index, kind, graph=True)
    metadata = get(index, 'context.metadata', dict)
    tenant = scope(index).removeprefix('/tenants/').casefold()
    if (get(metadata, 'tenant_verified', bool) is not True
            or get(metadata, 'tenant_id', str).casefold() != tenant):
        raise Unavailable('risk entitlement tenant authority unresolved')
    expected_capture = {key: text(get(metadata, key, str))
                        for key in ('credential_context_id', 'customer_context_id')}
    def captured(proof, *, row=False):
        if (get(proof, 'tenant_verified', bool) is not True
                or get(proof, 'tenant_id', str).casefold() != tenant
                or any(get(proof, key, str) != value for key, value in expected_capture.items())
                or (row and get(proof, 'read_only', bool) is not True)):
            raise Unavailable('risk entitlement capture or source authority unresolved')
    # Cross-check the same capture on all three independently read sources.
    for source_kind in ('conditional_access_policy', 'directory_user', kind):
        envelopes = get(index, 'collections', dict).get(source_kind, [])
        if (len(envelopes) != 1
                or get(envelopes[0], 'scope', str).casefold() != scope(index).casefold()
                or get(envelopes[0], 'service', str) != 'Microsoft.Graph'):
            raise Unavailable('risk entitlement source scope ambiguous')
        captured(get(envelopes[0], '_provenance', dict))
        for source_row in inventory(index, source_kind, graph=True):
            captured(get(source_row, '_provenance', dict), row=True)
    directory = {get(user, 'id', str).casefold(): get(user, 'accountEnabled', bool) for user in users}
    guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    if any(not re.fullmatch(guid, uid, re.I) for uid in directory):
        raise Unavailable('risk entitlement directory identities unresolved')
    observed, licensed = {}, set()
    for row in rows:
        uid = get(row, 'user_id', str).casefold()
        if (not re.fullmatch(guid, uid, re.I) or uid != get(row, 'id', str).casefold()
                or uid in observed or uid not in directory):
            raise Unavailable('risk entitlement user join ambiguous')
        enabled = get(row, 'account_enabled', bool)
        if enabled != directory[uid]:
            raise Unavailable('risk entitlement directory account state conflicts')
        observed[uid] = enabled
        proof = get(row, '_provenance', dict)
        expected = {'source_operation': 'Graph_UsersAssignedPlans+SubscribedSkus_List',
            'users_endpoint': '/v1.0/users?$select=id,accountEnabled,assignedPlans',
            'skus_endpoint': '/v1.0/subscribedSkus',
            'representation': 'risk_entitlement_plan_ids'}
        if any(get(proof, key, str) != value for key, value in expected.items()):
            raise Unavailable('risk entitlement native operation unresolved')
        plans = {}
        for field in ('active_service_plan_ids', 'risk_p2_service_plan_ids'):
            values = strings(get(row, field, list))
            if (any(not re.fullmatch(guid, value, re.I) for value in values)
                    or values != sorted({value.casefold() for value in values})):
                raise Unavailable('risk entitlement plan identity ambiguous')
            plans[field] = set(values)
        p2 = plans['risk_p2_service_plan_ids']
        if not p2 <= plans['active_service_plan_ids'] & {P2_SERVICE_PLAN_ID}:
            raise Unavailable('risk entitlement P2 intersection inconsistent')
        if enabled and p2:
            licensed.add(uid)
    if set(observed) != set(directory):
        raise Unavailable('risk entitlement user inventory differs from directory')
    return licensed


def native_mfa_fields_readable(value):
    """Coverage-only unread selectors are restrictions, never empty defaults."""
    try:
        guard(value)
        coverage = value.get('_coverage', {})
        for key in set(value) | set(coverage):
            if not isinstance(key, str):
                return False
            if key.startswith('_'):
                continue
            if '.' in key:
                # Graph @odata.context is a literal property name. get() treats
                # dots as paths, so check this key and its coverage together.
                literal = {'field': value[key]} if key in value else {}
                if key in coverage:
                    literal['_coverage'] = {'field': coverage[key]}
                get(literal, 'field')
            else:
                get(value, key)
        return True
    except Unavailable:
        return False


def native_mfa_source_capture(index, kind):
    """Bind each independently relied-on native source to this tenant capture."""
    endpoints = {
        'conditional_access_policy': '/v1.0/identity/conditionalAccess/policies',
        'directory_user': '/v1.0/users',
        'directory_security_defaults': '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy',
        'authentication_strength': '/v1.0/policies/authenticationStrengthPolicies',
    }
    metadata = get(index, 'context.metadata', dict)
    tenant = scope(index).removeprefix('/tenants/').casefold()
    if (get(metadata, 'tenant_verified', bool) is not True
            or get(metadata, 'tenant_id', str).casefold() != tenant):
        raise Unavailable('native MFA tenant authority unresolved')
    capture = {key: text(get(metadata, key, str))
               for key in ('credential_context_id', 'customer_context_id')}
    envelopes = get(index, 'collections', dict).get(kind, [])
    if (len(envelopes) != 1
            or get(envelopes[0], 'scope', str).casefold() != scope(index).casefold()
            or get(envelopes[0], 'service', str) != 'Microsoft.Graph'):
        raise Unavailable('native MFA source scope ambiguous')
    def captured(proof, *, row=False):
        if (get(proof, 'tenant_verified', bool) is not True
                or get(proof, 'tenant_id', str).casefold() != tenant
                or any(get(proof, key, str) != value for key, value in capture.items())
                or ((row or 'read_only' in proof) and get(proof, 'read_only', bool) is not True)):
            raise Unavailable('native MFA source capture or authority unresolved')
        if row and get(proof, 'endpoint', str) != endpoints[kind]:
            raise Unavailable('native MFA source endpoint unresolved')
        if row and kind == 'authentication_strength' and (
                get(proof, 'source_operation', str) != 'authenticationStrengthPolicies_List'
                or get(proof, 'representation', str) != 'full'):
            raise Unavailable('native MFA strength projection unresolved')
    captured(get(envelopes[0], '_provenance', dict))
    for row in inventory(index, kind, graph=True):
        captured(get(row, '_provenance', dict), row=True)


def native_mfa_approved_axes(p, enabled_user_count, cid):
    """A bounded approved universe; All entries are universal-scope markers."""
    apps = strings(get(p, 'requiredApplications', list), nonempty=True)
    clients = strings(get(p, 'requiredClientAppTypes', list), nonempty=True)
    guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    known_clients = {'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'}
    all_apps, all_clients = apps == ['All'], clients == ['all']
    if not all_apps and (any(not re.fullmatch(guid, app, re.I) for app in apps)
                         or len({app.casefold() for app in apps}) != len(apps)):
        return None
    if not all_clients and set(clients) - known_clients:
        return None
    risks = ('medium', 'high') if cid == RISK else (None,)
    if enabled_user_count * len(apps) * len(clients) * len(risks) > 16384:
        return None
    return {'apps': tuple(app.casefold() for app in apps) if not all_apps else ('All',),
            'clients': tuple(clients), 'risks': risks,
            'all_apps': all_apps, 'all_clients': all_clients}


def native_mfa_application_client_scope(conditions, axes):
    """Exact appId exclusions and documented clients; no bundle expansion."""
    try:
        apps = get(conditions, 'applications', dict)
        if not native_mfa_fields_readable(apps):
            return None
        if any(value not in (None, [], {}) for key, value in apps.items()
                if key not in ('includeApplications', 'excludeApplications') and not key.startswith('_')):
            return None
        included = strings(get(apps, 'includeApplications', list), nonempty=True)
        excluded = strings(get(apps, 'excludeApplications', list))
        clients = strings(get(conditions, 'clientAppTypes', list), nonempty=True)
        guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
        include_all, client_all = included == ['All'], clients == ['all']
        if ((not include_all and any(not re.fullmatch(guid, value, re.I) for value in included))
                or any(not re.fullmatch(guid, value, re.I) for value in excluded)
                or (not client_all and set(clients) - {
                    'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other'})):
            return None
        unrestricted_apps = include_all and not excluded
        unrestricted = unrestricted_apps and client_all
        if axes is None:
            return ((), (), True) if unrestricted else None
        if (axes['all_apps'] and not unrestricted_apps) or (axes['all_clients'] and not client_all):
            return None
        included_ids, excluded_ids = {value.casefold() for value in included}, {value.casefold() for value in excluded}
        app_keys = tuple(app for app in axes['apps']
                         if (include_all or app in included_ids) and app not in excluded_ids)
        client_keys = tuple(client for client in axes['clients'] if client_all or client in clients)
        return app_keys, client_keys, unrestricted
    except Unavailable:
        return None


def _mfa_company_policy_declared(index):
    """An explicit SW13 policy stays authoritative; unrelated policies do not."""
    metadata = get(index, 'context.metadata', dict)
    coverage = metadata.get('_coverage', {})
    if not isinstance(coverage, dict):
        raise Unavailable('MFA policy namespace coverage malformed')
    if 'compliance_policy' not in metadata:
        if 'compliance_policy' in coverage:
            raise Unavailable('declared MFA policy namespace unreadable')
        return False
    root = get(metadata, 'compliance_policy', dict)
    root_coverage = root.get('_coverage', {})
    if not isinstance(root_coverage, dict):
        raise Unavailable('MFA policy coverage malformed')
    return 'sw13' in root or 'sw13' in root_coverage


def native_universal_mfa(item, index, cid):
    """Prove the universal subset directly from native rules, without simulation."""
    provenance = item.get('_provenance', {})
    if (provenance.get('endpoint') != '/v1.0/identity/conditionalAccess/policies'
            or provenance.get('tenant_verified') is not True or provenance.get('read_only') is not True):
        return None
    target(item, index, 'conditional_access_policy', graph=True)
    rules = inventory(index, 'conditional_access_policy', graph=True)
    native_mfa_source_capture(index, 'conditional_access_policy')
    owner_declared = _mfa_company_policy_declared(index)
    p = (policy(index, cid) if owner_declared else
         {'userScope': 'all', 'requiredApplications': ['All'],
          'requiredClientAppTypes': ['all']})
    if not owner_declared:
        now(index)  # Reject malformed snapshot time on automatic native proof.
    mode = get(p, 'userScope', str)
    if mode not in ('all', 'designated', 'administrative') or (cid == ADMIN and owner_declared and mode != 'administrative'):
        raise Unavailable('user designation unresolved')
    strings(get(p, 'requiredApplications', list), nonempty=True)
    strings(get(p, 'requiredClientAppTypes', list), nonempty=True)
    # The exact all-users proof also covers any operator-designated subset.
    if mode == 'designated':
        strings(get(p, 'designatedUsers', list))
    if mode == 'administrative':
        strings(get(p, 'designatedGroups', list))
        strings(get(p, 'designatedRoles', list))
    defaults = inventory(index, 'directory_security_defaults', graph=True)
    native_mfa_source_capture(index, 'directory_security_defaults')
    if len(defaults) != 1 or get(defaults[0], 'isEnabled', bool):
        return None
    users = inventory(index, 'directory_user', graph=True)
    enabled = [u for u in users if get(u, 'accountEnabled', bool)]
    if not enabled:
        return None
    # Native collection consistency is a global prerequisite. Validate every
    # row before accepting an independent universal rule; otherwise the same
    # inconsistent inventory could PASS or be UNKNOWN depending on row order.
    for rule in rules:
        proof = get(rule, '_provenance', dict)
        if (get(proof, 'tenant_verified', bool) is not True or get(proof, 'read_only', bool) is not True
                or get(proof, 'endpoint', str) != '/v1.0/identity/conditionalAccess/policies'):
            raise Unavailable('native Conditional Access authority unresolved')
        state = get(rule, 'state', str)
        if state not in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'):
            raise Unavailable('unknown Conditional Access policy state')
    # The legacy All-users proof does not require an explicit roster join.
    # The new direct-user union does: only well-formed native GUID identities
    # may form that exhaustive enabled-principal universe.
    guid = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
    direct_ids = ({u['id'].casefold() for u in enabled}
                  if all(re.fullmatch(guid, u['id'], re.I) for u in users) else None)
    if owner_declared:
        try:
            native_mfa_source_capture(index, 'directory_user')
            directory_captured = True
        except Unavailable:
            # Historical owner-scoped proof can use an independently
            # unrestricted All-users rule without a roster join.
            directory_captured, direct_ids = False, None
    else:
        # A source-wide automatic verdict needs the complete enabled-user
        # universe bound to this same read-only Graph tenant capture.
        native_mfa_source_capture(index, 'directory_user')
        directory_captured = True
        if direct_ids is None:
            return None
        if cid == RISK:
            # Risk policy applicability needs current per-user P2 entitlement.
            if native_mfa_risk_licensed_users(index, users) != direct_ids:
                return None
    axes = native_mfa_approved_axes(p, len(direct_ids), cid) if direct_ids else None
    context_coverage = ({key: set() for key in product(axes['apps'], axes['clients'], axes['risks'])}
                        if axes is not None else {})
    context_proof_ids = []
    covered_ids, proof_ids = set(), []
    risk_coverage = {'medium': set(), 'high': set()}
    risk_proof_ids, licensed_ids = [], None
    strengths = None
    for rule in rules:
        state = get(rule, 'state', str)
        if state != 'enabled':
            continue
        try:
            conditions = get(rule, 'conditions', dict)
            if not native_mfa_fields_readable(conditions):
                continue
            supported = {'users', 'applications', 'clientAppTypes'}
            if cid == RISK:
                supported.add('signInRiskLevels')
            if any(k not in supported and not k.startswith('_')
                    and value not in (None, [], {}) for k, value in conditions.items()):
                continue
            try:
                # The accepted unconditional native path allows an unset risk
                # selector. Explicit unreadable field coverage is never omission.
                levels = (get(conditions, 'signInRiskLevels')
                          if 'signInRiskLevels' in conditions or
                          'signInRiskLevels' in conditions.get('_coverage', {}) else [])
                levels = [] if levels is None else strings(levels)
            except Unavailable:
                continue
            if set(levels) - {'low', 'medium', 'high'}:
                continue
            if levels and (cid != RISK or direct_ids is None):
                continue
            selected = get(conditions, 'users', dict)
            if not native_mfa_fields_readable(selected):
                continue
            universal_selector = (get(selected, 'includeUsers', list) == ['All']
                and not any(value not in (None, [], {}) for k, value in selected.items()
                            if k != 'includeUsers' and not k.startswith('_')))
            direct_scope = (native_mfa_user_group_scope(selected, direct_ids, index)
                            if direct_ids is not None else None)
            if not universal_selector and not direct_scope:
                continue
            app_client_scope = native_mfa_application_client_scope(conditions, axes)
            if app_client_scope is None:
                continue
            app_keys, client_keys, unrestricted_scope = app_client_scope
            if not unrestricted_scope and (not app_keys or not client_keys):
                continue
            controls = get(rule, 'grantControls', dict)
            if not native_mfa_fields_readable(controls):
                continue
            if any(value not in (None, [], {}) for k, value in controls.items()
                    if k not in ('operator', 'builtInControls', 'authenticationStrength') and not k.startswith('_') and not k.endswith('@odata.context')):
                continue
            if set(strings(get(controls, 'builtInControls', list))) - {'mfa', 'compliantDevice', 'domainJoinedDevice'}:
                continue
            context = {'device': {'isCompliant': False, 'isHybridJoined': False}, 'application': {}}
            try:
                if get(controls, 'authenticationStrength') is not None and strengths is None:
                    native_mfa_source_capture(index, 'authentication_strength')
                    strengths = inventory(index, 'authentication_strength', graph=True)
                _, enforced, _ = grant(rule, strengths or [], context)
            except Unavailable:
                continue
            if enforced:
                if not levels:
                    if unrestricted_scope:
                        if universal_selector:
                            return result(False, universal_mfa_policy_id=rule['id'],
                                proof='Native enabled All users / All applications / all clients MFA grant without restrictive conditions')
                        if direct_scope - covered_ids:
                            covered_ids.update(direct_scope)
                            proof_ids.append(rule['id'])
                    selected_users, applicable_risks = direct_scope, set(risk_coverage)
                else:
                    if licensed_ids is None:
                        try:
                            licensed_ids = native_mfa_risk_licensed_users(index, users)
                        except Unavailable:
                            licensed_ids = set()
                    selected_users = direct_scope & licensed_ids
                    applicable_risks = set(levels) & set(risk_coverage)
                if unrestricted_scope and any(selected_users - risk_coverage[risk] for risk in applicable_risks):
                    risk_proof_ids.append(rule['id'])
                    for risk in applicable_risks:
                        risk_coverage[risk].update(selected_users)
                if axes is not None and selected_users:
                    context_risks = (set(axes['risks']) if not levels else set(levels) & set(axes['risks']))
                    keys = tuple(product(app_keys, client_keys, context_risks))
                    if any(selected_users - context_coverage[key] for key in keys):
                        context_proof_ids.append(rule['id'])
                        for key in keys:
                            context_coverage[key].update(selected_users)
        except Unavailable:
            # Another complete policy may independently establish MFA coverage.
            # Unreadable candidate fields cannot erase that sufficient proof.
            continue
    if direct_ids and covered_ids == direct_ids:
        return result(False, native_mfa_policy_ids=proof_ids,
            enabled_user_count=len(direct_ids), covered_user_count=len(covered_ids),
            proof='Complete native enabled-user universe covered by unconditional All applications / all clients MFA policies with direct user selectors')
    if cid == RISK and direct_ids and all(users == direct_ids for users in risk_coverage.values()):
        return result(False, native_mfa_policy_ids=risk_proof_ids,
            required_risk_states=['medium', 'high'], enabled_user_count=len(direct_ids),
            covered_user_counts={risk: len(users) for risk, users in risk_coverage.items()},
            proof='Native medium/high sign-in risk MFA coverage with current per-user P2 entitlement or independent unconditional MFA')
    if context_coverage and all(covered == direct_ids for covered in context_coverage.values()):
        evidence = {'native_mfa_policy_ids': context_proof_ids, 'enabled_user_count': len(direct_ids),
            'all_applications_required': axes['all_apps'], 'all_client_types_required': axes['all_clients'],
            'proof': 'Complete native MFA coverage for the approved application and client scopes'}
        if not axes['all_apps']:
            evidence['required_application_count'] = len(axes['apps'])
        if not axes['all_clients']:
            evidence['required_client_type_count'] = len(axes['clients'])
        if cid == RISK:
            evidence['required_risk_states'] = ['medium', 'high']
        return result(False, **evidence)
    # Never infer a gap from a condition this limited adapter cannot evaluate.
    # With no enabled policies, however, no enabled CA MFA policy can exist.
    if (cid == USERS and mode == 'all' and directory_captured
            and (owner_declared or direct_ids is not None)
            and not any(r['state'] == 'enabled' for r in rules)):
        return result(True, reason='Complete native CA inventory has no enabled policy and Security Defaults is disabled',
            enabled_user_count=len(enabled))
    return None


def mfa(item, index, cid):
    owner_declared = _mfa_company_policy_declared(index)
    native = native_universal_mfa(item, index, cid)
    if native is not None:
        return native
    if not owner_declared:
        return unknown('native Conditional Access MFA proof inconclusive: complete tenant-bound Graph users, policies, defaults, risk entitlement and unrestricted selectors required')
    p, rules, profiles, contexts, locations, strengths, defaults = ca_inputs(item, index, cid)
    if not profiles:
        if cid == ADMIN:
            return 'NOT_APPLICABLE', {'reason': 'Complete approved administrative scope contains no enabled principals'}
        return result(False, enabled_user_count=0, semantics='Complete approved empty user scope')
    default_proof = None
    if defaults:
        default_proof = one(observations(index, 'security_defaults_context_proof', graph=True), 'checkId', cid)
        if not current(default_proof, index):
            raise Unavailable('security defaults proof stale')
    unproved = []
    gaps = ca_coverage(rules, profiles, contexts, locations, strengths, default_proof=default_proof, unproved_mfa=unproved)
    if not gaps and unproved:
        return unknown('blocked contexts do not prove an enforced MFA policy', unproved_mfa_contexts=unproved)
    return result(bool(gaps), uncovered_contexts=gaps, evaluated_principals=len(profiles))


@signed(ADMIN, *CA_DEPS, 'security_defaults_context_proof', 'conditional_access_group_membership')
def administrative_mfa(item, index):
    return mfa(item, index, ADMIN)


@signed(USERS, *CA_DEPS, 'security_defaults_context_proof', 'conditional_access_group_membership')
def users_mfa(item, index):
    return mfa(item, index, USERS)


@signed(RISK, *CA_DEPS, 'security_defaults_context_proof', 'conditional_access_group_membership', 'conditional_access_risk_entitlement')
def risky_mfa(item, index):
    return mfa(item, index, RISK)


def review(index, cid):
    reviews = observations(index, 'azure_compliance_review', graph=True)
    relevant = [r for r in reviews if get(r, 'checkId', str) == cid]
    if not relevant:
        return None
    if len(relevant) != 1:
        raise Unavailable('ambiguous consideration review')
    return relevant[0]


@signed(DEVICE, *CA_DEPS, 'azure_compliance_review')
def device_code_review(item, index):
    from peaso.collectors import azure_ca_consideration_native as native
    if item.get('_provenance', {}).get('endpoint') == native.ENDPOINT:
        target(item, index, 'conditional_access_policy', graph=True)
        outcome = native.native_result(item, get(index, 'context', dict),
            inventory(index, 'conditional_access_policy', graph=True), policy(index, DEVICE))
        if outcome is not None:
            return outcome
    p, rules, profiles, contexts, locations, strengths, defaults = ca_inputs(item, index, DEVICE)
    r = review(index, DEVICE)
    if r is None:
        return result(True, reason='Complete review inventory proves no device-flow consideration')
    if not current(r, index):
        return result(True, reason='Documented required review is expired')
    if get(r, 'decision', str) != 'block':
        return unknown('device-flow block approval unresolved')
    if set(strings(get(r, 'userIds', list))) != {x['userId'] for x in profiles} or set(strings(get(r, 'applicationIds', list))) != set(get(p, 'requiredApplications', list)):
        raise Unavailable('review user/app scope mismatch')
    reviewed_ids = strings(get(r, 'policyIds', list), nonempty=True)
    reviewed_rules = [rule for rule in rules if rule['id'] in reviewed_ids]
    for rule in reviewed_rules:
        state = get(rule, 'state', str)
        if state not in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'):
            raise Unavailable('reviewed device-code policy state unrecognized')
        if state == 'enabledForReportingButNotEnforced':
            raise Unavailable('reviewed device-code block policy is report-only')
    enabled_blocks = [rule for rule in reviewed_rules if get(rule, 'state', str) == 'enabled'
                      and get(rule, 'conditions.authenticationFlows.transferMethods', str) == 'deviceCodeFlow'
                      and strings(get(rule, 'grantControls.builtInControls', list)) == ['block']]
    if not enabled_blocks:
        return result(True, reason='Complete policy inventory proves no enabled reviewed device-code block')
    exceptions = strings(get(r, 'exceptionUserIds', list))
    text(get(r, 'exceptionsDocumentId', str))
    if set(exceptions) - {x['userId'] for x in profiles}:
        raise Unavailable('foreign exception principal')
    if {c['authenticationFlow']['value'] for c in contexts} != {'deviceCodeFlow'}:
        raise Unavailable('device-code context partition unresolved')
    gaps = ca_coverage(enabled_blocks, [x for x in profiles if x['userId'] not in exceptions], contexts, locations, strengths, block=True)
    return result(bool(gaps), uncovered_contexts=gaps, review_id=r['id'])


@signed(GEO, *CA_DEPS, 'azure_compliance_review')
def geographic_review(item, index):
    target(item, index, 'conditional_access_policy', graph=True)
    p = policy(index, GEO)
    if item.get('_provenance', {}).get('endpoint') == '/v1.0/identity/conditionalAccess/policies' and 'consideration' in p:
        from peaso.collectors import azure_geo_consideration_native as native
        locations = inventory(index, 'named_location', graph=True) if p.get('consideration', {}).get('decision') == 'block' else []
        outcome = native.native_result(item, get(index, 'context', dict),
            inventory(index, 'conditional_access_policy', graph=True), locations, p)
        if outcome is not None:
            return outcome
    r = review(index, GEO)
    if r is None:
        return result(True, reason='Complete required review inventory proves no geographic-access decision')
    if not current(r, index):
        return result(True, reason='Documented required geographic review is expired')
    if set(strings(get(r, 'applicationIds', list))) != set(strings(get(p, 'requiredApplications', list), nonempty=True)) or get(r, 'userScope', str) != get(p, 'userScope', str):
        raise Unavailable('geographic review scope mismatch')
    if get(p, 'userScope', str) == 'designated' and set(strings(get(r, 'userIds', list))) != set(strings(get(p, 'designatedUsers', list))):
        raise Unavailable('geographic designated users mismatch')
    if get(r, 'scopeComplete', bool) is not True:
        raise Unavailable('geographic review affected scope incomplete')
    text(get(r, 'rationale', str))
    decision = get(r, 'decision', str)
    if decision == 'noBlockRequired':
        return result(False, review_id=r['id'], semantics='Authorized current decision requires no geographic block')
    if decision != 'block':
        raise Unavailable('geographic decision unresolved')
    p, rules, profiles, contexts, locations, strengths, defaults = ca_inputs(item, index, GEO)
    countries = strings(get(r, 'prohibitedCountries', list), nonempty=True)
    if any(not re.fullmatch('[A-Z]{2}', c) for c in countries):
        raise Unavailable('malformed prohibited country')
    if set(countries) != {get(c['location'], 'country', str) for c in contexts}:
        raise Unavailable('country partition does not cover blocking requirement')
    gaps = ca_coverage(rules, profiles, contexts, locations, strengths, block=True)
    return result(bool(gaps), uncovered_contexts=gaps, review_id=r['id'])
def _geographic_empty_inventory(context, collection):
    from peaso.collectors import azure_geo_consideration_native as native
    config = context.get('metadata', {}).get('compliance_policy', {}).get('sw13', {}).get('checks', {}).get(native.KEY)
    return native.empty_result(context, collection, config)


# Opt in only this control. The primary inventory remains genuinely empty.
EVALUATORS[GEO].evaluate_empty_inventory = _geographic_empty_inventory


NOTIFY = 'azure_c5_iam_03_01ac'
CORRELATION = 'azure.other.security_event_correlation'


@signed(NOTIFY, 'audit_sign_in', 'authentication_monitoring_window', 'authentication_notification')
def suspicious_notifications(item, index):
    target(item, index, 'conditional_access_policy', graph=True)
    p = policy(index, NOTIFY)
    start, end = instant(get(p, 'windowStart', str)), instant(get(p, 'windowEnd', str))
    delay = number(get(p, 'notificationMaxDelaySeconds', int))
    if start >= end or end + timedelta(seconds=delay) > now(index):
        raise Unavailable('observation/delivery window not closed')
    levels = strings(get(p, 'suspiciousRiskLevels', list), nonempty=True)
    if set(levels) - {'low', 'medium', 'high'}:
        raise Unavailable('suspicious-event definition unsupported')
    recipients = strings(get(p, 'authorizedRecipientIds', list), nonempty=True)
    monitor = one(observations(index, 'authentication_monitoring_window', graph=True), 'checkId', NOTIFY)
    if instant(get(monitor, 'windowStart', str)) != start or instant(get(monitor, 'windowEnd', str)) != end:
        raise Unavailable('monitoring window mismatch')
    for field in ('detectionEnabled', 'ingestionConfirmed', 'observationComplete', 'deliveryRegistryComplete'):
        if get(monitor, field, bool) is not True:
            raise Unavailable('monitoring/ingestion/delivery evidence incomplete')
    observed_through = instant(get(monitor, 'observedThrough', str))
    if observed_through < end + timedelta(seconds=delay):
        raise Unavailable('delivery observation interval incomplete')
    if observed_through > now(index):
        raise Unavailable('future delivery observation coverage')
    events = inventory(index, 'audit_sign_in', graph=True)
    deliveries = observations(index, 'authentication_notification', graph=True)
    measured = []
    for event in events:
        at = instant(get(event, 'createdDateTime', str))
        if not start <= at < end:
            raise Unavailable('sign-in event outside bounded inventory')
        risk = get(event, 'signInRiskLevel', str)
        if risk not in ('none', 'low', 'medium', 'high'):
            raise Unavailable('event risk hidden or unrecognized')
        get(event, 'status.errorCode', int)
        if risk in levels:
            measured.append((event['id'], at))
    event_ids = {e['id'] for e in events}
    parsed = []
    pending_events = set()
    for record in deliveries:
        eid = get(record, 'eventId', str)
        if eid not in event_ids:
            raise Unavailable('notification event join unresolved')
        recipient = get(record, 'recipientId', str)
        state = get(record, 'deliveryStatus', str)
        delivered = instant(get(record, 'observedAt', str))
        if delivered > now(index):
            raise Unavailable('future delivery observation')
        if state not in ('Delivered', 'Failed'):
            if recipient in recipients:
                pending_events.add(eid)
            continue
        parsed.append((eid, recipient, state, delivered))
    gaps, unresolved = [], []
    for eid, at in measured:
        if any(event_id == eid and recipient in recipients and state == 'Delivered'
               and at <= delivered <= at + timedelta(seconds=delay)
               for event_id, recipient, state, delivered in parsed):
            continue
        if eid in pending_events:
            unresolved.append(eid)
        else:
            gaps.append(eid)
    details = {'unnotified_event_ids': gaps, 'suspicious_event_count': len(measured),
               'semantics': 'Closed, fully observed event and delivery window'}
    if unresolved:
        details['unresolved_event_ids'] = unresolved
    if gaps:
        return result(True, **details)
    if unresolved:
        return unknown('notification delivery pending or unknown', **details)
    return result(False, **details)


def duration(value):
    match = re.fullmatch(r'PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?', text(value))
    if not match or not any(match.groups()):
        raise Unavailable('unsupported ISO duration')
    return number(sum(int(v or 0) * factor for v, factor in zip(match.groups(), (3600, 60, 1))))


@signed(CORRELATION, 'action_group', 'security_query_review', 'security_table_ingestion', target='scope')
def event_correlation(item, index):
    import hashlib
    if 'id' in item:
        target(item, index, 'scheduled_query_rule')  # Legacy resource fixtures.
    elif get(item, 'provider', str) != 'azure' or get(item, 'scope', str) != scope(index):
        raise Unavailable('foreign correlation scope subject')
    p = policy(index, CORRELATION)
    workspaces = strings(get(p, 'requiredWorkspaceIds', list), nonempty=True)
    for wid in workspaces:
        bound(wid, index)
    tables = strings(get(p, 'requiredEventTables', list), nonempty=True)
    if len(tables) < 3:
        raise Unavailable('identity/resource/network event scope unresolved')
    fragments = strings(get(p, 'requiredCorrelationFragments', list), nonempty=True)
    maximum = number(get(p, 'maxCorrelationWindowSeconds', int))
    approved = list_of_objects(get(p, 'approvedCriteria', list))
    if not approved:
        raise Unavailable('approved threshold/aggregation missing')
    for a in approved:
        text(get(a, 'operator', str)); text(get(a, 'timeAggregation', str))
        if type(get(a, 'threshold')) not in (int, float) or not math.isfinite(a['threshold']):
            raise Unavailable('threshold malformed')
    rules = inventory(index, 'scheduled_query_rule')
    actions = inventory(index, 'action_group')
    reviews = observations(index, 'security_query_review')
    ingestion = observations(index, 'security_table_ingestion')
    for workspace, table in product(workspaces, tables):
        matches = [r for r in ingestion if get(r, 'workspaceId', str).casefold() == workspace.casefold() and get(r, 'tableName', str) == table]
        if len(matches) != 1 or not current(matches[0], index) or get(matches[0], 'ingestionConfirmed', bool) is not True:
            raise Unavailable('required event-table ingestion unresolved')
    qualified = set()
    for rule in rules:
        props = get(rule, 'properties', dict)
        if not get(props, 'enabled', bool):
            continue
        scopes = strings(get(props, 'scopes', list), nonempty=True)
        relevant = set(w.casefold() for w in workspaces) & set(s.casefold() for s in scopes)
        if not relevant:
            continue
        # ARM puts ScheduledQueryRuleResource.kind at the resource root.
        # Historical captured facts used properties.kind; retain that form,
        # while rejecting contradictory dual declarations.
        if 'kind' in rule or 'kind' in rule.get('_coverage', {}):
            kind = get(rule, 'kind', str)
        elif 'kind' in props or 'kind' in props.get('_coverage', {}):
            kind = get(props, 'kind', str)
        else:
            # The pinned native API defaults omitted kind to LogAlert. Only
            # accept that default with a verified native routing projection.
            from peaso.collectors.azure_alert_routing_native import verify_projection
            try:
                verify_projection('scheduled_query_rule', scope(index), rule)
            except ValueError as error:
                raise Unavailable('native scheduled query kind default unresolved') from error
            kind = 'LogAlert'
        if 'kind' in rule and 'kind' in props and get(props, 'kind', str) != kind:
            raise Unavailable('contradictory scheduled query kind')
        if kind not in ('LogAlert', 'LogToMetric'):
            raise Unavailable('unknown scheduled query kind')
        if kind != 'LogAlert':
            continue
        window = duration(get(props, 'windowSize', str))
        frequency = duration(get(props, 'evaluationFrequency', str))
        criteria = list_of_objects(get(props, 'criteria.allOf', list))
        if not criteria:
            raise Unavailable('scheduled query criteria unavailable')
        eligible = False
        for criterion in criteria:
            query = text(get(criterion, 'query', str))
            measured = {k: get(criterion, k) for k in ('operator', 'threshold', 'timeAggregation')}
            if measured['operator'] not in ('GreaterThan', 'GreaterThanOrEqual', 'LessThan', 'LessThanOrEqual', 'Equal', 'Equals') or measured['timeAggregation'] not in ('Count', 'Average', 'Minimum', 'Maximum', 'Total') or type(measured['threshold']) not in (int, float) or not math.isfinite(measured['threshold']):
                raise Unavailable('unrecognized criterion semantics')
            digest = hashlib.sha256(query.encode()).hexdigest()
            review_matches = [r for r in reviews if get(r, 'ruleId', str).casefold() == rule['id'].casefold() and get(r, 'querySha256', str) == digest]
            if len(review_matches) != 1:
                raise Unavailable('exact query review unresolved')
            r = review_matches[0]
            if not current(r, index):
                raise Unavailable('query review stale')
            joins = strings(get(r, 'correlatedTables', list))
            reviewed = get(r, 'approved', bool)
            eligible |= reviewed and set(tables) <= set(joins) and all(f in query for f in fragments) and measured in approved and window <= maximum and frequency <= window
        group_ids = strings(get(props, 'actions.actionGroups', list))
        routed = False
        for aid in group_ids:
            bound(aid, index)
            matches = [a for a in actions if a['id'].casefold() == aid.casefold()]
            if not matches:
                # Complete action-group list proves a dangling destination.
                continue
            routed |= get(matches[0], 'properties.enabled', bool)
        if eligible and routed:
            qualified.update(relevant)
    missing = [w for w in workspaces if w.casefold() not in qualified]
    return result(bool(missing), uncovered_workspace_ids=missing,
                  semantics='Reviewed configured correlation and routing; investigation quality unassessed')


CMK = 'azure.gap.recovery_service_vault_encrypted_with_cmk'
IMMUTABLE = 'azure.other.backup_immutability_30'
RESTORE = 'azure.other.backup_restore_evidence'
SCHEDULE = 'azure_recovery_vault_10_3_3_2_5313a3c'
POINTS = 'azure_recovery_vault_10_3_3_3_45b190e'


def _cmk_native_key_defect(index, key):
    """Only an exact, current Key Vault version can prove an unusable CMK."""
    envelopes = get(index, 'collections', dict).get('vault_key', [])
    if not envelopes:
        return None
    metadata = get(index, 'context.metadata', dict)
    if get(metadata, 'tenant_verified', bool) is not True or get(metadata, 'context_binding', str) != 'scan_local':
        raise Unavailable('CMK native key capture authority unresolved')
    capture = {field: text(get(metadata, field, str))
               for field in ('credential_context_id', 'customer_context_id')}
    if len(envelopes) != 1 or get(envelopes[0], 'scope', str).casefold() != scope(index).casefold() or get(envelopes[0], 'service', str) != 'Microsoft.KeyVault':
        raise Unavailable('CMK native key collection scope unresolved')
    proof = get(envelopes[0], '_provenance', dict)
    if any(get(proof, field, str) != capture[field] for field in capture):
        raise Unavailable('CMK native key collection capture inconsistent')
    rows = inventory(index, 'vault_key')
    parsed = urlsplit(key)
    if not re.fullmatch(r'/keys/[A-Za-z0-9-]+/[A-Za-z0-9-]+', parsed.path):
        return None  # A versionless URI cannot identify the active key version.
    matches = []
    for row in rows:
        versions = get(row, 'versions', list)
        if get(row, 'type', str).casefold() != 'microsoft.keyvault/vaults':
            raise Unavailable('CMK native key vault kind unresolved')
        row_id = text(get(row, 'id', str))
        if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[A-Za-z0-9-]{3,24}', row_id, re.I):
            raise Unavailable('CMK native key vault identity malformed')
        row_proof = get(row, '_provenance', dict)
        if (get(row_proof, 'source_operation', str) != 'GetKeys/GetKeyVersions/GetKey'
                or get(row_proof, 'api_version', str) != '2025-07-01'
                or get(row_proof, 'read_only', bool) is not True
                or any(get(row_proof, field, str) != capture[field] for field in capture)):
            raise Unavailable('CMK native key vault source unresolved')
        if get(row, '_coverage.versions.status', str) not in ('collected', 'empty'):
            raise Unavailable('CMK native key versions incomplete')
        for version in versions:
            if not isinstance(version, dict):
                raise Unavailable('CMK native key version malformed')
            if version.get('native_key_id') != key:
                continue
            if row_id.rsplit('/', 1)[1].casefold() + '.vault.azure.net' != parsed.hostname.casefold():
                raise Unavailable('CMK native key host differs from ARM vault')
            name, version_id = parsed.path.split('/')[2:]
            if get(version, 'id', str).casefold() != (row_id + '/versions/' + name + '/' + version_id).casefold():
                raise Unavailable('CMK native key version identity inconsistent')
            version_proof = get(version, '_provenance', dict)
            if (get(version_proof, 'source_operation', str) != 'GetKey'
                    or get(version_proof, 'request_uri', str) != key
                    or get(version_proof, 'api_version', str) != '2025-07-01'
                    or get(version_proof, 'read_only', bool) is not True
                    or any(field in version_proof and version_proof[field] != capture[field] for field in capture)
                    or get(version, 'key.kid', str) != key):
                raise Unavailable('CMK native key version GET authority unresolved')
            attributes = get(version, 'attributes', dict)
            enabled = get(attributes, 'enabled', bool)
            for field in ('nbf', 'exp'):
                if field in attributes and (type(attributes[field]) is not int or attributes[field] < 0):
                    raise Unavailable('CMK native key validity malformed')
            matches.append((enabled, attributes))
    if len(matches) > 1:
        raise Unavailable('duplicate native CMK key version')
    if not matches:
        return None
    enabled, attributes = matches[0]
    observed = now(index).timestamp()
    if not enabled:
        return 'Configured CMK key version is disabled'
    if 'nbf' in attributes and attributes['nbf'] > observed:
        return 'Configured CMK key version is not yet valid'
    if 'exp' in attributes and attributes['exp'] <= observed:
        return 'Configured CMK key version is expired'
    return None


def _cmk_observation_capture(row, index):
    proof = get(row, '_provenance', dict)
    metadata = get(index, 'context.metadata', dict)
    for field in ('credential_context_id', 'customer_context_id', 'tenant_id'):
        if field in proof:
            actual = text(get(proof, field, str))
            expected = text(get(metadata, field, str))
            if (actual.casefold() != expected.casefold() if field == 'tenant_id'
                    else actual != expected):
                raise Unavailable('CMK observation capture binding differs')


@signed(CMK, 'recovery_vault_capability', 'key_authorization_evidence')
def vault_customer_key(item, index):
    rid = target(item, index, 'recovery_vault')
    p = policy(index, CMK)
    key = omitted(item, 'properties.encryption.keyVaultProperties.keyUri', None)
    configured = isinstance(key, str) and bool(key)
    provenance = item.get('_provenance')
    # An actual ARM GET is useful only when its native proof belongs to this
    # verified capture. A malformed native marker cannot inherit the manual
    # capability path, which is reserved for snapshots without a native GET.
    native_marked = isinstance(provenance, dict) and (
        provenance.get('source_operation') == 'get'
        or provenance.get('api_version') == '2024-04-01'
        or (provenance.get('representation') == 'full'
            and item.get('type', '').casefold() == 'microsoft.recoveryservices/vaults'))
    if native_marked:
        metadata = get(index, 'context.metadata', dict)
        if get(metadata, 'tenant_verified', bool) is not True:
            raise Unavailable('CMK native tenant authority unresolved')
        tenant = text(get(metadata, 'tenant_id', str))
        capture = {field: text(get(metadata, field, str))
                   for field in ('credential_context_id', 'customer_context_id')}
        if get(metadata, 'context_binding', str) != 'scan_local':
            raise Unavailable('CMK native capture binding unresolved')
        tenants = get(metadata, 'subscription_tenants', dict)
        selected = [value for key, value in tenants.items()
                    if isinstance(key, str) and key.casefold() == scope(index).casefold()]
        if len(selected) > 1 or (selected and (not isinstance(selected[0], str)
                                               or selected[0].casefold() != tenant.casefold())):
            raise Unavailable('CMK native subscription tenant unresolved')
        envelopes = get(index, 'collections', dict).get('recovery_vault', [])
        if (len(envelopes) != 1 or get(envelopes[0], 'service', str) != 'Microsoft.RecoveryServices'
                or get(envelopes[0], 'scope', str).casefold() != scope(index).casefold()
                or get(envelopes[0], 'status', str) != 'collected'):
            raise Unavailable('CMK native vault collection scope unresolved')
        envelope_proof = get(envelopes[0], '_provenance', dict)
        if any(get(envelope_proof, field, str) != capture[field]
               or get(provenance, field, str) != capture[field] for field in capture):
            raise Unavailable('CMK native vault capture inconsistent')
        if (get(provenance, 'representation', str) != 'full'
                or get(provenance, 'source_operation', str) != 'get'
                or get(provenance, 'api_version', str) != '2024-04-01'
                or get(provenance, 'read_only', bool) is not True
                or get(item, 'type', str).casefold() != 'microsoft.recoveryservices/vaults'):
            raise Unavailable('CMK native vault GET authority unresolved')
    native_get = native_marked
    # The documented vault GET has a CMK keyUri but no cmkSupported/state flag.
    # A currently configured key establishes applicability for this vault only;
    # missing keyUri cannot establish unsupported capability.
    capability = None
    cap_envelopes = get(index, 'collections', dict).get('recovery_vault_capability', [])
    read_capability = not (native_get and configured) or any(
        isinstance(env, dict) and env.get('status') == 'collected' for env in cap_envelopes)
    if read_capability:
        capability = one(observations(index, 'recovery_vault_capability'), 'vaultId', rid)
        _cmk_observation_capture(capability, index)
        if not current(capability, index):
            raise Unavailable('CMK capability evidence stale')
        supported = get(capability, 'cmkSupported', bool)
        if native_get and configured and not supported:
            raise Unavailable('native configured CMK conflicts with capability evidence')
        if not supported:
            return 'NOT_APPLICABLE', {'reason': 'Explicitly measured vault does not support CMK'}
    if key is None or key == '':
        return result(True, reason='Complete supported vault has no CMK key URI')
    parsed = urlsplit(text(key))
    if parsed.scheme != 'https' or not parsed.hostname or not re.fullmatch(r'[a-zA-Z0-9-]+\.vault\.azure\.net', parsed.hostname) or parsed.query or parsed.fragment or parsed.port or parsed.username or not re.fullmatch(r'/keys/[A-Za-z0-9-]+(?:/[A-Za-z0-9-]+)?', parsed.path):
        raise Unavailable('malformed CMK key URI')
    kek = get(item, 'properties.encryption.kekIdentity', dict)
    system = omitted(item, 'properties.encryption.kekIdentity.useSystemAssignedIdentity', None)
    selected = omitted(item, 'properties.encryption.kekIdentity.userAssignedIdentity', None)
    if type(system) not in (bool, type(None)) or (selected is not None and not isinstance(selected, str)) or (system is True and selected not in (None, '')):
        raise Unavailable('ambiguous CMK identity selection')
    identity = get(item, 'identity', dict)
    typ = get(identity, 'type', str)
    if typ not in ('None', 'SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned'):
        raise Unavailable('vault identity type unknown')
    if system is True:
        if 'SystemAssigned' not in typ:
            return result(True, reason='CMK selects absent system-assigned identity')
        principal = text(get(identity, 'principalId', str))
    else:
        if selected in (None, ''):
            if system is False:
                return result(True, reason='No customer-key identity selected')
            raise Unavailable('CMK identity selection unavailable')
        selected = text(selected)
        bound(selected, index)
        if 'UserAssigned' not in typ:
            return result(True, reason='CMK identity not assigned to vault')
        assigned = get(identity, 'userAssignedIdentities', dict)
        matches = [v for k, v in assigned.items() if isinstance(k, str) and k.casefold() == selected.casefold()]
        if not matches:
            return result(True, reason='CMK identity not assigned to vault')
        if len(matches) != 1:
            raise Unavailable('ambiguous assigned identity')
        principal = text(get(matches[0], 'principalId', str))
    defect = _cmk_native_key_defect(index, key) if native_get else None
    if defect is not None:
        return result(True, reason=defect, key_uri=key)
    approved = strings(get(p, 'approvedKeyUris', list), nonempty=True)
    if key not in approved:
        # Owner approval cannot prove provider key authorization.
        return unknown('CMK key approval unresolved')
    evidence = observations(index, 'key_authorization_evidence')
    matching = [e for e in evidence if get(e, 'vaultId', str).casefold() == rid.casefold() and get(e, 'keyUri', str) == key and get(e, 'principalId', str) == principal]
    if len(matching) != 1 or not current(matching[0], index):
        raise Unavailable('effective CMK authorization unresolved')
    access = matching[0]
    _cmk_observation_capture(access, index)
    if not get(access, 'authorizationComplete', bool):
        raise Unavailable('effective key access not confirmed')
    if not get(access, 'keyEnabled', bool):
        return result(True, reason='Independently observed configured CMK key is disabled')
    permissions = strings(get(access, 'effectiveKeyOperations', list))
    if not {'get', 'wrapKey', 'unwrapKey'} <= set(permissions):
        return result(True, reason='Complete effective key authorization lacks required operations')
    if not get(access, 'networkAccessible', bool):
        raise Unavailable('effective key network access not confirmed')
    return result(False, key_uri=key, identity_principal_id=principal)


def vault_children(item, index, kind):
    rid = target(item, index, 'recovery_vault')
    rows = inventory(index, kind, parent=rid)
    for row in rows:
        if get(row, 'parent_id', str).casefold() != rid.casefold():
            raise Unavailable('foreign vault parent join')
    return rid, rows


def backup_semantics(row):
    """Recognized Standard Azure VM V1 schedules with measured tier durations.

    Month/year durations are intervals, never falsely equated to 30/365 days.
    All nonselected recovery points must have a daily-retention floor before
    immutability can PASS; unsupported/archive behavior stays UNKNOWN.
    """
    props = get(row, 'properties', dict)
    if get(props, 'backupManagementType', str) != 'AzureIaasVM':
        raise Unavailable('unsupported backup workload retention schema')
    archive = omitted(row, 'properties.tieringPolicy', None)
    if archive not in (None, {}):
        raise Unavailable('archive retention behavior unresolved')
    schedule = get(props, 'schedulePolicy', dict)
    if get(schedule, 'schedulePolicyType', str) != 'SimpleSchedulePolicy':
        raise Unavailable('unsupported enhanced/hourly schedule')
    if get(props, 'timeZone', str) != 'UTC':
        raise Unavailable('timezone frequency normalization unresolved')
    freq = get(schedule, 'scheduleRunFrequency', str)
    times = strings(get(schedule, 'scheduleRunTimes', list), nonempty=True)
    normalized_times = [instant(t).strftime('%H:%M:%S') for t in times]
    if len(times) != 1:
        raise Unavailable('multiple daily run frequency unsupported')
    if freq == 'Daily':
        interval = 1
    elif freq == 'Weekly':
        schedule_days = strings(get(schedule, 'scheduleRunDays', list), nonempty=True)
        week = ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
        if set(schedule_days) - set(week):
            raise Unavailable('unknown schedule day')
        offsets = sorted(week.index(d) for d in schedule_days)
        interval = max(b - a for a, b in zip(offsets, offsets[1:] + [offsets[0] + 7]))
    else:
        raise Unavailable('unrecognized backup frequency')
    retention = get(props, 'retentionPolicy', dict)
    if get(retention, 'retentionPolicyType', str) != 'LongTermRetentionPolicy':
        raise Unavailable('unsupported retention discriminator')
    tiers = {}
    for name in ('dailySchedule', 'weeklySchedule', 'monthlySchedule', 'yearlySchedule'):
        branch = omitted(row, 'properties.retentionPolicy.' + name, None)
        if branch is None:
            continue
        if not isinstance(branch, dict):
            raise Unavailable('malformed retention branch')
        retention_times = strings(get(branch, 'retentionTimes', list), nonempty=True)
        if set(instant(t).strftime('%H:%M:%S') for t in retention_times) != set(normalized_times):
            raise Unavailable('retention branch does not match backup times')
        if name == 'weeklySchedule':
            days = strings(get(branch, 'daysOfTheWeek', list), nonempty=True)
            if set(days) - {'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'}:
                raise Unavailable('unknown weekly retention day')
        if name in ('monthlySchedule', 'yearlySchedule'):
            raise Unavailable('monthly/yearly selection semantics unsupported')
        count = number(get(branch, 'retentionDuration.count', int))
        unit = get(branch, 'retentionDuration.durationType', str)
        if unit not in ('Days', 'Weeks', 'Months', 'Years'):
            raise Unavailable('unknown retention duration unit')
        lower, upper = {'Days': (1, 1), 'Weeks': (7, 7), 'Months': (28, 31), 'Years': (365, 366)}[unit]
        tiers[name] = (count * lower, count * upper)
    if not tiers:
        raise Unavailable('no measured retention tiers')
    if freq == 'Daily' and 'dailySchedule' not in tiers:
        raise Unavailable('retention of unselected daily points unresolved')
    if freq == 'Weekly':
        branch = get(retention, 'weeklySchedule', dict)
        if set(strings(get(branch, 'daysOfTheWeek', list))) != set(schedule_days):
            raise Unavailable('retention of unselected weekly points unresolved')
    return interval, tiers


def point_retention_floors(row, tiers):
    schedule = get(row, 'properties.schedulePolicy', dict)
    week = ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
    days = week if get(schedule, 'scheduleRunFrequency', str) == 'Daily' else strings(get(schedule, 'scheduleRunDays', list))
    weekly_days = set()
    if 'weeklySchedule' in tiers:
        weekly_days = set(strings(get(row, 'properties.retentionPolicy.weeklySchedule.daysOfTheWeek', list)))
    floors = []
    for day in days:
        applicable = []
        if 'dailySchedule' in tiers:
            applicable.append(tiers['dailySchedule'])
        if day in weekly_days:
            applicable.append(tiers['weeklySchedule'])
        if not applicable:
            raise Unavailable('scheduled point has no resolved retention branch')
        # A point selected by multiple GFS tiers survives for the longest
        # applicable retention; a shorter overlapping tier is not a gap.
        floors.append((max(t[0] for t in applicable), max(t[1] for t in applicable)))
    return floors


def below(interval, bound_days):
    low, high = interval
    if low >= bound_days:
        return False
    if high < bound_days:
        return True
    raise Unavailable('calendar duration straddles policy bound')


@signed(IMMUTABLE, 'backup_protected_item', 'backup_policy')
def immutable_backups(item, index):
    rid, protected = vault_children(item, index, 'backup_protected_item')
    if not protected:
        return 'NOT_APPLICABLE', {'reason': 'Complete vault inventory has no protected items'}
    state = get(item, 'properties.securitySettings.immutabilitySettings.state', str)
    if state not in ('Disabled', 'Unlocked', 'Locked'):
        raise Unavailable('unknown immutability state')
    if state != 'Locked':
        return result(True, immutability_state=state)
    policies = inventory(index, 'backup_policy', parent=rid)
    violations = []
    for protected_item in protected:
        policy_id = get(protected_item, 'properties.policyId', str)
        if not policy_id.casefold().startswith(rid.casefold() + '/backuppolicies/'):
            raise Unavailable('foreign policy assignment')
        assigned = one(policies, 'id', policy_id)
        frequency, tiers = backup_semantics(assigned)
        if any(below(t, 30) for t in point_retention_floors(assigned, tiers)):
            violations.append(assigned['id'])
    return result(bool(violations), short_retention_policy_ids=sorted(set(violations)), immutability_state=state)


@signed(SCHEDULE, 'backup_policy')
def policy_frequency_retention(item, index):
    rid, policies = vault_children(item, index, 'backup_policy')
    p = policy(index, SCHEDULE)
    frequency = get(p, 'requiredMinimumFrequency', str)
    if frequency not in ('Daily', 'Weekly'):
        raise Unavailable('minimum frequency unknown')
    minimum = number(get(p, 'minimumRetentionDays', int))
    if not policies:
        return 'NOT_APPLICABLE', {'reason': 'Complete in-scope vault has no backup policies'}
    gaps = []
    for row in policies:
        interval, tiers = backup_semantics(row)
        if interval > {'Daily': 1, 'Weekly': 7}[frequency] or any(below(t, minimum) for t in tiers.values()):
            gaps.append(row['id'])
    return result(bool(gaps), nonconforming_policy_ids=gaps)


@signed(POINTS, 'backup_protected_item', 'backup_recovery_point')
def measured_point_retention(item, index):
    rid, protected = vault_children(item, index, 'backup_protected_item')
    minimum = number(get(policy(index, POINTS), 'minRetentionDays', int))
    points = inventory(index, 'backup_recovery_point', parent=rid)
    eligible = []
    for protected_item in protected:
        state = get(protected_item, 'properties.protectionState', str)
        if state not in ('Protected', 'ProtectionStopped', 'SoftDeleted'):
            raise Unavailable('protected-item activity unresolved')
        if state == 'Protected':
            eligible.append(protected_item['id'])
    if not eligible:
        return 'NOT_APPLICABLE', {'reason': 'Complete vault has no active protected items'}
    measured, short = [], []
    for pid in eligible:
        assigned = [point for point in points if get(point, 'parent_id', str).casefold() == pid.casefold()]
        if not assigned:
            raise Unavailable('empty or unavailable recovery-point list')
        retained = []
        for point in assigned:
            if not point['id'].casefold().startswith(pid.casefold() + '/recoverypoints/'):
                raise Unavailable('foreign recovery-point identity')
            if get(point, 'properties.isSoftDeleted', bool):
                continue
            if get(point, '_provenance.detail_get_complete', bool) is not True:
                raise Unavailable('recovery-point detail GET incomplete')
            if get(point, '_provenance.retention_schema_supported', bool) is not True:
                raise Unavailable('unsupported workload point expiry schema')
            created = instant(get(point, 'properties.recoveryPointTime', str))
            expiry = instant(get(point, 'properties.recoveryPointProperties.expiryTime', str))
            if created > now(index) or expiry < created:
                raise Unavailable('invalid recovery-point retention interval')
            retained.append(point)
            measured.append(point['id'])
            if (expiry - created).total_seconds() < minimum * 86400:
                short.append(point['id'])
        if not retained:
            raise Unavailable('no eligible retained points')
    # Validate all point joins before assessing coverage.
    all_ids = {r['id'].casefold() for r in protected}
    for point in points:
        if get(point, 'parent_id', str).casefold() not in all_ids:
            raise Unavailable('recovery-point item join unresolved')
    return result(bool(short), short_retention_point_ids=short, measured_point_count=len(measured))


def backup_restore_native_capture(index):
    """Opaque collector capture plus the actual native read authority."""
    metadata = get(index, 'context.metadata', dict)
    if get(metadata, 'tenant_verified', bool) is not True:
        raise Unavailable('restore native tenant authority unresolved')
    capture = {key: text(get(metadata, key, str))
               for key in ('tenant_id', 'credential_context_id', 'customer_context_id')}
    for kind in ('recovery_vault', 'backup_protected_item', 'backup_job'):
        envelopes = get(index, 'collections', dict).get(kind, [])
        expected_service = 'Microsoft.RecoveryServices'
        if (len(envelopes) != 1 or get(envelopes[0], 'service', str) != expected_service
                or get(envelopes[0], 'scope', str).casefold() != scope(index).casefold()):
            raise Unavailable('restore native source scope unresolved')
        envelope_proof = get(envelopes[0], '_provenance', dict)
        if any(get(envelope_proof, key, str) != capture[key]
               for key in ('credential_context_id', 'customer_context_id')):
            raise Unavailable('restore native collection capture inconsistent')
        for row in inventory(index, kind):
            proof = get(row, '_provenance', dict)
            if (any(get(proof, key, str) != capture[key]
                    for key in ('credential_context_id', 'customer_context_id'))
                    or get(proof, 'read_only', bool) is not True
                    or get(proof, 'api_version', str) != '2024-04-01'):
                raise Unavailable('restore native source capture or readonly authority unresolved')
            if kind == 'recovery_vault':
                if (get(proof, 'source_operation', str) != 'get'
                        or get(proof, 'representation', str) != 'full'):
                    raise Unavailable('restore vault requires actual full native GET')
            else:
                parent = get(row, 'parent_id', str)
                field, operation = (('backupJobs', 'BackupJobs_List') if kind == 'backup_job'
                                    else ('backupProtectedItems', 'BackupProtectedItems_List'))
                if (get(proof, 'source_operation', str) != operation
                        or get(proof, 'representation', str) != 'metadata'
                        or get(proof, 'endpoint', str).casefold() != (parent + '/' + field).casefold()):
                    raise Unavailable('restore native metadata operation or endpoint unresolved')
    return capture



def backup_restore_digest(value):
    """Local canonical evidence digest; never represented as a provider hash."""
    import hashlib
    import json
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def backup_restore_arm_resource(value):
    """An unencoded ARM namespace followed by genuine type/name pairs."""
    if not isinstance(value, str) or not value.startswith('/'):
        raise Unavailable('restore ARM resource malformed')
    parts = value[1:].split('/')
    if (len(parts) < 8 or len(parts[6:]) % 2
            or [part.casefold() for part in (parts[0], parts[2], parts[4])] != ['subscriptions', 'resourcegroups', 'providers']
            or not re.fullmatch(r'[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+', parts[5])
            or any(not part or part in ('.', '..') or re.search(r'[%/?#\x00-\x20]', part) for part in parts)):
        raise Unavailable('restore ARM resource has invalid type/name pairs or encoded/traversal segments')
    return value


def backup_restore_validation(test, job, protected, index, vault_id, capture):
    """Explicit independent external test binds the exact native observations."""
    pid, jid = get(protected, 'id', str), get(job, 'id', str)
    segment = r'[^/?#\x00-\x20]+'
    if (not re.fullmatch(re.escape(vault_id) + '/backupJobs/' + segment, jid, re.I)
            or not re.fullmatch(re.escape(vault_id) + '/backupFabrics/' + segment
                + '/protectionContainers/' + segment + '/protectedItems/' + segment, pid, re.I)):
        raise Unavailable('restore native item or job ARM kind unresolved')
    management = get(job, 'properties.backupManagementType', str)
    job_types = {'AzureIaaSVMJob': 'AzureIaasVM', 'AzureIaaSVMJobV2': 'AzureIaasVM',
                 'AzureStorageJob': 'AzureStorage', 'AzureWorkloadJob': 'AzureWorkload'}
    if (job_types.get(get(job, 'properties.jobType', str)) != management
            or get(protected, 'properties.backupManagementType', str) != management):
        raise Unavailable('restore job and protected workload contradict or are unsupported')
    evidence = get(test, 'validationEvidence', dict)
    proof = get(evidence, '_provenance', dict)
    if (get(proof, 'source_operation', str) != 'external:restore-validation'
            or get(proof, 'representation', str) != 'full'
            or get(proof, 'read_only', bool) is not True
            or not current(evidence, index)):
        raise Unavailable('independent full restore validation authority unresolved')
    if get(evidence, 'document_id', str) != get(test, 'verificationDocumentId', str):
        raise Unavailable('restore validation document join unresolved')
    for field, expected in (('vaultId', vault_id), ('protectedItemId', pid), ('jobId', jid)):
        if get(evidence, field, str).casefold() != expected.casefold():
            raise Unavailable('restore validation exact resource binding differs')
    point = get(evidence, 'sourceRecoveryPointId', str)
    target_id = get(evidence, 'restoreTargetId', str)
    if (not re.fullmatch(re.escape(pid) + '/recoveryPoints/' + segment, point, re.I)
            or get(test, 'sourceRecoveryPointId', str).casefold() != point.casefold()
            or get(test, 'restoreTargetId', str).casefold() != target_id.casefold()):
        raise Unavailable('external restore source point or target binding unresolved')
    bound(target_id, index)
    for identity in (pid, jid, point, target_id):
        backup_restore_arm_resource(identity)
    for key in ('credential_context_id', 'customer_context_id'):
        if get(evidence, key, str) != capture[key]:
            raise Unavailable('external restore validation belongs to another capture')
    expected_digest = backup_restore_digest({'job': job, 'protected_item': protected, 'capture': capture})
    if get(evidence, 'nativeEvidenceSha256', str) != expected_digest:
        raise Unavailable('external restore validation native evidence digest differs')
    verified = instant(get(test, 'verifiedAt', str))
    if instant(get(evidence, 'observed_at', str)) != verified:
        raise Unavailable('usable-data validation timestamp differs')
    usable = get(evidence, 'usableDataValidation', dict)
    if get(usable, 'method', str) not in (
            'application-functional-test', 'database-consistency-check', 'restored-content-checksum'):
        raise Unavailable('restore verification method does not demonstrate usable data')
    text(get(usable, 'testId', str))
    if not re.fullmatch(r'[0-9a-f]{64}', get(usable, 'resultArtifactSha256', str)):
        raise Unavailable('usable-data result artifact binding unresolved')
    # Missing per-test outcome is unresolved, while two explicit conflicting
    # outcomes still invalidate the independent evidence for this registry.
    try:
        usable_outcome = get(usable, 'result', str)
    except Unavailable:
        usable_outcome = None
    try:
        outcome = get(test, 'result', str)
    except Unavailable:
        outcome = None
    if usable_outcome is None or outcome is None:
        return None
    if usable_outcome != outcome:
        raise Unavailable('usable-data validation outcome conflicts')
    if outcome not in ('Passed', 'Failed'):
        return None
    if outcome == 'Passed':
        try:
            verified_data = get(test, 'restoredDataVerified', bool)
        except Unavailable:
            return None
        if verified_data is not True:
            raise Unavailable('restore usable-data outcome contradicts verification')
    return outcome


@signed(RESTORE, 'backup_protected_item', 'backup_job', 'backup_restore_test', 'backup_restore_window')
def restoration_tests(item, index):
    rid, protected = vault_children(item, index, 'backup_protected_item')
    p = policy(index, RESTORE)
    critical = strings(get(p, 'criticalProtectedItemIds', list))
    age = number(get(p, 'restoreTestMaxAgeDays', int))
    start, end = now(index) - timedelta(days=age), now(index)
    for pid in critical:
        one(protected, 'id', pid)
    if not critical:
        return 'NOT_APPLICABLE', {'reason': 'Complete approved critical workload scope is empty'}
    window = one(observations(index, 'backup_restore_window', parent=rid), 'vaultId', rid)
    if instant(get(window, 'windowStart', str)) > start or instant(get(window, 'windowEnd', str)) < end or get(window, 'jobsComplete', bool) is not True or get(window, 'testsComplete', bool) is not True:
        raise Unavailable('restore-test lookback or registry incomplete')
    jobs = inventory(index, 'backup_job', parent=rid)
    tests = observations(index, 'backup_restore_test', parent=rid)
    capture = backup_restore_native_capture(index)
    if (not current(window, index)
            or get(window, '_provenance.source_operation', str) != 'external:restore-test-registry'
            or get(window, '_provenance.representation', str) != 'full'
            or any(get(window, key, str) != capture[key]
                   for key in ('credential_context_id', 'customer_context_id'))
            or get(window, 'jobsInventorySha256', str) != backup_restore_digest({'jobs': jobs, 'capture': capture})):
        raise Unavailable('restore history registry authority or capture unresolved')
    parsed_jobs = {}
    for job in jobs:
        if get(job, 'parent_id', str).casefold() != rid.casefold():
            raise Unavailable('foreign backup job')
        operation = get(job, 'properties.operation', str)
        if operation != 'Restore':
            continue
        state = get(job, 'properties.status', str)
        if state not in ('Completed', 'Failed', 'Cancelled'):
            raise Unavailable('restore job status unresolved')
        begin = instant(get(job, 'properties.startTime', str))
        finish = instant(get(job, 'properties.endTime', str))
        if begin > finish or finish > end:
            raise Unavailable('restore job timing unresolved')
        parsed_jobs[job['id'].casefold()] = (state, begin, finish, job)
    valid = set(); failed = set(); unresolved = set()
    for test in tests:
        pid = get(test, 'protectedItemId', str)
        protected_row = one(protected, 'id', pid)
        jid = get(test, 'jobId', str).casefold()
        if jid not in parsed_jobs:
            raise Unavailable('exact Restore job join unresolved')
        state, begin, finish, native_job = parsed_jobs[jid]
        outcome = backup_restore_validation(test, native_job, protected_row, index, rid, capture)
        if get(test, 'independentVerification', bool) is not True:
            raise Unavailable('restore verification not independent')
        verified = instant(get(test, 'verifiedAt', str))
        text(get(test, 'verificationDocumentId', str))
        if verified < finish or verified > end:
            raise Unavailable('restoration verification time unresolved')
        if outcome is None:
            unresolved.add(pid.casefold())
            continue
        if start <= verified <= end:
            if outcome == 'Failed':
                if get(test, 'required', bool):
                    failed.add(pid.casefold())
            elif state == 'Completed' and get(test, 'restoredDataVerified', bool):
                # Both job and independent verification must be timely.
                if start <= begin <= finish <= end:
                    valid.add(pid.casefold())
    missing = [pid for pid in critical if pid.casefold() not in valid or pid.casefold() in failed]
    if any(pid.casefold() in failed for pid in critical):
        return result(True, missing_or_failed_restore_item_ids=missing)
    if any(pid.casefold() in unresolved for pid in critical):
        return unknown('one or more required restore-test outcomes unresolved')
    return result(bool(missing), missing_or_failed_restore_item_ids=missing)
SERVICE_ENDPOINT = 'azure.gap.appservice_web_app_use_virtual_service_endpoint'
TLS = 'azure.other.endpoint_certificate_trust'
FUNCTION = 'azure_app_service_app_function_latest_runtime_version_f50215a'


def web_configuration(item, index):
    rid = target(item, index, 'app_service')
    if 'configuration' in item:
        config = get(item, 'configuration', dict)
    else:
        rows = inventory(index, 'app_service_config', parent=rid)
        config = one(rows, 'id', rid + '/config/web')
        if get(config, 'parent_id', str).casefold() != rid.casefold():
            raise Unavailable('foreign web configuration')
    if get(config, 'id', str).casefold() != (rid + '/config/web').casefold():
        raise Unavailable('foreign config/web response')
    return get(config, 'properties', dict)


@signed(SERVICE_ENDPOINT, 'app_service_config', 'subnet')
def inbound_service_endpoint(item, index):
    rid = target(item, index, 'app_service')
    kind = get(item, 'kind', str)
    if 'functionapp' in kind.casefold().split(','):
        return 'NOT_APPLICABLE', {'reason': 'Resource is a Function App rather than an in-scope web app'}
    approved = strings(get(policy(index, SERVICE_ENDPOINT), 'approvedSubnetIds', list), nonempty=True)
    config = web_configuration(item, index)
    rules = list_of_objects(get(config, 'ipSecurityRestrictions', list))
    default = get(config, 'ipSecurityRestrictionsDefaultAction', str)
    if default not in ('Allow', 'Deny'):
        raise Unavailable('access-restriction default unknown')
    ordered = []
    priorities = set()
    for rule in rules:
        priority = number(get(rule, 'priority', int), positive=False)
        if priority in priorities:
            raise Unavailable('ambiguous access-restriction priority')
        priorities.add(priority)
        action = get(rule, 'action', str)
        if action not in ('Allow', 'Deny'):
            raise Unavailable('unknown restriction action')
        # Optional selector omissions are allowed only on a full config read.
        subnet = get(rule, 'vnetSubnetResourceId')
        address = get(rule, 'ipAddress')
        headers = get(rule, 'headers', dict)
        tag = get(rule, 'tag', str)
        if headers or tag not in ('Default', ''):
            raise Unavailable('header/service-tag priority semantics unresolved')
        if subnet is not None:
            bound(text(subnet), index)
        if subnet and address not in (None, ''):
            raise Unavailable('ambiguous subnet/IP selector')
        network = None
        if address not in (None, '', 'Any'):
            try:
                network = ipaddress.ip_network(text(address), strict=True)
            except ValueError as exc:
                raise Unavailable('unmodeled IP/service-tag selector') from exc
        if subnet in (None, '') and address in (None, ''):
            raise Unavailable('empty access-restriction selector')
        ordered.append((priority, action, subnet, address, network))
    ordered.sort()
    subnets = inventory(index, 'subnet')
    permitted = []
    for sid in approved:
        bound(sid, index)
        matches = [s for s in subnets if s['id'].casefold() == sid.casefold()]
        if not matches:
            # A complete subnet inventory proves this reference nonexistent.
            continue
        subnet = matches[0]
        endpoints = list_of_objects(get(subnet, 'properties.serviceEndpoints', list))
        services = [get(e, 'service', str) for e in endpoints]
        if 'Microsoft.Web' not in services:
            continue
        cidrs = strings(get(subnet, 'properties.addressPrefixes', list), nonempty=True)
        subnet_permitted = True
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                raise Unavailable('malformed approved subnet address') from exc
            # Partition at every IP restriction boundary so a partly shadowed
            # Allow cannot pass as permission for the entire approved subnet.
            boundaries = {int(network.network_address), int(network.broadcast_address) + 1}
            for _, _, _, _, net in ordered:
                if net is not None and net.version == network.version and net.overlaps(network):
                    boundaries.add(max(int(net.network_address), int(network.network_address)))
                    boundaries.add(min(int(net.broadcast_address), int(network.broadcast_address)) + 1)
            cuts = sorted(boundaries)
            all_allowed = True
            named_allow = False
            for low, high in zip(cuts, cuts[1:]):
                verdict, via_named = default, False
                address = ipaddress.ip_address(low) if network.version == 4 else ipaddress.IPv6Address(low)
                for _, action, rule_subnet, raw_ip, net in ordered:
                    applies = (rule_subnet is not None and rule_subnet.casefold() == sid.casefold()) or raw_ip == 'Any' or (net is not None and address.version == net.version and address in net)
                    if applies:
                        verdict = action
                        via_named = bool(rule_subnet) and rule_subnet.casefold() == sid.casefold()
                        break
                all_allowed &= verdict == 'Allow' and via_named
                named_allow |= verdict == 'Allow' and via_named
            subnet_permitted &= all_allowed and named_allow
        if subnet_permitted:
            permitted.append(sid)
    return result(not permitted, permitted_approved_subnet_ids=sorted(set(permitted)),
                  semantics='Configured inbound restriction priority; live connectivity untested')


def hostname_matches(host, san):
    host = text(host).rstrip('.').casefold()
    names = strings(san)
    for name in names:
        name = name.rstrip('.').casefold()
        if name == host:
            return True
        if name.startswith('*.') and host.endswith(name[1:]) and host.count('.') == name.count('.'):
            return True
    return False


@signed(TLS, 'app_service_endpoint_inventory', 'app_service_endpoint', 'tls_endpoint_observation')
def endpoint_certificates(item, index):
    rid = target(item, index, 'app_service')
    p = policy(index, TLS)
    roots = strings(get(p, 'approvedTrustRootSha256', list), nonempty=True)
    if any(not re.fullmatch('[0-9a-f]{64}', r) for r in roots):
        raise Unavailable('trust-root policy malformed')
    max_age = number(get(p, 'maxObservationAgeSeconds', int))
    summary = one(observations(index, 'app_service_endpoint_inventory', parent=rid), 'appId', rid)
    if not current(summary, index) or get(summary, 'exposedPortsComplete', bool) is not True or get(summary, 'certificateEndpointsComplete', bool) is not True:
        raise Unavailable('exposed certificate port inventory incomplete')
    endpoints = observations(index, 'app_service_endpoint', parent=rid)
    if set(strings(get(summary, 'endpointIds', list))) != {r['id'] for r in endpoints}:
        raise Unavailable('endpoint inventory projection differs')
    readings = observations(index, 'tls_endpoint_observation', parent=rid)
    required = [e for e in endpoints if get(e, 'exposed', bool) and get(e, 'certificateBased', bool)]
    if not required:
        return 'NOT_APPLICABLE', {'reason': 'Complete exposed-port inventory has no certificate-based endpoints'}
    bad = []
    for endpoint in required:
        host = text(get(endpoint, 'hostname', str))
        port = number(get(endpoint, 'port', int))
        if port > 65535:
            raise Unavailable('malformed exposed port')
        record = one(readings, 'endpointId', endpoint['id'])
        if get(record, 'hostname', str).casefold() != host.casefold() or get(record, 'port', int) != port:
            raise Unavailable('foreign TLS endpoint observation')
        try:
            reference_ip = ipaddress.ip_address(host)
        except ValueError:
            reference_ip = None
        if reference_ip is None:
            if get(record, 'sni', str).casefold() != host.casefold():
                raise Unavailable('foreign TLS DNS SNI observation')
        elif '%' in host or get(record, 'sni') not in (None, ''):
            # RFC 9525: SNI conveys DNS names, never an IP reference identity.
            raise Unavailable('IP TLS observation requires an unscoped IP and no SNI')
        if get(record, 'handshakeStatus', str) != 'Completed':
            raise Unavailable('TLS handshake unavailable')
        observed = instant(get(record, 'observedAt', str))
        if not 0 <= (now(index) - observed).total_seconds() <= max_age:
            raise Unavailable('TLS observation stale or future')
        chain = strings(get(record, 'presentedChainSha256', list), nonempty=True)
        if any(not re.fullmatch('[0-9a-f]{64}', fingerprint) for fingerprint in chain):
            raise Unavailable('malformed presented certificate chain')
        if get(record, 'leafSha256', str) != chain[0] or get(record, 'fullPresentedChain', bool) is not True:
            raise Unavailable('presented chain incomplete')
        if set(strings(get(record, 'validatedAgainstRootSha256', list))) != set(roots) or instant(get(record, 'validatedAt', str)) != observed:
            raise Unavailable('trust roots or validation time differs from policy/observation')
        text(get(record, '_provenance.validationEngine', str))
        validation = get(record, 'chainValidation', str)
        if validation not in ('Trusted', 'Untrusted'):
            raise Unavailable('certificate chain validation unresolved')
        root = get(record, 'trustRootSha256')
        if validation == 'Trusted' and root not in roots:
            raise Unavailable('trusted-chain root not approved')
        before = instant(get(record, 'leaf.notBefore', str))
        after = instant(get(record, 'leaf.notAfter', str))
        if before >= after:
            raise Unavailable('malformed certificate lifetime')
        if observed < before:
            raise Unavailable('certificate not-yet-valid; signed failure predicate does not cover it')
        if reference_ip is None:
            names = strings(get(record, 'leaf.subjectAlternativeNames', list))
            identity_matches = hostname_matches(host, names)
        else:
            # Untyped DNS strings cannot establish an iPAddress SAN. Require
            # the independent observer's explicit typed IP SAN projection.
            names = strings(get(record, 'leaf.subjectAlternativeIpAddresses', list))
            try:
                if any('%' in name for name in names):
                    raise ValueError('scoped IP SAN unsupported')
                presented_ips = [ipaddress.ip_address(name) for name in names]
            except ValueError as exc:
                raise Unavailable('typed IP certificate SAN malformed') from exc
            identity_matches = reference_ip in presented_ips
        if observed >= after or validation == 'Untrusted' or not identity_matches:
            bad.append(endpoint['id'])
    return result(bool(bad), invalid_certificate_endpoint_ids=bad,
                  semantics='Live TLS observations at recorded time against approved roots')


def _function_native_memory_witness(item, index, rid, wanted):
    """A bound Flex site and plan GET can only disprove approved memory."""
    if get(wanted, 'hostingModel', str) != 'FlexConsumption':
        return None
    if get(wanted, 'memoryMetric', str) != 'FlexInstanceMemoryMB':
        raise Unavailable('approved Flex instance-memory metric unresolved')
    native = one(observations(index, 'function_app_runtime_native', parent=rid), 'appId', rid)
    if get(native, 'status', str) != 'collected':
        return None
    if (get(native, 'hostingModel', str) != 'FlexConsumption'
            or get(native, 'packageType', str) != 'Code'
            or get(native, 'runtimeType', str) != 'Language'):
        raise Unavailable('native Function classification unresolved')
    metadata = get(index, 'context.metadata', dict)
    proof = get(native, '_provenance', dict)
    app_proof = get(item, '_provenance', dict)
    for field in ('credential_context_id', 'customer_context_id'):
        value = text(get(metadata, field, str))
        if get(proof, field, str) != value or get(app_proof, field, str) != value:
            raise Unavailable('native Function capture binding differs')
    tenant = text(get(metadata, 'tenant_id', str))
    tenants = get(metadata, 'subscription_tenants', dict)
    if (get(metadata, 'tenant_verified', bool) is not True
            or get(proof, 'tenant_verified', bool) is not True
            or get(proof, 'tenant_id', str).casefold() != tenant.casefold()
            or get(tenants, scope(index), str).casefold() != tenant.casefold()):
        raise Unavailable('native Function tenant binding unresolved')
    observed_text = get(native, 'observedAt', str)
    if (get(proof, 'source_operation', str) != 'Microsoft.Web/sites GET + Microsoft.Web/serverfarms GET'
            or get(proof, 'api_version', str) != '2024-11-01'
            or get(proof, 'representation', str) != 'metadata_projection'
            or get(proof, 'observed_at', str) != observed_text):
        raise Unavailable('native Function capture provenance unresolved')
    observed = instant(observed_text)
    if not 0 <= (now(index) - observed).total_seconds() <= 900:
        raise Unavailable('native Function site capture stale or future')
    source = get(native, 'source', dict)
    if (get(source, 'operation', str) != 'Microsoft.Web/sites GET'
            or get(source, 'nativePath', str) != 'properties.functionAppConfig.scaleAndConcurrency.instanceMemoryMB'
            or get(source, 'apiVersion', str) != '2024-11-01'
            or get(source, 'representation', str) != 'full'
            or get(source, 'resourceId', str).casefold() != rid.casefold()
            or get(source, 'planOperation', str) != 'Microsoft.Web/serverfarms GET'
            or get(source, 'planSkuName', str) != 'FC1'
            or get(source, 'planSkuTier', str) != 'FlexConsumption'):
        raise Unavailable('native Function source semantics unresolved')
    plan_id = text(get(source, 'planResourceId', str))
    if (not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Web/serverfarms/[^/]+', plan_id, re.I)
            or not plan_id.casefold().startswith(scope(index).casefold() + '/')
            or get(item, 'properties.serverFarmId', str).casefold() != plan_id.casefold()):
        raise Unavailable('foreign native Function plan')
    measured = number(get(native, 'memoryMB', int))
    desired = number(get(wanted, 'memoryMB', int))
    if measured <= 0 or desired <= 0:
        raise Unavailable('Function memory baseline invalid')
    if measured != desired:
        return result(True, mismatched_settings=['memoryMB'], hosting_model='FlexConsumption',
                      configured_instance_memory_mb=measured, expected_instance_memory_mb=desired,
                      unresolved_settings=['runtime', 'role', 'timeoutSeconds'],
                      semantics='Exact native Flex per-instance memory contradiction; no installed runtime proof')
    return None


@signed(FUNCTION, 'function_app_configuration', 'function_app_runtime_native', 'app_service_plan', 'subscription')
def function_settings(item, index):
    rid = target(item, index, 'app_service')
    kind = strings(get(item, 'kind', str).casefold().split(','), nonempty=True)
    if 'functionapp' not in kind:
        return 'NOT_APPLICABLE', {'reason': 'Resource is not a Function App'}
    p = policy(index, FUNCTION)
    expected = get(p, 'expectedFunctionSettings', dict)
    wanted = keyed(expected, rid, dict)
    try:
        native = _function_native_memory_witness(item, index, rid, wanted)
    except Unavailable:
        native = None
    if native is not None:
        return native
    observed = one(observations(index, 'function_app_configuration', parent=rid), 'appId', rid)
    if not current(observed, index):
        raise Unavailable('Function configuration evidence stale')
    capture = get(observed, '_provenance', dict)
    metadata = get(index, 'context.metadata', dict)
    for field in ('credential_context_id', 'customer_context_id', 'tenant_id'):
        if field in capture:
            actual = text(get(capture, field, str))
            expected_context = text(get(metadata, field, str))
            if (actual.casefold() != expected_context.casefold() if field == 'tenant_id'
                    else actual != expected_context):
                raise Unavailable('Function configuration capture binding differs')
    package = get(observed, 'packageType', str)
    runtime_type = get(observed, 'runtimeType', str)
    if package not in ('Code', 'Container') or runtime_type not in ('Language', 'OSOnly'):
        raise Unavailable('Function package/runtime classification unresolved')
    if package == 'Container' or runtime_type == 'OSOnly':
        text(get(observed, '_provenance.classificationSource', str))
        return 'NOT_APPLICABLE', {'reason': 'Proven Container package or OS-only Runtime exception'}
    p = policy(index, FUNCTION)
    expected = get(p, 'expectedFunctionSettings', dict)
    wanted = keyed(expected, rid, dict)
    hosting = get(observed, 'hostingModel', str)
    if hosting not in ('Consumption', 'FlexConsumption', 'Premium', 'Dedicated'):
        raise Unavailable('Function hosting model unresolved')
    if get(wanted, 'hostingModel', str) != hosting:
        raise Unavailable('expected hosting model differs')
    # This fact is an explicit safe projection of config/web, runtime metadata,
    # host.json, service-plan memory, and managed identity role configuration.
    # It contains values + native source paths, never a compliance boolean.
    mismatches = []
    unavailable = []
    native_negative = []
    floating_runtime = False
    for field in ('runtime', 'role', 'timeoutSeconds', 'memoryMB'):
        try:
            measured = get(observed, 'settings.' + field)
            desired = get(wanted, field)
            source = get(observed, 'sources.' + field, dict)
            text(get(source, 'operation', str)); text(get(source, 'nativePath', str))
            if get(source, 'status', str) != 'collected':
                raise Unavailable('Function hosting field unavailable')
            if field in ('runtime', 'role'):
                text(measured); text(desired)
                if field == 'runtime' and (measured.startswith('~') or measured.casefold() in ('latest', 'auto')):
                    floating_runtime = True
                    raise Unavailable('floating runtime is not a resolved version')
            else:
                number(measured); number(desired)
        except Unavailable:
            unavailable.append(field)
            continue
        if measured != desired:
            mismatches.append(field)
            # The 2024-11-01 site GET schema exposes Flex Consumption
            # instanceMemoryMB. This proves configured per-instance memory only.
            if (field == 'memoryMB' and hosting == 'FlexConsumption'
                    and source.get('operation') == 'Microsoft.Web/sites GET'
                    and source.get('nativePath') == 'properties.functionAppConfig.scaleAndConcurrency.instanceMemoryMB'
                    and source.get('apiVersion') == '2024-11-01'
                    and source.get('representation') == 'full'
                    and isinstance(source.get('resourceId'), str)
                    and source['resourceId'].casefold() == rid.casefold()):
                native_negative.append(field)
    if unavailable:
        if native_negative and not floating_runtime:
            return result(True, mismatched_settings=native_negative, hosting_model=hosting,
                          unresolved_settings=unavailable,
                          semantics='Documented configured Flex instance memory mismatch only')
        raise Unavailable('Function hosting fields unavailable')
    if get(observed, 'runtimeResolved', bool) is not True:
        raise Unavailable('Function runtime version unresolved')
    return result(bool(mismatches), mismatched_settings=mismatches, hosting_model=hosting)
