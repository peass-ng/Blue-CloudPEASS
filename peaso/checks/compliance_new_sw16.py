"""Signed sw16 Azure compliance evaluators over complete, scoped snapshot facts.

Normalized evidence contracts are documented in sw16-collector-requests.md.
All checks aggregate their declared dependencies within one authorized scope.
No cloud calls, key material, tokens, or active probes are used.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, guard

META = {'azure_disk_10_3_3_12_174f526': {'provider': 'azure',
                                  'resource_kind': 'disk_and_backup_instance',
                                  'severity': 'medium',
                                  'category': 'recovery',
                                  'title': 'Protect managed disks with Azure Backup',
                                  'remediation_hint': 'Backup center > Backup instances: configure Azure '
                                                      'Disk Backup in a Backup vault for each disk and '
                                                      'verify ProtectionConfigured state.',
                                  'proposed_spec_sha256': '45cf128dac55fb36e598a7bbd0e5d0bb15b0d6e0f3c04b74e6ba8366e0eebd94'},
 'azure_storage_account_10_3_3_24_61d5e36': {'provider': 'azure',
                                             'resource_kind': 'storage_account_and_backup_instance',
                                             'severity': 'medium',
                                             'category': 'recovery',
                                             'title': 'Back up scoped Blob containers',
                                             'remediation_hint': 'Add each required Blob container to the '
                                                                 'backup instance selection or enable '
                                                                 'auto-protection with rules that include '
                                                                 'it; verify the instance is '
                                                                 'ProtectionConfigured.',
                                             'proposed_spec_sha256': 'f33338f58d30cfe132832d0d8db0dd1f363ad77ddd473f6cd2b4ec69a609dcc3'},
 'azure_search_service_10_6_3_27_ba08488': {'provider': 'azure',
                                            'resource_kind': 'search_service',
                                            'severity': 'medium',
                                            'category': 'hardening',
                                            'title': 'Azure AI Search permits Entra ID authentication',
                                            'remediation_hint': 'Azure AI Search > Settings > '
                                                                'Keys/Authentication: enable Microsoft Entra '
                                                                'RBAC authentication (aadOrApiKey) or '
                                                                'disable local API-key authentication.',
                                            'proposed_spec_sha256': '8092c00b624f1a904d3194c3ca98a263669551ff797149c9293d001fe7767e8d'},
 'azure_pci_3_7_4_5': {'provider': 'azure',
                       'resource_kind': 'policy_assignment',
                       'severity': 'medium',
                       'category': 'hardening',
                       'title': 'Required Key Vault keys rotate within the approved interval',
                       'remediation_hint': 'Configure automatic Rotate for each required Key Vault key, '
                                           'assign the enforcing Azure Policy at the effective scope without '
                                           'exemptions, and grant the rotation identity the required '
                                           'key-management permissions.',
                       'proposed_spec_sha256': '6a3e0a9c380d3db167e365901c0b078ebd56816e7b2ad0d1ee2dab2d1ea74e09'},
 'azure_c5_ops_05_04ac': {'provider': 'azure',
                          'resource_kind': 'security_contact',
                          'severity': 'medium',
                          'category': 'hardening',
                          'title': 'Enable Defender security contact alert emails',
                          'remediation_hint': 'Configure automatic deviation reporting to the designated '
                                              'experts and retain delivery, assessment and disposition '
                                              'timestamps for each deviation.',
                          'proposed_spec_sha256': '5a9509d0187451edfe73bcf16234a51b365fd9e911d77b1058c56acba1b32ed7'},
 'azure_c5_cry_09_02b': {'provider': 'azure',
                         'resource_kind': 'key_vault_key',
                         'severity': 'medium',
                         'category': 'encryption',
                         'title': 'Required Key Vault keys have bounded valid lifetimes',
                         'remediation_hint': 'Set activation and expiration on required Key Vault key '
                                             'versions to an approved bounded lifetime; record provisioning '
                                             'authorization and identity checks for CRY-09.01B.',
                         'proposed_spec_sha256': '11900c02217fde149dcceadf989acdd7919743687b5b06e4afb6c8e4e1fd6844'},
 'azure.cis.monitor_resource_logging_services_support_it': {'provider': 'azure',
                                                            'resource_kind': 'azure_diagnostic_eligible_resource',
                                                            'severity': 'medium',
                                                            'category': 'logging',
                                                            'title': 'Supported Azure resources export '
                                                                     'diagnostic logs',
                                                            'remediation_hint': 'Azure portal > Monitor > '
                                                                                'Diagnostic settings: Add a '
                                                                                'diagnostic setting with an '
                                                                                'enabled log category and a '
                                                                                'workspace, storage, or '
                                                                                'Event Hub sink.',
                                                            'proposed_spec_sha256': 'fca3562274da9a9f2af7c61608024ac5c2f0b6d06f71335d2ebcc38872223862'},
 'azure.cis.intune_logs_captured_sent_log_analytics': {'provider': 'azure',
                                                       'resource_kind': 'intune_diagnostic_setting',
                                                       'severity': 'medium',
                                                       'category': 'logging',
                                                       'title': 'Ensure that Intune logs are captured and '
                                                                'sent to Log Analytics',
                                                       'remediation_hint': 'In Intune admin center > Tenant '
                                                                           'administration > Diagnostics '
                                                                           'settings, route the required '
                                                                           'AuditLogs, OperationalLogs, '
                                                                           'DeviceComplianceOrg and '
                                                                           'IntuneDevices categories to an '
                                                                           'approved Log Analytics '
                                                                           'workspace.',
                                                       'proposed_spec_sha256': '8bea845b90eaf5ad589c66db9d0beca204c52f40adb2d7ff550d3648877b1e74'},
 'azure.gap.iot_hub_encrypted_with_cmk': {'provider': 'azure',
                                          'resource_kind': 'iot_dps',
                                          'severity': 'medium',
                                          'category': 'encryption',
                                          'title': 'IoT Device Provisioning Service CMK policy is compliant',
                                          'remediation_hint': 'Azure portal > Policy > Assignments: assign '
                                                              'the IoT DPS CMK Audit policy; configure DPS '
                                                              'customer-managed encryption and trigger a new '
                                                              'policy evaluation.',
                                          'proposed_spec_sha256': 'fbcff9fc39564b09407b9d16d9956e6c897f5d9c323ccf9ba87c7a9635069bf9'}}
IDS = tuple(META)
PROPOSED_SPEC_SHA256 = {key: value["proposed_spec_sha256"] for key, value in META.items()}

_ARM = re.compile(r'/subscriptions/[A-Za-z0-9._-]+(?:/resourceGroups/[^/?#\x00-\x20]+)?/providers/[A-Za-z0-9.]+(?:/[^/?#\x00-\x20]+){2,}', re.I)
_SCOPE = re.compile(r'/(subscriptions|tenants)/[A-Za-z0-9._-]+', re.I)
_KEY = re.compile(r'https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/[A-Za-z0-9-]+(?:/[A-Za-z0-9-]+)?')
_ACCEPTED = {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'}


def signed(identifier, *dependencies):
    meta = META[identifier]
    def decorate(function):
        register(identifier, 'azure', meta['category'] if meta['category'] in _ACCEPTED else 'hardening',
                 meta['resource_kind'], meta['title'], meta['severity'], 'CM-6',
                 meta['remediation_hint'], target='scope', dependencies=dependencies,
                 allow_incomplete_failure=(identifier == 'azure_pci_3_7_4_5'))(function)
        # The legacy decorator accepts fewer categories than the signed proposals.
        position = next(i for i, check in enumerate(CHECKS) if check.id == identifier)
        CHECKS[position] = replace(CHECKS[position], category=meta['category'])
        return function
    return decorate


def _scope(index, *, tenant=False):
    context = get(index, 'context', dict)
    scope = get(context, 'scope', str)
    match = _SCOPE.fullmatch(scope)
    if (get(context, 'provider', str) != 'azure' or not match or
            match.group(1).casefold() != ('tenants' if tenant else 'subscriptions')):
        raise Unavailable('Azure scope/provider authority unavailable')
    return scope.casefold()


def _arm(value, scope=None, type_path=None):
    if not isinstance(value, str) or not _ARM.fullmatch(value):
        raise Unavailable('malformed ARM resource identity')
    identity = value.casefold()
    suffix = re.split('/providers/', identity, flags=re.I)[-1].split('/')
    if len(suffix) < 3 or len(suffix[1:]) % 2:
        raise Unavailable('malformed ARM type/name segments')
    if scope and not identity.startswith(scope + '/'):
        raise Unavailable('foreign resource scope')
    if type_path and not re.search('/providers/' + re.escape(type_path.casefold()) + '/[^/]+$', identity):
        raise Unavailable('unexpected ARM resource type')
    return identity


def _strings(value, *, nonempty=True):
    if (not isinstance(value, list) or (nonempty and not value) or
            any(not isinstance(v, str) or not v or v.strip() != v for v in value) or
            len(set(value)) != len(value)):
        raise Unavailable('missing, malformed or duplicate string policy/list')
    return value


def _rows(index, kind, *, tenant=False, mode='arm'):
    scope = _scope(index, tenant=tenant)
    envelopes = get(index, 'collections', dict).get(kind)
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or envelopes[0].get('type') != kind or
            str(envelopes[0].get('scope', '')).casefold() != scope):
        raise Unavailable('missing or foreign scoped collection: ' + kind)
    rows = complete_items(index, kind)
    envelope = envelopes[0]
    if envelope.get('status') == 'empty' and rows:
        raise Unavailable('contradictory empty inventory')
    if 'items' in envelope and get(envelope, 'items', list) != rows:
        raise Unavailable('inventory differs from collection authority')
    wrappers = get(index, kind, list)
    identities = set()
    for row, wrapper in zip(rows, wrappers):
        guard(row)
        if (get(wrapper, 'type', str) != kind or
                get(wrapper, 'scope', str).casefold() != scope or
                wrapper.get('provider', 'azure') != 'azure'):
            raise Unavailable('foreign snapshot resource wrapper')
        identity = get(row, 'id', str)
        if mode == 'arm':
            identity = _arm(identity, scope)
        elif mode == 'key':
            if not _KEY.fullmatch(identity):
                raise Unavailable('malformed Key Vault key identity')
            if get(row, 'scope_id', str).casefold() != scope:
                raise Unavailable('foreign key scope')
        else:
            if not identity or get(row, 'scope_id', str).casefold() != scope:
                raise Unavailable('foreign or malformed evidence identity')
        if identity in identities:
            raise Unavailable('duplicate evidence/resource identity')
        identities.add(identity)
    return rows


def _covered(row, field):
    status = get(row, '_coverage.' + field + '.status', str)
    value = get(row, field, list)
    if status not in ('collected', 'empty') or (status == 'empty' and value):
        raise Unavailable('incomplete or contradictory embedded inventory: ' + field)
    return list_of_objects(value)


def _full(row):
    proof = get(row, '_provenance', dict)
    if (get(proof, 'read_only', bool) is not True or
            get(proof, 'representation', str) != 'full' or not get(proof, 'source_operation', str)):
        raise Unavailable('complete read-only evidence provenance unavailable')


def _policy(index, identifier, *, tenant=False):
    policies = get(index, 'context.metadata.compliance_policy.sw16', dict)
    if identifier not in policies:
        raise Unavailable('owner policy unreadable')
    selected = {'value': policies[identifier]}
    if identifier in policies.get('_coverage', {}):
        selected['_coverage'] = {'value': policies['_coverage'][identifier]}
    policy = get(selected, 'value', dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str).casefold() != _scope(index, tenant=tenant):
        raise Unavailable('owner policy missing or foreign')
    return policy


def _definition(value):
    if isinstance(value, str) and re.fullmatch(r'/providers/Microsoft\.Authorization/policyDefinitions/[^/?#\x00-\x20]+', value, re.I):
        return value.casefold()
    return _arm(value, type_path='Microsoft.Authorization/policyDefinitions')


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable('timestamp unavailable')
    try:
        instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc
    if instant.tzinfo is None:
        raise Unavailable('timestamp timezone unavailable')
    return instant.astimezone(timezone.utc)


def _now(index):
    return _instant(get(index, 'context.created_at', str))


def _positive(value):
    if type(value) is not int or value <= 0:
        raise Unavailable('positive integer policy threshold unavailable')
    return value


def _unique_join(rows, field, identity):
    matches = [row for row in rows if get(row, field, str).casefold() == identity.casefold()]
    if len(matches) != 1:
        raise Unavailable('missing or ambiguous evidence join: ' + field)
    return matches[0]


def _backup(index):
    scope = _scope(index)
    vaults = _rows(index, 'backup_vault')
    instances = _rows(index, 'backup_instance')
    vault_ids = {_arm(get(v, 'id', str), scope, 'Microsoft.DataProtection/backupVaults') for v in vaults}
    envelope = index['collections']['backup_instance'][0]
    covered = _strings(get(envelope, 'covered_parent_ids', list), nonempty=False)
    if {_arm(v, scope, 'Microsoft.DataProtection/backupVaults') for v in covered} != vault_ids:
        raise Unavailable('incomplete backup vault/instance scope')
    for row in instances:
        parent = _arm(get(row, 'parent_id', str), scope, 'Microsoft.DataProtection/backupVaults')
        identity = get(row, 'id', str).casefold()
        if parent not in vault_ids or not re.fullmatch(re.escape(parent) + '/backupinstances/[^/]+', identity):
            raise Unavailable('foreign backup instance or vault')
        _arm(get(row, 'properties.dataSourceInfo.resourceID', str), scope)
        _full(row)
    return instances


def _protection(row, scope):
    policy = get(row, 'properties.policyInfo.policyId', str)
    state = get(row, 'properties.currentProtectionState', str)
    if policy:
        _arm(policy, scope)
        parent = get(row, 'parent_id', str).casefold()
        if not re.fullmatch(re.escape(parent) + '/backuppolicies/[^/]+', policy.casefold()):
            raise Unavailable('foreign backup policy')
    if state not in {'ProtectionConfigured', 'NotProtected', 'ProtectionStopped', 'ProtectionError'}:
        raise Unavailable('transient or unknown backup protection state')
    if state == 'ProtectionConfigured' and not policy:
        raise Unavailable('active protection has no resolved policy')
    return state == 'ProtectionConfigured'


@signed(IDS[0], 'disk', 'backup_vault', 'backup_instance')
def disk_backup(item, index):
    disks = _rows(index, 'disk')
    instances = _backup(index)
    bad = []
    for disk in disks:
        rid = _arm(get(disk, 'id', str), _scope(index), 'Microsoft.Compute/disks')
        matches = [row for row in instances if get(row, 'properties.dataSourceInfo.resourceID', str).casefold() == rid]
        if len(matches) > 1:
            raise Unavailable('ambiguous disk backup join')
        if not matches or not _protection(matches[0], _scope(index)):
            bad.append(rid)
    if not disks:
        return 'NOT_APPLICABLE', {'reason': 'complete disk inventory is empty'}
    return result(bool(bad), unprotected_disk_ids=bad, disk_count=len(disks))


@signed(IDS[1], 'storage_account', 'backup_vault', 'backup_instance')
def blob_backup(item, index):
    accounts = _rows(index, 'storage_account')
    instances = _backup(index)
    bad, count = [], 0
    for account in accounts:
        rid = _arm(get(account, 'id', str), _scope(index), 'Microsoft.Storage/storageAccounts')
        containers = _covered(account, 'blobContainers')
        names, container_ids = set(), set()
        for container in containers:
            name = get(container, 'name', str)
            cid = _arm(get(container, 'id', str), _scope(index))
            if (not name or name != name.casefold() or name in names or cid in container_ids or
                    cid != rid + '/blobservices/default/containers/' + name):
                raise Unavailable('malformed, foreign or duplicate Blob container')
            names.add(name)
            container_ids.add(cid)
        count += len(names)
        matches = [row for row in instances if get(row, 'properties.dataSourceInfo.resourceID', str).casefold() == rid]
        if len(matches) > 1:
            raise Unavailable('ambiguous Blob backup instance join')
        if not names:
            continue
        if not matches:
            bad.extend(rid + '/' + name for name in sorted(names))
            continue
        row = matches[0]
        active = _protection(row, _scope(index))
        selection = _covered(row, 'containerSelectionEvidence')
        if len(selection) != 1:
            raise Unavailable('Blob selection evidence missing or ambiguous')
        evidence = selection[0]
        if get(evidence, 'backupInstanceId', str).casefold() != get(row, 'id', str).casefold():
            raise Unavailable('foreign Blob selection evidence')
        mode = get(evidence, 'mode', str)
        if mode == 'Explicit':
            params = list_of_objects(get(row, 'properties.policyInfo.policyParameters.backupDatasourceParametersList', list))
            chosen = set()
            for param in params:
                if get(param, 'objectType', str) != 'BlobBackupDatasourceParameters':
                    raise Unavailable('unsupported Blob datasource selection type')
                chosen.update(_strings(get(param, 'containersList', list), nonempty=False))
        elif mode == 'Automatic':
            _full(evidence)
            if not get(evidence, 'documentedApi', str) or not get(evidence, 'policyId', str):
                raise Unavailable('automatic selection policy unresolved')
            if get(evidence, 'policyId', str).casefold() != get(row, 'properties.policyInfo.policyId', str).casefold():
                raise Unavailable('automatic selection policy differs from instance')
            resolved = _covered(evidence, 'containerDecisions')
            decisions = {}
            for decision in resolved:
                name = get(decision, 'containerName', str)
                if name not in names or name in decisions:
                    raise Unavailable('foreign or duplicate automatic selection decision')
                decisions[name] = get(decision, 'included', bool)
            if set(decisions) != names:
                raise Unavailable('automatic selection does not cover exact container inventory')
            chosen = {name for name, included in decisions.items() if included}
        else:
            raise Unavailable('unresolved container selection mode')
        bad.extend(rid + '/' + name for name in sorted(names) if not active or name not in chosen)
    if not count:
        return 'NOT_APPLICABLE', {'reason': 'complete scoped Blob container inventory is empty'}
    return result(bool(bad), uncovered_containers=bad, container_count=count)


@signed(IDS[2], 'search_service')
def search_access(item, index):
    from fnmatch import fnmatchcase
    services = _rows(index, 'search_service')
    policy = _policy(index, IDS[2])
    requirements = list_of_objects(get(policy, 'services', list))
    wanted = {}
    for requirement in requirements:
        rid = _arm(get(requirement, 'resourceId', str), _scope(index), 'Microsoft.Search/searchServices')
        if rid in wanted:
            raise Unavailable('duplicate Search service owner policy')
        wanted[rid] = requirement
    actual = {_arm(get(service, 'id', str), _scope(index), 'Microsoft.Search/searchServices') for service in services}
    if set(wanted) != actual:
        raise Unavailable('Search policy does not cover complete service scope')
    bad, assessed = [], 0
    read_action = 'microsoft.search/searchservices/indexes/documents/read'
    elevate_action = 'microsoft.search/searchservices/indexes/contentsecurity/elevatedoperations/read'
    for service in services:
        rid = get(service, 'id', str).casefold()
        requirement = wanted[rid]
        required = set(_strings(get(requirement, 'requiredIndexes', list)))
        granularity = get(requirement, 'granularity', str)
        if granularity not in ('Index', 'Document'):
            raise Unavailable('required Search access granularity unresolved')
        approved = set(_strings(get(requirement, 'approvedPrincipalIds', list)))
        indexes = _covered(service, 'indexes')
        grants = _covered(service, 'effectiveGrants')
        paths = _covered(service, 'queryPaths')
        indexed = {}
        for row in indexes:
            _full(row)
            if get(row, 'serviceId', str).casefold() != rid:
                raise Unavailable('foreign Search index')
            name = get(row, 'name', str)
            if not name or name in indexed:
                raise Unavailable('duplicate or malformed Search index')
            indexed[name] = row
        if not required <= set(indexed):
            raise Unavailable('policy-required Search index missing')
        local_disabled = get(service, 'properties.disableLocalAuth', bool)
        granted, granted_principals, elevated = set(), set(), set()
        for grant in grants:
            _full(grant)
            if get(grant, 'serviceId', str).casefold() != rid:
                raise Unavailable('foreign Search access grant')
            scope = get(grant, 'scope', str).casefold()
            if scope != _scope(index) and not re.fullmatch(re.escape(_scope(index)) + '/resourcegroups/[^/?#\x00-\x20]+', scope):
                _arm(scope, _scope(index))
            principal = get(grant, 'principalId', str)
            if not principal or principal.strip() != principal:
                raise Unavailable('Search grant principal identity unavailable')
            _arm(get(grant, 'roleDefinitionId', str), type_path='Microsoft.Authorization/roleDefinitions')
            assignment_id = _arm(get(grant, 'assignmentId', str), _scope(index), 'Microsoft.Authorization/roleAssignments')
            if assignment_id != scope + '/providers/microsoft.authorization/roleassignments/' + assignment_id.rsplit('/', 1)[-1]:
                raise Unavailable('Search assignment identity does not match grant scope')
            condition = get(grant, 'condition')
            if condition not in (None, ''):
                raise Unavailable('Search grant condition semantics unresolved')
            actions = _strings(get(grant, 'dataActions', list), nonempty=False)
            denied = _strings(get(grant, 'notDataActions', list), nonempty=False)
            can_query = (any(fnmatchcase(read_action, a.casefold()) for a in actions) and
                         not any(fnmatchcase(read_action, a.casefold()) for a in denied))
            can_elevate = (any(fnmatchcase(elevate_action, a.casefold()) for a in actions) and
                           not any(fnmatchcase(elevate_action, a.casefold()) for a in denied))
            broad = scope == rid or rid.startswith(scope.rstrip('/') + '/')
            scoped_name = scope[len(rid + '/indexes/'):] if scope.startswith(rid + '/indexes/') else None
            if not broad and scoped_name not in indexed:
                raise Unavailable('unresolved or foreign effective Search grant scope')
            if can_elevate:
                elevated.update((name, principal) for name in (required if broad else {scoped_name}) if name in required)
            if not can_query:
                continue
            if scope == rid or rid.startswith(scope.rstrip('/') + '/'):
                bad.append({'service': rid, 'reason': 'broader data-plane role bypasses index boundary'})
            elif scope.startswith(rid + '/indexes/') and scope[len(rid + '/indexes/'):] in indexed:
                name = scope[len(rid + '/indexes/'):]
                if name not in required:
                    continue
                if principal not in approved:
                    bad.append({'index': name, 'reason': 'unapproved data-plane principal'})
                else:
                    granted.add(name)
                    granted_principals.add((name, principal))
            else:
                raise Unavailable('unresolved or foreign effective Search grant scope')
        if granularity == 'Document':
            for name, principal in sorted(elevated & granted_principals):
                bad.append({'index': name, 'principal': principal, 'reason': 'elevated read can bypass document permission filters'})
        seen_paths, seen_ids = set(), set()
        for path in paths:
            _full(path)
            if get(path, 'serviceId', str).casefold() != rid:
                raise Unavailable('foreign Search query path')
            name = get(path, 'indexName', str)
            pid = get(path, 'id', str)
            if name not in indexed or not pid or pid in seen_ids:
                raise Unavailable('malformed or duplicate Search query path')
            seen_ids.add(pid)
            mechanism = get(path, 'authentication', str)
            if mechanism not in ('Entra', 'ApiKey'):
                raise Unavailable('unmeasured Search query authorization mechanism')
            principal = get(path, 'principalId', str)
            if not principal or principal.strip() != principal:
                raise Unavailable('Search query principal identity unavailable')
            authorized = get(path, 'authorized', bool)
            if mechanism == 'ApiKey' and local_disabled:
                raise Unavailable('API-key path conflicts with disabled local authentication')
            if name not in required:
                continue
            seen_paths.add(name)
            if mechanism == 'ApiKey' or principal not in approved or not authorized:
                bad.append({'index': name, 'query_path': pid, 'reason': 'query path violates required boundary'})
            if mechanism == 'Entra' and (name, principal) not in granted_principals:
                bad.append({'index': name, 'query_path': pid, 'reason': 'query principal lacks approved index-scoped RBAC'})
            if granularity == 'Document' and not get(path, 'permissionFiltering', bool):
                bad.append({'index': name, 'query_path': pid, 'reason': 'document permission filtering bypassed'})
        if seen_paths != required:
            raise Unavailable('required Search query-path inventory unresolved')
        if not local_disabled and not any(get(p, 'authentication', str) == 'ApiKey' for p in paths):
            raise Unavailable('enabled API-key bypass paths unmeasured')
        for name in required:
            assessed += 1
            if name not in granted:
                bad.append({'index': name, 'reason': 'approved index-scoped query RBAC absent'})
            if granularity == 'Document':
                row = indexed[name]
                option = get(row, 'permissionFilterOption', str)
                if option not in ('enabled', 'disabled'):
                    raise Unavailable('Search permissionFilterOption unrecognized')
                fields = list_of_objects(get(row, 'fields', list))
                expected = get(requirement, 'requiredPermissionFilterFields', dict)
                if not expected or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v for k, v in expected.items()):
                    raise Unavailable('required document permission fields unresolved')
                by_name = {}
                for field in fields:
                    field_name = get(field, 'name', str)
                    if field_name in by_name:
                        raise Unavailable('duplicate Search field')
                    by_name[field_name] = field
                missing = option == 'disabled'
                for field_name, field_kind in expected.items():
                    if field_name not in by_name:
                        missing = True
                    else:
                        field = by_name[field_name]
                        missing |= get(field, 'permissionFilter', str) != field_kind or not get(field, 'filterable', bool)
                if missing:
                    bad.append({'index': name, 'reason': 'required document permission metadata absent'})
    if not services:
        return 'NOT_APPLICABLE', {'reason': 'complete Search service inventory is empty'}
    return result(bool(bad), violations=bad, index_count=assessed)


def _duration(value):
    # Calendar intervals compare as calendar months, fixed intervals as seconds.
    # Cross-family comparisons remain unresolved instead of assuming month length.
    if not isinstance(value, str):
        raise Unavailable('malformed rotation interval')
    match = re.fullmatch(r'P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?', value)
    if not match or not any(match.groups()):
        raise Unavailable('unsupported ISO-8601 rotation interval')
    years, months, days, hours, minutes, seconds = [int(v or 0) for v in match.groups()]
    calendar = years * 12 + months
    fixed = days * 86400 + hours * 3600 + minutes * 60 + seconds
    if bool(calendar) == bool(fixed):
        raise Unavailable('zero or mixed calendar/fixed rotation interval')
    return ('calendar', calendar) if calendar else ('fixed', fixed)


@signed(IDS[3], 'key_rotation_evidence')
def key_rotation(item, index):
    policy = _policy(index, IDS[3])
    required = _strings(get(policy, 'requiredKeyIds', list))
    if any(not _KEY.fullmatch(key) or len(urlsplit(key).path.strip('/').split('/')) != 2 for key in required):
        raise Unavailable('required unversioned key scope malformed')
    approved = _duration(get(policy, 'maxRotationInterval', str))
    definition = _definition(get(policy, 'rotationPolicyDefinitionId', str))
    rows, partial = _rotation_inventory(index)
    bad, unresolved = [], []
    for key in required:
        try:
            row = _unique_join(rows, 'keyId', key)
            _full(row)
            rotation = get(row, 'rotationPolicy', dict)
            _full(rotation)
            if get(rotation, 'keyId', str) != key:
                raise Unavailable('foreign key rotation policy')
            vault = _arm(get(row, 'vaultId', str), _scope(index), 'Microsoft.KeyVault/vaults')
            arm_key = _arm(get(row, 'armKeyId', str), _scope(index))
            if arm_key != vault + '/keys/' + urlsplit(key).path.rsplit('/', 1)[-1].casefold():
                raise Unavailable('rotation key ARM identity unresolved')
            origin = 'https://' + urlsplit(key).netloc
            if (get(row, 'vaultUri', str).rstrip('/') != origin or
                    urlsplit(key).hostname.casefold() != vault.rsplit('/', 1)[-1] + '.vault.azure.net'):
                raise Unavailable('rotation key data-plane authority unresolved')
            actions = list_of_objects(get(rotation, 'lifetimeActions', list))
            rotations = []
            for action in actions:
                kind = get(action, 'action.type', str)
                if kind not in ('Rotate', 'Notify'):
                    raise Unavailable('unknown key lifetime action')
                trigger = get(action, 'trigger', dict)
                if kind == 'Notify':
                    # A malformed or unreadable notification is not a complete
                    # native response proving that automatic rotation is absent.
                    if set(trigger) != {'timeBeforeExpiry'}:
                        raise Unavailable('notification trigger malformed')
                    _duration(get(trigger, 'timeBeforeExpiry', str))
                if kind == 'Rotate':
                    if 'timeAfterCreate' not in trigger or 'timeBeforeExpiry' in trigger:
                        raise Unavailable('expiry-relative rotation cannot prove approved interval')
                    interval = _duration(get(trigger, 'timeAfterCreate', str))
                    if interval[0] != approved[0]:
                        raise Unavailable('incomparable rotation interval families')
                    rotations.append(interval[1])
            # A fully read, exact-key policy can independently prove a violation.
            # Missing enforcement/permission evidence cannot restore a missing or
            # over-limit Rotate action. It still prevents PASS below.
            if not rotations or min(rotations) > approved[1]:
                return result(True, noncompliant_key_ids=[key], required_key_count=len(required),
                              reason='required key has no Rotate action within the approved interval')
            if partial:
                unresolved.append({'key_id': key, 'reason': 'native policy alone does not prove complete enforcement/rights'})
                continue
            assignments = _covered(row, 'enforcementAssignments')
            enforced = False
            for assignment in assignments:
                _full(assignment)
                if get(assignment, 'keyId', str) != key:
                    raise Unavailable('foreign key enforcement evidence')
                assignment_id = _arm(get(assignment, 'assignmentId', str), _scope(index),
                                     'Microsoft.Authorization/policyAssignments')
                if _definition(get(assignment, 'definitionId', str)) != definition:
                    raise Unavailable('unresolved rotation enforcement definition')
                assignment_scope = get(assignment, 'scope', str).casefold()
                if assignment_scope not in (_scope(index), vault, arm_key):
                    raise Unavailable('rotation assignment scope unresolved')
                if (not re.fullmatch(re.escape(assignment_scope) +
                        r'/providers/microsoft\.authorization/policyassignments/[^/?#%\\\x00-\x20]+', assignment_id)
                        or assignment_id.rsplit('/', 1)[-1] in ('.', '..')):
                    raise Unavailable('rotation assignment identity differs from its effective scope')
                effect = get(assignment, 'effect', str)
                if effect not in ('Deny', 'Modify', 'DeployIfNotExists', 'Audit', 'Disabled'):
                    raise Unavailable('unsupported rotation enforcement effect')
                mode = get(assignment, 'enforcementMode', str)
                if mode not in ('Default', 'DoNotEnforce'):
                    raise Unavailable('unknown policy enforcement mode')
                parameters = get(assignment, 'parameters', dict)
                interval = _duration(get(parameters, 'rotationInterval', str))
                if interval[0] != approved[0]:
                    raise Unavailable('enforcement rotation duration incomparable')
                exempt = get(assignment, 'exempt', bool)
                matches = get(assignment, 'conditionsMatch', bool)
                automatic = get(assignment, 'enforcesAutomaticRotation', bool)
                enforced |= (effect in ('Deny', 'Modify', 'DeployIfNotExists') and mode == 'Default' and
                             not exempt and matches and
                             automatic and interval[1] <= approved[1])
            identities = _covered(row, 'rotationIdentities')
            permitted = False
            for identity in identities:
                _full(identity)
                if get(identity, 'keyId', str) != key or not get(identity, 'principalId', str):
                    raise Unavailable('foreign or malformed key rotation identity')
                permissions = set(_strings(get(identity, 'effectivePermissions', list), nonempty=False))
                permitted |= {'keys/rotate', 'keys/getrotationpolicy', 'keys/setrotationpolicy'} <= permissions
            if not rotations or min(rotations) > approved[1] or not enforced or not permitted:
                bad.append(key)
        except Unavailable as exc:
            unresolved.append({'key_id': key, 'reason': str(exc)})
    if bad:
        return result(True, noncompliant_key_ids=bad, required_key_count=len(required))
    if partial or unresolved:
        return unknown('required key rotation evidence incomplete', unresolved_keys=unresolved)
    return result(False, noncompliant_key_ids=[], required_key_count=len(required))


def _rotation_inventory(index):
    """Partial facts can prove only a native policy violation, never compliance."""
    kind, scope = 'key_rotation_evidence', _scope(index)
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1 or envelopes[0].get('status') != 'partial':
        return _rows(index, kind, mode='evidence'), False
    envelope = envelopes[0]
    if get(envelope, 'type', str) != kind or get(envelope, 'scope', str).casefold() != scope:
        raise Unavailable('partial native rotation scope unavailable')
    rows = list_of_objects(get(envelope, 'items', list))
    wrappers = list_of_objects(get(index, kind, list))
    if len(rows) != len(wrappers):
        raise Unavailable('partial native rotation index differs from collection')
    vaults = {_arm(get(v, 'id', str), scope, 'Microsoft.KeyVault/vaults'): v for v in _rows(index, 'vault')}
    seen = set()
    from peaso.collectors.azure_key_rotation_evidence_native import _actions
    for row, wrapper in zip(rows, wrappers):
        if (get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str).casefold() != scope
                or wrapper.get('provider', 'azure') != 'azure' or get(wrapper, 'data', dict) != row
                or get(row, 'scope_id', str).casefold() != scope):
            raise Unavailable('partial native rotation wrapper is foreign')
        key = get(row, 'keyId', str)
        if not _KEY.fullmatch(key) or len(urlsplit(key).path.strip('/').split('/')) != 2:
            raise Unavailable('partial native rotation key identity malformed')
        vault = _arm(get(row, 'vaultId', str), scope, 'Microsoft.KeyVault/vaults')
        arm_key = _arm(get(row, 'armKeyId', str), scope)
        if (vault not in vaults or arm_key != vault + '/keys/' + urlsplit(key).path.rsplit('/', 1)[-1].casefold()
                or get(row, 'id', str).casefold() != arm_key + '/rotation-evidence' or key.casefold() in seen):
            raise Unavailable('partial native rotation key/vault association unresolved')
        seen.add(key.casefold())
        origin = 'https://' + urlsplit(key).netloc
        if (urlsplit(key).hostname.casefold() != vault.rsplit('/', 1)[-1] + '.vault.azure.net'
                or get(row, 'vaultUri', str).rstrip('/') != origin
                or get(vaults[vault], 'properties.vaultUri', str).rstrip('/') != origin):
            raise Unavailable('partial native rotation data-plane authority differs')
        rotation = get(row, 'rotationPolicy', dict)
        _full(row); _full(rotation)
        proof = get(row, '_provenance', dict)
        if (get(rotation, 'keyId', str) != key or get(rotation, '_provenance', dict) != proof
                or get(proof, 'source_operation', str) != 'keys/list+keys/rotationpolicy/get'
                or get(proof, 'adapter_version', str) != 'key_rotation_native_v1'
                or get(proof, 'projection', str) != 'current_rotation_policy_only'
                or get(proof, 'request_uri', str) != key + '/rotationpolicy'
                or get(proof, 'vault_inventory_complete', bool) is not True
                or get(proof, 'parent_inventory_complete', bool) is not True):
            raise Unavailable('partial native rotation provenance unavailable')
        actions = get(rotation, 'lifetimeActions', list)
        if actions != _actions(actions):
            raise Unavailable('partial native rotation policy is not a native projection')
    return rows, True


@signed(IDS[4], 'operational_deviation_evidence')
def deviation_response(item, index):
    policy = _policy(index, IDS[4])
    specifications = set(_strings(get(policy, 'requiredSpecificationIds', list)))
    experts = set(_strings(get(policy, 'authorizedExpertIds', list)))
    threshold = _positive(get(policy, 'immediateResponseSeconds', int))
    start = _instant(get(policy, 'windowStart', str))
    end = _instant(get(policy, 'windowEnd', str))
    if start >= end or end > _now(index):
        raise Unavailable('deviation assessment window invalid')
    rows = _rows(index, 'operational_deviation_evidence', mode='evidence')
    if len(rows) != 1:
        raise Unavailable('deviation detection/export evidence missing or ambiguous')
    capture = rows[0]
    _full(capture)
    scope = _scope(index)
    export_id = get(capture, 'id', str)
    specification_source = get(policy, 'specificationSourceId', str)
    proof = get(capture, '_provenance', dict)
    captured = _instant(get(capture, 'capturedAt', str))
    if (not specification_source or get(capture, 'specificationSourceId', str) != specification_source
            or _instant(get(proof, 'observed_at', str)) != captured
            or not end <= captured <= _now(index)):
        raise Unavailable('deviation export source or capture authority unresolved')
    if _instant(get(capture, 'windowStart', str)) != start or _instant(get(capture, 'windowEnd', str)) != end:
        raise Unavailable('deviation export does not cover required window')
    covered = set(_strings(get(capture, 'detectedSpecificationIds', list)))
    if not specifications <= covered:
        raise Unavailable('detection does not cover applicable specifications')
    events = _covered(capture, 'events')
    if not events:
        return unknown('empty deviation window lacks independent continuous detection/export proof')
    bad, seen, relevant = [], set(), []
    for event in events:
        _full(event)
        event_proof = get(event, '_provenance', dict)
        if (get(event, 'scope_id', str).casefold() != scope
                or get(event, 'exportId', str) != export_id
                or get(event, 'specificationSourceId', str) != specification_source
                or get(event_proof, 'source_operation', str) != get(proof, 'source_operation', str)
                or _instant(get(event_proof, 'observed_at', str)) != captured):
            raise Unavailable('deviation event not bound to approved export, scope or capture')
        eid = get(event, 'id', str)
        spec = get(event, 'specificationId', str)
        detected = _instant(get(event, 'detectedAt', str))
        if not eid or eid in seen or spec not in covered or not start <= detected < end:
            raise Unavailable('duplicate, foreign or out-of-window deviation event')
        seen.add(eid)
        if spec in specifications:
            relevant.append((event, eid, detected))
    if not relevant:
        return unknown('no event for an applicable specification; continuous detection/export proof unavailable')
    unresolved = False
    for event, eid, detected in relevant:
        def observed(field, kind):
            nonlocal unresolved
            try:
                return get(event, field, kind)
            except Unavailable as exc:
                if not str(exc).startswith('missing fact:'):
                    raise
                unresolved = True
                return None

        automatic = observed('automaticNotification', bool)
        delivered = observed('delivered', bool)
        recipient_ids = observed('recipientExpertIds', list)
        recipients = set(_strings(recipient_ids, nonempty=False)) if recipient_ids is not None else None
        assessed = observed('assessed', bool)
        deficient = (automatic is False or delivered is False or assessed is False
                     or (recipients is not None and recipients != experts))
        if delivered is True:
            sent_at = observed('deliveredAt', str)
            if sent_at is not None:
                sent = _instant(sent_at)
                if sent < detected or sent > captured:
                    raise Unavailable('notification time contradicts detected event or export capture')
                deficient |= (sent - detected).total_seconds() > threshold
        if assessed is True:
            assessed_at = observed('assessedAt', str)
            if assessed_at is not None:
                assessment = _instant(assessed_at)
                if assessment < detected or assessment > captured:
                    raise Unavailable('assessment time contradicts detected event or export capture')
                deficient |= (assessment - detected).total_seconds() > threshold
            disposition = observed('disposition', str)
            if disposition is not None and not disposition.strip():
                unresolved = True
        if deficient:
            bad.append(eid)
    if bad:
        return result(True, deviation_count=len(relevant), deficient_event_ids=bad)
    if unresolved:
        raise Unavailable('deviation response detail unresolved')
    return result(False, deviation_count=len(relevant), deficient_event_ids=[])


@signed(IDS[5], 'key_vault_key')
def key_lifetime_and_provisioning(item, index):
    policy = _policy(index, IDS[5])
    required = _strings(get(policy, 'requiredKeyIds', list))
    if any(not _KEY.fullmatch(key) or len(urlsplit(key).path.strip('/').split('/')) != 2 for key in required):
        raise Unavailable('required key scope malformed')
    rows = _rows(index, 'key_vault_key')
    now = int(_now(index).timestamp())
    bad, version_count = [], 0
    for key in required:
        row = _unique_join(rows, 'data_plane_id', key)
        _full(row)
        parent = _arm(get(row, 'parent_id', str), _scope(index), 'Microsoft.KeyVault/vaults')
        arm_key = _arm(get(row, 'id', str), _scope(index))
        if arm_key != parent + '/keys/' + urlsplit(key).path.rsplit('/', 1)[-1].casefold():
            raise Unavailable('required key ARM/data-plane identity mismatch')
        if get(row, 'vaultUri', str).rstrip('/') != 'https://' + urlsplit(key).netloc:
            raise Unavailable('required key vault endpoint authority unavailable')
        versions = _covered(row, 'versions')
        if not versions:
            raise Unavailable('required key versions unresolved')
        seen = set()
        for version in versions:
            _full(version)
            kid = get(version, 'kid', str)
            if not _KEY.fullmatch(kid) or not kid.startswith(key + '/') or kid in seen:
                raise Unavailable('foreign or duplicate key version')
            seen.add(kid)
            attributes = get(version, 'attributes', dict)
            if not get(attributes, 'enabled', bool):
                continue
            version_count += 1
            record = get(version, 'provisioningRecord', dict)
            _full(record)
            if get(record, 'keyVersionId', str) != kid:
                raise Unavailable('foreign provisioning record')
            secure = get(record, 'secureProvisioning', bool)
            identity = get(record, 'identityVerified', bool)
            authorized = get(record, 'authorized', bool)
            verified_at = _instant(get(record, 'identityVerifiedAt', str))
            authorized_at = _instant(get(record, 'authorizedAt', str))
            provisioned_at = _instant(get(record, 'provisionedAt', str))
            activated_at = _instant(get(record, 'activatedAt', str))
            if max(verified_at, authorized_at, provisioned_at, activated_at) > _now(index):
                raise Unavailable('provisioning record timestamp is future')
            chronology = verified_at <= provisioned_at and authorized_at <= provisioned_at <= activated_at
            # Missing/invalid dates in a full readable version are positive
            # evidence of an unbounded lifetime, as required by the signed spec.
            for field in ('nbf', 'exp'):
                if field in attributes.get('_coverage', {}):
                    get(attributes, field)
            nbf, exp = attributes.get('nbf'), attributes.get('exp')
            dates_valid = type(nbf) is int and type(exp) is int and nbf <= now < exp
            if not dates_valid or not secure or not identity or not authorized or not chronology:
                bad.append(kid)
    return result(bool(bad), deficient_key_version_ids=bad, enabled_version_count=version_count)


def _log_routes(resource, requirement, *, intune=False):
    parent = get(resource, 'id', str)
    categories = _covered(resource, 'categories')
    supported, groups, category_ids = set(), {}, set()
    for category in categories:
        _full(category)
        cid = get(category, 'id', str).casefold()
        if (get(category, 'parent_id', str).casefold() != parent.casefold() or
                not re.fullmatch(re.escape(parent.casefold()) + '/providers/microsoft.insights/diagnosticsettingscategories/[^/]+', cid)
                and not (intune and re.fullmatch('/providers/microsoft.intune/diagnosticsettingscategories/[^/]+', cid))):
            raise Unavailable('foreign diagnostic category discovery')
        name = get(category, 'name', str)
        if not name or cid in category_ids or cid.rsplit('/', 1)[-1] != name.casefold():
            raise Unavailable('duplicate or malformed diagnostic category')
        category_ids.add(cid)
        kind = get(category, 'properties.categoryType', str)
        if kind not in ('Logs', 'Metrics'):
            raise Unavailable('unknown diagnostic category type')
        if kind != 'Logs':
            continue
        if name in supported:
            raise Unavailable('duplicate supported log category')
        supported.add(name)
        # Intune 2017 category discovery has no categoryGroups field.
        # Explicit named routes need no inferred group membership.
        category_properties = get(category, 'properties', dict)
        if intune and 'categoryGroups' not in category_properties:
            continue
        for group in _strings(get(category, 'properties.categoryGroups', list), nonempty=False):
            groups.setdefault(group, set()).add(name)
    if not supported and not intune:
        return [], 0
    settings = _covered(resource, 'diagnosticSettings')
    if intune:
        required = set(_strings(get(requirement, 'requiredIntuneCategories', list)))
        sinks = {_arm(v, type_path='Microsoft.OperationalInsights/workspaces')
                 for v in _strings(get(requirement, 'approvedWorkspaceIds', list))}
        minimum = None
    else:
        required = set(_strings(get(requirement, 'requiredCategories', list), nonempty=False))
        for group in _strings(get(requirement, 'requiredCategoryGroups', list), nonempty=False):
            if group not in groups:
                raise Unavailable('required diagnostic group expansion unresolved')
            required.update(groups[group])
        if supported and not required:
            raise Unavailable('required supported category policy empty')
        sinks = {_arm(v) for v in _strings(get(requirement, 'approvedSinkIds', list))}
        minimum = _positive(get(requirement, 'minRetentionDays', int))
    if not required <= supported:
        raise Unavailable('required diagnostic category support unresolved')
    routed, setting_ids = set(), set()
    for setting in settings:
        _full(setting)
        sid = get(setting, 'id', str).casefold()
        expected = (r'/providers/microsoft.intune/diagnosticsettings/[^/]+' if intune else
                    re.escape(parent.casefold()) + '/providers/microsoft.insights/diagnosticsettings/[^/]+')
        if (not re.fullmatch(expected, sid) or sid in setting_ids or
                get(setting, 'parent_id', str).casefold() != parent.casefold()):
            raise Unavailable('foreign or duplicate diagnostic setting')
        setting_ids.add(sid)
        properties = get(setting, 'properties', dict)
        logs = list_of_objects(get(properties, 'logs', list))
        destinations = set()
        for field, resource_type in (('workspaceId', 'Microsoft.OperationalInsights/workspaces'),
                                      ('storageAccountId', 'Microsoft.Storage/storageAccounts'),
                                      ('eventHubAuthorizationRuleId', None)):
            # A full setting GET permits the documented absent optional sink.
            if field not in properties and field not in properties.get('_coverage', {}):
                continue
            value = get(properties, field)
            if value is None or value == '':
                continue
            destination = _arm(value, type_path=resource_type)
            if field == 'eventHubAuthorizationRuleId' and not re.fullmatch(
                    r'/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft.eventhub/namespaces/[^/]+/(?:eventhubs/[^/]+/)?authorizationrules/[^/]+', destination):
                raise Unavailable('malformed diagnostic Event Hub destination')
            if not intune or field == 'workspaceId':
                destinations.add(destination)
        approved = destinations & sinks
        seen_routes = set()
        for log in logs:
            enabled = get(log, 'enabled', bool)
            category = get(log, 'category') if 'category' in log or 'category' in log.get('_coverage', {}) else None
            group = get(log, 'categoryGroup') if 'categoryGroup' in log or 'categoryGroup' in log.get('_coverage', {}) else None
            if bool(category) == bool(group) or (category is not None and not isinstance(category, str)) or (group is not None and not isinstance(group, str)):
                raise Unavailable('ambiguous diagnostic log category/group route')
            if category:
                if category not in supported:
                    raise Unavailable('diagnostic category not proven supported')
                covered = {category}
            else:
                if group not in groups:
                    raise Unavailable('diagnostic group membership unresolved')
                covered = groups[group]
            route_identity = (category, group)
            if route_identity in seen_routes:
                raise Unavailable('duplicate diagnostic route')
            seen_routes.add(route_identity)
            if not enabled or not approved:
                continue
            if intune:
                routed.update(covered)
            else:
                evidence = _covered(setting, 'retentionEvidence')
                indexed = {}
                for retention in evidence:
                    _full(retention)
                    if get(retention, 'settingId', str).casefold() != sid:
                        raise Unavailable('foreign diagnostic retention evidence')
                    sink = _arm(get(retention, 'sinkId', str))
                    name = get(retention, 'category', str)
                    if sink not in destinations or name not in supported or (sink, name) in indexed:
                        raise Unavailable('unresolved or duplicate sink/category retention')
                    if not get(retention, 'sourceId', str):
                        raise Unavailable('retention source configuration unresolved')
                    days = get(retention, 'retentionDays', int)
                    if days < 0:
                        raise Unavailable('unknown diagnostic retention value')
                    indexed[sink, name] = days
                for name in covered & required:
                    values = [indexed[sink, name] for sink in approved if (sink, name) in indexed]
                    if not values:
                        raise Unavailable('effective category/sink retention unresolved')
                    # Normalized zero denotes verified unlimited retention.
                    if any(days == 0 or days >= minimum for days in values):
                        routed.add(name)
    return sorted(required - routed), len(supported)


@signed(IDS[6], 'azure_diagnostic_eligible_resource')
def resource_logging(item, index):
    resources = _rows(index, 'azure_diagnostic_eligible_resource')
    if not resources:
        return 'NOT_APPLICABLE', {'reason': 'complete resource scope is empty'}
    policy = _policy(index, IDS[6])
    requirements = list_of_objects(get(policy, 'resources', list))
    bad, supported_count = [], 0
    actual_ids = {get(resource, 'id', str).casefold() for resource in resources}
    policy_ids = [_arm(get(row, 'resourceId', str), _scope(index)) for row in requirements]
    if len(policy_ids) != len(set(policy_ids)) or set(policy_ids) != actual_ids:
        raise Unavailable('diagnostic owner policy resource scope incomplete or foreign')
    for resource in resources:
        rid = get(resource, 'id', str)
        requirement = _unique_join(requirements, 'resourceId', rid)
        missing, supported = _log_routes(resource, requirement)
        supported_count += supported
        if missing:
            bad.append({'resource_id': rid, 'missing_categories': missing})
    if not supported_count:
        return 'NOT_APPLICABLE', {'reason': 'complete discovery exposes no Logs categories'}
    return result(bool(bad), missing_routes=bad, resource_count=len(resources))


@signed(IDS[7], 'intune_diagnostic_setting')
def intune_logging(item, index):
    # This kind is a tenant aggregate, so an empty settings LIST is still
    # represented by one row containing diagnosticSettings=[].
    rows = _rows(index, 'intune_diagnostic_setting', tenant=True, mode='evidence')
    if len(rows) != 1 or get(rows[0], 'id', str).casefold() != '/providers/microsoft.intune':
        raise Unavailable('complete Intune tenant diagnostic aggregate unavailable')
    missing, supported = _log_routes(rows[0], _policy(index, IDS[7], tenant=True), intune=True)
    return result(bool(missing), missing_categories=missing, supported_category_count=supported)


@signed(IDS[8], 'iot_dps', 'azure_policy_state', 'azure_policy_assignment_evidence')
def dps_cmk(item, index):
    resources = _rows(index, 'iot_dps')
    if not resources:
        return 'NOT_APPLICABLE', {'reason': 'complete DPS inventory is empty'}
    policy = _policy(index, IDS[8])
    definition = _definition(get(policy, 'assignedDefinitionId', str))
    max_age = _positive(get(policy, 'maxPolicyStateAge', int))
    now = _now(index)
    states = _rows(index, 'azure_policy_state', mode='evidence')
    assignments = _rows(index, 'azure_policy_assignment_evidence')
    resolved = {}
    for assignment in assignments:
        _full(assignment)
        aid = get(assignment, 'id', str).casefold()
        properties = get(assignment, 'properties', dict)
        assigned_definition = _definition(get(properties, 'policyDefinitionId', str))
        scope = get(properties, 'scope', str).casefold()
        if scope != _scope(index) and not scope.startswith(_scope(index) + '/'):
            raise Unavailable('policy assignment scope foreign or unresolved')
        effect = get(assignment, 'effectiveEffect', str)
        if effect not in ('Audit', 'Deny', 'Disabled'):
            raise Unavailable('DPS CMK policy effect unsupported')
        parameters = get(properties, 'parameters', dict)
        verified = get(assignment, 'effectiveParameters', dict)
        parameters_verified = get(assignment, 'parametersVerified', bool)
        if parameters != verified or not parameters_verified:
            raise Unavailable('DPS CMK effective parameters unresolved')
        if 'effect' in verified and get(verified, 'effect.value', str) != effect:
            raise Unavailable('DPS effect conflicts with effective parameters')
        definition_fact = get(assignment, 'definition', dict)
        _full(definition_fact)
        if _definition(get(definition_fact, 'id', str)) != assigned_definition:
            raise Unavailable('DPS policy definition unresolved')
        rule_effect = get(definition_fact, 'properties.policyRule.then.effect', str)
        if rule_effect != effect and rule_effect != "[parameters('effect')]":
            raise Unavailable('DPS policy definition effect unresolved')
        mode = get(properties, 'enforcementMode', str)
        if mode not in ('Default', 'DoNotEnforce'):
            raise Unavailable('unknown DPS assignment enforcement mode')
        exemptions = _covered(assignment, 'exemptions')
        for exemption in exemptions:
            _full(exemption)
            _arm(get(exemption, 'resourceId', str), _scope(index))
            if get(exemption, 'policyAssignmentId', str).casefold() != aid:
                raise Unavailable('foreign policy exemption')
            get(exemption, 'active', bool)
        active = get(assignment, 'active', bool)
        if assigned_definition == definition:
            if effect == 'Disabled' or mode != 'Default' or not active:
                raise Unavailable('DPS CMK assignment inactive, Disabled or not enforcing')
            resolved[aid] = assignment
    bad = []
    for resource in resources:
        rid = _arm(get(resource, 'id', str), _scope(index), 'Microsoft.Devices/provisioningServices')
        candidates = []
        for state in states:
            _full(state)
            if get(state, '_provenance.source_operation', str) != 'policyStates/latest/queryResults':
                raise Unavailable('latest policy-state query provenance unavailable')
            state_resource = _arm(get(state, 'resourceId', str), _scope(index))
            state_definition = _definition(get(state, 'policyDefinitionId', str))
            aid = _arm(get(state, 'policyAssignmentId', str), _scope(index))
            if state_resource != rid or state_definition != definition:
                continue
            assignment = resolved.get(aid)
            if assignment is None:
                raise Unavailable('DPS policy state assignment unresolved')
            assignment_scope = get(assignment, 'properties.scope', str).casefold()
            if rid != assignment_scope and not rid.startswith(assignment_scope.rstrip('/') + '/'):
                raise Unavailable('DPS policy assignment does not cover exact resource')
            if any(get(exemption, 'active', bool) and
                   (rid == get(exemption, 'resourceId', str).casefold() or
                    rid.startswith(get(exemption, 'resourceId', str).casefold().rstrip('/') + '/'))
                   for exemption in assignment['exemptions']):
                raise Unavailable('DPS resource exempt from CMK policy')
            instant = _instant(get(state, 'timestamp', str))
            age = (now - instant).total_seconds()
            if age < 0 or age > max_age:
                raise Unavailable('DPS policy state stale or future')
            compliance = get(state, 'complianceState', str)
            if compliance not in ('Compliant', 'NonCompliant'):
                raise Unavailable('DPS policy compliance state unresolved')
            candidates.append(compliance)
        if len(candidates) != 1:
            raise Unavailable('DPS latest state absent, duplicate or conflicting')
        if candidates[0] == 'NonCompliant':
            bad.append(rid)
    return result(bool(bad), noncompliant_dps_ids=bad, resource_count=len(resources))

# Intune is a tenant-level ARM provider, bound to the verified tenant.
intune_logging.evaluation_scope = "tenant"
