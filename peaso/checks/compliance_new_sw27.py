"""Signed Azure compliance checks over scoped snapshot and explicit policy facts.

Uncollected child reads and external observations remain UNKNOWN. The evaluator
never performs cloud calls or treats an omitted field as a negative response.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects

SPECS = {'azure.cis.latest_os_patches_vms_applied': {'category': 'vulnerability',
                                             'remediation_hint': 'Azure Update Manager > Machines: '
                                                                 'assess and install '
                                                                 'critical/security updates for '
                                                                 'the VM, then rerun assessment '
                                                                 'and verify the available '
                                                                 'critical/security count is zero.',
                                             'resource_kind': 'virtual_machine',
                                             'severity': 'high',
                                             'sha': '36263f5ae5937e46eb897ddb2f5526f035c1bca72e59cc1c8206c27dfb0f0c8c',
                                             'title': 'Apply current critical and security VM '
                                                      'patches'},
 'azure.gap.monitor_log_cluster_encrypted_with_cmk': {'category': 'encryption',
                                                      'remediation_hint': 'Azure portal > Log '
                                                                          'Analytics clusters > '
                                                                          'Encryption: Assign a '
                                                                          'managed identity and '
                                                                          'configure '
                                                                          'keyVaultProperties with '
                                                                          'a Key Vault URI and key '
                                                                          'name.',
                                                      'resource_kind': 'log_analytics_cluster',
                                                      'severity': 'medium',
                                                      'sha': 'c6b4316415a0db06755d9bad0e747251ee8868d53751041fda7a5476d74fc20f',
                                                      'title': 'Azure Monitor Logs cluster uses a '
                                                               'customer-managed key'},
 'azure.other.access_analysis_coverage': {'category': 'hardening',
                                          'remediation_hint': 'Enable the native Defender CSPM '
                                                              'capabilities that analyze '
                                                              'external/public exposure and unused '
                                                              'access in each subscription, then '
                                                              'verify assessment coverage.',
                                          'resource_kind': 'defender_setting',
                                          'severity': 'high',
                                          'sha': '25080fcff2b7ac4d8bd1369ec8fb0b3a491921262c3628194bec71bc2f560fae',
                                          'title': 'Enable exposure and access-review coverage'},
 'azure.other.gateway_vmss_autoscale': {'category': 'hardening',
                                        'remediation_hint': 'Configure native Application Gateway '
                                                            'autoscaling and verify by monitored '
                                                            'load test that capacity increases '
                                                            'within five minutes of reaching 80 '
                                                            'percent.',
                                        'resource_kind': 'autoscale_setting',
                                        'severity': 'medium',
                                        'sha': '53a52c67dc9570c57e7473821f4138f5178fb45d2f3a3b53ff8dce8fd14007e0',
                                        'title': 'Application Gateway native autoscaling is '
                                                 'configured'},
 'azure.other.incident_triage_trace': {'category': 'monitoring',
                                       'remediation_hint': 'Triage overdue New incidents, assign '
                                                           'active incidents, record severity and '
                                                           'timeline, and attach the '
                                                           'procedure-required investigation and '
                                                           'closure evidence.',
                                       'resource_kind': 'defender_incident',
                                       'severity': 'high',
                                       'sha': 'b0287173646e70e01ca0ef18b1428f73d5395ebb4b9ef2c076861aac4d29d010',
                                       'title': 'Security incidents receive recorded triage'},
 'azure.other.snapshot_sharing_scope': {'category': 'hardening',
                                        'remediation_hint': 'Set snapshot networkAccessPolicy to '
                                                            'AllowPrivate or DenyAll, disable '
                                                            'publicNetworkAccess where applicable, '
                                                            'and remove unapproved grantAccess '
                                                            'role assignments.',
                                        'resource_kind': 'disk',
                                        'severity': 'high',
                                        'sha': '0dd5b7e17a2632f5f0fc53307dc5977f54155b617a23322fa409cb796ba9883f',
                                        'title': 'Snapshot export is private and limited to '
                                                 'approved principals'},
 'azure_azure_resource_keyvault_private_endpoints_c3995a6': {'category': 'network',
                                                             'remediation_hint': 'In each scoped '
                                                                                 'VNet, create a '
                                                                                 'private endpoint '
                                                                                 'in an approved '
                                                                                 'subnet for the '
                                                                                 'specified '
                                                                                 'service and '
                                                                                 'approve its '
                                                                                 'private link '
                                                                                 'connection.',
                                                             'resource_kind': 'vnet_and_private_endpoint',
                                                             'severity': 'medium',
                                                             'sha': '18145ccaa0fd9eb68eedf523cd6fb53a020b226bde99690f8421434e644a9d39',
                                                             'title': 'a Private Endpoint for the '
                                                                      'service provided in the '
                                                                      'rule parameter is created '
                                                                      'for each Azure Virtual '
                                                                      'Network (VNet)'},
 'azure_c5_ops_13_01b': {'category': 'logging',
                         'remediation_hint': 'Enable required source diagnostics, route them to '
                                             'the approved SIEM, validate ingestion and '
                                             'correlation, and document safeguard coverage.',
                         'resource_kind': 'subscription_diagnostic_setting',
                         'severity': 'medium',
                         'sha': '6a5218af0909dc99bbd57b7847b926693c09efd1ed8bb2a726b4d9e09f6caf9b',
                         'title': 'Integrate relevant cloud and provider logs into SIEM'},
 'azure_diagnostic_setting_app_http_logs_enabled_d32e8e1': {'category': 'logging',
                                                            'remediation_hint': 'Enable the '
                                                                                'supported App '
                                                                                'Service '
                                                                                'Environment '
                                                                                'platform-log '
                                                                                'category in '
                                                                                'Diagnostic '
                                                                                'settings, send it '
                                                                                'to the approved '
                                                                                'Log Analytics '
                                                                                'workspace, and '
                                                                                'confirm arrival.',
                                                            'resource_kind': 'app_service_environment',
                                                            'severity': 'medium',
                                                            'sha': 'f26aecb8cb38af8bac61a2bd40aea16dd8981b76f24c0bd5f23676a937e42d86',
                                                            'title': 'Azure App Service '
                                                                     'Environments are configured '
                                                                     'to send logs to Azure '
                                                                     'Monitor Logs'},
 'azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf': {'category': 'hardening',
                                                                          'remediation_hint': 'Enable '
                                                                                              'Microsoft '
                                                                                              'Entra '
                                                                                              'authentication '
                                                                                              'for '
                                                                                              'each '
                                                                                              'affected '
                                                                                              'MySQL/PostgreSQL '
                                                                                              'server '
                                                                                              'and '
                                                                                              'configure '
                                                                                              'a '
                                                                                              'valid '
                                                                                              'Entra '
                                                                                              'administrator.',
                                                                          'resource_kind': 'mysql_and_postgresql_flexible_server',
                                                                          'severity': 'medium',
                                                                          'sha': 'a81ff55fd7d58df98dfcd0976eb03de10a0c61c321f0e7424fa56712a0ab1b3c',
                                                                          'title': 'MySQL and '
                                                                                   'PostgreSQL '
                                                                                   'flexible '
                                                                                   'servers have '
                                                                                   'Entra '
                                                                                   'administrators'},
 'azure_redis_cache_10_3_3_17_5912e19': {'category': 'recovery',
                                         'remediation_hint': 'Enable Premium Redis RDB persistence '
                                                             'at a supported frequency and '
                                                             'configure enough retained snapshots '
                                                             'in accessible storage to meet the '
                                                             'approved retention period; verify '
                                                             'the oldest required snapshot exists.',
                                         'resource_kind': 'redis_cache',
                                         'severity': 'medium',
                                         'sha': '60bb5a9f431a23d31573e885e8eb38de629d1502d9b4d7ad98f585e1af35474f',
                                         'title': 'Premium Redis RDB snapshot schedule spans '
                                                  'required days'},
 'azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c': {'category': 'vulnerability',
                                                                                                 'remediation_hint': 'Azure '
                                                                                                                     'portal '
                                                                                                                     '> '
                                                                                                                     'Defender '
                                                                                                                     'for '
                                                                                                                     'Cloud '
                                                                                                                     '> '
                                                                                                                     'Recommendations: '
                                                                                                                     'Remediate '
                                                                                                                     'each '
                                                                                                                     'Unhealthy '
                                                                                                                     'assessment '
                                                                                                                     'until '
                                                                                                                     'Defender '
                                                                                                                     'reports '
                                                                                                                     'Healthy.',
                                                                                                 'resource_kind': 'vm_and_security_assessment',
                                                                                                 'severity': 'high',
                                                                                                 'sha': 'fc268ea589bf3e09da45541073fa09aa825506f3d48d654b82ca4dea1b8e94a3',
                                                                                                 'title': 'Resolve '
                                                                                                          'Defender '
                                                                                                          'VM '
                                                                                                          'baseline '
                                                                                                          'findings'},
 'azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9': {'category': 'hardening',
                                                                                                  'remediation_hint': 'Storage '
                                                                                                                      'account '
                                                                                                                      '> '
                                                                                                                      'Events '
                                                                                                                      '> '
                                                                                                                      'Event '
                                                                                                                      'Subscription: '
                                                                                                                      'create '
                                                                                                                      'or '
                                                                                                                      'fix '
                                                                                                                      'a '
                                                                                                                      'subscription '
                                                                                                                      'with '
                                                                                                                      'the '
                                                                                                                      'required '
                                                                                                                      'event '
                                                                                                                      'types '
                                                                                                                      'and '
                                                                                                                      'an '
                                                                                                                      'approved '
                                                                                                                      'destination; '
                                                                                                                      'verify '
                                                                                                                      'provisioning '
                                                                                                                      'succeeds.',
                                                                                                  'resource_kind': 'eventgrid_subscription',
                                                                                                  'severity': 'medium',
                                                                                                  'sha': '39927e092677f465334ead77541f194324c18126c78c7b973cfa25b496cf64a0',
                                                                                                  'title': 'Storage '
                                                                                                           'accounts '
                                                                                                           'publish '
                                                                                                           'required '
                                                                                                           'Event '
                                                                                                           'Grid '
                                                                                                           'events'},
 'azure_vm_1_2_8_10_1bd35d0': {'category': 'hardening',
                               'remediation_hint': 'Automation account > State Configuration (DSC) '
                                                   '> Nodes: assign the intended node '
                                                   'configuration, reconnect stale nodes and '
                                                   'remediate until status Compliant with recent '
                                                   'lastSeen.',
                               'resource_kind': 'guest_configuration_assignment',
                               'severity': 'medium',
                               'sha': 'a51a90d47adaaeac16aec017c9f0610f11f5a91362e6e30039fdf938c581a4ee',
                               'title': 'Required Azure Automation DSC nodes are compliant'},
 'azure_vm_vm_ensure_using_managed_disks_11f205b': {'category': 'hardening',
                                                    'remediation_hint': 'Attach each expected disk '
                                                                        'to its assigned VM and, '
                                                                        'when required, set the '
                                                                        'attachment delete option '
                                                                        'to Delete; correct an '
                                                                        'inaccurate approved disk '
                                                                        'mapping.',
                                                    'resource_kind': 'disk_and_vm',
                                                    'severity': 'medium',
                                                    'sha': '70a6aa254c8eb2d7e86eed16833865a816daeed0085af82706f67acd5a88d34f',
                                                    'title': 'Expected managed disks are attached '
                                                             'to their assigned VMs'}}

_SUB = re.compile(r"/subscriptions/[^/]+\Z", re.I)
_RESOURCE = re.compile(r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/([^/]+/[^/]+)/[^/]+(?:/[^/]+/[^/]+)*\Z", re.I)


def _context(index):
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    if get(context, "provider", str) != "azure" or not _SUB.fullmatch(scope):
        raise Unavailable("Azure subscription authority unavailable")
    return context, scope


def _id(value, scope, resource_type=None):
    if not isinstance(value, str) or not value.casefold().startswith(scope.casefold() + "/"):
        raise Unavailable("foreign or missing ARM resource ID")
    match = _RESOURCE.fullmatch(value)
    if match is None or (resource_type and match.group(2).casefold() != resource_type.casefold()):
        raise Unavailable("malformed or wrong-type ARM resource ID")
    return value.casefold()


def _inventory(index, kind, resource_type=None, *, subscription_child=False):
    _, scope = _context(index)
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("collection scope or pagination authority unavailable: " + kind)
    env = envelopes[0]
    if (not isinstance(env, dict) or env.get("type") != kind or
            str(env.get("scope", "")).casefold() != scope.casefold()):
        raise Unavailable("foreign collection: " + kind)
    rows = complete_items(index, kind)
    native = get(env, "items", list)
    wrapped = get(index, kind, list)
    if (len(rows) != len(native) or len(rows) != len(wrapped) or
            (env.get("status") == "empty") != (len(rows) == 0)):
        raise Unavailable("collection and index disagree: " + kind)
    seen = set()
    for row, original, wrapper in zip(rows, native, wrapped):
        if (row != original or not isinstance(wrapper, dict) or wrapper.get("type") != kind or
                str(wrapper.get("scope", "")).casefold() != scope.casefold() or
                wrapper.get("data") != row):
            raise Unavailable("collection wrapper mismatch: " + kind)
        rid = get(row, "id", str)
        if subscription_child:
            if not rid.casefold().startswith(scope.casefold() + "/"):
                raise Unavailable("foreign subscription child")
            if resource_type and not re.search(r"/providers/" + re.escape(resource_type) + r"/[^/]+\Z", rid, re.I):
                raise Unavailable("wrong-type subscription child")
            identity = rid.casefold()
        else:
            identity = _id(rid, scope, resource_type)
        if identity in seen:
            raise Unavailable("duplicate resource identity: " + kind)
        seen.add(identity)
    return rows


def _member(item, rows, scope, *, subscription_child=False):
    identity = get(item, "id", str).casefold()
    if subscription_child:
        if not identity.startswith(scope.casefold() + "/"):
            raise Unavailable("foreign subscription child")
    else:
        _id(identity, scope)
    if sum(get(row, "id", str).casefold() == identity and row == item for row in rows) != 1:
        raise Unavailable("resource is not a unique member of the scoped inventory")
    return identity


def _policy(index, field, expected):
    context, scope = _context(index)
    policy = get(context, "metadata.compliance_policy.sw27", dict)
    if "scope" in policy and get(policy, "scope", str).casefold() != scope.casefold():
        raise Unavailable("sw27 approval belongs to another subscription")
    if get(policy, "status", str) != "collected":
        raise Unavailable("sw27 policy is not approved and complete")
    return get(policy, field, expected)


def _time(value):
    if not isinstance(value, str):
        raise Unavailable("missing timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed timestamp") from exc
    if parsed.tzinfo is None:
        raise Unavailable("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _now(index):
    context, _ = _context(index)
    return _time(get(context, "created_at", str))


def _status(item, field):
    state = get(item, "_coverage." + field + ".status", str)
    if state not in ("collected", "empty"):
        raise Unavailable("child fact incomplete: " + field)
    return state


def _children(item, field):
    _status(item, field)
    return list_of_objects(get(item, field, list))


def _complete_mapping(value, label):
    if not isinstance(value, dict) or not value or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v for k, v in value.items()):
        raise Unavailable("missing or malformed " + label)
    return value


def _vm_patches(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "vm", "Microsoft.Compute/virtualMachines"), scope)
    _status(item, "instanceView")
    summary = get(item, "instanceView.patchStatus.availablePatchSummary", dict)
    if get(summary, "status", str) != "Succeeded":
        return unknown("patch assessment not successful")
    age = _now(index) - _time(get(summary, "lastModifiedTime", str))
    if age < timedelta(0) or age > timedelta(days=7):
        return unknown("patch assessment stale or future dated")
    count = get(summary, "criticalAndSecurityPatchCount", int)
    if count < 0:
        return unknown("invalid patch count")
    installation = item["instanceView"].get("patchStatus", {}).get("lastInstallationSummary")
    if installation is not None:
        state = get(installation, "status", str)
        if state not in ("Succeeded", "Completed"):
            return unknown("patch installation pending or unresolved")
    reboot = item["instanceView"].get("patchStatus", {}).get("rebootPending")
    if reboot is not None and type(reboot) is not bool:
        return unknown("malformed reboot state")
    if reboot is True:
        return unknown("reboot pending")
    return result(count > 0, vm_id=item["id"], available_critical_security_patches=count)


def _cluster_cmk(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "log_analytics_cluster", "Microsoft.OperationalInsights/clusters"), scope)
    props = get(item, "properties", dict)
    key = props.get("keyVaultProperties")
    identity = item.get("identity")
    if "keyVaultProperties" in props and (key is None or key == {}):
        return result(True, cluster_id=item["id"], reason="CMK explicitly absent")
    if "identity" in item and identity is None:
        return result(True, cluster_id=item["id"], reason="managed identity explicitly absent")
    if not isinstance(key, dict) or not isinstance(identity, dict):
        return unknown("CMK or identity configuration unresolved")
    uri, name = key.get("keyVaultUri"), key.get("keyName")
    if not isinstance(uri, str) or not uri or not isinstance(name, str) or not name:
        return unknown("partial key configuration")
    kind = get(identity, "type", str)
    if kind == "None":
        return result(True, cluster_id=item["id"], reason="managed identity explicitly disabled")
    if kind not in ("SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"):
        return unknown("unrecognized identity type")
    principal = identity.get("principalId")
    users = identity.get("userAssignedIdentities")
    if not (isinstance(principal, str) and principal) and not (isinstance(users, dict) and users and all(isinstance(v, dict) and isinstance(v.get("principalId"), str) and v["principalId"] for v in users.values())):
        return unknown("identity principal unresolved")
    _status(item, "keyAccess")
    access = get(item, "keyAccess", dict)
    if get(access, "keyVaultUri", str) != uri or get(access, "keyName", str) != name:
        return unknown("key access proof does not match configured key")
    state = get(access, "status", str)
    if state not in ("allowed", "denied"):
        return unknown("key access unresolved")
    return result(state == "denied", cluster_id=item["id"], key_access=state)


def _gateway_scale(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "application_gateway", "Microsoft.Network/applicationGateways"), scope)
    observations = _children(item, "scaleObservations")
    if not observations:
        return unknown("no controlled or observed 80-percent threshold crossing")
    measured = 0
    for obs in observations:
        if get(obs, "authorized", bool) is not True:
            continue
        ratio = get(obs, "capacityRatio", float)
        if ratio < 0.8 or ratio > 1:
            continue
        crossing = _time(get(obs, "crossedAt", str))
        before = get(obs, "servingInstancesBefore", int)
        after = get(obs, "servingInstancesAfter", int)
        if before < 1 or after < 0:
            return unknown("invalid serving-instance telemetry")
        measured += 1
        scaled_at = obs.get("additionalServingAt")
        if scaled_at is None:
            until = obs.get("observedUntil")
            if until is None or _time(until) - crossing < timedelta(minutes=5):
                return unknown("five-minute serving-instance observation incomplete")
            if after > before:
                return unknown("additional serving time missing")
            return result(True, gateway_id=item["id"], threshold_crossed_at=obs["crossedAt"])
        delta = _time(scaled_at) - crossing
        if delta < timedelta(0):
            return unknown("scale-out timestamp predates threshold crossing")
        if after <= before or delta > timedelta(minutes=5):
            return result(True, gateway_id=item["id"], threshold_crossed_at=obs["crossedAt"])
    if not measured:
        return unknown("no qualifying scale observation")
    return result(False, gateway_id=item["id"], qualifying_observations=measured)


def _snapshots(item, index):
    _, scope = _context(index)
    if "id" in item:
        _id(get(item, "id", str), scope, "Microsoft.Compute/snapshots")
    rows = _inventory(index, "snapshot", "Microsoft.Compute/snapshots")
    if not rows:
        return "NOT_APPLICABLE", {"reason": "complete snapshot inventory is empty"}
    _member(item, rows, scope)
    approved = set(_policy(index, "approvedRecipientIds", list))
    if not approved or any(not isinstance(x, str) or not x for x in approved):
        raise Unavailable("recipient approval policy unresolved")
    grants = _children(item, "effectiveGrantCapableRbac")
    sas = _children(item, "activeSasGrants")
    tests = _children(item, "sharingTests")
    for row in grants + sas:
        recipient = get(row, "recipientId", str)
        if recipient not in approved:
            return result(True, snapshot_id=item["id"], unauthorized_recipient=recipient)
    denied = False
    for test in tests:
        recipient = get(test, "recipientId", str)
        state = get(test, "status", str)
        if recipient not in approved and state == "succeeded":
            return result(True, snapshot_id=item["id"], successful_unauthorized_test=recipient)
        if recipient not in approved and state == "denied" and get(test, "current", bool):
            denied = True
        elif state not in ("denied", "succeeded"):
            return unknown("sharing test outcome unresolved")
    if not denied:
        return unknown("current unauthorized negative test or deny proof absent")
    network = get(item, "properties.networkAccessPolicy", str)
    public = get(item, "properties.publicNetworkAccess", str)
    association = get(item, "properties.diskAccessId")
    if network not in ("AllowAll", "AllowPrivate", "DenyAll") or public not in ("Enabled", "Disabled"):
        return unknown("snapshot network defaults unresolved")
    if network == "AllowPrivate" and (not isinstance(association, str) or not association):
        return unknown("private snapshot Disk Access association unresolved")
    return result(False, snapshot_id=item["id"], assessed_grants=len(grants) + len(sas))


def _access_coverage(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "security_pricing", "Microsoft.Security/pricings", subscription_child=True), scope, subscription_child=True)
    if get(item, "name", str) != "CloudPosture":
        return "NOT_APPLICABLE", {"reason": "not the CloudPosture pricing resource"}
    tier = get(item, "properties.pricingTier", str)
    if tier == "Free":
        return result(True, pricing_id=item["id"], reason="CloudPosture disabled")
    if tier != "Standard":
        return unknown("unrecognized CloudPosture pricing tier")
    coverage = get(item, "analysisCoverage", dict)
    _status(item, "analysisCoverage")
    if get(coverage, "scope", str).casefold() != scope.casefold():
        return unknown("analysis coverage has foreign scope")
    states = []
    for field in ("externalPublicAccess", "unusedAccess"):
        state = get(coverage, field + ".status", str)
        if state not in ("enabled", "disabled"):
            return unknown("analysis capability unresolved")
        states.append(state)
    if "disabled" in states:
        return result(True, pricing_id=item["id"], disabled_capability=True)
    if get(coverage, "assessmentsCurrent", bool) is not True:
        return unknown("assessment coverage or provisioning unresolved")
    return result(False, pricing_id=item["id"], capabilities=states)


def _incident(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "defender_incident", "Microsoft.SecurityInsights/incidents", subscription_child=True), scope)
    policy = _policy(index, "incidentTriage", dict)
    hours = get(policy, "approvedTriageHours", int)
    required = get(policy, "requiredResponseSteps", list)
    if (type(hours) is not int or hours <= 0 or not required or
            any(not isinstance(x, str) or not x.strip() or x != x.strip() for x in required) or
            len(required) != len(set(required))):
        raise Unavailable("incident triage procedure unresolved")
    now = _now(index)
    created = _time(get(item, "properties.createdTimeUtc", str))
    window = get(policy, "observationWindowHours", int)
    if type(window) is not int or window <= 0:
        raise Unavailable("incident observation window unresolved")
    if created > now or now - created > timedelta(hours=window):
        return "NOT_APPLICABLE", {"reason": "incident outside approved observation window"}
    history = _children(item, "triageHistory")
    complete = get(item, "triageHistoryComplete", bool)
    incident_id = get(item, "id", str).casefold()
    response_steps = set()
    for row in history:
        linked = row.get("incidentId")
        if "incidentId" in row and (not isinstance(linked, str) or linked.casefold() != incident_id):
            raise Unavailable("foreign incident history row")
        kind = row.get("type")
        if kind not in ("triage", "response", "closure"):
            raise Unavailable("incident history event type unresolved")
        if "at" in row and not created <= _time(row["at"]) <= now:
            raise Unavailable("incident history event falls outside creation and capture cutoff")
        if kind == "response":
            step = get(row, "step", str)
            if not step.strip() or step != step.strip():
                raise Unavailable("response step evidence malformed")
            response_steps.add(step)
    status = get(item, "properties.status", str)
    if status not in ("New", "Active", "Closed"):
        return unknown("unrecognized incident state")
    if not complete:
        return unknown("incident history completeness unresolved")
    decisions = [row for row in history if row.get("type") == "triage"]
    if not decisions:
        if now - created > timedelta(hours=hours) and complete:
            return result(True, incident_id=item["id"], reason="overdue and untriaged")
        return unknown("triage decision history incomplete or not overdue")
    decision_times = [_time(get(row, "at", str)) for row in decisions]
    if any(stamp < created or stamp > now for stamp in decision_times):
        return unknown("triage event falls outside incident creation and capture cutoff")
    triaged = min(decision_times)
    if triaged - created > timedelta(hours=hours):
        return result(True, incident_id=item["id"], reason="triage deadline missed")
    get(item, "properties.severity", str)
    missing = set(required) - response_steps
    if missing and complete:
        return result(True, incident_id=item["id"], missing_steps=sorted(missing))
    if missing:
        return unknown("response history incomplete")
    if status == "Closed" and not any(row.get("type") == "closure" for row in history):
        return unknown("closure evidence unavailable")
    return result(False, incident_id=item["id"], triaged_at=triaged.isoformat())


def _dsc_nodes(item, index):
    _, scope = _context(index)
    nodes = _inventory(index, "automation_node", subscription_child=True)
    if "id" in item:
        _member(item, nodes, scope)
    policy = _policy(index, "dscNodes", dict)
    required = get(policy, "requiredNodeIds", list)
    age_hours = get(policy, "maxHeartbeatAgeHours", int)
    if age_hours <= 0 or any(not isinstance(x, str) or not x for x in required):
        raise Unavailable("DSC node or heartbeat policy malformed")
    if not required:
        return "NOT_APPLICABLE", {"reason": "no required DSC nodes"}
    by_id = {}
    for node in nodes:
        node_id = get(node, "properties.nodeId", str)
        if node_id in by_id:
            raise Unavailable("duplicate DSC node ID")
        by_id[node_id] = node
    now = _now(index)
    uncertain = []
    for node_id in required:
        node = by_id.get(node_id)
        if node is None:
            uncertain.append(node_id)
            continue
        age = now - _time(get(node, "properties.lastSeen", str))
        if age < timedelta(0) or age > timedelta(hours=age_hours):
            uncertain.append(node_id)
            continue
        state = get(node, "properties.status", str)
        if state == "NotCompliant":
            return result(True, node_id=node_id, status=state)
        if state != "Compliant":
            uncertain.append(node_id)
            continue
        config = node.get("properties", {}).get("nodeConfiguration")
        if config is None and "nodeConfiguration" in node.get("properties", {}):
            return result(True, node_id=node_id, reason="configuration explicitly unassigned")
        if not isinstance(config, dict) or not isinstance(config.get("name"), str):
            uncertain.append(node_id)
        elif not config["name"]:
            return result(True, node_id=node_id, reason="configuration explicitly unassigned")
    if uncertain:
        return unknown("required DSC node evidence unresolved", node_ids=sorted(uncertain))
    return result(False, required_nodes=len(required))


def _private_endpoint(item, index):
    _, scope = _context(index)
    vnets = _inventory(index, "vnet", "Microsoft.Network/virtualNetworks")
    endpoints = _inventory(index, "private_endpoint", "Microsoft.Network/privateEndpoints")
    target = _policy(index, "targetPrivateEndpointServiceType", str).casefold()
    if not re.fullmatch(r"Microsoft\.[A-Za-z0-9]+/[A-Za-z0-9]+", target, re.I):
        raise Unavailable("target service ARM type policy unresolved")
    if not vnets:
        return "NOT_APPLICABLE", {"reason": "complete scoped VNet inventory is empty"}
    _member(item, vnets, scope)
    vnet_id = item["id"].casefold()
    matched = []
    uncertain = False
    for endpoint in endpoints:
        props = get(endpoint, "properties", dict)
        subnet = get(props, "subnet.id", str).casefold()
        if not re.fullmatch(re.escape(vnet_id) + r"/subnets/[^/]+", subnet):
            continue
        for field in ("privateLinkServiceConnections", "manualPrivateLinkServiceConnections"):
            for connection in list_of_objects(get(props, field, list)):
                service = get(connection, "properties.privateLinkServiceId", str)
                service_match = _RESOURCE.fullmatch(service)
                if not service_match:
                    uncertain = True
                    continue
                if service_match.group(2).casefold() == target:
                    matched.append({"endpoint_id": endpoint["id"], "approval_status": connection.get("properties", {}).get("privateLinkServiceConnectionState", {}).get("status")})
    if matched:
        return result(False, vnet_id=item["id"], connections=matched)
    if uncertain:
        return unknown("endpoint target service type unresolved")
    return result(True, vnet_id=item["id"], reason="no endpoint for target service type")


def _ase_logs(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "app_service_environment", "Microsoft.Web/hostingEnvironments"), scope)
    approved = set(_policy(index, "approvedLogAnalyticsWorkspaceIds", list))
    if not approved or any(not isinstance(x, str) or not x for x in approved):
        raise Unavailable("approved workspace policy unresolved")
    categories = _children(item, "diagnosticCategories")
    supported = {get(row, "name", str) for row in categories if get(row, "type", str) == "Logs"}
    groups = set()
    for row in categories:
        if get(row, "type", str) != "Logs":
            continue
        for group in row.get("properties", {}).get("categoryGroups", []):
            if not isinstance(group, str):
                raise Unavailable("malformed ASE category group")
            groups.add(group)
    if not supported:
        return unknown("ASE log category support unresolved")
    settings = _children(item, "diagnosticSettings")
    configured = set()
    unresolved_group = False
    for setting in settings:
        props = get(setting, "properties", dict)
        workspace = props.get("workspaceId")
        if workspace not in approved:
            continue
        for log in list_of_objects(get(props, "logs", list)):
            name = log.get("category") or log.get("categoryGroup")
            if "categoryGroup" in log and name not in groups:
                unresolved_group = True
                continue
            if (name in supported or name in groups) and get(log, "enabled", bool):
                configured.add((workspace, name))
    if not configured:
        if unresolved_group:
            return unknown("ASE diagnostic category group support unresolved")
        return result(True, ase_id=item["id"], reason="no supported enabled category exported to approved workspace")
    deliveries = _children(item, "logDelivery")
    observed = {}
    for delivery in deliveries:
        key = (get(delivery, "workspaceId", str), get(delivery, "category", str))
        if key in observed:
            raise Unavailable("duplicate ASE delivery proof")
        observed[key] = get(delivery, "status", str)
    unresolved = False
    for workspace, name in configured:
        state = observed.get((workspace, name))
        if state == "verified":
            return result(False, ase_id=item["id"], workspace_id=workspace, category=name)
        if state != "missing":
            unresolved = True
    if unresolved:
        return unknown("workspace log delivery unresolved")
    return result(True, ase_id=item["id"], reason="all configured approved exports have proven missing delivery")


def _redis(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "redis_cache", "Microsoft.Cache/redis"), scope)
    sku = get(item, "sku.name", str)
    if sku in ("Basic", "Standard"):
        return result(True, cache_id=item["id"], reason="SKU does not support RDB backup")
    if sku != "Premium":
        return unknown("unsupported or unknown Redis SKU")
    config = get(item, "properties.redisConfiguration", dict)
    enabled = get(config, "rdb-backup-enabled", str)
    if enabled.casefold() == "false":
        return result(True, cache_id=item["id"], reason="RDB explicitly disabled")
    if enabled.casefold() != "true":
        return unknown("RDB enablement malformed")
    frequency = get(config, "rdb-backup-frequency", str)
    if frequency not in {"15", "30", "60", "360", "720", "1440"}:
        return unknown("RDB frequency unsupported or malformed")
    days = _policy(index, "minimumSnapshotSpanDays", int)
    if days <= 0:
        raise Unavailable("retention policy unresolved")
    destination = get(item, "rdbStorageDestinationId", str)
    if not destination:
        return unknown("RDB storage destination absent")
    artifacts = _children(item, "rdbSnapshots")
    now = _now(index)
    good = []
    for artifact in artifacts:
        if get(artifact, "destinationId", str) != destination:
            return unknown("snapshot destination does not match configured storage")
        if get(artifact, "readable", bool) and get(artifact, "successful", bool):
            good.append(_time(get(artifact, "createdAt", str)))
    if not good:
        return result(True, cache_id=item["id"], reason="complete artifact inventory has no successful readable snapshots")
    oldest, newest = min(good), max(good)
    if oldest > now or now - oldest < timedelta(days=days) or newest > now or now - newest > timedelta(minutes=2 * int(frequency)):
        return result(True, cache_id=item["id"], oldest_snapshot=oldest.isoformat(), newest_snapshot=newest.isoformat())
    return result(False, cache_id=item["id"], oldest_snapshot=oldest.isoformat(), newest_snapshot=newest.isoformat(), required_days=days)


def _managed_disks(item, index):
    _, scope = _context(index)
    disks = _inventory(index, "disk", "Microsoft.Compute/disks")
    vms = _inventory(index, "vm", "Microsoft.Compute/virtualMachines")
    if "id" in item:
        if any(row == item for row in vms):
            _member(item, vms, scope)
        else:
            _member(item, disks, scope)
    mapping = _policy(index, "expectedDiskVmIds", dict)
    if not mapping:
        return "NOT_APPLICABLE", {"reason": "approved disk-to-VM map explicitly empty"}
    mapping = _complete_mapping(mapping, "disk-to-VM map")
    policy = get(get(index, "context", dict), "metadata.compliance_policy.sw27", dict)
    require_delete = policy.get("deleteWithVm", False)
    if type(require_delete) is not bool:
        raise Unavailable("delete-with-VM policy malformed")
    by_disk = {row["id"].casefold(): row for row in disks}
    by_vm = {row["id"].casefold(): row for row in vms}
    for disk_id, vm_id in mapping.items():
        _id(disk_id, scope, "Microsoft.Compute/disks")
        _id(vm_id, scope, "Microsoft.Compute/virtualMachines")
        disk, vm = by_disk.get(disk_id.casefold()), by_vm.get(vm_id.casefold())
        if disk is None or vm is None:
            return result(True, missing_disk=disk_id if disk is None else None, missing_vm=vm_id if vm is None else None)
        attachments = [get(vm, "properties.storageProfile.osDisk", dict)] + list_of_objects(get(vm, "properties.storageProfile.dataDisks", list))
        matched = [attachment for attachment in attachments if isinstance(attachment.get("managedDisk"), dict) and attachment["managedDisk"].get("id", "").casefold() == disk_id.casefold()]
        if not matched:
            return result(True, disk_id=disk_id, vm_id=vm_id, reason="VM does not reference expected disk")
        if len(matched) != 1:
            return unknown("ambiguous VM disk attachment")
        shares = get(disk, "properties.maxShares", int)
        if shares < 1:
            return unknown("disk sharing semantics malformed")
        if shares == 1:
            if "managedBy" not in disk:
                return unknown("disk managedBy fact missing")
            owner = disk.get("managedBy")
            if owner is None:
                return result(True, disk_id=disk_id, reason="disk explicitly detached")
            if not isinstance(owner, str):
                return unknown("disk owner malformed")
            if owner.casefold() != vm_id.casefold():
                return result(True, disk_id=disk_id, reason="disk owner differs from assigned VM")
        else:
            owners = get(disk, "managedByExtended", list)
            if any(not isinstance(owner, str) for owner in owners):
                return unknown("shared disk owners malformed")
            if vm_id.casefold() not in {owner.casefold() for owner in owners}:
                return result(True, disk_id=disk_id, reason="shared disk omits assigned VM")
            if require_delete:
                return unknown("delete-with-VM policy conflicts with shared disk semantics")
        if require_delete:
            option = get(matched[0], "deleteOption", str)
            if option not in ("Delete", "Detach"):
                return unknown("unrecognized attachment delete option")
            if option != "Delete":
                return result(True, disk_id=disk_id, reason="attachment does not delete with VM")
    return result(False, checked_mappings=len(mapping))


def _eventgrid(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "storage_account", "Microsoft.Storage/storageAccounts"), scope)
    expected = _policy(index, "storageEventSubscriptions", dict)
    if not expected:
        return unknown("Event Grid policy input explicitly empty")
    rule = expected.get(item["id"])
    if not isinstance(rule, dict):
        return "NOT_APPLICABLE", {"reason": "account outside policy scope"}
    event_types = get(rule, "includedEventTypes", list)
    destination_type = get(rule, "destinationType", str)
    destination_id = get(rule, "destinationId", str)
    if not event_types or any(not isinstance(x, str) or not x for x in event_types) or not destination_type or not destination_id:
        raise Unavailable("Event Grid policy is empty or malformed")
    subscriptions = _children(item, "eventSubscriptions")
    uncertain = False
    failed_matching = False
    for sub in subscriptions:
        child_id = get(sub, "id", str)
        if not re.fullmatch(re.escape(item["id"]) + r"/providers/Microsoft\.EventGrid/eventSubscriptions/[^/]+", child_id, re.I):
            raise Unavailable("foreign Event Grid child identity")
        props = get(sub, "properties", dict)
        state = get(props, "provisioningState", str)
        destination = get(props, "destination", dict)
        endpoint = get(destination, "endpointType", str)
        did = destination.get("properties", {}).get("resourceId")
        types = get(props, "filter.includedEventTypes", list)
        if not types:
            uncertain = True
            continue
        if any(not isinstance(x, str) for x in types):
            uncertain = True
            continue
        if endpoint == destination_type and did == destination_id and set(event_types) <= set(types):
            if state == "Succeeded":
                return result(False, account_id=item["id"], event_subscription_id=sub.get("id"))
            if state in ("Failed", "Canceled"):
                failed_matching = True
                continue
            uncertain = True
    if uncertain:
        return unknown("Event Grid type defaults, destination or provisioning unresolved")
    if failed_matching:
        return result(True, account_id=item["id"], reason="all matching subscriptions failed provisioning")
    return result(True, account_id=item["id"], reason="required Event Grid subscription absent")


def _database_admins(item, index):
    _, scope = _context(index)
    mysql = _inventory(index, "mysql_flexible_server", "Microsoft.DBforMySQL/flexibleServers")
    postgres = _inventory(index, "postgresql_flexible_server", "Microsoft.DBforPostgreSQL/flexibleServers")
    rows = mysql + postgres
    if not rows:
        return "NOT_APPLICABLE", {"reason": "no scoped flexible servers"}
    _member(item, rows, scope)
    native = item.get("_database_native", {}).get("schema") == "native-database-arm-v1"
    mysql_native = native and "/providers/microsoft.dbformysql/flexibleservers/" in item['id'].casefold()
    if not mysql_native:
        auth = get(item, "properties.authConfig.activeDirectoryAuth", str)
        if auth == "Disabled":
            return result(True, server_id=item["id"], reason="Entra authentication disabled")
        if auth != "Enabled":
            return unknown("Entra authentication state unresolved")
    admins = _children(item, "administrators")
    if not admins:
        return result(True, server_id=item["id"], reason="complete administrator list empty")
    for admin in admins:
        if native:
            if (get(admin, 'parent_id', str).casefold() != item['id'].casefold()
                    or admin.get('_provenance', {}).get('native_database_schema') != 'native-database-arm-v1'):
                return unknown('native administrator parent or schema unavailable')
            metadata = get(index, 'context.metadata', dict)
            if (metadata.get('tenant_verified') is not True
                    or not isinstance(metadata.get('tenant_id'), str)
                    or get(admin, 'properties.tenantId', str).casefold() != metadata['tenant_id'].casefold()
                    or item['_database_native'].get('tenant_id', '').casefold() != metadata['tenant_id'].casefold()):
                return unknown('native administrator tenant authority unavailable or foreign')
            if mysql_native and get(admin, 'properties.administratorType', str) != 'ActiveDirectory':
                return unknown('MySQL administrator is not Microsoft Entra')
            principal = get(admin, 'properties.sid' if mysql_native else 'properties.objectId', str)
            expected_child = 'ActiveDirectory' if mysql_native else principal
            if admin['id'].rsplit('/', 1)[-1].casefold() != expected_child.casefold():
                return unknown('native administrator resource and principal identity differ')
        else:
            principal = get(admin, "properties.principalId", str)
        if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", principal):
            return unknown("administrator principal identity unresolved")
    return result(False, server_id=item["id"], administrators=len(admins))


def _vm_assessments(item, index):
    _, scope = _context(index)
    _member(item, _inventory(index, "vm", "Microsoft.Compute/virtualMachines"), scope)
    assessments = _inventory(index, "security_assessment", "Microsoft.Security/assessments", subscription_child=True)
    keys = _policy(index, "vmBaselineAssessmentKeys", list)
    max_age = _policy(index, "assessmentMaxAgeHours", int)
    if not keys or max_age <= 0 or any(not isinstance(x, str) or not x for x in keys):
        raise Unavailable("VM baseline assessment policy unresolved")
    vm_id = item["id"].casefold()
    by_key = {}
    for row in assessments:
        rid = get(row, "properties.resourceDetails.id", str).casefold()
        if rid != vm_id:
            continue
        key = get(row, "name", str)
        if key in by_key:
            raise Unavailable("duplicate VM assessment key")
        by_key[key] = row
    uncertain = []
    now = _now(index)
    for key in keys:
        assessment = by_key.get(key)
        if assessment is None:
            uncertain.append(key)
            continue
        age = now - _time(get(assessment, "properties.status.changedAt", str))
        if age < timedelta(0) or age > timedelta(hours=max_age):
            uncertain.append(key)
            continue
        state = get(assessment, "properties.status.code", str)
        if state == "Unhealthy":
            return result(True, vm_id=item["id"], assessment_key=key)
        if state != "Healthy":
            uncertain.append(key)
    if uncertain:
        return unknown("VM baseline assessment missing, stale or not applicable", assessment_keys=sorted(uncertain))
    return result(False, vm_id=item["id"], assessment_keys=sorted(keys))


def _siem(item, index):
    _, scope = _context(index)
    diagnostics = _inventory(index, "subscription_diagnostic_setting", "Microsoft.Insights/diagnosticSettings", subscription_child=True)
    if "id" in item:
        _member(item, diagnostics, scope, subscription_child=True)
    policy = _policy(index, "siem", dict)
    required = get(policy, "requiredSourceIds", list)
    destination = get(policy, "approvedDestinationId", str)
    if not required or not destination or any(not isinstance(x, str) or not x for x in required):
        raise Unavailable("SIEM source/destination policy unresolved")
    evidence = get(index, "context.metadata.sw27_siem_evidence", dict)
    if get(evidence, "scope", str).casefold() != scope.casefold() or get(evidence, "status", str) != "collected":
        raise Unavailable("SIEM evidence incomplete or foreign")
    sources = list_of_objects(get(evidence, "sources", list))
    by_id = {}
    for row in sources:
        key = get(row, "sourceId", str)
        if key in by_id:
            raise Unavailable("duplicate SIEM source evidence")
        by_id[key] = row
    uncertain = []
    for source_id in required:
        row = by_id.get(source_id)
        if row is None:
            uncertain.append(source_id)
            continue
        export = get(row, "exportStatus", str)
        ingestion = get(row, "ingestionStatus", str)
        if export == "missing" or ingestion == "missing":
            return result(True, source_id=source_id, reason="required SIEM export or ingestion proven missing")
        if get(row, "destinationId", str) != destination:
            if export == "verified":
                return result(True, source_id=source_id, reason="required source exported to wrong destination")
            uncertain.append(source_id)
            continue
        if export != "verified" or ingestion != "verified":
            uncertain.append(source_id)
    if uncertain:
        return unknown("SIEM source coverage unresolved", sources=uncertain)
    if get(evidence, "correlationVerified", bool) is not True or get(evidence, "incidentWorkflowVerified", bool) is not True or get(evidence, "safeguardInventoryDocumented", bool) is not True:
        return unknown("SIEM correlation, workflow or safeguard evidence unresolved")
    # The diagnostic inventory is a partial corroborating signal, not the SIEM proof.
    return result(False, verified_sources=len(required), diagnostic_settings=len(diagnostics))


_SCOPE_SOURCES = {
    "azure.cis.latest_os_patches_vms_applied": ("vm", "PASS"),
    "azure.other.gateway_vmss_autoscale": ("application_gateway", "NOT_APPLICABLE"),
    "azure.other.snapshot_sharing_scope": ("snapshot", "NOT_APPLICABLE"),
    "azure.other.access_analysis_coverage": ("security_pricing", "UNKNOWN"),
    "azure.other.incident_triage_trace": ("defender_incident", "UNKNOWN"),
    "azure_vm_1_2_8_10_1bd35d0": ("automation_node", "NOT_APPLICABLE"),
    "azure_azure_resource_keyvault_private_endpoints_c3995a6": ("vnet", "NOT_APPLICABLE"),
    "azure_vm_vm_ensure_using_managed_disks_11f205b": ("disk", "NOT_APPLICABLE"),
    "azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9": ("storage_account", "NOT_APPLICABLE"),
    "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf": ("mysql_flexible_server", "NOT_APPLICABLE"),
    "azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c": ("vm", "NOT_APPLICABLE"),
    "azure_c5_ops_13_01b": ("subscription_diagnostic_setting", "UNKNOWN"),
}


def _aggregate_scope(check_id, evaluator, index):
    source, empty_status = _SCOPE_SOURCES[check_id]
    if check_id == "azure_vm_1_2_8_10_1bd35d0":
        return evaluator(get(index, "context", dict), index)
    if check_id == "azure_vm_vm_ensure_using_managed_disks_11f205b":
        return evaluator(get(index, "context", dict), index)
    if check_id == "azure_c5_ops_13_01b":
        return evaluator(get(index, "context", dict), index)
    if check_id == "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf":
        rows = _inventory(index, "mysql_flexible_server", "Microsoft.DBforMySQL/flexibleServers") + _inventory(index, "postgresql_flexible_server", "Microsoft.DBforPostgreSQL/flexibleServers")
    else:
        child_types = {"security_pricing": "Microsoft.Security/pricings",
                       "defender_incident": "Microsoft.SecurityInsights/incidents",
                       "subscription_diagnostic_setting": "Microsoft.Insights/diagnosticSettings"}
        rows = _inventory(index, source, child_types.get(source),
                          subscription_child=source in child_types)
    if not rows:
        return (empty_status, {"reason": "complete applicable inventory is empty"}) if empty_status != "UNKNOWN" else unknown("empty inventory does not prove applicable coverage")
    outcomes = [evaluator(row, index) for row in rows]
    if check_id == "azure.other.access_analysis_coverage" and all(status == "NOT_APPLICABLE" for status, _ in outcomes):
        return unknown("CloudPosture pricing resource absent")
    for priority in ("FAIL", "UNKNOWN", "PASS", "NOT_APPLICABLE"):
        matches = [(row, evidence) for row, (status, evidence) in zip(rows, outcomes) if status == priority]
        if matches:
            return priority, {"source_kind": source, "resource_ids": [row.get("id") for row, _ in matches],
                              "results": [evidence for _, evidence in matches]}
    return unknown("no conclusive scoped result")


_EVALUATORS = {
    "azure.cis.latest_os_patches_vms_applied": (_vm_patches, ["vm"]),
    "azure.gap.monitor_log_cluster_encrypted_with_cmk": (_cluster_cmk, ["log_analytics_cluster"]),
    "azure.other.gateway_vmss_autoscale": (_gateway_scale, ["application_gateway"]),
    "azure.other.snapshot_sharing_scope": (_snapshots, ["snapshot"]),
    "azure.other.access_analysis_coverage": (_access_coverage, ["security_pricing"]),
    "azure.other.incident_triage_trace": (_incident, ["defender_incident"]),
    "azure_vm_1_2_8_10_1bd35d0": (_dsc_nodes, ["automation_node"]),
    "azure_azure_resource_keyvault_private_endpoints_c3995a6": (_private_endpoint, ["vnet", "private_endpoint"]),
    "azure_diagnostic_setting_app_http_logs_enabled_d32e8e1": (_ase_logs, ["app_service_environment"]),
    "azure_redis_cache_10_3_3_17_5912e19": (_redis, ["redis_cache"]),
    "azure_vm_vm_ensure_using_managed_disks_11f205b": (_managed_disks, ["disk", "vm"]),
    "azure_storage_account_storage_ensure_azure_services_are_trusted_to_access_is_enabled_7677ce9": (_eventgrid, ["storage_account"]),
    "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf": (_database_admins, ["mysql_flexible_server", "postgresql_flexible_server"]),
    "azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c": (_vm_assessments, ["vm", "security_assessment"]),
    "azure_c5_ops_13_01b": (_siem, ["subscription_diagnostic_setting"]),
}


def _install(check_id, evaluator, dependencies):
    spec = SPECS[check_id]
    signed_category = spec["category"]
    accepted = {"hardening", "exposure", "least_privilege", "iam_graph", "network"}

    target = "scope" if check_id in _SCOPE_SOURCES else "resource"

    @register(check_id, "azure", signed_category if signed_category in accepted else "hardening",
              spec["resource_kind"], spec["title"], spec["severity"], "CM-6",
              spec["remediation_hint"], target=target, dependencies=dependencies)
    def check(item, index):
        if target == "scope" and "id" not in item:
            return _aggregate_scope(check_id, evaluator, index)
        return evaluator(item, index)

    if signed_category not in accepted:
        CHECKS[-1] = replace(CHECKS[-1], category=signed_category)
    return check


EVALUATORS = {check_id: _install(check_id, *data) for check_id, data in _EVALUATORS.items()}
IDS = tuple(_EVALUATORS)
SPEC_SHA256 = {check_id: spec["sha"] for check_id, spec in SPECS.items()}
