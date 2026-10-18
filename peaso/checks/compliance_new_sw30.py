"""Signed Azure compliance checks, evaluated only from complete scoped snapshot facts."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, optional, list_of_objects, full_representation

SPECS = {'azure.gap.kubernetes_cluster_upgraded_with_non_vulnerable_version': {'category': 'vulnerability',
                                                                       'proposed_spec_sha256': 'a88d4ed4247b6071112b6de33048c7bd96d6d5671f54c95cacc8af953337471e',
                                                                       'provider': 'azure',
                                                                       'remediation_hint': 'Upgrade '
                                                                                           'the '
                                                                                           'AKS '
                                                                                           'cluster '
                                                                                           'to a '
                                                                                           'supported '
                                                                                           'patched '
                                                                                           'version '
                                                                                           'that '
                                                                                           'meets '
                                                                                           'the '
                                                                                           'CVE-2019-9946 '
                                                                                           'floor '
                                                                                           'and '
                                                                                           'current '
                                                                                           'Microsoft '
                                                                                           'security '
                                                                                           'advisories.',
                                                                       'resource_kind': 'aks_cluster',
                                                                       'severity': 'medium',
                                                                       'title': 'Kubernetes '
                                                                                'Services should '
                                                                                'be upgraded to a '
                                                                                'non-vulnerable '
                                                                                'Kubernetes '
                                                                                'version'},
 'azure.other.admin_network_separation': {'category': 'network',
                                          'proposed_spec_sha256': '77d8b9549436ca5384abd11461685fa3d56f368ea49b9b066175e9273e8cc556',
                                          'provider': 'azure',
                                          'remediation_hint': 'Restrict admin-to-application paths '
                                                              'in subnet and NIC NSGs; also '
                                                              'document environment and '
                                                              'administration-system separation '
                                                              'outside this network check.',
                                          'resource_kind': 'nsg',
                                          'severity': 'high',
                                          'title': 'Administrative subnet access is limited to '
                                                   'approved ports'},
 'azure.other.monitor_external_lateral_access': {'category': 'hardening',
                                                 'proposed_spec_sha256': 'fde0bd43dafcaa9e017a6ec31a3d94e8f950efadfa909fbcf1bfde016c0a339d',
                                                 'provider': 'azure',
                                                 'remediation_hint': 'Limit monitor identity RBAC '
                                                                     'to required scopes and '
                                                                     'narrow NSG/route access to '
                                                                     'approvedDestinations and '
                                                                     'approvedPorts; verify '
                                                                     'effective access and routes.',
                                                 'resource_kind': 'nsg',
                                                 'severity': 'high',
                                                 'title': 'Monitoring identities reach only '
                                                          'approved internal destinations'},
 'azure.other.nsg_internet_https_restricted': {'category': 'network',
                                               'proposed_spec_sha256': '3b973a8ea12ca50535bdcd7396cde69d07b9eace581c571f2b904ebe4d6fd2e5',
                                               'provider': 'azure',
                                               'remediation_hint': 'Restrict effective HTTP and '
                                                                   'HTTPS ingress to approved '
                                                                   'sources with correctly '
                                                                   'prioritized NSG rules.',
                                               'resource_kind': 'nsg',
                                               'severity': 'high',
                                               'title': 'NSG restricts internet HTTPS ingress'},
 'azure_aks_cluster_10_2_1_1_17_885658f': {'category': 'logging',
                                           'proposed_spec_sha256': '815b503949e3ceab9efc00bddbd4b1efd032d2d6cf2ac65ebc4522dbeebb774c',
                                           'provider': 'azure',
                                           'remediation_hint': 'On each AKS cluster, enable all '
                                                               'supported diagnostic log types (or '
                                                               'allLogs) and route them to a valid '
                                                               'destination; verify every category '
                                                               'is covered.',
                                           'resource_kind': 'aks_cluster',
                                           'severity': 'medium',
                                           'title': 'AKS cluster exports Azure Monitor diagnostic '
                                                    'logs'},
 'azure_aks_cluster_6_3_3_4_98a0b2c': {'category': 'hardening',
                                       'proposed_spec_sha256': '1114fd52566d9df2936bb2aefb0d88427ed33cd20226cf3a58bb06c24ac88d8f',
                                       'provider': 'azure',
                                       'remediation_hint': 'AKS cluster > Kubernetes version > '
                                                           'Upgrade: choose a region-supported '
                                                           'version newer than the policy '
                                                           'oldestVersionSupported threshold.',
                                       'resource_kind': 'aks_cluster',
                                       'severity': 'medium',
                                       'title': 'AKS cluster runs a currently supported Kubernetes '
                                                'version'},
 'azure_aks_cluster_7_2_1_6_93c4fab': {'category': 'least_privilege',
                                       'proposed_spec_sha256': '73c7215c9dcdd4ea93d17bf29353c8a02e57cfef668bd60e61e20e825cd32003',
                                       'provider': 'azure',
                                       'remediation_hint': 'Set securityContext.privileged=false '
                                                           'or omit it on all regular, init and '
                                                           'ephemeral container templates; apply '
                                                           'Pod Security restricted admission to '
                                                           'prevent recurrence.',
                                       'resource_kind': 'aks_cluster',
                                       'severity': 'high',
                                       'title': 'AKS pods do not run privileged containers'},
 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524': {'category': 'hardening',
                                                        'proposed_spec_sha256': 'bdabfa2293eaa7c88cc0c6069e44f1d21f79a204501af7ecbf05582650dfbb60',
                                                        'provider': 'azure',
                                                        'remediation_hint': 'Azure portal > '
                                                                            'Kubernetes services > '
                                                                            'Workloads: Set a '
                                                                            'nonzero runAsUser on '
                                                                            'each pod or container '
                                                                            'securityContext.',
                                                        'resource_kind': 'aks_cluster',
                                                        'severity': 'medium',
                                                        'title': 'AKS pod containers run as an '
                                                                 'explicit non-root user'},
 'azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3': {'category': 'encryption',
                                                        'proposed_spec_sha256': 'f082c9187e12b7beb05f4f2eeb508aa633806c7187e9f8f08dee7fc25b6b032a',
                                                        'provider': 'azure',
                                                        'remediation_hint': 'AKS cluster > '
                                                                            'Security '
                                                                            'configuration: enable '
                                                                            'Azure Key Vault KMS, '
                                                                            'assign an accessible '
                                                                            'Key Vault key ID and '
                                                                            'grant the cluster '
                                                                            'identity required key '
                                                                            'permissions.',
                                                        'resource_kind': 'aks_cluster',
                                                        'severity': 'high',
                                                        'title': 'AKS secrets encryption uses '
                                                                 'Azure Key Vault KMS'},
 'azure_pci_1_3_1_33': {'category': 'hardening',
                        'proposed_spec_sha256': 'e57920a71756c9aa5cf31a0890763a6f665955154010377e82c43c35cde932da',
                        'provider': 'azure',
                        'remediation_hint': 'Synapse workspace > Networking > Private endpoint '
                                            'connections: create a private endpoint for the SQL '
                                            'endpoint subresource, approve it and configure '
                                            'private DNS.',
                        'resource_kind': 'synapse_workspace',
                        'severity': 'medium',
                        'title': 'Use private endpoints for Synapse SQL pools'},
 'azure_pci_3_5_1_29': {'category': 'encryption',
                        'proposed_spec_sha256': 'fcb7cc11e3700ca3d57f25db3c4d0674ad2bfeb4dcbe3aaafae20279382a3c6e',
                        'provider': 'azure',
                        'remediation_hint': 'Synapse workspace > Encryption: enable '
                                            'customer-managed key, select an approved Key Vault '
                                            'key, grant access, and verify CMK status Consistent.',
                        'resource_kind': 'synapse_workspace',
                        'severity': 'medium',
                        'title': 'Synapse workspaces use an approved customer-managed key'},
 'azure_storage_account_sqlserver_auditing_enabled_e4e4b28': {'category': 'logging',
                                                              'proposed_spec_sha256': '5cbbf81cd3e6bce062d99fd7e1018d04243eee352a679c039c77036e9446cf5d',
                                                              'provider': 'azure',
                                                              'remediation_hint': 'Synapse '
                                                                                  'workspace > SQL '
                                                                                  'pools > '
                                                                                  'Auditing: '
                                                                                  'enable auditing '
                                                                                  'for each '
                                                                                  'dedicated pool '
                                                                                  'and select the '
                                                                                  'designated '
                                                                                  'storage '
                                                                                  'account; verify '
                                                                                  'the storage '
                                                                                  'endpoint.',
                                                              'resource_kind': 'synapse_workspace',
                                                              'severity': 'medium',
                                                              'title': 'Synapse dedicated SQL '
                                                                       'pools audit to the '
                                                                       'required storage account'},
 'azure_synapse_workspace_10_2_1_1_28_47f4840': {'category': 'logging',
                                                 'proposed_spec_sha256': '2ae43b95253c0b0226670d07d4c6345565047ed8211e24d4167f32041b8fca5f',
                                                 'provider': 'azure',
                                                 'remediation_hint': 'Enable Synapse workspace CMK '
                                                                     'with the specified Key Vault '
                                                                     'key ID and enable each '
                                                                     'dedicated SQL pool blob '
                                                                     'auditing policy with an '
                                                                     'approved storage sink.',
                                                 'resource_kind': 'synapse_workspace',
                                                 'severity': 'medium',
                                                 'title': 'Synapse encryption key and SQL pool '
                                                          'auditing meet specified settings'},
 'azure_synapse_workspace_10_3_3_22_15e4d4e': {'category': 'hardening',
                                               'proposed_spec_sha256': '2ef41139d98281705eea4bf0bd78392c103f5e8a95fcc569c516fa30b6089d5c',
                                               'provider': 'azure',
                                               'remediation_hint': 'Review the policy bounds '
                                                                   'against Synapse dedicated SQL '
                                                                   'pool built-in seven-day '
                                                                   'automatic restore point '
                                                                   'retention; if different '
                                                                   'retention is required, use a '
                                                                   'supported backup architecture '
                                                                   'or adjust the approved '
                                                                   'requirement.',
                                               'resource_kind': 'synapse_workspace',
                                               'severity': 'medium',
                                               'title': 'Synapse dedicated SQL pool automatic '
                                                        'snapshot retention meets policy'},
 'azure_synapse_workspace_1_2_8_29_fcdc827': {'category': 'network',
                                              'proposed_spec_sha256': '6e3ffb517ca79d951829db4b465847d2f2f3a8b82e06a271e6464931335e9b20',
                                              'provider': 'azure',
                                              'remediation_hint': 'Set Synapse workspace public '
                                                                  'network access to Disabled for '
                                                                  'every workspace hosting a '
                                                                  'dedicated SQL pool.',
                                              'resource_kind': 'synapse_workspace',
                                              'severity': 'high',
                                              'title': 'Synapse dedicated SQL pools avoid '
                                                       'unrestricted public access'}}

def _base(item, index, kind):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    if not scope.startswith("/subscriptions/"):
        raise Unavailable("Azure subscription scope absent")
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or any(not isinstance(e, dict) or e.get("scope", "").casefold() != scope.casefold() for e in envelopes):
        raise Unavailable("foreign or malformed collection envelope")
    resources = get(index, kind, list)
    if any(not isinstance(e, dict) or e.get("scope", "").casefold() != scope.casefold() for e in resources):
        raise Unavailable("foreign or malformed resource envelope")
    rows = complete_items(index, kind)
    ids = []
    for row in rows:
        rid = get(row, "id", str)
        if not rid.casefold().startswith(scope.casefold().rstrip("/") + "/"):
            raise Unavailable("foreign-scope resource")
        ids.append(rid.casefold())
    if len(ids) != len(set(ids)):
        raise Unavailable("duplicate resource identity")
    rid = get(item, "id", str)
    if rid.casefold() not in ids:
        raise Unavailable("resource not in complete scoped inventory")
    return rid


def _policy(index, *path):
    policy = get(index, "context.metadata.compliance_policy", dict)
    if get(policy, "status", str) != "collected":
        raise Unavailable("policy unavailable")
    value = policy
    for key in path:
        value = get(value, key)
    return value


def _fresh(index, value):
    if get(value, "status", str) != "collected" or get(value, "complete", bool) is not True:
        raise Unavailable("dated evidence incomplete")
    captured = datetime.fromisoformat(get(index, "context.created_at", str).replace("Z", "+00:00"))
    observed = datetime.fromisoformat(get(value, "asOf", str).replace("Z", "+00:00"))
    age = get(value, "maxAgeSeconds", int)
    if captured.tzinfo is None or observed.tzinfo is None or age < 0 or not 0 <= (captured-observed).total_seconds() <= age:
        raise Unavailable("dated evidence stale or future-dated")


def _children(item, name, path=None):
    coverage = get(item, "_coverage." + name + ".status", str)
    if coverage not in ("collected", "empty"):
        raise Unavailable("child list incomplete: " + name)
    rows = list_of_objects(get(item, name, list))
    if coverage == "empty" and rows:
        raise Unavailable("child list contradicts empty coverage")
    if path:
        parent = get(item, "id", str).rstrip("/").casefold() + "/" + path.casefold() + "/"
        ids = []
        for row in rows:
            rid = get(row, "id", str).casefold()
            if not rid.startswith(parent) or not rid[len(parent):] or "/" in rid[len(parent):]:
                raise Unavailable("malformed or foreign child identity")
            ids.append(rid)
        if len(ids) != len(set(ids)):
            raise Unavailable("duplicate child identity")
    return rows


def _pools(item):
    return _children(item, "sqlPools", "sqlPools")


def _version(value):
    if not isinstance(value, str):
        raise Unavailable("malformed Kubernetes version")
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise Unavailable("unresolved Kubernetes version or build")
    return tuple(map(int, match.groups()))


def _arm_equal(a, b):
    return isinstance(a, str) and isinstance(b, str) and a.rstrip("/").casefold() == b.rstrip("/").casefold()


def _key_status(item, required):
    evidence = get(item, "keyResolution", dict)
    if get(evidence, "status", str) != "collected" or not get(evidence, "complete", bool):
        raise Unavailable("key resolution incomplete")
    actual = get(evidence, "keyId", str)
    if not _arm_equal(actual, required):
        return "different"
    if not get(evidence, "exists", bool) or not get(evidence, "enabled", bool) or not get(evidence, "accessible", bool):
        return "unusable"
    return "usable"


def _audit(item, field):
    pools = _pools(item)
    if not pools:
        return None
    policies = _children(item, field)
    expected = {get(pool, "id", str).casefold() for pool in pools}
    found = {}
    for row in policies:
        pid = get(row, "poolId", str).casefold()
        if pid not in expected or pid in found:
            raise Unavailable("foreign or duplicate SQL pool audit policy")
        found[pid] = row
    if set(found) != expected:
        raise Unavailable("SQL pool audit policy GET incomplete")
    return list(found.values())


def _endpoint(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise Unavailable("malformed storage blob endpoint")
    return parsed.netloc.casefold()


def _nsg_paths(item, index, field):
    _base(item, index, "nsg")
    envelope = get(item, field, dict)
    if get(envelope, "status", str) != "collected" or not get(envelope, "complete", bool):
        raise Unavailable("effective network paths incomplete")
    if not _arm_equal(get(envelope, "nsgId", str), get(item, "id", str)):
        raise Unavailable("foreign NSG path evidence")
    return list_of_objects(get(envelope, "paths", list))


def _cidr(value):
    try:
        return ip_network(value, strict=False)
    except (ValueError, TypeError) as exc:
        raise Unavailable("invalid CIDR policy or path") from exc


def _register(check_id, evaluator, dependencies):
    spec = SPECS[check_id]
    native_category = spec["category"] if spec["category"] in ("hardening", "exposure", "least_privilege", "iam_graph", "network") else "hardening"
    register(check_id, spec["provider"], native_category, spec["resource_kind"],
             spec["title"], spec["severity"], "CM-6", spec["remediation_hint"],
             dependencies=dependencies)(evaluator)
    if native_category != spec["category"]:
        CHECKS[-1] = replace(CHECKS[-1], category=spec["category"])


VULN = "azure.gap.kubernetes_cluster_upgraded_with_non_vulnerable_version"
DIAG = "azure_aks_cluster_10_2_1_1_17_885658f"
SUPPORT = "azure_aks_cluster_6_3_3_4_98a0b2c"
PRIV = "azure_aks_cluster_7_2_1_6_93c4fab"
NONROOT = "azure_aks_cluster_aks_cluster_rbac_enabled_db12524"
KMS = "azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3"
PRIVATE = "azure_pci_1_3_1_33"
CMK = "azure_pci_3_5_1_29"
STORAGE_AUDIT = "azure_storage_account_sqlserver_auditing_enabled_e4e4b28"
COMBINED = "azure_synapse_workspace_10_2_1_1_28_47f4840"
RETENTION = "azure_synapse_workspace_10_3_3_22_15e4d4e"
PUBLIC = "azure_synapse_workspace_1_2_8_29_fcdc827"
ADMIN = "azure.other.admin_network_separation"
MONITOR = "azure.other.monitor_external_lateral_access"
HTTPS = "azure.other.nsg_internet_https_restricted"


def vulnerability(item, index):
    _base(item, index, "aks_cluster")
    version = _version(get(item, "properties.kubernetesVersion", str))
    floors = {(1, 11): 9, (1, 12): 7, (1, 13): 5, (1, 14): 0}
    if version[:2] in floors and version[2] < floors[version[:2]]:
        return result(True, version=version, reason="below frozen CVE-2019-9946 patched floor")
    if version[:2] < (1, 11):
        raise Unavailable("branch has no mapped CVE floor")
    feed = _policy(index, "aksAdvisories")
    _fresh(index, feed)
    vulnerable = get(feed, "vulnerableVersions", list)
    if any(not isinstance(v, str) for v in vulnerable):
        raise Unavailable("malformed advisory versions")
    if tuple(version) in [_version(v) for v in vulnerable]:
        return result(True, version=version, reason="listed in current AKS advisory")
    supported = get(feed, "supportedBranches", list)
    if f"{version[0]}.{version[1]}" not in supported:
        raise Unavailable("branch support or advisory coverage unresolved")
    return result(False, version=version, advisory_as_of=feed["asOf"])


_register(VULN, vulnerability, ["aks_cluster"])


def diagnostics(item, index):
    _base(item, index, "aks_cluster")
    rid = get(item, "id", str)
    cats = _children(item, "diagnosticCategories")
    settings = _children(item, "diagnosticSettings")
    destinations = _children(item, "diagnosticDestinations")
    destination_ids = {}
    for destination in destinations:
        did = get(destination, "id", str).casefold()
        if did in destination_ids:
            raise Unavailable("duplicate diagnostic destination")
        destination_ids[did] = get(destination, "usable", bool)
    supported = set()
    for row in cats:
        name = get(row, "name", str)
        if get(row, "properties.categoryType", str) == "Logs":
            supported.add(name)
    if not supported:
        raise Unavailable("supported AKS log categories unresolved")
    enabled, uncertain = set(), False
    for row in settings:
        if not get(row, "id", str).casefold().startswith(rid.casefold() + "/providers/microsoft.insights/diagnosticsettings/"):
            raise Unavailable("foreign diagnostic setting")
        props = get(row, "properties", dict)
        sinks = [optional(props, key, None) for key in ("workspaceId", "eventHubAuthorizationRuleId", "storageAccountId")]
        if any(s is not None and not isinstance(s, str) for s in sinks):
            raise Unavailable("malformed diagnostic destination")
        sink_ok = any(destination_ids.get(s.casefold(), False) for s in sinks if s is not None)
        sink_unresolved = any(s.casefold() not in destination_ids for s in sinks if s is not None)
        for log in list_of_objects(get(props, "logs", list)):
            if get(log, "enabled", bool):
                category = optional(log, "category", None)
                group = optional(log, "categoryGroup", None)
                if category is None and group != "allLogs":
                    uncertain = True
                elif sink_ok:
                    enabled.update(supported if group == "allLogs" else [category])
                elif sink_unresolved:
                    uncertain = True
    if uncertain:
        return unknown("diagnostic sink or category unresolved")
    return result(bool(supported-enabled), missing_categories=sorted(supported-enabled))


_register(DIAG, diagnostics, ["aks_cluster"])


def support(item, index):
    _base(item, index, "aks_cluster")
    version = _version(get(item, "properties.kubernetesVersion", str))
    location = get(item, "location", str)
    plan = get(item, "properties.supportPlan", str)
    threshold = _version(_policy(index, "oldestVersionSupported"))
    feed = _policy(index, "aksRegionalSupport")
    _fresh(index, feed)
    if get(feed, "location", str).casefold() != location.casefold() or get(feed, "supportPlan", str) != plan:
        raise Unavailable("regional support feed does not match cluster")
    versions = get(feed, "supportedVersions", list)
    if any(not isinstance(v, str) for v in versions):
        raise Unavailable("malformed regional support versions")
    supported = version in [_version(v) for v in versions]
    if version < threshold:
        return result(True, version=version, oldest=threshold, requirement="6.3.3.4", requirement_6_3_3_5_status="FAIL")
    if version == threshold:
        return result(True, version=version, oldest=threshold, requirement="6.3.3.4", requirement_6_3_3_5_status="PASS" if supported else "UNKNOWN")
    if not supported:
        raise Unavailable("newer version support unverified")
    return result(False, version=version, requirement="6.3.3.4", requirement_6_3_3_5_status="PASS")


_register(SUPPORT, support, ["aks_cluster"])


def _pods(item):
    inventory = get(item, "podInventory", dict)
    if get(inventory, "status", str) != "collected" or not get(inventory, "pagesComplete", bool) or not get(inventory, "namespacesComplete", bool):
        raise Unavailable("AKS pod inventory incomplete")
    if not _arm_equal(get(inventory, "clusterId", str), get(item, "id", str)) or not get(inventory, "resourceVersion", str) or not get(inventory, "consistent", bool) or not get(inventory, "fullPodRepresentation", bool):
        raise Unavailable("foreign or stale AKS pod inventory")
    rows = list_of_objects(get(inventory, "items", list))
    keys = []
    for pod in rows:
        namespace = get(pod, "metadata.namespace", str)
        name = get(pod, "metadata.name", str)
        uid = get(pod, "metadata.uid", str)
        if not namespace or not name or not uid:
            raise Unavailable("malformed Pod identity")
        keys.append((namespace, name, uid))
    if len(keys) != len(set(keys)):
        raise Unavailable("duplicate Pod identity")
    return rows


def _containers(pod):
    spec = get(pod, "spec", dict)
    regular = list_of_objects(get(spec, "containers", list))
    if not regular:
        raise Unavailable("pod without regular container")
    return regular + list_of_objects(optional(spec, "initContainers", [])) + list_of_objects(optional(spec, "ephemeralContainers", []))


def privileged(item, index):
    _base(item, index, "aks_cluster")
    pods = _pods(item)
    count = 0
    privileged_names = []
    for pod in pods:
        get(pod, "metadata.namespace", str)
        for container in _containers(pod):
            get(container, "name", str)
            ctx = optional(container, "securityContext", {})
            if not isinstance(ctx, dict):
                raise Unavailable("invalid container security context")
            enabled = optional(ctx, "privileged", False)
            if type(enabled) is not bool:
                raise Unavailable("invalid privileged flag")
            count += 1
            if enabled:
                privileged_names.append(get(container, "name", str))
    return result(bool(privileged_names), privileged_containers=privileged_names, assessed_containers=count, limitation="present pods only")


_register(PRIV, privileged, ["aks_cluster"])


def nonroot(item, index):
    _base(item, index, "aks_cluster")
    pods = _pods(item)
    failed, uncertain, linux = [], False, 0
    for pod in pods:
        spec = get(pod, "spec", dict)
        os = optional(spec, "os", None)
        if not isinstance(os, dict) or optional(os, "name", None) not in ("linux", "windows"):
            uncertain = True
            continue
        if get(os, "name", str) == "windows":
            uncertain = True
            continue
        linux += 1
        podctx = optional(spec, "securityContext", {})
        if not isinstance(podctx, dict):
            uncertain = True
            continue
        poduid = optional(podctx, "runAsUser", None)
        for container in _containers(pod):
            ctx = optional(container, "securityContext", {})
            if not isinstance(ctx, dict):
                uncertain = True
                continue
            uid = optional(ctx, "runAsUser", poduid)
            if uid is None or type(uid) is int and uid == 0:
                failed.append(get(container, "name", str))
            elif type(uid) is not int or uid < 0:
                uncertain = True
    if failed:
        return result(True, containers=failed)
    if uncertain:
        return unknown("Windows OS, node OS or security context unresolved")
    if not linux:
        return "NOT_APPLICABLE", {"reason": "no applicable Linux pods"}
    return result(False, linux_pods=linux)


_register(NONROOT, nonroot, ["aks_cluster"])


def kms(item, index):
    _base(item, index, "aks_cluster")
    kmscfg = get(item, "properties.securityProfile.azureKeyVaultKms", dict)
    if not get(kmscfg, "enabled", bool):
        return result(True, reason="AKS Key Vault KMS disabled")
    key_id = optional(kmscfg, "keyId", None)
    if key_id is None and not full_representation(item):
        raise Unavailable("KMS key ID absent from unproven representation")
    if key_id is not None and not isinstance(key_id, str):
        raise Unavailable("malformed KMS key ID")
    if not key_id:
        return result(True, reason="enabled KMS has no key ID")
    key = get(item, "kmsKeyEvidence", dict)
    if get(key, "status", str) != "collected" or not get(key, "complete", bool) or get(key, "keyId", str) != key_id:
        raise Unavailable("KMS key evidence unresolved")
    for field in ("exists", "enabled", "identityCanUse", "networkReachable"):
        if not get(key, field, bool):
            return result(True, reason="authoritative unusable KMS key", failed_field=field)
    return result(False, key_id=key_id)


_register(KMS, kms, ["aks_cluster"])
def private_sql(item, index):
    _base(item, index, "synapse_workspace")
    if not _pools(item):
        return "NOT_APPLICABLE", {"reason": "no dedicated SQL pools"}
    rid = get(item, "id", str)
    connections = _children(item, "privateEndpointConnections", "privateEndpointConnections")
    endpoints = _children(item, "resolvedPrivateEndpoints")
    endpoint_map = {}
    for endpoint in endpoints:
        eid = get(endpoint, "id", str).casefold()
        if eid in endpoint_map:
            raise Unavailable("duplicate Network private endpoint")
        endpoint_map[eid] = endpoint
    good = False
    uncertain = False
    for row in connections:
        if get(row, "properties.privateLinkServiceConnectionState.status", str) != "Approved":
            continue
        eid = get(row, "properties.privateEndpoint.id", str).casefold()
        endpoint = endpoint_map.get(eid)
        if endpoint is None:
            uncertain = True
            continue
        for link in list_of_objects(get(endpoint, "properties.privateLinkServiceConnections", list)):
            props = get(link, "properties", dict)
            groups = get(props, "groupIds", list)
            if any(not isinstance(group, str) for group in groups):
                uncertain = True
                continue
            if _arm_equal(get(props, "privateLinkServiceId", str), rid) and "sql" in groups:
                good = True
    if uncertain:
        return unknown("private endpoint join or group unresolved")
    return result(not good, approved_sql_private_endpoint=good)


_register(PRIVATE, private_sql, ["synapse_workspace"])


def cmk(item, index):
    _base(item, index, "synapse_workspace")
    approved = _policy(index, "approvedKeyVaultKeyId")
    if not isinstance(approved, str) or not approved:
        raise Unavailable("approved Key Vault key absent")
    encryption = get(item, "properties.encryption", dict)
    cmkcfg = optional(encryption, "cmk", None)
    if cmkcfg is None:
        if not full_representation(item):
            raise Unavailable("CMK absence not proven by full workspace GET")
        return result(True, reason="CMK absent from complete workspace GET")
    if not isinstance(cmkcfg, dict):
        raise Unavailable("malformed Synapse CMK")
    status = get(cmkcfg, "status", str)
    if status in ("Disabled", "Inconsistent"):
        return result(True, status=status)
    if status != "Consistent":
        raise Unavailable("transitional or unknown CMK state")
    get(cmkcfg, "key.name", str)
    get(cmkcfg, "key.keyVaultUrl", str)
    resolved = _key_status(item, approved)
    if resolved in ("different", "unusable"):
        return result(True, reason=resolved)
    return result(False, approved_key=approved)


_register(CMK, cmk, ["synapse_workspace"])


def storage_audit(item, index):
    _base(item, index, "synapse_workspace")
    policies = _audit(item, "sqlPoolAuditingSettings")
    if policies is None:
        return "NOT_APPLICABLE", {"reason": "no dedicated SQL pools"}
    required = _policy(index, "requiredStorageAccountId")
    accounts = complete_items(index, "storage_account")
    matches = [a for a in accounts if _arm_equal(get(a, "id", str), required)]
    if len(matches) != 1:
        raise Unavailable("required storage account unresolved")
    expected = _endpoint(get(matches[0], "properties.primaryEndpoints.blob", str))
    failed, uncertain = [], False
    for policy in policies:
        props = get(policy, "properties", dict)
        state = get(props, "state", str)
        if state == "Disabled":
            failed.append(get(policy, "poolId", str))
        elif state == "Enabled":
            try:
                if _endpoint(get(props, "storageEndpoint", str)) != expected:
                    failed.append(get(policy, "poolId", str))
            except Unavailable:
                uncertain = True
        else:
            uncertain = True
    if failed:
        return result(True, pools=failed)
    if uncertain:
        return unknown("audit endpoint or policy unresolved")
    return result(False, pool_count=len(policies))


_register(STORAGE_AUDIT, storage_audit, ["synapse_workspace", "storage_account"])


def combined(item, index):
    _base(item, index, "synapse_workspace")
    policies = _audit(item, "sqlPoolBlobAuditingPolicies")
    if policies is None:
        return "NOT_APPLICABLE", {"reason": "no dedicated SQL pools"}
    required = _policy(index, "requiredKeyId")
    sink = _policy(index, "requiredAuditSink")
    if not isinstance(required, str) or not isinstance(sink, str) or not required or not sink:
        raise Unavailable("key or audit sink policy absent")
    encryption = get(item, "properties.encryption", dict)
    cmkcfg = get(encryption, "cmk", dict)
    status = get(cmkcfg, "status", str)
    if status in ("Disabled", "Inconsistent"):
        return result(True, reason="workspace CMK disabled")
    if status != "Consistent":
        raise Unavailable("workspace CMK unresolved")
    get(cmkcfg, "key.name", str)
    key = _key_status(item, required)
    if key in ("different", "unusable"):
        return result(True, reason=key)
    failed, uncertain = [], False
    for row in policies:
        props = get(row, "properties", dict)
        state = get(props, "state", str)
        if state == "Disabled":
            failed.append(get(row, "poolId", str))
        elif state == "Enabled":
            try:
                endpoint = _endpoint(get(props, "storageEndpoint", str))
                if endpoint != _endpoint(sink) or not get(row, "sinkUsable", bool):
                    uncertain = True
            except Unavailable:
                uncertain = True
        else:
            uncertain = True
    if failed:
        return result(True, pools=failed)
    if uncertain:
        return unknown("SQL pool audit sink unresolved")
    return result(False, pool_count=len(policies))


_register(COMBINED, combined, ["synapse_workspace"])


def retention(item, index):
    _base(item, index, "synapse_workspace")
    pools = _pools(item)
    if not pools:
        return "NOT_APPLICABLE", {"reason": "no dedicated SQL pools"}
    low = _policy(index, "minimumRetentionDays")
    high = _policy(index, "maximumRetentionDays")
    if type(low) is not int or type(high) is not int or low < 0 or high < low:
        raise Unavailable("invalid retention policy")
    for pool in pools:
        if get(pool, "properties.status", str) != "Online":
            raise Unavailable("SQL pool state unresolved for retention")
    evidence = _children(item, "sqlPoolRetentionEvidence")
    by_pool = {}
    for row in evidence:
        pid = get(row, "poolId", str).casefold()
        if pid in by_pool:
            raise Unavailable("duplicate retention evidence")
        by_pool[pid] = row
    if set(by_pool) != {get(pool, "id", str).casefold() for pool in pools}:
        raise Unavailable("retention evidence incomplete")
    bad = []
    for pid, row in by_pool.items():
        if get(row, "status", str) != "collected" or not get(row, "authoritative", bool):
            raise Unavailable("retention evidence not authoritative")
        enabled = get(row, "automaticSnapshotsEnabled", bool)
        days = get(row, "retentionDays", int)
        if days < 0:
            raise Unavailable("malformed retention duration")
        if not enabled or days == 0 or not low <= days <= high:
            bad.append(pid)
    return result(bool(bad), pools=bad, minimum_days=low, maximum_days=high)


_register(RETENTION, retention, ["synapse_workspace"])


def public_sql(item, index):
    _base(item, index, "synapse_workspace")
    if not _pools(item):
        return "NOT_APPLICABLE", {"reason": "no dedicated SQL pools"}
    value = get(item, "properties.publicNetworkAccess", str)
    if value not in ("Enabled", "Disabled"):
        raise Unavailable("unrecognized publicNetworkAccess")
    return result(value == "Enabled", publicNetworkAccess=value)


_register(PUBLIC, public_sql, ["synapse_workspace"])


def admin_network(item, index):
    paths = _nsg_paths(item, index, "effectiveAdminPaths")
    approved = _policy(index, "approvedAdminPorts")
    sources = _policy(index, "approvedAdminSourceCidrs")
    if not isinstance(sources, list):
        raise Unavailable("invalid approved admin sources")
    networks = [_cidr(source) for source in sources]
    if not isinstance(approved, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in approved):
        raise Unavailable("invalid approved admin ports")
    pairs = _policy(index, "adminApplicationPairs")
    if not isinstance(pairs, list):
        raise Unavailable("admin/application subnet pair policy malformed")
    declared = set()
    for pair in list_of_objects(pairs):
        declared.add((get(pair, "adminSubnetId", str).casefold(), get(pair, "applicationSubnetId", str).casefold()))
    if not declared:
        return "NOT_APPLICABLE", {"reason": "no declared admin-to-application pairs"}
    bad = []
    seen = set()
    for path in paths:
        pair = (get(path, "sourceSubnetId", str).casefold(), get(path, "destinationSubnetId", str).casefold())
        if pair not in declared:
            raise Unavailable("admin path not in declared subnet pairs")
        seen.add(pair)
        if get(path, "role", str) != "admin-to-application" or not get(path, "associationsResolved", bool):
            raise Unavailable("admin path roles or associations unresolved")
        port = get(path, "destinationPort", int)
        subnet = get(path, "subnetNsgAllows", bool)
        nic = get(path, "nicNsgAllows", bool)
        if not 1 <= port <= 65535:
            raise Unavailable("invalid destination port")
        source = _cidr(get(path, "sourceCidr", str))
        approved_source = any(source.subnet_of(network) for network in networks if network.version == source.version)
        if subnet and nic and (port not in approved or not approved_source):
            bad.append((str(source), port))
    if seen != declared:
        raise Unavailable("declared admin/application path coverage incomplete")
    return result(bool(bad), violating_ports=bad, requirement_coverage="PARTIAL: network paths only")


_register(ADMIN, admin_network, ["nsg"])


def monitor_access(item, index):
    paths = _nsg_paths(item, index, "effectiveMonitorPaths")
    principals = _policy(index, "monitorPrincipalIds")
    destinations = _policy(index, "approvedDestinations")
    ports = _policy(index, "approvedPorts")
    if not isinstance(principals, list) or not principals or any(not isinstance(x, str) for x in principals):
        raise Unavailable("monitor principal policy absent")
    if not isinstance(destinations, list) or any(not isinstance(x, str) for x in destinations) or not isinstance(ports, list) or any(type(x) is not int for x in ports):
        raise Unavailable("monitor destination policy malformed")
    seen, bad = set(), []
    for path in paths:
        principal = get(path, "principalId", str)
        if principal not in principals or not get(path, "identityAndRouteResolved", bool):
            raise Unavailable("monitor identity or route unresolved")
        seen.add(principal)
        destination = get(path, "destination", str)
        port = get(path, "destinationPort", int)
        if get(path, "reachable", bool) and (destination not in destinations or port not in ports):
            bad.append((principal, destination, port))
    if seen != set(principals):
        raise Unavailable("monitor principal coverage incomplete")
    return result(bool(bad), unapproved_reachable_paths=bad)


_register(MONITOR, monitor_access, ["nsg"])


def https_ingress(item, index):
    paths = _nsg_paths(item, index, "effectiveInternetIngress")
    approved = _policy(index, "approvedSourceCidrs")
    if not isinstance(approved, list):
        raise Unavailable("approved source CIDR policy absent")
    networks = [_cidr(v) for v in approved]
    if not paths:
        return "NOT_APPLICABLE", {"reason": "no applicable Internet-facing HTTP or HTTPS paths"}
    bad = []
    for path in paths:
        if not get(path, "associationResolved", bool) or not get(path, "rulesAndTagsExpanded", bool):
            raise Unavailable("NSG association or effective rule unresolved")
        port = get(path, "destinationPort", int)
        if port not in (80, 443):
            raise Unavailable("non-HTTP Internet path in evidence")
        source = _cidr(get(path, "sourceCidr", str))
        if get(path, "allowed", bool) and not any(source.subnet_of(allowed) for allowed in networks if source.version == allowed.version):
            bad.append((str(source), port))
    return result(bool(bad), unapproved_allowed_paths=bad)


_register(HTTPS, https_ingress, ["nsg"])
