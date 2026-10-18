"""Eight signed Azure predicates. All evaluation is offline and read-only.

Additional normalized and external evidence contracts are specified in
sw22-collector-requests.md; missing evidence is never a safe configuration.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import re
from uuid import UUID

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, omitted, memoized, optional

SPECS = {'azure_application_gateway_11_5_1_1_1_f56bdc2': {'id': 'azure_application_gateway_11_5_1_1_1_f56bdc2',
                                                  'provider': 'azure',
                                                  'resource_kind': 'application_gateway_frontdoor_load_balancer_public_ip',
                                                  'data_source': 'Paged Application Gateway, Front '
                                                                 'Door, Load Balancer and Public '
                                                                 'IP inventories; Public IP GET '
                                                                 'ddosSettings.protectionMode and '
                                                                 'plan; protected VNet association '
                                                                 'where inherited; effective App '
                                                                 'Gateway/Front Door WAF policy '
                                                                 'linkage, state and mode. Resolve '
                                                                 'WAF policy state defaults from '
                                                                 'the documented schema.',
                                                  'predicate': 'For every scoped public App '
                                                               'Gateway, Front Door, Load Balancer '
                                                               'and Public IP, verify applicable '
                                                               'DDoS protection by exact public '
                                                               'IP/plan or supported inherited '
                                                               'VNet protection; for App Gateway '
                                                               'and Front Door also verify an '
                                                               'effective WAF policy in Prevention '
                                                               'mode, treating omitted '
                                                               'policy/custom-rule state as '
                                                               'Enabled only where the API '
                                                               'documents that default. PASS only '
                                                               'when all applicable protections '
                                                               'are measured; FAIL on a proven '
                                                               'missing protection; UNKNOWN for '
                                                               'unsupported product-level DDoS '
                                                               'mapping, public frontend, '
                                                               'inherited VNet, plan, WAF '
                                                               'policy/default or incomplete '
                                                               'inventory. No public resources is '
                                                               'NOT_APPLICABLE.',
                                                  'severity': 'high',
                                                  'category': 'network',
                                                  'title': 'Protect public gateway and '
                                                           'load-balancer IPs from DDoS',
                                                  'description': 'Protect public gateway and '
                                                                 'load-balancer IPs from DDoS. A '
                                                                 'finding is raised when an '
                                                                 'internet-facing Application '
                                                                 'Gateway or Load Balancer is on a '
                                                                 'VNet without effective DDoS '
                                                                 'Network Protection or its public '
                                                                 'IP explicitly disables '
                                                                 'protection.',
                                                  'remediation_hint': 'Enable applicable Azure '
                                                                      'DDoS Protection for public '
                                                                      'IPs or associated VNets, '
                                                                      'and attach enabled '
                                                                      'Prevention-mode WAF '
                                                                      'policies to public '
                                                                      'Application Gateways and '
                                                                      'Front Door profiles.',
                                                  'proposed_spec_sha256': '9eae702c7cd2e36f40afc52039ddd690633f502494d15b2e9be8bf308a048f4a'},
 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28': {'id': 'azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28',
                                                                      'provider': 'azure',
                                                                      'resource_kind': 'service_principal',
                                                                      'data_source': 'Microsoft '
                                                                                     'Graph GET '
                                                                                     '/servicePrincipals?$select=id,passwordCredentials,keyCredentials; '
                                                                                     'exact '
                                                                                     'fields: '
                                                                                     'Microsoft.Graph/servicePrincipals[].passwordCredentials[].startDateTime,endDateTime,keyCredentials[].startDateTime,endDateTime; '
                                                                                     'parameter '
                                                                                     'maxCredentialAgeDays.',
                                                                      'predicate': 'For each '
                                                                                   'active, '
                                                                                   'unexpired '
                                                                                   'service-principal '
                                                                                   'passwordCredential '
                                                                                   'and '
                                                                                   'keyCredential, '
                                                                                   'FAIL if '
                                                                                   'startDateTime '
                                                                                   'is older than '
                                                                                   'maxCredentialAgeDays, '
                                                                                   'defaulting to '
                                                                                   '90 days when '
                                                                                   'the parameter '
                                                                                   'is absent. '
                                                                                   'PASS if every '
                                                                                   'active '
                                                                                   'credential is '
                                                                                   'within that '
                                                                                   'threshold and '
                                                                                   'all '
                                                                                   'principals/credentials '
                                                                                   'were '
                                                                                   'enumerated. '
                                                                                   'UNKNOWN if '
                                                                                   'dates, time '
                                                                                   'basis or Graph '
                                                                                   'paging is '
                                                                                   'incomplete; an '
                                                                                   'empty '
                                                                                   'credential '
                                                                                   'list passes '
                                                                                   'only with '
                                                                                   'complete '
                                                                                   'principal '
                                                                                   'scope.',
                                                                      'severity': 'high',
                                                                      'category': 'identity',
                                                                      'title': 'Rotate active '
                                                                               'service-principal '
                                                                               'credentials within '
                                                                               'policy age',
                                                                      'description': 'Checks age '
                                                                                     'of active '
                                                                                     'application '
                                                                                     'credentials '
                                                                                     'on service '
                                                                                     'principals; '
                                                                                     'expiry and '
                                                                                     'secret '
                                                                                     'retrieval '
                                                                                     'are separate '
                                                                                     'concerns.',
                                                                      'remediation_hint': 'Entra '
                                                                                          'admin '
                                                                                          'center '
                                                                                          '> App '
                                                                                          'registrations '
                                                                                          '> '
                                                                                          'Certificates '
                                                                                          '& '
                                                                                          'secrets: '
                                                                                          'add a '
                                                                                          'new '
                                                                                          'credential, '
                                                                                          'update '
                                                                                          'consumers, '
                                                                                          'then '
                                                                                          'remove '
                                                                                          'credentials '
                                                                                          'older '
                                                                                          'than '
                                                                                          'maxCredentialAgeDays; '
                                                                                          'prefer '
                                                                                          'managed '
                                                                                          'identity '
                                                                                          'or '
                                                                                          'workload '
                                                                                          'federation.',
                                                                      'proposed_spec_sha256': '6e2e97377d3b2e17d530b469e2c36880945e3455e0a8b3c74781f323552e4c3c'},
 'azure_c5_ops_08_01b': {'id': 'azure_c5_ops_08_01b',
                         'provider': 'azure',
                         'resource_kind': 'backup_job',
                         'data_source': 'New paged Microsoft.RecoveryServices/vaults/backupJobs '
                                        'LIST 2024-04-01: '
                                        'properties.jobType,operation,status,endTime,entityFriendlyName '
                                        'and workload-specific identity fields where present; '
                                        'policy input '
                                        'requiredProtectedItemIds,maxRestoreTestAgeDays. Do not '
                                        'assume a universal properties.entityId field: '
                                        'AzureIaaSVMJob responses may expose only '
                                        'entityFriendlyName. Join with protected-item records or '
                                        'external test records only when stable identity is '
                                        'demonstrable.; dated external restore-test records with '
                                        'job ID, stable protected item ID, validation result and '
                                        'contractual data class; complete required class/workload '
                                        'inventory; maxRestoreTestAgeDays <= 365',
                         'predicate': 'For each contractually required customer, derived and '
                                      'provider data class and protected item, PASS only if a '
                                      'stable item-to-job join shows a completed Restore job '
                                      'within the annual window and a dated validation record '
                                      'proves recovered data usable. FAIL when complete '
                                      'item/job/test inventory proves a required annual test is '
                                      'missing or failed. UNKNOWN if stable join, class coverage, '
                                      'outcome, date, contractual scope or paging is unresolved. A '
                                      'completed Restore job without validation cannot PASS.',
                         'severity': 'medium',
                         'category': 'recovery',
                         'title': 'Required protected workloads have recent completed restore jobs',
                         'description': 'Checks recent completed Restore jobs joined to stable '
                                        'protected-item identities; separate validation evidence '
                                        'is needed to claim a successful recovery test.',
                         'remediation_hint': 'Run and validate annual restore tests for every '
                                             'contractually required data class and protected '
                                             'item; retain stable item IDs, job IDs, timestamps '
                                             'and validation results.',
                         'proposed_spec_sha256': '16c51616a8c94f7a82e8b168f7599e1ef0b1ac78eb6f53c78d0f6ae99ee45cf5'},
 'azure_c5_dev_09_01b': {'id': 'azure_c5_dev_09_01b',
                         'provider': 'azure',
                         'resource_kind': 'source_control',
                         'data_source': 'Azure DevOps repository, branch, policy configuration and '
                                        'build-definition APIs with continuation tokens; '
                                        'source-code access permissions, branch/review/build '
                                        'policy, commit signature/provenance and audit evidence '
                                        'throughout development stages.',
                         'predicate': 'For the cloud service provider source-code lifecycle, PASS '
                                      'only when complete organization evidence shows version '
                                      'control and confidentiality, integrity and authenticity of '
                                      'source code at every development stage, including effective '
                                      'permissions, branch controls and provenance. FAIL on a '
                                      'proven missing required control; UNKNOWN if provider-owned '
                                      'repositories, stages, effective access, policy inheritance, '
                                      'signatures or audit evidence cannot be accessed. Customer '
                                      'Azure DevOps branch policies alone cannot prove this '
                                      'provider requirement.',
                         'severity': 'medium',
                         'category': 'hardening',
                         'title': 'Protect production Azure DevOps branches',
                         'description': 'Protect production Azure DevOps branches. A finding is '
                                        'raised when a production branch lacks enabled '
                                        'required-reviewer or build-validation policy.',
                         'remediation_hint': 'Apply and document version-control access, '
                                             'review/build protections and source authenticity '
                                             'controls across every provider development stage; '
                                             'retain evidence of their effective enforcement.',
                         'proposed_spec_sha256': 'a66105df534a257f96ceeee8e0ec084d8328b9ca8f8b19b10d3ec4c61b3af96e'},
 'azure.cis.defender_external_attack_surface_monitoring_easm': {'id': 'azure.cis.defender_external_attack_surface_monitoring_easm',
                                                                'provider': 'azure',
                                                                'resource_kind': 'easm_workspace',
                                                                'data_source': 'New paged ARM GET '
                                                                               '/subscriptions/{sub}/providers/Microsoft.Easm/workspaces?api-version=2023-04-01-preview; '
                                                                               'value[].properties.provisioningState '
                                                                               'is a string '
                                                                               '(Succeeded); '
                                                                               'follow nextLink. '
                                                                               'Existing collector '
                                                                               'has no '
                                                                               'easm_workspace '
                                                                               'kind.',
                                                                'predicate': 'PASS only if a '
                                                                             'complete '
                                                                             'subscription '
                                                                             'workspace list '
                                                                             'contains at least '
                                                                             'one '
                                                                             'provisioningState=Succeeded. '
                                                                             'FAIL if the complete '
                                                                             'list contains none. '
                                                                             'UNKNOWN on '
                                                                             'authorization, '
                                                                             'pagination or '
                                                                             'provisioning-state '
                                                                             'gaps.',
                                                                'severity': 'medium',
                                                                'category': 'vulnerability',
                                                                'title': 'Enable a provisioned '
                                                                         'Defender EASM workspace',
                                                                'description': 'Enable a '
                                                                               'provisioned '
                                                                               'Defender EASM '
                                                                               'workspace. A '
                                                                               'finding is raised '
                                                                               'when a complete '
                                                                               'subscription '
                                                                               'inventory contains '
                                                                               'no workspace with '
                                                                               'provisioningState=Succeeded.',
                                                                'remediation_hint': 'Azure portal '
                                                                                    '> Defender '
                                                                                    'EASM > create '
                                                                                    'workspace in '
                                                                                    'the '
                                                                                    'subscription, '
                                                                                    'then verify '
                                                                                    'provisioning '
                                                                                    'state is '
                                                                                    'Succeeded.',
                                                                'proposed_spec_sha256': '6aac61eb97ebac681f9cd05c27f0fa013f1e510ac9fd61f848ea3ff2b9563722'},
 'azure.gap.arc_kubernetes_cluster_azure_defender_extension_installed': {'id': 'azure.gap.arc_kubernetes_cluster_azure_defender_extension_installed',
                                                                         'provider': 'azure',
                                                                         'resource_kind': 'arc_kubernetes_cluster',
                                                                         'data_source': 'Paged ARM '
                                                                                        'connectedClusters '
                                                                                        'LIST and '
                                                                                        'Microsoft.KubernetesConfiguration/extensions '
                                                                                        'LIST per '
                                                                                        'cluster '
                                                                                        '2023-05-01: '
                                                                                        'properties.extensionType, '
                                                                                        'properties.provisioningState.',
                                                                         'predicate': 'For each '
                                                                                      'Arc '
                                                                                      'connected '
                                                                                      'cluster, '
                                                                                      'PASS only '
                                                                                      'if a fully '
                                                                                      'paged '
                                                                                      'extension '
                                                                                      'list '
                                                                                      'contains '
                                                                                      'extensionType=microsoft.azuredefender.kubernetes '
                                                                                      'with '
                                                                                      'provisioningState=Succeeded; '
                                                                                      'FAIL if '
                                                                                      'complete '
                                                                                      'lists prove '
                                                                                      'no '
                                                                                      'successful '
                                                                                      'matching '
                                                                                      'extension; '
                                                                                      'UNKNOWN on '
                                                                                      'unreadable/incomplete '
                                                                                      'lists or '
                                                                                      'unrecognized '
                                                                                      'state. '
                                                                                      'Complete '
                                                                                      'empty '
                                                                                      'cluster '
                                                                                      'inventory '
                                                                                      'is '
                                                                                      'NOT_APPLICABLE.',
                                                                         'severity': 'medium',
                                                                         'category': 'vulnerability',
                                                                         'title': 'Install the '
                                                                                  'Defender '
                                                                                  'extension on '
                                                                                  'Arc Kubernetes',
                                                                         'description': 'Install '
                                                                                        'the '
                                                                                        'Defender '
                                                                                        'extension '
                                                                                        'on Arc '
                                                                                        'Kubernetes. '
                                                                                        'A finding '
                                                                                        'is raised '
                                                                                        'when an '
                                                                                        'Arc '
                                                                                        'connected '
                                                                                        'cluster '
                                                                                        'has no '
                                                                                        'extension '
                                                                                        'of type '
                                                                                        'microsoft.azuredefender.kubernetes '
                                                                                        'with '
                                                                                        'provisioningState=Succeeded.',
                                                                         'remediation_hint': 'Azure '
                                                                                             'portal '
                                                                                             '> '
                                                                                             'Azure '
                                                                                             'Arc '
                                                                                             '> '
                                                                                             'Kubernetes '
                                                                                             'cluster '
                                                                                             '> '
                                                                                             'Extensions: '
                                                                                             'install '
                                                                                             'Microsoft '
                                                                                             'Defender '
                                                                                             'for '
                                                                                             'Containers '
                                                                                             'and '
                                                                                             'verify '
                                                                                             'Succeeded.',
                                                                         'proposed_spec_sha256': 'a6c72f056204834f6e05c0664f9446ed569f595873e4b97c00e1b762413b0541'},
 'azure.gap.kubernetes_cluster_service_listen_to_allowed_ports': {'id': 'azure.gap.kubernetes_cluster_service_listen_to_allowed_ports',
                                                                  'provider': 'azure',
                                                                  'resource_kind': 'service',
                                                                  'data_source': 'Kubernetes '
                                                                                 'read-only '
                                                                                 'core/v1 Services '
                                                                                 'list + '
                                                                                 'spec.ports and '
                                                                                 'approved-port '
                                                                                 'policy',
                                                                  'predicate': 'For each Service '
                                                                               'port entry, '
                                                                               'compare the '
                                                                               'declared port '
                                                                               'integer and '
                                                                               'protocol enum '
                                                                               '(default TCP) with '
                                                                               'the approved '
                                                                               'namespace/name-specific '
                                                                               'policy; FAIL on an '
                                                                               'observed '
                                                                               'unapproved pair; '
                                                                               'PASS only when all '
                                                                               'Services and ports '
                                                                               'are measured and '
                                                                               'approved; UNKNOWN '
                                                                               'on unresolved '
                                                                               'policy, service '
                                                                               'type or paged '
                                                                               'inventory. No '
                                                                               'applicable '
                                                                               'Services is '
                                                                               'NOT_APPLICABLE.',
                                                                  'severity': 'medium',
                                                                  'category': 'hardening',
                                                                  'title': 'Kubernetes cluster '
                                                                           'services should listen '
                                                                           'only on allowed ports',
                                                                  'description': 'Checks declared '
                                                                                 'Kubernetes '
                                                                                 'Service ports '
                                                                                 'against an '
                                                                                 'approved port '
                                                                                 'and protocol '
                                                                                 'list.',
                                                                  'remediation_hint': 'Edit the '
                                                                                      'Kubernetes '
                                                                                      'Service '
                                                                                      'spec.ports '
                                                                                      'list to '
                                                                                      'approved '
                                                                                      'port/protocol '
                                                                                      'pairs for '
                                                                                      'its '
                                                                                      'namespace '
                                                                                      'and name, '
                                                                                      'or update '
                                                                                      'the '
                                                                                      'approved '
                                                                                      'policy '
                                                                                      'after '
                                                                                      'review.',
                                                                  'proposed_spec_sha256': 'eaf993570dd93029b505465a7bc884e0c8746da6d63f95d969a94cfaafcf0a2c'},
 'azure.gap.logic_app_integration_service_environment_encrypted_with_cmk': {'id': 'azure.gap.logic_app_integration_service_environment_encrypted_with_cmk',
                                                                            'provider': 'azure',
                                                                            'resource_kind': 'integration_service_environment',
                                                                            'data_source': 'ARM '
                                                                                           'Microsoft.Logic/integrationServiceEnvironments '
                                                                                           'GET '
                                                                                           '2019-05-01: '
                                                                                           'properties.encryptionConfiguration.encryptionKeyReference.keyName,keyVault.id,keyVersion',
                                                                            'predicate': 'FAIL if '
                                                                                         'a '
                                                                                         'complete '
                                                                                         'ISE GET '
                                                                                         'has '
                                                                                         'encryptionConfiguration '
                                                                                         'but no '
                                                                                         'usable '
                                                                                         'encryptionKeyReference.keyName '
                                                                                         'or '
                                                                                         'keyVault.id. '
                                                                                         'PASS if '
                                                                                         'every '
                                                                                         'in-scope '
                                                                                         'ISE has '
                                                                                         'both and '
                                                                                         'an '
                                                                                         'approved '
                                                                                         'Key '
                                                                                         'Vault '
                                                                                         'key '
                                                                                         'identity. '
                                                                                         'UNKNOWN '
                                                                                         'if the '
                                                                                         'property '
                                                                                         'is '
                                                                                         'absent '
                                                                                         'in the '
                                                                                         'API '
                                                                                         'generation, '
                                                                                         'key '
                                                                                         'approval '
                                                                                         'policy '
                                                                                         'or ISE '
                                                                                         'inventory '
                                                                                         'is '
                                                                                         'unavailable.',
                                                                            'severity': 'medium',
                                                                            'category': 'encryption',
                                                                            'title': 'Assess Logic '
                                                                                     'Apps ISE '
                                                                                     'customer-managed '
                                                                                     'encryption',
                                                                            'description': 'Assess '
                                                                                           'Logic '
                                                                                           'Apps '
                                                                                           'ISE '
                                                                                           'customer-managed '
                                                                                           'encryption. '
                                                                                           'A '
                                                                                           'finding '
                                                                                           'is '
                                                                                           'raised '
                                                                                           'when '
                                                                                           'encryptionKeyReference '
                                                                                           'or its '
                                                                                           'keyName/keyVault.id '
                                                                                           'is '
                                                                                           'empty.',
                                                                            'remediation_hint': 'Deploy '
                                                                                                'or '
                                                                                                'update '
                                                                                                'the '
                                                                                                'Integration '
                                                                                                'Service '
                                                                                                'Environment '
                                                                                                'with '
                                                                                                'encryptionConfiguration '
                                                                                                'referencing '
                                                                                                'an '
                                                                                                'approved '
                                                                                                'Key '
                                                                                                'Vault '
                                                                                                'key; '
                                                                                                'verify '
                                                                                                'key '
                                                                                                'access '
                                                                                                'and '
                                                                                                'version.',
                                                                            'proposed_spec_sha256': '05b508b0d20a3c35eb094700da9060041406310f21e16c3c2c112ab958869159'}}

IDS = tuple(SPECS)
PROPOSED_SPEC_SHA256 = {key: spec["proposed_spec_sha256"] for key, spec in SPECS.items()}
NETWORK_ID, CREDENTIAL_ID, RESTORE_ID, SOURCE_ID, EASM_ID, ARC_ID, PORT_ID, ISE_ID = IDS


def _text(row, path):
    value = get(row, path, str)
    if not value or value != value.strip():
        raise Unavailable("empty or malformed identity: " + path)
    return value


def _time(value):
    if not isinstance(value, str):
        raise Unavailable("missing or malformed timestamp")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("invalid timestamp") from exc
    if instant.tzinfo is None:
        raise Unavailable("timestamp lacks timezone")
    return instant.astimezone(timezone.utc)


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("Azure scope authority unavailable")
    scope = _text(context, "scope")
    if not re.fullmatch(r"/(subscriptions|tenants)/[A-Za-z0-9._-]+", scope, re.I):
        raise Unavailable("Azure subscription or tenant scope unresolved")
    return context, scope


def _subscription(index):
    context, scope = _context(index)
    if not scope.casefold().startswith("/subscriptions/"):
        raise Unavailable("subscription scope required")
    return context, scope


def _inventory(index, kind, scope=None, service=None):
    _, actual = _context(index)
    scope = actual if scope is None else scope
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("complete single scoped inventory required: " + kind)
    envelope = envelopes[0]
    if (get(envelope, "type", str) != kind or get(envelope, "scope", str).casefold() != scope.casefold()
            or service is not None and get(envelope, "service", str) != service):
        raise Unavailable("foreign or malformed collection scope: " + kind)
    for key in ("nextLink", "@odata.nextLink", "continue"):
        if envelope.get(key):
            raise Unavailable("unconsumed pagination: " + kind)
    rows = complete_items(index, kind)
    native = list_of_objects(get(envelope, "items", list))
    wrappers = list_of_objects(get(index, kind, list))
    if rows != native or (envelope["status"] == "empty") != (not rows):
        raise Unavailable("inconsistent inventory completeness: " + kind)
    for wrapper in wrappers:
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str).casefold() != scope.casefold()
                or wrapper.get("provider", "azure") != "azure"):
            raise Unavailable("foreign resource wrapper: " + kind)
    return rows


def _arm(value, scope=None, resource_type=None):
    if not isinstance(value, str) or not re.fullmatch(
            r"/subscriptions/[A-Za-z0-9._-]+/resourceGroups/[A-Za-z0-9._-]+/providers/"
            r"[A-Za-z0-9.]+/(?:[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)(?:/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)*", value, re.I):
        raise Unavailable("malformed ARM resource identity")
    if scope is not None and not value.casefold().startswith(scope.casefold() + "/"):
        raise Unavailable("foreign subscription resource identity")
    if resource_type is not None:
        suffix = value.split("/providers/", 1)[-1] if "/providers/" in value else re.split("/providers/", value, flags=re.I)[-1]
        if not re.fullmatch(re.escape(resource_type) + r"/[A-Za-z0-9._-]+", suffix, re.I):
            raise Unavailable("wrong ARM resource type")
    return value.casefold()


def _by_id(rows, scope=None, resource_type=None):
    found = {}
    for row in rows:
        rid = _arm(get(row, "id", str), scope, resource_type)
        if rid in found:
            raise Unavailable("duplicate native identity")
        found[rid] = row
    return found


def _full(row, operation=None, version=None):
    proof = get(row, "_provenance", dict)
    if get(proof, "representation", str) != "full" or get(proof, "read_only", bool) is not True:
        raise Unavailable("full read-only response required")
    if operation is not None and get(proof, "source_operation", str) != operation:
        raise Unavailable("source operation unresolved")
    if version is not None and get(proof, "api_version", str) != version:
        raise Unavailable("API generation unresolved")


def _policy(index, name):
    context, scope = _context(index)
    metadata = get(context, 'metadata', dict)
    absent = object()
    # Read declared parents through strict accessors: a denied/malformed copy
    # cannot masquerade as an absent namespace and be hidden by the other one.
    parents = []
    legacy = optional(metadata, 'sw22', absent, dict)
    if legacy is not absent:
        parents.append(legacy)
    standard = optional(metadata, 'compliance_policy', absent, dict)
    if standard is not absent:
        standard = optional(standard, 'sw22', absent, dict)
        if standard is not absent:
            parents.append(standard)
    candidates = []
    for parent in parents:
        policy = optional(parent, name, absent, dict)
        if policy is absent:
            continue
        if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str).casefold() != scope.casefold():
            raise Unavailable('approved policy scope unavailable: ' + name)
        _text(policy, 'evidence_ref')
        candidates.append(policy)
    def exact(left, right):
        if isinstance(left, dict) and isinstance(right, dict):
            return set(left) == set(right) and all(exact(left[key], right[key]) for key in left)
        if isinstance(left, list) and isinstance(right, list):
            return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
        return type(left) is type(right) and left == right
    if not candidates or any(not exact(value, candidates[0]) for value in candidates[1:]):
        raise Unavailable('approved policy absent or ambiguous: ' + name)
    return candidates[0]


def _easm(item, index):
    _, scope = _subscription(index)
    rows = _by_id(_inventory(index, "easm_workspace"), scope, "Microsoft.Easm/workspaces")
    states = [get(row, "properties.provisioningState", str) for row in rows.values()]
    if any(state not in {"Succeeded", "Failed", "Canceled", "Creating", "Updating", "Deleting", "Accepted", "Provisioning"} for state in states):
        raise Unavailable("unrecognized EASM provisioning state")
    return result("Succeeded" not in states, workspace_count=len(rows), succeeded_count=states.count("Succeeded"))


def _arc(item, index):
    _, scope = _subscription(index)
    rows = _by_id(_inventory(index, "arc_kubernetes_cluster"), scope, "Microsoft.Kubernetes/connectedClusters")
    if not rows:
        return "NOT_APPLICABLE", {"reason": "Complete empty Arc cluster inventory"}
    failed = []
    for rid, row in rows.items():
        coverage = get(row, "_coverage.extensions", dict)
        state = get(coverage, "status", str)
        if state not in {"collected", "empty"} or get(coverage, "parent_id", str).casefold() != rid:
            raise Unavailable("Arc extension inventory incomplete or foreign")
        extensions = list_of_objects(get(row, "extensions", list))
        if (state == "empty") != (not extensions) or coverage.get("nextLink"):
            raise Unavailable("Arc extension inventory inconsistent or paged")
        seen, succeeded = set(), False
        for extension in extensions:
            eid = _arm(get(extension, "id", str), scope)
            prefix = rid + "/providers/microsoft.kubernetesconfiguration/extensions/"
            if (not eid.startswith(prefix) or "/" in eid[len(prefix):] or eid in seen
                    or get(extension, "parent_id", str).casefold() != rid):
                raise Unavailable("Arc extension identity unresolved")
            seen.add(eid)
            kind = _text(extension, "properties.extensionType")
            state = get(extension, "properties.provisioningState", str)
            if state not in {"Succeeded", "Failed", "Creating", "Updating", "Deleting"}:
                raise Unavailable("unrecognized Arc extension provisioning state")
            succeeded |= kind.casefold() == "microsoft.azuredefender.kubernetes" and state == "Succeeded"
        if not succeeded:
            failed.append(rid)
    return result(bool(failed), cluster_count=len(rows), no_successful_defender_extension=failed[:20])


def _credential_inventory(index):
    context, scope = _context(index)
    metadata = get(context, "metadata", dict)
    tenant = _text(metadata, "tenant_id")
    if scope.casefold() != "/tenants/" + tenant.casefold() or get(metadata, "tenant_verified", bool) is not True:
        raise Unavailable("verified Graph tenant scope required")
    rows = _inventory(index, "service_principal", service="Microsoft.Graph")
    envelope = index["collections"]["service_principal"][0]
    proof = get(envelope, "_provenance", dict)
    for field in ("tenant_id", "credential_context_id", "customer_context_id"):
        if _text(proof, field) != _text(metadata, field):
            raise Unavailable("Graph capture/customer/tenant binding unresolved")
    if get(proof, "tenant_verified", bool) is not True:
        raise Unavailable("Graph tenant authority unresolved")
    identities = set()
    for row in rows:
        rid = _text(row, "id")
        try:
            valid_uuid = str(UUID(rid)) == rid.casefold()
        except ValueError:
            valid_uuid = False
        if not valid_uuid or rid.casefold() in identities:
            raise Unavailable("Graph principal identity malformed or duplicated")
        identities.add(rid.casefold())
        rp = get(row, "_provenance", dict)
        if (get(rp, "tenant_id", str) != tenant or get(rp, "tenant_verified", bool) is not True
                or get(rp, "read_only", bool) is not True or get(rp, "endpoint", str) != "/v1.0/servicePrincipals"):
            raise Unavailable("Graph principal provenance unresolved")
    now = _time(get(context, "created_at", str))
    params = optional(metadata, "parameters", {}, dict)
    age = optional(params, "maxCredentialAgeDays", 90, int)
    if type(age) is not int or age <= 0:
        raise Unavailable("invalid maxCredentialAgeDays")
    counts = {}
    # Validate every credential before returning a verdict.
    for row in rows:
        row_old = row_active = row_expired = 0
        for field in ("passwordCredentials", "keyCredentials"):
            seen = set()
            for credential in list_of_objects(get(row, field, list)):
                key = _text(credential, "keyId")
                if key in seen:
                    raise Unavailable("duplicate credential identity")
                seen.add(key)
                start = _time(get(credential, "startDateTime", str))
                end = _time(get(credential, "endDateTime", str))
                if end <= start:
                    raise Unavailable("invalid credential lifetime")
                if end <= now:
                    row_expired += 1
                elif start <= now:
                    row_active += 1
                    row_old += now - start > timedelta(days=age)
        counts[row["id"].casefold()] = (row_old, row_active, row_expired)
    return {row["id"].casefold(): row for row in rows}, counts, age, now


def _credentials(item, index):
    rows, counts, age, now = memoized(index, ("sw22", "credential_inventory"),
                                    lambda: _credential_inventory(index))
    rid = get(item, "id", str).casefold()
    if rows.get(rid) != item:
        raise Unavailable("principal not in authoritative inventory")
    old, active, expired = counts[rid]
    return result(bool(old), active_count=active, expired_count=expired,
                  old_active_count=old, maxCredentialAgeDays=age, time_basis=now.isoformat())


def _ports(item, index):
    context, _ = _subscription(index)
    cluster = _text(context, "metadata.cluster_id")
    policy = _policy(index, "approved_service_ports")
    if get(policy, "cluster_id", str) != cluster:
        raise Unavailable("approved port policy belongs to another cluster")
    selections = {}
    for rule in list_of_objects(get(policy, "services", list)):
        key = (_text(rule, "namespace"), _text(rule, "name"))
        if key in selections:
            raise Unavailable("duplicate approved service policy")
        pairs = set()
        for pair in list_of_objects(get(rule, "allowed", list)):
            port, protocol = get(pair, "port", int), get(pair, "protocol", str)
            if not 1 <= port <= 65535 or protocol not in {"TCP", "UDP", "SCTP"} or (port, protocol) in pairs:
                raise Unavailable("malformed allowed port pair")
            pairs.add((port, protocol))
        selections[key] = pairs
    rows = _inventory(index, "service", service="Kubernetes.core/v1")
    seen, bad, applicable = set(), [], 0
    for row in rows:
        if get(row, "_provenance.cluster_id", str) != cluster:
            raise Unavailable("foreign Kubernetes cluster Service")
        _full(row, "core/v1/services:LIST")
        key = (_text(row, "metadata.namespace"), _text(row, "metadata.name"))
        uid = _text(row, "metadata.uid")
        if key in seen:
            raise Unavailable("duplicate Service identity")
        seen.add(key)
        kind = omitted(row, "spec.type", "ClusterIP", str)
        if kind not in {"ClusterIP", "NodePort", "LoadBalancer", "ExternalName"}:
            raise Unavailable("unrecognized Service type")
        ports = omitted(row, "spec.ports", [], list)
        if kind == "ExternalName" and not ports:
            continue
        if not ports:
            raise Unavailable("applicable Service port list is empty")
        if key not in selections:
            raise Unavailable("namespace/name-specific approved policy missing")
        applicable += 1
        for entry in list_of_objects(ports):
            port = get(entry, "port", int)
            protocol = omitted({**entry, "_provenance": row["_provenance"]}, "protocol", "TCP", str)
            if not 1 <= port <= 65535 or protocol not in {"TCP", "UDP", "SCTP"}:
                raise Unavailable("malformed declared Service port")
            if (port, protocol) not in selections[key]:
                bad.append({"namespace": key[0], "name": key[1], "uid": uid, "port": port, "protocol": protocol})
    if not applicable:
        return "NOT_APPLICABLE", {"reason": "No applicable declared Service ports in complete cluster inventory"}
    return result(bool(bad), applicable_service_count=applicable, unapproved_pairs=bad[:20],
                  semantics="Declared port/protocol pairs; targetPort and live reachability unassessed")


def _ise(item, index):
    _, scope = _subscription(index)
    rows = _by_id(_inventory(index, "integration_service_environment"), scope,
                  "Microsoft.Logic/integrationServiceEnvironments")
    identities, missing = [], []
    for rid, row in rows.items():
        _full(row, "Microsoft.Logic/integrationServiceEnvironments:GET", "2019-05-01")
        # An absent property is explicitly inconclusive in the signed predicate.
        config = get(row, "properties.encryptionConfiguration", dict)
        ref = omitted({**config, "_provenance": row["_provenance"]}, "encryptionKeyReference", None)
        if ref is None:
            missing.append(rid)
            continue
        if not isinstance(ref, dict):
            raise Unavailable("malformed ISE key reference")
        ref = {**ref, "_provenance": row["_provenance"]}
        name = omitted(ref, "keyName", None)
        vault_ref = omitted(ref, "keyVault", None)
        if vault_ref is not None and not isinstance(vault_ref, dict):
            raise Unavailable("malformed ISE vault reference")
        vault = None if vault_ref is None else omitted(
            {**vault_ref, "_provenance": row["_provenance"]}, "id", None)
        if name is not None and not isinstance(name, str) or vault is not None and not isinstance(vault, str):
            raise Unavailable("malformed ISE key identity")
        if not name or not vault:
            missing.append(rid)
            continue
        if not re.fullmatch(r"[A-Za-z0-9-]{1,127}", name):
            raise Unavailable("invalid Key Vault key name")
        vault = _arm(vault, resource_type="Microsoft.KeyVault/vaults")
        version = omitted(ref, "keyVersion", None)
        if version is not None and (not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9-]+", version)):
            raise Unavailable("invalid ISE key version")
        identities.append((vault, name, version))
    if missing:
        return result(True, missing_key_reference=missing[:20], ise_count=len(rows))
    if not rows:
        return result(False, ise_count=0)
    policy = _policy(index, "approved_ise_keys")
    approved = set()
    for key in list_of_objects(get(policy, "keys", list)):
        vault = _arm(get(key, "vault_id", str), resource_type="Microsoft.KeyVault/vaults")
        name = _text(key, "key_name")
        version = get(key, "key_version")
        if (not re.fullmatch(r"[A-Za-z0-9-]{1,127}", name)
                or version is not None and (not isinstance(version, str)
                                           or not re.fullmatch(r"[A-Za-z0-9-]+", version))):
            raise Unavailable("malformed approved key version")
        identity = (vault, name, version)
        if identity in approved:
            raise Unavailable("duplicate approved key identity")
        approved.add(identity)
    if any(identity not in approved for identity in identities):
        return unknown("ISE key identity is not approved by the available policy", ise_count=len(rows))
    return result(False, ise_count=len(rows), semantics="Approved configured CMK identities; key access and cryptographic use untested")


def _restore_policy(index):
    """Read either owner namespace with the same strict coverage and conflict rules."""
    _subscription(index)
    return _policy(index, 'restore_tests')


def _restore_history(index, jobs, protected, requirements, days, capture):
    from . import azure_backup_evidence as native
    end = native.now(index)
    windows = _inventory(index, 'backup_restore_window')
    vaults = _by_id(_inventory(index, 'recovery_vault'), _subscription(index)[1], 'Microsoft.RecoveryServices/vaults')
    required_vaults = {get(protected[rid], 'parent_id', str).casefold() for rid, _ in requirements}
    for vault_id in required_vaults:
        if vault_id not in vaults:
            raise Unavailable('required restore vault missing from native inventory')
        matches = [w for w in windows if get(w, 'vaultId', str).casefold() == vault_id]
        if len(matches) != 1:
            raise Unavailable('restore history registry vault binding unresolved')
        window = matches[0]
        _full(window, 'external:restore-test-registry')
        if (get(window, 'scope', str).casefold() != _subscription(index)[1].casefold()
                or not native.current(window, index)
                or native.instant(get(window, 'windowStart', str)) > end - timedelta(days=days)
                or native.instant(get(window, 'windowEnd', str)) < end
                or get(window, 'jobsComplete', bool) is not True or get(window, 'testsComplete', bool) is not True
                or any(get(window, key, str) != capture[key] for key in ('credential_context_id', 'customer_context_id'))):
            raise Unavailable('complete current independently authorized restore history unavailable')
        own_jobs = [job for job in jobs.values() if get(job, 'parent_id', str).casefold() == vault_id]
        if get(window, 'jobsInventorySha256', str) != native.backup_restore_digest({'jobs': own_jobs, 'capture': capture}):
            raise Unavailable('restore history native job digest differs')


def _restore(item, index):
    context, scope = _subscription(index)
    now = _time(get(context, "created_at", str))
    policy = _restore_policy(index)
    days = get(policy, "maxRestoreTestAgeDays", int)
    if not 1 <= days <= 365:
        raise Unavailable("annual restore-test window must be between 1 and 365 days")
    classes = {"customer", "derived", "provider"}
    requirements, covered = set(), set()
    for group in list_of_objects(get(policy, "data_classes", list)):
        data_class = get(group, "data_class", str)
        if data_class not in classes or data_class in covered:
            raise Unavailable("invalid contractual data class coverage")
        covered.add(data_class)
        ids = get(group, "required_item_ids", list)
        seen = set()
        for rid in ids:
            identity = _arm(rid, scope)
            if identity in seen:
                raise Unavailable("duplicate contractual protected item")
            seen.add(identity)
            requirements.add((identity, data_class))
    if covered != classes:
        raise Unavailable("contractual customer/derived/provider coverage incomplete")
    selected = get(policy, "requiredProtectedItemIds", list)
    selected_ids = [_arm(value, scope) for value in selected]
    if len(selected_ids) != len(set(selected_ids)) or set(selected_ids) != {rid for rid, _ in requirements}:
        raise Unavailable("required protected item scope inconsistent")
    if not requirements:
        raise Unavailable("contractual restore-test scope is empty")
    jobs = _by_id(_inventory(index, "backup_job"), scope)
    for rid, job in jobs.items():
        if not re.fullmatch(re.escape(scope.casefold()) + r"/resourcegroups/[^/]+/providers/microsoft.recoveryservices/vaults/[^/]+/backupjobs/[^/]+", rid):
            raise Unavailable("backup job native type unresolved")
        _text(job, "properties.jobType")
        _text(job, "properties.operation")
        status = get(job, "properties.status", str)
        if status not in {"Completed", "CompletedWithWarnings", "Failed", "Cancelled", "InProgress", "Cancelling"}:
            raise Unavailable("unrecognized backup job outcome")
        if status in {"Completed", "CompletedWithWarnings", "Failed", "Cancelled"}:
            end = _time(get(job, "properties.endTime", str))
            if end > now:
                raise Unavailable("backup job end time is in the future")
    from . import azure_backup_evidence as native
    capture = native.backup_restore_native_capture(index)
    protected = _by_id(_inventory(index, 'backup_protected_item'), scope)
    if any(rid not in protected for rid, _ in requirements):
        raise Unavailable('required restore item missing from native roster')
    _restore_history(index, jobs, protected, requirements, days, capture)
    records = _inventory(index, "restore_test_record")
    validated, failed, seen = set(), set(), set()
    for record in records:
        _full(record, "external:restore-validation")
        _text(record, "evidence_ref")
        if get(record, "scope", str).casefold() != scope.casefold():
            raise Unavailable("foreign restore validation scope")
        rid = _arm(get(record, "protected_item_id", str), scope)
        job_id = _arm(get(record, "job_id", str), scope)
        data_class = get(record, "data_class", str)
        if (rid, data_class) not in requirements:
            raise Unavailable("validation record lies outside contractual item/class scope")
        if get(record, "identity_basis", str) != "stable_resource_id":
            raise Unavailable("friendly names cannot establish protected item identity")
        _text(record, "identity_evidence_ref")
        stamp = _time(get(record, "validated_at", str))
        outcome = get(record, "validation_result", str)
        if stamp > now or outcome not in {"Passed", "Failed"}:
            raise Unavailable("validation date or usable-data outcome unresolved")
        key = (rid, data_class, job_id, stamp)
        if key in seen:
            raise Unavailable("duplicate restore validation record")
        seen.add(key)
        job = jobs.get(job_id)
        if job is None or get(job, "properties.operation", str) != "Restore":
            raise Unavailable("validation record has no exact Restore job join")
        # External evidence must explicitly bind the stable item to this exact
        # job; entityFriendlyName and a guessed universal entityId are unused.
        evidence = get(record, 'validationEvidence', dict)
        if get(evidence, 'dataClass', str) != data_class:
            raise Unavailable('independent restore result class mapping differs')
        canonical = {'protectedItemId': get(record, 'protected_item_id', str),
            'jobId': get(record, 'job_id', str), 'verifiedAt': get(record, 'validated_at', str),
            'verificationDocumentId': get(record, 'evidence_ref', str), 'result': outcome,
            'restoredDataVerified': get(record, 'restored_data_verified', bool),
            'sourceRecoveryPointId': get(record, 'source_recovery_point_id', str),
            'restoreTargetId': get(record, 'restore_target_id', str), 'validationEvidence': evidence}
        vault_id = get(protected[rid], 'parent_id', str)
        native.backup_restore_validation(canonical, job, protected[rid], index, vault_id, capture)
        end = _time(get(job, "properties.endTime", str))
        begin = _time(get(job, "properties.startTime", str))
        if begin > end:
            raise Unavailable('native Restore job timing contradicts')
        if stamp < end:
            raise Unavailable("data validation predates completion of Restore job")
        if now - timedelta(days=days) <= end <= stamp <= now:
            if get(job, "properties.status", str) == "Completed" and outcome == "Passed":
                validated.add((rid, data_class))
            else:
                failed.add((rid, data_class))
    missing = (requirements - validated) | failed
    return result(bool(missing), required_item_class_count=len(requirements),
                  validated_count=len(validated), missing_or_failed=sorted(missing)[:20],
                  recent_failed_validation_count=len(failed), maxRestoreTestAgeDays=days,
                  semantics="Dated external usable-data validation joined to exact ARM Restore job and stable protected item identity")


_SOURCE_CONTROLS = {"version_control", "confidentiality", "integrity", "authenticity",
                    "effective_permissions", "branch_controls", "provenance", "audit"}


def _source(item, index):
    context, scope = _subscription(index)
    now = _time(get(context, "created_at", str))
    policy = _policy(index, "provider_source_lifecycle")
    org = _text(policy, "organization_id")
    if get(policy, "provider_owned", bool) is not True:
        raise Unavailable("customer Azure DevOps controls do not prove provider lifecycle")
    max_age = get(policy, "max_age_seconds", int)
    if max_age <= 0:
        raise Unavailable("source lifecycle evidence freshness unresolved")
    required = {}
    for row in list_of_objects(get(policy, "repositories", list)):
        rid = _text(row, "repository_id")
        stages = get(row, "stage_ids", list)
        if rid in required or not stages or any(not isinstance(value, str) or not value for value in stages) or len(set(stages)) != len(stages):
            raise Unavailable("provider repository/stage coverage malformed")
        required[rid] = set(stages)
    if not required:
        raise Unavailable("provider repository ownership and development stages unresolved")
    repos = _inventory(index, "source_control")
    found = {}
    for repo in repos:
        rid = _text(repo, "id")
        if rid in found or get(repo, "organization_id", str) != org or get(repo, "owner", str) != "cloud_service_provider":
            raise Unavailable("repository organization or provider ownership unresolved")
        _full(repo, "AzureDevOps.repositories:LIST")
        found[rid] = repo
    if set(found) != set(required):
        raise Unavailable("complete provider repository scope unavailable")
    outcomes = {}
    for row in _inventory(index, "source_control_evidence"):
        _full(row, "external:provider-source-lifecycle")
        _text(row, "evidence_ref")
        if get(row, "scope", str).casefold() != scope.casefold():
            raise Unavailable("foreign source lifecycle evidence scope")
        if get(row, "organization_id", str) != org or get(row, "source_authority", str) != "provider_auditor":
            raise Unavailable("provider lifecycle evidence authority unresolved")
        rid, stage, control = _text(row, "repository_id"), _text(row, "stage_id"), _text(row, "control")
        if rid not in required or stage not in required[rid] or control not in _SOURCE_CONTROLS:
            raise Unavailable("foreign repository/stage/control evidence")
        stamp = _time(get(row, "observed_at", str))
        if stamp > now or (now - stamp).total_seconds() > max_age:
            raise Unavailable("stale or future lifecycle evidence")
        outcome = get(row, "outcome", str)
        if outcome not in {"enforced", "missing"}:
            raise Unavailable("effective control outcome unresolved")
        key = (rid, stage, control)
        if key in outcomes:
            raise Unavailable("ambiguous effective lifecycle evidence")
        outcomes[key] = outcome
    expected = {(rid, stage, control) for rid, stages in required.items() for stage in stages for control in _SOURCE_CONTROLS}
    if set(outcomes) != expected:
        raise Unavailable("effective permissions, policy inheritance, signatures or stage audit evidence incomplete")
    missing = sorted(key for key, value in outcomes.items() if value == "missing")
    return result(bool(missing), repository_count=len(repos), stage_control_count=len(outcomes),
                  missing_controls=missing[:20], semantics="Complete provider-owned lifecycle evidence; customer branch policies alone are insufficient")


_EDGE_TYPES = {"application_gateway": "Microsoft.Network/applicationGateways",
               "load_balancer": "Microsoft.Network/loadBalancers",
               "public_ip": "Microsoft.Network/publicIPAddresses",
               "frontdoor": "Microsoft.Network/frontDoors",
               "frontdoor_profile": "Microsoft.Cdn/profiles"}


def _coverage(row, field, parent):
    proof = get(row, "_coverage." + field, dict)
    if get(proof, "status", str) not in {"collected", "empty"} or get(proof, "parent_id", str).casefold() != parent or proof.get("nextLink"):
        raise Unavailable("incomplete or foreign edge detail: " + field)


def _waf(policy):
    _full(policy, "Azure.WAF:GET")
    rid = _arm(get(policy, "id", str))
    settings = get(policy, "properties.policySettings", dict)
    if "/applicationgatewaywebapplicationfirewallpolicies/" in rid:
        # Policy state has no documented default in this API; custom rule
        # state defaults to Enabled. Never apply the latter to policy state.
        state = get(settings, "state", str)
        custom = list_of_objects(get(policy, "properties.customRules", list))
        state_field = "state"
        default_versions = {"2025-09-01"}
        default_policy = False
    elif "/frontdoorwebapplicationfirewallpolicies/" in rid:
        state_field = "enabledState"
        custom = list_of_objects(get(policy, "properties.customRules.rules", list))
        default_versions = {"2022-05-01"}
        default_policy = True
        state = settings.get(state_field)
    else:
        raise Unavailable("unsupported WAF policy type")
    version = get(policy, "_provenance.api_version", str)
    if (get(policy, "properties.provisioningState", str) != "Succeeded"
            or get(policy, "properties.resourceState", str) not in {"Enabled", "Disabled"}):
        raise Unavailable("effective WAF policy provisioning unresolved")
    if state is None and default_policy and version in default_versions:
        state = omitted({**settings, "_provenance": policy["_provenance"]}, state_field, "Enabled", str)
    if state not in {"Enabled", "Disabled"}:
        raise Unavailable("WAF policy state/default unresolved")
    mode = get(settings, "mode", str)
    if mode not in {"Prevention", "Detection"}:
        raise Unavailable("WAF mode unresolved")
    for rule in custom:
        if state_field in rule:
            rule_state = get(rule, state_field, str)
        elif version in default_versions:
            rule_state = omitted({**rule, "_provenance": policy["_provenance"]}, state_field, "Enabled", str)
        else:
            raise Unavailable("WAF custom-rule state default unsupported")
        if rule_state not in {"Enabled", "Disabled"}:
            raise Unavailable("WAF custom-rule state unrecognized")
    return (state == "Enabled" and mode == "Prevention"
            and get(policy, "properties.resourceState", str) == "Enabled")


def _network(item, index):
    _, scope = _subscription(index)
    inventories = {kind: _by_id(_inventory(index, kind), scope, resource_type)
                   for kind, resource_type in _EDGE_TYPES.items()}
    all_resources = {rid: (kind, row) for kind, rows in inventories.items() for rid, row in rows.items()}
    bindings = {}
    for row in _inventory(index, "public_edge_binding"):
        _full(row, "Azure.publicEdgeProtection:resolve")
        rid = _arm(get(row, "resource_id", str), scope)
        if rid not in all_resources or rid in bindings or get(row, "resource_kind", str) != all_resources[rid][0]:
            raise Unavailable("edge binding identity unresolved")
        if get(row, "resource_etag", str) != _text(all_resources[rid][1], "etag"):
            raise Unavailable("edge binding refers to a different resource version")
        bindings[rid] = row
    if set(bindings) != set(all_resources):
        raise Unavailable("complete public frontend and effective protection resolution required")
    public, failed = [], []
    vn = None
    plans = None
    waf = None
    for rid, (kind, resource) in all_resources.items():
        binding = bindings[rid]
        is_public = get(binding, "public", bool)
        _coverage(binding, "frontends", rid)
        frontends = get(binding, "public_frontend_ids", list)
        if any(not isinstance(value, str) for value in frontends) or len(frontends) != len({value.casefold() for value in frontends}):
            raise Unavailable("malformed public frontend bindings")
        if (get(binding, "_coverage.frontends.status", str) == "empty") != (not frontends):
            raise Unavailable("public frontend coverage contradicts its inventory")
        if kind == "public_ip":
            if not is_public or frontends != [get(resource, "id", str)]:
                raise Unavailable("Public IP applicability incorrectly resolved")
        elif kind in {"application_gateway", "load_balancer"}:
            _full(resource)
            actual, seen_frontends = [], set()
            for frontend in list_of_objects(get(resource, "properties.frontendIPConfigurations", list)):
                fid = _arm(get(frontend, "id", str), scope)
                prefix = rid + "/frontendipconfigurations/"
                if (not fid.startswith(prefix) or "/" in fid[len(prefix):]
                        or fid in seen_frontends):
                    raise Unavailable("foreign public frontend identity")
                seen_frontends.add(fid)
                props = get(frontend, "properties", dict)
                ref = omitted({**props, "_provenance": resource["_provenance"]}, "publicIPAddress", None)
                if ref is not None:
                    ip_id = _arm(get(ref, "id", str), scope, _EDGE_TYPES["public_ip"])
                    if ip_id not in inventories["public_ip"]:
                        raise Unavailable("public frontend IP join unresolved")
                    actual.append(fid)
            if {value.casefold() for value in frontends} != set(actual) or is_public != bool(actual):
                raise Unavailable("public frontend evidence conflicts with native resource")
        else:
            _full(resource)
            if kind == "frontdoor":
                endpoints = list_of_objects(get(resource, "properties.frontendEndpoints", list))
                child_type = "/frontendendpoints/"
            else:
                if get(resource, "sku.name", str) not in {"Standard_AzureFrontDoor", "Premium_AzureFrontDoor"}:
                    raise Unavailable("unsupported Front Door profile product")
                _coverage(resource, "endpoints", rid)
                endpoints = list_of_objects(get(resource, "endpoints", list))
                if (get(resource, "_coverage.endpoints.status", str) == "empty") != (not endpoints):
                    raise Unavailable("inconsistent Front Door endpoint paging coverage")
                child_type = "/afdendpoints/"
            actual = []
            for endpoint in endpoints:
                eid = _arm(get(endpoint, "id", str), scope)
                if not eid.startswith(rid + child_type) or "/" in eid[len(rid + child_type):]:
                    raise Unavailable("foreign Front Door endpoint identity")
                _text(endpoint, "properties.hostName")
                if eid in actual:
                    raise Unavailable("duplicate Front Door endpoint")
                actual.append(eid)
            if (is_public != bool(actual)
                    or {value.casefold() for value in frontends} != set(actual)):
                raise Unavailable("Front Door public endpoint scope unresolved")
        if not is_public:
            continue
        public.append(rid)
        if kind in {"frontdoor", "frontdoor_profile"}:
            _coverage(binding, "ddos", rid)
            ddos = get(binding, "ddos", dict)
            if get(ddos, "resource_id", str).casefold() != rid:
                raise Unavailable("foreign Front Door DDoS product mapping")
            _text(ddos, "mapping_ref")
            _text(ddos, "evidence_ref")
            state = get(ddos, "state", str)
            if state not in {"Protected", "Unprotected"}:
                raise Unavailable("unsupported Front Door DDoS product mapping")
            if state == "Unprotected":
                failed.append((rid, "ddos"))
        # Every Public IP is assessed separately; gateway/LB exact bindings
        # are validated here so protection cannot be borrowed from another IP.
        elif kind == "public_ip":
            _full(resource, "Microsoft.Network/publicIPAddresses:GET")
            settings = get(resource, "properties.ddosSettings", dict)
            mode = get(settings, "protectionMode", str)
            if mode == "Disabled":
                failed.append((rid, "ddos"))
            elif mode == "Enabled":
                plan = omitted({**settings, "_provenance": resource["_provenance"]}, "ddosProtectionPlan", None)
                if plan is not None:
                    plan_id = _arm(get(plan, "id", str), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plans is None:
                        plans = _by_id(_inventory(index, "ddos_plan"), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plan_id not in plans or get(plans[plan_id], "properties.provisioningState", str) != "Succeeded":
                        raise Unavailable("Public IP DDoS plan not resolved or provisioned")
            elif mode == "VirtualNetworkInherited":
                _coverage(binding, "inherited_vnet", rid)
                vnet_id = _arm(get(binding, "inherited_vnet_id", str), scope, "Microsoft.Network/virtualNetworks")
                _text(binding, "vnet_association_evidence_ref")
                if vn is None:
                    vn = _by_id(_inventory(index, "vnet"), scope, "Microsoft.Network/virtualNetworks")
                if vnet_id not in vn:
                    raise Unavailable("inherited VNet exact association unresolved")
                vnet = vn[vnet_id]
                enabled = get(vnet, "properties.enableDdosProtection", bool)
                if not enabled:
                    failed.append((rid, "ddos"))
                else:
                    plan_id = _arm(get(vnet, "properties.ddosProtectionPlan.id", str), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plans is None:
                        plans = _by_id(_inventory(index, "ddos_plan"), scope, "Microsoft.Network/ddosProtectionPlans")
                    if plan_id not in plans or get(plans[plan_id], "properties.provisioningState", str) != "Succeeded":
                        raise Unavailable("inherited DDoS plan not resolved or provisioned")
            else:
                raise Unavailable("unrecognized public IP DDoS protection mode")
        if kind in {"application_gateway", "frontdoor", "frontdoor_profile"}:
            _coverage(binding, "effective_waf", rid)
            _text(binding, "waf_linkage_evidence_ref")
            policies = get(binding, "effective_waf_policy_ids", list)
            # An explicit null represents a fully resolved route/domain with
            # no WAF. [] is an unresolved public route set, never a PASS.
            if not policies:
                raise Unavailable("effective public WAF route/domain coverage empty")
            for policy_id in policies:
                if policy_id is None:
                    failed.append((rid, "waf"))
                    continue
                pid = _arm(policy_id, scope)
                if waf is None:
                    waf = _by_id(_inventory(index, "waf_policy"), scope)
                if pid not in waf:
                    raise Unavailable("effective WAF policy reference unresolved")
                expected_type = ("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
                                 if kind == "application_gateway" else
                                 "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies")
                _arm(policy_id, scope, expected_type)
                if not _waf(waf[pid]):
                    failed.append((rid, "waf"))
    if not public:
        return "NOT_APPLICABLE", {"reason": "Complete inventories and frontend resolution prove no public resources"}
    return result(bool(failed), public_resource_count=len(public), missing_protections=failed[:20],
                  semantics="Exact configured IP/VNet/plan and complete effective WAF bindings; traffic and mitigation efficacy untested")


_DEFINITIONS = {
    NETWORK_ID: (_network, [*_EDGE_TYPES, "public_edge_binding"], "scope"),
    CREDENTIAL_ID: (_credentials, ["service_principal"], "resource"),
    RESTORE_ID: (_restore, ["backup_job", "restore_test_record", "backup_protected_item", "recovery_vault", "backup_restore_window"], "scope"),
    SOURCE_ID: (_source, ["source_control", "source_control_evidence"], "scope"),
    EASM_ID: (_easm, ["easm_workspace"], "scope"),
    ARC_ID: (_arc, ["arc_kubernetes_cluster"], "scope"),
    PORT_ID: (_ports, ["service"], "scope"),
    ISE_ID: (_ise, ["integration_service_environment"], "scope"),
}


def _install(check_id):
    spec = SPECS[check_id]
    evaluator, dependencies, target = _DEFINITIONS[check_id]
    category = spec["category"]
    accepted = {"hardening", "exposure", "least_privilege", "iam_graph", "network"}
    @register(check_id, "azure", category if category in accepted else "hardening",
              spec["resource_kind"], spec["title"], spec["severity"], "CM-6",
              spec["remediation_hint"], dependencies=dependencies, target=target)
    def evaluate(item, index):
        if target == "scope":
            context, scope = _context(index)
            if (get(item, "scope", str) != scope
                    or get(item, "provider", str) != get(context, "provider", str)):
                raise Unavailable("scope evaluation target differs from snapshot authority")
        return evaluator(item, index)
    # Preserve signed domain categories despite the registry's legacy validator,
    # as in the wave-1 signed modules. No shared validator is changed.
    check = CHECKS[-1]
    CHECKS[-1] = replace(check, category=category)
    evaluate.__name__ = check_id.replace(".", "_")
    return CHECKS[-1]


LOCAL_CHECKS = {check_id: _install(check_id) for check_id in IDS}
