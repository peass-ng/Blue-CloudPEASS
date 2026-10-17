"""Signed Azure compliance checks; pure evaluation of complete scoped facts.

Auxiliary evidence contracts are documented in sw21-collector-requests.md.
No evaluator performs cloud calls or authentication attempts.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
import math
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects, optional

SPECS = {'azure_purview_account_a3_2_5_1_2_6690c25': {'id': 'azure_purview_account_a3_2_5_1_2_6690c25',
                                              'provider': 'azure',
                                              'resource_kind': 'purview_account',
                                              'data_source': 'Paged ARM Microsoft.Purview/accounts '
                                                             'ListBySubscription 2021-12-01: location '
                                                             'string, properties.provisioningState and '
                                                             'optional '
                                                             'properties.accountStatus.accountProvisioningState '
                                                             'enum; policy requiredRegions and authoritative '
                                                             'mapping of the source ENABLED status to '
                                                             'Purview service availability.',
                                              'predicate': 'For each required region, PASS only if a Purview '
                                                           'account is present with '
                                                           'provisioningState=Succeeded and authoritative '
                                                           'service status evidence maps it to the frozen '
                                                           'requirement ENABLED. FAIL if complete account '
                                                           'inventory proves no account in the region or '
                                                           'explicit failed/disabled service state. UNKNOWN '
                                                           'if requiredRegions, status mapping, optional '
                                                           'accountStatus, region normalization or '
                                                           'pagination is unavailable. Provisioning '
                                                           'Succeeded alone does not prove the source '
                                                           'status.',
                                              'severity': 'medium',
                                              'category': 'hardening',
                                              'title': 'Provision Purview in required Azure regions',
                                              'description': 'Provision Purview in required Azure regions. A '
                                                             'finding is raised when any required region '
                                                             'lacks a Succeeded Purview account.',
                                              'remediation_hint': 'Provision and enable a Purview account in '
                                                                  'each required region; verify service '
                                                                  'status as well as ARM provisioning '
                                                                  'state.'},
 'azure.cis.entra_activity_diagnostic': {'id': 'azure.cis.entra_activity_diagnostic',
                                         'provider': 'azure',
                                         'resource_kind': 'entra_diagnostic_setting',
                                         'data_source': 'NEW: tenant-scoped GET '
                                                        '/providers/Microsoft.aadiam/diagnosticSettings?api-version=2017-04-01, '
                                                        'follow nextLink; properties.logs[].category/enabled '
                                                        'and destination IDs. Do not use Graph audit event '
                                                        'lists as configuration.',
                                         'predicate': 'PASS when the complete tenant diagnostic-settings '
                                                      'list proves at least one enabled Microsoft Entra '
                                                      'activity-log category is routed to an approved '
                                                      'supported destination. FAIL when complete inventory '
                                                      'has no enabled activity-log export to an approved '
                                                      'sink. UNKNOWN when required activity categories, '
                                                      'destination approval, settings list or destination '
                                                      'identity cannot be resolved. If policy requires both '
                                                      'AuditLogs and SignInLogs, verify each explicitly.',
                                         'severity': 'medium',
                                         'category': 'logging',
                                         'title': 'Export Entra audit and sign-in logs',
                                         'description': 'Checks tenant-level Entra activity-log diagnostic '
                                                        'export to an appropriate approved destination.',
                                         'remediation_hint': 'Microsoft Entra ID > Monitoring & health > '
                                                             'Diagnostic settings: export the '
                                                             'policy-required activity-log categories to an '
                                                             'approved Log Analytics workspace, storage '
                                                             'account or Event Hub.'},
 'azure.cis.entra_graph_activity_diagnostic': {'id': 'azure.cis.entra_graph_activity_diagnostic',
                                               'provider': 'azure',
                                               'resource_kind': 'entra_diagnostic_setting',
                                               'data_source': 'Tenant ARM '
                                                              'Microsoft.aadiam/diagnosticSettings LIST '
                                                              '2017-04-01: '
                                                              'value[].properties.logs[].category (string), '
                                                              'enabled (boolean), '
                                                              'workspaceId/storageAccountId/eventHubAuthorizationRuleId '
                                                              '(strings).',
                                               'predicate': 'FAIL if a complete tenant diagnostic-settings '
                                                            'list has no enabled MicrosoftGraphActivityLogs '
                                                            'log routed to an approved destination. PASS if '
                                                            'one exists with a resolvable approved '
                                                            'destination. UNKNOWN if settings, sink policy '
                                                            'or destination validation is incomplete.',
                                               'severity': 'medium',
                                               'category': 'logging',
                                               'title': 'Export Microsoft Graph activity logs',
                                               'description': 'Export Microsoft Graph activity logs. A '
                                                              'finding is raised when complete tenant '
                                                              'diagnostic settings contain no enabled '
                                                              'MicrosoftGraphActivityLogs category with a '
                                                              'destination.',
                                               'remediation_hint': 'Microsoft Entra admin center > '
                                                                   'Monitoring & health > Diagnostic '
                                                                   'settings: add MicrosoftGraphActivityLogs '
                                                                   'and route it to the approved Log '
                                                                   'Analytics workspace, storage account or '
                                                                   'event hub.'},
 'azure.gap.databox_job_double_encryption_enabled': {'id': 'azure.gap.databox_job_double_encryption_enabled',
                                                     'provider': 'azure',
                                                     'resource_kind': 'databox_job',
                                                     'data_source': 'New paged ARM GET '
                                                                    '/subscriptions/{sub}/providers/Microsoft.DataBox/jobs?api-version=2025-07-01; '
                                                                    'request details expansion or GET '
                                                                    '{jobId}?api-version=2025-07-01&$expand=details '
                                                                    'for each job. Exact path '
                                                                    'properties.details.preferences.encryptionPreferences.doubleEncryption '
                                                                    'is enum string Enabled/Disabled; join '
                                                                    'SKU support matrix and follow nextLink. '
                                                                    'Collector has no databox_job kind.',
                                                     'predicate': 'PASS if every in-scope job on a SKU '
                                                                  'supporting double encryption has '
                                                                  'properties.details.preferences.encryptionPreferences.doubleEncryption="Enabled". '
                                                                  'FAIL if an applicable fully expanded job '
                                                                  'says "Disabled" or omits the preference '
                                                                  'where the documented Disabled default '
                                                                  'applies. UNKNOWN if details were not '
                                                                  'expanded, SKU support is unknown, the '
                                                                  'response is partial, or any job page '
                                                                  'failed; unsupported SKUs are excluded '
                                                                  'only with proof.',
                                                     'severity': 'medium',
                                                     'category': 'encryption',
                                                     'title': 'Azure Data Box jobs should enable double '
                                                              'encryption for data at rest on the device',
                                                     'description': 'Data Box device software encryption '
                                                                    'adds a second encryption layer when '
                                                                    'enabled.',
                                                     'remediation_hint': 'For a new Data Box order, set '
                                                                         'double encryption to Enabled in '
                                                                         'job encryption preferences before '
                                                                         'submission; replace an already '
                                                                         'dispatched noncompliant order.'},
 'azure.gap.databox_job_unlock_password_encrypted_with_cmk': {'id': 'azure.gap.databox_job_unlock_password_encrypted_with_cmk',
                                                              'provider': 'azure',
                                                              'resource_kind': 'databox_job',
                                                              'data_source': 'Paged Microsoft.DataBox/jobs '
                                                                             'LIST and per-job GET '
                                                                             '2025-07-01 with '
                                                                             '$expand=details: '
                                                                             'properties.details.keyEncryptionKey.kekType,kekUrl,kekVaultResourceID; '
                                                                             'job identity and approved '
                                                                             'key/vault IDs; resolve Key '
                                                                             'Vault access.',
                                                              'predicate': 'For each Data Box job, require a '
                                                                           'complete GET with '
                                                                           '$expand=details. PASS only when '
                                                                           'properties.details.keyEncryptionKey.kekType=CustomerManaged, '
                                                                           'kekUrl is a valid approved Key '
                                                                           'Vault key URL, '
                                                                           'kekVaultResourceID is its vault '
                                                                           'ARM ID, and the configured job '
                                                                           'identity can use that key. FAIL '
                                                                           'for MicrosoftManaged, including '
                                                                           'omitted kekType with the '
                                                                           'documented MicrosoftManaged '
                                                                           'default in an otherwise complete '
                                                                           'expanded response, or a fully '
                                                                           'observed invalid CustomerManaged '
                                                                           'configuration. UNKNOWN for '
                                                                           'absent details, unknown enum, '
                                                                           'unresolved key/identity '
                                                                           'authorization, missing approval, '
                                                                           'or incomplete paged job '
                                                                           'inventory. No jobs is '
                                                                           'NOT_APPLICABLE.',
                                                              'severity': 'medium',
                                                              'category': 'encryption',
                                                              'title': 'Encrypt Data Box unlock keys with a '
                                                                       'customer-managed key',
                                                              'description': 'Encrypt Data Box unlock keys '
                                                                             'with a customer-managed key. A '
                                                                             'finding is raised when '
                                                                             'keyEncryptionKey.kekType is '
                                                                             'MicrosoftManaged for an '
                                                                             'applicable job.',
                                                              'remediation_hint': 'For the Data Box job, '
                                                                                  'configure a '
                                                                                  'CustomerManaged '
                                                                                  'keyEncryptionKey with an '
                                                                                  'approved Key Vault key '
                                                                                  'URL, vault resource ID, '
                                                                                  'and required managed '
                                                                                  'identity access.'},
 'azure.other.lb_weight_change_authorized': {'id': 'azure.other.lb_weight_change_authorized',
                                             'provider': 'azure',
                                             'resource_kind': 'load_balancer',
                                             'data_source': 'Paged ARM Activity Logs LIST 2015-04-01 over '
                                                            'policy observation window plus independent '
                                                            'inventory of load-balancer routing-weight '
                                                            'changes; caller, operationName.value, '
                                                            'resourceId, status.value, correlationId; '
                                                            'policy-listed routing operations and trusted '
                                                            'immutable actor IDs; durable log destination '
                                                            'and delivery evidence.',
                                             'predicate': 'For every routing-weight change in the '
                                                          'independent complete change inventory and '
                                                          'observation window, require a successful Activity '
                                                          'Log event (or equivalent authoritative data-plane '
                                                          'audit event) joined by resource, operation and '
                                                          'time, an explicitly trusted immutable actor '
                                                          'identity, and proof of durable log delivery. FAIL '
                                                          'for a measured change by an untrusted actor or a '
                                                          'measured change with no required log. PASS when '
                                                          'all changes are covered, including a complete '
                                                          'zero-change window. UNKNOWN without independent '
                                                          'change completeness, actor resolution, event '
                                                          'pages, operation mapping, window or log-delivery '
                                                          'evidence.',
                                             'severity': 'high',
                                             'category': 'hardening',
                                             'title': 'Authorize load-balancer routing changes',
                                             'description': 'Checks observed successful load-balancer '
                                                            'routing changes in a configured lookback window '
                                                            'against approved caller IDs.',
                                             'remediation_hint': 'Remove untrusted identities from '
                                                                 'load-balancer routing change access and '
                                                                 'configure durable Activity Log export; '
                                                                 'investigate and record each unauthorized '
                                                                 'or unlogged weight change.'},
 'azure.other.database_default_login_restricted': {'id': 'azure.other.database_default_login_restricted',
                                                   'provider': 'azure',
                                                   'resource_kind': 'database_server',
                                                   'data_source': 'ARM SQL servers GET 2023-08-01 plus '
                                                                  'Microsoft.Sql/servers/azureADOnlyAuthentications/default '
                                                                  'GET; enumerate configured SQL logins in '
                                                                  'master and execute authorized negative '
                                                                  'authentication tests using the '
                                                                  'organization list of known default '
                                                                  'credentials.',
                                                   'predicate': 'FAIL if a known default credential '
                                                                'authenticates successfully. PASS only if '
                                                                'every approved default-credential test '
                                                                'fails with access denied, the tested '
                                                                'endpoint/server inventory is complete, and '
                                                                'no untested authentication path remains. '
                                                                'UNKNOWN when the credential baseline, test '
                                                                'authorization/results, endpoint inventory '
                                                                'or SQL catalog is incomplete. Entra-only '
                                                                'authentication is supporting configuration '
                                                                'evidence, not sole proof.',
                                                   'severity': 'high',
                                                   'category': 'hardening',
                                                   'title': 'Default SQL logins are restricted',
                                                   'description': 'ARM administrator metadata alone cannot '
                                                                  'establish whether SQL default logins are '
                                                                  'enabled.',
                                                   'remediation_hint': 'Disable or rotate known default SQL '
                                                                       'credentials, enable Entra-only '
                                                                       'authentication where supported, and '
                                                                       'repeat denied-login tests.'},
 'azure.other.entra_password_baseline': {'id': 'azure.other.entra_password_baseline',
                                         'provider': 'azure',
                                         'resource_kind': 'entra_domain',
                                         'data_source': 'Microsoft Graph v1.0 GET '
                                                        '/domains?$select=id,passwordValidityPeriodInDays,passwordNotificationWindowInDays,authenticationType '
                                                        '(follow @odata.nextLink); policy input '
                                                        'approvedPasswordBaseline; federated IdP settings '
                                                        'supplied separately. Graph does not expose every '
                                                        'password complexity rule.',
                                         'predicate': 'For each newly provisioned in-scope cloud identity, '
                                                      'FAIL only when a measured domain/IdP setting or '
                                                      'account-level policy violates an explicit '
                                                      'approvedPasswordBaseline bound. PASS only when '
                                                      'provisioning evidence links every new identity to an '
                                                      'effective managed or federated policy and every '
                                                      'required PCI baseline item, including complexity and '
                                                      'lockout, is directly verified. UNKNOWN when only '
                                                      'Graph domain expiration/notification fields are '
                                                      'available, or baseline, new-account inventory, '
                                                      'federated settings or required policy fields are '
                                                      'missing.',
                                         'severity': 'high',
                                         'category': 'identity',
                                         'title': 'Observable Entra password settings meet approved baseline',
                                         'description': 'Assesses only password policy settings exposed by '
                                                        'Graph; federated IdP and user password state need '
                                                        'separate evidence.',
                                         'remediation_hint': 'Configure the approved PCI password baseline '
                                                             'in Entra or the federated IdP and retain '
                                                             'effective policy plus new-account provisioning '
                                                             'evidence; set managed-domain '
                                                             'expiration/notification values where '
                                                             'required.'},
 'azure.other.entra_identity_audit_events': {'id': 'azure.other.entra_identity_audit_events',
                                             'provider': 'azure',
                                             'resource_kind': 'entra_audit_log',
                                             'data_source': 'Graph v1.0 paged /auditLogs/directoryAudits and '
                                                            '/auditLogs/signIns for optional freshness '
                                                            'checks. Tenant ARM '
                                                            'Microsoft.AADIAM/diagnosticSettings LIST '
                                                            'api-version=2017-04-01: '
                                                            'value[].properties.logs[].category/enabled and '
                                                            'setting-level '
                                                            'properties.workspaceId/storageAccountId/eventHubAuthorizationRuleId. '
                                                            'Resolve approved sink and its retention using '
                                                            'Log Analytics table retention, Storage '
                                                            'lifecycle/immutability, or Event Hubs '
                                                            'configuration; approved minimumRetentionDays '
                                                            'policy.',
                                             'predicate': 'For the narrow AuditLogs and SignInLogs export '
                                                          'subcheck, require a complete tenant '
                                                          'diagnostic-setting inventory, both categories '
                                                          'enabled, and at least one approved reachable sink '
                                                          'per category with measured effective retention >= '
                                                          'minimumRetentionDays; FAIL the subcheck on a '
                                                          'fully measured missing category, '
                                                          'unapproved/unreachable sink, or short retention; '
                                                          'UNKNOWN on unresolved scope, sink, retention, '
                                                          'policy or paging. For the mapped broad '
                                                          'identity-activity requirements, return UNKNOWN '
                                                          'unless separate evidence proves all required '
                                                          'event classes, privileged-action coverage, and '
                                                          'the required time window; do not report full PASS '
                                                          'from these two log categories alone.',
                                             'severity': 'high',
                                             'category': 'identity',
                                             'title': 'Entra audit and sign-in logs are exported and '
                                                      'retained',
                                             'description': 'Checks diagnostic export and destination '
                                                            'retention. Historical Graph events cannot prove '
                                                            'that every expected identity event was '
                                                            'generated.',
                                             'remediation_hint': 'In Entra admin center > Monitoring & '
                                                                 'health > Diagnostic settings, export '
                                                                 'AuditLogs and SignInLogs to approved '
                                                                 'sinks, verify their effective retention, '
                                                                 'and add sources needed for privileged '
                                                                 'activity coverage.'},
 'azure_frontdoor_1_2_8_4_90159db': {'id': 'azure_frontdoor_1_2_8_4_90159db',
                                     'provider': 'azure',
                                     'resource_kind': 'afd_security_policy',
                                     'data_source': 'New paged Microsoft.Cdn/profiles/securityPolicies, '
                                                    'customDomains, afdEndpoints/routes List 2024-02-01 and '
                                                    'WAF policy GET 2023-09-01. Security policy '
                                                    'properties.parameters.type, wafPolicy.id, '
                                                    'associations[].domains[].id, patternsToMatch; WAF '
                                                    'properties.policySettings.enabledState enum '
                                                    'Enabled/Disabled.',
                                     'predicate': 'For each publicly routed Front Door Standard/Premium '
                                                  'domain and route pattern, PASS only if a '
                                                  'WebApplicationFirewall security policy association covers '
                                                  'the exact effective domain and path pattern with a valid '
                                                  'WAF policy ID whose effective policySettings.enabledState '
                                                  'is Enabled (including its documented omitted-state '
                                                  'default). FAIL if complete profile, route, association '
                                                  'and WAF inventories prove an uncovered or disabled route. '
                                                  'UNKNOWN on unresolved associations, wildcard-pattern '
                                                  'semantics, WAF GET failure or incomplete pages. Complete '
                                                  'empty routed-domain scope is NOT_APPLICABLE.',
                                     'severity': 'high',
                                     'category': 'network',
                                     'title': 'Front Door Standard and Premium domains have WAF coverage',
                                     'description': 'Checks Front Door Standard/Premium WAF security policy '
                                                    'associations; classic Front Door is covered by the '
                                                    'native check.',
                                     'remediation_hint': 'Azure portal > Front Door > Security policies: '
                                                         'Associate each public Front Door domain and route '
                                                         'pattern with a WAF security policy.'},
 'azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a': {'id': 'azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a',
                                                                    'provider': 'azure',
                                                                    'resource_kind': 'mysql_postgresql_sql_server',
                                                                    'data_source': 'Paged SQL Server, MySQL '
                                                                                   'Flexible Server and '
                                                                                   'PostgreSQL Flexible '
                                                                                   'Server GET/LIST plus '
                                                                                   'each server '
                                                                                   'firewall-rules LIST, '
                                                                                   'using the matching '
                                                                                   'resource API version. '
                                                                                   'Read SQL '
                                                                                   'properties.publicNetworkAccess '
                                                                                   'and flexible-server '
                                                                                   'properties.network.publicNetworkAccess, '
                                                                                   'every firewall rule '
                                                                                   'startIpAddress/endIpAddress, '
                                                                                   'SQL Allow Azure services '
                                                                                   'special rule, and any '
                                                                                   'applicable public '
                                                                                   'trusted-service bypass. '
                                                                                   'PublicNetworkAccess=Enabled '
                                                                                   'alone is not proof of '
                                                                                   'reachable ingress.',
                                                                    'predicate': 'For every in-scope SQL, '
                                                                                 'MySQL and PostgreSQL '
                                                                                 'server, FAIL when '
                                                                                 'publicNetworkAccess is '
                                                                                 'Enabled and a complete '
                                                                                 'effective firewall/bypass '
                                                                                 'configuration admits an '
                                                                                 'external public client, '
                                                                                 'including an unrestricted '
                                                                                 '0.0.0.0-255.255.255.255 '
                                                                                 'range or applicable '
                                                                                 'Azure-service bypass. PASS '
                                                                                 'when publicNetworkAccess '
                                                                                 'is Disabled, or when it is '
                                                                                 'Enabled but complete '
                                                                                 'effective firewall '
                                                                                 'evidence proves no '
                                                                                 'external public client can '
                                                                                 'connect. UNKNOWN when '
                                                                                 'access mode, firewall '
                                                                                 'rules, bypass semantics or '
                                                                                 'pages are unresolved. '
                                                                                 'Complete empty inventory '
                                                                                 'is NOT_APPLICABLE.',
                                                                    'severity': 'high',
                                                                    'category': 'network',
                                                                    'title': 'Database servers have no '
                                                                             'full-range public IPv4 '
                                                                             'firewall rule',
                                                                    'description': 'Detects database servers '
                                                                                   'with enabled public '
                                                                                   'networking and an '
                                                                                   'explicit '
                                                                                   '0.0.0.0-255.255.255.255 '
                                                                                   'rule.',
                                                                    'remediation_hint': 'For each affected '
                                                                                        'SQL, MySQL or '
                                                                                        'PostgreSQL server, '
                                                                                        'set public network '
                                                                                        'access to Disabled '
                                                                                        'and provide '
                                                                                        'approved private '
                                                                                        'connectivity; '
                                                                                        'verify the '
                                                                                        'effective server '
                                                                                        'property.'},
 'azure_pci_10_2_1_1_16': {'id': 'azure_pci_10_2_1_1_16',
                           'provider': 'azure',
                           'resource_kind': 'container_group',
                           'data_source': 'Paged Container Instance group inventory and per-group GET '
                                          '2023-05-01: '
                                          'properties.diagnostics.logAnalytics.workspaceId/logType plus '
                                          'properties.containers[]; container logging enablement from '
                                          'supported runtime configuration or fresh per-container '
                                          'log/ingestion evidence.',
                           'predicate': 'For every active container group, PASS only when a valid Log '
                                        'Analytics workspace is configured and at least one container '
                                        'definition has logging enabled with verified collection evidence. '
                                        'FAIL if complete group/container evidence proves workspace absent '
                                        'or all container logging disabled; UNKNOWN if per-container logging '
                                        'cannot be established, group GET is incomplete, workspace ID cannot '
                                        'be resolved or inventory is partial. logType alone does not '
                                        'establish logging in a container definition.',
                           'severity': 'medium',
                           'category': 'hardening',
                           'title': 'Enable Azure Container Instances Log Analytics diagnostics',
                           'description': 'Enable Azure Container Instances Log Analytics diagnostics. A '
                                          'finding is raised when an active container group lacks '
                                          'logAnalytics.workspaceId or an allowed logType.',
                           'remediation_hint': 'Configure the container group Log Analytics workspace and '
                                               'enable logging in at least one container; verify logs reach '
                                               'the workspace.'},
 'azure_firewall_policy_10_2_1_1_24_0781f5f': {'id': 'azure_firewall_policy_10_2_1_1_24_0781f5f',
                                               'provider': 'azure',
                                               'resource_kind': 'azure_firewall',
                                               'data_source': 'Paged azureFirewalls GET 2023-09-01; '
                                                              'per-firewall diagnosticSettings LIST '
                                                              '2021-05-01-preview and '
                                                              'diagnosticSettingsCategories LIST. Use '
                                                              'setting.properties.logs[].category/categoryGroup/enabled '
                                                              'and '
                                                              'setting.properties.workspaceId/storageAccountId/eventHubAuthorizationRuleId; '
                                                              'policy requiredCategories and approved sink '
                                                              'IDs.',
                                               'predicate': 'For each Firewall, PASS only if every '
                                                            'policy-required supported log category (or '
                                                            'allLogs group) is enabled in its own '
                                                            'diagnostics and routed to an approved sink; '
                                                            'FAIL if complete category/settings lists prove '
                                                            'a gap; UNKNOWN if requiredCategories, supported '
                                                            'categories, sink approval or inventory is '
                                                            'missing.',
                                               'severity': 'high',
                                               'category': 'logging',
                                               'title': 'Azure Firewall diagnostic logs cover required '
                                                        'categories',
                                               'description': 'Checks Azure Firewall diagnostic category '
                                                              'export to an approved destination.',
                                               'remediation_hint': 'Azure portal > Azure Firewall > '
                                                                   'Diagnostic settings: Enable required '
                                                                   'firewall log categories in diagnostic '
                                                                   'settings and route them to an approved '
                                                                   'sink.'},
 'azure_storage_file_share_10_3_3_15_f2d7075': {'id': 'azure_storage_file_share_10_3_3_15_f2d7075',
                                                'provider': 'azure',
                                                'resource_kind': 'storage_file_share_and_backup_item',
                                                'data_source': 'Paged '
                                                               'Microsoft.Storage/storageAccounts/fileServices/default/shares '
                                                               'LIST api-version=2023-05-01 for every scoped '
                                                               'storage account; paged '
                                                               'Microsoft.RecoveryServices/vaults/backupProtectedItems '
                                                               'LIST api-version=2024-04-01 across all '
                                                               'accessible scoped vaults. Join '
                                                               'protectedItem.properties.sourceResourceId to '
                                                               'the parent account ID, friendlyName to share '
                                                               'name, and '
                                                               'protectedItemType=AzureFileShareProtectedItem; '
                                                               'read policyId and protectionState.',
                                                'predicate': 'For every enumerated Azure Files share, PASS '
                                                             'only if exactly one protected item joins on '
                                                             'normalized storage-account ID plus share name, '
                                                             'policyId is nonempty, and '
                                                             'protectionState="Protected". FAIL if complete '
                                                             'share and all-vault inventories prove no '
                                                             'matching protected item, a unique match has no '
                                                             'policyId, or its state is ProtectionStopped, '
                                                             'ProtectionError, ProtectionPaused or '
                                                             'BackupsSuspended. UNKNOWN for duplicates, '
                                                             'IRPending/Invalid/unrecognized state, missing '
                                                             'join fields, inaccessible vaults or incomplete '
                                                             'pages. A complete empty share inventory is '
                                                             'NOT_APPLICABLE.',
                                                'severity': 'medium',
                                                'category': 'recovery',
                                                'title': 'Azure Files file shares are included in an Azure '
                                                         'Backup policy',
                                                'description': 'Joins each required Azure file share to the '
                                                               'protected backup item using account ID and '
                                                               'share name; the backup sourceResourceId is '
                                                               'the storage account ID.',
                                                'remediation_hint': 'Enable Azure Backup for every Azure '
                                                                    'Files share in a Recovery Services '
                                                                    'vault and verify the matching share, '
                                                                    'backup policy and protected state.'},
 'azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b': {'id': 'azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b',
                                                                                                  'provider': 'azure',
                                                                                                  'resource_kind': 'resource_diagnostic_setting',
                                                                                                  'data_source': 'Paged '
                                                                                                                 'resource '
                                                                                                                 'inventory '
                                                                                                                 'and '
                                                                                                                 'Microsoft.Insights/diagnosticSettings '
                                                                                                                 'LIST '
                                                                                                                 '2021-05-01-preview '
                                                                                                                 'at '
                                                                                                                 'each '
                                                                                                                 'resource: '
                                                                                                                 'setting.properties.logs[].category/categoryGroup '
                                                                                                                 'and '
                                                                                                                 'enabled; '
                                                                                                                 'setting.properties.workspaceId '
                                                                                                                 'full '
                                                                                                                 'ARM '
                                                                                                                 'ID; '
                                                                                                                 'category '
                                                                                                                 'support '
                                                                                                                 'LIST '
                                                                                                                 'and '
                                                                                                                 'approved '
                                                                                                                 'workspace '
                                                                                                                 'IDs.',
                                                                                                  'predicate': 'For '
                                                                                                               'every '
                                                                                                               'in-scope '
                                                                                                               'resource, '
                                                                                                               'PASS '
                                                                                                               'if '
                                                                                                               'at '
                                                                                                               'least '
                                                                                                               'one '
                                                                                                               'supported '
                                                                                                               'log '
                                                                                                               'category '
                                                                                                               'or '
                                                                                                               'matching '
                                                                                                               'category '
                                                                                                               'group '
                                                                                                               'is '
                                                                                                               'enabled '
                                                                                                               'and '
                                                                                                               'the '
                                                                                                               'same '
                                                                                                               'diagnostic '
                                                                                                               'setting '
                                                                                                               'has '
                                                                                                               'a '
                                                                                                               'valid '
                                                                                                               'Log '
                                                                                                               'Analytics '
                                                                                                               'workspaceId. '
                                                                                                               'FAIL '
                                                                                                               'if '
                                                                                                               'a '
                                                                                                               'complete '
                                                                                                               'category/settings '
                                                                                                               'inventory '
                                                                                                               'proves '
                                                                                                               'no '
                                                                                                               'enabled '
                                                                                                               'log '
                                                                                                               'export '
                                                                                                               'to '
                                                                                                               'any '
                                                                                                               'Log '
                                                                                                               'Analytics '
                                                                                                               'workspace. '
                                                                                                               'UNKNOWN '
                                                                                                               'if '
                                                                                                               'resource '
                                                                                                               'scope, '
                                                                                                               'category '
                                                                                                               'support, '
                                                                                                               'workspace '
                                                                                                               'resolution '
                                                                                                               'or '
                                                                                                               'pages '
                                                                                                               'are '
                                                                                                               'incomplete. '
                                                                                                               'Additional '
                                                                                                               'required '
                                                                                                               'categories '
                                                                                                               'apply '
                                                                                                               'only '
                                                                                                               'when '
                                                                                                               'explicitly '
                                                                                                               'stated '
                                                                                                               'by '
                                                                                                               'a '
                                                                                                               'separate '
                                                                                                               'policy.',
                                                                                                  'severity': 'medium',
                                                                                                  'category': 'logging',
                                                                                                  'title': 'Send '
                                                                                                           'required '
                                                                                                           'resource '
                                                                                                           'logs '
                                                                                                           'to '
                                                                                                           'Log '
                                                                                                           'Analytics',
                                                                                                  'description': 'Send '
                                                                                                                 'required '
                                                                                                                 'resource '
                                                                                                                 'logs '
                                                                                                                 'to '
                                                                                                                 'Log '
                                                                                                                 'Analytics. '
                                                                                                                 'A '
                                                                                                                 'finding '
                                                                                                                 'is '
                                                                                                                 'raised '
                                                                                                                 'when '
                                                                                                                 'a '
                                                                                                                 'selected '
                                                                                                                 'resource '
                                                                                                                 'lacks '
                                                                                                                 'any '
                                                                                                                 'required '
                                                                                                                 'enabled '
                                                                                                                 'log '
                                                                                                                 'category '
                                                                                                                 'routed '
                                                                                                                 'to '
                                                                                                                 'the '
                                                                                                                 'specified '
                                                                                                                 'workspace.',
                                                                                                  'remediation_hint': 'Add '
                                                                                                                      'an '
                                                                                                                      'enabled '
                                                                                                                      'supported '
                                                                                                                      'log '
                                                                                                                      'category '
                                                                                                                      'in '
                                                                                                                      'the '
                                                                                                                      'resource '
                                                                                                                      'Diagnostic '
                                                                                                                      'settings '
                                                                                                                      'and '
                                                                                                                      'send '
                                                                                                                      'it '
                                                                                                                      'to '
                                                                                                                      'a '
                                                                                                                      'valid '
                                                                                                                      'Log '
                                                                                                                      'Analytics '
                                                                                                                      'workspace.'}}

PROPOSED_SPEC_SHA256 = {'azure.cis.entra_activity_diagnostic': '4217c9faafec7cadebc08d3205f1d139edf8d27d405a12ab2bbf003d76e5ea65',
 'azure.cis.entra_graph_activity_diagnostic': '7cdcf187730fe25570a94f1f7473cda5efe42f9c3d76e2f3316a4e62b61cc727',
 'azure.gap.databox_job_double_encryption_enabled': '84854484ffe010052ea60a022fc1693cf95f38594851df524487f558d0ca1b94',
 'azure.gap.databox_job_unlock_password_encrypted_with_cmk': '07ed33fdef48c15aafe09c3c5aad5a1a27ab15150ddc793ab886ca2ab0b1e6a6',
 'azure.other.database_default_login_restricted': 'a53c7c27657f347921ee8f92a3b400223aa9ecec1619c4a93c8e49c6efa9b452',
 'azure.other.entra_identity_audit_events': '2d4a4dc8fa5cc8a28f52371489314f86598a19e8583f73a23c3d51a9e473ce81',
 'azure.other.entra_password_baseline': '77cf250289ef0177ce3ec8d25bd0c1d71860bd8755c0b2b5e76ccc4af0d1513e',
 'azure.other.lb_weight_change_authorized': 'e95421c00ca0369df6fda41d151ae94238daaa0aee4d625e4304c190d26865f3',
 'azure_firewall_policy_10_2_1_1_24_0781f5f': 'a685e9445f0f6f9d3939b313059b0b842c800c4efc39b44a2612b058ceb80fe7',
 'azure_frontdoor_1_2_8_4_90159db': '802392e0565dd8236c4113bad0d71b24b07c386ea238c9d79fedd2e3a4ea1c4d',
 'azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b': '0aa29df516cdced6b4c726e01b52f7558e708783224263f40bc6d5d481c51db4',
 'azure_pci_10_2_1_1_16': '6cb0f4e3615a71e6656069580e12fab0ea80a691d62cde7c33351fbc3c43bdfe',
 'azure_purview_account_a3_2_5_1_2_6690c25': 'bc963f0e8b399b5d57c19df8a1e2202aa968919ef6da8a03b54d472c3d4dd559',
 'azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a': 'd74f4c31b5a93fabfac06384cbb8d69f19e2e0e97437b2cac9e1ec8ddbd31e3f',
 'azure_storage_file_share_10_3_3_15_f2d7075': 'bb797a334120350b78a54336ea3087c7707c8bb7e7fd1ab2e46526a0cd3b5214'}
IDS = tuple(SPECS)
EVALUATORS = {}


_UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
_SCOPE = re.compile(r'^/(subscriptions|tenants)/' + _UUID + r'$', re.I)
_ARM = re.compile(r'^/subscriptions/' + _UUID + r'/resourceGroups/[^/?#\s]+/providers/[^/?#\s]+(?:/[^/?#\s]+/[^/?#\s]+)+$', re.I)
_PATHS = {
    'purview_account': r'Microsoft.Purview/accounts/[^/]+',
    'databox_job': r'Microsoft.DataBox/jobs/[^/]+',
    'load_balancer': r'Microsoft.Network/loadBalancers/[^/]+',
    'database_server': r'Microsoft.Sql/servers/[^/]+',
    'mysql_postgresql_sql_server': r'Microsoft.(?:Sql/servers|DBforMySQL/flexibleServers|DBforPostgreSQL/flexibleServers)/[^/]+',
    'container_group': r'Microsoft.ContainerInstance/containerGroups/[^/]+',
    'azure_firewall': r'Microsoft.Network/azureFirewalls/[^/]+',
    'storage_file_share_and_backup_item': r'Microsoft.Storage/storageAccounts/[^/]+/fileServices/default/shares/[^/]+',
    'backup_protected_item': r'Microsoft.RecoveryServices/vaults/[^/]+/backupFabrics/[^/]+/protectionContainers/[^/]+/protectedItems/[^/]+',
    'afd_profile': r'Microsoft.Cdn/profiles/[^/]+',
    'afd_security_policy': r'Microsoft.Cdn/profiles/[^/]+/securityPolicies/[^/]+',
    'afd_route': r'Microsoft.Cdn/profiles/[^/]+/afdEndpoints/[^/]+/routes/[^/]+',
    'afd_domain': r'Microsoft.Cdn/profiles/[^/]+/(?:customDomains|afdEndpoints)/[^/]+',
    'frontdoor_waf_policy': r'Microsoft.Network/frontDoorWebApplicationFirewallPolicies/[^/]+',
}


def _signed(cid, *, dependencies=None, target='resource'):
    spec = SPECS[cid]
    category = spec['category']
    def decorate(fn):
        @register(cid, 'azure', category if category in {'hardening', 'network'} else 'hardening',
                  spec['resource_kind'], spec['title'], spec['severity'], 'CM-6',
                  spec['remediation_hint'], target=target,
                  dependencies=dependencies or [spec['resource_kind']])
        def evaluate(item, index):
            return fn(item, index)
        if cid in {'azure.cis.entra_activity_diagnostic', 'azure.cis.entra_graph_activity_diagnostic',
                   'azure.other.entra_identity_audit_events'}:
            evaluate.evaluation_scope = 'tenant'
        # Native registration predates the signed identity/encryption/logging/recovery categories.
        registered = CHECKS[-1]
        assert registered.id == cid
        CHECKS[-1] = replace(registered, category=category)
        EVALUATORS[cid] = CHECKS[-1].evaluate
        return fn
    return decorate


def _context(index, tenant=False):
    context = get(index, 'context', dict)
    scope = get(context, 'scope', str)
    match = _SCOPE.fullmatch(scope)
    if (get(context, 'provider', str) != 'azure' or not match or
            match.group(1).lower() != ('tenants' if tenant else 'subscriptions')):
        raise Unavailable('Azure scope authority unavailable')
    return context, scope.casefold()


def _strings(value, *, nonempty=False):
    if (not isinstance(value, list) or any(not isinstance(x, str) or not x or x.strip() != x for x in value)
            or len(set(x.casefold() for x in value)) != len(value) or nonempty and not value):
        raise Unavailable('malformed or empty policy/list')
    return value


def _provider_path(rid):
    return re.split(r'/providers/', rid, maxsplit=1, flags=re.I)[-1]


def _rows(index, kind, *, tenant=False):
    _, scope = _context(index, tenant)
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('missing or ambiguous scoped collection: ' + kind)
    envelope = envelopes[0]
    if (get(envelope, 'type', str) != kind or get(envelope, 'scope', str).casefold() != scope
            or envelope.get('provider', 'azure') != 'azure'):
        raise Unavailable('foreign collection: ' + kind)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    if (get(envelope, 'items', list) != rows or get(envelope, 'status', str) == 'empty' and rows):
        raise Unavailable('inconsistent collection projection: ' + kind)
    identities = set()
    for wrapper, row in zip(wrappers, rows):
        if (get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str).casefold() != scope
                or wrapper.get('provider', 'azure') != 'azure'):
            raise Unavailable('foreign resource wrapper')
        rid = get(row, 'id', str)
        if not rid or rid.casefold() in identities:
            raise Unavailable('missing or duplicate resource identity')
        identities.add(rid.casefold())
        if tenant:
            proof = get(row, '_provenance', dict)
            if (get(proof, 'tenant_id', str).casefold() != scope.rsplit('/', 1)[1]
                    or get(proof, 'tenant_verified', bool) is not True
                    or get(proof, 'read_only', bool) is not True):
                raise Unavailable('unverified tenant resource')
            if kind == 'entra_diagnostic_setting' and not re.fullmatch(
                    r'/providers/Microsoft.aadiam/diagnosticSettings/[^/?#\s]+', rid, re.I):
                raise Unavailable('malformed tenant diagnostic setting identity')
            if kind == 'entra_domain' and not re.fullmatch(r'[A-Za-z0-9.-]+\.[A-Za-z]{2,}', rid):
                raise Unavailable('malformed domain identity')
        else:
            if not _ARM.fullmatch(rid) or not rid.casefold().startswith(scope + '/'):
                raise Unavailable('foreign or malformed ARM identity')
            if kind in _PATHS and not re.fullmatch(_PATHS[kind], _provider_path(rid), re.I):
                raise Unavailable('ARM identity differs from resource kind')
    return rows


def _own(item, index, kind, *, tenant=False):
    rows = _rows(index, kind, tenant=tenant)
    if not any(row == item for row in rows):
        raise Unavailable('resource differs from complete inventory')
    return rows


def _policy(index, name, *, tenant=False):
    context, scope = _context(index, tenant)
    policy = get(context, 'metadata.compliance_policy.sw21', dict)
    if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str).casefold() != scope:
        raise Unavailable('approved policy unavailable or foreign')
    return get(policy, name, dict)


def _covered(item, field):
    if get(item, '_coverage.' + field + '.status', str) not in {'collected', 'empty'}:
        raise Unavailable('incomplete evidence: ' + field)
    value = list_of_objects(get(item, field, list))
    if item['_coverage'][field]['status'] == 'empty' and value:
        raise Unavailable('contradictory empty evidence: ' + field)
    return value


def _full(item, *, expanded=False):
    proof = get(item, '_provenance', dict)
    if (get(proof, 'source_operation', str) != 'get' or
            get(proof, 'representation', str) != 'full' or get(proof, 'read_only', bool) is not True):
        raise Unavailable('complete read-only GET unavailable')
    if expanded and get(proof, 'expand', str) != 'details':
        raise Unavailable('Data Box details expansion unavailable')


def _absent_default(item, path, default):
    # Only called after full GET validation. Explicit coverage errors still raise.
    node = item
    parts = path.split('.')
    for part in parts:
        if part not in node and part not in node.get('_coverage', {}):
            return default
        node = get(node, part)
    return node


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable('malformed time')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('malformed time') from exc
    if stamp.tzinfo is None:
        raise Unavailable('time zone unavailable')
    return stamp


def _na(reason):
    return 'NOT_APPLICABLE', {'reason': reason}


def _key_url(value):
    parsed = urlsplit(value)
    return (parsed.scheme == 'https' and parsed.netloc.casefold() == parsed.hostname and
            bool(re.fullmatch(r'[a-z0-9-]+\.vault\.(?:azure\.net|usgovcloudapi\.net|azure\.cn)', parsed.hostname or '')) and
            bool(re.fullmatch(r'/keys/[^/?#\s]+(?:/[^/?#\s]+)?', parsed.path)) and
            not parsed.query and not parsed.fragment)


def _key_principal(job, kek):
    selected = get(kek, 'identityProperties', dict)
    kind = get(selected, 'type', str)
    declared = get(job, 'identity', dict)
    job_kind = get(declared, 'type', str)
    if kind == 'SystemAssigned':
        if job_kind not in {'SystemAssigned', 'SystemAssigned,UserAssigned', 'SystemAssigned, UserAssigned'}:
            raise Unavailable('configured system identity is not attached to this job')
        principal = get(declared, 'principalId', str)
    elif kind == 'UserAssigned':
        identity_id = get(selected, 'userAssigned.resourceId', str)
        if (not _ARM.fullmatch(identity_id) or not re.fullmatch(
                r'Microsoft.ManagedIdentity/userAssignedIdentities/[^/]+', _provider_path(identity_id), re.I)
                or job_kind not in {'UserAssigned', 'SystemAssigned,UserAssigned', 'SystemAssigned, UserAssigned'}):
            raise Unavailable('configured user identity declaration unresolved')
        attached = get(declared, 'userAssignedIdentities', dict)
        matches = []
        for rid in attached:
            if rid == '_coverage':
                continue
            if (not isinstance(rid, str) or not _ARM.fullmatch(rid) or not re.fullmatch(
                    r'Microsoft.ManagedIdentity/userAssignedIdentities/[^/]+', _provider_path(rid), re.I)):
                raise Unavailable('malformed attached user identity ID')
            guard(attached[rid])
            if isinstance(rid, str) and rid.casefold() == identity_id.casefold():
                coverage_entries = attached.get('_coverage', {})
                if rid in coverage_entries:
                    field_coverage = coverage_entries[rid]
                    if (not isinstance(field_coverage, dict) or
                            field_coverage.get('status') not in {'collected', 'empty'} or
                            field_coverage['status'] == 'empty' and attached[rid]):
                        raise Unavailable('attached user identity detail unavailable')
                matches.append(get({'entry': attached[rid]}, 'entry', dict))
        if len(matches) != 1:
            raise Unavailable('configured key identity is not uniquely attached to the job')
        if 'principalId' in matches[0] or 'principalId' in matches[0].get('_coverage', {}):
            principal = get(matches[0], 'principalId', str)
        else:
            resolved = get(job, 'keyIdentity', dict)
            _full(resolved)
            if get(resolved, 'id', str).casefold() != identity_id.casefold():
                raise Unavailable('resolved key identity differs from configured user identity')
            principal = get(resolved, 'properties.principalId', str)
    else:
        raise Unavailable('unknown configured key identity type')
    if not re.fullmatch(_UUID, principal):
        raise Unavailable('job key identity principal is not an immutable UUID')
    return principal


@_signed('azure_purview_account_a3_2_5_1_2_6690c25', target='scope')
def purview_required_regions(item, index):
    accounts = _rows(index, 'purview_account')
    policy = _policy(index, 'purview')
    required = _strings(get(policy, 'requiredRegions', list), nonempty=True)
    mapping = get(policy, 'serviceStatusMapping', dict)
    if not mapping or any(not isinstance(k, str) or not k or v not in {'ENABLED', 'DISABLED', 'FAILED'}
                          for k, v in mapping.items()):
        raise Unavailable('authoritative service-status mapping unavailable')
    if not get(policy, 'serviceStatusMappingAuthority', str):
        raise Unavailable('service status mapping authority unavailable')
    for region in required:
        if not re.fullmatch(r'[a-z0-9]+', region):
            raise Unavailable('region normalization unavailable')
    grouped = {region: [] for region in required}
    for account in accounts:
        region = get(account, 'location', str)
        if not re.fullmatch(r'[a-z0-9]+', region):
            raise Unavailable('region normalization unavailable')
        if region in grouped:
            grouped[region].append(account)
    bad, unresolved = [], []
    for region, candidates in grouped.items():
        if not candidates:
            bad.append(region)
            continue
        states = []
        for account in candidates:
            provision = get(account, 'properties.provisioningState', str)
            if provision not in {'Succeeded', 'Failed', 'Creating', 'Updating', 'Deleting', 'Moving',
                                 'Accepted', 'Canceled', 'SoftDeleting', 'SoftDeleted'}:
                raise Unavailable('unrecognized Purview provisioning state')
            raw = get(account, 'properties.accountStatus.accountProvisioningState', str)
            if raw not in mapping:
                raise Unavailable('unmapped service status')
            states.append((provision, mapping[raw]))
        if any(p == 'Succeeded' and s == 'ENABLED' for p, s in states):
            continue
        if all(s in {'DISABLED', 'FAILED'} or p == 'Failed' for p, s in states):
            bad.append(region)
        else:
            unresolved.append(region)
    if unresolved:
        return unknown('required regional availability unresolved', regions=unresolved)
    return result(bool(bad), missing_or_disabled_regions=bad)


@_signed('azure.gap.databox_job_double_encryption_enabled', target='scope')
def databox_double_encryption(item, index):
    jobs = _rows(index, 'databox_job')
    if not jobs:
        return _na('complete empty Data Box job inventory')
    support = get(_policy(index, 'databox'), 'skuDoubleEncryptionSupport', dict)
    if (not support or any(not isinstance(k, str) or not k or k.strip() != k for k in support)
            or any(type(v) is not bool for v in support.values())):
        raise Unavailable('SKU support matrix unavailable')
    applicable, bad = 0, []
    for job in jobs:
        _full(job, expanded=True)
        get(job, 'properties.details', dict)
        sku = get(job, 'sku.name', str)
        if sku not in support:
            raise Unavailable('unknown SKU support')
        if not support[sku]:
            continue
        applicable += 1
        state = _absent_default(job, 'properties.details.preferences.encryptionPreferences.doubleEncryption', 'Disabled')
        if state not in {'Enabled', 'Disabled'}:
            raise Unavailable('unrecognized double-encryption preference')
        if state == 'Disabled':
            bad.append(job['id'])
    if not applicable:
        return _na('every job SKU has verified lack of double-encryption support')
    return result(bool(bad), disabled_jobs=bad)


@_signed('azure.gap.databox_job_unlock_password_encrypted_with_cmk', target='scope')
def databox_unlock_cmk(item, index):
    jobs = _rows(index, 'databox_job')
    if not jobs:
        return _na('complete empty Data Box job inventory')
    policy = _policy(index, 'databox')
    keys = _strings(get(policy, 'approvedKeyUrls', list))
    vaults = {x.casefold() for x in _strings(get(policy, 'approvedVaultIds', list))}
    vault_pattern = r'/subscriptions/' + _UUID + r'/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/([^/]+)'
    if any(not _key_url(key) for key in keys) or any(not re.fullmatch(vault_pattern, vault, re.I) for vault in vaults):
        raise Unavailable('malformed approved key/vault policy')
    approved_keys = {(urlsplit(key).hostname, urlsplit(key).path) for key in keys}
    bad = []
    for job in jobs:
        _full(job, expanded=True)
        details = get(job, 'properties.details', dict)
        kind = _absent_default(details, 'keyEncryptionKey.kekType', 'MicrosoftManaged')
        if kind == 'MicrosoftManaged':
            bad.append(job['id'])
            continue
        if kind != 'CustomerManaged':
            raise Unavailable('unknown key encryption type')
        kek = get(details, 'keyEncryptionKey', dict)
        key = _absent_default(kek, 'kekUrl', '')
        vault = _absent_default(kek, 'kekVaultResourceID', '')
        if not isinstance(key, str) or not isinstance(vault, str):
            raise Unavailable('malformed CustomerManaged key/vault fields')
        parsed = urlsplit(key)
        valid_key = _key_url(key)
        vault_match = re.fullmatch(vault_pattern, vault, re.I)
        if (not valid_key or not vault_match or parsed.hostname.split('.')[0].casefold() != vault_match.group(1).casefold()
                or (parsed.hostname, parsed.path) not in approved_keys or vault.casefold() not in vaults):
            bad.append(job['id'])
            continue
        access = get(job, 'keyAccessEvidence', dict)
        identity = _key_principal(job, kek)
        if (get(access, 'status', str) != 'collected' or
                get(access, 'principalId', str).casefold() != identity.casefold() or get(access, 'keyUrl', str) != key
                or get(access, 'vaultId', str).casefold() != vault.casefold()
                or get(access, 'source', str) != 'effective-key-authorization'):
            raise Unavailable('key authorization evidence does not match job identity/key')
        permitted = get(access, 'permittedActions', list)
        _strings(permitted)
        if not {'get', 'wrapKey', 'unwrapKey'}.issubset(permitted):
            bad.append(job['id'])
    return result(bool(bad), invalid_cmk_jobs=bad)

_DESTINATION_TYPES = {
    'workspaceId': r'Microsoft.OperationalInsights/workspaces/[^/]+',
    'storageAccountId': r'Microsoft.Storage/storageAccounts/[^/]+',
    'eventHubAuthorizationRuleId': r'Microsoft.EventHub/namespaces/[^/]+/authorizationRules/[^/]+',
}


def _setting(setting, parent=None):
    rid = get(setting, 'id', str)
    if parent is not None:
        if (get(setting, 'parent_id', str).casefold() != parent.casefold() or not re.fullmatch(
                re.escape(parent) + r'/providers/Microsoft.Insights/diagnosticSettings/[^/?#\s]+', rid, re.I)):
            raise Unavailable('foreign diagnostic setting')
    return get(setting, 'properties', dict)


def _supported(item):
    supported = _covered(item, 'supportedCategories')
    categories, groups = set(), {}
    for row in supported:
        name = get(row, 'name', str)
        category_type = get(row, 'properties.categoryType', str)
        if category_type not in {'Logs', 'Metrics'} or not name:
            raise Unavailable('unknown supported category type')
        if category_type == 'Logs':
            if name in categories:
                raise Unavailable('duplicate supported category')
            categories.add(name)
            for group in _strings(get(row, 'properties.categoryGroups', list)):
                groups.setdefault(group, set()).add(name)
    return categories, groups


def _logs(props, supported=None):
    enabled = set()
    seen = set()
    for log in list_of_objects(get(props, 'logs', list)):
        is_enabled = get(log, 'enabled', bool)
        category = optional(log, 'category', None)
        group = optional(log, 'categoryGroup', None)
        if ((category is None) == (group is None) or
                category is not None and (not isinstance(category, str) or not category) or
                group is not None and (not isinstance(group, str) or not group)):
            raise Unavailable('malformed log category/group')
        key = (category, group)
        if key in seen:
            raise Unavailable('duplicate diagnostic log category/group')
        seen.add(key)
        if supported is None:
            if group is not None:
                raise Unavailable('tenant category group semantics unresolved')
            expanded = {category}
        else:
            categories, groups = supported
            if category is not None:
                if category not in categories:
                    raise Unavailable('unsupported diagnostic log category')
                expanded = {category}
            else:
                if group not in groups:
                    raise Unavailable('unresolved diagnostic category group')
                expanded = groups[group]
        if is_enabled:
            enabled.update(expanded)
    return enabled


def _sinks(setting, approved=None, *, retention=False):
    props = get(setting, 'properties', dict)
    declared = []
    for field, pattern in _DESTINATION_TYPES.items():
        value = optional(props, field, None)
        if value is None:
            if field in props:
                raise Unavailable('null diagnostic destination identity')
            continue
        if (not isinstance(value, str) or not _ARM.fullmatch(value) or not re.fullmatch(
                pattern, _provider_path(value), re.I)):
            raise Unavailable('diagnostic destination identity unresolved')
        declared.append((field, value.casefold()))
    if not declared:
        return []
    evidence = _covered(setting, 'destinationEvidence')
    by_id = {}
    for row in evidence:
        rid = get(row, 'id', str).casefold()
        if rid in by_id or rid not in {rid for _, rid in declared}:
            raise Unavailable('foreign or duplicate destination resolution')
        by_id[rid] = row
    sinks = []
    for field, rid in declared:
        row = by_id.get(rid)
        if row is None:
            raise Unavailable('destination not resolved')
        exists = get(row, 'exists', bool)
        if retention:
            reachable = get(row, 'reachable', bool)
            days = get(row, 'effectiveRetentionDaysByCategory', dict)
            if any(not isinstance(category, str) or not category or type(value) is not int or value < 0
                   for category, value in days.items()):
                raise Unavailable('invalid retention')
        else:
            reachable, days = True, None
        sinks.append({'field': field, 'id': rid, 'good': exists and reachable and
                      (approved is None or rid in approved), 'retention': days})
    return sinks


def _tenant_export(index, required, approved, *, retention=None):
    settings = _rows(index, 'entra_diagnostic_setting', tenant=True)
    covered = set()
    for setting in settings:
        enabled = _logs(_setting(setting))
        sinks = _sinks(setting, approved, retention=retention is not None)
        if retention is None and any(s['good'] for s in sinks):
            covered.update(enabled)
        elif retention is not None:
            for category in enabled & set(required):
                if any(category not in sink['retention'] for sink in sinks):
                    raise Unavailable('effective retention for required log category unresolved')
                if any(sink['good'] and sink['retention'][category] >= retention for sink in sinks):
                    covered.add(category)
    return set(required) - covered, covered


def _approved_sinks(policy, field='approvedSinkIds', *, nonempty=False):
    ids = _strings(get(policy, field, list), nonempty=nonempty)
    if any(not _ARM.fullmatch(rid) or not any(re.fullmatch(pattern, _provider_path(rid), re.I)
                                            for pattern in _DESTINATION_TYPES.values()) for rid in ids):
        raise Unavailable('malformed approved diagnostic sink policy')
    return {rid.casefold() for rid in ids}


@_signed('azure.cis.entra_activity_diagnostic', target='scope')
def entra_activity_export(item, index):
    policy = _policy(index, 'entraDiagnostics', tenant=True)
    categories = _strings(get(policy, 'activityCategories', list), nonempty=True)
    required = _strings(get(policy, 'requiredActivityCategories', list))
    if not set(required).issubset(categories):
        raise Unavailable('required activity category mapping unavailable')
    approved = _approved_sinks(policy)
    missing, covered = _tenant_export(index, required, approved)
    return result(bool(missing) if required else not bool(set(categories) & covered),
                  required_categories=required, exported_activity_categories=sorted(set(categories) & covered))


@_signed('azure.cis.entra_graph_activity_diagnostic', target='scope')
def graph_activity_export(item, index):
    policy = _policy(index, 'entraDiagnostics', tenant=True)
    approved = _approved_sinks(policy)
    missing, _ = _tenant_export(index, ['MicrosoftGraphActivityLogs'], approved)
    return result(bool(missing), missing_categories=sorted(missing))


@_signed('azure.other.entra_identity_audit_events', target='scope', dependencies=['entra_diagnostic_setting'])
def entra_identity_audit(item, index):
    policy = _policy(index, 'entraDiagnostics', tenant=True)
    approved = _approved_sinks(policy)
    minimum = get(policy, 'minimumRetentionDays', int)
    if minimum < 1:
        raise Unavailable('invalid required retention')
    missing, _ = _tenant_export(index, ['AuditLogs', 'SignInLogs'], approved, retention=minimum)
    if missing:
        return result(True, failed_export_subcheck=sorted(missing), semantics='AuditLogs/SignInLogs export and retention subcheck')
    # Broad control coverage requires independently measured classes and time span.
    classes = _strings(get(policy, 'requiredEventClasses', list), nonempty=True)
    start, end = _instant(get(policy, 'windowStart', str)), _instant(get(policy, 'windowEnd', str))
    if start >= end:
        raise Unavailable('invalid required identity audit window')
    context, scope = _context(index, True)
    proof = get(context, 'metadata.sw21Evidence.identityAuditCoverage', dict)
    if (get(proof, 'status', str) != 'collected' or get(proof, 'scope', str).casefold() != scope
            or _instant(get(proof, 'windowStart', str)) > start
            or _instant(get(proof, 'windowEnd', str)) < end):
        raise Unavailable('broad identity audit coverage/window unresolved')
    measured = _strings(get(proof, 'verifiedEventClasses', list))
    if not get(proof, 'privilegedActionsComplete', bool) or not set(classes).issubset(measured):
        return unknown('broad identity activity requirements not proven')
    if not get(proof, 'source', str):
        raise Unavailable('coverage evidence source unavailable')
    return result(False, verified_event_classes=classes, semantics='Export subcheck and separate broad audit coverage evidence')


@_signed('azure_firewall_policy_10_2_1_1_24_0781f5f')
def firewall_diagnostics(item, index):
    _own(item, index, 'azure_firewall')
    policy = _policy(index, 'firewallDiagnostics')
    required = _strings(get(policy, 'requiredCategories', list), nonempty=True)
    approved = _approved_sinks(policy)
    supported = _supported(item)
    if not set(required).issubset(supported[0]):
        raise Unavailable('policy-required categories unsupported or unresolved')
    exported = set()
    for setting in _covered(item, 'diagnosticSettings'):
        props = _setting(setting, item['id'])
        enabled = _logs(props, supported)
        if any(s['good'] for s in _sinks(setting, approved)):
            exported.update(enabled)
    missing = set(required) - exported
    return result(bool(missing), missing_categories=sorted(missing))


@_signed('azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b', target='scope')
def resource_logs_to_workspace(item, index):
    resources = _rows(index, 'resource_diagnostic_setting')
    if not resources:
        return _na('complete empty in-scope resource inventory')
    bad = []
    for resource in resources:
        supported = _supported(resource)
        exported = False
        for setting in _covered(resource, 'diagnosticSettings'):
            props = _setting(setting, resource['id'])
            enabled = _logs(props, supported)
            sinks = _sinks(setting)
            exported |= bool(enabled) and any(s['good'] and s['field'] == 'workspaceId' for s in sinks)
        if not exported:
            bad.append(resource['id'])
    return result(bool(bad), resources_without_workspace_log_export=bad)

@_signed('azure.other.lb_weight_change_authorized')
def lb_routing_changes(item, index):
    _own(item, index, 'load_balancer')
    policy = _policy(index, 'loadBalancerChanges')
    operations = _strings(get(policy, 'routingOperations', list), nonempty=True)
    trusted = _strings(get(policy, 'trustedActorIds', list))
    if any(not re.fullmatch(_UUID, value) for value in trusted):
        raise Unavailable('trusted actors are not immutable identities')
    sinks = _approved_sinks(policy, 'approvedDurableSinkIds', nonempty=True)
    start, end = _instant(get(policy, 'windowStart', str)), _instant(get(policy, 'windowEnd', str))
    if start >= end:
        raise Unavailable('invalid routing observation window')
    window = get(item, 'routingChangeWindow', dict)
    if (get(window, 'source', str) != 'independent-routing-change-inventory'
            or _instant(get(window, 'start', str)) != start or _instant(get(window, 'end', str)) != end):
        raise Unavailable('independent change completeness/window unavailable')
    changes = _covered(item, 'routingChanges')
    events = _covered(item, 'routingAuditEvents')
    deliveries = _covered(item, 'auditDeliveryEvidence')
    change_ids, parsed_changes = set(), []
    for change in changes:
        cid = get(change, 'id', str)
        actor = get(change, 'actorId', str)
        stamp = _instant(get(change, 'eventTimestamp', str))
        operation = get(change, 'operationName.value', str)
        if (not cid or cid in change_ids or get(change, 'resourceId', str).casefold() != item['id'].casefold()
                or not re.fullmatch(_UUID, actor) or operation not in operations or not start <= stamp <= end):
            raise Unavailable('change identity/operation/actor/window unresolved')
        change_ids.add(cid)
        parsed_changes.append((change, actor.casefold(), stamp, operation))
    parsed_events = []
    for event in events:
        actor = get(event, 'resolvedActorId', str)
        if (get(event, 'resourceId', str).casefold() != item['id'].casefold()
                or not re.fullmatch(_UUID, actor) or
                get(event, '_coverage.actorResolution.status', str) != 'collected'):
            raise Unavailable('audit actor or resource unresolved')
        operation = get(event, 'operationName.value', str)
        stamp = _instant(get(event, 'eventTimestamp', str))
        status = get(event, 'status.value', str)
        correlation = get(event, 'correlationId', str)
        if operation not in operations or not start <= stamp <= end or not correlation or status not in {'Succeeded', 'Failed', 'Started', 'Accepted'}:
            raise Unavailable('audit operation/window/status unresolved')
        parsed_events.append((event, actor.casefold(), stamp, operation, status))
    delivered = set()
    for delivery in deliveries:
        if (get(delivery, 'resourceId', str).casefold() != item['id'].casefold()
                or get(delivery, 'destinationId', str).casefold() not in sinks
                or not get(delivery, 'durable', bool)):
            raise Unavailable('durable approved log delivery unresolved')
        delivered_at = _instant(get(delivery, 'deliveredAt', str))
        capture = _instant(get(index['context'], 'created_at', str))
        stamps = [stamp for event, actor, stamp, operation, status in parsed_events
                  if event['correlationId'] == get(delivery, 'correlationId', str) and status == 'Succeeded']
        if not stamps or not max(stamps) <= delivered_at <= capture:
            raise Unavailable('log-delivery time or event binding unresolved')
        delivered.add(get(delivery, 'correlationId', str))
    bad = []
    trusted = {x.casefold() for x in trusted}
    for change, actor, stamp, operation in parsed_changes:
        matches = [event for event, event_actor, event_stamp, event_op, status in parsed_events
                   if event_actor == actor and event_stamp == stamp and event_op == operation and status == 'Succeeded'
                   and event['correlationId'] == get(change, 'correlationId', str)]
        if actor not in trusted or not matches:
            bad.append(change['id'])
        elif not any(event['correlationId'] in delivered for event in matches):
            return unknown('successful change log delivery not proven')
    return result(bool(bad), unauthorized_or_unlogged_changes=bad, change_count=len(changes))


@_signed('azure.other.database_default_login_restricted')
def default_sql_logins(item, index):
    _own(item, index, 'database_server')
    assessment = get(item, 'defaultCredentialAssessment', dict)
    if get(assessment, 'status', str) != 'collected':
        raise Unavailable('default credential assessment incomplete')
    scope = get(index['context'], 'scope', str)
    if optional(assessment, 'scope', scope, str).casefold() != scope.casefold():
        raise Unavailable('default credential assessment scope unresolved')
    authorization = get(assessment, 'authorization', dict)
    if (not get(authorization, 'approved', bool) or
            get(authorization, 'serverId', str).casefold() != item['id'].casefold() or
            optional(authorization, 'scope', scope, str).casefold() != scope.casefold()):
        raise Unavailable('test authorization absent/foreign')
    baseline = get(assessment, 'baseline', dict)
    if not optional(baseline, 'approved', True, bool):
        raise Unavailable('credential baseline not approved')
    version = get(baseline, 'version', str)
    credentials = _strings(get(baseline, 'credentialIds', list), nonempty=True)
    if not version.strip():
        raise Unavailable('credential baseline unavailable')
    catalog = get(assessment, 'sqlCatalog', dict)
    if get(catalog, 'status', str) != 'collected':
        raise Unavailable('SQL login catalog incomplete')
    _strings(get(catalog, 'loginNames', list))
    if get(assessment, 'endpointInventoryStatus', str) != 'collected':
        raise Unavailable('endpoint/authentication-path inventory incomplete')
    paths = set()
    endpoint_ids = set()
    for endpoint in list_of_objects(get(assessment, 'endpoints', list)):
        endpoint_id = get(endpoint, 'id', str)
        if (not endpoint_id.strip() or endpoint_id.casefold() in endpoint_ids or
                get(endpoint, 'serverId', str).casefold() != item['id'].casefold() or
                optional(endpoint, 'scope', scope, str).casefold() != scope.casefold()):
            raise Unavailable('endpoint identity or server binding unavailable')
        endpoint_ids.add(endpoint_id.casefold())
        for path in _strings(get(endpoint, 'authenticationPaths', list), nonempty=True):
            key = (endpoint_id, path)
            if key in paths:
                raise Unavailable('duplicate authentication path')
            paths.add(key)
    if not paths:
        raise Unavailable('no tested endpoint paths')
    if get(assessment, 'testResultsStatus', str) != 'collected':
        raise Unavailable('authentication results incomplete')
    outcomes = {}
    for test in list_of_objects(get(assessment, 'tests', list)):
        if (optional(test, 'serverId', item['id'], str).casefold() != item['id'].casefold() or
                optional(test, 'scope', scope, str).casefold() != scope.casefold() or
                not optional(test, 'authorized', True, bool)):
            raise Unavailable('authentication test authority or server binding unresolved')
        key = (get(test, 'endpointId', str), get(test, 'authenticationPath', str), get(test, 'credentialId', str))
        if key[:2] not in paths or key[2] not in credentials or get(test, 'baselineVersion', str) != version or key in outcomes:
            raise Unavailable('test baseline/path binding unresolved')
        outcome = get(test, 'outcome', str)
        if outcome not in {'Authenticated', 'AccessDenied', 'NetworkError', 'Timeout', 'Unknown'}:
            raise Unavailable('unknown authentication test outcome')
        outcomes[key] = outcome
    if any(value == 'Authenticated' for value in outcomes.values()):
        return result(True, successful_default_credential_tests=sum(x == 'Authenticated' for x in outcomes.values()))
    required = {(endpoint, path, credential) for endpoint, path in paths for credential in credentials}
    if set(outcomes) != required or any(value != 'AccessDenied' for value in outcomes.values()):
        return unknown('all authorized credential/path tests must directly prove access denied')
    return result(False, denied_test_count=len(outcomes), semantics='Imported authorized test evidence; no authentication executed')


@_signed('azure.other.entra_password_baseline')
def entra_password_baseline(item, index):
    _own(item, index, 'entra_domain', tenant=True)
    baseline = get(_policy(index, 'passwords', tenant=True), 'approvedPasswordBaseline', dict)
    if not baseline or not {'complexity', 'lockoutThreshold'}.issubset(baseline):
        raise Unavailable('required password complexity/lockout baseline unavailable')
    for field, bounds in baseline.items():
        guard(bounds)
        if not field or not bounds or not set(bounds).issubset({'minimum', 'maximum', 'equals'}):
            raise Unavailable('malformed baseline bound')
        for operation, value in bounds.items():
            if operation == 'equals':
                if type(value) not in (bool, str, int, float):
                    raise Unavailable('malformed equality bound')
            elif type(value) not in (int, float):
                raise Unavailable('malformed numeric bound')
            if type(value) in (int, float) and not math.isfinite(value):
                raise Unavailable('nonfinite password baseline bound')
        if ('minimum' in bounds and 'maximum' in bounds and bounds['minimum'] > bounds['maximum']):
            raise Unavailable('contradictory baseline bounds')
    provisioned = _covered(item, 'newlyProvisionedIdentities')
    policies = _covered(item, 'effectivePasswordPolicies')
    by_id = {}
    for policy in policies:
        pid = get(policy, 'id', str)
        if not pid or pid in by_id or get(policy, 'domainId', str).casefold() != item['id'].casefold():
            raise Unavailable('effective password policy join unavailable')
        if get(policy, 'authenticationType', str) not in {'Managed', 'Federated'} or not get(policy, 'sourcePolicyAuthority', str):
            raise Unavailable('managed/federated policy authority unavailable')
        by_id[pid] = policy
    identities, violations, unresolved = set(), [], False
    for identity in provisioned:
        uid = get(identity, 'id', str)
        if (not re.fullmatch(_UUID, uid) or uid.casefold() in identities or
                get(identity, 'domainId', str).casefold() != item['id'].casefold()):
            raise Unavailable('new identity domain/provisioning binding unavailable')
        identities.add(uid.casefold())
        policy = by_id.get(get(identity, 'policyId', str))
        if policy is None:
            raise Unavailable('new identity effective policy unavailable')
        measured = _strings(get(policy, 'directlyVerifiedFields', list))
        settings = get(policy, 'settings', dict)
        for field, bounds in baseline.items():
            if field not in measured or field not in settings:
                unresolved = True
                continue
            value = get(settings, field)
            if type(value) in (int, float) and not math.isfinite(value):
                raise Unavailable('nonfinite measured password field')
            for operation, limit in bounds.items():
                if operation == 'equals':
                    if type(value) is not type(limit):
                        raise Unavailable('malformed measured password field')
                    violation = value != limit
                else:
                    if type(value) not in (int, float):
                        raise Unavailable('malformed measured password bound')
                    violation = value < limit if operation == 'minimum' else value > limit
                if violation:
                    violations.append({'identityId': uid, 'field': field})
    if unresolved:
        return unknown('not every required password policy field is directly verified')
    if violations:
        return result(True, baseline_violations=violations)
    return result(False, newly_provisioned_identity_count=len(identities))


@_signed('azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a', target='scope')
def database_public_ingress(item, index):
    servers = _rows(index, 'mysql_postgresql_sql_server')
    if not servers:
        return _na('complete empty SQL/MySQL/PostgreSQL server inventory')
    bad = []
    for server in servers:
        sql = '/providers/microsoft.sql/servers/' in server['id'].casefold()
        mode = get(server, 'properties.publicNetworkAccess' if sql else 'properties.network.publicNetworkAccess', str)
        if mode not in {'Enabled', 'Disabled'}:
            raise Unavailable('public-network access mode unresolved')
        if mode == 'Disabled':
            continue
        rules = _covered(server, 'firewallRules')
        bypass = get(server, 'publicBypassEvidence', dict)
        if get(bypass, 'status', str) != 'collected' or get(bypass, 'serverId', str).casefold() != server['id'].casefold():
            raise Unavailable('effective public bypass semantics unresolved')
        admitted = get(bypass, 'admitsExternalPublicClient', bool)
        if not get(bypass, 'source', str):
            raise Unavailable('bypass source unavailable')
        for rule in rules:
            if (get(rule, 'parent_id', str).casefold() != server['id'].casefold() or not re.fullmatch(
                    re.escape(server['id']) + r'/firewallRules/[^/?#\s]+', get(rule, 'id', str), re.I)):
                raise Unavailable('foreign firewall rule')
            start = IPv4Address(get(rule, 'properties.startIpAddress', str))
            end = IPv4Address(get(rule, 'properties.endIpAddress', str))
            if start > end:
                raise Unavailable('reversed firewall range')
            if int(start) == int(end) == 0:
                if sql:
                    admitted = True  # SQL's documented Allow Azure services special rule.
                elif not get(rule, 'specialRuleSemanticsResolved', bool):
                    raise Unavailable('flexible-server zero-address semantics unresolved')
                else:
                    admitted |= get(rule, 'admitsExternalPublicClient', bool)
                continue
            # Partition on all IPv4 special-use boundaries. Any globally routable
            # address inside the allowed interval is positive external-client evidence.
            probes = {int(start), int(end)}
            for lower, upper in _NONPUBLIC_RANGES:
                for point in (lower - 1, lower, upper, upper + 1):
                    if int(start) <= point <= int(end):
                        probes.add(point)
            admitted |= any(IPv4Address(point).is_global and not IPv4Address(point).is_multicast for point in probes)
        if admitted:
            bad.append(server['id'])
    return result(bool(bad), servers_admitting_public_clients=bad)


# Boundaries from IPv4 special-use networks; is_global determines each segment's semantics.
_NONPUBLIC_RANGES = [(int(net.network_address), int(net.broadcast_address)) for net in map(IPv4Network, (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
    '192.0.0.0/24', '192.0.0.0/29', '192.0.0.8/32', '192.0.0.9/32', '192.0.0.10/32', '192.0.0.170/31',
    '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'))]


@_signed('azure_pci_10_2_1_1_16')
def container_instance_logging(item, index):
    _own(item, index, 'container_group')
    _full(item)
    state = get(item, 'properties.instanceView.state', str)
    if state in {'Stopped', 'Succeeded', 'Failed'}:
        return _na('container group is inactive')
    if state not in {'Running', 'Pending'}:
        raise Unavailable('container group activity unresolved')
    containers = list_of_objects(get(item, 'properties.containers', list))
    if not containers:
        raise Unavailable('active group has no container definitions')
    names = [get(c, 'name', str) for c in containers]
    if any(not n for n in names) or len(set(names)) != len(names):
        raise Unavailable('container definition identities unresolved')
    workspace = _absent_default(item, 'properties.diagnostics.logAnalytics.workspaceId', '')
    # ACI's native workspaceId is the customer UUID, not the workspace ARM ID.
    if workspace == '':
        return result(True, reason='workspace explicitly absent')
    if not isinstance(workspace, str) or not re.fullmatch(_UUID, workspace):
        raise Unavailable('ACI workspace customer ID malformed')
    resolution = get(item, 'workspaceEvidence', dict)
    if get(resolution, 'customerId', str).casefold() != workspace.casefold() or not get(resolution, 'exists', bool):
        raise Unavailable('ACI Log Analytics workspace unresolved')
    if not _ARM.fullmatch(get(resolution, 'id', str)) or not re.fullmatch(
            _DESTINATION_TYPES['workspaceId'], _provider_path(resolution['id']), re.I):
        raise Unavailable('invalid resolved ACI workspace')
    evidence = _covered(item, 'containerLoggingEvidence')
    by_name = {}
    for row in evidence:
        name = get(row, 'containerName', str)
        if name not in names or name in by_name or get(row, 'groupId', str).casefold() != item['id'].casefold():
            raise Unavailable('container logging evidence binding unresolved')
        by_name[name] = row
    enabled, verified, disabled = [], [], []
    for name in names:
        row = by_name.get(name)
        if row is None:
            raise Unavailable('per-container logging evidence missing')
        if get(row, 'loggingEnabled', bool):
            enabled.append(name)
            if (get(row, 'workspaceCustomerId', str).casefold() == workspace.casefold()
                    and get(row, 'collectedRecordCount', int) > 0):
                stamp = _instant(get(row, 'lastCollectedAt', str))
                now = _instant(get(index['context'], 'created_at', str))
                age = get(row, 'maxAgeSeconds', int)
                if age > 0 and 0 <= (now - stamp).total_seconds() <= age:
                    verified.append(name)
        else:
            disabled.append(name)
    if verified:
        return result(False, verified_logging_containers=verified)
    if len(disabled) == len(names):
        return result(True, reason='all container logging explicitly disabled')
    return unknown('enabled container logging lacks fresh workspace collection evidence')


@_signed('azure_storage_file_share_10_3_3_15_f2d7075', target='scope',
         dependencies=['storage_file_share_and_backup_item', 'backup_protected_item'])
def azure_files_backup(item, index):
    shares = _rows(index, 'storage_file_share_and_backup_item')
    if not shares:
        return _na('complete empty Azure Files share inventory')
    backups = _rows(index, 'backup_protected_item')
    # Collector must attest all scoped vaults were accessible and paged.
    context, scope = _context(index)
    proof = get(context, 'metadata.sw21Evidence.backupVaultInventory', dict)
    if (get(proof, 'scope', str).casefold() != scope or get(proof, 'status', str) != 'collected'
            or not get(proof, 'allScopedVaultsAccessible', bool)):
        raise Unavailable('all-vault backup inventory incomplete')
    joined = {}
    for backup in backups:
        props = get(backup, 'properties', dict)
        kind = get(props, 'protectedItemType', str)
        if kind != 'AzureFileShareProtectedItem':
            continue
        account = get(props, 'sourceResourceId', str)
        name = get(props, 'friendlyName', str)
        if (not _ARM.fullmatch(account) or not re.fullmatch(r'/subscriptions/' + _UUID + r'/resourceGroups/[^/]+/providers/Microsoft.Storage/storageAccounts/[^/]+', account, re.I)
                or not account.casefold().startswith(scope + '/') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{1,61}[A-Za-z0-9]', name)):
            raise Unavailable('backup account/share join fields unavailable')
        joined.setdefault((account.casefold(), name.casefold()), []).append(props)
    bad = []
    for share in shares:
        account = re.split(r'/fileServices/', share['id'], maxsplit=1, flags=re.I)[0]
        name = get(share, 'name', str)
        if share['id'].rsplit('/', 1)[1].casefold() != name.casefold():
            raise Unavailable('share native name inconsistent')
        matches = joined.get((account.casefold(), name.casefold()), [])
        if len(matches) > 1:
            raise Unavailable('duplicate share protected-item join')
        if not matches:
            bad.append(share['id'])
            continue
        props = matches[0]
        state = get(props, 'protectionState', str)
        policy = optional(props, 'policyId', '')
        if not isinstance(policy, str):
            raise Unavailable('malformed backup policy identity')
        if state not in {'Protected', 'ProtectionStopped', 'ProtectionError', 'ProtectionPaused', 'BackupsSuspended'}:
            raise Unavailable('pending/invalid/unrecognized backup protection state')
        if not policy or state != 'Protected':
            bad.append(share['id'])
    return result(bool(bad), unprotected_file_shares=bad)

@_signed('azure_frontdoor_1_2_8_4_90159db', target='scope',
         dependencies=['afd_profile', 'afd_security_policy', 'afd_route', 'afd_domain', 'frontdoor_waf_policy'])
def frontdoor_waf_coverage(item, index):
    profiles = {row['id'].casefold(): row for row in _rows(index, 'afd_profile')}
    domains = {row['id'].casefold(): row for row in _rows(index, 'afd_domain')}
    routes = _rows(index, 'afd_route')
    for profile in profiles.values():
        if get(profile, 'sku.name', str) not in {'Standard_AzureFrontDoor', 'Premium_AzureFrontDoor'}:
            raise Unavailable('Front Door profile SKU scope unresolved')
    for rid, domain in domains.items():
        profile_id = rid.split('/customdomains/', 1)[0].split('/afdendpoints/', 1)[0]
        if profile_id not in profiles or not get(domain, 'properties.hostName', str):
            raise Unavailable('Front Door domain profile/hostname unresolved')
    if not routes:
        return _na('complete empty publicly routed Front Door domain/path scope')
    policies = _rows(index, 'afd_security_policy')
    wafs = {row['id'].casefold(): row for row in _rows(index, 'frontdoor_waf_policy')}
    associations = []
    for policy in policies:
        profile_id = policy['id'].casefold().split('/securitypolicies/', 1)[0]
        if profile_id not in profiles:
            raise Unavailable('security policy profile unresolved')
        parameters = get(policy, 'properties.parameters', dict)
        if get(parameters, 'type', str) != 'WebApplicationFirewall':
            raise Unavailable('security policy type unresolved')
        waf_id = get(parameters, 'wafPolicy.id', str).casefold()
        waf = wafs.get(waf_id)
        if waf is None:
            raise Unavailable('WAF GET unresolved')
        _full(waf)
        settings = get(waf, 'properties.policySettings', dict)
        state = _absent_default(settings, 'enabledState', 'Enabled')
        if state not in {'Enabled', 'Disabled'}:
            raise Unavailable('WAF enabled state unresolved')
        for association in list_of_objects(get(parameters, 'associations', list)):
            refs = [get(ref, 'id', str).casefold() for ref in list_of_objects(get(association, 'domains', list))]
            if len(set(refs)) != len(refs) or any(ref not in domains or not ref.startswith(profile_id + '/') for ref in refs):
                raise Unavailable('security association domain unresolved')
            patterns = _strings(get(association, 'patternsToMatch', list), nonempty=True)
            if any(not p.startswith('/') or '?' in p or '#' in p for p in patterns):
                raise Unavailable('security association path semantics unresolved')
            associations.append((set(refs), patterns, state))
    routed = []
    for route in routes:
        endpoint = route['id'].casefold().split('/routes/', 1)[0]
        profile_id = endpoint.split('/afdendpoints/', 1)[0]
        if profile_id not in profiles or endpoint not in domains:
            raise Unavailable('route endpoint/profile unresolved')
        props = get(route, 'properties', dict)
        state = get(props, 'enabledState', str)
        if state not in {'Enabled', 'Disabled'}:
            raise Unavailable('route enabled state unresolved')
        protocols = _strings(get(props, 'supportedProtocols', list), nonempty=True)
        if not set(protocols).issubset({'Http', 'Https'}):
            raise Unavailable('route public protocol semantics unresolved')
        refs = [get(ref, 'id', str).casefold() for ref in list_of_objects(get(props, 'customDomains', list))]
        link = get(props, 'linkToDefaultDomain', str)
        if link not in {'Enabled', 'Disabled'}:
            raise Unavailable('default domain routing unresolved')
        if link == 'Enabled':
            refs.append(endpoint)
        if len(refs) != len(set(refs)) or any(ref not in domains or not ref.startswith(profile_id + '/') for ref in refs):
            raise Unavailable('effective route domain unresolved')
        patterns = _strings(get(props, 'patternsToMatch', list), nonempty=True)
        if any(not p.startswith('/') or '?' in p or '#' in p for p in patterns):
            raise Unavailable('route pattern semantics unresolved')
        if state == 'Enabled':
            routed.extend((ref, pattern) for ref in refs for pattern in patterns)
    if not routed:
        return _na('complete empty publicly routed Front Door domain/path scope')
    bad, uncertain = [], []
    for domain, pattern in routed:
        covered, unresolved = False, False
        for refs, patterns, state in associations:
            if domain not in refs:
                continue
            exact = pattern in patterns or '/*' in patterns
            if exact and state == 'Enabled':
                covered = True
            elif not exact and any('*' in p or '*' in pattern for p in patterns):
                unresolved = True
        if not covered:
            (uncertain if unresolved else bad).append({'domainId': domain, 'pattern': pattern})
    if uncertain:
        return unknown('wildcard association semantics unresolved', routes=uncertain)
    return result(bool(bad), uncovered_or_disabled_routes=bad, routed_domain_path_count=len(routed))
