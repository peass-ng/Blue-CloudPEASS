"""Signed Azure compliance checks over scoped, read-only snapshot evidence.

Required additions are specified in sw14-collector-requests.md. No evaluator
performs network requests or treats an absent evidence field as a safe setting.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network, ip_address
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects

SPECS = {'azure_pci_1_2_8_19': {'id': 'azure_pci_1_2_8_19',
                        'provider': 'azure',
                        'resource_kind': 'app_service',
                        'data_source': 'Paged ARM Microsoft.Web/sites LIST, kind includes functionapp; '
                                       'GET each site and Microsoft.Web/sites/config/web for '
                                       'properties.publicNetworkAccess, ipSecurityRestrictions, '
                                       'ipSecurityRestrictionsDefaultAction; read '
                                       'privateEndpointConnections child status and join to the exact '
                                       'app ID. Resolve service tags, priorities, SCM/main-site scope '
                                       'and approved sources.',
                        'predicate': 'For each Function App, PASS if publicNetworkAccess=Disabled and '
                                     'an approved private endpoint is verified, or if complete '
                                     'effective main-site access restrictions and default action permit '
                                     'only policy-approved source ranges. FAIL if complete effective '
                                     'ingress proves an unapproved public source can reach the app or '
                                     'neither an approved private endpoint nor restrictive access rules '
                                     'exists. UNKNOWN for missing config, unresolved service tags or '
                                     'endpoint status, source policy, or incomplete site/config pages. '
                                     'No Function Apps is NOT_APPLICABLE.',
                        'severity': 'high',
                        'category': 'hardening',
                        'title': 'Restrict public Function App ingress',
                        'description': 'Restrict public Function App ingress. A finding is raised when '
                                       'a Function App allows public ingress without an effective '
                                       'deny-by-default restriction.',
                        'remediation_hint': 'In Function App > Networking > Access restrictions, '
                                            'disable public network access or configure approved Allow '
                                            'ranges with a Deny default action.'},
 'azure.other.gateway_api_cidr_allowlist': {'id': 'azure.other.gateway_api_cidr_allowlist',
                                            'provider': 'azure',
                                            'resource_kind': 'web_application_firewall_policy',
                                            'data_source': 'Paged Application Gateway, HTTP listener, '
                                                           'routing-rule and WAF-policy GETs; resolve '
                                                           'effective listener-level versus '
                                                           'gateway-level policy, '
                                                           'policySettings.mode/state, '
                                                           'customRules[].state/action/priority/ruleType/matchConditions, '
                                                           'and approvedCidrs. Include all alternate '
                                                           'listener/route paths to the API.',
                                            'predicate': 'For each in-scope API listener and effective '
                                                         'request path, evaluate ordered enabled custom '
                                                         'rules with RemoteAddr operator, negation, '
                                                         'transforms and matchValues. PASS only if the '
                                                         'attached WAF policy is effectively Enabled '
                                                         '(an omitted policySettings.state defaults to '
                                                         'Enabled), in Prevention mode, and every '
                                                         'outside-approved-CIDR source is blocked with '
                                                         'no earlier Allow or alternate unprotected '
                                                         'path. Ignore disabled rules; apply documented '
                                                         'rule-state defaults. FAIL for a provably '
                                                         'accepted outside address, including '
                                                         'policySettings.state=Disabled or a bypassing '
                                                         'listener. UNKNOWN for unsupported matching, '
                                                         'unresolved defaults/association, incomplete '
                                                         'pages, missing approvedCidrs or an unproven '
                                                         'effective path. Empty complete listener set '
                                                         'is NOT_APPLICABLE.',
                                            'severity': 'high',
                                            'category': 'hardening',
                                            'title': 'Gateway API restricts source CIDRs',
                                            'description': 'Checks effective source CIDR restrictions '
                                                           'on specified Application Gateway listeners.',
                                            'remediation_hint': 'Attach a WAF policy in Prevention mode '
                                                                'to each API listener and add '
                                                                'priority-ordered RemoteAddr allow/deny '
                                                                'rules covering only approved CIDRs.'},
 'azure_firewall_policy_6_4_1_6_2ad9039': {'id': 'azure_firewall_policy_6_4_1_6_2ad9039',
                                           'provider': 'azure',
                                           'resource_kind': 'web_application_firewall_policy',
                                           'data_source': 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies '
                                                          'GET api-version=2023-09-01: '
                                                          'properties.managedRules.managedRuleSets[].ruleGroupOverrides '
                                                          'and customRules[].priority. Separately '
                                                          'require Firewall Manager ruleGroups '
                                                          'parameter/rank and deployed group '
                                                          'association evidence for the exact policy. '
                                                          'WAF custom-rule priority is not rule-group '
                                                          'rank.',
                                           'predicate': 'PASS or FAIL only from a separately supplied, '
                                                        'authoritative Firewall Manager ruleGroups '
                                                        'parameter and deployed association/order '
                                                        'evidence that identifies the same WAF policy '
                                                        'and proves every group rank (0,1,2,...). '
                                                        'Return UNKNOWN when only Azure Application '
                                                        'Gateway WAF GET is available, even if its '
                                                        'customRules.priority values are 0,1,2. Also '
                                                        'UNKNOWN for absent association, ambiguous '
                                                        'order, missing parameter or incomplete '
                                                        'inventory.',
                                           'severity': 'high',
                                           'category': 'network',
                                           'title': 'WAF rule groups follow the approved Firewall '
                                                    'Manager rank',
                                           'description': 'Requires authoritative Firewall Manager '
                                                          'ruleGroups rank and deployed association '
                                                          'evidence; Azure WAF custom-rule priority is '
                                                          'unrelated.',
                                           'remediation_hint': 'In Firewall Manager, compare deployed '
                                                               'WAF rule-group associations with the '
                                                               'approved ruleGroups rank, correct their '
                                                               'priority order, and retain the '
                                                               'ruleGroups parameter and deployment '
                                                               'evidence.'},
 'azure_firewall_policy_6_4_1_7_a7975fc': {'id': 'azure_firewall_policy_6_4_1_7_a7975fc',
                                           'provider': 'azure',
                                           'resource_kind': 'web_application_firewall_policy',
                                           'data_source': 'Application Gateway WAF policy GET '
                                                          '2026-01-01 plus Application Gateway '
                                                          'association. Inspect policySettings.state, '
                                                          'managedRules.managedRuleSets with '
                                                          'ruleSetType/version, '
                                                          'ruleGroupOverrides[].ruleGroupName/rules[].state, '
                                                          'and the versioned managed rule-set group '
                                                          'catalogue; customRules are not managed '
                                                          'rule-group evidence.',
                                           'predicate': 'For every in-scope attached WAF v2 policy and '
                                                        'each effective managed rule group, FAIL if '
                                                        'policySettings.state is Disabled or complete '
                                                        'versioned rule-set/override evidence proves '
                                                        'the group has no enabled effective rule. An '
                                                        'override listing a group with an empty rules '
                                                        'array disables the group; an override rule '
                                                        'with omitted state defaults to Disabled. PASS '
                                                        'only when policy state is Enabled or omitted '
                                                        '(documented Enabled default), every applicable '
                                                        'group has at least one enabled effective rule '
                                                        'after defaults and overrides, and rule-set '
                                                        'versions are fully resolved. UNKNOWN for '
                                                        'missing association, catalogue, group/rule '
                                                        'state, policy mode or inventory. A custom rule '
                                                        'alone cannot make an empty managed group PASS.',
                                           'severity': 'high',
                                           'category': 'network',
                                           'title': 'Application Gateway WAF managed rule groups '
                                                    'contain enabled rules',
                                           'description': 'Checks each effective managed rule group '
                                                          'against its versioned rule-set catalogue and '
                                                          'overrides.',
                                           'remediation_hint': 'Application Gateway WAF policy > Policy '
                                                               'settings: enable the policy and '
                                                               'configure an active managed rule set or '
                                                               'valid enabled custom rules; attach it '
                                                               'to the gateway/listener.'},
 'azure.other.entra_app_secret_age_90': {'id': 'azure.other.entra_app_secret_age_90',
                                         'provider': 'azure',
                                         'resource_kind': 'application',
                                         'data_source': 'Collector peaso/collectors/azure.py: '
                                                        'directory_application uses paged Graph GET '
                                                        '/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials, '
                                                        'but _metadata_only currently keeps only keyId '
                                                        'and endDateTime and DROPS startDateTime. '
                                                        'Extend this safe credential metadata '
                                                        'projection to retain startDateTime '
                                                        '(DateTimeOffset string) without '
                                                        'secretKey/text, or make a new paged Graph read '
                                                        'with that projection. Active means start <= '
                                                        'now and end > now; null end requires policy '
                                                        'handling.',
                                         'predicate': 'PASS if every currently valid passwordCredential '
                                                      'and keyCredential on every application has a '
                                                      'parseable startDateTime newer than now minus 90 '
                                                      'days, with complete pages. FAIL if a known '
                                                      'active credential started at least 90 days ago. '
                                                      'UNKNOWN for null/invalid dates, time skew, '
                                                      'missing application pages or unclear active '
                                                      'state; zero active credentials is PASS only when '
                                                      'the full application inventory is known.',
                                         'severity': 'high',
                                         'category': 'identity',
                                         'title': 'Application credentials rotate within 90 days',
                                         'description': 'Checks the age of active static Microsoft '
                                                        'Entra application credentials.',
                                         'remediation_hint': 'Entra admin center > App registrations > '
                                                             'Certificates & secrets: replace active '
                                                             'credentials older than 90 days, remove '
                                                             'old credentials after cutover, or use '
                                                             'workload identity federation.'},
 'azure.other.external_impersonation_denied': {'id': 'azure.other.external_impersonation_denied',
                                               'provider': 'azure',
                                               'resource_kind': 'application',
                                               'data_source': 'Graph v1.0 paged applications and '
                                                              '/applications/{id}/federatedIdentityCredentials; '
                                                              'ARM paged user-assigned managed identity '
                                                              'federated credentials where in scope; '
                                                              'approved exact issuer/subject/audience '
                                                              'tuples; read-only authorization logs or '
                                                              'approved negative test evidence for '
                                                              'denied unapproved impersonation.',
                                               'predicate': 'FAIL if a complete observed federated '
                                                            'credential tuple grants an unapproved '
                                                            'external issuer/subject/audience, or if an '
                                                            'authoritative negative authorization test '
                                                            'succeeds. PASS only when the complete '
                                                            'in-scope trust inventory is approved and a '
                                                            'current authorized negative test or '
                                                            'equivalent deny evidence proves unapproved '
                                                            'external/unauthenticated impersonation is '
                                                            'rejected. UNKNOWN if negative-denial '
                                                            'evidence, application or managed-identity '
                                                            'coverage, policy, tuple fields or '
                                                            'pagination is absent.',
                                               'severity': 'high',
                                               'category': 'hardening',
                                               'title': 'Application federated identities trust only '
                                                        'approved external subjects',
                                               'description': 'Reviews configured federated trust as a '
                                                              'preventive signal for external '
                                                              'impersonation attempts; denial of an '
                                                              'actual attempt requires separate '
                                                              'authorization or test evidence.',
                                               'remediation_hint': 'Remove unapproved federated '
                                                                   'credentials and verify that '
                                                                   'unauthorized external or '
                                                                   'unauthenticated token exchanges are '
                                                                   'rejected.'},
 'azure.other.federated_subject_restricted': {'id': 'azure.other.federated_subject_restricted',
                                              'provider': 'azure',
                                              'resource_kind': 'application',
                                              'data_source': 'Paged Microsoft Graph application '
                                                             'federatedIdentityCredentials LIST v1.0 '
                                                             'and ARM '
                                                             'userAssignedIdentities/federatedIdentityCredentials '
                                                             'LIST 2023-01-31 provide issuer, subject '
                                                             'and audiences. Also collect scoped role '
                                                             'assignments/definitions and applicable '
                                                             'impersonation or trust policies to cover '
                                                             'the frozen rule beyond federated '
                                                             'credentials; policy supplies exact '
                                                             'approved issuer/subject/audience triples '
                                                             'and principal authorization.',
                                              'predicate': 'FAIL for a fully observed federated trust '
                                                           'with wildcard/public subject or unapproved '
                                                           'exact issuer/subject/audience tuple, or '
                                                           'another fully observed role-assumption '
                                                           'policy granting wildcard/public access. '
                                                           'PASS only when all in-scope impersonation '
                                                           'and role-assumption policy types are '
                                                           'inventoried and every principal/trust is '
                                                           'nonpublic and policy-approved. UNKNOWN when '
                                                           'only federated credentials were collected, '
                                                           'when app/identity/role lists are '
                                                           'incomplete, or when the approval policy is '
                                                           'absent. A safe federated-credential subset '
                                                           'does not prove the whole source rule.',
                                              'severity': 'high',
                                              'category': 'hardening',
                                              'title': 'Federated identity credentials use approved '
                                                       'issuer and subject pairs',
                                              'description': 'Federated token trust is limited to '
                                                             'explicit issuer and subject combinations.',
                                              'remediation_hint': 'Remove wildcard or public subjects '
                                                                  'from federated credentials and any '
                                                                  'role-assumption policy; grant '
                                                                  'impersonation only to exact approved '
                                                                  'principals and '
                                                                  'issuer/subject/audience '
                                                                  'combinations.'},
 'azure.gap.postgres_server_private_link_used': {'id': 'azure.gap.postgres_server_private_link_used',
                                                 'provider': 'azure',
                                                 'resource_kind': 'postgresql_flexible_server',
                                                 'data_source': 'PostgreSQL Flexible Server GET '
                                                                '2024-08-01 for '
                                                                'properties.network.publicNetworkAccess '
                                                                'and mode; paged '
                                                                'privateEndpointConnections LIST for '
                                                                'status and privateEndpoint.id; exact '
                                                                'server join and current public '
                                                                'firewall/network configuration.',
                                                 'predicate': 'For each PostgreSQL Flexible Server '
                                                              'supporting Private Link, PASS only if a '
                                                              'complete child list contains an Approved '
                                                              'private endpoint connection joined by '
                                                              'exact server and privateEndpoint.id and '
                                                              'public network access is Disabled. FAIL '
                                                              'if complete supported-server and network '
                                                              'evidence proves no approved connection '
                                                              'or public access remains enabled. '
                                                              'UNKNOWN when network mode, feature '
                                                              'support, public-access state, child '
                                                              'paging or status is unresolved. '
                                                              'Delegated-subnet private access alone '
                                                              'does not satisfy this Private Link '
                                                              'requirement.',
                                                 'severity': 'medium',
                                                 'category': 'network',
                                                 'title': 'PostgreSQL Flexible Servers use private '
                                                          'connectivity',
                                                 'description': 'Checks Approved Private Link '
                                                                'connections and disabled public '
                                                                'network access on PostgreSQL Flexible '
                                                                'Servers.',
                                                 'remediation_hint': 'For a PostgreSQL Flexible Server '
                                                                     'that supports Private Link, '
                                                                     'create and approve a private '
                                                                     'endpoint for the server; assess '
                                                                     'delegated-subnet-only deployments '
                                                                     'separately.'},
 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk': {'id': 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk',
                                                               'provider': 'azure',
                                                               'resource_kind': 'postgresql_flexible_server',
                                                               'data_source': 'azure.py '
                                                                              'postgresql_flexible_server: '
                                                                              'properties.dataEncryption.type,primaryKeyURI,primaryUserAssignedIdentityId; '
                                                                              'top-level '
                                                                              'identity.userAssignedIdentities; '
                                                                              'policy '
                                                                              'approvedKeyVaultKeyIds.',
                                                               'predicate': 'For each Flexible Server, '
                                                                            'PASS only if '
                                                                            'dataEncryption.type=AzureKeyVault, '
                                                                            'primaryKeyURI names an '
                                                                            'approved key, and '
                                                                            'dataEncryption.primaryUserAssignedIdentityId '
                                                                            'matches a key in top-level '
                                                                            'identity.userAssignedIdentities; '
                                                                            'FAIL on fully observed '
                                                                            'SystemManaged or '
                                                                            'mismatched/missing key or '
                                                                            'identity; UNKNOWN on '
                                                                            'missing approval or '
                                                                            'incomplete '
                                                                            'encryption/identity data. '
                                                                            'No servers is '
                                                                            'NOT_APPLICABLE.',
                                                               'severity': 'medium',
                                                               'category': 'encryption',
                                                               'title': 'PostgreSQL servers should use '
                                                                        'customer-managed keys to '
                                                                        'encrypt data at rest',
                                                               'description': 'Checks customer-managed '
                                                                              'key data encryption on '
                                                                              'PostgreSQL Flexible '
                                                                              'Server.',
                                                               'remediation_hint': 'In PostgreSQL '
                                                                                   'Flexible Server > '
                                                                                   'Data encryption, '
                                                                                   'select '
                                                                                   'Customer-managed '
                                                                                   'key, assign an '
                                                                                   'authorized '
                                                                                   'user-assigned '
                                                                                   'identity, and '
                                                                                   'choose an approved '
                                                                                   'Key Vault key.'},
 'azure.gap.postgresql_server_infrastructure_encryption_enabled': {'id': 'azure.gap.postgresql_server_infrastructure_encryption_enabled',
                                                                   'provider': 'azure',
                                                                   'resource_kind': 'postgresql_flexible_server',
                                                                   'data_source': 'ARM GET '
                                                                                  'Microsoft.DBforPostgreSQL/servers?api-version=2017-12-01: '
                                                                                  'properties.infrastructureEncryption; '
                                                                                  'applies to legacy '
                                                                                  'single servers, not '
                                                                                  'flexibleServers.',
                                                                   'predicate': 'For each legacy '
                                                                                'PostgreSQL Single '
                                                                                'Server, PASS if '
                                                                                'properties.infrastructureEncryption="Enabled"; '
                                                                                'FAIL if "Disabled"; '
                                                                                'UNKNOWN if server '
                                                                                'list/read is '
                                                                                'incomplete, field '
                                                                                'absent or enum '
                                                                                'unrecognized. Complete '
                                                                                'empty legacy inventory '
                                                                                'is NOT_APPLICABLE.',
                                                                   'severity': 'medium',
                                                                   'category': 'encryption',
                                                                   'title': 'Legacy PostgreSQL single '
                                                                            'server enables '
                                                                            'infrastructure encryption',
                                                                   'description': 'Checks the '
                                                                                  'infrastructureEncryption '
                                                                                  'property supported '
                                                                                  'by the legacy '
                                                                                  'PostgreSQL server '
                                                                                  'resource.',
                                                                   'remediation_hint': 'Enable '
                                                                                       'infrastructure '
                                                                                       'encryption at '
                                                                                       'server creation '
                                                                                       'where '
                                                                                       'supported; '
                                                                                       'migrate or '
                                                                                       'rebuild legacy '
                                                                                       'servers that '
                                                                                       'cannot be '
                                                                                       'changed in '
                                                                                       'place.'},
 'azure.other.devops_security_test_evidence': {'id': 'azure.other.devops_security_test_evidence',
                                               'provider': 'azure',
                                               'resource_kind': 'devops_pipeline',
                                               'data_source': 'Azure DevOps REST Build '
                                                              'Definitions/Builds/Test Runs and '
                                                              'deployment records with paging, plus '
                                                              'approved security-testing process, '
                                                              'required test categories, production '
                                                              'applications, platform-change register '
                                                              'and dated review/acceptance evidence.',
                                               'predicate': 'PASS only if a defined security-testing '
                                                            'process is documented and implemented for '
                                                            'every in-scope development and acceptance '
                                                            'activity, and critical applications '
                                                            'affected by each in-window platform change '
                                                            'have dated technical review and test '
                                                            'evidence showing no adverse '
                                                            'activity/security effect. FAIL only when '
                                                            'complete policy, change, build, test and '
                                                            'review evidence proves a required process '
                                                            'or execution absent. UNKNOWN if process, '
                                                            'test classification, review window, '
                                                            'critical-app scope or joins are '
                                                            'unmeasured.',
                                               'severity': 'medium',
                                               'category': 'hardening',
                                               'title': 'Production builds have security test evidence',
                                               'description': 'Links production deployments to '
                                                              'completed security test runs in Azure '
                                                              'DevOps.',
                                               'remediation_hint': 'Define the security-testing '
                                                                   'process; require relevant tests in '
                                                                   'development and acceptance '
                                                                   'pipelines, and record technical '
                                                                   'review and test outcomes after '
                                                                   'changes to critical application '
                                                                   'platforms.'},
 'azure_devops_project_3_5_1_7_dc58423': {'id': 'azure_devops_project_3_5_1_7_dc58423',
                                          'provider': 'azure',
                                          'resource_kind': 'devops_pipeline',
                                          'data_source': 'Azure DevOps 7.1 paged project variable '
                                                         'groups, build definitions and pipeline '
                                                         'YAML/variable templates expanded at a pinned '
                                                         'revision; inspect credential variable '
                                                         'metadata (isSecret) for project and pipeline '
                                                         'scopes without retaining values. Pipeline '
                                                         'definition GET alone does not expose all '
                                                         'variables.',
                                          'predicate': 'For every in-scope project and pipeline, find '
                                                       'AZURE_CLIENT_SECRET and other approved '
                                                       'credential variable names in all applicable '
                                                       'variable groups and expanded pipeline '
                                                       'variables. FAIL if any such variable is '
                                                       'explicitly plaintext (isSecret is not true or a '
                                                       'YAML literal/inline value). PASS only when '
                                                       'complete expansion and metadata prove every '
                                                       'present credential variable is secret-backed, '
                                                       'and required variable presence is established '
                                                       'by policy. UNKNOWN if a template, group, '
                                                       'definition, variable kind, continuation page or '
                                                       'naming policy is unresolved; absence of a '
                                                       'credential variable is not evidence that a '
                                                       'plaintext credential is absent elsewhere.',
                                          'severity': 'high',
                                          'category': 'hardening',
                                          'title': 'Azure DevOps client secrets in variable groups are '
                                                   'marked secret',
                                          'description': 'Checks confidentiality metadata for named '
                                                         'Azure DevOps variable-group secrets.',
                                          'remediation_hint': 'Move plaintext AZURE_CLIENT_SECRET and '
                                                              'other credentials to secret variables or '
                                                              'Key Vault backed variable groups; update '
                                                              'all affected pipeline and project '
                                                              'definitions, then rotate exposed '
                                                              'secrets.'},
 'azure_vnet_gateway_10_2_1_1_14_4189d89': {'id': 'azure_vnet_gateway_10_2_1_1_14_4189d89',
                                            'provider': 'azure',
                                            'resource_kind': 'vnet_gateway',
                                            'data_source': 'Paged ARM '
                                                           'Microsoft.Network/virtualNetworkGateways '
                                                           'inventory 2023-09-01; separately LIST '
                                                           '{gatewayId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview. '
                                                           'Read '
                                                           'setting.properties.logs[].category/.enabled '
                                                           'and setting.properties.workspaceId or '
                                                           'approved eventHub/storage destination.',
                                            'predicate': 'For each VPN gateway supporting point-to-site '
                                                         'client connections, PASS only if a complete '
                                                         'child diagnostic-setting list has '
                                                         'P2SDiagnosticLog enabled with an approved '
                                                         'nonempty destination on the same setting. '
                                                         'FAIL if the complete list proves none; '
                                                         'UNKNOWN for unsupported gateway '
                                                         'applicability, missing destination policy, '
                                                         'incomplete gateway/settings lists or '
                                                         'unreadable status. GatewayDiagnosticLog and '
                                                         'TunnelDiagnosticLog do not prove client '
                                                         'connection logging.',
                                            'severity': 'medium',
                                            'category': 'hardening',
                                            'title': 'Azure VPN Gateway has diagnostic logging enabled '
                                                     'for client connections',
                                            'description': 'Checks if Azure VPN Gateway has diagnostic '
                                                           'logging enabled for client connections. The '
                                                           'rule is NON_COMPLIANT if diagnostic '
                                                           'settings are not configured to capture '
                                                           'connection logs.',
                                            'remediation_hint': 'On the VPN gateway, enable the '
                                                                'P2SDiagnosticLog category in a '
                                                                'diagnostic setting and send it to an '
                                                                'approved Log Analytics workspace, '
                                                                'Event Hub or storage destination.'},
 'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc': {'id': 'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc',
                                                                       'provider': 'azure',
                                                                       'resource_kind': 'vnet_gateway',
                                                                       'data_source': 'Paged ARM '
                                                                                      'Microsoft.Network/virtualNetworkGateways '
                                                                                      'LIST and '
                                                                                      'per-gateway GET '
                                                                                      '2026-01-01; '
                                                                                      'properties.ipConfigurations[].properties.subnet.id; '
                                                                                      'parameter '
                                                                                      'approvedVnetIds.',
                                                                       'predicate': 'For every virtual '
                                                                                    'network gateway, '
                                                                                    'require a complete '
                                                                                    'nonempty '
                                                                                    'properties.ipConfigurations '
                                                                                    'list and resolve '
                                                                                    'each '
                                                                                    'properties.ipConfigurations[].properties.subnet.id '
                                                                                    'to its parent '
                                                                                    'VNet. FAIL if a '
                                                                                    'fully observed '
                                                                                    'gateway has a '
                                                                                    'subnet in a VNet '
                                                                                    'outside '
                                                                                    'approvedVnetIds. '
                                                                                    'PASS if every '
                                                                                    'observed gateway '
                                                                                    'subnet resolves to '
                                                                                    'an approved VNet. '
                                                                                    'UNKNOWN if '
                                                                                    'approvedVnetIds, '
                                                                                    'ipConfigurations/subnet '
                                                                                    'ID, subnet parsing '
                                                                                    'or gateway '
                                                                                    'inventory is '
                                                                                    'missing or '
                                                                                    'incomplete. '
                                                                                    'Complete empty '
                                                                                    'gateway inventory '
                                                                                    'is NOT_APPLICABLE.',
                                                                       'severity': 'medium',
                                                                       'category': 'network',
                                                                       'title': 'Virtual network '
                                                                                'gateways reside in '
                                                                                'approved VNets',
                                                                       'description': 'Checks the VNet '
                                                                                      'placement of '
                                                                                      'Azure Virtual '
                                                                                      'Network '
                                                                                      'gateways; it '
                                                                                      'does not measure '
                                                                                      'SSH exposure.',
                                                                       'remediation_hint': 'Deploy a '
                                                                                           'replacement '
                                                                                           'virtual '
                                                                                           'network '
                                                                                           'gateway in '
                                                                                           'GatewaySubnet '
                                                                                           'of an '
                                                                                           'approved '
                                                                                           'VNet and '
                                                                                           'migrate '
                                                                                           'connections '
                                                                                           'before '
                                                                                           'removing '
                                                                                           'the old '
                                                                                           'gateway.'},
 'azure.gap.mysql_server_private_link_used': {'id': 'azure.gap.mysql_server_private_link_used',
                                              'provider': 'azure',
                                              'resource_kind': 'mysql_flexible_server',
                                              'data_source': 'Paged MySQL Flexible Server inventory and '
                                                             'each privateEndpointConnections LIST '
                                                             '2024-12-30: '
                                                             'properties.privateLinkServiceConnectionState.status, '
                                                             'properties.privateEndpoint.id. Also GET '
                                                             'server networking/publicNetworkAccess and '
                                                             'inspect effective firewall rules for '
                                                             'public ingress.',
                                              'predicate': 'PASS only if every applicable MySQL server '
                                                           'has an Approved private endpoint connection '
                                                           'with a valid endpoint ID and public access '
                                                           'is disabled or proven restricted to the '
                                                           'known approved networks required by the '
                                                           'frozen rule. FAIL if complete evidence '
                                                           'proves no approved endpoint or an '
                                                           'unapproved public path. UNKNOWN if '
                                                           'parent/child paging, network setting or '
                                                           'effective firewall evidence is incomplete.',
                                              'severity': 'medium',
                                              'category': 'network',
                                              'title': 'Private endpoint should be enabled for MySQL '
                                                       'servers',
                                              'description': 'Checks approved private endpoint '
                                                             'connection presence on '
                                                             'Microsoft.DBforMySQL/flexibleServers.',
                                              'remediation_hint': 'Create and approve a private '
                                                                  'endpoint for MySQL Flexible Server; '
                                                                  'disable public network access or '
                                                                  'restrict it to explicitly approved '
                                                                  'networks and validate connectivity.'}}

PROPOSED_SPEC_SHA256 = {'azure_pci_1_2_8_19': 'aa466c18672ad1620230f8e7170ca37ab0f738f434af6b88d00924c794bb9048',
 'azure.other.gateway_api_cidr_allowlist': 'c3f3321c834ce92b68c70a2aa2c48d637e3fed4cc9496385368706ade7e1c052',
 'azure_firewall_policy_6_4_1_6_2ad9039': 'b8718d131836e1fdbbf7fc538e999398c4e2509336a25ba2ff0d1c04322d12df',
 'azure_firewall_policy_6_4_1_7_a7975fc': 'b481ed309254ecf12706e3dd8290f559a6aea23accfe2e3d140dbc1c9eefc42d',
 'azure.other.entra_app_secret_age_90': '09a61ffbd9501a64ab497315966c42954f81de35348edff65bfca0cb4da824fd',
 'azure.other.external_impersonation_denied': '54c688e6504ca7c4fda90a9de67d1d1f3c929676759cffd42f18cd31c8df5283',
 'azure.other.federated_subject_restricted': '95757a21dae283e1a194f1e6196bec253b9e543b534ce71ad73ee2619bbf244a',
 'azure.gap.postgres_server_private_link_used': 'f51f4d1dea8ea42e9cd50fc5d0bfdd558c8f74bffd56272e19677f123f72bf34',
 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk': '6d0e857f59f8fef60944398bf3af0ff919335a5740d04bff6f891c443fee04b9',
 'azure.gap.postgresql_server_infrastructure_encryption_enabled': '8528d026b7e00a37094d292b7383ef3f1df0dbd41f480d6ebafe965a0b4c6ca7',
 'azure.other.devops_security_test_evidence': 'e9fffc8bafec2fa34333df5847267f2b31408a41a3205263ab9397310368992e',
 'azure_devops_project_3_5_1_7_dc58423': 'ab93deba583a133b2771d1fecb91545963677bce6f5b2b7fa364d88e2f02c58e',
 'azure_vnet_gateway_10_2_1_1_14_4189d89': '3e56bd233079d68dfd3ba21f0ce94c7c4ee107b40c4d1754e08810a71efa4ed4',
 'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc': '56be068db56911dc90a714be4f0d74144fcec9a637099bf9ea596beba2b5c765',
 'azure.gap.mysql_server_private_link_used': '275f3f418dae6789587e9f61f2a5e15eaedf159f376b6cffc909aa49a451fba1'}

IDS = tuple(SPECS)
_ARM = re.compile(r'/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/([^/]+)/([^/]+)/([^/]+)', re.I)
_TYPES = {
    'app_service': 'Microsoft.Web/sites',
    'web_application_firewall_policy': 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
    'application_gateway': 'Microsoft.Network/applicationGateways',
    'vnet_gateway': 'Microsoft.Network/virtualNetworkGateways',
    'virtual_network_gateway': 'Microsoft.Network/virtualNetworkGateways',
    'postgresql_flexible_server': 'Microsoft.DBforPostgreSQL/flexibleServers',
    'postgresql_single_server': 'Microsoft.DBforPostgreSQL/servers',
    'mysql_flexible_server': 'Microsoft.DBforMySQL/flexibleServers',
}


def _enum(obj, path, allowed):
    value = get(obj, path, str)
    if value not in allowed:
        raise Unavailable('unrecognized ' + path)
    return value


def _strings(value, *, nonempty=False):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise Unavailable('malformed string list')
    if len(value) != len(set(value)) or (nonempty and not value):
        raise Unavailable('duplicate or empty required string list')
    return value


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('missing timestamp')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('invalid timestamp') from exc
    if stamp.tzinfo is None:
        raise Unavailable('timestamp has no timezone')
    return stamp.astimezone(timezone.utc)


def _context(index):
    ctx = get(index, 'context', dict)
    if get(ctx, 'provider', str) != 'azure':
        raise Unavailable('foreign provider')
    if not re.fullmatch(r'/(subscriptions|tenants|devops)/[^/]+', get(ctx, 'scope', str), re.I):
        raise Unavailable('unrecognized Azure scope')
    return ctx


def _arm(rid, rtype=None, scope=None):
    parsed = _ARM.fullmatch(rid) if isinstance(rid, str) else None
    if not parsed or rtype and (parsed[3] + '/' + parsed[4]).casefold() != rtype.casefold():
        raise Unavailable('invalid ARM resource identity')
    if scope and not rid.casefold().startswith(scope.casefold() + '/'):
        raise Unavailable('foreign ARM resource')
    return rid.casefold()


def _inventory(index, kind, item=None):
    ctx = _context(index)
    scope = ctx['scope']
    if (kind in _TYPES and not scope.lower().startswith('/subscriptions/') or
            kind in ('application', 'directory_application') and not scope.lower().startswith('/tenants/') or
            kind == 'devops_pipeline' and not scope.startswith('/devops/')):
        raise Unavailable('inventory authority has wrong scope type')
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('missing or ambiguous inventory: ' + kind)
    env = envelopes[0]
    if get(env, 'type', str) != kind or get(env, 'scope', str).casefold() != scope.casefold():
        raise Unavailable('foreign inventory: ' + kind)
    rows = complete_items(index, kind)
    declared = list_of_objects(get(env, 'items', list))
    if declared != rows or env['status'] == 'empty' and rows:
        raise Unavailable('inventory envelope and resource rows differ')
    for wrapper in list_of_objects(get(index, kind, list)):
        if (get(wrapper, 'type', str) != kind or
                get(wrapper, 'scope', str).casefold() != scope.casefold() or
                wrapper.get('provider', 'azure') != 'azure'):
            raise Unavailable('foreign resource wrapper')
    by_id = {}
    for row in rows:
        rid = get(row, 'id', str)
        if kind in _TYPES:
            rid = _arm(rid, _TYPES[kind], scope)
        elif kind in ('application', 'directory_application'):
            if not scope.startswith('/tenants/') or not re.fullmatch(r'[0-9a-fA-F-]{36}', rid):
                raise Unavailable('application tenant identity missing')
            proof = get(row, '_provenance', dict)
            if get(proof, 'tenant_id', str).casefold() != scope.split('/')[-1].casefold() or get(proof, 'tenant_verified', bool) is not True:
                raise Unavailable('unverified directory tenant')
            rid = rid.casefold()
        elif kind == 'devops_pipeline':
            if not scope.startswith('/devops/') or get(row, 'organization', str) != scope.split('/')[-1]:
                raise Unavailable('foreign DevOps organization')
            get(row, 'projectId', str)
            get(row, 'revision', str)
        if rid in by_id:
            raise Unavailable('duplicate resource identity')
        by_id[rid] = row
    if item is not None:
        rid = get(item, 'id', str).casefold()
        if by_id.get(rid) != item:
            raise Unavailable('resource differs from scoped inventory')
    return rows


def _primary(item, index, kind):
    # Preserve the signed runtime kind while recognizing current collector names.
    aliases = {'application': 'directory_application', 'vnet_gateway': 'virtual_network_gateway'}
    actual = kind if kind in get(index, 'collections', dict) else aliases.get(kind, kind)
    return _inventory(index, actual, item if item else None)


def _policy(index, key, expected=list):
    ctx = _context(index)
    policy = get(get(ctx, 'metadata', dict), 'sw14Policy', dict)
    if (get(policy, 'scope', str).casefold() != ctx['scope'].casefold() or
            get(policy, 'status', str) != 'collected'):
        raise Unavailable('approval policy scope or status unavailable')
    return get(policy, key, expected)


def _full_default(obj, field, default, owner):
    if field in obj or field in obj.get('_coverage', {}):
        return get(obj, field)
    proof = get(owner, '_provenance', dict)
    if get(proof, 'representation', str) != 'full' or get(proof, 'read_only', bool) is not True:
        raise Unavailable('omitted setting without complete representation')
    return default


def _evidence(item, field, index):
    native = item.get(field, {})
    if (isinstance(native, dict) and isinstance(native.get('_provenance'), dict)
            and native['_provenance'].get('native_devops_schema') == 1):
        from peaso.collectors.azure_devops_pipeline_native import native_evidence
        return native_evidence(item, field, index)
    value = get(item, field, dict)
    proof = get(value, '_provenance', dict)
    ctx = _context(index)
    if (get(proof, 'read_only', bool) is not True or
            get(proof, 'authority', str) not in {'approved-evidence', 'FirewallManager'} or
            get(proof, 'resource_id', str).casefold() != get(item, 'id', str).casefold() or
            get(proof, 'scope', str).casefold() != ctx['scope'].casefold() or
            get(proof, 'snapshot_id', str) != get(ctx, 'snapshot_id', str)):
        raise Unavailable('evidence association or authority unavailable')
    if get(value, 'status', str) != 'collected':
        raise Unavailable('incomplete evidence')
    return value


def _children(item, field):
    coverage = get(item, '_coverage', dict)
    state = _enum(get(coverage, field, dict), 'status', {'collected', 'empty'})
    rows = list_of_objects(get(item, field, list))
    if state == 'empty' and rows:
        raise Unavailable('contradictory child inventory')
    seen = set()
    parent = get(item, 'id', str)
    for row in rows:
        rid = get(row, 'id', str)
        prefix = parent + ('/providers/Microsoft.Insights/diagnosticSettings/' if field == 'diagnosticSettings' else '/' + field + '/')
        if not rid.casefold().startswith(prefix.casefold()) or not rid[len(prefix):] or '/' in rid[len(prefix):] or rid.casefold() in seen:
            raise Unavailable('foreign or duplicate child')
        seen.add(rid.casefold())
    return rows


def _connections(item):
    rows = _children(item, 'privateEndpointConnections')
    approved = []
    for row in rows:
        state = _enum(row, 'properties.privateLinkServiceConnectionState.status', {'Approved', 'Pending', 'Rejected', 'Disconnected'})
        endpoint = _arm(get(row, 'properties.privateEndpoint.id', str), 'Microsoft.Network/privateEndpoints')
        if state == 'Approved':
            approved.append(endpoint)
    return approved


def _ranges(values):
    values = _strings(values)
    out = []
    for value in values:
        try:
            net = ip_network(value, strict=True)
        except ValueError as exc:
            raise Unavailable('invalid CIDR') from exc
        out.append((net.version, int(net.network_address), int(net.broadcast_address)))
    return out


def _intersection(a, b):
    return [(v, max(lo, x), min(hi, y)) for v, lo, hi in a for w, x, y in b
            if v == w and max(lo, x) <= min(hi, y)]


def _subtract(a, b):
    out = list(a)
    for w, x, y in b:
        next_rows = []
        for v, lo, hi in out:
            if v != w or y < lo or x > hi:
                next_rows.append((v, lo, hi))
            else:
                if lo < x:
                    next_rows.append((v, lo, x - 1))
                if y < hi:
                    next_rows.append((v, y + 1, hi))
        out = next_rows
    return out


_UNIVERSE = [(4, 0, 2**32 - 1), (6, 0, 2**128 - 1)]


def _ordered_ingress(rules, default, approved):
    # All declarations are validated before grading to avoid malformed-fact results.
    ordered, priorities = [], set()
    for rule in list_of_objects(rules):
        priority = get(rule, 'priority', int)
        if priority < 0 or priority in priorities:
            raise Unavailable('ambiguous rule priority')
        priorities.add(priority)
        action = _enum(rule, 'action', {'Allow', 'Deny'})
        if get(rule, 'headers', dict):
            raise Unavailable('header-sensitive access rule unsupported')
        tag = _enum(rule, 'tag', {'Default', 'ServiceTag'})
        if tag != 'Default':
            raise Unavailable('service tag resolution unavailable')
        ranges = _ranges([get(rule, 'ipAddress', str)])
        ordered.append((priority, action, ranges))
    if default not in {'Allow', 'Deny'}:
        raise Unavailable('missing effective default action')
    remaining = _subtract(_UNIVERSE, approved)
    for _, action, ranges in sorted(ordered):
        matched = _intersection(remaining, ranges)
        if action == 'Allow' and matched:
            return True
        remaining = _subtract(remaining, ranges)
    return default == 'Allow' and bool(remaining)


def function_ingress(item, index):
    rows = _primary(item, index, 'app_service')
    apps = [row for row in rows if 'functionapp' in get(row, 'kind', str).lower().split(',')]
    if not apps or item and item not in apps:
        return 'NOT_APPLICABLE', {'reason': 'No applicable Function App'}
    if not item:
        raise Unavailable('Function App resource required')
    public = _enum(item, 'properties.publicNetworkAccess', {'Enabled', 'Disabled'})
    if public == 'Disabled':
        endpoints = _connections(item)
        allowed = {_arm(x, 'Microsoft.Network/privateEndpoints') for x in _strings(_policy(index, 'approvedPrivateEndpointIds'))}
        return result(not bool(set(endpoints) & allowed), approved_private_endpoints=sorted(set(endpoints) & allowed))
    approved = _ranges(_policy(index, 'approvedCidrs'))
    configs = _inventory_child(index, 'app_service_config', item, '/config/web')
    props = get(configs[0], 'properties', dict)
    failed = _ordered_ingress(get(props, 'ipSecurityRestrictions', list),
                              get(props, 'ipSecurityRestrictionsDefaultAction', str), approved)
    return result(failed, semantics='Effective declared main-site source access restrictions')


def _inventory_child(index, kind, parent, suffix=None):
    parent_id = get(parent, 'id', str)
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or not envelopes:
        raise Unavailable('missing child inventory')
    own = [e for e in envelopes if get(e, 'scope', str).casefold() == parent_id.casefold()]
    if len(own) != 1 or get(own[0], 'type', str) != kind or get(own[0], 'status', str) not in {'collected', 'empty'}:
        raise Unavailable('incomplete exact-parent child inventory')
    all_rows = list_of_objects(get(index, kind, list))
    rows = [get(r, 'data', dict) for r in all_rows if get(r, 'scope', str).casefold() == parent_id.casefold()]
    if own[0]['status'] == 'empty' and rows:
        raise Unavailable('contradictory child inventory')
    ids = set()
    for row in rows:
        rid = get(row, 'id', str).casefold()
        if (suffix and rid != (parent_id + suffix).casefold() or
                not rid.startswith(parent_id.casefold() + '/') or rid in ids):
            raise Unavailable('foreign or ambiguous child association')
        if 'parent_id' in row and get(row, 'parent_id', str).casefold() != parent_id.casefold():
            raise Unavailable('foreign child parent')
        ids.add(rid)
    if suffix and len(rows) != 1:
        raise Unavailable('exact configuration unavailable')
    return rows


def vnet_placement(item, index):
    rows = _primary(item, index, 'vnet_gateway')
    if not rows:
        return 'NOT_APPLICABLE', {'reason': 'Complete empty gateway inventory'}
    approved = {_arm(x, 'Microsoft.Network/virtualNetworks') for x in _strings(_policy(index, 'approvedVnetIds'))}
    configs = list_of_objects(get(item, 'properties.ipConfigurations', list))
    if not configs:
        raise Unavailable('gateway IP configuration absent')
    networks = []
    for config in configs:
        rid = get(config, 'properties.subnet.id', str)
        if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+/subnets/[^/]+', rid, re.I):
            raise Unavailable('invalid gateway subnet identity')
        networks.append(_arm(rid.rsplit('/subnets/', 1)[0] if '/subnets/' in rid else rid[:rid.lower().rfind('/subnets/')], 'Microsoft.Network/virtualNetworks'))
    return result(any(x not in approved for x in networks), vnet_ids=networks)


def vpn_logging(item, index):
    _primary(item, index, 'vnet_gateway')
    kind = _enum(item, 'properties.gatewayType', {'Vpn', 'ExpressRoute', 'LocalGateway'})
    if kind != 'Vpn':
        return 'NOT_APPLICABLE', {'reason': 'Gateway does not support VPN clients'}
    vpn = get(item, 'properties.vpnClientConfiguration', dict)
    prefixes = _strings(get(vpn, 'vpnClientAddressPool.addressPrefixes', list))
    _ranges(prefixes)
    if not prefixes:
        return 'NOT_APPLICABLE', {'reason': 'Point-to-site address pool is empty'}
    allowed = {_arm(x) for x in _strings(_policy(index, 'approvedDiagnosticDestinationIds'))}
    settings = _children(item, 'diagnosticSettings')
    found = False
    for setting in settings:
        props = get(setting, 'properties', dict)
        enabled = False
        for log in list_of_objects(get(props, 'logs', list)):
            category = get(log, 'category', str)
            flag = get(log, 'enabled', bool)
            if category == 'P2SDiagnosticLog' and flag:
                enabled = True
        sinks = []
        for field in ('workspaceId', 'storageAccountId', 'eventHubAuthorizationRuleId'):
            value = _full_default(props, field, None, setting)
            if value is not None:
                sinks.append(_arm(value))
        found |= enabled and bool(set(sinks) & allowed)
    return result(not found, category='P2SDiagnosticLog')


def private_link(item, index, *, postgres):
    kind = 'postgresql_flexible_server' if postgres else 'mysql_flexible_server'
    _primary(item, index, kind)
    if postgres:
        feature = _evidence(item, 'privateLinkSupport', index)
        _enum(feature, 'networkMode', {'Public', 'PrivateLink', 'DelegatedSubnet'})
        if get(feature, 'supported', bool) is not True:
            return 'NOT_APPLICABLE', {'reason': 'Authoritative server feature evidence excludes Private Link'}
    public = _enum(item, 'properties.network.publicNetworkAccess', {'Enabled', 'Disabled'})
    endpoints = _connections(item)
    if postgres:
        return result(not endpoints or public != 'Disabled', approved_endpoint_ids=endpoints, public_network_access=public)
    if public == 'Disabled':
        return result(not endpoints, approved_endpoint_ids=endpoints)
    approved = _ranges(_policy(index, 'approvedCidrs'))
    rules = _children(item, 'firewallRules')
    unsafe = False
    for row in rules:
        try:
            start = ip_address(get(row, 'properties.startIpAddress', str))
            end = ip_address(get(row, 'properties.endIpAddress', str))
        except ValueError as exc:
            raise Unavailable('invalid firewall range') from exc
        if start.version != end.version or int(start) > int(end):
            raise Unavailable('invalid firewall range order')
        # The Azure-services 0.0.0.0 sentinel cannot be treated as a single approved IP.
        if int(start) == int(end) == 0:
            raise Unavailable('Azure-services firewall sentinel unresolved')
        unsafe |= bool(_subtract([(start.version, int(start), int(end))], approved))
    return result(not endpoints or unsafe, approved_endpoint_ids=endpoints)


def postgres_cmk(item, index):
    rows = _primary(item, index, 'postgresql_flexible_server')
    if not rows:
        return 'NOT_APPLICABLE', {'reason': 'Complete empty server inventory'}
    allowed = _strings(_policy(index, 'approvedKeyVaultKeyIds'))
    for value in allowed:
        _key_uri(value)
    encryption = get(item, 'properties.dataEncryption', dict)
    kind = _enum(encryption, 'type', {'AzureKeyVault', 'SystemManaged'})
    if kind == 'SystemManaged':
        return result(True, encryption_type=kind)
    key = _full_default(encryption, 'primaryKeyURI', None, item)
    identity = _full_default(encryption, 'primaryUserAssignedIdentityId', None, item)
    identities = get(item, 'identity.userAssignedIdentities', dict)
    names = set()
    for name, detail in identities.items():
        names.add(_arm(name, 'Microsoft.ManagedIdentity/userAssignedIdentities'))
        guard(detail)
    if key is not None:
        _key_uri(key)
    if identity is not None:
        identity = _arm(identity, 'Microsoft.ManagedIdentity/userAssignedIdentities')
    return result(key is None or identity is None or key not in allowed or identity not in names,
                  key_uri=key, assigned_identity=identity)


def _key_uri(value):
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (parsed is None or parsed.scheme != 'https' or parsed.username or parsed.password or
            parsed.query or parsed.fragment or parsed.port or
            not re.fullmatch(r'[A-Za-z0-9-]+\.vault\.azure\.net', parsed.hostname or '') or
            not re.fullmatch(r'/keys/[A-Za-z0-9-]+(?:/[A-Za-z0-9-]+)?', parsed.path)):
        raise Unavailable('invalid Key Vault key URI')


def infrastructure_encryption(item, index):
    # Signed kind is flexible_server; evaluate ONLY the separately inventoried legacy source.
    if item:
        rid = get(item, 'id', str)
        _arm(rid, scope=_context(index)['scope'])
        if not any(_arm(rid).split('/providers/')[1].startswith(t.casefold() + '/') for t in (_TYPES['postgresql_single_server'], _TYPES['postgresql_flexible_server'])):
            raise Unavailable('unsupported PostgreSQL identity')
    rows = _inventory(index, 'postgresql_single_server')
    if not rows:
        return 'NOT_APPLICABLE', {'reason': 'Complete empty legacy PostgreSQL inventory'}
    if item and item.get('id', '').casefold() in {r['id'].casefold() for r in rows}:
        rows = [next(r for r in rows if r['id'].casefold() == item['id'].casefold())]
        if rows[0] != item:
            raise Unavailable('legacy resource differs from inventory')
    states = [_enum(r, 'properties.infrastructureEncryption', {'Enabled', 'Disabled'}) for r in rows]
    return result('Disabled' in states, legacy_server_count=len(rows), states=states)


def credential_age(item, index):
    rows = _primary(item, index, 'application')
    now = _time(get(_context(index), 'created_at', str))
    aged, uncertain, active = [], False, 0
    for app in rows:
        for field in ('passwordCredentials', 'keyCredentials'):
            try:
                credentials = list_of_objects(get(app, field, list))
            except Unavailable:
                uncertain = True
                continue
            seen = set()
            for cred in credentials:
                try:
                    key = get(cred, 'keyId', str)
                    if not key or key in seen:
                        raise Unavailable('duplicate or absent credential key')
                    seen.add(key)
                    start = _time(get(cred, 'startDateTime', str))
                    end = _time(get(cred, 'endDateTime', str))
                    if start >= end:
                        raise Unavailable('credential date order or time skew')
                    if start <= now < end:
                        active += 1
                        if start <= now - timedelta(days=90):
                            aged.append({'application_id': app['id'], 'key_id': key})
                except Unavailable:
                    uncertain = True
    if aged:
        return result(True, aged_active_credentials=aged)
    if uncertain:
        return unknown('active state or credential dates unavailable')
    return result(False, active_credential_count=active)


def _trust_rows(item, index):
    _primary(item, index, 'application')
    policy = _policy(index, 'federatedTrustPolicy', dict)
    approved = set()
    for row in list_of_objects(get(policy, 'approvedTuples', list)):
        issuer, subject = get(row, 'issuer', str), get(row, 'subject', str)
        audiences = _strings(get(row, 'audiences', list), nonempty=True)
        if not issuer or not subject:
            raise Unavailable('empty approved federated tuple')
        approved.add((issuer, subject, tuple(sorted(audiences))))
    principals = set(_strings(get(policy, 'approvedPrincipals', list)))
    evidence = _evidence(item, 'trustInventory', index)
    required = set(_strings(get(policy, 'requiredPolicyTypes', list), nonempty=True))
    covered = set(_strings(get(evidence, 'inventoriedPolicyTypes', list)))
    # Preserve complete individual observations even if wider inventory is not measured.
    credentials = list_of_objects(get(evidence, 'federatedCredentials', list))
    roles = list_of_objects(get(evidence, 'roleAssumptionPolicies', list))
    bad = []
    for row in credentials:
        issuer, subject = get(row, 'issuer', str), get(row, 'subject', str)
        audiences = _strings(get(row, 'audiences', list), nonempty=True)
        if not issuer or not subject or not get(row, 'id', str):
            raise Unavailable('incomplete federated tuple')
        if get(row, 'ownerId', str).casefold() not in {x.casefold() for x in _strings(get(evidence, 'ownerIds', list))}:
            raise Unavailable('foreign federated trust owner')
        if '*' in subject or subject.lower() in {'public', 'allusers', 'allauthenticatedusers'} or (issuer, subject, tuple(sorted(audiences))) not in approved:
            bad.append(row['id'])
    for row in roles:
        principal = get(row, 'principal', str)
        if not principal or not get(row, 'id', str):
            raise Unavailable('incomplete role assumption policy')
        if '*' in principal or principal.lower() in {'public', 'allusers', 'allauthenticatedusers'} or principal not in principals:
            bad.append(row['id'])
    coverage = get(evidence, 'coverage', dict)
    complete = required <= covered and all(get(coverage, key, str) == 'complete' for key in (
        'applications', 'managedIdentities', 'federatedCredentials', 'roleAssignments', 'roleDefinitions', 'impersonationPolicies'))
    return evidence, bad, complete


def federated_restricted(item, index):
    evidence, bad, complete = _trust_rows(item, index)
    if bad:
        return result(True, unapproved_trust_ids=bad)
    if not complete:
        return unknown('safe trust subset does not cover all policy types')
    return result(False, inventoried_policy_types=evidence['inventoriedPolicyTypes'])


def external_denied(item, index):
    _primary(item, index, 'application')
    try:
        _, bad, complete = _trust_rows(item, index)
    except Unavailable:
        bad, complete = [], False
    if bad:
        return result(True, unapproved_trust_ids=bad)
    evidence = _evidence(item, 'negativeAuthorizationEvidence', index)
    policy = _policy(index, 'federatedTrustPolicy', dict)
    now = _time(get(_context(index), 'created_at', str))
    ttl = get(policy, 'negativeEvidenceMaxAgeDays', int)
    if ttl <= 0:
        raise Unavailable('negative evidence freshness policy unavailable')
    cases = list_of_objects(get(evidence, 'tests', list))
    observed, succeeded = set(), False
    for case in cases:
        scenario = _enum(case, 'scenario', {'unapprovedExternal', 'unauthenticated'})
        if get(case, 'authorized', bool) is not True:
            raise Unavailable('test was not authorized')
        stamp = _time(get(case, 'testedAt', str))
        if not now - timedelta(days=ttl) <= stamp <= now:
            raise Unavailable('authorization evidence stale or future')
        outcome = _enum(case, 'outcome', {'Denied', 'Succeeded'})
        observed.add(scenario)
        succeeded |= outcome == 'Succeeded'
    if succeeded:
        return result(True, reason='Authoritative unauthorized-impersonation scenario succeeded')
    if not complete or observed != {'unapprovedExternal', 'unauthenticated'}:
        return unknown('complete trust inventory and both denial scenarios required')
    return result(False, denied_scenarios=sorted(observed))


def firewall_rank(item, index):
    _primary(item, index, 'web_application_firewall_policy')
    evidence = _evidence(item, 'firewallManagerOrder', index)
    if get(evidence, '_provenance.authority', str) != 'FirewallManager':
        raise Unavailable('Firewall Manager authority required')
    parameter = list_of_objects(get(evidence, 'ruleGroups', list))
    deployed = list_of_objects(get(evidence, 'deployedGroups', list))
    if not parameter or not deployed:
        raise Unavailable('group association or order missing')
    def ordered(rows, *, parameter=False):
        groups, ranks = {}, set()
        for row in rows:
            gid, rank = get(row, 'groupId', str), get(row, 'rank', int)
            if not gid or rank < 0 or rank in ranks or gid in groups:
                raise Unavailable('ambiguous group rank')
            groups[gid] = rank
            ranks.add(rank)
        if parameter and ranks != set(range(len(rows))):
            raise Unavailable('noncontiguous rank evidence')
        return groups
    expected, observed = ordered(parameter, parameter=True), ordered(deployed)
    return result(expected != observed, approved_ranks=expected, deployed_ranks=observed)


def _attached_paths(item, index):
    # Association evidence is derived from a complete gateway/listener/route graph,
    # retaining the exact IDs and parent precedence for every path.
    evidence = _evidence(item, 'gatewayAssociations', index)
    if get(evidence, 'gatewayInventory', str) != 'complete' or get(evidence, 'routeInventory', str) != 'complete':
        raise Unavailable('gateway or alternate path inventory incomplete')
    paths = list_of_objects(get(evidence, 'paths', list))
    keys = set()
    for row in paths:
        gateway = _arm(get(row, 'gatewayId', str), 'Microsoft.Network/applicationGateways', _context(index)['scope'])
        listener = get(row, 'listenerId', str).casefold()
        route = get(row, 'routeId', str).casefold()
        if not listener.startswith(gateway + '/httplisteners/') or not route.startswith(gateway + '/'):
            raise Unavailable('foreign route or listener association')
        key = (listener, route)
        if key in keys:
            raise Unavailable('duplicate effective gateway path')
        keys.add(key)
        if get(row, 'sku', str) != 'WAF_v2':
            raise Unavailable('gateway WAF applicability unsupported')
        if get(row, 'associationResolved', bool) is not True:
            raise Unavailable('effective policy precedence unresolved')
        policy = get(row, 'effectivePolicyId')
        if policy is not None:
            _arm(policy, _TYPES['web_application_firewall_policy'], _context(index)['scope'])
        get(row, 'apiInScope', bool)
    return paths


def _policy_settings(item):
    settings = get(item, 'properties.policySettings', dict)
    state = _full_default(settings, 'state', 'Enabled', item)
    if state not in {'Enabled', 'Disabled'}:
        raise Unavailable('unrecognized WAF policy state')
    mode = _enum(settings, 'mode', {'Detection', 'Prevention'})
    return state, mode


def waf_managed_groups(item, index):
    _primary(item, index, 'web_application_firewall_policy')
    paths = _attached_paths(item, index)
    attached = [p for p in paths if p['effectivePolicyId'] is not None and p['effectivePolicyId'].casefold() == item['id'].casefold()]
    if not attached:
        return 'NOT_APPLICABLE', {'reason': 'Policy has no attached in-scope WAF v2 path'}
    state, mode = _policy_settings(item)
    if state == 'Disabled':
        return result(True, policy_state=state)
    catalogue = _evidence(item, 'managedRuleCatalogue', index)
    sets = list_of_objects(get(item, 'properties.managedRules.managedRuleSets', list))
    cats = list_of_objects(get(catalogue, 'ruleSets', list))
    indexed = {}
    for cat in cats:
        key = (get(cat, 'ruleSetType', str), get(cat, 'ruleSetVersion', str))
        if key in indexed:
            raise Unavailable('ambiguous versioned rule-set catalogue')
        indexed[key] = cat
    if not sets:
        return result(True, reason='Attached policy contains no managed rule group')
    inactive, assessed, set_seen = [], 0, set()
    for ruleset in sets:
        key = (get(ruleset, 'ruleSetType', str), get(ruleset, 'ruleSetVersion', str))
        if key not in indexed or key in set_seen:
            raise Unavailable('unresolved or duplicate managed rule-set version')
        set_seen.add(key)
        groups = {}
        for group in list_of_objects(get(indexed[key], 'ruleGroups', list)):
            name = get(group, 'ruleGroupName', str)
            if not name or name in groups:
                raise Unavailable('duplicate managed group catalogue')
            defaults = {}
            for rule in list_of_objects(get(group, 'rules', list)):
                rid = get(rule, 'ruleId', str)
                if not rid or rid in defaults:
                    raise Unavailable('duplicate catalogue rule')
                defaults[rid] = _enum(rule, 'state', {'Enabled', 'Disabled'})
            groups[name] = defaults
        if not groups:
            raise Unavailable('versioned rule-set has no catalogue groups')
        overrides = _full_default(ruleset, 'ruleGroupOverrides', [], item)
        override_seen = set()
        for override in list_of_objects(overrides):
            name = get(override, 'ruleGroupName', str)
            if name not in groups or name in override_seen:
                raise Unavailable('unresolved or duplicate managed group override')
            override_seen.add(name)
            overrides_rules = list_of_objects(get(override, 'rules', list))
            if not overrides_rules:
                groups[name] = dict.fromkeys(groups[name], 'Disabled')
            seen = set()
            for rule in overrides_rules:
                rid = get(rule, 'ruleId', str)
                if rid not in groups[name] or rid in seen:
                    raise Unavailable('unresolved override rule')
                seen.add(rid)
                state = _full_default(rule, 'state', 'Disabled', item)
                if state not in {'Enabled', 'Disabled'}:
                    raise Unavailable('unrecognized managed rule override state')
                groups[name][rid] = state
        for name, rules in groups.items():
            assessed += 1
            if not any(state == 'Enabled' for state in rules.values()):
                inactive.append('/'.join(key) + '/' + name)
    return result(bool(inactive), inactive_groups=inactive, assessed_group_count=assessed, mode=mode)


def _remote_rules(policy, outside):
    state, mode = _policy_settings(policy)
    if state == 'Disabled' or mode == 'Detection':
        return 'FAIL' if outside else 'UNKNOWN'
    rules = list_of_objects(get(policy, 'properties.customRules', list))
    ordered, priorities = [], set()
    for rule in rules:
        state = _full_default(rule, 'state', 'Enabled', policy)
        if state not in {'Enabled', 'Disabled'}:
            raise Unavailable('unresolved custom-rule state')
        if state == 'Disabled':
            continue
        priority = get(rule, 'priority', int)
        if not 1 <= priority <= 100 or priority in priorities:
            raise Unavailable('invalid or ambiguous custom-rule priority')
        priorities.add(priority)
        if get(rule, 'ruleType', str) != 'MatchRule':
            raise Unavailable('unsupported WAF matching rule type')
        action = _enum(rule, 'action', {'Allow', 'Block', 'Log'})
        conditions = list_of_objects(get(rule, 'matchConditions', list))
        if not conditions:
            raise Unavailable('missing WAF conditions')
        matched = list(_UNIVERSE)
        for condition in conditions:
            variables = list_of_objects(get(condition, 'matchVariables', list))
            if len(variables) != 1 or get(variables[0], 'variableName', str) != 'RemoteAddr':
                raise Unavailable('unsupported WAF request variable')
            selector = _full_default(variables[0], 'selector', None, policy)
            if selector not in (None, '') or get(condition, 'operator', str) != 'IPMatch':
                raise Unavailable('unsupported RemoteAddr operator')
            transforms = _strings(get(condition, 'transforms', list))
            if transforms:
                raise Unavailable('unsupported RemoteAddr transform')
            ranges = _ranges(get(condition, 'matchValues', list))
            negated = get(condition, 'negationConditon', bool) if 'negationConditon' in condition else get(condition, 'negationCondition', bool)
            if negated:
                ranges = _subtract(_UNIVERSE, ranges)
            matched = _intersection(matched, ranges)
        ordered.append((priority, action, matched))
    remaining = list(outside)
    for _, action, ranges in sorted(ordered):
        if action == 'Allow' and _intersection(remaining, ranges):
            return 'FAIL'
        if action == 'Block':
            remaining = _subtract(remaining, ranges)
    # Falling through custom rules may still hit managed rules. It cannot prove
    # arbitrary outside requests accepted without a matching Allow or bypass.
    return 'PASS' if not remaining else 'UNKNOWN'


def gateway_cidrs(item, index):
    policies = _primary(item, index, 'web_application_firewall_policy')
    paths = [p for p in _attached_paths(item, index) if p['apiInScope']]
    if not paths:
        return 'NOT_APPLICABLE', {'reason': 'Complete empty in-scope API listener set'}
    outside = _subtract(_UNIVERSE, _ranges(_policy(index, 'approvedCidrs')))
    by_id = {p['id'].casefold(): p for p in policies}
    outcomes = []
    for path in paths:
        if path['effectivePolicyId'] is None:
            outcomes.append('FAIL' if outside else 'UNKNOWN')
        else:
            policy = by_id.get(path['effectivePolicyId'].casefold())
            if policy is None:
                raise Unavailable('effective gateway policy unavailable')
            outcomes.append(_remote_rules(policy, outside))
    if 'FAIL' in outcomes:
        return result(True, effective_path_outcomes=outcomes)
    if 'UNKNOWN' in outcomes:
        return unknown('outside-address acceptance or blocking unproven', effective_path_outcomes=outcomes)
    return result(False, effective_path_count=len(paths))


def devops_secrets(item, index):
    _primary(item, index, 'devops_pipeline')
    policy = _policy(index, 'devopsCredentialPolicy', dict)
    names = set(_strings(get(policy, 'credentialVariableNames', list), nonempty=True))
    if 'AZURE_CLIENT_SECRET' not in names:
        raise Unavailable('credential naming policy does not cover AZURE_CLIENT_SECRET')
    required = set(_strings(get(policy, 'requiredVariableNames', list)))
    if not required <= names:
        raise Unavailable('required credential naming policy unresolved')
    evidence = _evidence(item, 'expandedVariables', index)
    if get(evidence, 'revision', str) != get(item, 'revision', str):
        raise Unavailable('expanded variables are not from pinned pipeline revision')
    rows = list_of_objects(get(evidence, 'variables', list))
    present, plaintext = set(), []
    for row in rows:
        name = get(row, 'name', str)
        if name not in names:
            continue
        source = _enum(row, 'source', {'variableGroup', 'pipeline', 'yamlLiteral', 'yamlInline', 'keyVault'})
        scope = get(row, 'scopeId', str)
        if scope not in {item['projectId'], item['id']} | set(_strings(get(evidence, 'variableGroupIds', list))):
            raise Unavailable('foreign variable scope')
        present.add(name)
        if source in {'yamlLiteral', 'yamlInline'}:
            plaintext.append(name)
        elif get(row, 'isSecret', bool) is not True:
            plaintext.append(name)
    if plaintext:
        return result(True, plaintext_variable_names=sorted(set(plaintext)))
    coverage = get(evidence, 'coverage', dict)
    if not all(get(coverage, field, str) == 'complete' for field in ('projects', 'pipelines', 'variableGroups', 'templates', 'variables')):
        return unknown('variable-group, project, pipeline or template expansion incomplete')
    if not required <= present:
        return unknown('policy-required credential variable presence unproven')
    return result(False, secret_variable_names=sorted(present))


def devops_security_tests(item, index):
    _primary(item, index, 'devops_pipeline')
    policy = _policy(index, 'devopsSecurityTestingPolicy', dict)
    categories = set(_strings(get(policy, 'requiredTestCategories', list), nonempty=True))
    apps = set(_strings(get(policy, 'productionApplicationIds', list), nonempty=True))
    critical = set(_strings(get(policy, 'criticalApplicationIds', list)))
    if not critical <= apps:
        raise Unavailable('critical application scope inconsistent')
    start = _time(get(policy, 'reviewWindowStart', str))
    end = _time(get(policy, 'reviewWindowEnd', str))
    now = _time(get(_context(index), 'created_at', str))
    if not start < end <= now:
        raise Unavailable('invalid review window')
    evidence = _evidence(item, 'securityTestingEvidence', index)
    coverage = get(evidence, 'coverage', dict)
    for field in ('policy', 'activities', 'changes', 'builds', 'tests', 'reviews', 'deployments'):
        if get(coverage, field, str) != 'complete':
            raise Unavailable('unmeasured complete security-testing evidence: ' + field)
    process = get(evidence, 'process', dict)
    documented = get(process, 'documented', bool)
    implemented = get(process, 'implemented', bool)
    if documented:
        if not get(process, 'documentId', str):
            raise Unavailable('security-testing process document missing')
    activities = list_of_objects(get(evidence, 'activities', list))
    changes = list_of_objects(get(evidence, 'platformChanges', list))
    tests = list_of_objects(get(evidence, 'tests', list))
    reviews = list_of_objects(get(evidence, 'reviews', list))
    failures, activity_ids, test_ids, review_ids = [], set(), set(), set()
    if not documented or not implemented:
        failures.append('required security-testing process absent')
    for row in tests:
        tid = get(row, 'id', str)
        if not tid or tid in test_ids:
            raise Unavailable('ambiguous test run')
        test_ids.add(tid)
        _enum(row, 'state', {'Completed', 'InProgress', 'NotStarted', 'Aborted'})
        _enum(row, 'outcome', {'Passed', 'Failed', 'Inconclusive'})
        get(row, 'category', str)
        if get(row, 'applicationId', str) not in apps:
            raise Unavailable('foreign application test')
        stamp = _time(get(row, 'completedAt', str))
        if not start <= stamp <= end:
            raise Unavailable('test outside measured review window')
    for row in reviews:
        rid = get(row, 'id', str)
        if not rid or rid in review_ids:
            raise Unavailable('ambiguous technical review')
        review_ids.add(rid)
        if get(row, 'applicationId', str) not in apps:
            raise Unavailable('foreign application review')
        get(row, 'changeId', str)
        if not start <= _time(get(row, 'reviewedAt', str)) <= end:
            raise Unavailable('review outside measured window')
        get(row, 'noAdverseActivityEffect', bool)
        get(row, 'noAdverseSecurityEffect', bool)
    for activity in activities:
        aid = get(activity, 'id', str)
        if not aid or aid in activity_ids:
            raise Unavailable('ambiguous development/acceptance activity')
        activity_ids.add(aid)
        app = get(activity, 'applicationId', str)
        if app not in apps:
            raise Unavailable('foreign production application activity')
        _enum(activity, 'phase', {'development', 'acceptance'})
        stamp = _time(get(activity, 'occurredAt', str))
        if not start <= stamp <= end:
            raise Unavailable('activity outside measured review window')
        build = get(activity, 'buildId', str)
        if not build:
            raise Unavailable('activity build join unmeasured')
        matching = [t for t in tests if get(t, 'activityId', str) == aid and get(t, 'buildId', str) == build and t['applicationId'] == app]
        found = {t['category'] for t in matching if t['state'] == 'Completed' and t['outcome'] == 'Passed'}
        if not categories <= found:
            failures.append('activity:' + aid)
    change_ids = set()
    for change in changes:
        cid = get(change, 'id', str)
        if not cid or cid in change_ids:
            raise Unavailable('ambiguous platform change')
        change_ids.add(cid)
        changed = _time(get(change, 'changedAt', str))
        if not start <= changed <= end:
            raise Unavailable('platform change outside measured review window')
        affected = set(_strings(get(change, 'affectedApplicationIds', list)))
        if not affected <= apps:
            raise Unavailable('unmeasured affected application scope')
        for app in affected & critical:
            matching_reviews = [r for r in reviews if r['changeId'] == cid and r['applicationId'] == app and
                changed <= _time(r['reviewedAt']) <= end and r['noAdverseActivityEffect'] and r['noAdverseSecurityEffect']]
            matching_tests = [t for t in tests if get(t, 'changeId', str) == cid and t['applicationId'] == app and
                changed <= _time(t['completedAt']) <= end and t['state'] == 'Completed' and t['outcome'] == 'Passed']
            if not matching_reviews or not categories <= {t['category'] for t in matching_tests}:
                failures.append('platform-change:' + cid + ':' + app)
    return result(bool(failures), missing_or_adverse_evidence=failures,
                  activity_count=len(activities), platform_change_count=len(changes))


_RULES = {
    'azure_pci_1_2_8_19': function_ingress,
    'azure.other.gateway_api_cidr_allowlist': gateway_cidrs,
    'azure_firewall_policy_6_4_1_6_2ad9039': firewall_rank,
    'azure_firewall_policy_6_4_1_7_a7975fc': waf_managed_groups,
    'azure.other.entra_app_secret_age_90': credential_age,
    'azure.other.external_impersonation_denied': external_denied,
    'azure.other.federated_subject_restricted': federated_restricted,
    'azure.gap.postgres_server_private_link_used': lambda item, index: private_link(item, index, postgres=True),
    'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk': postgres_cmk,
    'azure.gap.postgresql_server_infrastructure_encryption_enabled': infrastructure_encryption,
    'azure.other.devops_security_test_evidence': devops_security_tests,
    'azure_devops_project_3_5_1_7_dc58423': devops_secrets,
    'azure_vnet_gateway_10_2_1_1_14_4189d89': vpn_logging,
    'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc': vnet_placement,
    'azure.gap.mysql_server_private_link_used': lambda item, index: private_link(item, index, postgres=False),
}
DEPENDENCIES = {cid: [spec['resource_kind']] for cid, spec in SPECS.items()}
for _cid in ('azure.other.entra_app_secret_age_90', 'azure.other.external_impersonation_denied', 'azure.other.federated_subject_restricted'):
    DEPENDENCIES[_cid].append('directory_application')
for _cid in ('azure_vnet_gateway_10_2_1_1_14_4189d89', 'azure_vnet_gateway_network_ssh_internet_access_restricted_e19b1dc'):
    DEPENDENCIES[_cid].append('virtual_network_gateway')
DEPENDENCIES['azure_pci_1_2_8_19'].append('app_service_config')
DEPENDENCIES['azure.gap.postgresql_server_infrastructure_encryption_enabled'] = ['postgresql_single_server']
DEPENDENCIES['azure.other.entra_app_secret_age_90'] = ['directory_application']
_SCOPE_IDS = {'azure.gap.postgresql_server_infrastructure_encryption_enabled', 'azure.other.entra_app_secret_age_90'}


def _register(cid):
    spec = SPECS[cid]
    category = spec['category']
    # The shared registrar accepts only its historical categories. Keep the
    # signed category on this module's new immutable Check without changing it.
    registry_category = 'hardening' if category in {'identity', 'encryption'} else category
    @register(cid, spec['provider'], registry_category, spec['resource_kind'], spec['title'],
              spec['severity'], 'CM-6', spec['remediation_hint'], dependencies=DEPENDENCIES[cid],
              target='scope' if cid in _SCOPE_IDS else 'resource')
    def evaluate(item, index):
        return _RULES[cid]({} if cid in _SCOPE_IDS and 'id' not in item else item, index)
    if registry_category != category:
        position = next(i for i, c in enumerate(CHECKS) if c.id == cid)
        CHECKS[position] = replace(CHECKS[position], category=category)
    check = next(c for c in CHECKS if c.id == cid)
    return check.evaluate


EVALUATORS = {cid: _register(cid) for cid in IDS}
