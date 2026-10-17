"""Signed Azure sw19 predicates over complete, authority-bound snapshot facts.

Enrichment contracts are documented in sw19-collector-requests.md. All checks
are offline: case/control observations are evidence, not configuration proxies.
"""
from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, azure_directory_join_authorized

SPECS = {'azure.cis.multifactor_auth_status_privileged_users': {'id': 'azure.cis.multifactor_auth_status_privileged_users',
                                                        'provider': 'azure',
                                                        'resource_kind': 'directory_user',
                                                        'data_source': 'Graph v1.0 paged /users, '
                                                                       '/identity/conditionalAccess/policies, '
                                                                       '/reports/authenticationMethods/userRegistrationDetails; '
                                                                       'paged directory and Azure RBAC role '
                                                                       'assignments, role definitions, PIM '
                                                                       'active schedules, transitive group '
                                                                       'membership; '
                                                                       '/policies/identitySecurityDefaultsEnforcementPolicy. '
                                                                       'Resolve named locations, '
                                                                       'authentication strengths, device '
                                                                       'filters and sign-in conditions. For '
                                                                       'CIS 1.1.2 exact legacy status, Graph '
                                                                       'beta GET '
                                                                       '/users/{id}/authentication/requirements '
                                                                       'returns perUserMfaState string; this '
                                                                       'beta API must be explicitly '
                                                                       'supported or that status is UNKNOWN.',
                                                        'predicate': 'Report per frozen requirement: for '
                                                                     'broad MFA requirements, every enabled '
                                                                     'user (including nonprivileged users '
                                                                     'and effective Azure resource writers) '
                                                                     'must have enforced MFA across '
                                                                     'applicable sign-in contexts after all '
                                                                     'policy conditions and exclusions are '
                                                                     'resolved. For CIS 1.1.2 status '
                                                                     'specifically, each privileged user '
                                                                     'must have perUserMfaState enabled or '
                                                                     'enforced; Conditional Access coverage '
                                                                     'alone does not make the legacy status '
                                                                     'Enabled. FAIL for a proven uncovered '
                                                                     'broad-scope context or explicitly '
                                                                     'disabled legacy status in that '
                                                                     'requirement. UNKNOWN for uncollected '
                                                                     'beta status, incomplete users, '
                                                                     'RBAC/PIM/groups, policy conditions or '
                                                                     'registration. Empty complete '
                                                                     'applicable scope is NOT_APPLICABLE.',
                                                        'severity': 'high',
                                                        'category': 'least_privilege',
                                                        'title': 'MFA covers all enabled users, including '
                                                                 'privileged and write access users',
                                                        'description': 'Checks effective MFA coverage for '
                                                                       'all enabled users, with explicit '
                                                                       'coverage of privileged and Azure '
                                                                       'resource writers.',
                                                        'remediation_hint': 'Require MFA for every in-scope '
                                                                            'user, including privileged and '
                                                                            'Azure resource writers; remove '
                                                                            'Conditional Access bypasses and '
                                                                            'verify effective coverage. '
                                                                            'Where the frozen CIS 1.1.2 '
                                                                            'legacy status is assessed, set '
                                                                            'and verify per-user MFA Enabled '
                                                                            'or Enforced for each privileged '
                                                                            'user under the '
                                                                            'organization-approved MFA '
                                                                            'approach.'},
 'azure_c5_iam_03_01as': {'id': 'azure_c5_iam_03_01as',
                          'provider': 'azure',
                          'resource_kind': 'directory_user',
                          'data_source': 'Graph v1.0 paged /identityProtection/riskyUsers (riskLevel, '
                                         'riskState, riskLastUpdatedDateTime) and relevant risk detections; '
                                         'authoritative identity inventory, compromised-credential case '
                                         'records, disabling time, reviewer decision and policy response '
                                         'deadline.',
                          'predicate': 'FAIL if a confirmed compromised identity remains enabled beyond the '
                                       'required response deadline or a measured case lacks authorized '
                                       'review. PASS only if every in-scope identity/case has monitoring '
                                       'coverage, compromised identities were disabled pending authorized '
                                       'review, and case records demonstrate the process. UNKNOWN if case '
                                       'coverage, all-identity inventory, deadline, review or disable '
                                       'evidence is incomplete. A fresh riskyUser timestamp alone never '
                                       'proves PASS.',
                          'severity': 'medium',
                          'category': 'hardening',
                          'title': 'Disable compromised identities pending authorized review',
                          'description': 'Check the monitored identity population and response records for '
                                         'compromised credentials.',
                          'remediation_hint': 'Document and operate compromised-credential monitoring for '
                                              'all responsible identities; disable confirmed compromised '
                                              'accounts pending authorized review.'},
 'azure_directory_user_7_2_1_19_28e2aa7': {'id': 'azure_directory_user_7_2_1_19_28e2aa7',
                                           'provider': 'azure',
                                           'resource_kind': 'directory_user',
                                           'data_source': 'Paged Graph /users, directory roleAssignments, '
                                                          'active and eligible PIM role assignment '
                                                          'instances/schedules; complete paged ARM '
                                                          'roleAssignments across tenant root/management '
                                                          'groups, subscriptions, resource groups and child '
                                                          'resource scopes; compare principalId to user.id '
                                                          'and resolve principal type.',
                                           'predicate': 'For every directory user, FAIL if any direct active '
                                                        'or eligible Entra directory role, PIM assignment, '
                                                        'or Azure RBAC role assignment at any applicable '
                                                        'scope targets that user ID. PASS only when complete '
                                                        'user, directory, PIM and ARM assignment inventories '
                                                        'across tenant and resource hierarchy prove no '
                                                        'direct grants. UNKNOWN if pages, hierarchy/scope '
                                                        'coverage, principal type or identity join is '
                                                        'incomplete. Group-granted roles are not direct user '
                                                        'assignments.',
                                           'severity': 'medium',
                                           'category': 'hardening',
                                           'title': 'Assign roles through approved groups',
                                           'description': 'Finds direct active or eligible directory, PIM or '
                                                          'Azure RBAC role grants to any directory user.',
                                           'remediation_hint': 'Replace direct user directory, PIM and Azure '
                                                               'RBAC assignments with approved group '
                                                               'assignments across all scopes.'},
 'azure_directory_user_7_2_4_2_7a90cfb': {'id': 'azure_directory_user_7_2_4_2_7a90cfb',
                                          'provider': 'azure',
                                          'resource_kind': 'directory_user',
                                          'data_source': 'Paged Graph v1.0 '
                                                         '/users?$select=id,accountEnabled,createdDateTime,signInActivity '
                                                         'with nullable lastSuccessfulSignInDateTime; '
                                                         'additional per-credential issuance and last '
                                                         'successful use evidence for password and active '
                                                         'access credentials; policy inactiveDays and scan '
                                                         'UTC time.',
                                          'predicate': 'For every enabled user and in-scope password or '
                                                       'active access credential, FAIL if a verified last '
                                                       'successful use is older than inactiveDays. PASS only '
                                                       'if complete per-credential evidence proves recent '
                                                       'use within the threshold. UNKNOWN for never-used '
                                                       'credentials without issuance time, missing/null '
                                                       'sign-in activity, noninteractive credential use not '
                                                       'measured by user signInActivity, missing '
                                                       'policy/clock or incomplete paging. Empty applicable '
                                                       'set is NOT_APPLICABLE.',
                                          'severity': 'medium',
                                          'category': 'identity',
                                          'title': 'Enabled Entra users with successful sign-ins are not '
                                                   'stale',
                                          'description': 'Reviews stale enabled Azure AD identities and '
                                                         'credentials using last successful sign-in as one '
                                                         'signal; credential-level use requires additional '
                                                         'evidence.',
                                          'remediation_hint': 'Investigate enabled accounts or credentials '
                                                              'with verified inactivity beyond inactiveDays; '
                                                              'disable or remove them after owner review.'},
 'azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9': {'id': 'azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9',
                                                                    'provider': 'azure',
                                                                    'resource_kind': 'directory_user',
                                                                    'data_source': 'Paged Graph v1.0 '
                                                                                   '/users?$select=id,accountEnabled; '
                                                                                   '/identity/conditionalAccess/policies; '
                                                                                   '/policies/identitySecurityDefaultsEnforcementPolicy; '
                                                                                   'transitive group '
                                                                                   'membership and '
                                                                                   'authentication-method '
                                                                                   'registration; sign-in '
                                                                                   'contexts required by '
                                                                                   'policy.',
                                                                    'predicate': 'For every enabled Entra '
                                                                                 'user and each '
                                                                                 'policy-required sign-in '
                                                                                 'context, PASS only if '
                                                                                 'complete effective enabled '
                                                                                 'policy evidence requires '
                                                                                 'MFA, resolving exclusions, '
                                                                                 'application/client/location/device/risk '
                                                                                 'conditions, groups and '
                                                                                 'authentication strengths. '
                                                                                 'FAIL when complete '
                                                                                 'evidence proves a '
                                                                                 'user/context without MFA. '
                                                                                 'UNKNOWN if context, '
                                                                                 'policy, membership, '
                                                                                 'registration or inventory '
                                                                                 'is incomplete; enabled '
                                                                                 'security defaults alone '
                                                                                 'does not prove every '
                                                                                 'sign-in has MFA.',
                                                                    'severity': 'high',
                                                                    'category': 'least_privilege',
                                                                    'title': 'Enabled Entra users are '
                                                                             'covered by MFA',
                                                                    'description': 'Checks effective MFA '
                                                                                   'coverage for every '
                                                                                   'enabled Entra user '
                                                                                   'across policy-required '
                                                                                   'sign-in contexts.',
                                                                    'remediation_hint': 'In Entra admin '
                                                                                        'center > Protection '
                                                                                        '> Conditional '
                                                                                        'Access, cover every '
                                                                                        'enabled user and '
                                                                                        'required app/client '
                                                                                        'context with '
                                                                                        'enforced MFA; '
                                                                                        'resolve bypass '
                                                                                        'exclusions and '
                                                                                        'verify '
                                                                                        'registration.'},
 'azure_directory_user_entra_privileged_user_has_mfa_6f6d584': {'id': 'azure_directory_user_entra_privileged_user_has_mfa_6f6d584',
                                                                'provider': 'azure',
                                                                'resource_kind': 'directory_user',
                                                                'data_source': 'Microsoft Graph '
                                                                               '/roleManagement/directory/roleAssignments, '
                                                                               '/users, '
                                                                               '/identity/conditionalAccess/policies, '
                                                                               '/policies/identitySecurityDefaultsEnforcementPolicy: '
                                                                               'principalId,roleDefinitionId,accountEnabled,state,conditions,grantControls,isEnabled',
                                                                'predicate': 'For every enabled effective '
                                                                             'Global Administrator, PASS '
                                                                             'only if security defaults are '
                                                                             'confirmed applicable or '
                                                                             'enforced Conditional Access '
                                                                             'requires MFA for Azure console '
                                                                             'sign-in after all relevant '
                                                                             'user/group, cloud-app, '
                                                                             'client-app, location, device, '
                                                                             'risk and authentication-flow '
                                                                             'conditions and exclusions are '
                                                                             'evaluated. FAIL when an '
                                                                             'enabled administrator has a '
                                                                             'demonstrably uncovered console '
                                                                             'sign-in path. UNKNOWN for '
                                                                             'role-group/PIM activation '
                                                                             'ambiguity, conditional grant '
                                                                             'alternatives, security-default '
                                                                             'applicability or incomplete '
                                                                             'Graph inventory.',
                                                                'severity': 'high',
                                                                'category': 'least_privilege',
                                                                'title': 'Require MFA for Global '
                                                                         'Administrators',
                                                                'description': 'Require MFA for Global '
                                                                               'Administrators. A finding is '
                                                                               'raised when an enabled '
                                                                               'Global Administrator has no '
                                                                               'effective MFA Conditional '
                                                                               'Access coverage and security '
                                                                               'defaults are disabled.',
                                                                'remediation_hint': 'Azure portal > Entra ID '
                                                                                    '> Protection > '
                                                                                    'Conditional Access: '
                                                                                    'require MFA for Global '
                                                                                    'Administrators across '
                                                                                    'relevant apps and '
                                                                                    'flows; remove bypassing '
                                                                                    'exclusions or enable '
                                                                                    'security defaults where '
                                                                                    'appropriate.'},
 'azure_frontdoor_1_2_5_4_ccc7b8f': {'id': 'azure_frontdoor_1_2_5_4_ccc7b8f',
                                     'provider': 'azure',
                                     'resource_kind': 'frontdoor_and_cdn_endpoint',
                                     'data_source': 'Enumerate classic Front Door frontend endpoints from '
                                                    'Microsoft.Network/frontDoors GET (2019-05-01 schema) '
                                                    'and classic CDN profile/endpoint/customDomain lists '
                                                    'with paging. Front Door: '
                                                    'properties.frontendEndpoints[].properties.customHttpsProvisioningState, '
                                                    'customHttpsConfiguration.certificateSource and '
                                                    'protocolType. CDN: each custom domain '
                                                    'properties.customHttpsProvisioningState, '
                                                    'customHttpsParameters.certificateSource and '
                                                    'protocolType. Do not infer SNI from certificate type.',
                                     'predicate': 'For each applicable classic Front Door frontend endpoint '
                                                  'or classic CDN custom HTTPS domain, PASS only when '
                                                  'customHttpsProvisioningState=Enabled, the active '
                                                  'certificate source is AzureKeyVault, and SNI is '
                                                  'explicitly selected (Front Door '
                                                  'customHttpsConfiguration.protocolType=ServerNameIndication; '
                                                  'CDN '
                                                  'customHttpsParameters.protocolType=ServerNameIndication). '
                                                  'FAIL when complete settings show HTTPS Disabled/Failed, '
                                                  'FrontDoor/Cdn-managed certificate, or CDN IPBased TLS. '
                                                  'UNKNOWN for missing/transitional fields, Standard/Premium '
                                                  'profiles where equivalent SNI semantics are not exposed, '
                                                  'or incomplete endpoint/domain paging. No applicable '
                                                  'endpoints is NOT_APPLICABLE.',
                                     'severity': 'medium',
                                     'category': 'encryption',
                                     'title': 'Use SNI for classic Front Door and CDN custom HTTPS',
                                     'description': 'Checks documented TLS extension mode only where the '
                                                    'provider exposes an SNI setting.',
                                     'remediation_hint': 'Configure a customer-managed certificate and SNI '
                                                         'on each applicable classic Front Door or CDN '
                                                         'custom HTTPS endpoint; resolve Standard/Premium '
                                                         'TLS capability separately.'},
 'azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9': {'id': 'azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9',
                                                                    'provider': 'azure',
                                                                    'resource_kind': 'frontdoor_and_cdn_endpoint',
                                                                    'data_source': 'Paged Classic Front Door '
                                                                                   'GET 2021-06-01 '
                                                                                   'routingRules; paged '
                                                                                   'Microsoft.Cdn profiles, '
                                                                                   'endpoints/customDomains '
                                                                                   'and afdEndpoints/routes '
                                                                                   'GET 2024-02-01; inspect '
                                                                                   'classic '
                                                                                   'acceptedProtocols/routeConfiguration, '
                                                                                   'AFD '
                                                                                   'supportedProtocols/httpsRedirect, '
                                                                                   'and CDN '
                                                                                   'endpoint/custom-domain '
                                                                                   'HTTPS/protocol or '
                                                                                   'rules-engine redirect '
                                                                                   'configuration for each '
                                                                                   'SKU.',
                                                                    'predicate': 'For every Azure Front Door '
                                                                                 'and Azure CDN public route '
                                                                                 'or custom domain, PASS if '
                                                                                 'it is HTTPS-only or each '
                                                                                 'accepted HTTP request is '
                                                                                 'effectively redirected to '
                                                                                 'HTTPS. FAIL when a fully '
                                                                                 'resolved route accepts '
                                                                                 'HTTP and can serve or '
                                                                                 'forward it without HTTPS '
                                                                                 'redirect. UNKNOWN for '
                                                                                 'unresolved CDN '
                                                                                 'SKU/rules-engine behavior, '
                                                                                 'protocol setting, '
                                                                                 'route/custom-domain '
                                                                                 'association or incomplete '
                                                                                 'profile/endpoint/route '
                                                                                 'paging.',
                                                                    'severity': 'medium',
                                                                    'category': 'hardening',
                                                                    'title': 'Front Door HTTP routes '
                                                                             'redirect to HTTPS',
                                                                    'description': 'Checks HTTP-capable '
                                                                                   'classic Front Door and '
                                                                                   'Azure Front Door '
                                                                                   'Standard/Premium routes '
                                                                                   'for HTTPS redirection.',
                                                                    'remediation_hint': 'On each Front Door '
                                                                                        'or CDN endpoint, '
                                                                                        'route and custom '
                                                                                        'domain, require '
                                                                                        'HTTPS-only access '
                                                                                        'or configure an '
                                                                                        'effective '
                                                                                        'HTTP-to-HTTPS '
                                                                                        'redirect; verify '
                                                                                        'all HTTP-capable '
                                                                                        'paths.'},
 'azure_frontdoor_app_minimum_tls_version_12_0512053': {'id': 'azure_frontdoor_app_minimum_tls_version_12_0512053',
                                                        'provider': 'azure',
                                                        'resource_kind': 'frontdoor_and_cdn_endpoint',
                                                        'data_source': 'Collect both resource families with '
                                                                       'complete pagination: classic '
                                                                       'Microsoft.Network/frontDoors '
                                                                       'frontendEndpoints[].properties.customHttpsConfiguration.minimumTlsVersion; '
                                                                       'CDN '
                                                                       'Microsoft.Cdn/profiles/endpoints/customDomains '
                                                                       'GET '
                                                                       'properties.customHttpsParameters.minimumTlsVersion '
                                                                       '(enum None/TLS10/TLS12); AFD '
                                                                       'Standard/Premium '
                                                                       'Microsoft.Cdn/profiles/customDomains '
                                                                       'GET '
                                                                       'properties.tlsSettings.cipherSuiteSetType '
                                                                       'and minimumTlsVersion '
                                                                       '(TLS10/TLS12/TLS13 for Customized). '
                                                                       'Resolve HTTPS enablement, custom '
                                                                       'domain deployment, and the effective '
                                                                       'minimum for AFD preset cipher suites '
                                                                       'separately.',
                                                        'predicate': 'For every applicable HTTPS classic '
                                                                     'Front Door frontend, CDN endpoint '
                                                                     'custom domain, and AFD '
                                                                     'Standard/Premium custom domain, '
                                                                     'compare its effective minimum TLS '
                                                                     'version with 1.2 using the correct '
                                                                     'resource-specific field and enum. AFD '
                                                                     'preset cipherSuiteSetType can '
                                                                     'determine the effective minimum even '
                                                                     'when minimumTlsVersion is omitted; do '
                                                                     'not pass on that field alone. FAIL for '
                                                                     'a proven effective minimum below 1.2; '
                                                                     'PASS only with complete domain '
                                                                     'inventory, HTTPS applicability and '
                                                                     'effective TLS evidence for every '
                                                                     'domain. UNKNOWN for unresolved HTTPS '
                                                                     'state, absent or unrecognized '
                                                                     'settings/preset, incomplete '
                                                                     'deployment, API generation or paging. '
                                                                     'No applicable HTTPS domains is '
                                                                     'NOT_APPLICABLE.',
                                                        'severity': 'medium',
                                                        'category': 'encryption',
                                                        'title': 'Front Door and CDN custom domains require '
                                                                 'TLS 1.2 or later',
                                                        'description': 'Checks minimum TLS on the actual '
                                                                       'HTTPS frontend or custom domain.',
                                                        'remediation_hint': 'In Front Door/CDN > Domains, '
                                                                            'open each HTTPS domain and set '
                                                                            'its minimum TLS version to TLS '
                                                                            '1.2 or newer.'},
 'azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a': {'id': 'azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a',
                                                                                   'provider': 'azure',
                                                                                   'resource_kind': 'frontdoor_and_cdn_endpoint',
                                                                                   'data_source': 'ARM '
                                                                                                  'Microsoft.Insights/diagnosticSettings '
                                                                                                  'LIST '
                                                                                                  '2021-05-01-preview '
                                                                                                  'at '
                                                                                                  'Microsoft.Network/frontDoors '
                                                                                                  'and '
                                                                                                  'Microsoft.Cdn/profiles '
                                                                                                  'IDs: '
                                                                                                  'properties.logs[].category/categoryGroup, '
                                                                                                  'enabled '
                                                                                                  'and '
                                                                                                  'setting-level '
                                                                                                  'properties.workspaceId/storageAccountId. '
                                                                                                  'Discover '
                                                                                                  'supported '
                                                                                                  'categories '
                                                                                                  'for each '
                                                                                                  'resource '
                                                                                                  'with '
                                                                                                  'diagnosticSettingsCategories '
                                                                                                  'LIST; '
                                                                                                  'expand '
                                                                                                  'allLogs '
                                                                                                  'groups.',
                                                                                   'predicate': 'For every '
                                                                                                'classic '
                                                                                                'Front Door '
                                                                                                'and '
                                                                                                'CDN/Front '
                                                                                                'Door '
                                                                                                'profile, '
                                                                                                'require an '
                                                                                                'enabled '
                                                                                                'diagnostic '
                                                                                                'setting '
                                                                                                'whose '
                                                                                                'explicit '
                                                                                                'category or '
                                                                                                'expanded '
                                                                                                'categoryGroup '
                                                                                                'includes '
                                                                                                'the '
                                                                                                'access-log '
                                                                                                'category '
                                                                                                'supported '
                                                                                                'by that '
                                                                                                'exact '
                                                                                                'resource '
                                                                                                'type and '
                                                                                                'whose '
                                                                                                'setting-level '
                                                                                                'workspaceId '
                                                                                                'or '
                                                                                                'storageAccountId '
                                                                                                'is present. '
                                                                                                'Use '
                                                                                                'FrontdoorAccessLog '
                                                                                                'for '
                                                                                                'Microsoft.Network/frontDoors; '
                                                                                                'discover '
                                                                                                'FrontDoorAccessLog '
                                                                                                'or '
                                                                                                'AzureCdnAccessLog '
                                                                                                'for '
                                                                                                'Microsoft.Cdn/profiles. '
                                                                                                'FAIL after '
                                                                                                'complete '
                                                                                                'inventory '
                                                                                                'if no '
                                                                                                'qualifying '
                                                                                                'route; '
                                                                                                'UNKNOWN for '
                                                                                                'unresolved '
                                                                                                'category-group '
                                                                                                'membership, '
                                                                                                'category '
                                                                                                'discovery, '
                                                                                                'destination '
                                                                                                'or list '
                                                                                                'pages.',
                                                                                   'severity': 'medium',
                                                                                   'category': 'logging',
                                                                                   'title': 'Export Front '
                                                                                            'Door and CDN '
                                                                                            'access logs',
                                                                                   'description': 'Export '
                                                                                                  'Front '
                                                                                                  'Door and '
                                                                                                  'CDN '
                                                                                                  'access '
                                                                                                  'logs. A '
                                                                                                  'finding '
                                                                                                  'is raised '
                                                                                                  'when any '
                                                                                                  'Front '
                                                                                                  'Door or '
                                                                                                  'CDN '
                                                                                                  'profile '
                                                                                                  'lacks an '
                                                                                                  'enabled '
                                                                                                  'access-log '
                                                                                                  'category '
                                                                                                  'routed to '
                                                                                                  'workspace '
                                                                                                  'or '
                                                                                                  'storage.',
                                                                                   'remediation_hint': 'In '
                                                                                                       'each '
                                                                                                       'Front '
                                                                                                       'Door '
                                                                                                       'or '
                                                                                                       'CDN '
                                                                                                       'profile '
                                                                                                       '> '
                                                                                                       'Diagnostic '
                                                                                                       'settings, '
                                                                                                       'enable '
                                                                                                       'its '
                                                                                                       'offered '
                                                                                                       'access-log '
                                                                                                       'category '
                                                                                                       'and '
                                                                                                       'send '
                                                                                                       'it '
                                                                                                       'to a '
                                                                                                       'Log '
                                                                                                       'Analytics '
                                                                                                       'workspace '
                                                                                                       'or '
                                                                                                       'storage '
                                                                                                       'account.'},
 'azure_frontdoor_network_http_internet_access_restricted_7004685': {'id': 'azure_frontdoor_network_http_internet_access_restricted_7004685',
                                                                     'provider': 'azure',
                                                                     'resource_kind': 'frontdoor_and_cdn_endpoint',
                                                                     'data_source': 'Paged classic Front '
                                                                                    'Door routing rules and '
                                                                                    'AFD routes with '
                                                                                    'effective rule-set '
                                                                                    'forwarding overrides; '
                                                                                    'enumerate Microsoft.Cdn '
                                                                                    'classic '
                                                                                    'profiles/endpoints/origins '
                                                                                    'for scope. Classic CDN '
                                                                                    'endpoint GET exposes '
                                                                                    'isHttpAllowed/isHttpsAllowed '
                                                                                    'and origin ports but '
                                                                                    'does not expose a '
                                                                                    'universal '
                                                                                    'origin-protocol policy; '
                                                                                    'require '
                                                                                    'provider-specific '
                                                                                    'configuration or '
                                                                                    'traffic evidence before '
                                                                                    'judging its origin '
                                                                                    'protocol. Resolve each '
                                                                                    'enabled route/endpoint '
                                                                                    'with a custom origin '
                                                                                    'and all effective '
                                                                                    'origin-request paths.',
                                                                     'predicate': 'For every enabled Front '
                                                                                  'Door route to a custom '
                                                                                  'origin, PASS only when '
                                                                                  'every effective request '
                                                                                  'path forwards to the '
                                                                                  'origin over HTTPS: '
                                                                                  'HttpsOnly passes even if '
                                                                                  'client HTTP is accepted; '
                                                                                  'MatchRequest passes only '
                                                                                  'if all accepted client '
                                                                                  'paths are HTTPS or HTTP '
                                                                                  'is redirected before '
                                                                                  'forwarding. FAIL for an '
                                                                                  'effective HttpOnly origin '
                                                                                  'path or MatchRequest path '
                                                                                  'that forwards accepted '
                                                                                  'HTTP to the origin. For '
                                                                                  'classic CDN endpoints, '
                                                                                  'return UNKNOWN unless '
                                                                                  'provider-specific '
                                                                                  'origin-protocol '
                                                                                  'configuration or observed '
                                                                                  'origin traffic proves the '
                                                                                  'same condition; '
                                                                                  'isHttpAllowed/isHttpsAllowed '
                                                                                  'and origin ports alone do '
                                                                                  'not prove the origin '
                                                                                  'protocol. UNKNOWN also '
                                                                                  'for unresolved overrides, '
                                                                                  'origin policy, or '
                                                                                  'incomplete pages. '
                                                                                  'Disabled routes are '
                                                                                  'outside scope. A complete '
                                                                                  'inventory with no '
                                                                                  'applicable custom origins '
                                                                                  'is NOT_APPLICABLE.',
                                                                     'severity': 'medium',
                                                                     'category': 'network',
                                                                     'title': 'Front Door routes enforce '
                                                                              'HTTPS for clients and origins',
                                                                     'description': 'Checks both client HTTP '
                                                                                    'redirect and HTTPS-only '
                                                                                    'forwarding to origins.',
                                                                     'remediation_hint': 'Azure portal > '
                                                                                         'Front Door > '
                                                                                         'Routes: enable '
                                                                                         'HTTPS redirect, '
                                                                                         'restrict accepted '
                                                                                         'client protocols '
                                                                                         'where possible, '
                                                                                         'and set origin '
                                                                                         'forwarding '
                                                                                         'protocol to HTTPS '
                                                                                         'only.'},
 'azure.gap.monitor_log_analytics_workspace_integrated_with_encrypted_storage_account': {'id': 'azure.gap.monitor_log_analytics_workspace_integrated_with_encrypted_storage_account',
                                                                                         'provider': 'azure',
                                                                                         'resource_kind': 'log_analytics_workspace',
                                                                                         'data_source': 'ARM '
                                                                                                        'read-only '
                                                                                                        'Microsoft.OperationalInsights/workspaces/linkedStorageAccounts/Query '
                                                                                                        'GET: '
                                                                                                        'properties.storageAccountIds[]; '
                                                                                                        'ARM '
                                                                                                        'GET '
                                                                                                        'Microsoft.Storage/storageAccounts '
                                                                                                        'for '
                                                                                                        'each '
                                                                                                        'linked '
                                                                                                        'ID: '
                                                                                                        'properties.encryption.keySource,keyVaultProperties; '
                                                                                                        'collected '
                                                                                                        'log_analytics_workspace.items[].id '
                                                                                                        'supplies '
                                                                                                        'workspace '
                                                                                                        'scope.',
                                                                                         'predicate': 'For '
                                                                                                      'each '
                                                                                                      'policy-required '
                                                                                                      'workspace, '
                                                                                                      'PASS '
                                                                                                      'only '
                                                                                                      'if '
                                                                                                      'the '
                                                                                                      'Query '
                                                                                                      'linkedStorageAccounts '
                                                                                                      'child '
                                                                                                      'GET '
                                                                                                      'returns '
                                                                                                      'at '
                                                                                                      'least '
                                                                                                      'one '
                                                                                                      'storageAccountId '
                                                                                                      'and '
                                                                                                      'every '
                                                                                                      'uniquely '
                                                                                                      'resolved '
                                                                                                      'account '
                                                                                                      'has '
                                                                                                      'properties.encryption.keySource=Microsoft.Keyvault, '
                                                                                                      'a '
                                                                                                      'complete '
                                                                                                      'keyVaultProperties '
                                                                                                      'key '
                                                                                                      'reference, '
                                                                                                      'and '
                                                                                                      'proven '
                                                                                                      'usable '
                                                                                                      'CMK '
                                                                                                      'access. '
                                                                                                      'FAIL '
                                                                                                      'for a '
                                                                                                      'complete '
                                                                                                      'absent '
                                                                                                      'Query '
                                                                                                      'link '
                                                                                                      'or an '
                                                                                                      'explicit '
                                                                                                      'Microsoft.Storage '
                                                                                                      'key '
                                                                                                      'source. '
                                                                                                      'UNKNOWN '
                                                                                                      'for '
                                                                                                      'missing '
                                                                                                      'workspace '
                                                                                                      'policy, '
                                                                                                      'ambiguous '
                                                                                                      'account '
                                                                                                      'ID, '
                                                                                                      'unreadable '
                                                                                                      'key, '
                                                                                                      'key '
                                                                                                      'access '
                                                                                                      'or '
                                                                                                      'inventory. '
                                                                                                      'A '
                                                                                                      'storage '
                                                                                                      'account '
                                                                                                      'CMK '
                                                                                                      'without '
                                                                                                      'the '
                                                                                                      'Query '
                                                                                                      'link '
                                                                                                      'is '
                                                                                                      'insufficient.',
                                                                                         'severity': 'medium',
                                                                                         'category': 'encryption',
                                                                                         'title': 'Required '
                                                                                                  'Log '
                                                                                                  'Analytics '
                                                                                                  'Query '
                                                                                                  'linked '
                                                                                                  'storage '
                                                                                                  'uses '
                                                                                                  'customer '
                                                                                                  'keys',
                                                                                         'description': 'Checks '
                                                                                                        'policy-required '
                                                                                                        'Query '
                                                                                                        'linked '
                                                                                                        'storage '
                                                                                                        'accounts '
                                                                                                        'and '
                                                                                                        'their '
                                                                                                        'Key '
                                                                                                        'Vault '
                                                                                                        'customer-managed '
                                                                                                        'encryption '
                                                                                                        'configuration.',
                                                                                         'remediation_hint': 'In '
                                                                                                             'Log '
                                                                                                             'Analytics '
                                                                                                             'workspace '
                                                                                                             '> '
                                                                                                             'Linked '
                                                                                                             'storage '
                                                                                                             'accounts, '
                                                                                                             'link '
                                                                                                             'the '
                                                                                                             'approved '
                                                                                                             'storage '
                                                                                                             'account '
                                                                                                             'for '
                                                                                                             'Query; '
                                                                                                             'in '
                                                                                                             'its '
                                                                                                             'Encryption '
                                                                                                             'settings '
                                                                                                             'select '
                                                                                                             'a '
                                                                                                             'Key '
                                                                                                             'Vault '
                                                                                                             'customer-managed '
                                                                                                             'key.'},
 'azure.other.log_expiry_query': {'id': 'azure.other.log_expiry_query',
                                  'provider': 'azure',
                                  'resource_kind': 'log_analytics_workspace',
                                  'data_source': 'Paged Log Analytics workspace and table retention policy '
                                                 'GET 2023-09-01 plus Azure Monitor Logs query API. Policy '
                                                 'input is the organization retention days and scoped '
                                                 'tables; query all retained tiers/time ranges for rows with '
                                                 'TimeGenerated earlier than now minus policy days.',
                                  'predicate': 'For each policy-scoped table, query the entire accessible '
                                               'time range for any event older than the organization '
                                               'retention limit, including archive/search tiers if '
                                               'queryable. FAIL if any expired event is returned. PASS if '
                                               'every complete bounded query proves zero expired events and '
                                               'all scoped tables are measured. UNKNOWN for empty/unprovided '
                                               'table policy, query/truncation limits, partial time range, '
                                               'permissions or inaccessible tiers. The effective Azure '
                                               'retention setting does not replace the policy threshold.',
                                  'severity': 'medium',
                                  'category': 'logging',
                                  'title': 'Expired log events are not queryable',
                                  'description': 'Tests whether Azure Monitor Logs still returns records '
                                                 'beyond the configured table retention cutoff.',
                                  'remediation_hint': 'Set workspace and per-table retention to the '
                                                      'organization limit, purge or expire older queryable '
                                                      'events, and rerun complete time-range queries.'},
 'azure_c5_ops_17_02ac': {'id': 'azure_c5_ops_17_02ac',
                          'provider': 'azure',
                          'resource_kind': 'log_analytics_workspace',
                          'data_source': 'Microsoft.OperationalInsights/workspaces GET: '
                                         'properties.publicNetworkAccessForIngestion, '
                                         'properties.publicNetworkAccessForQuery, properties.retentionInDays',
                          'predicate': 'For the full OPS-17.02AC requirement, PASS only with direct evidence '
                                       'of documented and implemented confidentiality, integrity, '
                                       'availability, access and recovery controls for logs and '
                                       'infrastructure. FAIL only on a directly demonstrated violation of '
                                       'those required measures. Otherwise UNKNOWN, including when '
                                       'publicNetworkAccessForIngestion/Query is Enabled or retentionInDays '
                                       'is short; these are configuration signals to investigate, not by '
                                       'themselves a full C5 verdict. Missing inventory, policy, or '
                                       'unsupported enum is UNKNOWN.',
                          'severity': 'medium',
                          'category': 'hardening',
                          'title': 'Log Analytics workspaces restrict public access and meet default '
                                   'retention minimum',
                          'description': 'Checks public query and ingestion switches and default workspace '
                                         'retention against the approved minimum.',
                          'remediation_hint': 'Disable public ingestion/query and set required retention in '
                                              'Log Analytics workspace; document and verify log access '
                                              'control, integrity protection and recovery measures.'},
 'azure_vault_10_3_2_3_922adc4': {'id': 'azure_vault_10_3_2_3_922adc4',
                                  'provider': 'azure',
                                  'resource_kind': 'log_analytics_workspace',
                                  'data_source': 'Existing log_analytics_workspace; add paged clusters list '
                                                 'plus GET. Microsoft.OperationalInsights/workspaces GET '
                                                 '2023-09-01: properties.features.clusterResourceId; '
                                                 'Microsoft.OperationalInsights/clusters GET 2023-09-01: '
                                                 'properties.keyVaultProperties.keyVaultUri,keyName,keyVersion; '
                                                 'policy approvedKeyVaultKeyIds',
                                  'predicate': 'For every scoped Log Analytics workspace, resolve '
                                               'properties.features.clusterResourceId to a dedicated cluster '
                                               'and form the full Key Vault key ID from keyVaultUri, keyName '
                                               'and keyVersion when pinned. PASS only if cluster encryption '
                                               'is provisioned and active, the key ID matches '
                                               'approvedKeyVaultKeyIds, and key availability/access for the '
                                               'cluster identity are verified. FAIL if complete evidence '
                                               'proves no cluster link, no CMK or an unapproved key. UNKNOWN '
                                               'for missing approval policy, unresolved '
                                               'cluster/key/identity/access, provisioning state or '
                                               'incomplete workspace/cluster inventory. A complete empty '
                                               'workspace inventory is NOT_APPLICABLE.',
                                  'severity': 'medium',
                                  'category': 'encryption',
                                  'title': 'Log Analytics workspaces use an approved cluster CMK',
                                  'description': 'Checks every scoped Log Analytics workspace for active '
                                                 'customer-managed key encryption through a linked cluster.',
                                  'remediation_hint': 'Azure portal > Log Analytics workspaces > Linked '
                                                      'cluster: For each workspace, link an approved '
                                                      'dedicated Log Analytics cluster, set its Key Vault '
                                                      'CMK and grant its managed identity key access.'}}

SPEC_SHA256 = {'azure.cis.multifactor_auth_status_privileged_users': '3a6b92dabadfe11d091fcc059c740fb10f482b8417488a952de0bc1f711b7013',
 'azure.gap.monitor_log_analytics_workspace_integrated_with_encrypted_storage_account': '7371a4102c11dd5fae3b68719f42d042abc8268288dec12dc5f45303942856b6',
 'azure.other.log_expiry_query': '673ff70298060d1461dd878946f5aecd3f8b00f2197ce39a8dc4478212658918',
 'azure_c5_iam_03_01as': '58bdc3197648fba24ca1953b8ceeaa714ff824854baa08a3c9c34432455f9b46',
 'azure_c5_ops_17_02ac': 'cfbe642710b791d13b6b25d629981bb80612ed93f9b5e08de02dd107f6dfed1c',
 'azure_directory_user_7_2_1_19_28e2aa7': '9a2f2882ce2c68669d523c582ae39efc5d73824e7e5cefcd7c9f6438258d00c4',
 'azure_directory_user_7_2_4_2_7a90cfb': '742c36ee8dfd3820a42676c002b194f11680bbc291ca8829967c4e01a366ec66',
 'azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9': '677c8ed3bfcd9c546bc9b9c15bf58ad8e3cbe526a472ed3a16e1d497bfaa4450',
 'azure_directory_user_entra_privileged_user_has_mfa_6f6d584': '2daa5baab00c3782190a08282701c232e1c0ee696ad911a7edf7774f8b04a02b',
 'azure_frontdoor_1_2_5_4_ccc7b8f': 'ee4e1b84ae8ce3f12cef3abb083480982c9310d8e182972bf1e010ebcb1ab68f',
 'azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9': 'e9c31a1bbb9c352ff6ea5685f486db1d3507d13018be2084c6107c4438fd69a9',
 'azure_frontdoor_app_minimum_tls_version_12_0512053': 'b0e045007682e659a9efa140427f13327ef1866bec0167fb18e3385c48f3c643',
 'azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a': '383f151c78d720d3a36b6357a637bc999ad0caed3b93a8afd62380c13f4147cf',
 'azure_frontdoor_network_http_internet_access_restricted_7004685': 'b6200afecf3e350c8d50eb881ccb9201ed9531b06244844ae5e82f7480ec33d9',
 'azure_vault_10_3_2_3_922adc4': '499279c044de1f95ca921b2043a341fc97c86b5717ff7334d5a17d685d815e97'}

IDS = tuple(SPECS)
CIS_MFA, COMPROMISED, DIRECT, STALE, ALL_MFA, ADMIN_MFA, SNI, REDIRECT, TLS, ACCESS_LOG, ORIGIN, QUERY_CMK, EXPIRY, C5_LOGS, CLUSTER_CMK = IDS
_ARM = re.compile(r'/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+', re.I)
_KINDS = {'log_analytics_workspace': 'Microsoft.OperationalInsights/workspaces',
          'log_analytics_cluster': 'Microsoft.OperationalInsights/clusters',
          'storage_account': 'Microsoft.Storage/storageAccounts'}
_GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10'
_RESOLVED = ('users', 'groups', 'roles', 'applications', 'clientApps', 'locations',
             'devices', 'risks', 'authenticationFlows', 'authenticationStrengths', 'exclusions')


def _require(value, message):
    if not value:
        raise Unavailable(message)


def _instant(value):
    _require(isinstance(value, str), 'timestamp missing')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Unavailable('timestamp malformed') from exc
    _require(parsed.utcoffset() is not None, 'timestamp lacks timezone')
    return parsed.astimezone(timezone.utc)


def _now(index):
    return _instant(get(index, 'context.created_at', str))


def _context(index):
    context = get(index, 'context', dict)
    _require(get(context, 'provider', str) == 'azure', 'foreign provider')
    scope = get(context, 'scope', str)
    _require(re.fullmatch(r'/(subscriptions|tenants)/[^/?#]+', scope, re.I), 'invalid Azure scope')
    return context, scope


def _inventory(index, kind, *, directory=False):
    context, scope = _context(index)
    envelopes = get(index, 'collections', dict).get(kind)
    _require(isinstance(envelopes, list) and len(envelopes) == 1, 'missing or ambiguous collection: ' + kind)
    envelope = envelopes[0]
    _require(get(envelope, 'type', str) == kind, 'foreign collection kind')
    actual = get(envelope, 'scope', str)
    if directory:
        metadata = get(context, 'metadata', dict)
        tenant = get(metadata, 'tenant_id', str)
        _require(get(metadata, 'tenant_verified', bool), 'unverified tenant')
        _require(actual.casefold() == ('/tenants/' + tenant).casefold(), 'foreign directory collection')
        if scope.casefold().startswith('/subscriptions/'):
            _require(azure_directory_join_authorized(scope, metadata, envelope), 'unbound directory capture')
        else:
            _require(actual.casefold() == scope.casefold(), 'foreign tenant context')
        proof = get(envelope, '_provenance', dict)
        _require(get(proof, 'tenant_verified', bool) and get(proof, 'tenant_id', str).casefold() == tenant.casefold(), 'foreign tenant proof')
        for key in ('credential_context_id', 'customer_context_id'):
            _require(get(proof, key, str) == get(metadata, key, str) and bool(proof[key]), 'foreign directory capture')
    else:
        _require(actual.casefold() == scope.casefold(), 'foreign ARM collection')
    rows = complete_items(index, kind)
    declared = list_of_objects(get(envelope, 'items', list))
    _require(rows == declared and (get(envelope, 'status', str) == 'empty') == (not rows), 'collection count or body mismatch')
    wrappers = list_of_objects(get(index, kind, list))
    seen = set()
    for wrapper, row in zip(wrappers, rows):
        _require(get(wrapper, 'type', str) == kind and get(wrapper, 'scope', str).casefold() == actual.casefold(), 'foreign resource wrapper')
        rid = get(row, 'id', str)
        _require(rid and rid.casefold() not in seen, 'empty or duplicate resource identity')
        seen.add(rid.casefold())
        if directory:
            _require(re.fullmatch(r'[A-Za-z0-9-]+', rid), 'malformed directory identity')
            proof = get(row, '_provenance', dict)
            _require(get(proof, 'tenant_verified', bool) and get(proof, 'tenant_id', str).casefold() == tenant.casefold(), 'foreign directory row')
            _require(get(proof, 'read_only', bool), 'directory source not read-only')
            for key in ('credential_context_id', 'customer_context_id'):
                _require(get(proof, key, str) == metadata[key], 'foreign row capture')
        else:
            _require(_ARM.fullmatch(rid) and rid.casefold().startswith(scope.casefold() + '/'), 'foreign or malformed ARM identity')
            native = get(row, 'type', str)
            expected = _KINDS.get(kind)
            _require(native.casefold() == expected.casefold() if expected else native.casefold() in ('microsoft.network/frontdoors', 'microsoft.cdn/profiles'), 'foreign native type')
            _require('/providers/' + native.casefold() + '/' in rid.casefold(), 'native type and ID mismatch')
    return rows


def _subject(item, index, kind, *, directory=False):
    rows = _inventory(index, kind, directory=directory)
    _require(sum(row == item for row in rows) == 1, 'subject absent or differs from authoritative fact')


def _policy(item, index, check_id):
    _, scope = _context(index)
    policy = get(index, 'context.metadata.compliance_policy.sw19', dict)
    _require(get(policy, 'scope', str).casefold() == scope.casefold() and get(policy, 'status', str) == 'collected', 'policy absent or foreign')
    # Check IDs are literal keys, some containing periods; get() paths split periods.
    _require(check_id in policy, 'check policy missing')
    selected = {'entry': policy[check_id]}
    if check_id in policy.get('_coverage', {}):
        selected['_coverage'] = {'entry': policy['_coverage'][check_id]}
    entry = get(selected, 'entry', dict)
    if 'resources' in entry:
        resources = get(entry, 'resources', dict)
        matches = [value for rid, value in resources.items() if isinstance(rid, str) and rid.casefold() == get(item, 'id', str).casefold()]
        _require(len(matches) == 1, 'resource policy absent or ambiguous')
        entry = get({'entry': matches[0]}, 'entry', dict)
    _require(get(entry, 'resource_id', str).casefold() == get(item, 'id', str).casefold(), 'policy target differs')
    return entry


def _evidence(item, field):
    _require(get(item, '_coverage.' + field + '.status', str) == 'collected', 'evidence unavailable: ' + field)
    value = get(item, field, dict)
    _require(get(value, 'parent_id', str).casefold() == get(item, 'id', str).casefold(), 'foreign evidence parent')
    return value


def _children(item, field):
    state = get(item, '_coverage.' + field + '.status', str)
    _require(state in ('collected', 'empty'), 'child inventory incomplete: ' + field)
    rows = list_of_objects(get(item, field, list))
    _require((state == 'empty') == (not rows), 'child coverage count mismatch: ' + field)
    seen = set()
    parent = get(item, 'id', str)
    for row in rows:
        rid = get(row, 'id', str)
        _require(get(row, 'parent_id', str).casefold() == parent.casefold(), 'foreign child parent')
        _require(rid and rid.casefold() not in seen, 'duplicate child identity')
        seen.add(rid.casefold())
    return rows


def _resolution(value, fields):
    resolved = get(value, 'resolved', dict)
    for field in fields:
        _require(get(resolved, field, bool), 'unresolved evidence: ' + field)


def _strings(value):
    _require(isinstance(value, list) and all(isinstance(v, str) and v for v in value) and len(value) == len(set(value)), 'malformed string set')
    return value


def _roles(item):
    evidence = _evidence(item, 'effectiveRoles')
    _resolution(evidence, ('directory', 'rbacHierarchy', 'pimActive', 'pimEligible', 'transitiveGroups', 'definitions'))
    roles = _strings(get(evidence, 'directoryRoleTemplateIds', list))
    privileged = get(evidence, 'privilegedDirectoryUser', bool)
    writer = get(evidence, 'azureResourceWriter', bool)
    return roles, writer, privileged


def _mfa(item, index, check_id):
    _subject(item, index, 'directory_user', directory=True)
    if not get(item, 'accountEnabled', bool):
        return 'NOT_APPLICABLE', {'reason': 'Disabled user'}
    roles, writer, privileged = ([], False, False)
    if check_id in (CIS_MFA, ADMIN_MFA):
        roles, writer, privileged = _roles(item)
        if check_id == ADMIN_MFA and _GLOBAL_ADMIN not in roles:
            return 'NOT_APPLICABLE', {'reason': 'Not an effective Global Administrator'}
    legacy = None
    if check_id == CIS_MFA and (privileged or writer):
        auth = _evidence(item, 'authenticationRequirements')
        _require(get(auth, 'api_version', str) == 'beta', 'legacy MFA beta evidence missing')
        legacy = get(auth, 'perUserMfaState', str)
        _require(legacy in ('disabled', 'enabled', 'enforced'), 'unrecognized legacy MFA state')
    evidence = _evidence(item, 'mfaContexts')
    _resolution(evidence, _RESOLVED + ('inventory', 'registration', 'contextCoverage'))
    registration = get(evidence, 'registration', dict)
    # Registration is coverage evidence; capability alone never establishes enforcement.
    get(registration, 'isMfaRegistered', bool)
    get(registration, 'isMfaCapable', bool)
    contexts = list_of_objects(get(evidence, 'contexts', list))
    _require(contexts, 'empty policy-required sign-in context set')
    policies = _inventory(index, 'conditional_access_policy', directory=True)
    by_id = {get(policy, 'id', str): policy for policy in policies}
    uncovered, names, blocked = [], set(), []
    for context in contexts:
        name = get(context, 'id', str)
        _require(name and name not in names, 'duplicate sign-in context')
        names.add(name)
        _require(get(context, 'purpose', str) == ('azureConsole' if check_id == ADMIN_MFA else 'requiredSignIn'), 'wrong MFA context scope')
        decisions = list_of_objects(get(context, 'policyDecisions', list))
        _require({get(d, 'policyId', str) for d in decisions} == set(by_id) and len(decisions) == len(by_id), 'incomplete policy decisions')
        covered = False
        for decision in decisions:
            _resolution(decision, _RESOLVED)
            matches = get(decision, 'matches', bool)
            excluded = get(decision, 'excluded', bool)
            policy = by_id[decision['policyId']]
            state = get(policy, 'state', str)
            _require(state in ('enabled', 'disabled', 'enabledForReportingButNotEnforced'), 'unknown CA state')
            if state != 'enabled' or not matches or excluded:
                continue
            grant = get(policy, 'grantControls', dict)
            controls = _strings(get(grant, 'builtInControls', list)) if get(grant, 'builtInControls', list) else []
            _require(set(controls) <= {'mfa', 'block', 'compliantDevice', 'domainJoinedDevice', 'approvedApplication', 'compliantApplication', 'passwordChange'}, 'unknown grant control')
            operator = get(grant, 'operator', str)
            _require(operator in ('AND', 'OR'), 'unknown grant alternatives')
            custom = _strings(get(grant, 'customAuthenticationFactors', list)) if get(grant, 'customAuthenticationFactors', list) else []
            terms = _strings(get(grant, 'termsOfUse', list)) if get(grant, 'termsOfUse', list) else []
            strength = get(decision, 'authenticationStrengthRequiresMfa', bool)
            strength_ref = get(grant, 'authenticationStrength')
            _require(strength_ref is None or isinstance(strength_ref, dict), 'malformed authentication strength reference')
            if strength_ref is None:
                _require(not strength, 'MFA strength proof has no policy strength')
            else:
                _require(get(strength_ref, 'id', str) == get(decision, 'authenticationStrengthId', str), 'foreign authentication strength proof')
            if 'block' in controls:
                blocked.append(name)
            choices = len(controls) + len(custom) + len(terms) + int(strength)
            covered |= ('mfa' in controls or strength) and (operator == 'AND' or choices == 1)
        if check_id == ADMIN_MFA:
            # Only a context-specific resolved security-default requirement counts.
            defaults = get(context, 'securityDefaults', dict)
            _require(get(defaults, 'applicabilityResolved', bool), 'unresolved security defaults applicability')
            defaults_enabled = get(defaults, 'isEnabled', bool)
            defaults_mfa = get(defaults, 'requiresMfa', bool)
            covered |= defaults_enabled and defaults_mfa
        if not covered and name not in blocked:
            uncovered.append(name)
    if blocked and not uncovered and legacy != 'disabled':
        return unknown('Blocked contexts do not establish an MFA requirement', blocked_contexts=blocked)
    return result(bool(uncovered) or legacy == 'disabled', uncovered_contexts=uncovered,
                  legacy_per_user_mfa_state=legacy,
                  broad_mfa_status='FAIL' if uncovered else 'PASS',
                  cis_1_1_2_legacy_status=('FAIL' if legacy == 'disabled' else 'PASS') if legacy is not None else 'NOT_APPLICABLE',
                  semantics='Resolved policy-required contexts; registration alone is not enforcement')


def _direct(item, index):
    _subject(item, index, 'directory_user', directory=True)
    evidence = _evidence(item, 'directAssignments')
    _resolution(evidence, ('users', 'directory', 'pimActive', 'pimEligible', 'rbacHierarchy', 'principalTypes'))
    assignments = list_of_objects(get(evidence, 'assignments', list))
    tenant = get(index, 'context.metadata.tenant_id', str)
    scopes = _strings(get(evidence, 'hierarchyScopeIds', list))
    _require(scopes and ('/tenants/' + tenant).casefold() in {s.casefold() for s in scopes}, 'tenant hierarchy coverage missing')
    found = []
    for row in assignments:
        principal = get(row, 'principalId', str)
        kind = get(row, 'principalType', str)
        _require(kind in ('User', 'Group', 'ServicePrincipal'), 'unresolved assignment principal type')
        source = get(row, 'source', str)
        _require(source in ('directory', 'pimActive', 'pimEligible', 'azureRbac'), 'unknown role grant source')
        scope = get(row, 'scope', str)
        _require(scope.casefold() in {value.casefold() for value in scopes}, 'foreign assignment scope')
        _require(get(row, 'tenant_id', str).casefold() == tenant.casefold(), 'foreign assignment tenant')
        if source in ('directory', 'pimActive', 'pimEligible'):
            tenant_scope = '/tenants/' + tenant
            _require(scope.casefold() == tenant_scope.casefold() or re.fullmatch(re.escape(tenant_scope) + r'/administrativeUnits/[^/?#]+', scope, re.I), 'foreign directory assignment scope')
        else:
            subscription = re.match(r'(/subscriptions/[^/?#]+)(?:/|$)', scope, re.I)
            if subscription:
                tenants = get(index, 'context.metadata.subscription_tenants', dict)
                matching = [value for name, value in tenants.items() if name.casefold() == subscription.group(1).casefold()]
                _require(len(matching) == 1 and isinstance(matching[0], str) and matching[0].casefold() == tenant.casefold(), 'unbound ARM assignment subscription')
            else:
                _require(scope == '/' or re.fullmatch(r'/providers/Microsoft.Management/managementGroups/[^/?#]+', scope, re.I), 'foreign ARM assignment hierarchy scope')
        get(row, 'roleDefinitionId', str)
        if principal == item['id']:
            _require(kind == 'User', 'conflicting user principal type')
            found.append(get(row, 'id', str))
    return result(bool(found), direct_assignment_ids=found, semantics='Direct grants only; group grants excluded')


def _stale(item, index):
    _subject(item, index, 'directory_user', directory=True)
    if not get(item, 'accountEnabled', bool):
        return 'NOT_APPLICABLE', {'reason': 'Disabled user'}
    policy = _policy(item, index, STALE)
    days = get(policy, 'inactiveDays', int)
    _require(days > 0, 'invalid inactivity threshold')
    now = _now(index)
    last = _instant(get(item, 'signInActivity.lastSuccessfulSignInDateTime', str))
    _require(last <= now, 'successful sign-in occurs after capture')
    evidence = _evidence(item, 'credentialActivity')
    _resolution(evidence, ('credentialInventory', 'successfulUse', 'issuance'))
    credentials = list_of_objects(get(evidence, 'credentials', list))
    stale, seen = [], set()
    for credential in credentials:
        cid = get(credential, 'id', str)
        _require(cid and cid not in seen, 'duplicate credential')
        seen.add(cid)
        _require(get(credential, 'kind', str) in ('password', 'accessCredential'), 'unrecognized credential kind')
        if not get(credential, 'active', bool):
            continue
        issued = _instant(get(credential, 'issuedAt', str))
        used = get(credential, 'lastSuccessfulUse')
        _require(used is not None, 'Never-used credential has no verified successful use')
        used = _instant(used)
        _require(issued <= used <= now, 'credential dates are inconsistent')
        if used < now - timedelta(days=days):
            stale.append(cid)
    active = sum(get(c, 'active', bool) for c in credentials)
    if not active:
        return 'NOT_APPLICABLE', {'reason': 'Complete credential inventory has no applicable active credentials'}
    return result(bool(stale) or last < now - timedelta(days=days), stale_credential_ids=stale,
                  last_successful_sign_in=last.isoformat(), inactive_days=days)


def _compromised(item, index):
    _subject(item, index, 'directory_user', directory=True)
    enabled = get(item, 'accountEnabled', bool)
    policy = _policy(item, index, COMPROMISED)
    deadline = get(policy, 'responseDeadlineHours', int)
    _require(deadline > 0, 'invalid response deadline')
    now = _now(index)
    evidence = _evidence(item, 'compromiseCases')
    _resolution(evidence, ('allIdentities', 'monitoring', 'cases', 'review', 'disableHistory'))
    _require(get(evidence, 'monitoringCovered', bool), 'identity monitoring coverage unavailable')
    cases = list_of_objects(get(evidence, 'cases', list))
    failed, pending, seen = [], [], set()
    for case in cases:
        cid = get(case, 'id', str)
        _require(cid and cid not in seen, 'duplicate compromise case')
        seen.add(cid)
        _require(get(case, 'userId', str) == item['id'], 'foreign compromise case')
        confirmed = get(case, 'confirmedCompromise', bool)
        review = get(case, 'authorizedReview', bool)
        if not review:
            failed.append(cid)
        if not confirmed:
            continue
        instant = _instant(get(case, 'confirmedAt', str))
        _require(instant <= now, 'case confirmed after capture')
        disabled = get(case, 'disabledAt')
        disabled = None if disabled is None else _instant(disabled)
        reviewed = get(case, 'reviewedAt')
        reviewed = None if reviewed is None else _instant(reviewed)
        if disabled is not None:
            _require(instant <= disabled <= now, 'disable timestamp inconsistent')
        if reviewed is not None:
            _require(instant <= reviewed <= now, 'review timestamp inconsistent')
        if enabled and disabled is None and now > instant + timedelta(hours=deadline):
            failed.append(cid)
        elif disabled is None or reviewed is None or disabled > reviewed or disabled > instant + timedelta(hours=deadline):
            pending.append(cid)
        elif enabled:
            reenabled = _instant(get(case, 'reenabledAt', str))
            _require(reviewed <= reenabled <= now, 'Enabled compromised account lacks reviewed reenablement')
    if failed:
        return result(True, violating_case_ids=sorted(set(failed)))
    if pending:
        return unknown('disablement pending authorized review is not proven', pending_case_ids=pending)
    return result(False, monitored_identity=item['id'], measured_case_count=len(cases))


def _family(item):
    native = get(item, 'type', str).casefold()
    if native == 'microsoft.network/frontdoors':
        return 'classicFrontDoor'
    sku = get(item, 'sku.name', str)
    if sku in ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor'):
        return 'afd'
    _require(sku in ('Standard_Microsoft', 'Standard_Akamai', 'Standard_Verizon', 'Premium_Verizon', 'Standard_ChinaCdn'), 'unrecognized CDN SKU')
    return 'classicCdn'


def _arm_child(row, parent, pattern):
    rid = get(row, 'id', str)
    _require(re.fullmatch(re.escape(parent) + pattern, rid, re.I), 'foreign or malformed native child ID')
    native = get(row, 'type', str)
    parts = rid.casefold().rsplit('/providers/', 1)[1].split('/')
    expected = '/'.join([parts[0], *parts[1::2]])
    _require(native.casefold() == expected, 'child type and ID mismatch')


def _domains(item, family):
    rows = _children(item, 'domains')
    pattern = {'classicFrontDoor': r'/frontendEndpoints/[^/?#]+',
               'classicCdn': r'/endpoints/[^/?#]+/customDomains/[^/?#]+',
               'afd': r'/customDomains/[^/?#]+'}[family]
    expected = {'classicFrontDoor': 'Microsoft.Network/frontDoors/frontendEndpoints',
                'classicCdn': 'Microsoft.Cdn/profiles/endpoints/customDomains',
                'afd': 'Microsoft.Cdn/profiles/customDomains'}[family]
    for row in rows:
        _arm_child(row, item['id'], pattern)
        _require(get(row, 'type', str).casefold() == expected.casefold(), 'foreign domain API generation')
    return rows


def _domain_checks(item, index, check_id):
    _subject(item, index, 'frontdoor_and_cdn_endpoint')
    family = _family(item)
    domains = _domains(item, family)
    if not domains:
        return 'NOT_APPLICABLE', {'reason': 'Complete domain inventory is empty'}
    if check_id == SNI and family == 'afd':
        return unknown('Standard/Premium does not expose equivalent classic SNI semantics')
    violations, applicable = [], 0
    for domain in domains:
        props = get(domain, 'properties', dict)
        if family == 'afd':
            _require(get(props, 'provisioningState', str) == 'Succeeded' and get(props, 'deploymentStatus', str) == 'Succeeded', 'AFD HTTPS deployment unresolved')
            state = get(domain, 'httpsState', str)
        else:
            state = get(props, 'customHttpsProvisioningState', str)
        _require(state in ('Enabled', 'Disabled', 'Failed'), 'HTTPS state missing or transitional')
        if check_id == TLS and state == 'Disabled':
            continue
        if state == 'Failed' and check_id == TLS:
            raise Unavailable('HTTPS deployment failed; effective TLS unknown')
        applicable += 1
        if check_id == SNI:
            if state != 'Enabled':
                violations.append(domain['id'])
                continue
            config = get(props, 'customHttpsConfiguration' if family == 'classicFrontDoor' else 'customHttpsParameters', dict)
            source = get(config, 'certificateSource', str)
            protocol = get(config, 'protocolType', str)
            _require(source in ('AzureKeyVault', 'FrontDoor', 'Cdn'), 'unknown certificate source')
            _require(protocol in ('ServerNameIndication', 'IPBased'), 'unknown TLS extension protocol')
            _require(family != 'classicFrontDoor' or protocol == 'ServerNameIndication', 'unsupported classic Front Door TLS extension')
            if state != 'Enabled' or source != 'AzureKeyVault' or protocol != 'ServerNameIndication':
                violations.append(domain['id'])
        else:
            config = get(props, {'classicFrontDoor': 'customHttpsConfiguration', 'classicCdn': 'customHttpsParameters', 'afd': 'tlsSettings'}[family], dict)
            if family == 'afd':
                preset = get(config, 'cipherSuiteSetType', str)
                _require(preset in ('Customized', 'TLS10_2019', 'TLS12_2022', 'TLS12_2023'), 'unrecognized AFD cipher suite preset')
                version = get(config, 'minimumTlsVersion', str) if preset == 'Customized' else {'TLS10_2019': 'TLS10', 'TLS12_2022': 'TLS12', 'TLS12_2023': 'TLS12'}[preset]
            else:
                version = get(config, 'minimumTlsVersion', str)
            allowed = ('TLS10', 'TLS12', 'TLS13') if family == 'afd' else (('1.0', '1.2') if family == 'classicFrontDoor' else ('None', 'TLS10', 'TLS12'))
            _require(version in allowed, 'unrecognized minimum TLS version')
            # CDN None does not establish an effective protocol minimum.
            _require(version != 'None', 'CDN minimum TLS None has unresolved effective semantics')
            if version in ('1.0', 'TLS10'):
                violations.append(domain['id'])
    if not applicable:
        return 'NOT_APPLICABLE', {'reason': 'No applicable HTTPS domains'}
    return result(bool(violations), violating_domain_ids=violations, assessed_domains=applicable)


def _route_checks(item, index, check_id):
    _subject(item, index, 'frontdoor_and_cdn_endpoint')
    family = _family(item)
    routes = _children(item, 'effectiveRoutes')
    violations, applicable = [], 0
    for route in routes:
        pattern = {'classicFrontDoor': r'/routingRules/[^/?#]+', 'afd': r'/afdEndpoints/[^/?#]+/routes/[^/?#]+', 'classicCdn': r'/endpoints/[^/?#]+(?:/customDomains/[^/?#]+)?'}[family]
        _arm_child(route, item['id'], pattern)
        state = get(route, 'enabledState', str)
        _require(state in ('Enabled', 'Disabled'), 'unrecognized route state')
        if state == 'Disabled':
            continue
        required = ('routeAssociation', 'protocols', 'ruleSets', 'pathCoverage')
        _resolution(route, required + (('originPolicy',) if check_id == ORIGIN else ()))
        if check_id == ORIGIN and not get(route, 'customOrigin', bool):
            continue
        applicable += 1
        paths = list_of_objects(get(route, 'paths', list))
        _require(paths, 'enabled route lacks effective paths')
        for path in paths:
            protocols = _strings(get(path, 'acceptedProtocols', list))
            _require(protocols and set(protocols) <= {'Http', 'Https'}, 'unknown accepted protocols')
            action = get(path, 'action', str)
            _require(action in ('Forward', 'Redirect'), 'unresolved effective action')
            if action == 'Redirect':
                destination = get(path, 'redirectProtocol', str)
                _require(destination in ('HttpOnly', 'HttpsOnly', 'MatchRequest'), 'unknown redirect protocol')
                # Redirect-only paths do not reach an origin. Client check requires HTTPS.
                if check_id == REDIRECT and 'Http' in protocols and destination != 'HttpsOnly':
                    violations.append(route['id'])
                continue
            if check_id == REDIRECT:
                if 'Http' in protocols:
                    violations.append(route['id'])
                continue
            if family == 'classicCdn':
                proof = get(path, 'originProtocolEvidence', dict)
                _require(get(proof, 'source', str) in ('providerConfiguration', 'observedOriginTraffic'), 'CDN origin ports do not establish protocol')
                _require(get(proof, 'allPathsMeasured', bool), 'partial CDN origin observations')
                protocol = get(proof, 'protocol', str)
                _require(protocol in ('HttpsOnly', 'HttpOnly', 'MatchRequest'), 'unknown CDN origin protocol')
            else:
                protocol = get(path, 'forwardingProtocol', str)
                _require(protocol in ('HttpsOnly', 'HttpOnly', 'MatchRequest'), 'unknown origin forwarding protocol')
            if protocol == 'HttpOnly' or protocol == 'MatchRequest' and 'Http' in protocols:
                violations.append(route['id'])
    if not applicable:
        return 'NOT_APPLICABLE', {'reason': 'Complete inventory has no applicable enabled routes/custom origins'}
    return result(bool(violations), violating_route_ids=sorted(set(violations)), assessed_routes=applicable,
                  semantics='Complete effective path declarations; unresolved rules never infer origin protocol')


def _access_logs(item, index):
    _subject(item, index, 'frontdoor_and_cdn_endpoint')
    _family(item)
    categories = _children(item, 'diagnosticCategories')
    settings = _children(item, 'diagnosticSettings')
    offered, groups = set(), {}
    for category in categories:
        _arm_child(category, item['id'], r'/providers/Microsoft.Insights/diagnosticSettingsCategories/[^/?#]+')
        name = get(category, 'name', str)
        _require(category['id'].rsplit('/', 1)[1] == name, 'category identity mismatch')
        category_type = get(category, 'properties.categoryType', str)
        _require(category_type in ('Logs', 'Metrics'), 'unknown diagnostic category type')
        if category_type != 'Logs':
            continue
        offered.add(name)
        for group in _strings(get(category, 'properties.categoryGroups', list)):
            groups.setdefault(group, set()).add(name)
    supported = {'FrontdoorAccessLog'} if item['type'].casefold() == 'microsoft.network/frontdoors' else {'FrontDoorAccessLog', 'AzureCdnAccessLog'}
    supported &= offered
    _require(supported, 'access-log category discovery unresolved')
    found = []
    for setting in settings:
        _arm_child(setting, item['id'], r'/providers/Microsoft.Insights/diagnosticSettings/[^/?#]+')
        props = get(setting, 'properties', dict)
        logs = list_of_objects(get(props, 'logs', list))
        enabled_categories = set()
        for log in logs:
            enabled = get(log, 'enabled', bool)
            keys = [key for key in ('category', 'categoryGroup') if key in log]
            _require(len(keys) == 1, 'ambiguous log category/group')
            value = get(log, keys[0], str)
            if keys[0] == 'categoryGroup':
                _require(value in groups, 'category group expansion unresolved')
                expanded = groups[value]
            else:
                _require(value in offered, 'unsupported log category')
                expanded = {value}
            if enabled:
                enabled_categories |= expanded
        destinations = []
        for key, kind in (('workspaceId', 'log_analytics_workspace'), ('storageAccountId', 'storage_account')):
            value = get(props, key)
            _require(value is None or isinstance(value, str), 'malformed diagnostic destination')
            if value:
                _require(_ARM.fullmatch(value) and '/providers/' + _KINDS[kind].casefold() + '/' in value.casefold(), 'malformed log destination ID')
                destinations.append(value)
        if enabled_categories & supported and destinations:
            found.append(setting['id'])
    return result(not found, qualifying_setting_ids=found, semantics='Declared export; delivery and destination privacy unassessed')


def _key_id(uri, name, version):
    parsed = urlsplit(uri)
    _require(re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/?', uri) and parsed.scheme == 'https', 'malformed Key Vault URI')
    _require(re.fullmatch(r'[A-Za-z0-9-]+', name), 'malformed key name')
    _require(version is None or isinstance(version, str) and re.fullmatch(r'[A-Za-z0-9-]+', version), 'malformed key version')
    return uri.rstrip('/') + '/keys/' + name + ('/' + version if version else '')


def _key_access(item, key_id):
    proof = _evidence(item, 'cmkAccess')
    _require(get(proof, 'key_id', str).casefold() == key_id.casefold(), 'foreign CMK availability proof')
    identity = get(item, 'identity.principalId', str)
    _require(identity and get(proof, 'principal_id', str) == identity, 'CMK access belongs to another identity')
    _resolution(proof, ('keyMetadata', 'identity', 'access', 'network', 'provisioning'))
    _require(get(proof, 'keyEnabled', bool) and get(proof, 'keyUsable', bool), 'CMK usability not proven')
    _require(get(proof, 'wrapKeyAllowed', bool) and get(proof, 'unwrapKeyAllowed', bool), 'CMK identity access not proven')


def _joined(index, kind, rid):
    rows = _inventory(index, kind)
    matches = [row for row in rows if row['id'].casefold() == rid.casefold()]
    _require(len(matches) == 1, 'missing or ambiguous native join: ' + kind)
    return matches[0]


def _query_cmk(item, index):
    _subject(item, index, 'log_analytics_workspace')
    policy = _policy(item, index, QUERY_CMK)
    if not get(policy, 'required', bool):
        return 'NOT_APPLICABLE', {'reason': 'Workspace outside explicit Query-CMK policy'}
    link = _evidence(item, 'queryLinkedStorage')
    _require(get(link, 'id', str).casefold() == (item['id'] + '/linkedStorageAccounts/Query').casefold(), 'foreign Query storage child')
    accounts = _strings(get(link, 'properties.storageAccountIds', list)) if get(link, 'properties.storageAccountIds', list) else []
    if not accounts:
        return result(True, reason='Complete Query child has no linked storage accounts')
    weak = []
    for rid in accounts:
        account = _joined(index, 'storage_account', rid)
        source = get(account, 'properties.encryption.keySource', str)
        _require(source in ('Microsoft.Storage', 'Microsoft.Keyvault'), 'unrecognized storage key source')
        if source == 'Microsoft.Storage':
            weak.append(rid)
            continue
        props = get(account, 'properties.encryption.keyVaultProperties', dict)
        key = _key_id(get(props, 'keyvaulturi', str), get(props, 'keyname', str), get(props, 'keyversion'))
        _key_access(account, key)
    return result(bool(weak), provider_key_storage_account_ids=weak, linked_storage_count=len(accounts))


def _cluster_cmk(item, index):
    _subject(item, index, 'log_analytics_workspace')
    policy = _policy(item, index, CLUSTER_CMK)
    approved = _strings(get(policy, 'approvedKeyVaultKeyIds', list))
    _require(approved, 'empty CMK approval policy')
    for key in approved:
        _require(re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/keys/[A-Za-z0-9-]+(?:/[A-Za-z0-9-]+)?', key), 'malformed approved key ID')
    rid = get(item, 'properties.features.clusterResourceId')
    if rid is None:
        return result(True, reason='Explicitly absent dedicated cluster link')
    _require(isinstance(rid, str) and bool(rid), 'cluster link malformed')
    cluster = _joined(index, 'log_analytics_cluster', rid)
    _require(get(cluster, 'properties.provisioningState', str) == 'Succeeded', 'cluster provisioning unresolved')
    props = get(cluster, 'properties.keyVaultProperties')
    if props is None:
        return result(True, reason='Dedicated cluster explicitly has no CMK')
    _require(isinstance(props, dict), 'cluster key reference malformed')
    key = _key_id(get(props, 'keyVaultUri', str), get(props, 'keyName', str), get(props, 'keyVersion'))
    if key.casefold() not in {value.casefold() for value in approved}:
        return result(True, unapproved_key_id=key)
    _key_access(cluster, key)
    _require(get(cluster, 'cmkAccess.encryptionActive', bool), 'cluster encryption activation unproven')
    return result(False, approved_key_id=key, dedicated_cluster_id=rid)


def _expiry(item, index):
    _subject(item, index, 'log_analytics_workspace')
    policy = _policy(item, index, EXPIRY)
    days = get(policy, 'retentionDays', int)
    _require(days > 0, 'invalid retention policy')
    tables = _strings(get(policy, 'tables', list))
    _require(tables and all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', table) for table in tables), 'empty or malformed scoped table policy')
    cutoff = _now(index) - timedelta(days=days)
    evidence = _evidence(item, 'expiryQueries')
    queries = list_of_objects(get(evidence, 'queries', list))
    _require(len(queries) == len(tables) and {get(q, 'table', str) for q in queries} == set(tables), 'incomplete or duplicate policy table measurement')
    expired, uncertain = [], []
    for query in queries:
        _require(get(query, 'workspace_id', str).casefold() == item['id'].casefold(), 'foreign workspace query')
        _require(_instant(get(query, 'cutoff', str)) == cutoff, 'query cutoff differs from organization policy')
        count = get(query, 'expiredEventCount', int)
        _require(count >= 0, 'negative expired count')
        # Returned timestamps are positive evidence even if the zero-count proof is bounded/partial.
        events = get(query, 'expiredEventTimes', list)
        _require(all(_instant(event) < cutoff for event in events) and len(events) <= count, 'query expired-event evidence inconsistent')
        if count > 0:
            _require(events, 'count lacks a verified expired event')
            expired.append(query['table'])
        flags = ('allRetainedTiers', 'entireAccessibleRange', 'queryComplete', 'notTruncated', 'permissionsComplete')
        if not all(get(query, flag, bool) for flag in flags):
            uncertain.append(query['table'])
    if expired:
        return result(True, tables_with_expired_events=expired)
    if uncertain:
        return unknown('Zero counts do not cover every retained tier/time range', incomplete_tables=uncertain)
    return result(False, measured_tables=tables, policy_cutoff=cutoff.isoformat())


def _c5_logs(item, index):
    _subject(item, index, 'log_analytics_workspace')
    props = get(item, 'properties', dict)
    for key in ('publicNetworkAccessForIngestion', 'publicNetworkAccessForQuery'):
        if key in props or key in props.get('_coverage', {}):
            _require(get(props, key, str) in ('Enabled', 'Disabled'), 'unsupported workspace access enum')
    if 'retentionInDays' in props or 'retentionInDays' in props.get('_coverage', {}):
        _require(get(props, 'retentionInDays', int) > 0, 'malformed retention signal')
    policy = _policy(item, index, C5_LOGS)
    controls = ('confidentiality', 'integrity', 'availability', 'access', 'recovery')
    requirements = get(policy, 'requiredMeasures', dict)
    evidence = _evidence(item, 'logProtectionMeasures')
    _resolution(evidence, ('logs', 'infrastructure', 'policyCoverage'))
    measures = list_of_objects(get(evidence, 'measures', list))
    expected = set()
    for control in controls:
        ids = _strings(get(requirements, control, list))
        _require(ids, 'empty required C5 control policy')
        expected.update((control, mid) for mid in ids)
    observed, violations, uncertain = set(), [], []
    for measure in measures:
        key = (get(measure, 'control', str), get(measure, 'measureId', str))
        _require(key in expected and key not in observed, 'foreign or duplicate C5 control measure')
        observed.add(key)
        _require(get(measure, 'evidenceRef', str), 'C5 measure lacks direct evidence reference')
        status = get(measure, 'observation', str)
        _require(status in ('implemented', 'violated', 'unresolved'), 'unrecognized direct C5 observation')
        documented = get(measure, 'documented', bool)
        if status == 'violated':
            violations.append(key[1])
        elif status == 'unresolved' or not documented:
            uncertain.append(key[1])
    if violations:
        return result(True, directly_violated_measure_ids=violations)
    if observed != expected or uncertain:
        return unknown('Required documented and implemented log/infrastructure controls not fully proven', unresolved_measure_ids=uncertain)
    return result(False, direct_control_measure_count=len(measures))


def _cluster_scope(item, index):
    _require(item == get(index, 'context', dict), 'scope subject differs from Azure context')
    rows = _inventory(index, 'log_analytics_workspace')
    if not rows:
        return 'NOT_APPLICABLE', {'reason': 'Complete workspace inventory is empty'}
    outcomes = []
    for row in rows:
        try:
            status, evidence = _cluster_cmk(row, index)
        except Unavailable as exc:
            status, evidence = unknown(str(exc))
        outcomes.append({'workspace_id': row['id'], 'status': status, 'evidence': evidence})
    if any(outcome['status'] == 'UNKNOWN' for outcome in outcomes):
        return unknown('One or more workspace cluster/CMK facts unresolved', workspaces=outcomes)
    return result(any(outcome['status'] == 'FAIL' for outcome in outcomes), workspaces=outcomes)


def _evaluate(check_id, item, index):
    if check_id == CLUSTER_CMK:
        return _cluster_scope(item, index)
    if check_id in (CIS_MFA, ALL_MFA, ADMIN_MFA):
        return _mfa(item, index, check_id)
    if check_id in (SNI, TLS):
        return _domain_checks(item, index, check_id)
    if check_id in (REDIRECT, ORIGIN):
        return _route_checks(item, index, check_id)
    return {COMPROMISED: _compromised, DIRECT: _direct, STALE: _stale,
            ACCESS_LOG: _access_logs, QUERY_CMK: _query_cmk, EXPIRY: _expiry,
            C5_LOGS: _c5_logs, CLUSTER_CMK: _cluster_cmk}[check_id](item, index)


DEPENDENCIES = {cid: [spec['resource_kind']] for cid, spec in SPECS.items()}
for _cid in (CIS_MFA, ALL_MFA, ADMIN_MFA):
    DEPENDENCIES[_cid].append('conditional_access_policy')
DEPENDENCIES[QUERY_CMK].append('storage_account')
DEPENDENCIES[CLUSTER_CMK].append('log_analytics_cluster')


def _register(check_id):
    spec = SPECS[check_id]
    native_category = spec['category'] if spec['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'
    @register(check_id, spec['provider'], native_category, spec['resource_kind'],
              spec['title'], spec['severity'], 'CM-6', spec['remediation_hint'],
              dependencies=DEPENDENCIES[check_id], target='scope' if check_id == CLUSTER_CMK else 'resource')
    def evaluate(item, index):
        return _evaluate(check_id, item, index)
    evaluate.__name__ = check_id.replace('.', '_')
    # Existing sw03 convention: preserve signed categories outside the legacy
    # decorator whitelist without changing the shared registry implementation.
    position = next(i for i, check in enumerate(CHECKS) if check.id == check_id)
    if native_category != spec['category']:
        CHECKS[position] = replace(CHECKS[position], category=spec['category'])
    return CHECKS[position].evaluate


EVALUATORS = {cid: _register(cid) for cid in IDS}
