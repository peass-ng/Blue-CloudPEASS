"""Signed Azure sw20 checks. Offline evaluation of complete, scoped evidence.

Missing facts are UNKNOWN. Collector contracts are documented in sw20's
collector request; effective decisions require measured source evidence.
"""
from __future__ import annotations

import re
import base64
import hashlib
from cryptography import x509
import math
from dataclasses import replace
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects

SPECS = {'azure.gap.compute_vm_scale_set_automatic_upgrade_enabled': {'id': 'azure.gap.compute_vm_scale_set_automatic_upgrade_enabled',
                                                              'provider': 'azure',
                                                              'resource_kind': 'vm_scale_set',
                                                              'data_source': 'Existing vm_scale_set '
                                                                             'collection. Collected '
                                                                             'vm_scale_set.items[].properties.upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade',
                                                              'predicate': 'For each VMSS using a supported '
                                                                           'platform image and upgrade mode, '
                                                                           'PASS on '
                                                                           'upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade=true; '
                                                                           'FAIL on explicit false; UNKNOWN '
                                                                           'if model eligibility or field '
                                                                           'cannot be established. Aggregate '
                                                                           'FAIL before UNKNOWN.',
                                                              'severity': 'medium',
                                                              'category': 'vulnerability',
                                                              'title': 'Enable automatic OS image upgrades '
                                                                       'on VM scale sets',
                                                              'description': 'Enable automatic OS image '
                                                                             'upgrades on VM scale sets. A '
                                                                             'finding is raised when an '
                                                                             'applicable VM scale set '
                                                                             'explicitly has '
                                                                             'enableAutomaticOSUpgrade=false.',
                                                              'remediation_hint': 'Azure portal > Virtual '
                                                                                  'machine scale sets > '
                                                                                  'Upgrades: Set '
                                                                                  'upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade=true.'},
 'azure.gap.compute_vm_scale_set_endpoint_protection_solution_installed': {'id': 'azure.gap.compute_vm_scale_set_endpoint_protection_solution_installed',
                                                                           'provider': 'azure',
                                                                           'resource_kind': 'vm_scale_set',
                                                                           'data_source': 'Paged VMSS parent '
                                                                                          'inventory, VMSS '
                                                                                          'instance LIST '
                                                                                          '2024-07-01 and '
                                                                                          'Microsoft.Security/assessments '
                                                                                          'LIST 2020-01-01. '
                                                                                          'Resolve stable '
                                                                                          'endpoint-protection '
                                                                                          'assessment key '
                                                                                          'and join '
                                                                                          'properties.resourceDetails.id '
                                                                                          'to either the '
                                                                                          'parent VMSS or an '
                                                                                          'instance '
                                                                                          'according to the '
                                                                                          'assessment '
                                                                                          'resource type. '
                                                                                          'Obtain '
                                                                                          'per-instance '
                                                                                          'endpoint '
                                                                                          'agent/health '
                                                                                          'evidence when '
                                                                                          'parent assessment '
                                                                                          'does not prove '
                                                                                          'installation on '
                                                                                          'every current '
                                                                                          'instance.',
                                                                           'predicate': 'For each VMSS, '
                                                                                        'evaluate its '
                                                                                        'current instances '
                                                                                        'and the stable '
                                                                                        'endpoint-protection '
                                                                                        'assessment at its '
                                                                                        'documented resource '
                                                                                        'scope. A parent '
                                                                                        'Healthy assessment '
                                                                                        'is '
                                                                                        'recommendation-health '
                                                                                        'evidence, not an '
                                                                                        'instance-ID join or '
                                                                                        'standalone proof of '
                                                                                        'every agent '
                                                                                        'installation. PASS '
                                                                                        'only when current '
                                                                                        'per-instance '
                                                                                        'endpoint-protection '
                                                                                        'evidence or a '
                                                                                        'documented '
                                                                                        'assessment contract '
                                                                                        'proving full '
                                                                                        'instance coverage '
                                                                                        'confirms '
                                                                                        'installation for '
                                                                                        'all applicable '
                                                                                        'instances. FAIL on '
                                                                                        'measured missing '
                                                                                        'protection or '
                                                                                        'Unhealthy '
                                                                                        'applicable '
                                                                                        'assessment. UNKNOWN '
                                                                                        'when assessment '
                                                                                        'scope, instance '
                                                                                        'inventory, agent '
                                                                                        'evidence, status, '
                                                                                        'assessment key or '
                                                                                        'applicability '
                                                                                        'cannot be resolved; '
                                                                                        'NotApplicable '
                                                                                        'requires '
                                                                                        'independent '
                                                                                        'justification.',
                                                                           'severity': 'medium',
                                                                           'category': 'vulnerability',
                                                                           'title': 'Endpoint protection '
                                                                                    'solution should be '
                                                                                    'installed on virtual '
                                                                                    'machine scale sets',
                                                                           'description': 'Checks the VM '
                                                                                          'scale set '
                                                                                          'endpoint-protection '
                                                                                          'assessment at its '
                                                                                          'documented scope '
                                                                                          'and verifies '
                                                                                          'current instance '
                                                                                          'coverage.',
                                                                           'remediation_hint': 'Defender for '
                                                                                               'Cloud > '
                                                                                               'Recommendations '
                                                                                               '> endpoint '
                                                                                               'protection: '
                                                                                               'install or '
                                                                                               'repair the '
                                                                                               'supported '
                                                                                               'solution on '
                                                                                               'affected '
                                                                                               'VMSS '
                                                                                               'instances '
                                                                                               'and verify a '
                                                                                               'Healthy '
                                                                                               'reassessment.'},
 'azure.gap.compute_vm_scale_set_security_configuration_vulnerabilities_remediated': {'id': 'azure.gap.compute_vm_scale_set_security_configuration_vulnerabilities_remediated',
                                                                                      'provider': 'azure',
                                                                                      'resource_kind': 'vm_scale_set',
                                                                                      'data_source': 'Paged '
                                                                                                     'Defender '
                                                                                                     'for '
                                                                                                     'Cloud '
                                                                                                     'Assessments '
                                                                                                     'LIST '
                                                                                                     '2020-01-01; '
                                                                                                     'VMSS '
                                                                                                     'id; '
                                                                                                     'assessment.properties.resourceDetails.id '
                                                                                                     'and '
                                                                                                     'properties.status.code. '
                                                                                                     'Policy '
                                                                                                     'requiredOsVulnerabilityAssessmentKeys '
                                                                                                     'must '
                                                                                                     'identify '
                                                                                                     'the '
                                                                                                     'Defender '
                                                                                                     'OS-vulnerability '
                                                                                                     'assessments '
                                                                                                     'for '
                                                                                                     'VMSS, '
                                                                                                     'not '
                                                                                                     'security-configuration '
                                                                                                     'assessments.',
                                                                                      'predicate': 'For each '
                                                                                                   'VMSS and '
                                                                                                   'each '
                                                                                                   'explicitly '
                                                                                                   'configured '
                                                                                                   'OS-vulnerability '
                                                                                                   'assessment '
                                                                                                   'key, '
                                                                                                   'join '
                                                                                                   'exact '
                                                                                                   'normalized '
                                                                                                   'assessed-resource '
                                                                                                   'ID and '
                                                                                                   'assessment '
                                                                                                   'key. '
                                                                                                   'FAIL on '
                                                                                                   'a '
                                                                                                   'current '
                                                                                                   'Unhealthy '
                                                                                                   'OS-vulnerability '
                                                                                                   'assessment; '
                                                                                                   'PASS '
                                                                                                   'only '
                                                                                                   'when '
                                                                                                   'every '
                                                                                                   'required '
                                                                                                   'OS-vulnerability '
                                                                                                   'assessment '
                                                                                                   'is '
                                                                                                   'current '
                                                                                                   'and '
                                                                                                   'Healthy. '
                                                                                                   'UNKNOWN '
                                                                                                   'for '
                                                                                                   'absent/NotApplicable/stale/conflicting '
                                                                                                   'assessments, '
                                                                                                   'unrecognized '
                                                                                                   'status, '
                                                                                                   'missing '
                                                                                                   'keys or '
                                                                                                   'freshness '
                                                                                                   'policy, '
                                                                                                   'incomplete '
                                                                                                   'VMSS/assessment '
                                                                                                   'pages, '
                                                                                                   'or an '
                                                                                                   'assessment '
                                                                                                   'that '
                                                                                                   'only '
                                                                                                   'measures '
                                                                                                   'security '
                                                                                                   'configuration. '
                                                                                                   'A '
                                                                                                   'complete '
                                                                                                   'empty '
                                                                                                   'VMSS '
                                                                                                   'inventory '
                                                                                                   'is '
                                                                                                   'NOT_APPLICABLE.',
                                                                                      'severity': 'medium',
                                                                                      'category': 'vulnerability',
                                                                                      'title': 'OS '
                                                                                               'vulnerabilities '
                                                                                               'on virtual '
                                                                                               'machine '
                                                                                               'scale sets '
                                                                                               'are '
                                                                                               'remediated',
                                                                                      'description': 'Checks '
                                                                                                     'Defender '
                                                                                                     'OS-vulnerability '
                                                                                                     'assessments '
                                                                                                     'for VM '
                                                                                                     'scale '
                                                                                                     'sets; '
                                                                                                     'security-configuration '
                                                                                                     'assessments '
                                                                                                     'alone '
                                                                                                     'do not '
                                                                                                     'establish '
                                                                                                     'this '
                                                                                                     'requirement.',
                                                                                      'remediation_hint': 'In '
                                                                                                          'Defender '
                                                                                                          'for '
                                                                                                          'Cloud '
                                                                                                          '> '
                                                                                                          'Recommendations, '
                                                                                                          'inspect '
                                                                                                          'each '
                                                                                                          'Unhealthy '
                                                                                                          'VMSS '
                                                                                                          'security '
                                                                                                          'configuration '
                                                                                                          'assessment '
                                                                                                          'and '
                                                                                                          'remediate '
                                                                                                          'its '
                                                                                                          'listed '
                                                                                                          'findings.'},
 'azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled': {'id': 'azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled',
                                                                         'provider': 'azure',
                                                                         'resource_kind': 'entra_user',
                                                                         'data_source': 'Paged ARM role '
                                                                                        'assignments with '
                                                                                        'atScope(), role '
                                                                                        'definitions, active '
                                                                                        'PIM assignments and '
                                                                                        'transitive Entra '
                                                                                        'group membership; '
                                                                                        'Graph users, '
                                                                                        'Conditional Access '
                                                                                        'policies and '
                                                                                        'sign-in evidence. '
                                                                                        'MFA registration '
                                                                                        'alone is not '
                                                                                        'enforcement. '
                                                                                        'Include security '
                                                                                        'defaults state and '
                                                                                        'an approved set of '
                                                                                        'sign-in contexts.',
                                                                         'predicate': 'For each enabled '
                                                                                      'human principal with '
                                                                                      'effective '
                                                                                      'subscription Owner, '
                                                                                      'read or write '
                                                                                      'privilege, including '
                                                                                      'inherited/custom/group/PIM '
                                                                                      'grants, PASS only '
                                                                                      'when effective MFA '
                                                                                      'enforcement is proven '
                                                                                      'for every required '
                                                                                      'Azure management '
                                                                                      'sign-in context. FAIL '
                                                                                      'when complete grant '
                                                                                      'and policy evidence '
                                                                                      'proves a context can '
                                                                                      'sign in without MFA. '
                                                                                      'UNKNOWN for '
                                                                                      'unresolved role '
                                                                                      'actions, membership, '
                                                                                      'PIM, CA '
                                                                                      'conditions/exclusions, '
                                                                                      'security defaults, or '
                                                                                      'sign-in contexts. '
                                                                                      'Empty completely '
                                                                                      'enumerated principal '
                                                                                      'set is '
                                                                                      'NOT_APPLICABLE.',
                                                                         'severity': 'medium',
                                                                         'category': 'identity',
                                                                         'title': 'Subscription readers have '
                                                                                  'MFA enforced',
                                                                         'description': 'Measures effective '
                                                                                        'MFA enforcement for '
                                                                                        'enabled users with '
                                                                                        'read access to the '
                                                                                        'subscription.',
                                                                         'remediation_hint': 'In Entra admin '
                                                                                             'center > '
                                                                                             'Conditional '
                                                                                             'Access, '
                                                                                             'require MFA '
                                                                                             'for all '
                                                                                             'enabled users '
                                                                                             'with '
                                                                                             'subscription '
                                                                                             'read access to '
                                                                                             'Azure '
                                                                                             'management; '
                                                                                             'resolve '
                                                                                             'exclusions and '
                                                                                             'enroll users.'},
 'azure.other.disabled_identity_24h': {'id': 'azure.other.disabled_identity_24h',
                                       'provider': 'azure',
                                       'resource_kind': 'entra_user',
                                       'data_source': 'Authoritative IdP disable/delete event feed with '
                                                      'source subject ID and timestamp; Entra Graph '
                                                      'users/deletedItems and directoryAudits with immutable '
                                                      'subject mapping; paged ARM and Graph role '
                                                      'assignments, transitive groups and cloud policy '
                                                      'grants; snapshot UTC clock.',
                                       'predicate': 'For each authoritative IdP disable/delete event older '
                                                    'than 24 hours, FAIL if a mapped cloud identity or '
                                                    'effective access policy remains active. PASS only when '
                                                    'the cloud identity and its effective policies were '
                                                    'disabled/deleted within 24 hours of the IdP event, '
                                                    'supported by dated cloud audit/history evidence. '
                                                    'UNKNOWN for missing IdP event time, identity mapping, '
                                                    'cloud change time, deleted-user evidence, group grants '
                                                    'or incomplete paging. Events younger than 24 hours are '
                                                    'pending, not PASS.',
                                       'severity': 'high',
                                       'category': 'identity',
                                       'title': 'Disabled Entra users lose privileged assignments within 24 '
                                                'hours',
                                       'description': 'Checks effective Azure RBAC and Entra directory roles '
                                                      'after a verified user disable event.',
                                       'remediation_hint': 'Disable or delete the mapped Entra cloud '
                                                           'identity and remove its effective cloud access '
                                                           'policies within 24 hours of the IdP '
                                                           'disable/delete event; preserve dated evidence.'},
 'azure.other.human_federated_signin': {'id': 'azure.other.human_federated_signin',
                                        'provider': 'azure',
                                        'resource_kind': 'entra_user',
                                        'data_source': 'Paged Graph v1.0 auditLogs/signIns with bounded '
                                                       'filter: userId, createdDateTime, status.errorCode; '
                                                       'complete /users human classification; approved IdP '
                                                       'mapping and documented sign-in issuer/authentication '
                                                       'evidence from a supported API or external IdP logs, '
                                                       'plus domain federation configuration. v1.0 signIn '
                                                       'does not document tokenIssuerType/tokenIssuerName.',
                                        'predicate': 'Within the approved lookback window, inspect every '
                                                     'successful human-user sign-in. FAIL only when an event '
                                                     'is joined by stable sign-in correlation to evidence of '
                                                     'authentication outside the approved federated IdP. '
                                                     'PASS only if complete retained sign-in and IdP '
                                                     'histories cover every required human user and every '
                                                     'successful event has positive correlated proof of '
                                                     'approved federated authentication, with current domain '
                                                     'federation configuration. UNKNOWN for no observations, '
                                                     'short retention, missing correlation, human '
                                                     'classification, issuer evidence, configuration or '
                                                     'pages. Historical events alone do not prove future '
                                                     'enforcement.',
                                        'severity': 'high',
                                        'category': 'hardening',
                                        'title': 'Use approved federation for human sign-ins',
                                        'description': 'Checks each observed human sign-in for positively '
                                                       'correlated authentication through the approved '
                                                       'federated IdP.',
                                        'remediation_hint': 'Configure the approved federated IdP, remove '
                                                            'direct-authentication bypasses, and retain '
                                                            'correlated sign-in and IdP evidence for the '
                                                            'approved lookback window.'},
 'azure.other.certificate_rotation_180_days': {'id': 'azure.other.certificate_rotation_180_days',
                                               'provider': 'azure',
                                               'resource_kind': 'vault_certificate',
                                               'data_source': 'Complete inventory of exposed TLS '
                                                              'ports/endpoints and their live active '
                                                              'certificate chains; CA issuance records with '
                                                              'certificate serial/thumbprint and issuance '
                                                              'timestamp; paged Key Vault '
                                                              '/certificates/{name}/versions?api-version=7.4 '
                                                              'and App Service '
                                                              'Microsoft.Web/certificates/bindings only as '
                                                              'supporting joins. Key Vault '
                                                              'attributes.created is import/version '
                                                              'creation, not authoritative issuance.',
                                               'predicate': 'For every in-scope exposed TLS endpoint, join '
                                                            'its live active certificate thumbprint/serial '
                                                            'to a unique CA issuance record and compare the '
                                                            'issuance timestamp to a 180-day window. PASS '
                                                            'only when every exposed endpoint has verified '
                                                            'active-certificate issuance or rotation within '
                                                            '180 days. FAIL for a uniquely identified active '
                                                            'certificate older than 180 days. UNKNOWN for '
                                                            'unmeasured exposed endpoints, missing issuance '
                                                            'records, ambiguous thumbprints, incomplete '
                                                            'pages or unknown binding status.',
                                               'severity': 'medium',
                                               'category': 'encryption',
                                               'title': 'Rotate exposed certificates within 180 days',
                                               'description': 'Rotate exposed certificates within 180 days. '
                                                              'A finding is raised when an active exposed '
                                                              'hostname binds a certificate version created '
                                                              'more than 180 days ago.',
                                               'remediation_hint': 'Inventory every exposed TLS endpoint, '
                                                                   'renew certificates older than 180 days '
                                                                   'from issuance and update the active '
                                                                   'bindings; retain issuance and deployment '
                                                                   'evidence.'},
 'azure.other.certificate_rotation_90_days': {'id': 'azure.other.certificate_rotation_90_days',
                                              'provider': 'azure',
                                              'resource_kind': 'vault_certificate',
                                              'data_source': 'Key Vault data-plane paged GET '
                                                             '/certificates?api-version=2025-07-01 and '
                                                             '/certificates/{name}/versions?api-version=2025-07-01: '
                                                             'attributes.created Unix seconds, enabled '
                                                             'boolean, x5t thumbprint; complete public TLS '
                                                             'endpoint and version-specific '
                                                             'certificate-binding inventories across '
                                                             'approved Azure services; snapshot UTC time. '
                                                             'Obtain authoritative issuance timestamp from '
                                                             'the bound X.509 certificate or CA record; Key '
                                                             'Vault attributes.created is only vault-object '
                                                             'creation time and cannot substitute for '
                                                             'issuance.',
                                              'predicate': 'For each public port using certificate-based '
                                                           'encryption in the approved service inventory, '
                                                           'PASS only if the exact active bound certificate '
                                                           'version or thumbprint uniquely resolves, is '
                                                           'enabled, and authoritative certificate/CA '
                                                           'evidence shows issuance within 90 days. FAIL if '
                                                           'a uniquely identified active bound certificate '
                                                           'was issued more than 90 days ago. UNKNOWN for '
                                                           'incomplete endpoint coverage, version binding, '
                                                           'issuance evidence, pagination or clock; unused '
                                                           'versions are outside scope. Key Vault '
                                                           'attributes.created alone never establishes '
                                                           'issuance age.',
                                              'severity': 'medium',
                                              'category': 'encryption',
                                              'title': 'Exposed certificates rotate within 90 days',
                                              'description': 'Checks age of certificate versions actively '
                                                             'bound to public Azure endpoints.',
                                              'remediation_hint': 'Renew active endpoint certificates before '
                                                                  '90 days and update each public TLS '
                                                                  'binding to the new version; verify the '
                                                                  'bound thumbprint.'},
 'azure.other.metric_ingestion_rate_alert': {'id': 'azure.other.metric_ingestion_rate_alert',
                                             'provider': 'azure',
                                             'resource_kind': 'data_collection_rule',
                                             'data_source': 'Paged scheduledQueryRules LIST 2021-08-01 with '
                                                            'criteria query/window/threshold and action '
                                                            'group; declared custom/user-defined metric '
                                                            'collectors and per-source ingestion rate-limit '
                                                            'configuration plus flood-test or throttling '
                                                            'telemetry; policy flood threshold/window and '
                                                            'approved workspaces.',
                                             'predicate': 'For every in-scope custom/user-defined metric '
                                                          'source, PASS only if a verified rate limit '
                                                          'reduces flood traffic at the declared threshold '
                                                          'and a reachable enabled alert fires over the '
                                                          'policy window. FAIL if complete evidence proves '
                                                          'either rate limiting or alerting absent. UNKNOWN '
                                                          'when source inventory, effective throttle, '
                                                          'threshold/window, query semantics, alert action '
                                                          'or paging is unmeasured. An alert alone cannot '
                                                          'PASS.',
                                             'severity': 'medium',
                                             'category': 'monitoring',
                                             'title': 'Alert on abnormal metric ingestion by source',
                                             'description': 'Checks both rate limiting and alerting for a '
                                                            'metric source that floods its collector.',
                                             'remediation_hint': 'Configure an effective ingestion rate '
                                                                 'limit for custom/user-defined metric '
                                                                 'floods and a scheduled query alert with '
                                                                 'the approved threshold/window and enabled '
                                                                 'action group.'},
 'azure.other.monitor_stream_auth': {'id': 'azure.other.monitor_stream_auth',
                                     'provider': 'azure',
                                     'resource_kind': 'data_collection_rule',
                                     'data_source': 'Paged ARM dataCollectionRules/dataCollectionEndpoints '
                                                    '2023-03-11 for stream inventory; data-plane ingestion '
                                                    'endpoint configuration, per-stream '
                                                    'credential/authentication policy and negative/positive '
                                                    'authentication tests or gateway logs for each '
                                                    'metric/trace type; ARM RBAC and Graph transitive groups '
                                                    'where applicable.',
                                     'predicate': 'For each declared metric or trace type, PASS only with '
                                                  'data-plane evidence that pushing that type requires a '
                                                  'valid type-authorized identity and rejects anonymous or '
                                                  'wrong-type credentials. FAIL when a verified '
                                                  'unauthenticated or wrong-type push is accepted. UNKNOWN '
                                                  'when stream inventory, credential-to-type mapping, '
                                                  'data-plane enforcement tests or policy scope is missing. '
                                                  'DCR/DCE write RBAC alone cannot PASS.',
                                     'severity': 'medium',
                                     'category': 'hardening',
                                     'title': 'DCR streams and ingestion publishers are approved',
                                     'description': 'Checks data-plane authentication and type-specific '
                                                    'authorization for metric and trace ingestion.',
                                     'remediation_hint': 'Require authenticated ingestion for each '
                                                         'metric/trace type and bind publisher credentials '
                                                         'to the permitted type; verify rejection of '
                                                         'anonymous and wrong-type pushes.'},
 'azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63': {'id': 'azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63',
                                                                              'provider': 'azure',
                                                                              'resource_kind': 'application_gateway_and_frontdoor',
                                                                              'data_source': 'Application '
                                                                                             'Gateway GET '
                                                                                             'api-version=2023-09-01: '
                                                                                             'properties.httpListeners[].properties.protocol/sslCertificate.id, '
                                                                                             'properties.sslCertificates[].id/properties; '
                                                                                             'classic Front '
                                                                                             'Door GET '
                                                                                             'api-version=2021-06-01: '
                                                                                             'properties.frontendEndpoints[].properties.customHttpsConfiguration, '
                                                                                             'properties.routingRules[].properties.acceptedProtocols. '
                                                                                             'For each '
                                                                                             'exposed '
                                                                                             'hostname '
                                                                                             'perform TLS '
                                                                                             'handshake and '
                                                                                             'validate '
                                                                                             'chain, '
                                                                                             'hostname and '
                                                                                             'expiry at '
                                                                                             'observation '
                                                                                             'time; resolve '
                                                                                             'Key '
                                                                                             'Vault-backed '
                                                                                             'certificate '
                                                                                             'material when '
                                                                                             'applicable.',
                                                                              'predicate': 'For every '
                                                                                           'exposed '
                                                                                           'Application '
                                                                                           'Gateway or '
                                                                                           'classic Front '
                                                                                           'Door '
                                                                                           'hostname/listener '
                                                                                           'in scope, PASS '
                                                                                           'only if HTTPS is '
                                                                                           'configured and '
                                                                                           'an associated '
                                                                                           'certificate '
                                                                                           'validates for '
                                                                                           'that hostname, '
                                                                                           'chain and '
                                                                                           'observation '
                                                                                           'time. FAIL on a '
                                                                                           'measured '
                                                                                           'HTTP-only '
                                                                                           'listener, '
                                                                                           'missing HTTPS '
                                                                                           'binding, '
                                                                                           'expired/mismatched/untrusted '
                                                                                           'certificate or '
                                                                                           'failed TLS '
                                                                                           'validation. '
                                                                                           'UNKNOWN if '
                                                                                           'hostname, '
                                                                                           'certificate '
                                                                                           'binding/material, '
                                                                                           'endpoint '
                                                                                           'reachability, '
                                                                                           'effective '
                                                                                           'routing or '
                                                                                           'inventory is '
                                                                                           'unresolved. '
                                                                                           'HTTP-to-HTTPS '
                                                                                           'redirect alone '
                                                                                           'does not satisfy '
                                                                                           'the frozen '
                                                                                           'requirement.',
                                                                              'severity': 'medium',
                                                                              'category': 'encryption',
                                                                              'title': 'HTTP routes redirect '
                                                                                       'to HTTPS on '
                                                                                       'Application Gateway '
                                                                                       'and Front Door',
                                                                              'description': 'Checks actual '
                                                                                             'HTTP-to-HTTPS '
                                                                                             'redirect '
                                                                                             'routing rather '
                                                                                             'than only the '
                                                                                             'existence of '
                                                                                             'an SSL '
                                                                                             'certificate.',
                                                                              'remediation_hint': 'Configure '
                                                                                                  'HTTPS '
                                                                                                  'listeners '
                                                                                                  'and bind '
                                                                                                  'valid '
                                                                                                  'certificates '
                                                                                                  'for every '
                                                                                                  'exposed '
                                                                                                  'Application '
                                                                                                  'Gateway '
                                                                                                  'or Front '
                                                                                                  'Door '
                                                                                                  'hostname; '
                                                                                                  'renew or '
                                                                                                  'replace '
                                                                                                  'invalid '
                                                                                                  'certificates '
                                                                                                  'and '
                                                                                                  'validate '
                                                                                                  'the live '
                                                                                                  'TLS '
                                                                                                  'endpoint.'},
 'azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17': {'id': 'azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17',
                                                                              'provider': 'azure',
                                                                              'resource_kind': 'application_gateway_and_frontdoor',
                                                                              'data_source': 'Paged '
                                                                                             'Application '
                                                                                             'Gateway and '
                                                                                             'Front Door '
                                                                                             'inventory; '
                                                                                             'Application '
                                                                                             'Gateway GET '
                                                                                             'listener '
                                                                                             'sslProfileId, '
                                                                                             'gateway '
                                                                                             'properties.sslPolicy '
                                                                                             'and '
                                                                                             'sslProfiles[].properties.sslPolicy; '
                                                                                             'Front Door GET '
                                                                                             'frontend '
                                                                                             'endpoint '
                                                                                             'HTTPS/TLS '
                                                                                             'policy '
                                                                                             'settings; '
                                                                                             'policy-approved '
                                                                                             'predefinedPolicyName '
                                                                                             'values.',
                                                                              'predicate': 'For every '
                                                                                           'in-scope '
                                                                                           'Application '
                                                                                           'Gateway or Front '
                                                                                           'Door HTTPS '
                                                                                           'listener, '
                                                                                           'resolve its '
                                                                                           'effective SSL '
                                                                                           'policy and '
                                                                                           'require '
                                                                                           'policyType="Predefined" '
                                                                                           'with the exact '
                                                                                           'policy-approved '
                                                                                           'name. PASS only '
                                                                                           'if every '
                                                                                           'listener is '
                                                                                           'measured and '
                                                                                           'matches; FAIL on '
                                                                                           'a measured '
                                                                                           'different policy '
                                                                                           'type/name; '
                                                                                           'UNKNOWN for '
                                                                                           'unresolved '
                                                                                           'listener/profile '
                                                                                           'inheritance, '
                                                                                           'unsupported '
                                                                                           'Front Door '
                                                                                           'policy '
                                                                                           'representation, '
                                                                                           'missing approved '
                                                                                           'name or '
                                                                                           'incomplete '
                                                                                           'inventory. No '
                                                                                           'applicable HTTPS '
                                                                                           'listeners is '
                                                                                           'NOT_APPLICABLE.',
                                                                              'severity': 'medium',
                                                                              'category': 'encryption',
                                                                              'title': 'Application Gateway '
                                                                                       'and Front Door HTTPS '
                                                                                       'listeners use '
                                                                                       'approved predefined '
                                                                                       'SSL policies',
                                                                              'description': 'Each '
                                                                                             'applicable '
                                                                                             'HTTPS listener '
                                                                                             'uses the '
                                                                                             'frozen '
                                                                                             'requirement’s '
                                                                                             'approved '
                                                                                             'predefined SSL '
                                                                                             'policy.',
                                                                              'remediation_hint': 'Apply the '
                                                                                                  'approved '
                                                                                                  'predefined '
                                                                                                  'SSL '
                                                                                                  'policy to '
                                                                                                  'every '
                                                                                                  'applicable '
                                                                                                  'Application '
                                                                                                  'Gateway '
                                                                                                  'and Front '
                                                                                                  'Door '
                                                                                                  'HTTPS '
                                                                                                  'listener.'},
 'azure_vault_3_7_1_2_532ecd2': {'id': 'azure_vault_3_7_1_2_532ecd2',
                                 'provider': 'azure',
                                 'resource_kind': 'key_vault_certificate',
                                 'data_source': 'Paged Key Vault data-plane GET /certificates and GET '
                                                '/certificates/{name} current issued version, with X.509 '
                                                'certificate bytes or backing public key used to measure '
                                                'actual RSA modulus. Optional GET '
                                                '/certificates/{name}/policy?api-version=7.4 supplies '
                                                'future-issuance context only.',
                                 'predicate': 'For every current RSA or RSA-HSM certificate, require the '
                                              'actual issued X.509 public key modulus to be at least 2048 '
                                              'bits. FAIL on a measured smaller issued RSA key; PASS when '
                                              'every current RSA certificate is measured at least 2048 bits '
                                              'with complete inventory. UNKNOWN for unreadable current '
                                              'version, key type/size or incomplete pages; EC certificates '
                                              'are NOT_APPLICABLE. Renewal policy key_props.key_size is '
                                              'supporting future-issuance context and cannot substitute for '
                                              'the issued key measurement.',
                                 'severity': 'medium',
                                 'category': 'encryption',
                                 'title': 'Current Key Vault RSA certificates use at least 2048-bit keys',
                                 'description': 'Checks the RSA modulus length of each current issued Key '
                                                'Vault certificate.',
                                 'remediation_hint': 'Set RSA issuance/renewal policy size to at least 2048 '
                                                     'and reissue every current undersized RSA certificate; '
                                                     'verify the new certificate public key size.'},
 'azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3': {'id': 'azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3',
                                                                 'provider': 'azure',
                                                                 'resource_kind': 'key_vault_certificate',
                                                                 'data_source': 'Key Vault data plane GET '
                                                                                '/certificates?api-version=7.4 '
                                                                                '(paged), then GET '
                                                                                '/certificates/{name}?api-version=7.4 '
                                                                                'for current version: '
                                                                                'attributes.enabled boolean, '
                                                                                'attributes.exp integer Unix '
                                                                                'seconds; policy '
                                                                                'expirationWithinDays.',
                                                                 'predicate': 'For each currently enabled '
                                                                              'certificate from complete '
                                                                              'paged /certificates '
                                                                              'enumeration, GET its current '
                                                                              'version. PASS when '
                                                                              'attributes.exp is an integer '
                                                                              'Unix timestamp later than '
                                                                              'scanTime plus the approved '
                                                                              'expirationWithinDays. FAIL '
                                                                              'when a complete current '
                                                                              'certificate has no expiry or '
                                                                              'is within that window. '
                                                                              'UNKNOWN if the threshold, '
                                                                              'pages, current-version '
                                                                              'resolution or authorization '
                                                                              'is missing. No enabled '
                                                                              'certificates is '
                                                                              'NOT_APPLICABLE.',
                                                                 'severity': 'medium',
                                                                 'category': 'encryption',
                                                                 'title': 'Enabled Key Vault certificates '
                                                                          'are outside the expiry window',
                                                                 'description': 'Checks expiration '
                                                                                'timestamps of enabled Key '
                                                                                'Vault certificates.',
                                                                 'remediation_hint': 'In Key Vault > '
                                                                                     'Certificates, renew '
                                                                                     'each expiring '
                                                                                     'certificate and set an '
                                                                                     'expiry date beyond '
                                                                                     'expirationWithinDays; '
                                                                                     'disable certificates '
                                                                                     'no longer in use.'},
 'azure_purview_account_a3_2_5_1_1_282bac6': {'id': 'azure_purview_account_a3_2_5_1_1_282bac6',
                                              'provider': 'azure',
                                              'resource_kind': 'purview_account',
                                              'data_source': 'Purview Scanning data-plane 2023-09-01 paged '
                                                             'data sources, scans ListByDataSource, and '
                                                             'scan-result ListScanHistory per scan; read '
                                                             'recurrence/schedule, scan '
                                                             'ruleset/classification coverage and run '
                                                             'status. Policy inputs: account applicability '
                                                             '(administrator/member), in-scope source '
                                                             'inventory, required sensitive-data '
                                                             'classification rules and scan recency.',
                                              'predicate': 'For applicable administrator accounts, PASS only '
                                                           'if every in-scope data source has an enabled '
                                                           'recurring scan configured to discover sensitive '
                                                           'data with the required classification rules and '
                                                           'a recent successful completed run within the '
                                                           'approved window. FAIL if complete '
                                                           'scans/runs/ruleset evidence proves automated '
                                                           'sensitive discovery disabled, failed or overdue. '
                                                           'UNKNOWN if account type, source scope, '
                                                           'classification coverage, schedule, run history '
                                                           'or paging is unresolved. Member accounts are '
                                                           'NOT_APPLICABLE only when account type is '
                                                           'verified.',
                                              'severity': 'medium',
                                              'category': 'hardening',
                                              'title': 'Required Purview data sources run recurring '
                                                       'successful scans',
                                              'description': 'Checks scheduled scans and latest run status '
                                                             'for specifically named Purview data sources.',
                                              'remediation_hint': 'For administrator accounts, enable '
                                                                  'scheduled Purview scans with '
                                                                  'sensitive-data classification rules on '
                                                                  'every required source and resolve failed '
                                                                  'or overdue runs.'}}

SPEC_SHA256 = {'azure.gap.compute_vm_scale_set_automatic_upgrade_enabled': '2ee41fd24fe2116b27f2b3104c58dcccb08cb23a82233e9e5a699e8403206720',
 'azure.gap.compute_vm_scale_set_endpoint_protection_solution_installed': 'e4bc588679a51be447555c63031a8663f46dd3832321d71ed46b153b33a10527',
 'azure.gap.compute_vm_scale_set_security_configuration_vulnerabilities_remediated': '55a5a27eb638e2bc0ffebf7fa73f557985180fd4f245313bf1f31ba95a7b8f9b',
 'azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled': '8efe6c39ac000c2eb0b0d0cc1b8b2c7e603275aca30301f4c93d016999ed2b1f',
 'azure.other.disabled_identity_24h': '6124c6fa142a86901e813a884093a4348908d8af318257970c3034e1069dc137',
 'azure.other.human_federated_signin': '0fd7446b5efc6b85506fe03007914eb2193f9ccbc7dde69dbc6addda07ecd29d',
 'azure.other.certificate_rotation_180_days': '8e6afb784a929159e1ac81b32afe2bc6a1b9e3be7c1d465b87e6d124be98d374',
 'azure.other.certificate_rotation_90_days': 'aab44f51fa4e58e02b4735e0152bfa1f2f5bafaa5c05b2d8b7f07c0fbd6d09fb',
 'azure.other.metric_ingestion_rate_alert': '6378e89e45fce4d89cf820eb79f60dff8bf2dcb45c0f8038a4c0870834d07fe1',
 'azure.other.monitor_stream_auth': '3042bb8d537e2cfdc013c655093f9e5dc40e991b62f78a356d8f50d131cbf436',
 'azure_application_gateway_app_ensure_http_is_redirected_to_https_debad63': '975ca416ea9047612ec6b2f0eb6269b6cac001b82c30c61bd6cd254174eb3683',
 'azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17': '68b16321aaa5d420e33b4bb7f4914bdb2d3cd56cd542e33cade197ee5937c364',
 'azure_vault_3_7_1_2_532ecd2': '8a844f542ab2db5658b90b1b2d0b54f6973f0a3d52a45c436a486bb3704eb4d1',
 'azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3': '9530b6f8c1ce547f926980024ec6a442d500270a9796baafea1ab105fe59721b',
 'azure_purview_account_a3_2_5_1_1_282bac6': '6424ee85f47a4feaeffea070d3a61b458ef824305fbb3678025e7c4d4309f191'}

IDS = tuple(SPECS)

UPGRADE, ENDPOINT, VULNERABILITY, MFA, DISABLED, FEDERATED, ROTATE180, ROTATE90, RATE, AUTH, HTTPS, SSL, RSA, EXPIRY, PURVIEW = IDS
_CATEGORIES = {"hardening", "exposure", "least_privilege", "iam_graph", "network"}


def signed(check_id, *dependencies):
    """Register with the signed category, retaining the legacy validator."""
    spec = SPECS[check_id]
    def decorate(function):
        def dispatch(item, index):
            if (get(item, "provider", str) != "azure" or
                    get(item, "scope", str).casefold() != _scope(index).casefold()):
                raise Unavailable("foreign scope subject")
            return function(item, index)
        register(check_id, spec["provider"], spec["category"] if spec["category"] in _CATEGORIES else "hardening",
                 spec["resource_kind"], spec["title"], spec["severity"], "CM-6", spec["remediation_hint"],
                 target="scope", dependencies=list(dependencies))(dispatch)
        if CHECKS[-1].id != check_id:
            raise RuntimeError("unexpected registry order")
        CHECKS[-1] = replace(CHECKS[-1], category=spec["category"])
        return function
    return decorate


def _text(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise Unavailable("empty or malformed identity")
    return value


def _strings(value):
    if not isinstance(value, list):
        raise Unavailable("string inventory missing")
    values = [_text(v) for v in value]
    if len(values) != len(set(values)):
        raise Unavailable("duplicate string inventory")
    return values


def _time(value):
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("malformed timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Unavailable("timestamp requires timezone")
    return parsed


def _scope(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("Azure provider authority unavailable")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"/subscriptions/[A-Za-z0-9-]+", scope, re.I):
        raise Unavailable("Azure subscription authority unavailable")
    return scope


def _clock(index):
    return _time(get(get(index, "context", dict), "created_at", str))


def _fresh(row, index, seconds):
    if type(seconds) is not int or seconds <= 0:
        raise Unavailable("invalid evidence freshness policy")
    elapsed = (_clock(index) - _time(get(row, "observed_at", str))).total_seconds()
    if not 0 <= elapsed <= seconds:
        raise Unavailable("stale or future evidence")


def _policy(index):
    policy = get(index, "context.metadata.compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str).casefold() != _scope(index).casefold():
        raise Unavailable("missing or foreign subscription policy")
    _fresh(policy, index, get(policy, "max_age_seconds", int))
    return get(policy, "parameters", dict)


def _positive(policy, key):
    value = get(policy, key, int)
    if value <= 0:
        raise Unavailable("policy threshold must be positive")
    return value


def _identity(row, scope):
    identity = _text(get(row, "id", str))
    if identity.casefold().startswith("/subscriptions/"):
        if not identity.casefold().startswith(scope.casefold() + "/"):
            raise Unavailable("foreign Azure resource identity")
        if not re.fullmatch(r"/subscriptions/[^/?#]+/(?:[^/?#]+/)*[^/?#]+", identity, re.I):
            raise Unavailable("malformed Azure resource identity")
    elif get(row, "subscription_id", str).casefold() != scope.casefold():
        raise Unavailable("foreign external evidence subscription")
    return identity.casefold()


def _inventory(index, kind):
    scope = _scope(index)
    envelopes = get(get(index, "collections", dict), kind, list)
    if len(envelopes) != 1:
        raise Unavailable("ambiguous scoped collection")
    envelope = envelopes[0]
    if get(envelope, "type", str) != kind or get(envelope, "scope", str).casefold() != scope.casefold():
        raise Unavailable("foreign collection scope")
    native = complete_items(index, kind)
    if list_of_objects(get(envelope, "items", list)) != native:
        raise Unavailable("collection projection differs from complete envelope")
    if envelope["status"] == "empty" and native:
        raise Unavailable("nonempty empty inventory")
    wrappers = get(index, kind, list)
    if any(get(w, "type", str) != kind or get(w, "scope", str).casefold() != scope.casefold() for w in wrappers):
        raise Unavailable("foreign resource wrapper")
    identities = [_identity(row, scope) for row in native]
    if len(identities) != len(set(identities)):
        raise Unavailable("duplicate resource identity")
    return native


def _source(row, operation):
    provenance = get(row, "_provenance", dict)
    if get(provenance, "source_operation", str) != operation or get(provenance, "read_only", bool) is not True:
        raise Unavailable("source operation authority unavailable")


def _detail(row, key, operation):
    detail = get(row, key, dict)
    if get(detail, "parent_id", str).casefold() != get(row, "id", str).casefold():
        raise Unavailable("foreign child evidence")
    if get(detail, "collection_status", str) not in {"collected", "empty"}:
        raise Unavailable("child evidence incomplete")
    _source(detail, operation)
    values = list_of_objects(get(detail, "items", list))
    if detail["collection_status"] == "empty" and values:
        raise Unavailable("nonempty empty child evidence")
    identities = [_text(get(value, "id", str)).casefold() for value in values if "id" in value]
    if len(identities) != len(set(identities)):
        raise Unavailable("duplicate child evidence identity")
    return values


def _one(rows, field, identity):
    matches = [row for row in rows if get(row, field, str).casefold() == identity.casefold()]
    if len(matches) != 1:
        raise Unavailable("missing or ambiguous exact evidence join")
    return matches[0]


def _aggregate(rows, evaluate, *, empty="NOT_APPLICABLE"):
    outcomes = []
    for row in rows:
        try:
            outcomes.append(evaluate(row))
        except Unavailable as exc:
            outcomes.append(unknown(str(exc)))
    statuses = [status for status, _ in outcomes]
    status = next((s for s in ("FAIL", "UNKNOWN", "PASS") if s in statuses), "NOT_APPLICABLE" if outcomes else empty)
    return status, {"evaluated_count": len(rows), "outcomes": [dict(status=s, **e) for s, e in outcomes]}


def _arm_type(row, native_type):
    if get(row, "type", str).casefold() != native_type.casefold():
        raise Unavailable("resource type mismatches evidence")
    if not re.fullmatch(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/" + re.escape(native_type) + r"/[^/?#]+", get(row, "id", str), re.I):
        raise Unavailable("resource identity mismatches type")


@signed(UPGRADE, "vm_scale_set")
def automatic_os_upgrade(item, index):
    rows = _inventory(index, "vm_scale_set")
    def evaluate(row):
        _arm_type(row, "Microsoft.Compute/virtualMachineScaleSets")
        image = get(row, "properties.virtualMachineProfile.storageProfile.imageReference", dict)
        eligibility = get(row, "automaticOSUpgradeEligibility", dict)
        _source(eligibility, "platform_image_upgrade_capability")
        _fresh(eligibility, index, _positive(_policy(index), "upgradeEligibilityMaxAgeSeconds"))
        if (get(eligibility, "resource_id", str).casefold() != row["id"].casefold() or
                get(eligibility, "imageReference", dict) != image or
                get(eligibility, "upgradeMode", str) != get(row, "properties.upgradePolicy.mode", str)):
            raise Unavailable("upgrade eligibility does not match VMSS model")
        supported = get(eligibility, "supported", bool)
        _text(get(eligibility, "basis", str))
        if not supported:
            return "NOT_APPLICABLE", {"reason": "documented unsupported VMSS image or upgrade mode"}
        if "id" in image or any(not _text(get(image, field, str)) for field in ("publisher", "offer", "sku", "version")):
            raise Unavailable("supported platform image unresolved")
        if eligibility["upgradeMode"] not in {"Manual", "Automatic", "Rolling"}:
            raise Unavailable("unrecognized VMSS upgrade mode")
        enabled = get(row, "properties.upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade", bool)
        return result(not enabled, resource_id=row["id"], automatic_os_upgrade=enabled)
    return _aggregate(rows, evaluate)


def _assessments(index, key, category):
    rows = _inventory(index, "security_assessment")
    matches = []
    for row in rows:
        name = get(row, "name", str)
        resource = get(row, "properties.resourceDetails.id", str)
        _identity({"id": resource}, _scope(index))
        if name == key:
            if "/providers/microsoft.compute/virtualmachinescalesets/" not in resource.casefold():
                # The same Defender key can assess ordinary VMs; they do not
                # establish or contradict a VMSS/instance recommendation.
                continue
            if not re.fullmatch(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft.Compute/virtualMachineScaleSets/[^/?#]+(?:/virtualMachines/[^/?#]+)?", resource, re.I):
                raise Unavailable("malformed assessed VMSS resource identity")
            metadata = get(row, "assessmentMetadata", dict)
            _source(metadata, "assessment_metadata_get")
            if get(metadata, "key", str) != key or get(metadata, "category", str) != category:
                raise Unavailable("assessment key measures another recommendation")
            resource_type = get(metadata, "resource_type", str).casefold()
            expected_type = "microsoft.compute/virtualmachinescalesets/virtualmachines" if "/virtualmachines/" in resource.casefold() else "microsoft.compute/virtualmachinescalesets"
            if resource_type != expected_type:
                raise Unavailable("assessment resource contract does not match VMSS/instance scope")
            if get(row, "id", str).casefold() != (resource.rstrip("/") + "/providers/Microsoft.Security/assessments/" + key).casefold():
                raise Unavailable("assessment identity or resource scope mismatch")
            matches.append(row)
    return matches


@signed(VULNERABILITY, "vm_scale_set", "security_assessment")
def os_vulnerabilities(item, index):
    vmss = _inventory(index, "vm_scale_set")
    if not vmss:
        return "NOT_APPLICABLE", {"reason": "complete empty VMSS inventory"}
    policy = _policy(index)
    keys = _strings(get(policy, "requiredOsVulnerabilityAssessmentKeys", list))
    if not keys:
        return unknown("required OS-vulnerability assessment keys unavailable")
    age = _positive(policy, "assessmentMaxAgeSeconds")
    assessments = {key: _assessments(index, key, "os-vulnerability") for key in keys}
    def evaluate(row):
        _arm_type(row, "Microsoft.Compute/virtualMachineScaleSets")
        def assess(key):
            fact = _one(assessments[key], "properties.resourceDetails.id", row["id"])
            _fresh(fact, index, age)
            code = get(fact, "properties.status.code", str)
            if code not in {"Healthy", "Unhealthy"}:
                raise Unavailable("OS-vulnerability assessment not current/applicable")
            return result(code == "Unhealthy", resource_id=row["id"], assessment_key=key, assessment_status=code)
        return _aggregate(keys, assess, empty="UNKNOWN")
    return _aggregate(vmss, evaluate)


@signed(ENDPOINT, "vm_scale_set", "security_assessment")
def endpoint_protection(item, index):
    vmss = _inventory(index, "vm_scale_set")
    if not vmss:
        return "NOT_APPLICABLE", {"reason": "complete empty VMSS inventory"}
    policy = _policy(index)
    key = _text(get(policy, "endpointProtectionAssessmentKey", str))
    age = _positive(policy, "endpointProtectionMaxAgeSeconds")
    assessments = _assessments(index, key, "endpoint-protection")
    def evaluate(row):
        _arm_type(row, "Microsoft.Compute/virtualMachineScaleSets")
        instances = _detail(row, "instances", "virtual_machine_scale_set_vms_list")
        identities = []
        for instance in instances:
            iid = _text(get(instance, "id", str))
            if not re.fullmatch(re.escape(row["id"]) + r"/virtualMachines/[^/?#]+", iid, re.I):
                raise Unavailable("foreign or malformed VMSS instance")
            identities.append(iid.casefold())
        if len(identities) != len(set(identities)):
            raise Unavailable("duplicate VMSS instance")
        if not instances:
            return "NOT_APPLICABLE", {"reason": "no current VMSS instances"}
        applicable_assessments = [a for a in assessments if get(a, "properties.resourceDetails.id", str).casefold() in {row["id"].casefold(), *identities}]
        if not applicable_assessments:
            raise Unavailable("endpoint assessment scope/key unresolved for this VMSS")
        seen_targets = set()
        for assessment in applicable_assessments:
            target = assessment["properties"]["resourceDetails"]["id"].casefold()
            if target in seen_targets:
                raise Unavailable("conflicting endpoint assessment")
            seen_targets.add(target)
            _fresh(assessment, index, age)
            code = get(assessment, "properties.status.code", str)
            if code not in {"Healthy", "Unhealthy", "NotApplicable"}:
                raise Unavailable("unrecognized endpoint assessment status")
            if code == "Unhealthy":
                return result(True, assessed_resource=target, assessment_key=key)
        def agent(instance):
            fact = get(instance, "endpointProtection", dict)
            _source(fact, "endpoint_agent_health_read")
            if get(fact, "resource_id", str).casefold() != instance["id"].casefold():
                raise Unavailable("foreign endpoint agent evidence")
            _fresh(fact, index, age)
            if not get(fact, "applicable", bool):
                _text(get(fact, "not_applicable_reason", str))
                return "NOT_APPLICABLE", {"resource_id": instance["id"]}
            return result(not get(fact, "installed", bool), resource_id=instance["id"])
        # Parent Healthy alone never proves installation on every instance.
        agent_status, agent_evidence = _aggregate(instances, agent)
        if agent_status != "UNKNOWN":
            return agent_status, agent_evidence
        for assessment in applicable_assessments:
            if assessment["properties"]["status"]["code"] != "Healthy":
                continue
            contract = assessment.get("fullInstanceCoverage")
            if contract is None:
                continue
            _source(contract, "documented_endpoint_assessment_instance_contract")
            _text(get(contract, "contract_reference", str))
            _fresh(contract, index, age)
            if (get(contract, "assessment_id", str).casefold() != assessment["id"].casefold() or
                    set(v.casefold() for v in _strings(get(contract, "covered_instance_ids", list))) != set(identities)):
                raise Unavailable("endpoint assessment does not cover every current instance")
            if get(contract, "confirms_agent_installation", bool):
                return result(False, resource_id=row["id"], assessment_key=key, full_instance_contract=True)
        return agent_status, agent_evidence
    return _aggregate(vmss, evaluate)


def _user(row, index):
    if get(row, "tenant_id", str) != get(index, "context.metadata.tenant_id", str):
        raise Unavailable("foreign Entra tenant")
    _text(get(row, "id", str))
    return get(row, "human", bool), get(row, "accountEnabled", bool)


def _resolved(row, fields):
    """Coverage means resolved source evidence, never the desired outcome."""
    coverage = get(row, "resolution", dict)
    for field in fields:
        if get(coverage, field, str) != "complete":
            raise Unavailable("effective evidence unresolved: " + field)
    if not _strings(get(row, "source_evidence_ids", list)):
        raise Unavailable("source evidence references absent")


def _scope_coverage(index, kind, operation, fields):
    """Additional universe coverage for normalized multi-service inventories."""
    envelope = get(get(index, "collections", dict), kind, list)[0]
    evidence = get(envelope, "scopeCoverage", dict)
    _source(evidence, operation)
    if get(evidence, "scope", str).casefold() != _scope(index).casefold():
        raise Unavailable("foreign universe coverage")
    _resolved(evidence, fields)
    return evidence


def _subscription_principal_universe(index, users, max_age):
    """A tenant roster is not the complete subscription authorization universe."""
    proof = _scope_coverage(index, 'entra_user',
        'subscription_effective_principal_universe_read',
        ('directRoleAssignments', 'inheritedGrants', 'transitiveGroups', 'activePim',
         'conditionalGrants', 'lighthouseDelegations', 'managedApplicationAccess',
         'principalClassification'))
    _fresh(proof, index, max_age)
    metadata = get(index, 'context.metadata', dict)
    tenant = _text(get(metadata, 'tenant_id', str)).casefold()
    if get(proof, 'managedTenantId', str).casefold() != tenant:
        raise Unavailable('subscription principal universe belongs to another tenant')
    principals = _strings(get(proof, 'principal_ids', list))
    normalized = {value.casefold() for value in principals}
    if len(normalized) != len(principals) or normalized != {get(user, 'id', str).casefold() for user in users}:
        raise Unavailable('subscription principal universe differs from evaluated roster')
    # Customer-tenant CA policies do not govern Lighthouse managing-tenant
    # users. This evaluator has no independently resolved foreign-tenant policy
    # adapter, so it cannot certify their MFA from local tenant evidence.
    delegated = _strings(get(proof, 'delegatedTenantIds', list))
    if any(value.casefold() != tenant for value in delegated):
        raise Unavailable('delegated managing-tenant MFA evidence unavailable')
    origin = get(proof, '_provenance', dict)
    for key in ('credential_context_id', 'customer_context_id'):
        if key in metadata or key in origin or key in proof:
            expected = _text(get(metadata, key, str))
            if get(origin, key, str) != expected or (key in proof and get(proof, key, str) != expected):
                raise Unavailable('subscription principal universe capture differs')
    return len(principals)


def _identity_evidence_join(row, index, user):
    """Reject explicit foreign identity, tenant, or capture on nested evidence."""
    metadata = get(index, "context.metadata", dict)
    provenance = get(row, "_provenance", dict) if "_provenance" in row else {}
    for facts in (row, provenance):
        for field in ("tenant_id", "source_idp_id", "source_subject_id"):
            if field in facts:
                expected = get(metadata, "tenant_id", str) if field == "tenant_id" else get(user, field, str)
                if get(facts, field, str) != expected:
                    raise Unavailable("foreign identity evidence " + field)
    for field in ("credential_context_id", "customer_context_id"):
        if field in metadata or field in row or field in provenance:
            expected = _text(get(metadata, field, str))
            if get(provenance, field, str) != expected or (field in row and get(row, field, str) != expected):
                raise Unavailable("identity evidence capture differs")


@signed(MFA, "entra_user")
def subscription_mfa(item, index):
    users = _inventory(index, "entra_user")
    if not users:
        _subscription_principal_universe(index, users,
            _positive(_policy(index), "identityEvidenceMaxAgeSeconds"))
        return "NOT_APPLICABLE", {"reason": "complete subscription principal universe is empty"}
    policy = _policy(index)
    contexts = _strings(get(policy, "requiredManagementSignInContexts", list))
    if not contexts:
        return unknown("approved Azure management sign-in contexts absent")
    approved_strengths = _strings(get(policy, "mfaAuthenticationStrengthIds", list))
    age = _positive(policy, "identityEvidenceMaxAgeSeconds")
    def evaluate(user):
        human, enabled = _user(user, index)
        if not human or not enabled:
            return "NOT_APPLICABLE", {"reason": "verified nonhuman or disabled principal"}
        grants = get(user, "effectiveSubscriptionGrants", dict)
        _source(grants, "effective_subscription_authorization_read")
        _identity_evidence_join(grants, index, user)
        _fresh(grants, index, age)
        if get(grants, "subscription_id", str).casefold() != _scope(index).casefold() or get(grants, "principal_id", str) != user["id"]:
            raise Unavailable("foreign effective grant evidence")
        _resolved(grants, ("roleAssignments", "roleDefinitions", "inheritedGrants", "transitiveGroups", "activePim", "conditions"))
        privileges = _strings(get(grants, "privileges", list))
        if any(p not in {"owner", "read", "write"} for p in privileges):
            raise Unavailable("unrecognized effective privilege")
        if not privileges:
            return "NOT_APPLICABLE", {"reason": "complete grant resolution proves no subscription privilege"}
        decisions = _detail(user, "managementSignInDecisions", "effective_management_signin_policy_read")
        _identity_evidence_join(get(user, "managementSignInDecisions", dict), index, user)
        def decision(context):
            fact = _one(decisions, "context_id", context)
            _identity_evidence_join(fact, index, user)
            _fresh(fact, index, age)
            if get(fact, "principal_id", str) != user["id"] or get(fact, "subscription_id", str).casefold() != _scope(index).casefold():
                raise Unavailable("foreign management sign-in decision")
            _resolved(fact, ("conditionalAccess", "conditions", "exclusions", "securityDefaults", "authenticationStrengths"))
            # All possible permitted policy paths must require MFA. An OR
            # control containing a non-MFA alternative does not enforce MFA.
            paths = list_of_objects(get(fact, "allowed_paths", list))
            if not paths:
                raise Unavailable("no permitted sign-in path to measure MFA enforcement")
            unresolved = None
            for path in paths:
                try:
                    controls = _strings(get(path, "required_controls", list))
                    strengths = _strings(get(path, "required_authentication_strength_ids", list))
                except Unavailable as exc:
                    unresolved = exc
                    continue
                if not ("mfa" in controls or any(s in approved_strengths for s in strengths)):
                    return result(True, principal_id=user["id"], context_id=context, reason="permitted sign-in path without MFA")
            if unresolved is not None:
                raise unresolved
            return result(False, principal_id=user["id"], context_id=context)
        return _aggregate(contexts, decision, empty="UNKNOWN")
    status, evidence = _aggregate(users, evaluate)
    if status in ('PASS', 'NOT_APPLICABLE'):
        try:
            count = _subscription_principal_universe(index, users, age)
        except Unavailable as exc:
            return unknown(str(exc), evaluated_count=len(users), local_outcomes=evidence['outcomes'])
        evidence = {**evidence, 'principal_universe_verified': True, 'universe_principal_count': count}
    return status, evidence


@signed(DISABLED, "entra_user", "idp_identity_event")
def disabled_identity_deadline(item, index):
    users = _inventory(index, "entra_user")
    events = _inventory(index, "idp_identity_event")
    now = _clock(index)
    age = _positive(_policy(index), "identityEvidenceMaxAgeSeconds")
    # Distinct record IDs do not make an identical upstream transition two
    # independent events. Reject ambiguity before aggregating per-event PASS.
    event_keys = [(_text(get(event, "source_idp_id", str)),
                   _text(get(event, "source_subject_id", str)),
                   _text(get(event, "event_type", str)),
                   _time(get(event, "event_time", str))) for event in events]
    if len(event_keys) != len(set(event_keys)):
        raise Unavailable("duplicate upstream identity lifecycle event")
    def evaluate(event):
        _source(event, "authoritative_idp_identity_events")
        if get(event, "event_type", str) not in {"disable", "delete"}:
            raise Unavailable("unsupported authoritative IdP event")
        start = _time(get(event, "event_time", str))
        if start > now:
            raise Unavailable("future IdP event")
        source_idp = _text(get(event, "source_idp_id", str))
        subject = _text(get(event, "source_subject_id", str))
        matches = [user for user in users
                   if get(user, "source_idp_id", str) == source_idp
                   and get(user, "source_subject_id", str) == subject]
        if len(matches) != 1:
            raise Unavailable("missing or ambiguous IdP subject mapping")
        user = matches[0]
        _user(user, index)
        if now - start <= timedelta(hours=24):
            return unknown("IdP event pending the 24-hour deadline", event_id=event["id"])
        removal = get(user, "cloudAccessRemoval", dict)
        _source(removal, "cloud_identity_access_history_read")
        _fresh(removal, index, age)
        if get(removal, "principal_id", str) != user["id"]:
            raise Unavailable("foreign cloud identity history")
        _resolved(removal, ("identityMapping", "usersAndDeletedItems", "directoryRoles", "armRoles", "transitiveGroups", "cloudPolicies", "auditHistory"))
        identity_active = get(removal, "identity_active", bool)
        policies_active = get(removal, "effective_policies_active", bool)
        if identity_active != get(user, "accountEnabled", bool):
            raise Unavailable("cloud removal history contradicts current identity state")
        if identity_active or policies_active:
            return result(True, event_id=event["id"], principal_id=user["id"], identity_active=identity_active, effective_policies_active=policies_active)
        changed = [_time(get(removal, field, str)) for field in ("identity_inactive_at", "effective_policies_inactive_at")]
        if any(t > now for t in changed):
            raise Unavailable("future cloud removal timestamp")
        # Already disabled before the event also meets the deadline.
        if any(t > start + timedelta(hours=24) for t in changed):
            return result(True, event_id=event["id"], principal_id=user["id"], reason="authoritative dated removal exceeded 24-hour deadline", removal_times=[t.isoformat() for t in changed])
        return result(False, event_id=event["id"], principal_id=user["id"], removal_times=[t.isoformat() for t in changed])
    return _aggregate(events, evaluate)


@signed(FEDERATED, "entra_user", "human_signin_history", "domain_federation")
def human_federation(item, index):
    def supplied_source(row, operation, user):
        # Preserve the operation/read-only trust contract, while refusing
        # explicit foreign facts or a cross-customer/credential capture join.
        _source(row, operation)
        _identity_evidence_join(row, index, user)
    users = _inventory(index, "entra_user")
    histories = _inventory(index, "human_signin_history")
    domains = _inventory(index, "domain_federation")
    policy = _policy(index)
    days = _positive(policy, "federationLookbackDays")
    issuers = _strings(get(policy, "approvedFederatedIssuerIds", list))
    if not issuers:
        return unknown("approved federated IdP mapping absent")
    now = _clock(index)
    def evaluate(user):
        human, _ = _user(user, index)
        if not human:
            return "NOT_APPLICABLE", {"reason": "verified nonhuman identity"}
        history = _one(histories, "user_id", user["id"])
        supplied_source(history, "correlated_signin_idp_history_read", user)
        _resolved(history, ("signInPages", "idpPages", "humanClassification", "stableCorrelation"))
        retained_from = _time(get(history, "retained_from", str))
        retained_until = _time(get(history, "retained_until", str))
        if retained_until > now:
            raise Unavailable("future completed federation history coverage")
        if retained_from > now - timedelta(days=days) or retained_until < now:
            raise Unavailable("retention does not cover approved lookback")
        events = list_of_objects(get(history, "signIns", list))
        successful = []
        seen = set()
        for event in events:
            eid = _text(get(event, "id", str))
            if eid in seen or get(event, "userId", str) != user["id"]:
                raise Unavailable("duplicate or foreign sign-in event")
            seen.add(eid)
            when = _time(get(event, "createdDateTime", str))
            if not now - timedelta(days=days) <= when <= now:
                raise Unavailable("out-of-window sign-in evidence")
            error = get(event, "status.errorCode", int)
            if error < 0:
                raise Unavailable("malformed sign-in error code")
            if error == 0:
                successful.append(event)
        if not successful:
            return unknown("no successful human sign-in observations", principal_id=user["id"])
        proofs = list_of_objects(get(history, "authenticationEvidence", list))
        def authenticate(event):
            proof = _one(proofs, "signInId", event["id"])
            supplied_source(proof, "documented_authentication_issuer_evidence", user)
            if get(proof, "userId", str) != user["id"] or get(proof, "correlationId", str) != _text(get(event, "correlationId", str)):
                raise Unavailable("authentication issuer correlation unresolved")
            if _time(get(proof, "event_time", str)) != _time(event["createdDateTime"]):
                raise Unavailable("authentication evidence time mismatch")
            issuer = _text(get(proof, "issuer_id", str))
            method = get(proof, "authentication_kind", str)
            if method not in {"federated", "direct"}:
                raise Unavailable("authentication kind unresolved")
            return result(method != "federated" or issuer not in issuers, principal_id=user["id"], sign_in_id=event["id"], issuer_id=issuer)
        outcome = _aggregate(successful, authenticate, empty="UNKNOWN")
        if outcome[0] != "PASS":
            # A positively correlated direct or unapproved-issuer sign-in is
            # a violation regardless of today's domain configuration. Only
            # PASS needs the current federation configuration proof.
            return outcome
        domain = _one(domains, "domain_name", get(user, "domain_name", str))
        supplied_source(domain, "domain_federation_configuration_list", user)
        _fresh(domain, index, _positive(policy, "federationConfigMaxAgeSeconds"))
        if get(domain, "authenticationType", str) != "Federated" or get(domain, "issuer_id", str) not in issuers:
            raise Unavailable("current approved federation configuration unavailable")
        return outcome
    return _aggregate(users, evaluate, empty="UNKNOWN")


def _rotation(index, days):
    # vault_certificate is a normalized live binding record, never an unused
    # vault version. Exact serial + thumbprint joins avoid version-name guesses.
    endpoints = _inventory(index, "vault_certificate")
    issuance = _inventory(index, "certificate_issuance")
    coverage = _scope_coverage(index, "vault_certificate", "public_tls_universe_inventory_read", ("exposedPorts", "activeBindings", "pagination"))
    services = _strings(get(_policy(index), "approvedTlsServiceInventory", list))
    if not services or set(_strings(get(coverage, "covered_services", list))) != set(services):
        raise Unavailable("approved public TLS service inventory not fully measured")
    now = _clock(index)
    def evaluate(endpoint):
        _source(endpoint, "exposed_tls_endpoint_certificate_observation")
        if get(endpoint, "service_type", str) not in services:
            raise Unavailable("TLS endpoint service outside the approved measured universe")
        if not get(endpoint, "exposed", bool):
            return "NOT_APPLICABLE", {"reason": "verified non-exposed endpoint"}
        if get(endpoint, "binding_status", str) != "active":
            raise Unavailable("active certificate binding unresolved")
        _text(get(endpoint, "hostname", str))
        port = get(endpoint, "port", int)
        if not 1 <= port <= 65535:
            raise Unavailable("malformed endpoint port")
        _fresh(endpoint, index, _positive(_policy(index), "tlsObservationMaxAgeSeconds"))
        thumb = _text(get(endpoint, "thumbprint", str)).casefold()
        serial = _text(get(endpoint, "serial", str)).casefold()
        # A public leaf supplied by the endpoint observation must agree with
        # the labels used to join the independent CA record. A vault's public
        # certificate is not evidence that this leaf was served here.
        if "served_leaf_der" in endpoint:
            encoded = _text(get(endpoint, "served_leaf_der", str))
            if len(encoded) > 90000:
                raise Unavailable("served certificate exceeds public DER limit")
            try:
                der = base64.b64decode(encoded, validate=True)
                if not der or len(der) > 65536:
                    raise ValueError("public DER size")
                leaf = x509.load_der_x509_certificate(der)
            except (ValueError, TypeError, base64.binascii.Error) as exc:
                raise Unavailable("malformed served public certificate") from exc
            if hashlib.sha1(der).hexdigest() != thumb:
                raise Unavailable("served certificate thumbprint conflicts with observation")
            try:
                if int(serial, 16) != leaf.serial_number:
                    raise Unavailable("served certificate serial conflicts with observation")
            except ValueError as exc:
                raise Unavailable("malformed served certificate serial") from exc
            observed = _time(get(endpoint, "observed_at", str))
            if not leaf.not_valid_before_utc <= observed <= leaf.not_valid_after_utc:
                raise Unavailable("served certificate validity conflicts with observation")
        matches = [r for r in issuance if get(r, "thumbprint", str).casefold() == thumb and get(r, "serial", str).casefold() == serial]
        if len(matches) != 1:
            raise Unavailable("active certificate issuance join absent or ambiguous")
        fact = matches[0]
        _source(fact, "authoritative_certificate_issuance_read")
        authority = get(fact, "authority", str)
        if authority != "ca_issuance_record":
            raise Unavailable("independent CA issuance record unavailable")
        issued = _time(get(fact, "issued_at", str))
        if issued > now or issued > _time(get(endpoint, "observed_at", str)):
            raise Unavailable("certificate issuance is later than observation")
        too_old = now - issued > timedelta(days=days)
        if too_old:
            return result(True, endpoint_id=endpoint["id"], issuance_time=issued.isoformat(), maximum_age_days=days)
        if days == 90 and not get(endpoint, "enabled", bool):
            raise Unavailable("active bound certificate not confirmed enabled")
        return result(False, endpoint_id=endpoint["id"], issuance_time=issued.isoformat(), maximum_age_days=days)
    return _aggregate(endpoints, evaluate, empty="PASS")


@signed(ROTATE180, "vault_certificate", "certificate_issuance")
def certificate_rotation_180(item, index):
    return _rotation(index, 180)


@signed(ROTATE90, "vault_certificate", "certificate_issuance")
def certificate_rotation_90(item, index):
    return _rotation(index, 90)


@signed(RATE, "data_collection_rule", "scheduled_query_rule")
def metric_flood_controls(item, index):
    rules = _inventory(index, "data_collection_rule")
    alerts = _inventory(index, "scheduled_query_rule")
    _scope_coverage(index, "data_collection_rule", "metric_source_universe_inventory_read", ("customMetricSources", "pagination"))
    policy = _policy(index)
    threshold = _positive(policy, "metricFloodThreshold")
    window = _positive(policy, "metricFloodWindowSeconds")
    workspaces = _strings(get(policy, "approvedMetricWorkspaces", list))
    age = _positive(policy, "metricEvidenceMaxAgeSeconds")
    def evaluate(rule):
        _arm_type(rule, "Microsoft.Insights/dataCollectionRules")
        sources = _detail(rule, "metricSources", "custom_metric_source_inventory_read")
        def source(row):
            sid = _text(get(row, "id", str))
            if not get(row, "custom", bool):
                return "NOT_APPLICABLE", {"reason": "verified noncustom metric source"}
            evidence = get(row, "floodControls", dict)
            _source(evidence, "metric_throttle_alert_telemetry_read")
            if get(evidence, "source_id", str) != sid:
                raise Unavailable("foreign metric source evidence")
            _fresh(evidence, index, age)
            _resolved(evidence, ("rateLimitConfiguration", "alertInventory", "querySemantics", "actionDelivery", "floodTelemetry"))
            rate_enabled = get(evidence, "rate_limit_enabled", bool)
            alert_present = get(evidence, "alert_present", bool)
            if not rate_enabled or not alert_present:
                return result(True, source_id=sid, rate_limit_enabled=rate_enabled, alert_present=alert_present)
            if get(evidence, "threshold", int) != threshold or get(evidence, "window_seconds", int) != window:
                raise Unavailable("measured throttle threshold/window differ from policy")
            received = get(evidence, "received_count", int)
            ingested = get(evidence, "ingested_count", int)
            if received <= threshold or not 0 <= ingested <= received:
                raise Unavailable("flood telemetry does not exercise the policy threshold")
            alert = _one(alerts, "id", get(evidence, "alert_id", str))
            _arm_type(alert, "Microsoft.Insights/scheduledQueryRules")
            props = get(alert, "properties", dict)
            enabled = get(props, "enabled", bool)
            if not enabled or ingested > threshold:
                return result(True, source_id=sid, alert_enabled=enabled, received_count=received, ingested_count=ingested)
            scopes = _strings(get(props, "scopes", list))
            if not scopes or any(s not in workspaces for s in scopes):
                raise Unavailable("alert workspace outside approved scope")
            if get(props, "windowSize", str) != "PT" + str(window) + "S":
                # Native ARM ISO durations may use minutes/hours too.
                duration = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", props["windowSize"])
                if not duration or sum(int(v or 0) * m for v, m in zip(duration.groups(), (3600, 60, 1))) != window:
                    raise Unavailable("alert window differs from approved flood window")
            criteria = list_of_objects(get(props, "criteria.allOf", list))
            if not criteria:
                raise Unavailable("alert criteria absent")
            criterion = _one(criteria, "query", get(evidence, "verified_query", str))
            native_threshold = get(criterion, "threshold")
            if (type(native_threshold) not in (int, float) or not math.isfinite(native_threshold) or
                    native_threshold != threshold or get(criterion, "operator", str) != "GreaterThan"):
                raise Unavailable("alert threshold semantics differ from policy")
            actions = _strings(get(props, "actions.actionGroups", list))
            if get(evidence, "action_group_id", str) not in actions:
                raise Unavailable("verified delivery target not bound to alert")
            if not get(evidence, "action_reachable", bool) or not get(evidence, "alert_fired", bool):
                return result(True, source_id=sid, reason="complete flood evidence proves alert delivery absent")
            return result(False, source_id=sid, received_count=received, ingested_count=ingested)
        return _aggregate(sources, source)
    return _aggregate(rules, evaluate)


@signed(AUTH, "data_collection_rule")
def stream_authentication(item, index):
    rules = _inventory(index, "data_collection_rule")
    _scope_coverage(index, "data_collection_rule", "stream_universe_inventory_read", ("metricTraceTypes", "pagination"))
    age = _positive(_policy(index), "streamAuthEvidenceMaxAgeSeconds")
    def evaluate(rule):
        _arm_type(rule, "Microsoft.Insights/dataCollectionRules")
        streams = _detail(rule, "streamInventory", "metric_trace_stream_inventory_read")
        names = [_text(get(s, "name", str)) for s in streams]
        if len(names) != len(set(names)):
            raise Unavailable("duplicate stream type inventory")
        def stream(row):
            stream_type = get(row, "signal_type", str)
            if stream_type not in {"metric", "trace", "log"}:
                raise Unavailable("unknown ingestion signal type")
            if stream_type == "log":
                return "NOT_APPLICABLE", {"reason": "verified log-only stream"}
            tests = get(row, "authenticationEvidence", dict)
            _source(tests, "ingestion_authentication_logs_read")
            if get(tests, "stream_name", str) != row["name"] or get(tests, "rule_id", str).casefold() != rule["id"].casefold():
                raise Unavailable("foreign stream authentication evidence")
            _text(get(tests, "ingestion_endpoint", str))
            _fresh(tests, index, age)
            _resolved(tests, ("streamScope", "credentialTypeMapping", "dataPlaneObservations"))
            observations = list_of_objects(get(tests, "observations", list))
            seen = set()
            for obs in observations:
                kind = get(obs, "credential_kind", str)
                if kind not in {"authorized", "anonymous", "wrong_type"} or kind in seen:
                    raise Unavailable("authentication observation missing or ambiguous")
                seen.add(kind)
                if get(obs, "stream_name", str) != row["name"] or get(obs, "endpoint", str) != tests["ingestion_endpoint"]:
                    raise Unavailable("authentication observations apply to another type/endpoint")
                _text(get(obs, "request_id", str))
                accepted = get(obs, "accepted", bool)
                if kind != "anonymous":
                    _text(get(obs, "principal_id", str))
                    allowed = _strings(get(obs, "authorized_stream_types", list))
                    if (row["name"] in allowed) != (kind == "authorized"):
                        raise Unavailable("credential-to-type mapping contradicts observation")
                if kind in {"anonymous", "wrong_type"} and accepted:
                    return result(True, stream_name=row["name"], accepted_credential_kind=kind)
                if kind == "authorized" and not accepted:
                    raise Unavailable("authorized positive control did not reach ingestion")
            if seen != {"authorized", "anonymous", "wrong_type"}:
                raise Unavailable("required authentication observations missing")
            return result(False, stream_name=row["name"])
        return _aggregate(streams, stream)
    return _aggregate(rules, evaluate)


def _gateway(row):
    kind = get(row, "type", str)
    if kind.casefold() not in {"microsoft.network/applicationgateways", "microsoft.network/frontdoors"}:
        raise Unavailable("unsupported gateway/Front Door resource representation")
    _arm_type(row, kind)
    return kind.casefold()


@signed(HTTPS, "application_gateway_and_frontdoor")
def exposed_gateway_https(item, index):
    gateways = _inventory(index, "application_gateway_and_frontdoor")
    _scope_coverage(index, "application_gateway_and_frontdoor", "gateway_frontdoor_inventory_read", ("applicationGateways", "classicFrontDoors", "exposedHostnames", "pagination"))
    age = _positive(_policy(index), "tlsObservationMaxAgeSeconds")
    def evaluate(row):
        gateway_type = _gateway(row)
        endpoints = _detail(row, "exposedEndpoints", "gateway_exposed_endpoint_inventory_read")
        def endpoint(ep):
            _text(get(ep, "hostname", str))
            if not get(ep, "exposed", bool):
                return "NOT_APPLICABLE", {"reason": "verified non-exposed gateway endpoint"}
            listener_id = _text(get(ep, "listener_id", str))
            child_type = "httpListeners" if gateway_type == "microsoft.network/applicationgateways" else "frontendEndpoints"
            if not re.fullmatch(re.escape(row["id"] + "/" + child_type + "/") + r"[^/?#]+", listener_id, re.I):
                raise Unavailable("exposed listener belongs to another gateway or Front Door")
            _resolved(ep, ("hostname", "effectiveRouting", "httpsBinding", "certificateMaterial"))
            measured = get(ep, "tlsObservation", dict)
            _source(measured, "tls_handshake_validation_read")
            if get(measured, "hostname", str).casefold() != ep["hostname"].casefold() or get(measured, "listener_id", str).casefold() != ep["listener_id"].casefold():
                raise Unavailable("foreign TLS validation observation")
            _fresh(measured, index, age)
            if not get(measured, "reachable", bool):
                raise Unavailable("TLS endpoint unreachable")
            https = get(ep, "https_configured", bool)
            bound = get(ep, "certificate_bound", bool)
            if not https or not bound:
                return result(True, hostname=ep["hostname"], https_configured=https, certificate_bound=bound)
            if not get(measured, "handshake_valid", bool):
                return result(True, hostname=ep["hostname"], reason="measured TLS validation failure")
            if get(measured, "thumbprint", str).casefold() != _text(get(ep, "thumbprint", str)).casefold():
                raise Unavailable("TLS certificate differs from configured binding")
            valid = [get(measured, field, bool) for field in ("chain_valid", "hostname_valid", "time_valid", "handshake_valid")]
            return result(not all(valid), hostname=ep["hostname"], validation=dict(zip(("chain", "hostname", "time", "handshake"), valid)))
        return _aggregate(endpoints, endpoint)
    return _aggregate(gateways, evaluate)


def _children(props, name, parent):
    rows = list_of_objects(get(props, name, list))
    identities = []
    for row in rows:
        rid = _text(get(row, "id", str)).casefold()
        if not re.fullmatch(re.escape(parent + "/" + name + "/") + r"[^/?#]+", rid, re.I):
            raise Unavailable("foreign or malformed gateway child")
        identities.append(rid)
    if len(identities) != len(set(identities)):
        raise Unavailable("duplicate gateway child identity")
    return rows


@signed(SSL, "application_gateway_and_frontdoor")
def predefined_ssl_policy(item, index):
    gateways = _inventory(index, "application_gateway_and_frontdoor")
    _scope_coverage(index, "application_gateway_and_frontdoor", "gateway_frontdoor_inventory_read", ("applicationGateways", "classicFrontDoors", "pagination"))
    policy = _policy(index)
    approved = _text(get(policy, "approvedPredefinedSslPolicyName", str))
    def evaluate(row):
        kind = _gateway(row)
        props = get(row, "properties", dict)
        if kind == "microsoft.network/frontdoors":
            # Classic Front Door's minimumTlsVersion is not a predefined
            # Application Gateway SSL policy. Never synthesize that policy.
            endpoints = _children(props, "frontendEndpoints", row["id"])
            rules = _children(props, "routingRules", row["id"])
            applicable = set()
            for rule in rules:
                protocols = _strings(get(rule, "properties.acceptedProtocols", list))
                if any(p not in {"Http", "Https"} for p in protocols):
                    raise Unavailable("unsupported Front Door protocol")
                if "Https" in protocols:
                    for ref in list_of_objects(get(rule, "properties.frontendEndpoints", list)):
                        endpoint = _one(endpoints, "id", get(ref, "id", str))
                        applicable.add(endpoint["id"])
            for endpoint in endpoints:
                state = get(endpoint, "properties.customHttpsProvisioningState", str)
                if state not in {"Enabled", "Disabled", "Enabling", "Disabling", "Failed"}:
                    raise Unavailable("Front Door HTTPS binding state unresolved")
                if state != "Disabled":
                    applicable.add(endpoint["id"])
            if not applicable:
                return "NOT_APPLICABLE", {"reason": "no Front Door HTTPS listeners in complete declaration"}
            return unknown("classic Front Door does not expose the required predefined SSL policy representation")
        listeners = _children(props, "httpListeners", row["id"])
        profiles = _children(props, "sslProfiles", row["id"])
        def listener(row_listener):
            lp = get(row_listener, "properties", dict)
            protocol = get(lp, "protocol", str)
            if protocol not in {"Http", "Https"}:
                raise Unavailable("unsupported gateway listener protocol")
            if protocol == "Http":
                return "NOT_APPLICABLE", {"reason": "HTTP listener outside HTTPS SSL-policy scope"}
            # Explicit null marks a full GET's absent profile. Omission in a
            # projection is UNKNOWN, rather than assumed inheritance.
            if "sslProfileId" in lp:
                profile_id = get(lp, "sslProfileId")
                if profile_id is not None and not isinstance(profile_id, str):
                    raise Unavailable("malformed SSL profile ID")
                ref = None if profile_id is None else {"id": profile_id}
                if "sslProfile" in lp and get(lp, "sslProfile") != ref:
                    raise Unavailable("conflicting SSL profile references")
            else:
                ref = get(lp, "sslProfile")
            if ref is None:
                effective = get(props, "sslPolicy", dict)
            else:
                profile = _one(profiles, "id", get(ref, "id", str))
                effective = get(profile, "properties.sslPolicy", dict)
            typ = get(effective, "policyType", str)
            if typ not in {"Predefined", "Custom", "CustomV2"}:
                raise Unavailable("unknown effective SSL policy type")
            if typ != "Predefined":
                return result(True, listener_id=row_listener["id"], policy_type=typ)
            if "predefinedPolicyName" in effective:
                name = _text(get(effective, "predefinedPolicyName", str))
                if "policyName" in effective and get(effective, "policyName", str) != name:
                    raise Unavailable("conflicting predefined SSL policy names")
            else:
                name = _text(get(effective, "policyName", str))
            return result(name != approved, listener_id=row_listener["id"], configured_policy=name, required_policy=approved)
        return _aggregate(listeners, listener)
    return _aggregate(gateways, evaluate)


def _current_certificate(row):
    parent = _text(get(row, "parent_id", str))
    if not re.fullmatch(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft.KeyVault/vaults/[^/?#]+", parent, re.I):
        raise Unavailable("certificate vault parent unresolved")
    name = _text(get(row, "name", str))
    if not re.fullmatch(r"[A-Za-z0-9-]{1,127}", name) or get(row, "id", str).casefold() != (parent + "/certificates/" + name).casefold():
        raise Unavailable("foreign certificate native identity")
    origin = get(row, "vault_uri", str).rstrip("/")
    if not re.fullmatch(r"https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net", origin):
        raise Unavailable("certificate vault endpoint unresolved")
    fact = get(row, "currentCertificate", dict)
    _source(fact, "certificates_get_current")
    provenance = get(fact, "_provenance", dict)
    if get(provenance, "request_uri", str) != origin + "/certificates/" + name or get(provenance, "representation", str) != "full":
        raise Unavailable("complete unversioned current certificate GET unavailable")
    if not re.fullmatch(re.escape(origin + "/certificates/" + name + "/") + r"[A-Za-z0-9-]+", get(fact, "id", str)):
        raise Unavailable("current certificate version unresolved or foreign")
    return fact


@signed(RSA, "key_vault_certificate")
def issued_rsa_size(item, index):
    rows = _inventory(index, "key_vault_certificate")
    _scope_coverage(index, "key_vault_certificate", "vault_current_certificate_inventory_read", ("vaults", "certificatePages", "currentVersions"))
    def evaluate(row):
        fact = _current_certificate(row)
        try:
            from cryptography import x509
            from cryptography.exceptions import UnsupportedAlgorithm
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
        except ImportError as exc:
            raise Unavailable("current issued X.509 parser unavailable") from exc
        try:
            encoded = get(fact, "cer", str)
            public = x509.load_der_x509_certificate(base64.b64decode(encoded, validate=True)).public_key()
        except (ValueError, TypeError, x509.InvalidVersion, UnsupportedAlgorithm) as exc:
            raise Unavailable("current issued X.509 public key unreadable") from exc
        if isinstance(public, ec.EllipticCurvePublicKey):
            return "NOT_APPLICABLE", {"reason": "current certificate has an EC public key"}
        if not isinstance(public, rsa.RSAPublicKey):
            raise Unavailable("current certificate public key type unsupported")
        bits = public.public_numbers().n.bit_length()
        return result(bits < 2048, certificate_id=fact["id"], measured_rsa_modulus_bits=bits)
    return _aggregate(rows, evaluate)


@signed(EXPIRY, "key_vault_certificate")
def enabled_certificate_expiry(item, index):
    rows = _inventory(index, "key_vault_certificate")
    _scope_coverage(index, "key_vault_certificate", "vault_current_certificate_inventory_read", ("vaults", "certificatePages", "currentVersions"))
    if not rows:
        return "NOT_APPLICABLE", {"reason": "no current enabled certificates in complete inventory"}
    days = _positive(_policy(index), "expirationWithinDays")
    threshold = _clock(index).timestamp() + days * 86400
    def evaluate(row):
        fact = _current_certificate(row)
        attrs = get(fact, "attributes", dict)
        if not get(attrs, "enabled", bool):
            return "NOT_APPLICABLE", {"reason": "current certificate explicitly disabled"}
        if "exp" not in attrs:
            # Missing expiry is adverse only after the full current GET. A
            # denied/partial field remains unavailable even on that GET.
            coverage = get(attrs, "_coverage", dict) if "_coverage" in attrs else {}
            if "exp" in coverage:
                raise Unavailable("expiry fact masked or unavailable")
            return result(True, certificate_id=fact["id"], reason="full current certificate has no expiry")
        exp = get(attrs, "exp")
        if exp is None:
            return result(True, certificate_id=fact["id"], reason="full current certificate has no expiry")
        if type(exp) is not int or exp < 0:
            raise Unavailable("malformed certificate Unix expiry")
        return result(exp <= threshold, certificate_id=fact["id"], expires_at_unix=exp, expiration_window_days=days)
    return _aggregate(rows, evaluate)


@signed(PURVIEW, "purview_account")
def recurring_sensitive_discovery(item, index):
    accounts = _inventory(index, "purview_account")
    def evaluate(account):
        _arm_type(account, "Microsoft.Purview/accounts")
        applicability = get(account, "accountApplicability", dict)
        _source(applicability, "purview_account_applicability_read")
        if get(applicability, "account_id", str).casefold() != account["id"].casefold():
            raise Unavailable("foreign Purview account applicability")
        typ = get(applicability, "account_type", str)
        if typ == "member":
            return "NOT_APPLICABLE", {"reason": "verified Purview member account"}
        if typ != "administrator":
            raise Unavailable("Purview account type unresolved")
        policy = _policy(index)
        required_by_account = get(policy, "purviewRequiredSources", dict)
        names = _strings(get({"sources": required_by_account.get(account["id"])}, "sources", list))
        classifications = _strings(get(policy, "requiredSensitiveClassificationRules", list))
        if not classifications:
            raise Unavailable("sensitive classification policy absent")
        age = _positive(policy, "purviewScanRecencySeconds")
        sources = _detail(account, "dataSources", "purview_data_sources_list")
        def source(name):
            source_row = _one(sources, "name", name)
            if get(source_row, "id", str).casefold() != (account["id"] + "/dataSources/" + name).casefold():
                raise Unavailable("foreign Purview source identity")
            scans = _detail(source_row, "scans", "purview_scans_list_by_data_source")
            def scan(scan_row):
                if not re.fullmatch(re.escape(source_row["id"] + "/scans/") + r"[^/?#]+", get(scan_row, "id", str), re.I):
                    raise Unavailable("foreign Purview scan identity")
                config = get(scan_row, "properties", dict)
                enabled = get(config, "enabled", bool)
                recurring = get(config, "recurring", bool)
                ruleset = get(scan_row, "classificationRuleset", dict)
                _source(ruleset, "purview_scan_ruleset_read")
                if get(ruleset, "scan_id", str) != get(scan_row, "id", str) or get(ruleset, "collection_status", str) != "collected":
                    raise Unavailable("classification ruleset unreadable or foreign")
                covered = _strings(get(ruleset, "classification_rules", list))
                history = _detail(scan_row, "runs", "purview_scan_history_list")
                run_outcomes = []
                for run in history:
                    status = get(run, "status", str)
                    if status not in {"Succeeded", "Failed", "Canceled", "InProgress", "Queued"}:
                        raise Unavailable("unrecognized Purview scan status")
                    when = _time(get(run, "started_at", str))
                    if when > _clock(index):
                        raise Unavailable("future Purview run")
                    if status == "Succeeded":
                        completed = _time(get(run, "completed_at", str))
                        if not when <= completed <= _clock(index):
                            raise Unavailable("Purview completion time unresolved")
                        if (_clock(index) - completed).total_seconds() <= age:
                            run_outcomes.append(True)
                    elif status in {"InProgress", "Queued"}:
                        run_outcomes.append(None)
                if not enabled or not recurring or not set(classifications).issubset(covered):
                    return result(True, source_name=name, scan_id=scan_row["id"], reason="recurring sensitive discovery disabled or incomplete classification rules")
                schedule = get(config, "schedule", dict)
                if get(schedule, "recurrence", str) not in {"Hour", "Day", "Week", "Month"} or get(schedule, "interval", int) <= 0:
                    raise Unavailable("recurring Purview schedule unresolved")
                next_run = _time(get(schedule, "next_run_at", str))
                if next_run < _clock(index):
                    raise Unavailable("Purview schedule next run is stale")
                if True in run_outcomes:
                    return result(False, source_name=name, scan_id=scan_row["id"])
                if None in run_outcomes:
                    return unknown("Purview run pending without a recent successful completed run")
                return result(True, source_name=name, scan_id=scan_row["id"], reason="complete scan history proves failed or overdue discovery")
            outcomes = []
            for scan_row in scans:
                try:
                    outcomes.append(scan(scan_row))
                except Unavailable as exc:
                    outcomes.append(unknown(str(exc)))
            # One qualifying scan is sufficient for this source; an obsolete
            # disabled alternative cannot negate that successful discovery.
            if any(status == "PASS" for status, _ in outcomes):
                return result(False, source_name=name)
            if any(status == "UNKNOWN" for status, _ in outcomes):
                return unknown("one or more Purview scan candidates unresolved", source_name=name)
            return result(True, source_name=name, reason="complete scan inventory contains no qualifying recurring sensitive scan")
        return _aggregate(names, source, empty="NOT_APPLICABLE")
    return _aggregate(accounts, evaluate)
