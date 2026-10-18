"""Signed Azure CSPM predicates; pure snapshot evaluation, no cloud calls.

Evidence collections below are versioned collector contracts, not inferred from
account defaults. External policy/issuer/restore evidence is deliberately required
where Azure ARM or data-plane enumeration cannot establish the signed predicate.
"""
from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta
import hashlib
import json
import math
import re

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects, memoized

SPECS = {'azure.other.signed_log_integrity': {'id': 'azure.other.signed_log_integrity',
                                      'provider': 'azure',
                                      'resource_kind': 'storage_account',
                                      'data_source': 'New paged Azure Blob List Blobs '
                                                     '(x-ms-version=2023-11-03, marker continuation) '
                                                     'and GET blob bytes for the protected container; '
                                                     'read complete signed manifest with blobName, '
                                                     'versionId, SHA-256 and signature. New Key Vault '
                                                     'data-plane GET '
                                                     '/keys/{name}/{version}?api-version=7.4 for '
                                                     'trusted public JWK; verify signature locally over '
                                                     'canonical manifest payload. Collector has no '
                                                     'blob-content or manifest collection.',
                                      'predicate': 'PASS only if a complete point-in-time versioned '
                                                   'listing of every retained log blob matches a '
                                                   'manifest entry by name and version, its '
                                                   'full-content SHA-256 matches, and the manifest '
                                                   'signature verifies under the pinned trusted '
                                                   'key/version. FAIL for a known missing, changed, '
                                                   'extra or invalidly signed item. UNKNOWN if '
                                                   'enumeration, version consistency, key trust, '
                                                   'manifest format, bytes or signature algorithm '
                                                   'cannot be established.',
                                      'severity': 'high',
                                      'category': 'hardening',
                                      'title': 'Signed log manifests detect modification',
                                      'description': 'Verifies log object hashes against a signed '
                                                     'manifest and an explicitly trusted signing key.',
                                      'remediation_hint': 'Storage account > Containers: investigate '
                                                          'mismatched log blob versions; regenerate a '
                                                          'complete manifest, sign it with the approved '
                                                          'Key Vault key version and protect both logs '
                                                          'and manifest with immutable retention.',
                                      'proposed_spec_sha256': '0d39f71966121d2765ccffe3a45d711f41e5683bef9f57080a5f10585ab8c64a'},
 'azure.other.signed_log_completeness': {'id': 'azure.other.signed_log_completeness',
                                         'provider': 'azure',
                                         'resource_kind': 'storage_account',
                                         'data_source': 'New paged Blob List Blobs using marker, '
                                                        'manifest GET and signature verification. '
                                                        'Storage Blob data plane GET '
                                                        'https://{account}.blob.core.windows.net/{container}?restype=container&comp=list: '
                                                        'Blobs.Blob.Name,Properties.Content-MD5; GET '
                                                        '/{manifestBlob}: declared '
                                                        'sequence,blobName,digest.',
                                         'predicate': 'PASS only when a trusted signature over a '
                                                      'complete log manifest verifies, an independently '
                                                      'established expected sequence baseline and '
                                                      'policy time window are known, all expected '
                                                      'sequence numbers and named blobs exist after '
                                                      'complete marker pagination, and downloaded bytes '
                                                      'match signed digests. FAIL on a verified missing '
                                                      'expected sequence/blob or digest mismatch. '
                                                      'UNKNOWN when the trusted key, independent '
                                                      'baseline, time window, manifest generation '
                                                      'completeness, pages or blob reads are '
                                                      'unavailable. A signed manifest containing only '
                                                      'surviving blobs cannot prove deletion detection; '
                                                      'Blob Content-MD5 is not signing evidence.',
                                         'severity': 'high',
                                         'category': 'hardening',
                                         'title': 'Signed log manifests detect deletion',
                                         'description': 'Verifies signed log manifests against stored '
                                                        'blob names, hashes and sequence numbers.',
                                         'remediation_hint': 'Azure portal > Storage accounts > '
                                                             'Containers: Restore missing log blobs and '
                                                             'investigate manifest signature or digest '
                                                             'mismatches.',
                                         'proposed_spec_sha256': 'eef2575f85acc4deae799853f67b3fcb2397db6d87f3e9a9a7db172e768d2e9f'},
 'azure.other.audit_storage_access_logging': {'id': 'azure.other.audit_storage_access_logging',
                                              'provider': 'azure',
                                              'resource_kind': 'storage_account',
                                              'data_source': 'Azure Monitor diagnostic settings LIST at '
                                                             'each blob service, with '
                                                             'properties.logs[].category/categoryGroup, '
                                                             'enabled and setting-level destination '
                                                             'IDs; destination/account identity. '
                                                             'Separate data-plane blob-read, blob-write '
                                                             'and blob-delete audit log evidence and a '
                                                             'policy-approved independent secure '
                                                             'logging sink are required to assess '
                                                             'bucket-style server access logging.',
                                              'predicate': 'For each policy-identified audit log '
                                                           'storage account, PASS only if complete '
                                                           'evidence shows access events for that '
                                                           'account are captured and delivered to a '
                                                           'separate approved secure logging '
                                                           'account/sink with verified retention and '
                                                           'access controls. FAIL only on complete '
                                                           'evidence proving access logging absent or '
                                                           'same-account delivery. UNKNOWN if '
                                                           'audit-log-account scope, actual event '
                                                           'delivery, sink separation/security, '
                                                           'category support or inventory is '
                                                           'unmeasured. A diagnostic setting alone does '
                                                           'not prove delivery or secure sink.',
                                              'severity': 'medium',
                                              'category': 'logging',
                                              'title': 'Audit storage access logging enabled',
                                              'description': 'Ensures blob data access logs are '
                                                             'exported to a separate approved log sink.',
                                              'remediation_hint': 'Enable Blob access logging for each '
                                                                  'audit log account and route its '
                                                                  'read/write/delete events to a '
                                                                  'separately approved secure logging '
                                                                  'destination; verify delivery and '
                                                                  'destination controls.',
                                              'proposed_spec_sha256': '2e8c90d43c9b5a5704d67f40b4497ca3bee2f4c9cdf837a80696d562dfbc8f3f'},
 'azure.other.storage_lifecycle': {'id': 'azure.other.storage_lifecycle',
                                   'provider': 'azure',
                                   'resource_kind': 'storage_account',
                                   'data_source': 'Existing azure.py storage_account.items[]; new '
                                                  'managementPolicies/default GET 2023-05-01 per '
                                                  'account. properties.policy.rules[].enabled boolean, '
                                                  'type=Lifecycle, '
                                                  'definition.filters.blobTypes/prefixMatch/blobIndexMatch, '
                                                  'definition.actions.baseBlob.delete.daysAfterModificationGreaterThan; '
                                                  'policy protected prefixes, minimum retention and '
                                                  'maximum deletion days.',
                                   'predicate': 'For every protected blockBlob prefix, PASS only if '
                                                'every applicable enabled delete rule respects minimum '
                                                'retention and at least one rule guarantees deletion by '
                                                'approved maximum. FAIL if an applicable rule can '
                                                'delete earlier or complete policy has no timely '
                                                'deletion. UNKNOWN if overlap, filters, '
                                                'creation/last-access predicates, version/snapshot '
                                                'protection, bounds or policy read cannot be resolved; '
                                                'a broad safe rule cannot mask an earlier overlapping '
                                                'rule.',
                                   'severity': 'medium',
                                   'category': 'recovery',
                                   'title': 'Storage lifecycle deletes protected blobs within approved '
                                            'window',
                                   'description': 'Checks lifecycle deletion rules against minimum '
                                                  'retention and maximum deletion age.',
                                   'remediation_hint': 'Storage account > Lifecycle management: define '
                                                       'enabled blockBlob delete rules for each '
                                                       'protected prefix within the approved min/max '
                                                       'days; remove earlier overlapping deletes and '
                                                       'verify filters.',
                                   'proposed_spec_sha256': '8d5d0e0cdcc8081bc31b2d0e83222cc073eea423da8e8c8aae45a08f722798a5'},
 'azure.other.blob_uniform_access': {'id': 'azure.other.blob_uniform_access',
                                     'provider': 'azure',
                                     'resource_kind': 'storage_account',
                                     'data_source': 'Paged storage account/container inventory; Get '
                                                    'Container ACL (x-ms-version=2023-11-03) for stored '
                                                    'access policies, paged HNS List Paths/Get Path ACL '
                                                    'for object ACLs; account and user-delegation SAS '
                                                    'issuance plus per-blob permissions require '
                                                    'external authoritative evidence because Azure '
                                                    'cannot enumerate all issued SAS tokens.',
                                     'predicate': 'For each container, compare the effective allowed '
                                                  'permission set of every object with the permission '
                                                  'set allowed for that container, including HNS ACLs '
                                                  'and all applicable SAS grants. FAIL when measured '
                                                  'permissions differ. PASS only with complete object '
                                                  'enumeration and authoritative evidence covering '
                                                  'non-enumerable SAS grants; UNKNOWN when issued SAS, '
                                                  'object ACLs, policy semantics or paging cannot be '
                                                  'fully observed. Public access level and stored '
                                                  'policies alone cannot prove uniformity.',
                                     'severity': 'high',
                                     'category': 'hardening',
                                     'title': 'Blob container access settings match the approved policy',
                                     'description': 'Evaluates enumerable container anonymous access, '
                                                    'stored access policies and HNS ACLs; issued SAS '
                                                    'access is not observable.',
                                     'remediation_hint': 'Align each object’s ACL and SAS grants with '
                                                         'the container-approved permission set; remove '
                                                         'divergent HNS ACLs and revoke or expire '
                                                         'divergent SAS credentials.',
                                     'proposed_spec_sha256': '5daea22fe3ccae690a528cb39581ca631a666c7106c183ea93b561dc8b28a3cf'},
 'azure.other.infrastructure_configuration_backup': {'id': 'azure.other.infrastructure_configuration_backup',
                                                     'provider': 'azure',
                                                     'resource_kind': 'storage_account',
                                                     'data_source': 'Authoritative inventory of '
                                                                    'infrastructure configuration '
                                                                    'resources and backup policy '
                                                                    '(maximum age and retention); '
                                                                    'export manifest with resource ARM '
                                                                    'ID, export completion time, '
                                                                    'artifact URI and integrity hash; '
                                                                    'read artifact and a dated '
                                                                    'restore-validation record. '
                                                                    'Automation runbook '
                                                                    'publishContentLink alone is not '
                                                                    'backup evidence.',
                                                     'predicate': 'For every required infrastructure '
                                                                  'configuration resource, PASS only '
                                                                  'when a complete manifest shows a '
                                                                  'successful export within the '
                                                                  'approved maximum age, the artifact '
                                                                  'is readable and integrity-checked, '
                                                                  'retained for the required period, '
                                                                  'and a restore validation within the '
                                                                  'approved interval demonstrates that '
                                                                  'configuration can be recovered. FAIL '
                                                                  'on a fully measured '
                                                                  'missing/stale/corrupt export or '
                                                                  'failed restore. UNKNOWN if resource '
                                                                  'inventory, age/retention policy, '
                                                                  'artifact, or restoration evidence is '
                                                                  'missing; an empty required inventory '
                                                                  'without an authoritative scope '
                                                                  'decision is UNKNOWN.',
                                                     'severity': 'medium',
                                                     'category': 'recovery',
                                                     'title': 'Infrastructure configuration is backed '
                                                              'up',
                                                     'description': 'Uses an explicit export manifest '
                                                                    'and protected storage evidence to '
                                                                    'verify infrastructure '
                                                                    'configuration backups.',
                                                     'remediation_hint': 'Schedule exports of each '
                                                                         'required infrastructure '
                                                                         'configuration, retain '
                                                                         'verified artifacts for the '
                                                                         'approved period, and perform '
                                                                         'and record a restore test.',
                                                     'proposed_spec_sha256': '7bec07368a73f6c3ba122280f0790f24a58245a1057012ee068aa429f477497d'},
 'azure.other.storage_geo': {'id': 'azure.other.storage_geo',
                             'provider': 'azure',
                             'resource_kind': 'storage_account',
                             'data_source': 'existing collected storage_account location, sku.name, '
                                            'properties.secondaryLocation; organization-approved '
                                            'EU-region list; authoritative customer-data '
                                            'storage/processing inventory, all applicable service '
                                            'region metadata, and Azure Policy assignments plus '
                                            'compliance results for approved EU locations',
                             'predicate': 'For each customer-data storage or processing resource in a '
                                          'complete classified inventory, PASS only if every known '
                                          'primary, replica and processing location is within the '
                                          'approved EU region set and an effective region-restriction '
                                          'policy is assigned and compliant at its scope. FAIL on a '
                                          'fully measured non-EU location or absent/noncompliant '
                                          'restriction policy. UNKNOWN when inventory, region mapping, '
                                          'secondary location, processing location, policy inheritance '
                                          'or compliance result is unresolved. A storage-account-only '
                                          'scan cannot PASS the whole requirement.',
                             'severity': 'high',
                             'category': 'hardening',
                             'title': 'Storage data stays in approved EU regions',
                             'description': 'Checks primary and replicated storage-account regions '
                                            'against an approved EU-region list.',
                             'remediation_hint': 'Move customer data storage and processing to approved '
                                                 'EU regions and assign/enforce approved-location Azure '
                                                 'Policies at every applicable scope.',
                             'proposed_spec_sha256': '3e2ecf52eca006476e44f16441185f3888d95e107499417f3ed29e9427ee3105'},
 'azure_api_management_1_2_8_1_ba319cf': {'id': 'azure_api_management_1_2_8_1_ba319cf',
                                          'provider': 'azure',
                                          'resource_kind': 'api_management',
                                          'data_source': 'Paged ARM '
                                                         'Microsoft.ApiManagement/service/apis LIST '
                                                         '2024-05-01: value[].properties.protocols enum '
                                                         'http/https/ws/wss; frozen expected endpoint '
                                                         'type parameter per API. Protocols cover these '
                                                         'four transport types only.',
                                          'predicate': 'For each in-scope APIM API, compare '
                                                       'properties.protocols with the frozen expected '
                                                       'endpoint type when it is one of http, https, ws '
                                                       'or wss. PASS only if every API has the expected '
                                                       'protocol and no protocol forbidden by the '
                                                       'supplied rule parameter. FAIL for a fully '
                                                       'observed mismatch. UNKNOWN for an endpoint type '
                                                       'not represented by this enum, missing rule '
                                                       'parameter, absent protocols field, unrecognized '
                                                       'value or incomplete pages. Complete empty API '
                                                       'inventory is NOT_APPLICABLE.',
                                          'severity': 'medium',
                                          'category': 'hardening',
                                          'title': 'Use approved APIM API protocols',
                                          'description': 'Use approved APIM API protocols. A finding is '
                                                         'raised when any in-scope API omits a required '
                                                         'protocol or exposes a forbidden protocol '
                                                         'under expectedProtocols.',
                                          'remediation_hint': 'Set the APIM API protocols to the '
                                                              'approved HTTP/HTTPS endpoint type. For '
                                                              'endpoint types beyond the protocols '
                                                              'field, review the API configuration and '
                                                              'supply separate evidence.',
                                          'proposed_spec_sha256': '0d01a758e49f3c58bbb3c169ba87576979a3bfe01c97bc33859ee849b8d45f78'},
 'azure_api_management_1_2_8_3_e8fe737': {'id': 'azure_api_management_1_2_8_3_e8fe737',
                                          'provider': 'azure',
                                          'resource_kind': 'api_management',
                                          'data_source': 'Paged APIM service GET, APIs LIST, service '
                                                         'hostnameConfigurations and '
                                                         'publicNetworkAccess/virtualNetworkType; DNS '
                                                         'resolution for every APIM default and custom '
                                                         'gateway hostname; paged Application Gateway '
                                                         'listeners/rules/backends/WAF policy and AFD '
                                                         'endpoints/routes/origins/securityPolicies '
                                                         'with WAF GET. The API list alone does not '
                                                         'establish the gateway path.',
                                          'predicate': 'For every in-scope APIM API and every publicly '
                                                       'usable default or custom gateway hostname/path, '
                                                       'PASS only if complete DNS, origin and route '
                                                       'evidence proves all reachable paths traverse an '
                                                       'effective enabled Prevention-mode WAF and '
                                                       'direct APIM gateway ingress is blocked. FAIL '
                                                       'for a demonstrated reachable direct or '
                                                       'unprotected path. UNKNOWN on API/hostname '
                                                       'enumeration, DNS, alternate gateway endpoints, '
                                                       'route matching, origin restriction or WAF '
                                                       'state. Complete empty API scope is '
                                                       'NOT_APPLICABLE.',
                                          'severity': 'high',
                                          'category': 'network',
                                          'title': 'Azure API Management (APIM) APIs are associated '
                                                   'with Azure Web Application Firewall (WAF) policies',
                                          'description': 'Checks that public APIM API routes are '
                                                         'protected by an associated WAF policy.',
                                          'remediation_hint': 'Publish every APIM gateway hostname and '
                                                              'API path through a WAF-protected '
                                                              'Application Gateway or Front Door route, '
                                                              'and block direct public access to the '
                                                              'native APIM gateway.',
                                          'proposed_spec_sha256': '6da1983ec49d792c1d31507b5550d583c696640d178dd1c5489cd39d14d0c4ff'},
 'azure_api_management_10_3_1_3_8a50dc0': {'id': 'azure_api_management_10_3_1_3_8a50dc0',
                                           'provider': 'azure',
                                           'resource_kind': 'api_management',
                                           'data_source': 'Paged APIM APIs LIST and per-API diagnostics '
                                                          'LIST 2024-05-01; service loggers LIST. Join '
                                                          'diagnostic.properties.loggerId (full ARM ID) '
                                                          'to logger.id, require '
                                                          'logger.properties.loggerType=applicationInsights; '
                                                          'inspect '
                                                          'diagnostic.properties.sampling.percentage '
                                                          'and alwaysLog.',
                                           'predicate': 'For every APIM REST API, PASS only if its '
                                                        'fully paged API diagnostic list contains an '
                                                        'Application Insights diagnostic referencing an '
                                                        'existing usable logger and producing traces '
                                                        '(sampling.percentage>0 or '
                                                        'alwaysLog=allErrors). FAIL if complete API, '
                                                        'diagnostic and logger reads prove none '
                                                        'qualifies; UNKNOWN if credentials, revision '
                                                        'coverage, sampling/alwaysLog or any child page '
                                                        'is unresolved. No APIs is NOT_APPLICABLE.',
                                           'severity': 'medium',
                                           'category': 'hardening',
                                           'title': 'APIM APIs send diagnostics to Application Insights',
                                           'description': 'Checks API-level diagnostics against an '
                                                          'actual APIM Application Insights logger.',
                                           'remediation_hint': 'Attach a working Application Insights '
                                                               'logger in each API’s Diagnostics '
                                                               'settings, enable nonzero sampling or '
                                                               'all-error logging, and validate '
                                                               'telemetry.',
                                           'proposed_spec_sha256': 'c5bc134035705e0b6b10beb0b38dada3b052d3857475820e4af4eb62aace966f'},
 'azure_storage_account_10_3_4_7_02943e9': {'id': 'azure_storage_account_10_3_4_7_02943e9',
                                            'provider': 'azure',
                                            'resource_kind': 'storage_account',
                                            'data_source': 'Paged '
                                                           'Microsoft.Storage/storageAccounts/blobServices/default/containers '
                                                           'LIST 2023-05-01, each container GET and '
                                                           'immutabilityPolicies/default GET, plus '
                                                           'storage-account GET 2023-05-01: container '
                                                           'properties.immutableStorageWithVersioning.enabled, '
                                                           'properties.immutabilityPolicy, account '
                                                           'properties.immutabilityPolicy. Resolve '
                                                           'effective container-level or inherited '
                                                           'account/container default version-level '
                                                           'retention policy and its period/state.',
                                            'predicate': 'For every in-scope Blob container, PASS only '
                                                         'if a complete read proves that newly written '
                                                         'blobs or versions inherit an effective '
                                                         'default immutability policy with a positive '
                                                         'retention period, either at container scope '
                                                         'or via a supported account/container default '
                                                         'version-level policy. '
                                                         'immutableStorageWithVersioning.enabled alone '
                                                         'cannot PASS. FAIL if complete '
                                                         'account/container/policy reads prove no '
                                                         'effective default immutability policy. '
                                                         'UNKNOWN if container inventory, policy '
                                                         'inheritance, policy state, period or child '
                                                         'reads are unresolved. Complete empty '
                                                         'container inventory is NOT_APPLICABLE.',
                                            'severity': 'medium',
                                            'category': 'hardening',
                                            'title': 'Required Blob containers have locked immutable '
                                                     'retention',
                                            'description': 'Checks enforced locked retention, rather '
                                                           'than only the capability to enable '
                                                           'version-level immutability.',
                                            'remediation_hint': 'Enable immutable blob storage with '
                                                                'versioning on each affected container; '
                                                                'configure and lock a retention policy '
                                                                'separately where your retention policy '
                                                                'requires it.',
                                            'proposed_spec_sha256': '65cb7aa5bb8aef9ab6bf9e180ff39b8c2ff67ecbc364c28a83bbcd4cb2085d7c'},
 'azure_storage_account_10_5_1_13_2f5d4f6': {'id': 'azure_storage_account_10_5_1_13_2f5d4f6',
                                             'provider': 'azure',
                                             'resource_kind': 'storage_account',
                                             'data_source': 'Paged ARM storageAccounts and '
                                                            'blobServices/default GET 2023-05-01: blob '
                                                            'service properties.isVersioningEnabled; '
                                                            'paged blobContainers LIST for applicable '
                                                            'containers; managementPolicies/default GET '
                                                            '2023-05-01: '
                                                            'properties.policy.rules[].enabled/type/definition.filters '
                                                            'and '
                                                            'definition.actions.baseBlob/snapshot/version.',
                                             'predicate': 'For each container in a versioning-enabled '
                                                          'account, PASS only when an enabled Lifecycle '
                                                          'rule has a supported action and its '
                                                          'blobTypes, case-sensitive prefixMatch and '
                                                          'blobIndexMatch filters are proven to cover '
                                                          'the required blobs/versions in that '
                                                          'container. A prefix for a different '
                                                          'container, or a narrower path, is not '
                                                          'full-container coverage; a tag filter needs '
                                                          'blob-tag evidence. FAIL when complete policy '
                                                          'and applicable-blob evidence prove no rule '
                                                          'applies. UNKNOWN when blob population/tags, '
                                                          'filters, action validity, versioning, or '
                                                          'inventories are unresolved. No versioned '
                                                          'containers is NOT_APPLICABLE.',
                                             'severity': 'medium',
                                             'category': 'recovery',
                                             'title': 'Azure Blob Storage containers with versioning '
                                                      'enabled have a lifecycle management policy '
                                                      'configured',
                                             'description': 'Checks lifecycle management on versioned '
                                                            'Blob Storage accounts.',
                                             'remediation_hint': 'Add an enabled storage lifecycle rule '
                                                                 'with an applicable action and filters '
                                                                 'covering every versioned container.',
                                             'proposed_spec_sha256': '1faa0e3239f2285dcd3e59abef6e5698cde9e008392dd5143d73601aecf2c05c'},
 'azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3': {'id': 'azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3',
                                                                               'provider': 'azure',
                                                                               'resource_kind': 'storage_account',
                                                                               'data_source': 'Paged '
                                                                                              'Blob '
                                                                                              'container '
                                                                                              'LIST/GET '
                                                                                              'and '
                                                                                              'storage '
                                                                                              'account '
                                                                                              'GET '
                                                                                              '2023-05-01; '
                                                                                              'container '
                                                                                              'properties.defaultEncryptionScope '
                                                                                              'and '
                                                                                              'denyEncryptionScopeOverride; '
                                                                                              'account '
                                                                                              'properties.encryption.keySource/keyVaultProperties; '
                                                                                              'account '
                                                                                              'encryptionScopes '
                                                                                              'child '
                                                                                              'LIST/GET '
                                                                                              'with '
                                                                                              'source '
                                                                                              'and '
                                                                                              'keyVaultProperties; '
                                                                                              'resolve '
                                                                                              'effective '
                                                                                              'scope '
                                                                                              'for each '
                                                                                              'container '
                                                                                              'and any '
                                                                                              'permitted '
                                                                                              'per-blob '
                                                                                              'override.',
                                                                               'predicate': 'For every '
                                                                                            'scoped '
                                                                                            'container, '
                                                                                            'prove that '
                                                                                            'every '
                                                                                            'existing '
                                                                                            'blob is '
                                                                                            'encrypted '
                                                                                            'with an '
                                                                                            'Azure Key '
                                                                                            'Vault key. '
                                                                                            'Resolve '
                                                                                            'the '
                                                                                            'container '
                                                                                            'default '
                                                                                            'encryption '
                                                                                            'scope, '
                                                                                            'account '
                                                                                            'default '
                                                                                            'key, and '
                                                                                            'any '
                                                                                            'per-blob '
                                                                                            'encryption-scope '
                                                                                            'override; '
                                                                                            'defaults '
                                                                                            'alone '
                                                                                            'cannot '
                                                                                            'prove the '
                                                                                            'keys of '
                                                                                            'pre-existing '
                                                                                            'objects. '
                                                                                            'PASS only '
                                                                                            'when '
                                                                                            'complete '
                                                                                            'blob-level '
                                                                                            'scope/key '
                                                                                            'evidence '
                                                                                            'or an '
                                                                                            'authoritative '
                                                                                            'equivalent '
                                                                                            'proves all '
                                                                                            'existing '
                                                                                            'objects '
                                                                                            'use Key '
                                                                                            'Vault keys '
                                                                                            'and new '
                                                                                            'writes '
                                                                                            'cannot use '
                                                                                            'a '
                                                                                            'platform-managed '
                                                                                            'key. FAIL '
                                                                                            'on a '
                                                                                            'measured '
                                                                                            'blob with '
                                                                                            'a '
                                                                                            'Microsoft.Storage '
                                                                                            'key or an '
                                                                                            'effective '
                                                                                            'mandatory '
                                                                                            'platform-managed '
                                                                                            'scope. '
                                                                                            'UNKNOWN '
                                                                                            'when '
                                                                                            'override '
                                                                                            'use, '
                                                                                            'historical '
                                                                                            'blob '
                                                                                            'scope, '
                                                                                            'scope '
                                                                                            'source, '
                                                                                            'key '
                                                                                            'reference '
                                                                                            'or '
                                                                                            'container/account '
                                                                                            'inventory '
                                                                                            'is '
                                                                                            'unresolved.',
                                                                               'severity': 'medium',
                                                                               'category': 'encryption',
                                                                               'title': 'Blob '
                                                                                        'containers use '
                                                                                        'Azure Key '
                                                                                        'Vault '
                                                                                        'encryption '
                                                                                        'keys',
                                                                               'description': 'Checks '
                                                                                              'the '
                                                                                              'effective '
                                                                                              'encryption '
                                                                                              'key for '
                                                                                              'each '
                                                                                              'scoped '
                                                                                              'Blob '
                                                                                              'container, '
                                                                                              'including '
                                                                                              'encryption '
                                                                                              'scopes '
                                                                                              'and '
                                                                                              'allowed '
                                                                                              'overrides.',
                                                                               'remediation_hint': 'For '
                                                                                                   'the '
                                                                                                   'backing '
                                                                                                   'storage '
                                                                                                   'account, '
                                                                                                   'enable '
                                                                                                   'customer-managed '
                                                                                                   'encryption '
                                                                                                   'with '
                                                                                                   'a '
                                                                                                   'Key '
                                                                                                   'Vault '
                                                                                                   'key '
                                                                                                   'and '
                                                                                                   'verify '
                                                                                                   'the '
                                                                                                   'key '
                                                                                                   'reference '
                                                                                                   'and '
                                                                                                   'access.',
                                                                               'proposed_spec_sha256': '990e994c7c43e23ac03e3e3e6678c0c9fec040d75d3747f5be4dcb2c5dbd17b3'},
 'azure_c5_ops_13_03b': {'id': 'azure_c5_ops_13_03b',
                         'provider': 'azure',
                         'resource_kind': 'storage_account',
                         'data_source': 'GET each scoped container child immutabilityPolicies/default '
                                        '2023-05-01, properties.state and '
                                        'immutabilityPeriodSinceCreationInDays; SIEM ingestion '
                                        'inventory, source/destination counts, clock synchronization '
                                        'evidence and original/copy hash records for approved '
                                        'observation window.',
                         'predicate': 'For each policy-listed SIEM archive container, require a Locked '
                                      'immutability policy with at least the approved retention days '
                                      'and independently verify complete SIEM-log delivery, timestamp '
                                      'synchronization and evidence integrity/copy hashes for the '
                                      'observation window. FAIL for a proven tamperable/unprotected '
                                      'archive or failed integrity check; PASS only when all C5 '
                                      'OPS-13.03B and OPS-15.02AC evidence is complete. UNKNOWN when '
                                      'archive scope, retention threshold, child policy GET, log '
                                      'completeness, synchronization or hashes are unmeasured. A locked '
                                      'container alone cannot satisfy both frozen requirements.',
                         'severity': 'medium',
                         'category': 'hardening',
                         'title': 'SIEM logs are protected and preserve evidence integrity',
                         'description': 'Checks archive immutability, log completeness, synchronized '
                                        'timestamps and evidence-copy integrity.',
                         'remediation_hint': 'Lock approved retention on SIEM archive containers, then '
                                             'verify complete ingestion, synchronized timestamps and '
                                             'matching evidence hashes for the full observation window.',
                         'proposed_spec_sha256': 'da02770f9eca8f0276574f4a9e7d80385b117fc3c06d2d1bab969db80699a782'},
 'azure.cis.shared_access_signature_tokens_expire_within_hour': {'id': 'azure.cis.shared_access_signature_tokens_expire_within_hour',
                                                                 'provider': 'azure',
                                                                 'resource_kind': 'storage_account',
                                                                 'data_source': 'Paged '
                                                                                'Microsoft.Storage/storageAccounts '
                                                                                'GET 2023-05-01: '
                                                                                'properties.sasPolicy.sasExpirationPeriod '
                                                                                'string in DD.HH:MM:SS '
                                                                                'format and '
                                                                                'expirationAction enum '
                                                                                'Log/Block. Collect '
                                                                                'issuer-side inventory '
                                                                                'or retained issuance '
                                                                                'records for active '
                                                                                'user-delegation, '
                                                                                'service and account '
                                                                                'SAS tokens, including '
                                                                                'st/se or '
                                                                                'stored-access-policy '
                                                                                'expiry; validate any '
                                                                                'applicable '
                                                                                'service-specific '
                                                                                'exception.',
                                                                 'predicate': 'For each storage '
                                                                              'account, FAIL if a known '
                                                                              'active SAS has an actual '
                                                                              'validity interval over '
                                                                              'one hour or complete '
                                                                              'policy evidence shows no '
                                                                              'enforcing account limit '
                                                                              '(absent policy, interval '
                                                                              'over one hour, or '
                                                                              'expirationAction=Log, '
                                                                              'its documented default). '
                                                                              'PASS for the '
                                                                              'token-expiry requirement '
                                                                              'only when the account '
                                                                              'policy parses to at most '
                                                                              '00.01:00:00 with '
                                                                              'effective Block AND '
                                                                              'complete active-token '
                                                                              'issuance evidence shows '
                                                                              'every applicable SAS '
                                                                              'expires within one hour; '
                                                                              'resolve '
                                                                              'stored-access-policy SAS '
                                                                              'separately. UNKNOWN when '
                                                                              'token inventory is '
                                                                              'unavailable, period '
                                                                              'malformed, action '
                                                                              'unknown or account '
                                                                              'inventory incomplete. '
                                                                              'The account policy alone '
                                                                              'is a configuration '
                                                                              'signal, not proof of '
                                                                              'every issued token.',
                                                                 'severity': 'medium',
                                                                 'category': 'identity',
                                                                 'title': 'Ensure that Shared Access '
                                                                          'Signature Tokens Expire '
                                                                          'Within an Hour',
                                                                 'description': 'Limits account and '
                                                                                'service SAS validity '
                                                                                'using the storage '
                                                                                'account SAS expiration '
                                                                                'policy; user '
                                                                                'delegation SAS '
                                                                                'limitations must be '
                                                                                'assessed separately.',
                                                                 'remediation_hint': 'Set storage SAS '
                                                                                     'expiration policy '
                                                                                     'to 00.01:00:00 or '
                                                                                     'less and action '
                                                                                     'Block; review '
                                                                                     'previously issued '
                                                                                     'SAS separately.',
                                                                 'proposed_spec_sha256': 'fa4ae0f9eb68ee394e2b2e0de6f5ca27a285739d8013dfbe403c9b364165a390'}}

IDS = tuple(SPECS)
SPEC_SHA256 = {key: value["proposed_spec_sha256"] for key, value in SPECS.items()}

SAS = "azure.cis.shared_access_signature_tokens_expire_within_hour"
AUDIT = "azure.other.audit_storage_access_logging"
UNIFORM = "azure.other.blob_uniform_access"
BACKUP = "azure.other.infrastructure_configuration_backup"
COMPLETENESS = "azure.other.signed_log_completeness"
INTEGRITY = "azure.other.signed_log_integrity"
GEO = "azure.other.storage_geo"
LIFECYCLE = "azure.other.storage_lifecycle"
SIEM = "azure_c5_ops_13_03b"
IMMUTABLE = "azure_storage_account_10_3_4_7_02943e9"
VERSION_LIFECYCLE = "azure_storage_account_10_5_1_13_2f5d4f6"
KEYS = "azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3"
DIAGNOSTICS = "azure_api_management_10_3_1_3_8a50dc0"
PROTOCOLS = "azure_api_management_1_2_8_1_ba319cf"
WAF = "azure_api_management_1_2_8_3_e8fe737"

EVIDENCE_KINDS = {
    SAS: "storage_sas_issuance", AUDIT: "audit_storage_access_evidence",
    UNIFORM: "blob_access_evidence", BACKUP: "configuration_backup_evidence",
    COMPLETENESS: "signed_log_evidence", INTEGRITY: "signed_log_evidence",
    GEO: "customer_data_region_evidence", LIFECYCLE: "storage_management_policy_evidence",
    SIEM: "siem_archive_evidence", IMMUTABLE: "storage_immutability_evidence",
    VERSION_LIFECYCLE: "storage_version_lifecycle_evidence", KEYS: "storage_blob_key_evidence",
    DIAGNOSTICS: "apim_diagnostic_evidence", PROTOCOLS: "apim_api_evidence",
    WAF: "apim_route_evidence",
}


def _time(value):
    if not isinstance(value, str):
        raise Unavailable("timestamp absent or malformed")
    try:
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unavailable("timestamp malformed") from exc
    if value.tzinfo is None:
        raise Unavailable("timestamp lacks timezone")
    return value


def _number(row, key, *, positive=False):
    value = get(row, key)
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or positive and value <= 0:
        raise Unavailable("invalid nonnegative bound: " + key)
    return value


def _integer(row, key):
    value = get(row, key, int)
    if value < 0:
        raise Unavailable("invalid nonnegative integer: " + key)
    return value


def _strings(row, key, *, nonempty=False):
    values = get(row, key, list)
    if any(not isinstance(x, str) or not x for x in values) or len(values) != len(set(values)) or nonempty and not values:
        raise Unavailable("malformed string set: " + key)
    return values


def _require(row, *keys):
    for key in keys:
        if get(row, key, bool) is not True:
            raise Unavailable("evidence unresolved: " + key)


def _validate_evidence(value):
    """Do not let short-circuit predicates hide denied/malformed child facts."""
    if isinstance(value, dict):
        guard(value)
        for name, coverage in value.get("_coverage", {}).items():
            if not isinstance(name, str) or not isinstance(coverage, dict) or coverage.get("status") not in {"collected", "empty"}:
                raise Unavailable("evidence contains unresolved field coverage")
            if name not in value:
                raise Unavailable("covered evidence field absent")
        for name, child in value.items():
            if name != "_coverage":
                _validate_evidence(child)
    elif isinstance(value, list):
        for child in value:
            _validate_evidence(child)


def _objects(row, key):
    container = get(row, key, dict)
    status = get(container, "collection_status", str)
    if status not in ("collected", "empty"):
        raise Unavailable("child inventory incomplete: " + key)
    rows = list_of_objects(get(container, "items", list))
    if status == "empty" and rows:
        raise Unavailable("empty child inventory contains rows")
    for value in rows:
        guard(value)
    return rows


def _unique(rows, key="id", *, insensitive=True):
    found = {}
    for row in rows:
        rid = get(row, key, str)
        rid = rid.casefold() if insensitive else rid
        if not rid or rid in found:
            raise Unavailable("missing or duplicate identity: " + key)
        found[rid] = row
    return found


def _context(index):
    context = get(index, "context", dict)
    scope = get(context, "scope", str)
    if get(context, "provider", str) != "azure" or not re.fullmatch(
            r"/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", scope):
        raise Unavailable("Azure subscription authority unavailable")
    return context, scope.casefold()


def _inventory(index, kind):
    def read():
        _, scope = _context(index)
        envelopes = get(index, "collections", dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable("missing or ambiguous inventory: " + kind)
        env = envelopes[0]
        if get(env, "scope", str).casefold() != scope or get(env, "type", str) != kind:
            raise Unavailable("foreign collection: " + kind)
        rows = complete_items(index, kind)
        native = list_of_objects(get(env, "items", list))
        if native != rows or get(env, "status", str) == "empty" and rows:
            raise Unavailable("collection projection differs: " + kind)
        for wrapper in get(index, kind, list):
            if get(wrapper, "scope", str).casefold() != scope or get(wrapper, "type", str) != kind:
                raise Unavailable("foreign resource wrapper")
            if "provider" in wrapper and get(wrapper, "provider", str) != "azure":
                raise Unavailable("foreign provider wrapper")
        found = _unique(rows)
        for rid in found:
            if not rid.startswith(scope + "/"):
                raise Unavailable("foreign resource identity")
        return found
    return memoized(index, ("sw23.inventory", kind), read)


def _own(item, index, kind):
    rid = get(item, "id", str).casefold()
    if _inventory(index, kind).get(rid) != item:
        raise Unavailable("target differs from collected inventory")
    _, scope = _context(index)
    suffix = "Microsoft.Storage/storageAccounts" if kind == "storage_account" else "Microsoft.ApiManagement/service"
    if not re.fullmatch(re.escape(scope) + r"/resourcegroups/[^/]+/providers/" + re.escape(suffix.casefold()) + r"/[^/]+", rid):
        raise Unavailable("target ARM resource type malformed")
    return rid


def _evidence(item, index, cid):
    parent = _own(item, index, SPECS[cid]["resource_kind"])
    rows = _inventory(index, EVIDENCE_KINDS[cid])
    found = []
    for row in rows.values():
        pid = get(row, "parent_id", str).casefold()
        if not get(row, "id", str).casefold().startswith(pid + "/complianceEvidence/".casefold()):
            raise Unavailable("evidence identity not bound to parent")
        if pid not in _inventory(index, SPECS[cid]["resource_kind"]):
            raise Unavailable("evidence bound to uncollected parent")
        if pid == parent:
            found.append(row)
    if len(found) != 1:
        raise Unavailable("parent evidence absent or ambiguous")
    row = found[0]
    provenance = get(row, "_provenance", dict)
    if get(provenance, "schema_version", int) != 1:
        raise Unavailable("unsupported evidence contract version")
    _require(provenance, "read_only", "policy_approved", "complete")
    context, _ = _context(index)
    if _time(get(provenance, "captured_at", str)) != _time(get(context, "created_at", str)):
        raise Unavailable("evidence is not bound to snapshot instant")
    payload = get(row, "payload", dict)
    _validate_evidence(payload)
    return payload


def _child_id(row, parent, segment):
    rid = get(row, "id", str).casefold()
    prefix = parent.casefold() + "/" + segment.casefold() + "/"
    if not rid.startswith(prefix) or not rid[len(prefix):] or "/" in rid[len(prefix):]:
        raise Unavailable("foreign or malformed child ARM identity")
    return rid


def _containers(evidence, parent):
    rows = _objects(evidence, "containers")
    _unique(rows)
    for row in rows:
        _child_id(row, parent, "blobServices/default/containers")
    return rows


def _na(reason):
    return "NOT_APPLICABLE", {"reason": reason}


def _signed(cid):
    def decorate(fn):
        spec = SPECS[cid]
        category = spec["category"]
        # The frozen ledger uses categories the older register guard does not
        # accept; retain the signed category on this check only, as in sw03.
        native = category if category in {"hardening", "network", "exposure", "least_privilege", "iam_graph"} else "hardening"
        fn.proposed_spec_sha256 = SPEC_SHA256[cid]
        register(cid, "azure", native, spec["resource_kind"], spec["title"], spec["severity"],
                 "CM-6", spec["remediation_hint"],
                 dependencies=[spec["resource_kind"], EVIDENCE_KINDS[cid]])(fn)
        for number, check in enumerate(CHECKS):
            if check.id == cid:
                CHECKS[number] = replace(check, category=category)
                break
        return fn
    return decorate


@_signed(SAS)
def sas_expiry(item, index):
    _own(item, index, "storage_account")
    props = get(item, "properties", dict)
    # Absence/default semantics need an actual full account GET.
    if "sasPolicy" not in props or props.get("sasPolicy") is None:
        if get(item, "_provenance.representation", str) != "full" or get(item, "_provenance.source_operation", str) != "get":
            raise Unavailable("omitted account SAS policy not authoritative")
        get(props, "sasPolicy") if "sasPolicy" in props.get("_coverage", {}) else None
        return result(True, reason="full account GET proves absent enforcing SAS policy")
    policy = get(props, "sasPolicy", dict)
    _validate_evidence(policy)
    duration = get(policy, "sasExpirationPeriod", str)
    match = re.fullmatch(r"(\d+)\.(\d{2}):(\d{2}):(\d{2})", duration)
    if not match or any(int(match[n]) > bound for n, bound in ((2, 23), (3, 59), (4, 59))):
        raise Unavailable("malformed SAS policy duration")
    seconds = sum(int(match[n]) * weight for n, weight in ((1, 86400), (2, 3600), (3, 60), (4, 1)))
    if "expirationAction" in policy or "expirationAction" in policy.get("_coverage", {}):
        action = get(policy, "expirationAction", str)
    elif get(item, "_provenance.representation", str) == "full" and get(item, "_provenance.source_operation", str) == "get":
        action = "Log"  # documented Azure API default
    else:
        raise Unavailable("SAS action omission not authoritative")
    if action not in {"Log", "Block"}:
        raise Unavailable("unknown SAS expiration action")
    if seconds > 3600 or action == "Log":
        return result(True, reason="account policy does not enforce one-hour SAS limit")
    ev = _evidence(item, index, SAS)
    _require(ev, "issuer_inventory_complete", "service_exceptions_resolved", "stored_policies_resolved")
    now = _time(get(get(index, "context", dict), "created_at", str))
    unsafe = []
    unresolved = []
    tokens = _objects(ev, "tokens")
    _unique(tokens, "issuance_id", insensitive=False)
    # Account binding, kind and exception decisions govern the whole issuer
    # inventory. They cannot be treated as uncertainty in one token's interval.
    for token in tokens:
        if get(token, "account_id", str).casefold() != get(item, "id", str).casefold():
            raise Unavailable("foreign SAS issuance record")
        if get(token, "kind", str) not in {"user_delegation", "service", "account", "stored_policy"}:
            raise Unavailable("unknown SAS kind")
        _require(token, "exception_resolved")
    for token in tokens:
        issuance_id = get(token, "issuance_id", str)
        try:
            _require(token, "validity_resolved")
            start, end = _time(get(token, "effective_start", str)), _time(get(token, "effective_expiry", str))
            if end <= start:
                raise Unavailable("invalid effective SAS interval")
            active = get(token, "active", bool)
            if active != (start <= now < end):
                raise Unavailable("SAS active status conflicts with validity interval")
        except Unavailable:
            unresolved.append(issuance_id)
            continue
        if active and end - start > timedelta(hours=1):
            unsafe.append(issuance_id)
    if unsafe:
        return result(True, overlong_active_issuance_ids=unsafe, unresolved_issuance_ids=unresolved)
    if unresolved:
        return unknown("SAS token validity unresolved", unresolved_issuance_ids=unresolved)
    return result(False, overlong_active_issuance_ids=[])



@_signed(AUDIT)
def audit_access(item, index):
    from peaso.collectors import azure_audit_storage_native as native
    if native.has_native(item, index):
        parent = _own(item, index, 'storage_account')
        context, _ = _context(index)
        return native.assess(parent, context, _inventory(index, native.KIND), _inventory(index, 'storage_account'))
    ev = _evidence(item, index, AUDIT)
    _require(ev, "audit_scope_authoritative", "category_support_resolved", "observation_complete")
    if not get(ev, "is_audit_account", bool):
        return _na("authoritative policy excludes this account from audit storage")
    events = _objects(ev, "events")
    by_op = _unique(events, "operation", insensitive=False)
    if set(by_op) != {"read", "write", "delete"}:
        raise Unavailable("read/write/delete audit observations incomplete")
    bad = []
    for op, event in by_op.items():
        if get(event, "source_account_id", str).casefold() != get(item, "id", str).casefold():
            raise Unavailable("foreign audit source")
        _require(event, "delivery_measured", "sink_identity_resolved", "sink_security_measured")
        captured = get(event, "captured", bool)
        delivered = get(event, "delivered", bool)
        sink = get(event, "sink", dict)
        identity = get(sink, "id", str)
        segment = r"[^/?#%\\\x00-\x20]+"
        if (not re.fullmatch(
                r"/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
                + r"/resourceGroups/" + segment
                + r"/providers/[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+"
                + r"(?:/" + segment + r"/" + segment + r")+", identity, re.I)
                or any(part in (".", "..") for part in identity.split("/")[1:])):
            raise Unavailable("sink identity malformed")
        source_id = get(item, "id", str).casefold()
        same = identity.casefold() == source_id or identity.casefold().startswith(source_id + "/")
        approved = get(sink, "approved", bool)
        retention = get(sink, "retention_verified", bool)
        access = get(sink, "access_controls_verified", bool)
        if not captured or same:
            bad.append(op)
        elif not delivered or not (approved and retention and access):
            raise Unavailable("actual delivery to approved secure sink unproven")
    return result(bool(bad), absent_or_same_account_access_logs=bad)


@_signed(UNIFORM)
def uniform_permissions(item, index):
    ev = _evidence(item, index, UNIFORM)
    _require(ev, "sas_issuance_authoritative", "permission_semantics_resolved", "hns_acls_complete")
    containers = _containers(ev, get(item, "id", str))
    if not containers:
        return _na("complete container inventory is empty")
    # Complete container/object inventories, unique names and SAS-grant
    # coverage are authority gates; verify every child before assessing one.
    inventory = []
    for container in containers:
        objects = _objects(container, "objects")
        _unique(objects, "name", insensitive=False)
        for obj in objects:
            _require(obj, "all_sas_grants_resolved")
            # Explicit effective-grant subject scope must agree with the
            # object inventory parent; equal permission strings alone do not
            # bind a grant to this container or account.
            if "container_id" in obj and get(obj, "container_id", str).casefold() != get(container, "id", str).casefold():
                raise Unavailable("foreign object grant container")
            if "account_id" in obj and get(obj, "account_id", str).casefold() != get(item, "id", str).casefold():
                raise Unavailable("foreign object grant account")
        inventory.append((container, objects))
    bad = []
    unresolved = []
    for container, objects in inventory:
        container_id = get(container, "id", str)
        try:
            allowed = set(_strings(container, "allowed_permissions"))
        except Unavailable:
            allowed = None
        for obj in objects:
            identity = {"container_id": container_id, "blob": get(obj, "name", str)}
            try:
                if allowed is None:
                    raise Unavailable("container allowed permissions unresolved")
                _require(obj, "effective_acl_resolved")
                actual = set(_strings(obj, "effective_permissions"))
            except Unavailable:
                unresolved.append(identity)
                continue
            if actual != allowed:
                bad.append(identity)
    if bad:
        return result(True, divergent_objects=bad, unresolved_objects=unresolved)
    if unresolved:
        return unknown("object permissions unresolved", unresolved_objects=unresolved)
    return result(False, divergent_objects=[])



def _hash_bytes(row, key="content_base64"):
    value = get(row, key, str)
    try:
        content = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Unavailable("blob/artifact bytes malformed") from exc
    return hashlib.sha256(content).hexdigest()


def _digest(row, key):
    value = get(row, key, str)
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Unavailable("SHA-256 digest malformed")
    return value


def _restore_validation(restore, artifact, policy, rid, scope, completed, now):
    """Verify supplied, independently approved restore-result bytes locally."""
    validation = get(restore, "validation", dict)
    source = get(policy, "approved_restore_validation_source_id", str)
    method = get(policy, "approved_restore_validation_method", str)
    if not source or not method or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", source) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", method):
        raise Unavailable("restore-validation authority or method unavailable")
    tested = _time(get(restore, "tested_at", str))
    digest = _digest(artifact, "sha256")
    expected = {"scope_id": scope, "resource_id": rid, "artifact_uri": get(artifact, "uri", str),
                "artifact_sha256": digest, "export_completed_at": completed.isoformat(),
                "tested_at": tested.isoformat(), "source_id": source, "method": method}
    def matches_export(key, actual, expected_value):
        if key in {"scope_id", "resource_id"}:
            return actual.casefold() == expected_value
        if key in {"export_completed_at", "tested_at"}:
            return _time(actual) == _time(expected_value)
        return actual == expected_value

    for key, value in expected.items():
        actual = get(validation, key, str)
        if not matches_export(key, actual, value):
            raise Unavailable("restore validation is not bound to this export")
    provenance = get(validation, "_provenance", dict)
    if (get(provenance, "source_operation", str) != "ExternalRestoreValidation_Read"
            or get(provenance, "source_id", str) != source
            or get(provenance, "representation", str) != "full"):
        raise Unavailable("restore validation source unavailable")
    _require(provenance, "read_only")
    captured = _time(get(provenance, "captured_at", str))
    observed = _time(get(provenance, "observed_at", str))
    if captured != now or not completed <= tested <= observed <= now:
        raise Unavailable("restore validation chronology unresolved")
    result_artifact = get(validation, "result_artifact", dict)
    if not get(result_artifact, "uri", str).startswith("https://"):
        raise Unavailable("restore result artifact URI malformed")
    _require(result_artifact, "read_complete")
    encoded = get(result_artifact, "content_base64", str)
    if len(encoded) > 87384:
        raise Unavailable("restore result artifact exceeds bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Unavailable("restore result bytes malformed") from exc
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != _digest(result_artifact, "sha256"):
        raise Unavailable("restore result bytes incomplete or altered")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Unavailable("duplicate restore result field")
            result[key] = value
        return result
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise Unavailable("restore result JSON malformed") from exc
    if not isinstance(report, dict):
        raise Unavailable("restore result object absent")
    for key, value in expected.items():
        actual = get(report, key, str)
        if not matches_export(key, actual, value):
            raise Unavailable("restore result is not bound to this export")
    if get(report, "restored_resource_id", str).casefold() != rid:
        raise Unavailable("restored configuration resource differs")
    usable = get(report, "usable", bool)
    if usable:
        _digest(report, "recovered_configuration_sha256")
    return usable


@_signed(BACKUP)
def configuration_backup(item, index):
    ev = _evidence(item, index, BACKUP)
    _require(ev, "required_inventory_authoritative", "manifest_complete", "retention_measured")
    policy = get(ev, "policy", dict)
    max_age = _number(policy, "maximum_age_hours", positive=True)
    retention = _number(policy, "retention_days", positive=True)
    restore_age = _number(policy, "restore_interval_days", positive=True)
    resources = _objects(ev, "required_resources")
    required = _unique(resources)
    _, scope = _context(index)
    if any(not rid.startswith(scope + "/resourcegroups/") for rid in required):
        raise Unavailable("foreign required configuration resource")
    if not required:
        if get(ev, "empty_scope_approved", bool):
            return _na("authoritative policy declares no required configuration resources")
        raise Unavailable("empty required inventory lacks authoritative scope decision")
    exports = _unique(_objects(ev, "exports"), "resource_id")
    if set(exports) - set(required):
        raise Unavailable("export manifest contains foreign required-resource identity")
    now = _time(get(get(index, "context", dict), "created_at", str))
    bad = []
    unresolved = []
    for rid in required:
        export = exports.get(rid)
        if export is None:
            bad.append(rid)
            continue
        try:
            success = get(export, "successful", bool)
            completed = _time(get(export, "completed_at", str))
            if completed > now:
                raise Unavailable("configuration export is future-dated")
            artifact = get(export, "artifact", dict)
            uri = get(artifact, "uri", str)
            if not uri.startswith("https://"):
                raise Unavailable("artifact URI malformed")
            _require(artifact, "read_complete")
            corrupt = _hash_bytes(artifact) != _digest(artifact, "sha256")
            until = _time(get(artifact, "retained_until", str))
            # A fully measured bad export already violates the backup requirement;
            # missing restore proof cannot make that independent failure unknown.
            if (not success or corrupt or now - completed > timedelta(hours=max_age)
                    or until < completed + timedelta(days=retention)):
                bad.append(rid)
                continue
            restore = get(export, "restore", dict)
            tested = _time(get(restore, "tested_at", str))
            if tested > now:
                raise Unavailable("restore record is future-dated")
            restore_ok = get(restore, "successful", bool)
            if get(restore, "artifact_sha256", str) != _digest(artifact, "sha256"):
                raise Unavailable("restore record refers to a different artifact")
            validated_usable = _restore_validation(restore, artifact, policy, rid, scope, completed, now)
            if restore_ok != validated_usable:
                raise Unavailable("restore record conflicts with independent result")
            if not validated_usable or now - tested > timedelta(days=restore_age):
                bad.append(rid)
        except Unavailable:
            # Global authority, completeness and identity guards are above the
            # loop. Only this resource's export/restore proof is unresolved.
            unresolved.append(rid)
    if unresolved:
        if bad:
            return result(True, missing_stale_corrupt_or_unrecoverable_resources=bad,
                          unresolved_resource_ids=unresolved)
        return unknown("required configuration export or restore evidence unresolved",
                       unresolved_resource_ids=unresolved)
    return result(bool(bad), missing_stale_corrupt_or_unrecoverable_resources=bad)


def _signed_container(container, now, *, sequence_baseline=False):
    """Verify RS256 locally against the policy-pinned versioned public JWK.

    The signed bytes are UTF-8 JSON, sorted keys, compact separators,
    ensure_ascii=False. Unsupported formats/algorithms remain UNKNOWN.
    """
    _require(container, "listing_complete", "point_in_time_consistent", "manifest_generation_complete")
    manifest = get(container, "manifest", dict)
    payload = get(manifest, "payload", dict)
    if get(payload, "container_id", str).casefold() != get(container, "id", str).casefold():
        raise Unavailable("signed manifest belongs to a different container")
    if sequence_baseline:
        start, end = _time(get(payload, "window_start", str)), _time(get(payload, "window_end", str))
        if start >= end or end > now:
            raise Unavailable("manifest window malformed or future-dated")
    entries = list_of_objects(get(payload, "entries", list))
    indexed = {}
    sequences = set()
    for entry in entries:
        name = get(entry, "blobName", str)
        version = get(entry, "versionId", str)
        if not name or not version or (name, version) in indexed:
            raise Unavailable("manifest entry identity ambiguous")
        if sequence_baseline:
            sequence = get(entry, "sequence", int)
            if sequence < 0 or sequence in sequences:
                raise Unavailable("manifest entry sequence ambiguous")
            sequences.add(sequence)
        _digest(entry, "sha256")
        indexed[name, version] = entry
    key = get(container, "trusted_key", dict)
    kid = get(key, "kid", str)
    if not re.fullmatch(r"https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/[A-Za-z0-9-]+/[A-Za-z0-9-]+", kid):
        raise Unavailable("trusted signing key must pin Key Vault name and version")
    if get(manifest, "kid", str) != kid or get(manifest, "algorithm", str) != "RS256":
        raise Unavailable("manifest key trust or algorithm unresolved")
    jwk = get(key, "jwk", dict)
    if get(jwk, "kty", str) != "RSA" or get(jwk, "kid", str) != kid:
        raise Unavailable("trusted JWK format or version unresolved")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:
        raise Unavailable("signature verifier unavailable") from exc

    def integer(name):
        encoded = get(jwk, name, str)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
            raise Unavailable("malformed RSA public JWK integer")
        return int.from_bytes(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)), "big")

    public_key = rsa.RSAPublicNumbers(integer("e"), integer("n")).public_key()
    if public_key.key_size < 2048:
        raise Unavailable("unsupported trusted RSA key strength")
    fingerprint = hashlib.sha256(public_key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    if fingerprint != _digest(key, "pinned_spki_sha256"):
        raise Unavailable("trusted public key differs from independently pinned fingerprint")
    try:
        signature = base64.b64decode(get(manifest, "signature_base64", str), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Unavailable("signature encoding malformed") from exc
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    valid = True
    try:
        public_key.verify(signature, canonical, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        valid = False
    # A trusted-key verification failure independently disproves integrity.
    # Unavailable blob bytes cannot repair it or establish specific blob gaps.
    # Completeness still requires a verified baseline before deletion inference.
    if not valid and not sequence_baseline:
        return payload, indexed, {}, False
    blobs = _objects(container, "blobs")
    listing = {}
    for blob in blobs:
        identity = get(blob, "blobName", str), get(blob, "versionId", str)
        if not all(identity) or identity in listing:
            raise Unavailable("versioned blob listing identity ambiguous")
        _require(blob, "read_complete", "version_consistent")
        listing[identity] = _hash_bytes(blob)
    return payload, indexed, listing, valid


@_signed(INTEGRITY)
def signed_integrity(item, index):
    ev = _evidence(item, index, INTEGRITY)
    _require(ev, "protected_scope_authoritative")
    containers = _containers(ev, get(item, "id", str))
    if not containers:
        return _na("authoritative protected container scope is empty")
    now = _time(get(get(index, "context", dict), "created_at", str))
    bad = []
    unresolved = []
    for container in containers:
        cid = get(container, "id", str)
        try:
            _, entries, listing, valid = _signed_container(container, now)
        except (Unavailable, ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError):
            # Scope, provenance, inventory completeness and container identity
            # were validated above; only this container's proof is unresolved.
            unresolved.append(cid)
            continue
        if not valid:
            bad.append({"container_id": cid, "invalid_signature": True,
                        "missing_or_extra": [], "changed": []})
            continue
        differing = set(entries) ^ set(listing)
        changed = [identity for identity in set(entries) & set(listing)
                   if listing[identity] != entries[identity]["sha256"]]
        if not valid or differing or changed:
            bad.append({"container_id": cid, "invalid_signature": not valid,
                        "missing_or_extra": sorted(differing), "changed": sorted(changed)})
    if unresolved:
        if bad:
            return result(True, manifest_integrity_gaps=bad, unresolved_container_ids=unresolved)
        return unknown("signed log integrity evidence unresolved", unresolved_container_ids=unresolved)
    return result(bool(bad), manifest_integrity_gaps=bad)


@_signed(COMPLETENESS)
def signed_completeness(item, index):
    ev = _evidence(item, index, COMPLETENESS)
    _require(ev, "protected_scope_authoritative")
    containers = _containers(ev, get(item, "id", str))
    if not containers:
        return _na("authoritative protected container scope is empty")
    now = _time(get(get(index, "context", dict), "created_at", str))
    bad = []
    unresolved = []
    for container in containers:
        cid = get(container, "id", str)
        try:
            payload, entries, listing, valid = _signed_container(container, now, sequence_baseline=True)
            if not valid:
                raise Unavailable("deletion baseline manifest signature does not verify")
            baseline = get(container, "baseline", dict)
            _require(baseline, "independently_established", "complete")
            if (_time(get(baseline, "window_start", str)) != _time(get(payload, "window_start", str))
                    or _time(get(baseline, "window_end", str)) != _time(get(payload, "window_end", str))):
                raise Unavailable("independent policy window differs from signed manifest")
            expected = get(baseline, "expected_sequences", list)
            if any(type(x) is not int or x < 0 for x in expected) or len(set(expected)) != len(expected):
                raise Unavailable("independent sequence baseline malformed")
        except (Unavailable, ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError):
            unresolved.append(cid)
            continue
        sequences = {get(e, "sequence", int) for e in entries.values()}
        missing_seq = set(expected) - sequences
        missing_blob = set(entries) - set(listing)
        changed = [identity for identity in set(entries) & set(listing)
                   if listing[identity] != entries[identity]["sha256"]]
        if missing_seq or missing_blob or changed:
            bad.append({"container_id": cid, "missing_sequences": sorted(missing_seq),
                        "missing_blobs": sorted(missing_blob), "changed": sorted(changed)})
        elif sequences - set(expected) or set(listing) - set(entries):
            # The independently complete sequence universe and signed digest
            # inventory cannot establish completeness for these extra items.
            unresolved.append(cid)
    if unresolved:
        if bad:
            return result(True, verified_log_deletion_or_digest_gaps=bad,
                          unresolved_container_ids=unresolved)
        return unknown("signed log completeness evidence unresolved", unresolved_container_ids=unresolved)
    return result(bool(bad), verified_log_deletion_or_digest_gaps=bad)


@_signed(GEO)
def customer_data_regions(item, index):
    ev = _evidence(item, index, GEO)
    _require(ev, "classified_inventory_complete", "all_storage_and_processing_services_covered",
             "region_mapping_resolved", "policy_inheritance_resolved")
    approved = _strings(ev, "approved_eu_regions", nonempty=True)
    if any(not region.isascii() for region in approved):
        raise Unavailable("approved region identifier is not ASCII")
    # Azure programmatic IDs use ASCII letters and digits; labels are not IDs.
    allowed = {region.lower() for region in approved if region.isalnum()}
    resources = _objects(ev, "customer_data_resources")
    identities = _unique(resources)
    _, scope = _context(index)
    if any(not rid.startswith(scope + "/") for rid in identities):
        raise Unavailable("foreign classified customer-data resource")
    if not resources:
        if get(ev, "empty_scope_approved", bool):
            return _na("authoritative complete scope contains no customer-data resources")
        raise Unavailable("empty classified inventory is not approved")
    # The ARM primary location is a native fact about this storage account.
    # It cannot establish all data/processing locations, but an external
    # complete location claim for this same classified account must include it.
    account_id = get(item, "id", str).casefold()
    if "location" in item or "location" in item.get("_coverage", {}):
        primary = get(item, "location", str)
        if not primary or not primary.isascii() or not primary.isalnum():
            raise Unavailable("native storage primary location malformed")
        account_resource = identities.get(account_id)
        if account_resource is not None:
            claimed = _strings(account_resource, "locations", nonempty=True)
            if primary.lower() not in {location.lower() for location in claimed
                                       if location.isascii() and location.isalnum()}:
                raise Unavailable("classified locations omit native storage primary region")
    bad = []
    for resource in resources:
        _require(resource, "primary_replica_processing_locations_complete", "restriction_policy_measured")
        locations = _strings(resource, "locations", nonempty=True)
        assigned = get(resource, "effective_restriction_assigned", bool)
        compliant = get(resource, "restriction_compliant", bool)
        if any(not location.isascii() or not location.isalnum() or location.lower() not in allowed
               for location in locations) or not assigned or not compliant:
            bad.append(get(resource, "id", str))
    return result(bool(bad), nonapproved_locations_or_region_policy_gaps=bad,
                  evaluated_customer_data_resources=len(resources))


def _rules(ev):
    policy = get(ev, "management_policy", dict)
    _require(policy, "read_complete")
    rules = list_of_objects(get(policy, "properties.policy.rules", list))
    _unique(rules, "name", insensitive=False)
    enabled = []
    for rule in rules:
        if get(rule, "type", str) != "Lifecycle":
            raise Unavailable("unrecognized management rule type")
        if get(rule, "enabled", bool):
            definition = get(rule, "definition", dict)
            filters = get(definition, "filters", dict)
            types = _strings(filters, "blobTypes", nonempty=True)
            if set(types) - {"blockBlob", "appendBlob"}:
                raise Unavailable("unrecognized lifecycle blob type")
            # Omitted optional filter fields are documented broad defaults,
            # usable only in a complete management-policy GET.
            prefixes = _strings(filters, "prefixMatch") if "prefixMatch" in filters or "prefixMatch" in filters.get("_coverage", {}) else []
            tags = list_of_objects(get(filters, "blobIndexMatch", list)) if "blobIndexMatch" in filters or "blobIndexMatch" in filters.get("_coverage", {}) else []
            for tag in tags:
                if get(tag, "op", str) != "==" or not get(tag, "name", str):
                    raise Unavailable("unsupported blob-index filter")
                get(tag, "value", str)
            actions = get(definition, "actions", dict)
            enabled.append((rule, types, prefixes, tags, actions))
    return enabled


def _delete_days(actions):
    if "baseBlob" not in actions:
        return None
    base = get(actions, "baseBlob", dict)
    if "delete" not in base:
        return None
    delete = get(base, "delete", dict)
    if set(delete) - {"daysAfterModificationGreaterThan", "_coverage", "collection_status"}:
        raise Unavailable("creation/last-access lifecycle deletion predicate unresolved")
    return _integer(delete, "daysAfterModificationGreaterThan")


@_signed(LIFECYCLE)
def protected_lifecycle(item, index):
    ev = _evidence(item, index, LIFECYCLE)
    _require(ev, "protected_scope_authoritative", "version_snapshot_protection_resolved", "overlap_resolved")
    rules = _rules(ev)
    protected = _objects(ev, "protected_prefixes")
    _unique(protected, "prefix", insensitive=False)
    if not protected:
        return _na("authoritative policy contains no protected blockBlob prefixes")
    bad = []
    for target in protected:
        prefix = get(target, "prefix", str)
        minimum = _number(target, "minimum_retention_days")
        maximum = _number(target, "maximum_deletion_days", positive=True)
        if minimum > maximum:
            raise Unavailable("approved lifecycle bounds inverted")
        covering = False
        early = False
        for _, types, prefixes, tags, actions in rules:
            if "blockBlob" not in types:
                continue
            filters = prefixes or [""]
            overlap = any(prefix.startswith(p) or p.startswith(prefix) for p in filters)
            if not overlap:
                continue
            days = _delete_days(actions)
            if days is None:
                continue
            if tags:
                raise Unavailable("tag-filter overlap of protected prefix unresolved")
            early |= days < minimum
            covering |= any(prefix.startswith(p) for p in filters) and days <= maximum
        if early or not covering:
            bad.append({"prefix": prefix, "early_delete": early, "timely_covering_delete": covering})
    return result(bool(bad), lifecycle_window_gaps=bad)


def _immutability(policy):
    """Return measured default retention; None means authoritative absence."""
    _require(policy, "read_complete", "inheritance_resolved")
    if not get(policy, "present", bool):
        return None
    state = get(policy, "properties.state", str)
    if state not in {"Locked", "Unlocked", "Disabled"}:
        raise Unavailable("unknown immutability policy state")
    days = _integer(policy, "properties.immutabilityPeriodSinceCreationInDays")
    return state, days


@_signed(IMMUTABLE)
def default_immutability(item, index):
    ev = _evidence(item, index, IMMUTABLE)
    _require(ev, "account_read_complete")
    containers = _containers(ev, get(item, "id", str))
    if not containers:
        return _na("complete container inventory is empty")
    bad = []
    for container in containers:
        _require(container, "container_read_complete", "default_version_policy_support_resolved")
        # Resolution must attest new-write inheritance, not the versioning flag.
        effective = get(container, "effective_default_policy", dict)
        policy = _immutability(effective)
        inherited = get(effective, "new_writes_inherit", bool)
        if policy is not None:
            source = get(effective, "source_kind", str)
            source_id = get(effective, "source_id", str).casefold()
            expected = {
                "container_time": get(container, "id", str).casefold() + "/immutabilitypolicies/default",
                "container_version_default": get(container, "id", str).casefold(),
                "account_version_default": get(item, "id", str).casefold(),
            }
            if source not in expected or source_id != expected[source]:
                raise Unavailable("effective default policy source or inheritance scope unresolved")
        if policy is None or policy[0] == "Disabled" or policy[1] <= 0 or not inherited:
            bad.append(get(container, "id", str))
    return result(bool(bad), containers_without_effective_default_retention=bad)



def _siem_evidence(item, index):
    """Validate the full outer authority, then defer child details per archive."""
    parent = _own(item, index, "storage_account")
    rows = _inventory(index, EVIDENCE_KINDS[SIEM])
    found = []
    for row in rows.values():
        pid = get(row, "parent_id", str).casefold()
        if not get(row, "id", str).casefold().startswith(pid + "/complianceEvidence/".casefold()):
            raise Unavailable("evidence identity not bound to parent")
        if pid not in _inventory(index, "storage_account"):
            raise Unavailable("evidence bound to uncollected parent")
        if pid == parent:
            found.append(row)
    if len(found) != 1:
        raise Unavailable("parent evidence absent or ambiguous")
    row = found[0]
    provenance = get(row, "_provenance", dict)
    if get(provenance, "schema_version", int) != 1:
        raise Unavailable("unsupported evidence contract version")
    _require(provenance, "read_only", "policy_approved", "complete")
    context, _ = _context(index)
    if _time(get(provenance, "captured_at", str)) != _time(get(context, "created_at", str)):
        raise Unavailable("evidence is not bound to snapshot instant")
    payload = get(row, "payload", dict)
    archive_inventory = get(payload, "containers", dict)
    shallow = dict(payload)
    shallow["containers"] = dict(archive_inventory)
    shallow["containers"]["items"] = []
    _validate_evidence(shallow)
    return payload


def _siem_ids_digest(values):
    canonical = json.dumps(sorted(values), separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(canonical).hexdigest()


def _siem_observation_binding(ev, container, source_ids, destination_ids, source, destination, synchronized,
                              account_id, start, end, now):
    approved = get(ev, "approved_delivery_source_id", str)
    observation = get(container, "observation", dict)
    provenance = get(observation, "_provenance", dict)
    if (not approved or get(provenance, "source_operation", str) != "ExternalSiemObservation_Read"
            or get(provenance, "source_id", str) != approved):
        raise Unavailable("SIEM delivery observation authority unavailable")
    _require(provenance, "read_only", "complete")
    if (_time(get(provenance, "captured_at", str)) != now
            or not end <= _time(get(provenance, "observed_at", str)) <= now
            or get(observation, "account_id", str).casefold() != account_id
            or get(observation, "container_id", str).casefold() != get(container, "id", str).casefold()
            or _time(get(observation, "window_start", str)) != start
            or _time(get(observation, "window_end", str)) != end
            or get(observation, "source_count", int) != source
            or get(observation, "destination_count", int) != destination
            or get(observation, "source_event_ids_sha256", str) != _siem_ids_digest(source_ids)
            or get(observation, "destination_event_ids_sha256", str) != _siem_ids_digest(destination_ids)
            or get(observation, "clock_synchronized", bool) != synchronized):
        raise Unavailable("SIEM delivery observation differs from measured container window")


def _siem_hash_binding(ev, container, record, event_id, start, end, now):
    approved = get(ev, "approved_hash_source_id", str)
    provenance = get(record, "_provenance", dict)
    if (not approved or get(provenance, "source_operation", str) != "ExternalSiemHashComparison_Read"
            or get(provenance, "source_id", str) != approved):
        raise Unavailable("SIEM hash comparison authority unavailable")
    _require(provenance, "read_only")
    if (_time(get(provenance, "captured_at", str)) != now
            or not end <= _time(get(provenance, "observed_at", str)) <= now
            or get(record, "container_id", str).casefold() != get(container, "id", str).casefold()
            or _time(get(record, "window_start", str)) != start
            or _time(get(record, "window_end", str)) != end
            or get(record, "source_event_id", str) != event_id
            or get(record, "destination_event_id", str) != event_id):
        raise Unavailable("SIEM hash comparison belongs to another event or window")


@_signed(SIEM)
def siem_archives(item, index):
    ev = _siem_evidence(item, index)
    _require(ev, "archive_scope_authoritative", "observation_window_complete")
    retention = _number(ev, "approved_retention_days", positive=True)
    containers = _containers(ev, get(item, "id", str))
    if not containers:
        return _na("authoritative policy lists no SIEM archive containers")
    now = _time(get(get(index, "context", dict), "created_at", str))
    start, end = _time(get(ev, "window_start", str)), _time(get(ev, "window_end", str))
    if start >= end or end > now:
        raise Unavailable("SIEM observation window malformed")
    bad = []
    unresolved = []
    account_id = get(item, "id", str).casefold()
    for container in containers:
        cid = get(container, "id", str)
        try:
            policy = _immutability(get(container, "immutability_policy", dict))
            if policy is None or policy[0] != "Locked" or policy[1] < retention:
                bad.append(cid)
                continue
            _validate_evidence(container)
            _require(container, "ingestion_inventory_complete", "delivery_counts_measured", "clock_sync_measured",
                     "copy_hash_inventory_complete")
            source = get(container, "source_count", int)
            destination = get(container, "destination_count", int)
            if min(source, destination) < 0:
                raise Unavailable("negative SIEM event count")
            source_ids = set(_strings(container, "source_event_ids"))
            destination_ids = set(_strings(container, "destination_event_ids"))
            if len(source_ids) != source or len(destination_ids) != destination:
                raise Unavailable("SIEM event identity inventory conflicts with measured counts")
            synchronized = get(container, "clock_synchronized", bool)
            _siem_observation_binding(ev, container, source_ids, destination_ids, source, destination,
                                      synchronized, account_id, start, end, now)
            records = _objects(container, "hash_records")
            hashes_by_id = _unique(records, "event_id", insensitive=False)
            if set(hashes_by_id) != destination_ids:
                raise Unavailable("SIEM copy hash coverage differs from destination inventory")
            known_failure = source_ids != destination_ids or not synchronized
            hash_unresolved = False
            for event_id, record in hashes_by_id.items():
                try:
                    _siem_hash_binding(ev, container, record, event_id, start, end, now)
                    known_failure |= _digest(record, "original_sha256") != _digest(record, "copy_sha256")
                except Unavailable:
                    hash_unresolved = True
            if known_failure:
                bad.append(cid)
            elif hash_unresolved:
                raise Unavailable("SIEM hash comparison unresolved")
        except Unavailable:
            unresolved.append(cid)
    if bad:
        return result(True, unprotected_or_incomplete_siem_archives=bad, unresolved_archive_ids=unresolved)
    if unresolved:
        return unknown("SIEM archive delivery or integrity evidence unresolved", unresolved_archive_ids=unresolved)
    return result(False, unprotected_or_incomplete_siem_archives=[])


def _supported_actions(actions):
    supported = {}
    for kind, predicates in {
            "baseBlob": {"daysAfterModificationGreaterThan", "daysAfterCreationGreaterThan", "daysAfterLastAccessTimeGreaterThan"},
            "snapshot": {"daysAfterCreationGreaterThan"},
            "version": {"daysAfterCreationGreaterThan"}}.items():
        if kind not in actions:
            continue
        block = get(actions, kind, dict)
        found = set()
        for name, value in block.items():
            if name in {"_coverage", "collection_status"}:
                continue
            if name == "enableAutoTierToHotFromCool" and kind == "baseBlob":
                get(block, name, bool)
                continue
            if name not in {"delete", "tierToCool", "tierToCold", "tierToArchive"}:
                raise Unavailable("unsupported lifecycle action")
            action = get(block, name, dict)
            keys = set(action) - {"_coverage", "collection_status"}
            if not keys or keys - predicates:
                raise Unavailable("unsupported lifecycle action age predicate")
            for key in keys:
                _integer(action, key)
            found.add(name)
        supported[kind] = found
    if set(actions) - {"baseBlob", "snapshot", "version", "_coverage", "collection_status"}:
        raise Unavailable("unknown lifecycle action target")
    return supported


@_signed(VERSION_LIFECYCLE)
def versioned_lifecycle(item, index):
    ev = _evidence(item, index, VERSION_LIFECYCLE)
    _require(ev, "versioning_read_complete")
    enabled = get(ev, "blob_service.properties.isVersioningEnabled", bool)
    containers = _containers(ev, get(item, "id", str))
    if not enabled or not containers:
        return _na("no containers in a versioning-enabled account")
    rules = [(types, prefixes, tags, _supported_actions(actions))
             for _, types, prefixes, tags, actions in _rules(ev)]
    bad = []
    for container in containers:
        _require(container, "blob_population_complete", "blob_tags_complete", "required_scope_authoritative")
        name = get(container, "id", str).rsplit("/", 1)[-1]
        objects = _objects(container, "required_objects")
        _unique(objects, "identity", insensitive=False)
        if not objects:
            # Empty current population cannot establish what future required
            # versions/tags are; do not infer applicability from a default.
            raise Unavailable("empty required blob population cannot prove lifecycle coverage")
        for obj in objects:
            path = get(obj, "path", str)
            if not path.startswith(name + "/"):
                raise Unavailable("foreign lifecycle object path")
            blob_type = get(obj, "blobType", str)
            if blob_type not in {"blockBlob", "appendBlob"}:
                raise Unavailable("unknown required blob type")
            kind = get(obj, "kind", str)
            if kind not in {"baseBlob", "snapshot", "version"}:
                raise Unavailable("unknown required blob/version kind")
            obj_tags = get(obj, "tags", dict)
            if any(not isinstance(k, str) or not isinstance(v, str) for k, v in obj_tags.items()):
                raise Unavailable("blob tags malformed")
            applies = []
            for types, prefixes, tags, actions in rules:
                # Require a full container prefix; a selected current path is
                # not evidence of coverage for the container's required scope.
                full_prefix = not prefixes or any((name + "/").startswith(p) for p in prefixes)
                tag_match = all(obj_tags.get(get(tag, "name", str)) == get(tag, "value", str) for tag in tags)
                valid_actions = actions.get(kind, set())
                supported_for_type = bool(valid_actions) and (blob_type == "blockBlob" or "delete" in valid_actions)
                applies.append(full_prefix and blob_type in types and tag_match and supported_for_type)
            if not any(applies):
                bad.append({"container_id": get(container, "id", str), "object": get(obj, "identity", str)})
    return result(bool(bad), required_objects_without_covering_lifecycle_rule=bad)


def _key_source(key):
    source = get(key, "source", str)
    sources = {"microsoft.storage": "Microsoft.Storage", "microsoft.keyvault": "Microsoft.KeyVault"}
    if source.casefold() not in sources:
        raise Unavailable("encryption key source unrecognized")
    source = sources[source.casefold()]
    if source == "Microsoft.KeyVault":
        kid = get(key, "key_uri", str)
        if not re.fullmatch(r"https://[A-Za-z0-9-]+\.vault\.azure\.net/keys/[A-Za-z0-9-]+/[A-Za-z0-9-]+", kid):
            raise Unavailable("effective Key Vault key reference/version unresolved")
    return source


@_signed(KEYS)
def blob_keyvault_keys(item, index):
    from peaso.collectors import azure_storage_blob_keys_native as native
    if native.has_native(item, index):
        parent = _own(item, index, 'storage_account')
        context, _ = _context(index)
        return native.assess(parent, context, _inventory(index, native.KIND),
            _inventory(index, 'storage_account'))
    ev = _evidence(item, index, KEYS)
    _require(ev, "account_key_resolved", "encryption_scopes_complete")
    containers = _containers(ev, get(item, "id", str))
    if not containers:
        return _na("complete container inventory is empty")
    bad = []
    for container in containers:
        _require(container, "default_scope_resolved", "override_use_resolved", "historical_blob_keys_resolved")
        default_source = _key_source(get(container, "effective_default_key", dict))
        mandatory = get(container, "denyEncryptionScopeOverride", bool)
        allowed_keys = _objects(container, "permitted_write_keys")
        sources = [_key_source(key) for key in allowed_keys]
        if not sources:
            raise Unavailable("new-write effective key set unavailable")
        if mandatory and set(sources) != {default_source} or default_source not in sources:
            raise Unavailable("effective write-key set conflicts with default/override restriction")
        blobs = _objects(container, "blobs")
        _unique(blobs, "identity", insensitive=False)
        measured = []
        for blob in blobs:
            _require(blob, "scope_resolved", "key_resolved")
            measured.append(_key_source(get(blob, "effective_key", dict)))
        if "Microsoft.Storage" in measured or mandatory and default_source == "Microsoft.Storage":
            bad.append(get(container, "id", str))
        elif "Microsoft.Storage" in sources:
            # Optional platform-managed writes without an observed blob are
            # not a measured mandatory platform-managed scope.
            raise Unavailable("new writes can use an optional platform-managed key")
    return result(bool(bad), containers_with_measured_platform_managed_encryption=bad)


def _apis(ev, parent):
    _require(ev, "revision_coverage_complete")
    rows = _objects(ev, "apis")
    _unique(rows)
    for api in rows:
        _child_id(api, parent, "apis")
    return rows


@_signed(PROTOCOLS)
def api_protocols(item, index):
    ev = _evidence(item, index, PROTOCOLS)
    apis = _apis(ev, get(item, "id", str))
    if not apis:
        return _na("complete in-scope API inventory is empty")
    bad = []
    allowed = {"http", "https", "ws", "wss"}
    for api in apis:
        parameter = get(api, "frozen_protocol_policy", dict)
        _require(parameter, "frozen", "scope_resolved")
        expected = get(parameter, "expected_endpoint_type", str)
        forbidden = set(_strings(parameter, "forbidden_protocols"))
        actual = set(_strings(api, "properties.protocols", nonempty=False))
        if expected not in allowed or forbidden - allowed or actual - allowed or expected in forbidden:
            raise Unavailable("protocol enum or frozen expected endpoint type unsupported")
        if expected not in actual or actual & forbidden:
            bad.append(get(api, "id", str))
    return result(bool(bad), api_protocol_mismatches=bad)


@_signed(DIAGNOSTICS)
def api_application_insights(item, index):
    from ..collectors import azure_apim_diagnostic_evidence_native as native
    if native.has_native(item, index):
        parent = _own(item, index, 'api_management')
        context, _ = _context(index)
        return native.assess(parent, context, _inventory(index, native.KIND),
            _inventory(index, native.SOURCE), _inventory(index, 'api_management'))
    ev = _evidence(item, index, DIAGNOSTICS)
    apis = _apis(ev, get(item, "id", str))
    if not apis:
        return _na("complete API inventory is empty")
    parent_id = get(item, "id", str)
    def bound_child(row, parent, segment):
        rid = get(row, "id", str)
        pattern = re.escape(parent) + "/" + re.escape(segment) + r"/[^/?#%\\\s]+"
        if re.fullmatch(pattern, rid, re.I) is None:
            raise Unavailable("foreign or malformed APIM child identity")
        return rid.casefold()

    loggers = _unique(_objects(ev, "loggers"))
    for logger in loggers.values():
        bound_child(logger, parent_id, "loggers")
    # Resolve the complete API and child identity universe before verdicts.
    validated = []
    for api in apis:
        bound_child(api, parent_id, "apis")
        api_type = get(api, "properties.type", str)
        if api_type not in {"http", "odata", "soap", "websocket", "graphql", "grpc"}:
            raise Unavailable("APIM API type unrecognized")
        is_rest = api_type in {"http", "odata"}
        if not is_rest and "diagnostics" not in api:
            continue
        diagnostics = _objects(api, "diagnostics")
        _unique(diagnostics)
        # Identity and source binding are unconditional: a malformed peer may
        # never be hidden by a different API's missing diagnostic.
        references = []
        for diagnostic in diagnostics:
            bound_child(diagnostic, get(api, "id", str), "diagnostics")
            reference = get(diagnostic, "properties.loggerId", str).casefold()
            if re.fullmatch(re.escape(parent_id) + r"/loggers/[^/?#%\\\s]+", reference, re.I) is None:
                raise Unavailable("diagnostic logger reference is foreign or malformed")
            references.append(reference)
        validated.append((api, is_rest, diagnostics, references))
    bad = []
    uncertain = False
    rest = 0
    for api, is_rest, diagnostics, references in validated:
        if not is_rest:
            continue
        rest += 1
        if not diagnostics:
            bad.append(get(api, "id", str))
            continue
        possible = False
        qualified = False
        metadata_unresolved = False
        for diagnostic, reference in zip(diagnostics, references):
            # Every diagnostic needs resolved trace settings, including peers
            # of a usable route. Keep that uncertainty within this API.
            try:
                props = get(diagnostic, "properties", dict)
                sampling = _number(props, "sampling.percentage")
                if sampling > 100:
                    raise Unavailable("APIM sampling percentage outside API range")
                if "alwaysLog" not in props:
                    raise Unavailable("APIM alwaysLog value unresolved")
                always = get(props, "alwaysLog")
                if always not in (None, "allErrors"):
                    raise Unavailable("unknown APIM alwaysLog value")
            except Unavailable:
                metadata_unresolved = True
                continue
            try:
                logger = loggers.get(reference)
                if logger is None:
                    continue
                logger_type = get(logger, "properties.loggerType", str)
                if logger_type not in {"applicationInsights", "azureEventHub", "azureMonitor"}:
                    raise Unavailable("unknown APIM logger type")
                if logger_type != "applicationInsights" or sampling == 0 and always != "allErrors":
                    continue
                _require(logger, "credentials_measured")
                if get(logger, "usable", bool):
                    qualified = True
            except Unavailable:
                possible = True
        if metadata_unresolved or not qualified and possible:
            uncertain = True
        elif not qualified:
            bad.append(get(api, "id", str))
    if not rest:
        return _na("complete scope contains no APIM REST APIs")
    if bad:
        return result(True, rest_apis_without_usable_tracing_diagnostic=bad)
    if uncertain:
        raise Unavailable("referenced APIM logger usability or diagnostic configuration unresolved")
    return result(False, rest_apis_without_usable_tracing_diagnostic=[])


@_signed(WAF)
def api_waf_paths(item, index):
    ev = _evidence(item, index, WAF)
    apis = _apis(ev, get(item, "id", str))
    if not apis:
        return _na("complete in-scope API inventory is empty")
    _require(ev, "service_get_complete", "gateway_hostnames_complete", "dns_complete",
             "alternate_endpoints_complete", "origin_restrictions_resolved", "route_matching_complete")
    hostnames = _strings(ev, "gateway_hostnames", nonempty=True)
    for hostname in hostnames:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", hostname):
            raise Unavailable("APIM gateway hostname malformed")
    paths = _objects(ev, "reachable_paths")
    _unique(paths, "path_id", insensitive=False)
    expected = {(get(api, "id", str).casefold(), host.casefold()) for api in apis for host in hostnames}
    covered = set()
    bad = []
    for path in paths:
        pair = get(path, "api_id", str).casefold(), get(path, "hostname", str).casefold()
        if pair not in expected:
            raise Unavailable("route proof belongs to an unlisted API or hostname")
        covered.add(pair)
        _require(path, "dns_origin_route_chain_measured", "all_matching_routes_resolved", "reachability_measured")
        reachable = get(path, "reachable", bool)
        direct = get(path, "direct_apim_ingress", bool)
        waf = get(path, "waf", dict)
        _require(waf, "effective_policy_measured")
        attached = get(waf, "attached", bool)
        enabled = get(waf, "enabled", bool)
        mode = get(waf, "mode", str)
        if mode not in {"Prevention", "Detection", "None"}:
            raise Unavailable("WAF mode unrecognized")
        if reachable and (direct or not (attached and enabled and mode == "Prevention")):
            bad.append(get(path, "path_id", str))
    if covered != expected:
        raise Unavailable("not every API/hostname has complete path or blocked-path evidence")
    if not get(ev, "direct_ingress_blocked", bool) and not bad:
        raise Unavailable("direct APIM gateway ingress blocking unproven")
    return result(bool(bad), publicly_reachable_unprotected_apim_paths=bad)


# Capture this module's wrapped evaluators for isolated direct-module tests.
REGISTERED_CHECKS = tuple(check for check in CHECKS if check.id in IDS)
EVALUATORS = {check.id: check.evaluate for check in REGISTERED_CHECKS}
