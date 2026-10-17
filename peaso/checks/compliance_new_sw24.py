"""Signed sw24 Azure predicates over scoped native and measured snapshot facts.

No network calls or probes are initiated here. Complex policy/network/query
semantics require independently reviewed, configuration-bound resolution facts;
configuration presence alone never substitutes for behavioral evidence.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
import json
import math
import re
from urllib.parse import urlsplit

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, guard, list_of_objects

SPECS = {'azure_api_management_3_5_1_1_345bdac': {'id': 'azure_api_management_3_5_1_1_345bdac',
                                          'provider': 'azure',
                                          'resource_kind': 'api_management',
                                          'data_source': 'Paged APIM APIs and operations LIST; '
                                                         'operation, API, product and global policy GET '
                                                         '2024-05-01 with XML properties.value, plus '
                                                         'APIM caches LIST/GET and referenced Azure '
                                                         'Cache for Redis TLS configuration. Resolve '
                                                         'XML base inheritance, policy conditions and '
                                                         'cache-lookup/cache-store IDs; policy supplies '
                                                         'requiredOperationIds and '
                                                         'approvedEncryptedCacheIds.',
                                          'predicate': 'For every required APIM operation, PASS only '
                                                       'when its effective inbound and outbound policy '
                                                       'paths both perform approved cache lookup/store, '
                                                       'the referenced external cache is approved, and '
                                                       'its endpoint/TLS settings prove encryption in '
                                                       'transit and approved at-rest protection. FAIL '
                                                       'on a fully resolved path lacking a required '
                                                       'caching step or using a known '
                                                       'unencrypted/unapproved cache. UNKNOWN on '
                                                       'unresolved base inheritance, choose branches, '
                                                       'missing cache identity, redacted connection '
                                                       'string, encryption evidence or incomplete '
                                                       'operation/policy pages. No required operations '
                                                       'is UNKNOWN until scope policy is supplied.',
                                          'severity': 'medium',
                                          'category': 'encryption',
                                          'title': 'Required APIM operations cache through approved '
                                                   'encrypted cache',
                                          'description': 'Checks operation-level caching and approved '
                                                         'encrypted external cache use for explicitly '
                                                         'listed operations.',
                                          'remediation_hint': 'Add effective cache-lookup and '
                                                              'cache-store policies to each required '
                                                              'operation, select an approved external '
                                                              'cache, and configure and verify its TLS '
                                                              'and at-rest encryption.'},
 'azure_api_management_app_http_logs_enabled_21c108d': {'id': 'azure_api_management_app_http_logs_enabled_21c108d',
                                                        'provider': 'azure',
                                                        'resource_kind': 'api_management',
                                                        'data_source': 'Paged APIM service, API and '
                                                                       'API-revision inventory; service '
                                                                       'and per-API diagnostics LIST '
                                                                       'plus logger LIST (2024-05-01); '
                                                                       'diagnostic properties.loggerId, '
                                                                       'frontend, backend, sampling and '
                                                                       'alwaysLog; logger destination '
                                                                       'and dated sink-ingestion '
                                                                       'evidence.',
                                                        'predicate': 'For every APIM API and deployed '
                                                                     'revision, resolve its effective '
                                                                     'API diagnostic or inherited '
                                                                     'service diagnostic. PASS only if '
                                                                     'it references an existing usable '
                                                                     'logger, configured '
                                                                     'frontend/backend HTTP capture and '
                                                                     'sampling meet approved coverage, '
                                                                     'and dated sink evidence confirms '
                                                                     'receipt. FAIL if complete API, '
                                                                     'diagnostic, override and logger '
                                                                     'evidence proves no HTTP access '
                                                                     'logging. UNKNOWN if API '
                                                                     'inventory, inheritance, '
                                                                     'destination, ingestion, sampling '
                                                                     'policy or any page is unresolved. '
                                                                     'Do not require a nonexistent '
                                                                     'diagnostic or logger enabled '
                                                                     'flag.',
                                                        'severity': 'medium',
                                                        'category': 'logging',
                                                        'title': 'APIM HTTP diagnostics send logs '
                                                                 'through a usable logger',
                                                        'description': 'Checks effective APIM HTTP '
                                                                       'diagnostics, logger binding and '
                                                                       'required sampling across '
                                                                       'service and API scopes.',
                                                        'remediation_hint': 'Attach a usable '
                                                                            'Application Insights or '
                                                                            'Event Hub logger to the '
                                                                            'effective service/API '
                                                                            'diagnostic, configure '
                                                                            'approved HTTP capture and '
                                                                            'sampling, and verify '
                                                                            'access events at the '
                                                                            'sink.'},
 'azure_api_management_app_http_logs_enabled_9b3b56e': {'id': 'azure_api_management_app_http_logs_enabled_9b3b56e',
                                                        'provider': 'azure',
                                                        'resource_kind': 'api_management',
                                                        'data_source': 'Paged APIM service and API '
                                                                       'inventory; service diagnostics '
                                                                       'LIST and API diagnostics LIST '
                                                                       '2024-05-01; service loggers '
                                                                       'LIST. Inspect '
                                                                       'diagnostic.properties.loggerId, '
                                                                       'verbosity enum '
                                                                       'error/information/verbose, '
                                                                       'sampling, alwaysLog and '
                                                                       'frontend.request/response, and '
                                                                       'resolve logger destination.',
                                                        'predicate': 'For every APIM service, PASS only '
                                                                     'when an applicable service or API '
                                                                     'diagnostic covers every required '
                                                                     'API, references a valid logger, '
                                                                     'has effective HTTP diagnostic '
                                                                     'logging, and has verbosity error '
                                                                     'or verbose as specified by the '
                                                                     'frozen rule. FAIL if complete '
                                                                     'child inventories prove absent '
                                                                     'coverage, an invalid logger, '
                                                                     'disabled effective logging, or a '
                                                                     'different verbosity. UNKNOWN for '
                                                                     'missing API, logger, diagnostic, '
                                                                     'paging or effective routing '
                                                                     'evidence. Do not require nonzero '
                                                                     'request/response body bytes when '
                                                                     'HTTP metadata is logged.',
                                                        'severity': 'medium',
                                                        'category': 'logging',
                                                        'title': 'Enable APIM diagnostics with a logger',
                                                        'description': 'Enable APIM diagnostics with a '
                                                                       'logger. A finding is raised '
                                                                       'when an APIM service has no '
                                                                       'diagnostic connected to a valid '
                                                                       'logger for the required scope.',
                                                        'remediation_hint': 'Configure service or API '
                                                                            'diagnostics with a valid '
                                                                            'logger and HTTP '
                                                                            'request/response settings; '
                                                                            'set trace verbosity to '
                                                                            'error or verbose and '
                                                                            'verify delivery.'},
 'azure_api_management_app_http_logs_enabled_9ef06db': {'id': 'azure_api_management_app_http_logs_enabled_9ef06db',
                                                        'provider': 'azure',
                                                        'resource_kind': 'api_management',
                                                        'data_source': 'Paged APIM APIs, operations and '
                                                                       'API/service diagnostics LIST '
                                                                       '2024-05-01; join '
                                                                       'diagnostic.properties.loggerId '
                                                                       'to service logger.id and '
                                                                       'inspect loggerType, '
                                                                       'properties.verbosity enum '
                                                                       'error/information/verbose, '
                                                                       'sampling.percentage, alwaysLog, '
                                                                       'and scope override. There is no '
                                                                       'diagnostic.enabled or '
                                                                       'logger.enabled property in this '
                                                                       'schema.',
                                                        'predicate': 'For every APIM API operation, '
                                                                     'resolve the effective API or '
                                                                     'service diagnostic. PASS only if '
                                                                     'an applicable diagnostic '
                                                                     'references a present usable '
                                                                     'logger, has verbosity=error or '
                                                                     'information as the frozen rule '
                                                                     'requires, and samples ordinary '
                                                                     'requests at a positive '
                                                                     'percentage; alwaysLog=allErrors '
                                                                     'alone is insufficient when '
                                                                     'sampling is zero. FAIL if '
                                                                     'complete inheritance and logger '
                                                                     'reads prove an operation has no '
                                                                     'qualifying diagnostic. UNKNOWN if '
                                                                     'operation coverage, logger '
                                                                     'destination, credentials, scope '
                                                                     'override, optional sampling '
                                                                     'configuration or any page is '
                                                                     'unresolved. Complete empty '
                                                                     'operation inventory is '
                                                                     'NOT_APPLICABLE.',
                                                        'severity': 'medium',
                                                        'category': 'logging',
                                                        'title': 'All methods in Azure API Management '
                                                                 '(APIM) services have logging enabled',
                                                        'description': 'Checks effective APIM API '
                                                                       'operation diagnostics and '
                                                                       'logger bindings.',
                                                        'remediation_hint': 'Configure effective APIM '
                                                                            'diagnostics for every '
                                                                            'operation with a valid '
                                                                            'logger, logging level '
                                                                            'Error or Information, and '
                                                                            'nonzero sampling or '
                                                                            'all-error logging; verify '
                                                                            'telemetry.'},
 'azure_api_management_appinsights_ensure_is_configured_42aac6a': {'id': 'azure_api_management_appinsights_ensure_is_configured_42aac6a',
                                                                   'provider': 'azure',
                                                                   'resource_kind': 'api_management',
                                                                   'data_source': 'Collector '
                                                                                  'peaso/collectors/azure.py: '
                                                                                  'api_management '
                                                                                  'parent is collected '
                                                                                  'but '
                                                                                  'logger/diagnostic '
                                                                                  'children are not. '
                                                                                  'New paged ARM GET '
                                                                                  '{serviceId}/loggers?api-version=2024-05-01 '
                                                                                  'and '
                                                                                  '{serviceId}/diagnostics?api-version=2024-05-01; '
                                                                                  'logger '
                                                                                  'properties.loggerType '
                                                                                  'enum '
                                                                                  'applicationInsights, '
                                                                                  'properties.resourceId '
                                                                                  'string; diagnostic '
                                                                                  'properties.loggerId '
                                                                                  'string, '
                                                                                  'sampling.percentage '
                                                                                  'number, alwaysLog '
                                                                                  'enum if needed; '
                                                                                  'follow nextLink. '
                                                                                  'Enumerate APIs and '
                                                                                  'API-level '
                                                                                  'diagnostics as well '
                                                                                  'as service '
                                                                                  'diagnostics; resolve '
                                                                                  'documented '
                                                                                  'inheritance/override '
                                                                                  'and GET each '
                                                                                  'referenced '
                                                                                  'Application Insights '
                                                                                  'component. Enumerate '
                                                                                  'APIs and API-level '
                                                                                  'diagnostics as well '
                                                                                  'as service '
                                                                                  'diagnostics; resolve '
                                                                                  'documented '
                                                                                  'inheritance/override '
                                                                                  'and GET each '
                                                                                  'referenced '
                                                                                  'Application Insights '
                                                                                  'component.',
                                                                   'predicate': 'For each APIM service '
                                                                                'and every active API, '
                                                                                'PASS only if its '
                                                                                'effective diagnostic '
                                                                                '(API override or '
                                                                                'inherited service '
                                                                                'diagnostic) references '
                                                                                'an exact '
                                                                                'applicationInsights '
                                                                                'logger ID whose '
                                                                                'resourceId resolves to '
                                                                                'an existing '
                                                                                'Application Insights '
                                                                                'component, and fixed '
                                                                                'sampling is explicitly '
                                                                                'positive or its '
                                                                                'documented effective '
                                                                                'default is positive. '
                                                                                'FAIL if complete '
                                                                                'logger, service/API '
                                                                                'diagnostic and API '
                                                                                'inventories prove any '
                                                                                'active API lacks that '
                                                                                'effective tracing '
                                                                                'path. UNKNOWN if '
                                                                                'child/API pages, '
                                                                                'logger resource, '
                                                                                'effective '
                                                                                'override/inheritance, '
                                                                                'sampling default or '
                                                                                'API coverage is '
                                                                                'unresolved. No active '
                                                                                'APIs is NOT_APPLICABLE '
                                                                                'only after complete '
                                                                                'enumeration.',
                                                                   'severity': 'medium',
                                                                   'category': 'hardening',
                                                                   'title': 'Azure API Management '
                                                                            '(APIM) services have Azure '
                                                                            'Monitor Application '
                                                                            'Insights (AI) tracing '
                                                                            'enabled',
                                                                   'description': 'Connects an APIM '
                                                                                  'Application Insights '
                                                                                  'logger to a service '
                                                                                  'diagnostic that '
                                                                                  'emits telemetry.',
                                                                   'remediation_hint': 'API Management '
                                                                                       '> Loggers: add '
                                                                                       'an Application '
                                                                                       'Insights '
                                                                                       'logger; '
                                                                                       'Diagnostics > '
                                                                                       'All APIs: '
                                                                                       'select that '
                                                                                       'logger and set '
                                                                                       'a positive '
                                                                                       'sampling '
                                                                                       'percentage.'},
 'azure.other.ml_approved_images': {'id': 'azure.other.ml_approved_images',
                                    'provider': 'azure',
                                    'resource_kind': 'ml_workspace',
                                    'data_source': 'Paged AML compute inventory with actual '
                                                   'VM/container image IDs; paged policy '
                                                   'assignments/definitions/initiatives/exemptions at '
                                                   'all inherited scopes plus Policy Insights query '
                                                   'results; approvedImageIds; authorized '
                                                   'unapproved-image creation probe.',
                                    'predicate': 'PASS only if every in-scope AML compute image is in '
                                                 'approvedImageIds and an effective enforced Deny '
                                                 'policy blocks creation of each disallowed VM and '
                                                 'container image, after resolving inherited '
                                                 'assignments, parameters, initiatives, notScopes, '
                                                 'resource selectors, exemptions, enforcementMode and '
                                                 'policy rule conditions; an authorized denied creation '
                                                 'probe supplies behavioral evidence. FAIL for a known '
                                                 'unapproved image or successful prohibited creation '
                                                 'probe. UNKNOWN for missing image IDs, unmodeled '
                                                 'policy conditions, incomplete '
                                                 'scope/definition/assignment/exemption inventory, or '
                                                 'absent probe evidence.',
                                    'severity': 'medium',
                                    'category': 'hardening',
                                    'title': 'ML compute uses approved images',
                                    'description': 'Checks policy enforcement and deployed compliance '
                                                   'for approved Azure ML compute images.',
                                    'remediation_hint': 'Azure Policy > Assignments: assign an enforced '
                                                        'Deny definition at the ML scope limiting '
                                                        'compute image IDs to the approved set; '
                                                        'remediate existing disallowed computes and '
                                                        'remove unintended exemptions.'},
 'azure.other.ml_compute_access_roles': {'id': 'azure.other.ml_compute_access_roles',
                                         'provider': 'azure',
                                         'resource_kind': 'ml_workspace',
                                         'data_source': 'Paged AML workspaces/computes LIST 2024-04-01 '
                                                        '(compute.id); ARM roleAssignments and '
                                                        'roleDefinitions at compute, workspace, '
                                                        'resource group, subscription and '
                                                        'management-group scopes; deny '
                                                        'assignments/conditions; Graph transitive '
                                                        'groups; policy sensitiveComputeIds and '
                                                        'approvedPrincipalIds.',
                                         'predicate': 'For each sensitive ML compute, expand effective '
                                                      'read/control permissions from compute, '
                                                      'workspace, resource group and subscription '
                                                      'assignments, role definitions, denies, '
                                                      'conditions and transitive groups. FAIL on a '
                                                      'proven unapproved principal; PASS only with '
                                                      'complete expansion and approvedPrincipalIds; '
                                                      'UNKNOWN on missing scope, compute inventory or '
                                                      'unresolved effective permission. Empty sensitive '
                                                      'set is NOT_APPLICABLE.',
                                         'severity': 'high',
                                         'category': 'hardening',
                                         'title': 'ML compute access is scoped',
                                         'description': 'Limits effective Azure ML compute access to '
                                                        'approved principals for explicitly classified '
                                                        'sensitive compute.',
                                         'remediation_hint': 'In Azure ML compute/workspace > Access '
                                                             'control (IAM), remove unapproved '
                                                             'assignments or move them to narrower '
                                                             'scopes.'},
 'azure.other.ml_download_audit': {'id': 'azure.other.ml_download_audit',
                                   'provider': 'azure',
                                   'resource_kind': 'ml_workspace',
                                   'data_source': 'Paged AML workspace and backing storage-account '
                                                  'inventory; diagnosticSettings LIST '
                                                  '2021-05-01-preview at each relevant resource with '
                                                  'setting-level properties.workspaceId, '
                                                  'logs[].category/categoryGroup/enabled. Use '
                                                  'resource-specific supported log categories, such as '
                                                  'StorageRead on the backing Blob service where '
                                                  'downloads occur, plus Log Analytics records (for '
                                                  'example BlobRead) or a controlled download probe and '
                                                  'correlated identity/object/time evidence. Approved '
                                                  'observation window and nonsensitive MLDE '
                                                  'classification are required.',
                                   'predicate': 'For each nonsensitive MLDE instance, PASS only if '
                                                'every actual file-download path has supported '
                                                'data-plane audit logging to an approved destination '
                                                'and a controlled probe or complete observation proves '
                                                'download records are emitted with enough '
                                                'identity/object/time detail. FAIL on a proven unlogged '
                                                'download path or a controlled download with no '
                                                'attributable record after ingestion delay. UNKNOWN '
                                                'when backend/path mapping, category support, '
                                                'destination, attribution, sensitivity, observation '
                                                'window or inventory is unresolved. An AML workspace '
                                                'diagnostic setting alone cannot prove file-download '
                                                'logging. Empty instance set is NOT_APPLICABLE.',
                                   'severity': 'medium',
                                   'category': 'logging',
                                   'title': 'Export Azure ML audit categories',
                                   'description': 'Export Azure ML audit categories. A finding is '
                                                  'raised when a workspace lacks enabled export of '
                                                  'every configured audit category to Log Analytics.',
                                   'remediation_hint': 'Enable the supported AML download audit '
                                                       'categories in workspace diagnostic settings, '
                                                       'send them to the approved Log Analytics '
                                                       'workspace, and validate a download event.'},
 'azure.other.runtime_public_ip': {'id': 'azure.other.runtime_public_ip',
                                   'provider': 'azure',
                                   'resource_kind': 'ml_workspace',
                                   'data_source': 'Existing azure.py ml_workspace.items[]; new paged '
                                                  'Microsoft.MachineLearningServices/workspaces/computes '
                                                  'LIST 2024-04-01 per workspace; '
                                                  'properties.properties.enableNodePublicIp boolean for '
                                                  'supported compute types and subnet.id; policy '
                                                  'sensitive compute ARM IDs. Also inspect workspace '
                                                  'publicNetworkAccess, compute endpoint/proxy exposure '
                                                  'and effective network paths for sensitive instances; '
                                                  'node IP alone is a partial signal.',
                                   'predicate': 'For each sensitive MLDE compute instance, FAIL on a '
                                                'proven public-IP access path, including '
                                                'enableNodePublicIp=true or its documented true default '
                                                'for applicable compute types. PASS only if node public '
                                                'IP is explicitly disabled and workspace, '
                                                'endpoint/proxy and network evidence exclude every '
                                                'applicable public-IP access path. UNKNOWN if sensitive '
                                                'scope, compute type, public endpoint paths or '
                                                'inventory is unresolved; zero sensitive instances is '
                                                'NOT_APPLICABLE.',
                                   'severity': 'high',
                                   'category': 'network',
                                   'title': 'Sensitive Azure ML compute nodes do not receive public IPs',
                                   'description': 'Checks compute node public IP allocation for '
                                                  'explicitly identified sensitive Azure ML resources.',
                                   'remediation_hint': 'Azure ML studio > Compute > selected cluster > '
                                                       'Networking: recreate or update compute with '
                                                       'node public IP disabled and a private subnet; '
                                                       'verify enableNodePublicIp=false.'},
 'azure_ml_workspace_1_2_8_36_33f50db': {'id': 'azure_ml_workspace_1_2_8_36_33f50db',
                                         'provider': 'azure',
                                         'resource_kind': 'ml_workspace',
                                         'data_source': 'Paged ARM '
                                                        'Microsoft.MachineLearningServices/workspaces/computes '
                                                        'LIST 2024-04-01; for ComputeInstance use the '
                                                        'compute-instance-specific '
                                                        'properties.properties.subnet.id ARM ID where '
                                                        'returned; policy approvedSubnetIds. Resolve '
                                                        'workspace and compute inventory completely.',
                                         'predicate': 'For every Azure ML ComputeInstance, PASS only if '
                                                      'its documented subnet ARM ID is present and is '
                                                      'in approvedSubnetIds. FAIL if a complete '
                                                      'response explicitly identifies a different '
                                                      'subnet or no VNet placement. UNKNOWN when '
                                                      'policy, inventory, compute-specific subnet field '
                                                      'or ID interpretation is unavailable; other '
                                                      'compute types are outside this check.',
                                         'severity': 'medium',
                                         'category': 'network',
                                         'title': 'Place Azure ML compute instances on approved subnets',
                                         'description': 'Place Azure ML compute instances on approved '
                                                        'subnets. A finding is raised when a '
                                                        'ComputeInstance is not attached to a subnet in '
                                                        'approvedSubnetIds.',
                                         'remediation_hint': 'Create or recreate each Azure ML compute '
                                                             'instance on an approved VNet subnet; '
                                                             'update the approvedSubnetIds policy only '
                                                             'after network review.'},
 'azure_ml_workspace_1_2_8_37_973721f': {'id': 'azure_ml_workspace_1_2_8_37_973721f',
                                         'provider': 'azure',
                                         'resource_kind': 'ml_workspace',
                                         'data_source': 'Paged AML computes LIST 2024-04-01: '
                                                        'properties.computeType, '
                                                        'properties.properties.enableNodePublicIp and '
                                                        'subnet.id; compute-instance network mode, '
                                                        'effective subnet NSG/UDR, firewall/NAT egress '
                                                        'and authorized outbound reachability evidence.',
                                         'predicate': 'For each in-scope AML ComputeInstance, FAIL if '
                                                      'public node IP is true or complete network '
                                                      'evidence shows direct Internet egress. PASS only '
                                                      'if public node IP is false and complete '
                                                      'effective routing, firewall and outbound '
                                                      'observations prove direct Internet access is '
                                                      'blocked. UNKNOWN if IP flag, compute list, '
                                                      'effective egress path or network policy is '
                                                      'unresolved. A false public-IP flag alone cannot '
                                                      'PASS.',
                                         'severity': 'medium',
                                         'category': 'network',
                                         'title': 'Azure ML compute instances have no node public IP',
                                         'description': 'Checks public node IP and effective outbound '
                                                        'Internet access for Azure Machine Learning '
                                                        'compute instances.',
                                         'remediation_hint': 'Disable public node IP and block direct '
                                                             'Internet egress for the compute instance '
                                                             'using approved private routing and '
                                                             'outbound controls.'},
 'azure.other.activity_alert': {'id': 'azure.other.activity_alert',
                                'provider': 'azure',
                                'resource_kind': 'activity_log_alert',
                                'data_source': 'ARM activityLogAlerts LIST 2020-10-01 and actionGroups '
                                               'GET 2021-09-01; inspect properties.enabled, scopes, '
                                               'condition.allOf, actions.actionGroups[].actionGroupId '
                                               'and action-group properties.enabled. Add complete '
                                               'Activity Log event inventory or controlled '
                                               'test-event/delivery evidence for named log-source '
                                               'disable and logging-configuration operations.',
                                'predicate': 'For each policy-named log-source disable or '
                                             'logging-configuration change operation and scope, require '
                                             'an enabled matching Activity Log alert, an enabled action '
                                             'group, and observed alert generation or a successful '
                                             'controlled test within the approved lookback window. FAIL '
                                             'on a proven unalerted test/event or definitively absent '
                                             'matching configuration. PASS only with complete operation '
                                             'inventory and delivery evidence for every required case. '
                                             'UNKNOWN when operation mapping, time window, event '
                                             'capture, delivery, scopes or pages are unresolved.',
                                'severity': 'medium',
                                'category': 'logging',
                                'title': 'Sensitive Azure activity raises an alert',
                                'description': 'Ensures specified management operations are covered by '
                                               'actionable Activity Log alerts.',
                                'remediation_hint': 'Configure Activity Log alerts and enabled action '
                                                    'groups for log-source disable and '
                                                    'logging-configuration changes; test that each '
                                                    'required operation generates an alert.'},
 'azure.other.azure_activity_anomaly': {'id': 'azure.other.azure_activity_anomaly',
                                        'provider': 'azure',
                                        'resource_kind': 'activity_log_alert',
                                        'data_source': 'Paged scheduledQueryRules 2021-08-01, scoped '
                                                       'Log Analytics workspace/table availability, '
                                                       'evaluationFrequency/windowSize, '
                                                       'criteria.allOf[].query, enabled action groups '
                                                       'and delivery evidence; policy-approved '
                                                       'suspicious-API-request and per-principal '
                                                       'anomalous-log-query detection definitions and '
                                                       'maximum alert latency.',
                                        'predicate': 'Evaluate both frozen requirements separately. '
                                                     'PASS only when enabled rules and live action '
                                                     'groups cover suspicious API requests and '
                                                     'anomalously high per-principal log-query volume '
                                                     'with reviewed query logic, complete scope, '
                                                     'bounded evaluation windows and alert latency '
                                                     'meeting the real-time policy. FAIL for a proven '
                                                     'missing or inadequate required detector; UNKNOWN '
                                                     'when detection thresholds, query semantics, '
                                                     'source-table coverage, latency, alert delivery or '
                                                     'inventory is unmeasured. A query containing '
                                                     'fragments alone does not prove detection.',
                                        'severity': 'medium',
                                        'category': 'monitoring',
                                        'title': 'Required Azure activity anomaly query routes to an '
                                                 'action group',
                                        'description': 'Checks a specifically defined scheduled query '
                                                       'detection for Azure activity anomalies.',
                                        'remediation_hint': 'In Azure Monitor > Alerts, create or fix a '
                                                            'scheduled query rule over AzureActivity '
                                                            'with the approved detection query, scope, '
                                                            'evaluation window and enabled action '
                                                            'group.'},
 'azure.other.diagnostic_destination_alert': {'id': 'azure.other.diagnostic_destination_alert',
                                              'provider': 'azure',
                                              'resource_kind': 'activity_log_alert',
                                              'data_source': 'Activity Log alerts LIST 2020-10-01 and '
                                                             'actionGroups GET 2021-09-01; add '
                                                             'service/child-resource redirection '
                                                             'controls, operational-state evidence, and '
                                                             'controlled change-event delivery test.',
                                              'predicate': 'An enabled alert covering '
                                                           'diagnosticSettings/write and /delete with a '
                                                           'valid action group is only a partial '
                                                           'signal. PASS for the full frozen '
                                                           'requirement requires controlled evidence '
                                                           'that redirection during operation is '
                                                           'blocked unless the resource halts, plus '
                                                           'publication to monitored channels for both '
                                                           'the service and child resources. FAIL on a '
                                                           'measured redirect without halt or missing '
                                                           'publication; UNKNOWN when enforcement, '
                                                           'child scope or delivery cannot be tested. '
                                                           'Alert configuration alone cannot PASS.',
                                              'severity': 'high',
                                              'category': 'monitoring',
                                              'title': 'Log routing changes generate alerts',
                                              'description': 'Measures diagnostic-setting change alerts '
                                                             'as partial evidence; the frozen rule also '
                                                             'requires redirect prevention or downtime '
                                                             'and monitored publication.',
                                              'remediation_hint': 'Enforce diagnostic destination '
                                                                  'change controls for service and '
                                                                  'child resources and verify monitored '
                                                                  'publication during a controlled '
                                                                  'change test.'},
 'azure.other.retention_change_alert': {'id': 'azure.other.retention_change_alert',
                                        'provider': 'azure',
                                        'resource_kind': 'activity_log_alert',
                                        'data_source': 'Paged ARM Microsoft.Insights/activityLogAlerts '
                                                       'LIST 2020-10-01: '
                                                       'properties.enabled,scopes,condition.allOf[].field/equals,actions.actionGroups; '
                                                       'GET action groups. Approved '
                                                       'retention/object-lock operation names across '
                                                       'each external log source and bucket; collect '
                                                       'activity-log event results or perform '
                                                       'authorized attempt probes, including failed '
                                                       'operations.',
                                        'predicate': 'For every required log source and '
                                                     'retention/object-lock mutation operation, PASS '
                                                     'only if an enabled alert scopes it, matches the '
                                                     'operation including attempted/failed status, has '
                                                     'an enabled action group, and alert delivery for '
                                                     'an attempted change is evidenced within an '
                                                     'approved window. FAIL if complete definitions or '
                                                     'a measured attempt prove no alert. UNKNOWN for '
                                                     'incomplete operation/source inventory, unknown '
                                                     'filter semantics, missing delivery window or '
                                                     'untested alert delivery.',
                                        'severity': 'high',
                                        'category': 'monitoring',
                                        'title': 'Retention changes generate alerts',
                                        'description': 'Alerts on specified management operations that '
                                                       'modify log retention or immutability settings.',
                                        'remediation_hint': 'Create scoped activity-log alerts for each '
                                                            'retention and object-lock mutation '
                                                            'operation, include failed attempts, attach '
                                                            'an enabled action group, and verify '
                                                            'delivery with an authorized test.'}}

PROPOSED_SPEC_SHA256 = {'azure_api_management_3_5_1_1_345bdac': '485608129311b21b22cf0eb779f9a24e815f2076ca2867b7e5592b96ec0bfe5c',
 'azure_api_management_app_http_logs_enabled_21c108d': '55309362e2893e2b26f757b104edc90500b18c7193090fc03c9c77e301551242',
 'azure_api_management_app_http_logs_enabled_9b3b56e': 'ee73687e28a820a69f9e73af685488efaa5a531f4de52c703eb09d2fcf40c600',
 'azure_api_management_app_http_logs_enabled_9ef06db': 'e7d3c741187fd1c7dd8f9df562fe64803608a9a3b57cab6b2e67ccc0d1478a75',
 'azure_api_management_appinsights_ensure_is_configured_42aac6a': '72f20de1ae592d55056bf3f1347732729526985d8072f8d41faeab33d5798ba1',
 'azure.other.ml_approved_images': '3f1ed38451f2080099b55fa14e883e5cd0cb368ba099290992a25893b6f3b40d',
 'azure.other.ml_compute_access_roles': '7502d39a30ad5e6dac9e760749f64958403745fc6484786547b5c516148c1cc3',
 'azure.other.ml_download_audit': 'cdfda8b677e32a68fea1c69be68202ebd9cb6c66b795f51b93b6bde05dce8ce6',
 'azure.other.runtime_public_ip': '4e397fd3c651a5de508ce664c8342ea043ff3ae881a91345721b6aa8c9e28e5e',
 'azure_ml_workspace_1_2_8_36_33f50db': '58937a3865b734d83ff6a11dc077918a7fbe4d56b9c9b891a54fcd4f8d19e742',
 'azure_ml_workspace_1_2_8_37_973721f': 'df957bab75ccf0416fd2f3119e495a3e2c8ae36763d744125c5763670228fe3a',
 'azure.other.activity_alert': '1fb5ef67c7463f333ba8e5598d1432ede909e7620d96162dcfd7193e0cc881d4',
 'azure.other.azure_activity_anomaly': '1d5a4bf6e49740772cb723f90ae41de3d80c714c4948c306de86a3d5386c8ea8',
 'azure.other.diagnostic_destination_alert': '3636e9a21dc0322f2915399754287ebacd7dd23a986e1ba9fe7b075b4bd3dec8',
 'azure.other.retention_change_alert': '25e5eeff2ec7d05243e86366fe55189f7a6e879396d534386bce2112c557f689'}
IDS = tuple(SPECS)
CHECK_OBJECTS = {}

_SUB = re.compile(r'/subscriptions/[^/?#]+\Z', re.I)
_ARM = re.compile(r'/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+(?:/[^/?#]+/[^/?#]+)*\Z', re.I)
_SUPPORTED_COMPUTE = {'ComputeInstance', 'AmlCompute', 'VirtualMachine', 'Kubernetes', 'AKS', 'Databricks', 'DataLakeAnalytics', 'HDInsight', 'SynapseSpark'}
EVIDENCE_KIND = 'azure_sw24_evidence'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _text(value):
    if not isinstance(value, str) or not value or value.strip() != value:
        raise Unavailable('empty or malformed text')
    return value


def _strings(value, *, empty=True):
    if not isinstance(value, list):
        raise Unavailable('string inventory unavailable')
    values = [_text(v) for v in value]
    if len(set(values)) != len(values) or (not empty and not values):
        raise Unavailable('duplicate or empty required inventory')
    return values


def _arm(value, *, prefix=None, native_type=None):
    value = _text(value)
    if not _ARM.fullmatch(value):
        raise Unavailable('malformed ARM identity')
    if prefix and not value.casefold().startswith(prefix.casefold() + '/'):
        raise Unavailable('foreign ARM identity')
    if native_type and not re.search('/providers/' + re.escape(native_type) + r'/[^/]+\Z', value, re.I):
        raise Unavailable('ARM resource type differs from declared kind')
    return value.casefold()


def _instant(value):
    parsed = datetime.fromisoformat(_text(value).replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise Unavailable('timestamp timezone unavailable')
    return parsed


def _principal(value):
    value = _text(value)
    if not re.fullmatch(r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', value):
        raise Unavailable('Azure principal object ID malformed')
    return value.casefold()


def _cache_resource_id(value):
    # APIM Cache.resourceId is an external-system URI in the REST schema;
    # the public ARM HTTPS URI and native ARM ID are both documented forms.
    value = _text(value)
    if value.startswith('https://'):
        parsed = urlsplit(value)
        if parsed.netloc.casefold() != 'management.azure.com' or parsed.query or parsed.fragment:
            raise Unavailable('external cache resource URI authority unresolved')
        value = parsed.path
    return _arm(value, native_type='Microsoft.Cache/redis')


def _number(value, *, minimum=0, maximum=None):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum or (maximum is not None and value > maximum):
        raise Unavailable('unrecognized numeric fact')
    return value


def _context(index):
    context = get(index, 'context', dict)
    scope = get(context, 'scope', str)
    if get(context, 'provider', str) != 'azure' or not _SUB.fullmatch(scope):
        raise Unavailable('Azure subscription authority unavailable')
    return scope


def _inventory(index, kind, *, native=True):
    scope = _context(index)
    envelopes = get(index, 'collections', dict).get(kind)
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or envelopes[0].get('type') != kind or
            str(envelopes[0].get('scope', '')).casefold() != scope.casefold()):
        raise Unavailable('collection scope authority unavailable: ' + kind)
    rows = complete_items(index, kind)
    native_rows = list_of_objects(get(envelopes[0], 'items', list))
    wrappers = list_of_objects(get(index, kind, list))
    if ((envelopes[0]['status'] == 'empty') != (not rows) or rows != native_rows or
            len(wrappers) != len(rows) or any(w.get('type') != kind or
            str(w.get('scope', '')).casefold() != scope.casefold() for w in wrappers)):
        raise Unavailable('collection and scoped index disagree: ' + kind)
    seen = set()
    for row in rows:
        identity = _arm(get(row, 'id', str), prefix=scope) if native else _text(get(row, 'id', str))
        if identity in seen:
            raise Unavailable('duplicate snapshot identity')
        seen.add(identity)
        guard(row)
        if not native:
            rid = get(row, 'resource_id', str)
            if rid.casefold() != scope.casefold():
                _arm(rid, prefix=scope)
    return rows


def _subject(item, index, kind):
    rows = _inventory(index, kind)
    identity = _arm(get(item, 'id', str), prefix=_context(index), native_type={
        'api_management': 'Microsoft.ApiManagement/service',
        'ml_workspace': 'Microsoft.MachineLearningServices/workspaces',
    }[kind])
    if sum(row == item and get(row, 'id', str).casefold() == identity for row in rows) != 1:
        raise Unavailable('subject differs from unique collected parent')
    return identity


def _scope_subject(item, index):
    scope = _context(index)
    if get(item, 'provider', str) != 'azure' or get(item, 'scope', str).casefold() != scope.casefold():
        raise Unavailable('foreign scope subject')
    return scope.casefold()


def _children(item, key, segment):
    status = get(item, '_coverage.' + key + '.status', str)
    if status not in ('collected', 'empty'):
        raise Unavailable('child pages incomplete: ' + key)
    rows = list_of_objects(get(item, key, list))
    if (status == 'empty') != (not rows):
        raise Unavailable('child status conflicts with inventory')
    parent = get(item, 'id', str)
    seen = set()
    for row in rows:
        rid = _arm(get(row, 'id', str), prefix=parent)
        prefix = parent.casefold() + '/' + segment.casefold() + '/'
        if not rid.startswith(prefix) or '/' in rid[len(prefix):] or rid in seen:
            raise Unavailable('foreign, duplicate or malformed child identity')
        if get(row, 'parent_id', str).casefold() != parent.casefold():
            raise Unavailable('child parent binding unavailable')
        seen.add(rid)
    return rows


def _policy(index, cid, rid):
    root = get(index, 'context.metadata.compliance_policy.sw24', dict)
    if get(root, 'status', str) != 'collected' or get(root, 'scope', str).casefold() != _context(index).casefold():
        raise Unavailable('complete subscription-bound policy unavailable')
    policies = list_of_objects(get(root, 'checks', list))
    matches = [p for p in policies if p.get('check_id') == cid and str(p.get('resource_id', '')).casefold() == rid]
    if len(matches) != 1 or get(matches[0], 'status', str) != 'collected':
        raise Unavailable('unique resource-bound approved policy unavailable')
    return matches[0]


def _window(policy, index):
    start = _instant(get(policy, 'window.start', str))
    end = _instant(get(policy, 'window.end', str))
    captured = _instant(get(index, 'context.created_at', str))
    if not start < end <= captured:
        raise Unavailable('approved observation window unavailable')
    return start, end


def _dated(value, policy, index):
    start, end = _window(policy, index)
    stamp = _instant(value)
    if not start <= stamp <= end:
        raise Unavailable('observation outside approved window')
    return stamp


def _evidence(index, cid, rid, policy, configuration):
    rows = _inventory(index, EVIDENCE_KIND, native=False)
    matches = [r for r in rows if r.get('check_id') == cid and str(r.get('resource_id', '')).casefold() == rid]
    if len(matches) != 1:
        raise Unavailable('unique measured evidence unavailable')
    row = matches[0]
    if get(row, 'schema_version', int) != 1 or get(row, 'status', str) != 'collected':
        raise Unavailable('unrecognized or incomplete measured evidence')
    if get(row, 'configuration_sha256', str) != digest(configuration):
        raise Unavailable('evidence is stale or bound to another configuration')
    # The review digest is excluded to avoid a circular policy/evidence hash.
    baseline = {k: v for k, v in policy.items() if k != 'reviewedResolutionSha256'}
    if get(row, 'policy_sha256', str) != digest(baseline):
        raise Unavailable('evidence differs from approved scope policy')
    provenance = get(row, '_provenance', dict)
    if get(provenance, 'read_only', bool) is not True:
        raise Unavailable('read-only evidence import provenance unavailable')
    _text(get(provenance, 'source', str))
    _dated(get(row, 'observed_at', str), policy, index)
    return get(row, 'payload', dict)


def _reviewed(payload, policy, required_sources, index):
    """Only a policy-approved exact resolution can supply complex semantics.

    This is an imported, independently reviewed proof contract, not an attempt
    to infer arbitrary XML, RBAC, Azure Policy or KQL semantics from fragments.
    The native configuration and complete observation are bound separately.
    """
    resolution = get(payload, 'resolution', dict)
    if digest(resolution) != get(policy, 'reviewedResolutionSha256', str):
        raise Unavailable('semantic resolution lacks independent policy approval')
    if get(resolution, 'unresolved', list) != []:
        raise Unavailable('unmodeled inherited scope, conditions or path')
    sources = list_of_objects(get(resolution, 'sources', list))
    seen = set()
    for source in sources:
        kind = _text(get(source, 'kind', str))
        if kind in seen or get(source, 'status', str) not in ('collected', 'empty'):
            raise Unavailable('duplicate or incomplete source inventory')
        refs = _strings(get(source, 'references', list))
        if (source['status'] == 'empty') != (not refs):
            raise Unavailable('source inventory status conflicts with references')
        documents = list_of_objects(get(source, 'documents', list))
        document_ids = set()
        for document in documents:
            identity = _text(get(document, 'id', str))
            if identity in document_ids or get(document, 'sha256', str) != digest(get(document, 'data', dict)):
                raise Unavailable('duplicate or altered semantic source document')
            document_ids.add(identity)
            _dated(get(document, 'observed_at', str), policy, index)
            if get(document, '_provenance.read_only', bool) is not True:
                raise Unavailable('semantic source read-only provenance unavailable')
        if document_ids != set(refs):
            raise Unavailable('semantic source references lack complete native documents')
        seen.add(kind)
    if seen != set(required_sources):
        raise Unavailable('complete semantic source inventory unavailable')
    return resolution


def _aggregate(states, **evidence):
    if not states:
        return unknown('required coverage is empty', **evidence)
    if 'UNKNOWN' in states:
        return unknown('required fact or interpretation unresolved', **evidence)
    return result('FAIL' in states, **evidence)


def _signed(cid, dependencies, *, target='resource'):
    spec = SPECS[cid]
    def decorate(function):
        # Copy the wave-1 pattern: retain the strict registry safe wrapper and
        # restore signed categories unsupported by its historical validator.
        category = spec['category'] if spec['category'] in {'hardening', 'network', 'exposure', 'least_privilege', 'iam_graph'} else 'hardening'
        register(cid, spec['provider'], category, spec['resource_kind'], spec['title'],
                 spec['severity'], 'CM-6', spec['remediation_hint'], target=target,
                 dependencies=dependencies)(function)
        CHECKS[-1] = replace(CHECKS[-1], category=spec['category'])
        CHECK_OBJECTS[cid] = CHECKS[-1]
        return function
    return decorate


CACHE_ID, HTTP_ID, VERBOSE_ID, METHODS_ID, INSIGHTS_ID, IMAGES_ID, ACCESS_ID, DOWNLOAD_ID, PUBLIC_ID, SUBNET_ID, EGRESS_ID, ACTIVITY_ID, ANOMALY_ID, DESTINATION_ID, RETENTION_ID = IDS


def _apis(item):
    apis = _children(item, 'apis', 'apis')
    for api in apis:
        # Enumeration must include deployed revisions; a collector may only
        # assert completeness after following API and revision nextLinks.
        if get(api, '_coverage.revisions.status', str) != 'collected':
            raise Unavailable('deployed API revision inventory unresolved')
        get(api, '_provenance.deployed', bool)
    return apis


def _diagnostics(item, api):
    service = _children(item, 'diagnostics', 'diagnostics')
    overrides = _children(api, 'diagnostics', 'diagnostics')
    # Diagnostic names (applicationinsights/azuremonitor) identify independent
    # destinations. A per-API definition overrides that same service name.
    effective = {r['id'].rsplit('/', 1)[1].casefold(): r for r in service}
    effective.update({r['id'].rsplit('/', 1)[1].casefold(): r for r in overrides})
    return list(effective.values())


def _logger_state(logger, payload, policy, index):
    props = get(logger, 'properties', dict)
    kind = get(props, 'loggerType', str)
    if kind not in ('applicationInsights', 'azureMonitor', 'azureEventHub'):
        raise Unavailable('unrecognized APIM logger destination type')
    destination = _arm(get(props, 'resourceId', str))
    states = list_of_objects(get(payload, 'loggers', list))
    matches = [s for s in states if str(s.get('logger_id', '')).casefold() == logger['id'].casefold()]
    if len(matches) != 1:
        raise Unavailable('logger destination or credentials usability unmeasured')
    state = matches[0]
    if (get(state, 'configuration_sha256', str) != digest(props) or
            _arm(get(state, 'destination_id', str)) != destination):
        raise Unavailable('logger observation configuration or destination differs')
    _dated(get(state, 'observed_at', str), policy, index)
    exists = get(state, 'destination_exists', bool)
    usable = get(state, 'credentials_usable', bool)
    _text(get(state, 'observation_id', str))
    return exists and usable, kind, destination


def _sampling(props):
    sampling = get(props, 'sampling', dict)
    if get(sampling, 'samplingType', str) != 'fixed':
        raise Unavailable('APIM sampling default or type unresolved')
    percentage = _number(get(sampling, 'percentage'), maximum=100)
    if 'alwaysLog' in props and get(props, 'alwaysLog', str) != 'allErrors':
        raise Unavailable('APIM alwaysLog enum unresolved')
    return percentage


def _capture(props, sides=('frontend', 'backend')):
    for side in sides:
        for direction in ('request', 'response'):
            entry = get(props, side + '.' + direction, dict)
            _strings(get(entry, 'headers', list))
            # Zero bytes still captures HTTP metadata. Body capture is not
            # mandatory under either frozen HTTP diagnostic requirement.
            _number(get(entry, 'body.bytes'), maximum=8192)


def _http_check(cid, item, index):
    if cid in (HTTP_ID, VERBOSE_ID, METHODS_ID) and get(index, 'collections', dict).get('apim_native'):
        from .azure_apim_diagnostics_native import evaluate
        return evaluate(cid, item, index)
    rid = _subject(item, index, 'api_management')
    apis = [a for a in _apis(item) if a['_provenance']['deployed']]
    loggers = {r['id'].casefold(): r for r in _children(item, 'loggers', 'loggers')}
    operations = []
    if cid == METHODS_ID:
        for api in apis:
            operations.extend(_children(api, 'operations', 'operations'))
        if not operations:
            return 'NOT_APPLICABLE', {'reason': 'Complete deployed operation inventory is empty'}
    if cid == INSIGHTS_ID and not apis:
        return 'NOT_APPLICABLE', {'reason': 'Complete API/revision enumeration has no active API'}
    policy = _policy(index, cid, rid)
    required = _strings(get(policy, 'requiredApiIds', list)) if cid == VERBOSE_ID else [a['id'] for a in apis if cid != METHODS_ID or _children(a, 'operations', 'operations')]
    if not required or any(r.casefold() not in {a['id'].casefold() for a in apis} for r in required):
        return unknown('required API policy empty or outside deployed API inventory')
    # Resolve all native definitions before reading behavioral evidence. A
    # genuinely absent diagnostic/logger is a positive configuration gap.
    effective = {}
    for api in apis:
        if cid == METHODS_ID and not _children(api, 'operations', 'operations'):
            continue
        effective[api['id'].casefold()] = _diagnostics(item, api)
    if any(not effective.get(a.casefold()) for a in required):
        return result(True, reason='Complete effective diagnostic inventory proves missing API coverage')
    payload = None
    states = []
    for api_id in required:
        candidates = []
        for diagnostic in effective[api_id.casefold()]:
            props = get(diagnostic, 'properties', dict)
            logger_id = _arm(get(props, 'loggerId', str), prefix=rid)
            if not logger_id.startswith(rid + '/loggers/') or '/' in logger_id[len(rid + '/loggers/'):]:
                raise Unavailable('foreign diagnostic logger reference')
            logger = loggers.get(logger_id)
            if logger is None:
                candidates.append('FAIL')
                continue
            if cid != INSIGHTS_ID:
                verbosity = get(props, 'verbosity', str)
                if verbosity not in ('error', 'information', 'verbose'):
                    raise Unavailable('unrecognized diagnostic verbosity')
                allowed = ('error', 'verbose') if cid == VERBOSE_ID else ('error', 'information') if cid == METHODS_ID else ('error', 'information', 'verbose')
                if verbosity not in allowed:
                    candidates.append('FAIL')
                    continue
            percent = _sampling(props)
            if cid in (HTTP_ID, VERBOSE_ID):
                _capture(props, ('frontend',) if cid == VERBOSE_ID else ('frontend', 'backend'))
            minimum = _number(get(policy, 'minimumSamplingPercentage'), minimum=0.000001, maximum=100) if cid == HTTP_ID else 0.000001
            if percent < minimum and not (cid == VERBOSE_ID and props.get('alwaysLog') == 'allErrors'):
                candidates.append('UNKNOWN' if cid == HTTP_ID and (percent > 0 or props.get('alwaysLog') == 'allErrors') else 'FAIL')
                continue
            logger_type = get(logger, 'properties.loggerType', str)
            if logger_type not in ('applicationInsights', 'azureMonitor', 'azureEventHub'):
                raise Unavailable('unrecognized APIM logger type')
            if cid == INSIGHTS_ID and logger_type != 'applicationInsights':
                candidates.append('FAIL')
                continue
            if payload is None:
                payload = _evidence(index, cid, rid, policy, item)
            usable, kind, destination = _logger_state(logger, payload, policy, index)
            if cid == INSIGHTS_ID:
                _arm(destination, native_type='Microsoft.Insights/components')
                components = _inventory(index, 'application_insights')
                usable = usable and any(r['id'].casefold() == destination for r in components)
            if not usable:
                candidates.append('FAIL')
                continue
            if cid == HTTP_ID:
                receipts = list_of_objects(get(payload, 'receipts', list))
                rows = [r for r in receipts if str(r.get('api_id', '')).casefold() == api_id.casefold() and str(r.get('logger_id', '')).casefold() == logger_id]
                if not rows:
                    candidates.append('UNKNOWN')
                    continue
                for row in rows:
                    _dated(get(row, 'received_at', str), policy, index)
                    _text(get(row, 'request_id', str))
                    if _arm(get(row, 'destination_id', str)) != destination:
                        raise Unavailable('sink receipt belongs to another destination')
            candidates.append('PASS')
        states.append('PASS' if 'PASS' in candidates else 'UNKNOWN' if 'UNKNOWN' in candidates else 'FAIL')
    return _aggregate(states, required_api_count=len(required), semantics='Effective native HTTP diagnostics with configuration-bound destination evidence')


@_signed(HTTP_ID, ['api_management', EVIDENCE_KIND, 'apim_native'])
def http_logging(item, index):
    return _http_check(HTTP_ID, item, index)


@_signed(VERBOSE_ID, ['api_management', EVIDENCE_KIND, 'apim_native'])
def diagnostic_verbosity(item, index):
    return _http_check(VERBOSE_ID, item, index)


@_signed(METHODS_ID, ['api_management', EVIDENCE_KIND, 'apim_native'])
def all_methods_logging(item, index):
    return _http_check(METHODS_ID, item, index)


@_signed(INSIGHTS_ID, ['api_management', 'application_insights', EVIDENCE_KIND])
def application_insights_tracing(item, index):
    return _http_check(INSIGHTS_ID, item, index)


@_signed(CACHE_ID, ['api_management', 'redis_cache', EVIDENCE_KIND])
def encrypted_external_cache(item, index):
    rid = _subject(item, index, 'api_management')
    policy = _policy(index, CACHE_ID, rid)
    required = {_arm(v, prefix=rid) for v in _strings(get(policy, 'requiredOperationIds', list))}
    if not required:
        return unknown('required operation scope policy is empty')
    operations = {r['id'].casefold(): r for a in _apis(item) for r in _children(a, 'operations', 'operations')}
    if not required <= operations.keys():
        raise Unavailable('required operation absent from complete inventory')
    caches = {c['id'].casefold(): c for c in _children(item, 'caches', 'caches')}
    approved = {_arm(v, prefix=rid) for v in _strings(get(policy, 'approvedEncryptedCacheIds', list))}
    payload = _evidence(index, CACHE_ID, rid, policy, item)
    resolution = _reviewed(payload, policy, ('global_policies', 'product_policies', 'api_policies', 'operation_policies', 'product_bindings', 'cache_bindings'), index)
    paths = list_of_objects(get(resolution, 'paths', list))
    seen, states = set(), []
    redis = {r['id'].casefold(): r for r in _inventory(index, 'redis_cache')}
    for path in paths:
        op = _arm(get(path, 'operation_id', str), prefix=rid)
        path_id = _text(get(path, 'path_id', str))
        if op not in required or (op, path_id) in seen:
            raise Unavailable('foreign or duplicate effective policy path')
        seen.add((op, path_id))
        stages = []
        for section, needed in (('inbound', 'cache-lookup'), ('outbound', 'cache-store')):
            steps = list_of_objects(get(path, section, list))
            for step in steps:
                if get(step, 'kind', str) not in ('cache-lookup', 'cache-store'):
                    raise Unavailable('unmodeled effective caching instruction')
            matches = [s for s in steps if s['kind'] == needed]
            if not matches:
                stages.append('FAIL')
                continue
            for step in matches:
                cache_id = _arm(get(step, 'cache_id', str), prefix=rid)
                if cache_id not in approved or cache_id not in caches:
                    stages.append('FAIL')
                    continue
                cache = caches[cache_id]
                endpoint = get(cache, 'connectionEndpoint', dict)
                host = _text(get(endpoint, 'host', str)).casefold()
                tls = get(endpoint, 'tls', bool)
                redis_id = _cache_resource_id(get(cache, 'properties.resourceId', str))
                resource = redis.get(redis_id)
                if resource is None:
                    raise Unavailable('referenced cache endpoint resource unresolved')
                if host != get(resource, 'properties.hostName', str).casefold():
                    raise Unavailable('cache connection endpoint differs from referenced resource')
                non_ssl = get(resource, 'properties.enableNonSslPort', bool)
                minimum = get(resource, 'properties.minimumTlsVersion', str)
                if minimum not in ('1.0', '1.1', '1.2', '1.3'):
                    raise Unavailable('unknown cache TLS version')
                protection = get(step, 'at_rest', dict)
                _text(get(protection, 'evidence_id', str))
                encrypted = get(protection, 'encrypted', bool)
                approved_protection = get(protection, 'approved', bool)
                stages.append('PASS' if tls and not non_ssl and minimum in ('1.2', '1.3') and encrypted and approved_protection else 'FAIL')
        states.append('FAIL' if 'FAIL' in stages else 'PASS')
    if {op for op, _ in seen} != required:
        raise Unavailable('exhaustive effective policy path coverage unavailable')
    return _aggregate(states, required_operation_count=len(required), effective_path_count=len(paths))


def _computes(item, index):
    rid = _subject(item, index, 'ml_workspace')
    parents = {r['id'].casefold() for r in _inventory(index, 'ml_workspace')}
    rows = _inventory(index, 'ml_compute')
    selected = []
    for row in rows:
        parent = _arm(get(row, 'parent_id', str))
        identity = _arm(get(row, 'id', str), prefix=parent)
        if parent not in parents or not re.fullmatch(re.escape(parent) + '/computes/[^/]+', identity):
            raise Unavailable('foreign ML compute or unresolved workspace')
        provenance = get(row, '_provenance', dict)
        if (get(provenance, 'source_operation', str) != 'LIST' or
                get(provenance, 'api_version', str) != '2024-04-01' or
                get(provenance, 'read_only', bool) is not True):
            raise Unavailable('complete native ML compute provenance unavailable')
        kind = get(row, 'properties.computeType', str)
        if kind not in _SUPPORTED_COMPUTE:
            raise Unavailable('unrecognized compute type')
        if parent == rid:
            selected.append(row)
    return rid, selected


def _classified(policy, field, rid, computes):
    required = {_arm(v, prefix=rid) for v in _strings(get(policy, field, list))}
    found = {r['id'].casefold(): r for r in computes}
    if not required <= found.keys():
        raise Unavailable('classified compute missing from scoped inventory')
    return [found[v] for v in sorted(required)]


def _configuration(item, computes):
    return {'workspace': item, 'computes': computes}


def _node_public(row):
    kind = get(row, 'properties.computeType', str)
    if kind not in ('ComputeInstance', 'AmlCompute'):
        raise Unavailable('compute type public IP contract unresolved')
    # Omission defaults are deliberately not inferred from a partial read.
    return get(row, 'properties.properties.enableNodePublicIp', bool)


@_signed(SUBNET_ID, ['ml_workspace', 'ml_compute'])
def approved_compute_instance_subnets(item, index):
    rid, computes = _computes(item, index)
    instances = [r for r in computes if r['properties']['computeType'] == 'ComputeInstance']
    if not instances:
        return 'NOT_APPLICABLE', {'reason': 'Complete inventory contains no ComputeInstance'}
    policy = _policy(index, SUBNET_ID, rid)
    approved = {_arm(v, native_type='Microsoft.Network/virtualNetworks') if '/subnets/' not in v.casefold() else _arm(v) for v in _strings(get(policy, 'approvedSubnetIds', list))}
    if any(not re.search(r'/providers/microsoft.network/virtualnetworks/[^/]+/subnets/[^/]+\Z', v) for v in approved):
        raise Unavailable('approved subnet ID interpretation unresolved')
    states = []
    for compute in instances:
        properties = get(compute, 'properties.properties', dict)
        subnet = get(properties, 'subnet')
        if subnet is None:
            full = get(compute, '_provenance.representation', str) == 'full'
            if not full:
                raise Unavailable('absence of VNet placement is not proven by full response')
            states.append('FAIL')
            continue
        subnet_id = _arm(get(subnet, 'id', str))
        if not re.search(r'/providers/microsoft.network/virtualnetworks/[^/]+/subnets/[^/]+\Z', subnet_id):
            raise Unavailable('compute-specific subnet ID interpretation unresolved')
        states.append('PASS' if subnet_id in approved else 'FAIL')
    return _aggregate(states, compute_instance_count=len(instances))


def _network_check(cid, item, index):
    rid, computes = _computes(item, index)
    policy = _policy(index, cid, rid)
    selected = _classified(policy, 'sensitiveComputeIds', rid, computes) if cid == PUBLIC_ID else [r for r in computes if r['properties']['computeType'] == 'ComputeInstance']
    if not selected:
        return 'NOT_APPLICABLE', {'reason': 'Complete classified scope has no applicable compute'}
    flags = [_node_public(r) for r in selected]
    if any(flags):
        return result(True, reason='Explicit node public IP allocation', compute_ids=[r['id'] for r, public in zip(selected, flags) if public])
    payload = _evidence(index, cid, rid, policy, _configuration(item, computes))
    sources = ('workspace_network', 'endpoint_inventory', 'proxy_inventory', 'effective_network_paths') if cid == PUBLIC_ID else ('network_mode', 'subnets', 'nsgs', 'routes', 'firewalls', 'nat', 'outbound_observations')
    resolution = _reviewed(payload, policy, sources, index)
    rows = list_of_objects(get(resolution, 'paths' if cid == PUBLIC_ID else 'egress', list))
    required = {r['id'].casefold() for r in selected}
    seen, states = set(), []
    for row in rows:
        compute_id = _arm(get(row, 'compute_id', str), prefix=rid)
        if compute_id not in required:
            raise Unavailable('foreign or unclassified network path')
        if cid == PUBLIC_ID:
            kind = get(row, 'path_type', str)
            if kind not in ('workspace', 'endpoint', 'proxy', 'network') or (compute_id, kind) in seen:
                raise Unavailable('duplicate or unmodeled public network path')
            seen.add((compute_id, kind))
            _strings(get(row, 'path_ids', list))
            states.append('FAIL' if get(row, 'public_ip_access', bool) else 'PASS')
        else:
            if compute_id in seen:
                raise Unavailable('duplicate effective egress expansion')
            seen.add(compute_id)
            _strings(get(row, 'route_ids', list))
            _strings(get(row, 'firewall_ids', list))
            observations = list_of_objects(get(row, 'observations', list))
            if not observations:
                raise Unavailable('effective egress behavioral observation missing')
            outcomes = []
            for observation in observations:
                _text(get(observation, 'destination', str))
                _text(get(observation, 'observation_id', str))
                _dated(get(observation, 'observed_at', str), policy, index)
                outcome = get(observation, 'outcome', str)
                if outcome not in ('blocked', 'allowed'):
                    raise Unavailable('outbound reachability unresolved')
                outcomes.append(outcome)
            direct = get(row, 'direct_internet', bool)
            if not direct and 'allowed' in outcomes:
                raise Unavailable('outbound observation contradicts resolved network paths')
            states.append('FAIL' if direct else 'PASS')
    expected = {(v, k) for v in required for k in ('workspace', 'endpoint', 'proxy', 'network')} if cid == PUBLIC_ID else required
    if seen != expected:
        raise Unavailable('complete public or egress path expansion unavailable')
    return _aggregate(states, compute_count=len(selected))


@_signed(PUBLIC_ID, ['ml_workspace', 'ml_compute', EVIDENCE_KIND])
def sensitive_runtime_public_ip(item, index):
    return _network_check(PUBLIC_ID, item, index)


@_signed(EGRESS_ID, ['ml_workspace', 'ml_compute', EVIDENCE_KIND])
def compute_instance_internet_egress(item, index):
    return _network_check(EGRESS_ID, item, index)


@_signed(IMAGES_ID, ['ml_workspace', 'ml_compute', EVIDENCE_KIND])
def approved_compute_images(item, index):
    rid, computes = _computes(item, index)
    policy = _policy(index, IMAGES_ID, rid)
    approved = set(_strings(get(policy, 'approvedImageIds', list)))
    actual = []
    for compute in computes:
        if get(compute, '_coverage.imageIds.status', str) != 'collected':
            raise Unavailable('actual VM/container image identity inventory unavailable')
        image_ids = get(compute, 'imageIds', dict)
        for image_type in ('vm', 'container'):
            actual.extend(_strings(get(image_ids, image_type, list)))
        if not image_ids['vm'] and not image_ids['container']:
            raise Unavailable('actual compute image identity missing')
    if any(image not in approved for image in actual):
        return result(True, reason='Known deployed unapproved image', unapproved_image_ids=sorted(set(actual) - approved))
    payload = _evidence(index, IMAGES_ID, rid, policy, _configuration(item, computes))
    probes = list_of_objects(get(payload, 'creation_probes', list))
    tested = set()
    outcomes = []
    for probe in probes:
        if _arm(get(probe, 'scope', str)) != rid:
            raise Unavailable('image creation probe belongs to another workspace')
        kind = get(probe, 'image_type', str)
        image = _text(get(probe, 'image_id', str))
        if kind not in ('vm', 'container') or image in approved:
            raise Unavailable('probe did not test a prohibited VM/container image')
        _text(get(probe, 'probe_id', str))
        _dated(get(probe, 'observed_at', str), policy, index)
        if get(probe, 'authorized', bool) is not True:
            raise Unavailable('authorized behavioral evidence unavailable')
        outcome = get(probe, 'outcome', str)
        if outcome not in ('denied_by_policy', 'created'):
            raise Unavailable('creation outcome unresolved')
        outcomes.append(outcome)
        tested.add(kind)
    if 'created' in outcomes:
        return result(True, reason='Prohibited image creation succeeded')
    if tested != {'vm', 'container'}:
        raise Unavailable('VM and container Deny behavior not both measured')
    resolution = _reviewed(payload, policy, ('policy_assignments', 'policy_definitions', 'policy_initiatives', 'policy_exemptions', 'policy_insights', 'inherited_scopes'), index)
    domains = list_of_objects(get(resolution, 'deny_domains', list))
    by_kind = {}
    for domain in domains:
        kind = get(domain, 'image_type', str)
        if kind not in ('vm', 'container') or kind in by_kind:
            raise Unavailable('duplicate or unmodeled image policy domain')
        if _arm(get(domain, 'scope', str)) != rid:
            raise Unavailable('effective image Deny domain belongs to another workspace')
        if set(_strings(get(domain, 'allowed_image_ids', list))) != approved:
            raise Unavailable('Deny image domain differs from approved image policy')
        if get(domain, 'effect', str) != 'Deny' or get(domain, 'enforcementMode', str) != 'Default':
            raise Unavailable('effective enforced Deny policy not proven')
        if get(domain, 'excluded_compute_ids', list) != []:
            raise Unavailable('image creation can bypass enforced policy scope')
        by_kind[kind] = domain
    if set(by_kind) != {'vm', 'container'}:
        raise Unavailable('universal VM/container image Deny coverage unresolved')
    return result(False, deployed_image_count=len(actual), denied_probe_count=len(probes))


@_signed(ACCESS_ID, ['ml_workspace', 'ml_compute', EVIDENCE_KIND])
def sensitive_compute_access(item, index):
    rid, computes = _computes(item, index)
    policy = _policy(index, ACCESS_ID, rid)
    selected = _classified(policy, 'sensitiveComputeIds', rid, computes)
    if not selected:
        return 'NOT_APPLICABLE', {'reason': 'Complete policy sensitive compute set is empty'}
    approved_values = _strings(get(policy, 'approvedPrincipalIds', list))
    approved = {_principal(value) for value in approved_values}
    if len(approved) != len(approved_values):
        raise Unavailable('duplicate approved principal object ID')
    payload = _evidence(index, ACCESS_ID, rid, policy, _configuration(item, computes))
    resolution = _reviewed(payload, policy, ('role_assignments', 'role_definitions', 'deny_assignments', 'conditions', 'transitive_groups', 'inherited_scopes'), index)
    rows = list_of_objects(get(resolution, 'effective_access', list))
    required = {r['id'].casefold() for r in selected}
    seen, unapproved = set(), set()
    for row in rows:
        compute_id = _arm(get(row, 'compute_id', str), prefix=rid)
        if compute_id not in required or compute_id in seen:
            raise Unavailable('duplicate or foreign effective permission expansion')
        seen.add(compute_id)
        permissions = list_of_objects(get(row, 'permissions', list))
        unique = set()
        for permission in permissions:
            principal = _principal(get(permission, 'principal_id', str))
            action = get(permission, 'permission', str)
            if action not in ('read', 'control') or (principal, action) in unique:
                raise Unavailable('effective compute permission unresolved')
            unique.add((principal, action))
            _strings(get(permission, 'source_ids', list), empty=False)
            if principal not in approved:
                unapproved.add(principal)
    if seen != required:
        raise Unavailable('sensitive compute effective access coverage incomplete')
    return result(bool(unapproved), sensitive_compute_count=len(selected), unapproved_principal_ids=sorted(unapproved))


@_signed(DOWNLOAD_ID, ['ml_workspace', 'ml_compute', EVIDENCE_KIND])
def nonsensitive_download_audit(item, index):
    rid, computes = _computes(item, index)
    policy = _policy(index, DOWNLOAD_ID, rid)
    selected = _classified(policy, 'nonsensitiveComputeIds', rid, computes)
    if not selected:
        return 'NOT_APPLICABLE', {'reason': 'Complete nonsensitive MLDE instance set is empty'}
    approved = {_arm(v) for v in _strings(get(policy, 'approvedDestinationIds', list))}
    delay = _number(get(policy, 'ingestionDelaySeconds'))
    payload = _evidence(index, DOWNLOAD_ID, rid, policy, _configuration(item, computes))
    resolution = _reviewed(payload, policy, ('instance_classification', 'download_paths', 'backing_resources', 'supported_categories', 'diagnostic_settings'), index)
    mapping = list_of_objects(get(resolution, 'instances', list))
    required = {r['id'].casefold() for r in selected}
    paths, covered = {}, set()
    for instance in mapping:
        identity = _arm(get(instance, 'compute_id', str), prefix=rid)
        if identity not in required or identity in covered:
            raise Unavailable('duplicate or foreign download instance')
        covered.add(identity)
        ids = _strings(get(instance, 'download_path_ids', list), empty=False)
        for path in ids:
            if path in paths:
                raise Unavailable('ambiguous instance download path mapping')
            paths[path] = identity
    if covered != required:
        raise Unavailable('actual download path mapping incomplete')
    rows = list_of_objects(get(payload, 'paths', list))
    path_facts = [{key: get(row, key) for key in ('path_id', 'resource_id', 'supported_categories', 'diagnostic_settings')} for row in rows]
    if get(resolution, 'path_facts', list) != path_facts:
        raise Unavailable('backend path or category support differs from reviewed mapping')
    seen, states = set(), []
    for row in rows:
        identity = _text(get(row, 'path_id', str))
        if identity not in paths or identity in seen:
            raise Unavailable('duplicate or foreign download path')
        seen.add(identity)
        resource = _arm(get(row, 'resource_id', str))
        supported = set(_strings(get(row, 'supported_categories', list), empty=False))
        settings = list_of_objects(get(row, 'diagnostic_settings', list))
        good = False
        for setting in settings:
            if get(setting, 'parent_id', str).casefold() != resource:
                raise Unavailable('download diagnostic setting belongs to another backend')
            props = get(setting, 'properties', dict)
            destination = _arm(get(props, 'workspaceId', str))
            logs = list_of_objects(get(props, 'logs', list))
            for log in logs:
                category = get(log, 'category', str)
                enabled = get(log, 'enabled', bool)
                good |= enabled and category in supported and destination in approved
        if not good:
            states.append('FAIL')
            continue
        observations = list_of_objects(get(row, 'downloads', list))
        if not observations:
            states.append('UNKNOWN')
            continue
        for observation in observations:
            _text(get(observation, 'probe_or_event_id', str))
            actor = _text(get(observation, 'identity', str))
            obj = _text(get(observation, 'object_id', str))
            occurred = _dated(get(observation, 'occurred_at', str), policy, index)
            until = _dated(get(observation, 'observed_until', str), policy, index)
            if (until - occurred).total_seconds() < delay or get(observation, 'record_inventory_complete', bool) is not True:
                raise Unavailable('download observation window or ingestion delay unresolved')
            records = list_of_objects(get(observation, 'records', list))
            matched = False
            for record in records:
                event_time = _dated(get(record, 'event_time', str), policy, index)
                _text(get(record, 'record_id', str))
                dest = _arm(get(record, 'destination_id', str))
                matched |= (get(record, 'identity', str) == actor and get(record, 'object_id', str) == obj and
                            dest in approved and abs((event_time - occurred).total_seconds()) <= _number(get(policy, 'correlationToleranceSeconds')))
            states.append('PASS' if matched else 'FAIL')
    if seen != paths.keys():
        raise Unavailable('download path logging coverage incomplete')
    return _aggregate(states, nonsensitive_compute_count=len(selected), download_path_count=len(paths))


def _alert_models(index):
    scope = _context(index)
    alerts = _inventory(index, 'activity_log_alert')
    groups = {r['id'].casefold(): r for r in _inventory(index, 'action_group')}
    for group in groups.values():
        _arm(group['id'], native_type='Microsoft.Insights/actionGroups')
        get(group, 'properties.enabled', bool)
    models = []
    for alert in alerts:
        _arm(alert['id'], native_type='Microsoft.Insights/activityLogAlerts')
        props = get(alert, 'properties', dict)
        enabled = get(props, 'enabled', bool)
        scopes = _strings(get(props, 'scopes', list), empty=False)
        for target in scopes:
            if target.casefold() != scope.casefold() and not target.casefold().startswith(scope.casefold() + '/'):
                raise Unavailable('foreign activity alert scope')
        filters = {}
        for condition in list_of_objects(get(props, 'condition.allOf', list)):
            field = get(condition, 'field', str).casefold()
            if field not in ('category', 'operationname', 'status', 'resourceid') or field in filters:
                raise Unavailable('unmodeled or duplicate Activity Log filter semantics')
            if set(condition) != {'field', 'equals'}:
                raise Unavailable('unmodeled Activity Log condition branch')
            filters[field] = _text(get(condition, 'equals', str)).casefold()
        references = list_of_objects(get(props, 'actions.actionGroups', list))
        usable = set()
        seen = set()
        for reference in references:
            gid = _arm(get(reference, 'actionGroupId', str), prefix=scope, native_type='Microsoft.Insights/actionGroups')
            if gid in seen:
                raise Unavailable('duplicate action group reference')
            seen.add(gid)
            if gid in groups and groups[gid]['properties']['enabled']:
                usable.add(gid)
        models.append({'id': alert['id'].casefold(), 'enabled': enabled,
                       'scopes': [s.casefold() for s in scopes], 'filters': filters, 'groups': usable})
    return alerts, list(groups.values()), models


def _cases(policy, index, *, retention=False):
    rows = list_of_objects(get(policy, 'requiredCases', list))
    if not rows:
        raise Unavailable('approved operation and source inventory is empty')
    seen = set()
    for row in rows:
        case_id = _text(get(row, 'case_id', str))
        if case_id in seen:
            raise Unavailable('duplicate required operation case')
        seen.add(case_id)
        scope = _text(get(row, 'scope', str))
        if scope.casefold() != _context(index).casefold() and not scope.casefold().startswith(_context(index).casefold() + '/'):
            raise Unavailable('foreign policy source scope')
        operation = _text(get(row, 'operation', str))
        if not re.fullmatch(r'Microsoft\.[^/]+/(?:[^/]+/)+(?:write|delete|action)', operation, re.I):
            raise Unavailable('approved management operation mapping unresolved')
        statuses = set(_strings(get(row, 'statuses', list), empty=False))
        if not statuses <= {'Started', 'Succeeded', 'Failed'} or (retention and not {'Started', 'Failed'} <= statuses):
            raise Unavailable('attempted/failed operation status policy unresolved')
    return rows


def _matching(case, models, event_status=None):
    matches = []
    scope = case['scope'].casefold()
    required_statuses = {s.casefold() for s in case['statuses']}
    for model in models:
        f = model['filters']
        if not model['enabled'] or not model['groups']:
            continue
        if not any(scope == s or scope.startswith(s + '/') for s in model['scopes']):
            continue
        if ('operationname' in f and f['operationname'] != case['operation'].casefold()) or ('category' in f and f['category'] != 'administrative') or ('resourceid' in f and f['resourceid'] != scope):
            continue
        if 'status' in f and f['status'] not in required_statuses:
            continue
        if event_status is not None and 'status' in f and f['status'] != event_status.casefold():
            continue
        matches.append(model)
    return matches


def _covered(case, models):
    return all(_matching(case, models, status) for status in case['statuses'])


def _deliveries(payload, cases, models, policy, index):
    if get(payload, 'event_inventory_complete', bool) is not True:
        raise Unavailable('event capture or controlled test inventory incomplete')
    if set(_strings(get(payload, 'case_ids', list))) != {r['case_id'] for r in cases}:
        raise Unavailable('required operation observation coverage unresolved')
    channels = set(_strings(get(policy, 'monitoredChannelIds', list), empty=False))
    deadline = _number(get(policy, 'deliveryDeadlineSeconds'), minimum=1)
    events = list_of_objects(get(payload, 'events', list))
    by_case = {c['case_id']: c for c in cases}
    seen, event_ids, states = set(), set(), []
    for event in events:
        case_id = get(event, 'case_id', str)
        if case_id not in by_case:
            raise Unavailable('foreign required operation test/event')
        case = by_case[case_id]
        eid = _text(get(event, 'event_id', str))
        if eid in event_ids:
            raise Unavailable('duplicate management event identity')
        event_ids.add(eid)
        seen.add(case_id)
        if (get(event, 'scope', str).casefold() != case['scope'].casefold() or
                get(event, 'operation', str).casefold() != case['operation'].casefold() or
                get(event, 'status', str) not in case['statuses']):
            raise Unavailable('event source, operation or attempted status differs')
        occurred = _dated(get(event, 'occurred_at', str), policy, index)
        until = _dated(get(event, 'observed_until', str), policy, index)
        if (until - occurred).total_seconds() < deadline or get(event, 'delivery_inventory_complete', bool) is not True:
            raise Unavailable('delivery observation incomplete or too short')
        matching = _matching(case, models, event['status'])
        delivered = False
        for record in list_of_objects(get(event, 'deliveries', list)):
            alert = _arm(get(record, 'alert_id', str), prefix=_context(index))
            group = _arm(get(record, 'action_group_id', str), prefix=_context(index))
            channel = _text(get(record, 'channel_id', str))
            _text(get(record, 'delivery_id', str))
            published = _dated(get(record, 'published_at', str), policy, index)
            if published < occurred or published > until:
                raise Unavailable('delivery correlation timestamp conflicts with event')
            delivered |= channel in channels and any(m['id'] == alert and group in m['groups'] for m in matching) and (published - occurred).total_seconds() <= deadline
        states.append('PASS' if delivered else 'FAIL')
    if seen != by_case.keys():
        raise Unavailable('some approved operations have no event or controlled test')
    return states


def _activity_check(cid, item, index):
    rid = _scope_subject(item, index)
    policy = _policy(index, cid, rid)
    _window(policy, index)
    cases = _cases(policy, index, retention=cid == RETENTION_ID)
    alerts, groups, models = _alert_models(index)
    if any(not _covered(case, models) for case in cases):
        return result(True, reason='Complete definitions prove no enabled actionable alert for a required operation/scope/status')
    configuration = {'alerts': alerts, 'action_groups': groups}
    payload = _evidence(index, cid, rid, policy, configuration)
    states = _deliveries(payload, cases, models, policy, index)
    return _aggregate(states, required_case_count=len(cases))


@_signed(ACTIVITY_ID, ['activity_log_alert', 'action_group', EVIDENCE_KIND], target='scope')
def sensitive_activity_alert(item, index):
    return _activity_check(ACTIVITY_ID, item, index)


@_signed(RETENTION_ID, ['activity_log_alert', 'action_group', EVIDENCE_KIND], target='scope')
def attempted_retention_change_alert(item, index):
    return _activity_check(RETENTION_ID, item, index)


@_signed(DESTINATION_ID, ['activity_log_alert', 'action_group', EVIDENCE_KIND], target='scope')
def diagnostic_destination_controls(item, index):
    rid = _scope_subject(item, index)
    policy = _policy(index, DESTINATION_ID, rid)
    cases = _cases(policy, index)
    alerts, groups, models = _alert_models(index)
    payload = _evidence(index, DESTINATION_ID, rid, policy, {'alerts': alerts, 'action_groups': groups})
    resolution = _reviewed(payload, policy, ('service_inventory', 'child_resource_inventory', 'redirection_controls', 'operational_state'), index)
    resources = {_arm(v, prefix=rid) for v in _strings(get(policy, 'resourceIds', list), empty=False)}
    if {_arm(v, prefix=rid) for v in _strings(get(resolution, 'resource_ids', list))} != resources:
        raise Unavailable('service and child resource control coverage unresolved')
    expected = {(r, operation) for r in resources for operation in ('microsoft.insights/diagnosticsettings/write', 'microsoft.insights/diagnosticsettings/delete')}
    case_targets = {(r['scope'].casefold(), r['operation'].casefold()) for r in cases}
    if case_targets != expected:
        raise Unavailable('service/child write and delete operation coverage incomplete')
    controls = list_of_objects(get(payload, 'control_tests', list))
    seen, failures = set(), []
    for control in controls:
        resource = _arm(get(control, 'resource_id', str), prefix=rid)
        operation = get(control, 'operation', str).casefold()
        key = resource, operation
        if key not in expected or key in seen:
            raise Unavailable('duplicate or foreign redirection control test')
        seen.add(key)
        _text(get(control, 'test_id', str))
        _dated(get(control, 'observed_at', str), policy, index)
        before = get(control, 'before_state', str)
        after = get(control, 'after_state', str)
        if before != 'Running' or after not in ('Running', 'Stopped'):
            raise Unavailable('operational-state redirection test unresolved')
        applied = get(control, 'redirection_applied', bool)
        failures.append(applied and after == 'Running')
    if seen != expected:
        raise Unavailable('service or child redirection enforcement untested')
    if any(failures):
        return result(True, reason='Measured diagnostic redirection without resource halt')
    delivery = _deliveries(payload, cases, models, policy, index)
    if 'FAIL' in delivery:
        return result(True, reason='Measured missing publication to monitored channels')
    if any(not _covered(case, models) for case in cases):
        return unknown('change-alert configuration remains only partial or missing evidence')
    return _aggregate(delivery, resource_count=len(resources), control_test_count=len(controls))


def _duration(value):
    match = re.fullmatch(r'PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?', _text(value))
    if not match or not any(match.groups()):
        raise Unavailable('scheduled query duration unsupported')
    seconds = sum(int(v or 0) * weight for v, weight in zip(match.groups(), (3600, 60, 1)))
    if seconds <= 0:
        raise Unavailable('scheduled query duration nonpositive')
    return seconds


@_signed(ANOMALY_ID, ['activity_log_alert', 'scheduled_query_rule', 'action_group', EVIDENCE_KIND], target='scope')
def azure_activity_anomaly(item, index):
    rid = _scope_subject(item, index)
    _inventory(index, 'activity_log_alert')
    policy = _policy(index, ANOMALY_ID, rid)
    _window(policy, index)
    detectors = list_of_objects(get(policy, 'detectors', list))
    by_kind = {}
    for detector in detectors:
        kind = get(detector, 'kind', str)
        if kind not in ('suspicious_api_requests', 'per_principal_log_query_volume') or kind in by_kind:
            raise Unavailable('both frozen detection policies must be defined separately')
        criteria = list_of_objects(get(detector, 'criteria', list))
        if not criteria:
            raise Unavailable('reviewed detector criteria unavailable')
        for criterion in criteria:
            _text(get(criterion, 'query', str))
            if get(criterion, 'operator', str) not in ('GreaterThan', 'GreaterThanOrEqual', 'LessThan', 'LessThanOrEqual', 'Equal'):
                raise Unavailable('query operator semantics unresolved')
            _number(get(criterion, 'threshold'))
            if get(criterion, 'timeAggregation', str) not in ('Count', 'Average', 'Minimum', 'Maximum', 'Total'):
                raise Unavailable('query aggregation semantics unresolved')
        if kind == 'per_principal_log_query_volume':
            _text(get(detector, 'principalColumn', str))
        _strings(get(detector, 'tableIds', list), empty=False)
        for scope in _strings(get(detector, 'scopes', list), empty=False):
            _arm(scope, prefix=rid, native_type='Microsoft.OperationalInsights/workspaces')
        for field in ('maxEvaluationSeconds', 'maxWindowSeconds', 'maxLatencySeconds'):
            _number(get(detector, field), minimum=1)
        by_kind[kind] = detector
    if set(by_kind) != {'suspicious_api_requests', 'per_principal_log_query_volume'}:
        raise Unavailable('required suspicious API and per-principal query volume policies incomplete')
    rules = _inventory(index, 'scheduled_query_rule')
    groups = {g['id'].casefold(): g for g in _inventory(index, 'action_group')}
    for group in groups.values():
        get(group, 'properties.enabled', bool)
    configurations = {}
    for rule in rules:
        _arm(rule['id'], native_type='Microsoft.Insights/scheduledQueryRules')
        props = get(rule, 'properties', dict)
        enabled = get(props, 'enabled', bool)
        criteria = list_of_objects(get(props, 'criteria.allOf', list))
        scopes = {_arm(v, prefix=rid) for v in _strings(get(props, 'scopes', list), empty=False)}
        frequency = _duration(get(props, 'evaluationFrequency', str))
        window = _duration(get(props, 'windowSize', str))
        group_ids = {_arm(v, prefix=rid, native_type='Microsoft.Insights/actionGroups') for v in _strings(get(props, 'actions.actionGroups', list))}
        live = {g for g in group_ids if g in groups and groups[g]['properties']['enabled']}
        for kind, detector in by_kind.items():
            if criteria == detector['criteria']:
                good = enabled and live and scopes == {s.casefold() for s in detector['scopes']} and frequency <= detector['maxEvaluationSeconds'] and window <= detector['maxWindowSeconds']
                configurations.setdefault(kind, []).append((rule, bool(good), live))
    # Arbitrary alternative KQL cannot be classified as inadequate by text
    # fragments. Complete emptiness or a measured approved definition can.
    for kind in by_kind:
        if kind not in configurations:
            if rules:
                return unknown('query semantics differ from reviewed required detector', detector=kind)
            return result(True, reason='Complete scheduled query inventory has no required detector', detector=kind)
        if not any(good for _, good, _ in configurations[kind]):
            if any(rule['properties']['enabled'] and rule['properties']['criteria']['allOf'] not in [d['criteria'] for d in detectors] for rule in rules):
                return unknown('an alternative enabled query has unreviewed detector semantics', detector=kind)
            return result(True, reason='Reviewed detector has disabled, unbounded or unactionable configuration', detector=kind)
    payload = _evidence(index, ANOMALY_ID, rid, policy, {'rules': rules, 'action_groups': list(groups.values())})
    resolution = _reviewed(payload, policy, ('query_semantics', 'thresholds', 'per_principal_aggregation', 'scope_inventory', 'source_tables', 'delivery'), index)
    if set(_strings(get(resolution, 'detector_kinds', list))) != set(by_kind):
        raise Unavailable('reviewed detector semantics incomplete')
    tables = list_of_objects(get(payload, 'tables', list))
    available = set()
    for table in tables:
        identity = _text(get(table, 'table_id', str))
        if identity in available:
            raise Unavailable('duplicate detection source table')
        if not get(table, 'available', bool):
            raise Unavailable('detection source table availability unresolved')
        _dated(get(table, 'observed_at', str), policy, index)
        available.add(identity)
    if not set(t for d in detectors for t in d['tableIds']) <= available:
        raise Unavailable('required source-table coverage incomplete')
    observations = list_of_objects(get(payload, 'detections', list))
    seen, states = set(), []
    for observation in observations:
        kind = get(observation, 'kind', str)
        if kind not in by_kind or kind in seen:
            raise Unavailable('duplicate or foreign detector observation')
        seen.add(kind)
        rule_id = _arm(get(observation, 'rule_id', str), prefix=rid)
        matching = [(rule, live) for rule, good, live in configurations[kind] if good and rule['id'].casefold() == rule_id]
        if len(matching) != 1:
            raise Unavailable('detection not bound to qualifying native rule')
        event_time = _dated(get(observation, 'event_time', str), policy, index)
        until = _dated(get(observation, 'observed_until', str), policy, index)
        max_latency = by_kind[kind]['maxLatencySeconds']
        if (until - event_time).total_seconds() < max_latency or get(observation, 'delivery_inventory_complete', bool) is not True:
            raise Unavailable('real-time latency or delivery unmeasured')
        _text(get(observation, 'event_id', str))
        if kind == 'per_principal_log_query_volume':
            _text(get(observation, 'principal_id', str))
        deliveries = list_of_objects(get(observation, 'deliveries', list))
        passed = False
        for delivery in deliveries:
            gid = _arm(get(delivery, 'action_group_id', str), prefix=rid)
            _text(get(delivery, 'delivery_id', str))
            published = _dated(get(delivery, 'published_at', str), policy, index)
            if published < event_time or published > until:
                raise Unavailable('detector delivery timestamp contradicts event')
            passed |= gid in matching[0][1] and (published - event_time).total_seconds() <= max_latency
        states.append('PASS' if passed else 'FAIL')
    if seen != set(by_kind):
        raise Unavailable('both required detector deliveries must be measured')
    return _aggregate(states, detector_count=2)
