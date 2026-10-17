"""The fifteen signed ten-field Azure specifications and their canonical digests."""

SPECS = {'azure_pci_10_2_1_1_25': {'id': 'azure_pci_10_2_1_1_25',
                           'provider': 'azure',
                           'resource_kind': 'mysql_flexible_server',
                           'data_source': 'Paged MySQL Flexible Server and per-server configurations LIST '
                                          '2023-12-30: name=audit_log_enabled, properties.value string; '
                                          'per-server diagnosticSettings LIST 2021-05-01-preview: '
                                          'setting.properties.logs[].category=MySqlAuditLogs and enabled '
                                          'boolean, setting.properties.workspaceId; approved workspace '
                                          'policy and supported categories.',
                           'predicate': 'For each MySQL Flexible Server, PASS only if '
                                        'audit_log_enabled.properties.value="ON" and a diagnostic setting '
                                        'for that exact server enables MySqlAuditLogs to an approved '
                                        'setting-level workspaceId. FAIL for explicit OFF or complete '
                                        'configuration/settings proving no export. UNKNOWN for missing '
                                        'configuration, category support, workspace approval or '
                                        'inventory/paging.',
                           'severity': 'high',
                           'category': 'logging',
                           'title': 'MySQL Flexible Server generates and exports audit logs',
                           'description': 'Checks MySQL flexible-server audit generation and export of '
                                          'MySqlAuditLogs to Log Analytics.',
                           'remediation_hint': 'In Azure portal > MySQL Flexible Server > Server parameters, '
                                               'set audit_log_enabled=ON; under Diagnostic settings, enable '
                                               'MySqlAuditLogs to the approved Log Analytics workspace.'},
 'azure_vault_keyvault_non_rbac_secret_expiration_set_0041351': {'id': 'azure_vault_keyvault_non_rbac_secret_expiration_set_0041351',
                                                                 'provider': 'azure',
                                                                 'resource_kind': 'key_vault_secret',
                                                                 'data_source': 'Key Vault data-plane paged '
                                                                                'GET '
                                                                                '{vaultUri}/secrets?api-version=7.4 '
                                                                                'yields base secret IDs and '
                                                                                'attributes.enabled. Query '
                                                                                'complete AzureDiagnostics '
                                                                                'Key Vault AuditEvent '
                                                                                'history for policy '
                                                                                'unusedForDays using '
                                                                                'OperationName, ResultType, '
                                                                                'TimeGenerated and audited '
                                                                                'secret URI; match all '
                                                                                'versions by normalized '
                                                                                'vault and base secret name. '
                                                                                'Resolve versioned IDs only '
                                                                                'when an audit record '
                                                                                'requires it.',
                                                                 'predicate': 'For each enabled base secret '
                                                                              'in a complete paged /secrets '
                                                                              'inventory, PASS if complete '
                                                                              'AuditEvent history within the '
                                                                              'policy window contains a '
                                                                              'successful SecretGet for that '
                                                                              'vault and secret name, '
                                                                              'regardless of version. FAIL '
                                                                              'only when diagnostic '
                                                                              'collection and retention '
                                                                              'cover the entire window, '
                                                                              'audit identifiers and success '
                                                                              'semantics are comparable, and '
                                                                              'no successful matching read '
                                                                              'exists. UNKNOWN if audit '
                                                                              'URI/name, timestamp/status, '
                                                                              'diagnostic route/retention, '
                                                                              'query completeness, window or '
                                                                              'secret inventory is '
                                                                              'unresolved. Aggregate '
                                                                              'definite FAIL before UNKNOWN.',
                                                                 'severity': 'high',
                                                                 'category': 'encryption',
                                                                 'title': 'Enabled Key Vault secrets have '
                                                                          'recent successful use',
                                                                 'description': 'Detects unused enabled '
                                                                                'secrets only when complete '
                                                                                'Key Vault audit history is '
                                                                                'available.',
                                                                 'remediation_hint': 'In Key Vault > Secrets '
                                                                                     'and Azure Monitor '
                                                                                     'logs, investigate '
                                                                                     'secrets with no '
                                                                                     'successful SecretGet '
                                                                                     'in the approved '
                                                                                     'window; rotate or '
                                                                                     'disable unused secrets '
                                                                                     'after owner review.'},
 'azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7': {'id': 'azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7',
                                                                 'provider': 'azure',
                                                                 'resource_kind': 'key_vault_secret',
                                                                 'data_source': 'NEW: paged Key Vault '
                                                                                'data-plane GET '
                                                                                '/secrets?api-version=7.4 to '
                                                                                'enumerate names and current '
                                                                                'metadata; paged GET '
                                                                                '/secrets/{name}/versions?api-version=7.4 '
                                                                                'to confirm current version '
                                                                                'and created/ enabled '
                                                                                'attributes. Collector '
                                                                                'azure.py has no secret '
                                                                                'list.',
                                                                 'predicate': 'For each in-scope enabled '
                                                                              'current secret, PASS iff the '
                                                                              'current version '
                                                                              'attributes.created (Unix '
                                                                              'seconds) is within '
                                                                              'maxDaysSinceRotation; FAIL '
                                                                              'iff its current enabled '
                                                                              'version is older. UNKNOWN if '
                                                                              'current version status, '
                                                                              'creation timestamp, name '
                                                                              'list, version list, vault '
                                                                              'scope or policy is '
                                                                              'incomplete. A newer disabled '
                                                                              'version does not count; a '
                                                                              'recent old version does not '
                                                                              'prove current rotation.',
                                                                 'severity': 'high',
                                                                 'category': 'encryption',
                                                                 'title': 'Rotate Key Vault secrets on '
                                                                          'schedule',
                                                                 'description': 'Rotate Key Vault secrets on '
                                                                                'schedule. A finding is '
                                                                                'raised when an enabled '
                                                                                'secret has no enabled '
                                                                                'version created within '
                                                                                'maxDaysSinceRotation.',
                                                                 'remediation_hint': 'Azure portal > Key '
                                                                                     'Vault > Secrets > '
                                                                                     'selected secret > New '
                                                                                     'Version: set and '
                                                                                     'enable a new value '
                                                                                     'within the approved '
                                                                                     'rotation period, then '
                                                                                     'update consumers if '
                                                                                     'version-pinned.'},
 'azure.cis.app_service_entra_registration_enabled': {'id': 'azure.cis.app_service_entra_registration_enabled',
                                                      'provider': 'azure',
                                                      'resource_kind': 'web_app',
                                                      'data_source': 'Paged ARM App Service site inventory '
                                                                     'and GET 2025-03-01: identity.type, '
                                                                     'principalId and '
                                                                     'userAssignedIdentities. Resolve '
                                                                     'referenced user-assigned identity ARM '
                                                                     'IDs if attachment is ambiguous. App '
                                                                     'Service authsettingsV2 and Graph app '
                                                                     'registration are optional separate '
                                                                     'inbound-authentication evidence, not '
                                                                     'prerequisites for this '
                                                                     'managed-identity benchmark.',
                                                      'predicate': 'For each applicable App Service, PASS '
                                                                   'when an active system-assigned identity '
                                                                   'has a principalId or a user-assigned '
                                                                   'identity ARM ID is attached; FAIL when a '
                                                                   'complete site GET proves no managed '
                                                                   'identity is attached. UNKNOWN if site '
                                                                   'kind, identity state, identity reference '
                                                                   'or inventory is unresolved. An App '
                                                                   'Service can satisfy this outbound '
                                                                   'service-access requirement without '
                                                                   'enabling the inbound Entra '
                                                                   'authentication provider.',
                                                      'severity': 'high',
                                                      'category': 'identity',
                                                      'title': 'App Service has a managed identity for Entra '
                                                               'service access',
                                                      'description': 'Checks the managed identity described '
                                                                     'in the frozen CIS benchmark, which '
                                                                     'enables secret-free access from the '
                                                                     'app to Azure services.',
                                                      'remediation_hint': 'Enable a system-assigned or '
                                                                          'user-assigned managed identity on '
                                                                          'the App Service and grant it the '
                                                                          'needed target-resource access.'},
 'azure.cis.key_vaults_store_secrets': {'id': 'azure.cis.key_vaults_store_secrets',
                                        'provider': 'azure',
                                        'resource_kind': 'web_app',
                                        'data_source': 'Paged Microsoft.Web/sites and slots plus POST '
                                                       '{site-or-slot-id}/config/appsettings/list?api-version=2023-12-01; '
                                                       'GET each app and slot configreferences/appsettings '
                                                       'to check reference resolution. An authoritative '
                                                       'workload-wide secret inventory must identify every '
                                                       'in-scope secret and storage location, including '
                                                       'secrets outside App Service. Keep values transient.',
                                        'predicate': 'For every workload secret in an approved complete '
                                                     'secret inventory, PASS only if its current storage is '
                                                     'an authorized Key Vault secret and, for App '
                                                     'Service/slot settings, its effective setting is a '
                                                     'valid Key Vault reference with a successful current '
                                                     'resolution status. FAIL for a fully identified secret '
                                                     'stored literally outside Key Vault, a required missing '
                                                     'secret, or a known failed reference. UNKNOWN if the '
                                                     'workload-wide inventory, App Service/slot pages, '
                                                     'classification, reference status, or another workload '
                                                     'secret location is unmeasured. A syntactically valid '
                                                     'reference alone cannot PASS the broad CIS requirement.',
                                        'severity': 'medium',
                                        'category': 'encryption',
                                        'title': 'Named App Service secret settings use Key Vault references',
                                        'description': 'Checks only explicitly identified secret-bearing App '
                                                       'Service settings; arbitrary application settings '
                                                       'cannot be classified as secrets from ARM values '
                                                       'alone.',
                                        'remediation_hint': 'Azure portal > App Service > Environment '
                                                            'variables: move each named secret to Key Vault, '
                                                            'set its app setting to a Key Vault reference, '
                                                            'and grant the app identity Get Secret.'},
 'azure.gap.monitor_log_profile_enabled_for_all_categories': {'id': 'azure.gap.monitor_log_profile_enabled_for_all_categories',
                                                              'provider': 'azure',
                                                              'resource_kind': 'subscription',
                                                              'data_source': 'ARM '
                                                                             'Microsoft.Insights/logProfiles '
                                                                             'List 2016-03-01: '
                                                                             'value[].properties.categories,locations,storageAccountId,serviceBusRuleId,retentionPolicy; '
                                                                             'subscription inventory',
                                                              'predicate': 'For every subscription and each '
                                                                           'required Write, Delete and '
                                                                           'Action category, PASS only when '
                                                                           'complete log-profile inventory '
                                                                           'proves that category is exported '
                                                                           'by a profile with a nonempty '
                                                                           'configured storageAccountId or '
                                                                           'serviceBusRuleId. FAIL if '
                                                                           'complete inventory shows any '
                                                                           'required category uncovered. '
                                                                           'UNKNOWN when profile paging, '
                                                                           'category details or destination '
                                                                           'identity cannot be resolved.',
                                                              'severity': 'medium',
                                                              'category': 'logging',
                                                              'title': 'Azure Monitor log profile should '
                                                                       "collect logs for categories 'write,' "
                                                                       "'delete,' and 'action'",
                                                              'description': 'Checks legacy Activity Log '
                                                                             'profile export only where '
                                                                             'policy explicitly requires log '
                                                                             'profiles; subscription '
                                                                             'diagnostic settings are a '
                                                                             'separate modern mechanism.',
                                                              'remediation_hint': 'In Azure Monitor, '
                                                                                  'configure the required '
                                                                                  'legacy log profile with '
                                                                                  'Write, Delete and Action '
                                                                                  'categories, applicable '
                                                                                  'locations and a valid '
                                                                                  'destination.'},
 'azure.gap.monitor_log_profile_retention_365_days': {'id': 'azure.gap.monitor_log_profile_retention_365_days',
                                                      'provider': 'azure',
                                                      'resource_kind': 'subscription',
                                                      'data_source': 'ARM Microsoft.Insights/logProfiles '
                                                                     'LIST 2016-03-01 per subscription; '
                                                                     'value[].properties.retentionPolicy.enabled '
                                                                     '(boolean), days (integer), plus '
                                                                     'categories/locations and configured '
                                                                     'sink IDs; follow nextLink if returned.',
                                                      'predicate': 'For each legacy Monitor log profile, '
                                                                   'PASS when complete '
                                                                   'properties.retentionPolicy shows '
                                                                   'enabled=true and days>=365, or days=0 '
                                                                   'with verified unlimited retention for '
                                                                   'the configured destination. FAIL when a '
                                                                   'fully read, enabled policy has days from '
                                                                   '1 through 364. UNKNOWN when '
                                                                   'retentionPolicy is disabled without '
                                                                   'verified destination retention, days is '
                                                                   'omitted/invalid, or profile inventory is '
                                                                   'incomplete. No profile is NOT_APPLICABLE '
                                                                   'to this retention control.',
                                                      'severity': 'medium',
                                                      'category': 'logging',
                                                      'title': 'Subscription Activity Log exports are '
                                                               'retained for 365 days',
                                                      'description': 'Evaluates the destination retention '
                                                                     'for subscription Activity Log exports.',
                                                      'remediation_hint': 'Azure Monitor > Activity log > '
                                                                          'legacy log profiles: enable '
                                                                          'retention for at least 365 days, '
                                                                          'or use the documented unlimited '
                                                                          'setting where supported.'},
 'azure.other.storage_immutability': {'id': 'azure.other.storage_immutability',
                                      'provider': 'azure',
                                      'resource_kind': 'storage_service',
                                      'data_source': 'Complete inventory of in-scope object and audit-log '
                                                     'containers plus required retention policy; ARM '
                                                     'container immutabilityPolicies/default GET '
                                                     'properties.state and '
                                                     'immutabilityPeriodSinceCreationInDays; blob-service '
                                                     'version-level immutability and legal-hold settings '
                                                     'where used; test/evidence of effective default '
                                                     'retention and denied premature delete/modify.',
                                      'predicate': 'For every in-scope object or audit-log container, PASS '
                                                   'only if a default retention policy of the required '
                                                   'duration is active, the policy cannot be weakened during '
                                                   'its term (Locked or equivalent immutable version-level '
                                                   'protection), and effective object-level evidence '
                                                   'establishes premature delete/modify denial. FAIL on '
                                                   'fully measured absent/short/unlocked protection or '
                                                   'successful premature change. UNKNOWN if scope, duration, '
                                                   'object-level override, inheritance or effective '
                                                   'enforcement evidence is missing. A Locked container '
                                                   'policy is a configuration signal, not by itself proof '
                                                   'for every object.',
                                      'severity': 'high',
                                      'category': 'recovery',
                                      'title': 'Audit storage has locked immutability',
                                      'description': 'Requires locked time-based immutability for designated '
                                                     'audit log containers.',
                                      'remediation_hint': 'Apply the approved default immutable retention to '
                                                          'each in-scope container or object version, lock '
                                                          'the policy where supported, and verify premature '
                                                          'modification and deletion are denied.'},
 'azure.other.monitor_alert_ack_authorization': {'id': 'azure.other.monitor_alert_ack_authorization',
                                                 'provider': 'azure',
                                                 'resource_kind': 'action_group',
                                                 'data_source': 'Paged ARM '
                                                                'Microsoft.Authorization/roleAssignments and '
                                                                'roleDefinitions at alert scopes and '
                                                                'ancestors, including actions/notActions, '
                                                                'conditions, transitive groups and PIM. '
                                                                'Resolve '
                                                                'Microsoft.AlertsManagement/alerts/changeState/action '
                                                                'or relevant alert-management action and '
                                                                'approvedResponders. For alerts acknowledged '
                                                                'in Sentinel/ITSM, obtain that system’s '
                                                                'effective permissions and audit events.',
                                                 'predicate': 'For each in-scope alert workflow, FAIL if a '
                                                              'concrete unapproved effective principal can '
                                                              'change state, silence or acknowledge an '
                                                              'alert. PASS only if all effective principals '
                                                              'with the actual acknowledgment/silence '
                                                              'action, including inherited and '
                                                              'external-system access, are '
                                                              'approvedResponders. UNKNOWN if action '
                                                              'mapping, scopes, groups, PIM, conditions, '
                                                              'external workflow or inventory is unresolved; '
                                                              'generic alert write permission alone is not '
                                                              'proof of acknowledgement authority.',
                                                 'severity': 'high',
                                                 'category': 'monitoring',
                                                 'title': 'Only responders can silence alerts',
                                                 'description': 'Checks effective Azure Monitor '
                                                                'alert-management permissions against an '
                                                                'approved responder list.',
                                                 'remediation_hint': 'Restrict the actual alert '
                                                                     'change-state, silence and '
                                                                     'acknowledgement permissions to '
                                                                     'approved responders across Azure '
                                                                     'Monitor and any connected incident '
                                                                     'system.'},
 'azure.other.vault_old_secret_disabled': {'id': 'azure.other.vault_old_secret_disabled',
                                           'provider': 'azure',
                                           'resource_kind': 'vault_secret',
                                           'data_source': 'Paged Key Vault data-plane '
                                                          '/secrets?api-version=7.4 and '
                                                          '/secrets/{name}/versions?api-version=7.4: '
                                                          'attributes.enabled boolean, created integer Unix '
                                                          'seconds, id/version; approvedRotationDays and UTC '
                                                          'clock; version ordering and current version '
                                                          'resolved by version ID. Current authorized '
                                                          'negative read test or equivalent Key Vault '
                                                          'authorization evidence for each applicable '
                                                          'superseded version is required for the frozen '
                                                          'denial claim.',
                                           'predicate': 'For every secret, FAIL if a controlled read of a '
                                                        'superseded version past approvedRotationDays '
                                                        'succeeds, or if authoritative effective access '
                                                        'evidence proves it remains readable. PASS only if '
                                                        'complete name/version pages and ordering identify '
                                                        'every outdated superseded version and current '
                                                        'authorized negative tests or equivalent '
                                                        'effective-denial evidence prove access is denied '
                                                        'for each. UNKNOWN for missing rotation policy, '
                                                        'creation time, version identity, incomplete paging '
                                                        'or unmeasured effective denial. '
                                                        'attributes.enabled=false is a useful configuration '
                                                        'signal but alone does not prove the frozen '
                                                        'access-denial requirement.',
                                           'severity': 'high',
                                           'category': 'hardening',
                                           'title': 'Old secret versions are disabled',
                                           'description': 'Checks disabled state of old Key Vault secret '
                                                          'versions after rotation.',
                                           'remediation_hint': 'Azure portal > Key Vault > Secrets > '
                                                               'Versions: Disable superseded secret versions '
                                                               'older than the approved rotation period.'},
 'azure.other.build_private_network': {'id': 'azure.other.build_private_network',
                                       'provider': 'azure',
                                       'resource_kind': 'build_agent',
                                       'data_source': 'Managed DevOps Pools ARM GET 2025-09-20 for pool '
                                                      'inventory and network profile; self-hosted agent '
                                                      'host/NIC/firewall inventory; approved source policy; '
                                                      'dated external-network probe results for each '
                                                      'accessible build endpoint.',
                                       'predicate': 'For every in-scope build environment, execute or obtain '
                                                    'a dated external-network access probe against the '
                                                    'exposed agent endpoints, alongside complete host, NIC, '
                                                    'firewall and effective routing evidence. PASS only when '
                                                    'each attempted unauthorized external access is denied '
                                                    'during the approved observation window. FAIL on a '
                                                    'successful unauthorized external probe. UNKNOWN without '
                                                    'current probes, endpoint inventory, approved source '
                                                    'policy or effective network evidence.',
                                       'severity': 'high',
                                       'category': 'hardening',
                                       'title': 'Build agents restrict external access',
                                       'description': 'Flags build agent resources where an in-scope build '
                                                      'agent is reachable from an unapproved external '
                                                      'network. Unnecessary network reachability expands the '
                                                      'attack surface.',
                                       'remediation_hint': 'Block unauthorized external ingress to build '
                                                           'agents with private networking and effective '
                                                           'firewall/NSG rules, then repeat and record '
                                                           'external access probes.'},
 'azure.other.function_invoke_rate_limit': {'id': 'azure.other.function_invoke_rate_limit',
                                            'provider': 'azure',
                                            'resource_kind': 'function_app',
                                            'data_source': 'Paged APIM APIs/operations and '
                                                           'service/API/operation policy GET 2024-05-01 with '
                                                           'effective XML rate-limit-by-key '
                                                           'calls,renewal-period,counter-key; identify '
                                                           'policy-named exposed Function API operations. '
                                                           'Execute authorized same-entity calls up to and '
                                                           'beyond threshold and record response codes '
                                                           'within approved test window.',
                                            'predicate': 'For each exposed Function operation, PASS only if '
                                                         'effective rate-limit-by-key is within approved '
                                                         'calls/window, uses a stable caller key, '
                                                         'allowed-threshold test calls succeed and an '
                                                         'additional same-entity call is denied. FAIL if a '
                                                         'complete policy tree has no effective limit or a '
                                                         'measured beyond-threshold call succeeds. UNKNOWN '
                                                         'for unresolved API mapping, policy '
                                                         'inheritance/expressions, counter key, thresholds, '
                                                         'paging, authorization to test or probe result.',
                                            'severity': 'high',
                                            'category': 'hardening',
                                            'title': 'Rate-limit exposed Function API invocation',
                                            'description': 'Rate-limit exposed Function API invocation. A '
                                                           'finding is raised when an exposed Function API '
                                                           'lacks an effective per-caller rate-limit-by-key '
                                                           'policy within maxCalls.',
                                            'remediation_hint': 'Apply an APIM rate-limit-by-key policy with '
                                                                'an approved caller key and threshold, then '
                                                                'verify allowed calls succeed and the next '
                                                                'same-entity call is denied.'},
 'azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d': {'id': 'azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d',
                                                                         'provider': 'azure',
                                                                         'resource_kind': 'mysql_postgresql_sql_firewall_rule',
                                                                         'data_source': 'Existing azure.py '
                                                                                        'sql_server and '
                                                                                        'mysql/postgresql '
                                                                                        'flexible server '
                                                                                        'items, '
                                                                                        'sql_firewall_rule '
                                                                                        'child for SQL only; '
                                                                                        'new paged '
                                                                                        'firewallRules list '
                                                                                        'per '
                                                                                        'MySQL/PostgreSQL '
                                                                                        'server using each '
                                                                                        'provider API; '
                                                                                        'properties.startIpAddress/endIpAddress '
                                                                                        'IPv4 strings.',
                                                                         'predicate': 'For every SQL, MySQL '
                                                                                      'and PostgreSQL '
                                                                                      'server, evaluate all '
                                                                                      'child firewall rules '
                                                                                      'against the frozen '
                                                                                      'rule: custom '
                                                                                      'non-default rules '
                                                                                      'that allow '
                                                                                      'unrestricted inbound '
                                                                                      'access fail. FAIL on '
                                                                                      'a measured custom '
                                                                                      'rule spanning the '
                                                                                      'public IPv4 range, '
                                                                                      'and evaluate '
                                                                                      'Azure-services '
                                                                                      '0.0.0.0 sentinel '
                                                                                      'separately against '
                                                                                      'the rule’s '
                                                                                      'approved-source '
                                                                                      'policy. PASS only '
                                                                                      'when all paged child '
                                                                                      'lists and effective '
                                                                                      'public-access '
                                                                                      'settings are complete '
                                                                                      'and no unrestricted '
                                                                                      'custom rule exists. '
                                                                                      'UNKNOWN for absent '
                                                                                      'lists, malformed IPs, '
                                                                                      'unresolved '
                                                                                      'default-rule '
                                                                                      'classification, '
                                                                                      'approved-source '
                                                                                      'policy or unsupported '
                                                                                      'server generation. No '
                                                                                      'servers is '
                                                                                      'NOT_APPLICABLE.',
                                                                         'severity': 'high',
                                                                         'category': 'network',
                                                                         'title': 'Database firewall rules '
                                                                                  'do not allow unrestricted '
                                                                                  'inbound access',
                                                                         'description': 'Checks custom SQL, '
                                                                                        'MySQL and '
                                                                                        'PostgreSQL firewall '
                                                                                        'rules for '
                                                                                        'unrestricted public '
                                                                                        'inbound access.',
                                                                         'remediation_hint': 'On each '
                                                                                             'SQL/MySQL/PostgreSQL '
                                                                                             'server > '
                                                                                             'Networking > '
                                                                                             'Firewall '
                                                                                             'rules, remove '
                                                                                             '0.0.0.0-255.255.255.255 '
                                                                                             'and replace '
                                                                                             'with approved '
                                                                                             'source ranges '
                                                                                             'or private '
                                                                                             'endpoints.'},
 'azure_vm_1_4_5_1_d40be43': {'id': 'azure_vm_1_4_5_1_d40be43',
                              'provider': 'azure',
                              'resource_kind': 'vm_and_vm_scale_set',
                              'data_source': 'Paged ARM virtualMachines GET/LIST 2024-07-01 '
                                             '(networkProfile.networkInterfaces[].id); networkInterfaces GET '
                                             '2023-09-01 (ipConfigurations[].properties.publicIPAddress.id); '
                                             'virtualMachineScaleSets GET/LIST 2024-07-01 '
                                             '(virtualMachineProfile.networkProfile.networkInterfaceConfigurations[].properties.ipConfigurations[].properties.publicIPAddressConfiguration). '
                                             'VMSS instance NICs provide a separate drift signal.',
                              'predicate': 'For each in-scope VM NIC and each VMSS NIC template, FAIL if a '
                                           'NIC ipConfiguration has publicIPAddress.id or a template has '
                                           'publicIPAddressConfiguration. PASS when complete VM, NIC and '
                                           'VMSS template inventories have none. UNKNOWN for unresolved NIC '
                                           'references, absent ipConfiguration details or incomplete paging. '
                                           'Inspect VMSS instance NICs separately for runtime drift, but '
                                           'instance drift alone does not change the frozen '
                                           'default-configuration result.',
                              'severity': 'high',
                              'category': 'network',
                              'title': 'VMs and VM scale set instances do not receive public IPs',
                              'description': 'Checks the default public IP assignment configuration of VM '
                                             'NICs and VMSS NIC templates. Existing VMSS instance NICs are a '
                                             'separate drift signal.',
                              'remediation_hint': 'Remove public IP references from VM NIC IP configurations '
                                                  'and VMSS NIC templates; update or reimage existing '
                                                  'scale-set instances and verify each instance NIC.'},
 'azure_storage_account_10_2_1_1_20_5914d2c': {'id': 'azure_storage_account_10_2_1_1_20_5914d2c',
                                               'provider': 'azure',
                                               'resource_kind': 'servicebus_namespace',
                                               'data_source': 'Paged Service Bus namespace inventory '
                                                              'including SKU and per-namespace '
                                                              'Microsoft.Insights/diagnosticSettings LIST '
                                                              '2021-05-01-preview. Read setting-level '
                                                              'properties.workspaceId/storageAccountId and '
                                                              'properties.logs[].category/enabled. Verify '
                                                              'approved sink. Supported categories include '
                                                              'OperationalLogs and, for Premium data-plane '
                                                              'access auditing, RuntimeAuditLogs.',
                                               'predicate': 'For every Service Bus namespace, require '
                                                            'complete diagnostic-setting pages and an '
                                                            'approved resolvable Log Analytics or Storage '
                                                            'destination. PASS only if OperationalLogs is '
                                                            'enabled and routed; for Premium namespaces '
                                                            'requiring data-plane access audit, also require '
                                                            'RuntimeAuditLogs. FAIL if complete evidence '
                                                            'proves a required category is absent or '
                                                            'unrouted. UNKNOWN for unknown SKU, required '
                                                            'audit scope, namespace/settings paging, '
                                                            'unsupported category, sink or approval policy. '
                                                            'Event Hub-only routing does not PASS.',
                                               'severity': 'medium',
                                               'category': 'logging',
                                               'title': 'Service Bus namespaces export operational logs',
                                               'description': 'Checks the Service Bus OperationalLogs '
                                                              'category and configured destination.',
                                               'remediation_hint': 'Service Bus namespace > Diagnostic '
                                                                   'settings: enable OperationalLogs to an '
                                                                   'approved Log Analytics workspace or '
                                                                   'Storage account and verify the sink.'}}
SPEC_SHA256 = {'azure.cis.app_service_entra_registration_enabled': '7759b611ae4dc6f5ad2950f86e7db8a7138899d10084845b49532a4deff0e29c',
 'azure.cis.key_vaults_store_secrets': 'c1ac381cb4615ea69bcb2870e6440f7be004c9aaa80cff96a0a76ca558000417',
 'azure.gap.monitor_log_profile_enabled_for_all_categories': 'cb59e62c1cf8dd69105934a5dfe8d0e013b9b3ba1edaacce065c249c2e87e30a',
 'azure.gap.monitor_log_profile_retention_365_days': '79ba51c47bda8b66e9a9b95854be99025fb8e45c83a88b1b0b934bf89e4105d1',
 'azure.other.build_private_network': '4922f870ec542c5802eecb1be76bbd349e6ef9fff35f568e3f5273706a3a524d',
 'azure.other.function_invoke_rate_limit': 'a6c31d7db7775375c5fe591d22aa348df0215ae34ab8c6c60ba3b3e47a80291c',
 'azure.other.monitor_alert_ack_authorization': '8f0367ec20f61f5c9b09afa3416d181500135ef4a98e0af3c259c6ee798c7e5e',
 'azure.other.storage_immutability': 'd236ccbf8c8462225c35bc1773d5918433c4983bd195ccc03e8bbb163d6cbdd4',
 'azure.other.vault_old_secret_disabled': '7217cce08a4f28253c03c690c747250d9cdec9c2d88f0b657f00ee55bfcea1af',
 'azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d': 'c736ee942c8e94b6d35517be09be88e252e47a8e30ae2a605971d10e5a0ccec4',
 'azure_pci_10_2_1_1_25': '70f91666b6ee62e9215fcde7acc02d33a5440fc632dc6a3e54a42839c525925f',
 'azure_storage_account_10_2_1_1_20_5914d2c': '8cb3aa955f1722a6dcd008448ddb9056cc6c6dfb0000322d3f561cb06495b783',
 'azure_vault_keyvault_non_rbac_secret_expiration_set_0041351': 'e957baf26a2461130c2cf7fab26bc91b5d53b200448d55ae775fc844324dadc9',
 'azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7': 'ca214ae537011b69c4dbb894f6d846cf5e52954072da48fd3b6ae110d666561d',
 'azure_vm_1_4_5_1_d40be43': '8fde61f6fd77dbda5645df1339c6bee4b515741e91710d4cd8bd4d86eb0aeae8'}
IDS = tuple(SPECS)
