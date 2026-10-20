"""Narrow guidance successors; preserve the original signed-row base guards."""
from copy import deepcopy
import hashlib
import json

# Pin the prior reviewed fields separately from their original signed base.
# A changed predecessor must receive a new review, never a blanket hash refresh.
SUCCESSORS = {
    ('azure.claude.storage_access_keys_rotated_90', 'description'): (
        'a0827ceecb2174fb121e97cedb5570bb10382ba6103add0d351dd8abef0e9c17', {
            'description': 'Checks both native storage-key creation times against the captured scan time. Either key older than 90 days fails; incomplete, future or malformed times remain unresolved.',
            'pass_when': 'Both key1 and key2 have valid creation times no more than 90 days before the captured scan time.',
            'fail_when': 'At least one of the two valid native key creation times is more than 90 days before the captured scan time.',
            'not_applicable_when': 'No automatic exclusion; absent, incomplete, future or malformed key creation times remain UNKNOWN.',
        }),
    ('azure.claude.storage_access_keys_rotated_90', 'remediation'): (
        '320d46eb73a44c5d764b5e8750bba6c5a951ebe3479f2396a1e32b7c305656f2', {
            'caveats': ['Both key creation times and a valid collection time are required. Missing or future dates remain unresolved. Key age does not establish credential compromise.'],
        }),
    ('azure.claude.storage_vhd_accounts_cmk', 'description'): (
        '71951bfd23a1f570248bc30b5e039a5e5162f77039d7b447c6169008b6969888', {
            'description': 'Matches unmanaged OS-disk HTTPS VHD URLs to the native Blob endpoint of a collected storage account, then checks that account’s encryption key source. Foreign or unresolved endpoints cannot establish compliance.',
        }),
    ('azure.claude2.nsg_flow_log_configured', 'description'): (
        '54cdbc50c5459de4b2b9a029c28b1aaac12eda191789369763ff57f7b23ebfa7', {
            'description': 'For an attached NSG, checks for an enabled matching NSG flow log or an enabled VNet flow log covering its NIC, subnet or VNet. A reference alone cannot satisfy this check.',
            'pass_when': 'An enabled native NSG flow log targets the NSG, or an enabled VNet flow log covers a related NIC, subnet or VNet.',
            'fail_when': 'Complete native inventories contain no enabled matching NSG or covering VNet flow log.',
        }),
    ('azure.claude2.nsg_flow_log_configured', 'remediation'): (
        '07e74bcb7cc32066a621615b39eaa33ceeac62b19d4e368e67ebb62dd01ea8fb', {
            'caveats': ['Unattached NSGs are not applicable. A native matching log must be enabled; configuration does not prove log delivery.'],
        }),
    ('azure.claude.vm_windows_secure_boot', 'description'): (
        '23c572e4e80d23867b7ffa16e74507843e95e0780d61492aaa2d3b50e38d36c4', {
            'description': 'Uses the native Windows OS type, including SQL and custom images, to check the security profile and UEFI Secure Boot flag. Standard profiles or explicitly disabled Secure Boot fail.',
            'not_applicable_when': 'The native OS type is Linux. Missing or contradictory OS facts and unrecognized security capabilities remain UNKNOWN.',
        }),
}

SUCCESSORS.update({('azure.claude.synapse_workspace_vulnerability_assessment', 'description'): ('890923904940f7b19c01a051f791545d8fc219b6f1a3359f766507722803a11e',
                                                                              {'description': 'Checks the '
                                                                                              'workspace SQL '
                                                                                              'server '
                                                                                              'vulnerability-assessment '
                                                                                              'policy for '
                                                                                              'recurring '
                                                                                              'scans. SQL '
                                                                                              'pool policies '
                                                                                              'and completed '
                                                                                              'scan results '
                                                                                              'are '
                                                                                              'separate.'}),
 ('azure.claude.synapse_workspace_vulnerability_assessment', 'remediation'): ('bc551f16621d4424f616438333db05a811f398f98aae9b75f372e19d3a7dcba5',
                                                                              {'references': [{'title': 'Synapse '
                                                                                                        'workspace '
                                                                                                        'SQL '
                                                                                                        'vulnerability '
                                                                                                        'assessments',
                                                                                               'url': 'https://learn.microsoft.com/en-us/rest/api/synapse/sqlserver/workspace-managed-sql-server-vulnerability-assessments/list?view=rest-synapse-sqlserver-2021-06-01'}]}),
 ('azure.claude.acr_vnet_service_endpoint', 'description'): ('169770c4496dd3c43d42dda8167ca24d441442609fad42bab469bfbb1bd7f2d5',
                                                             {'description': 'Checks for deny-by-default '
                                                                             'registry network rules with at '
                                                                             'least one VNet rule. Allowed '
                                                                             'IP ranges and public network '
                                                                             'access are evaluated '
                                                                             'separately.'}),
 ('azure.claude.acr_vnet_service_endpoint', 'remediation'): ('756f11e550b84de0bf0ece6063bb946bfe32a91ec146dfb5b50bc2ed1167a773',
                                                             {'caveats': ['A VNet rule with default Deny '
                                                                          'does not exclude public IP '
                                                                          'exceptions. Review allowed IP '
                                                                          'ranges and public network access '
                                                                          'separately.']}),
 ('azure.claude.vmss_not_empty', 'description'): ('57ff25c7d1ab14b8fe466dd3f8da0beb7dfe0f4146d9aba14c0d1cde1c0340e8',
                                                  {'description': 'Checks whether the scale set declares '
                                                                  'nonzero capacity in sku.capacity. This '
                                                                  'does not count running or healthy VM '
                                                                  'instances.'}),
 ('azure.claude.vmss_not_empty', 'remediation'): ('48461355a4267989344ed217acfbcf6279bd4764fd9769cc130920ebd7abaaff',
                                                  {'caveats': ['Declared capacity does not prove that '
                                                               'instances exist or are healthy. Zero '
                                                               'capacity may be intentional for an idle '
                                                               'scale set.']})})

SUCCESSORS.update({('azure.claude.managed_hsm_audit_logging', 'description'): ('49f46dd84b30845146d9deeffd24daaf6065aaec12799d0b7b673dde507d0bf2',
                                                             {'description': 'Checks declared HSM AuditEvent '
                                                                             'storage logging. Legacy '
                                                                             'diagnostic retention stopped '
                                                                             'applying in September 2025, so '
                                                                             'an archive declaration alone '
                                                                             'leaves this combined retention '
                                                                             'requirement unresolved.',
                                                              'pass_when': 'No current native PASS: legacy '
                                                                           'diagnostic retention fields do '
                                                                           'not establish current retention.',
                                                              'fail_when': 'No diagnostic setting declares '
                                                                           'enabled AuditEvent logging to a '
                                                                           'storage account destination.'}),
 ('azure.claude.managed_hsm_audit_logging', 'remediation'): ('d0b4af536fdb95f99cb659e496fce303112eaccede9b2f29577d6945dd540237',
                                                             {'caveats': ['Diagnostic-settings storage '
                                                                          'retention stopped applying in '
                                                                          'September 2025. Verify supported '
                                                                          'storage retention separately; '
                                                                          'legacy enabled/days fields cannot '
                                                                          'establish it.']}),
 ('azure.claude.recovery_vault_backup_retention_30_days', 'description'): ('3f7bac567933ad09efcc39c8a9cd8e71b47f11fd8136048c8ef6bb8310569a76',
                                                                           {'description': 'Checks each '
                                                                                           'daily backup '
                                                                                           'policy’s native '
                                                                                           'retention '
                                                                                           'duration and '
                                                                                           'unit '
                                                                                           'against 30 days. '
                                                                                           'One calendar '
                                                                                           'month is '
                                                                                           'unresolved; '
                                                                                           'missing or '
                                                                                           'invalid units '
                                                                                           'cannot pass.',
                                                                            'evaluated': ['backupPolicies[].properties.retentionPolicy.dailySchedule.retentionDuration.count',
                                                                                          'backupPolicies[].properties.retentionPolicy.dailySchedule.retentionDuration.durationType'],
                                                                            'not_applicable_when': 'Policies '
                                                                                                   'exist '
                                                                                                   'but none '
                                                                                                   'has a '
                                                                                                   'daily '
                                                                                                   'retention '
                                                                                                   'schedule. '
                                                                                                   'An empty '
                                                                                                   'policy '
                                                                                                   'inventory '
                                                                                                   'fails.'}),
 ('azure.claude.recovery_vault_backup_retention_30_days', 'remediation'): ('9260b41aa2b5eebfbb558973d82f564520990a253195f9706c3ffd06c05ce88a',
                                                                           {'caveats': ['No policies fails; '
                                                                                        'no daily schedule '
                                                                                        'is not applicable. '
                                                                                        'Units and positive '
                                                                                        'counts are '
                                                                                        'required; one '
                                                                                        'calendar month '
                                                                                        'alone does not '
                                                                                        'prove 30 days.']})})


# Exact network/database native-contract guidance successors.
SUCCESSORS.update({('azure.claude.aks_authorized_ip_ranges', 'description'): ('c9cd017090a4c45fc6bb348b51e93e75389c23cbd04d048169bc4b9c54fd33ab',
                                                            {'description': 'Checks public API authorized '
                                                                            'CIDRs for a restricted address '
                                                                            'union. Empty ranges or rules '
                                                                            'covering the Internet fail; '
                                                                            'malformed ranges remain '
                                                                            'unresolved. Azure’s special '
                                                                            'outbound-IP selector is '
                                                                            'preserved.',
                                                             'fail_when': 'Authorized ranges are empty or '
                                                                          'their union allows every source.',
                                                             'pass_when': 'The authorized IP ranges are '
                                                                          'valid and their union does not '
                                                                          'allow every source.'}),
 ('azure.claude.aks_authorized_ip_ranges', 'remediation'): ('ee6eba44efa71115a4e5a3bc65e031b4d7b21372b064c5a312b870db82e37161',
                                                            {'caveats': ['An authorized-range declaration '
                                                                         'does not prove packet '
                                                                         'reachability. A universal CIDR or '
                                                                         'combined address-space coverage is '
                                                                         'unrestricted.']}),
 ('azure.claude.sql_database_va_findings_resolved', 'description'): ('ccd14cdead74fca75f9d30908c3c64cfbc6ff727296b9ace0a1b25829b5d77e6',
                                                                     {'description': 'Checks the latest '
                                                                                     'completed database '
                                                                                     'vulnerability scan’s '
                                                                                     'failed-check count. '
                                                                                     'Execution errors, '
                                                                                     'missing completion '
                                                                                     'state or contradictory '
                                                                                     'counts remain '
                                                                                     'unresolved; an '
                                                                                     'unexecuted scan with '
                                                                                     'zero findings cannot '
                                                                                     'pass.',
                                                                      'fail_when': 'The latest scan '
                                                                                   'completed with Failed '
                                                                                   'state and a positive '
                                                                                   'failed-check count.',
                                                                      'pass_when': 'The latest scan '
                                                                                   'completed with Passed '
                                                                                   'state and zero failed '
                                                                                   'security checks.'}),
 ('azure.claude.sql_database_va_findings_resolved', 'remediation'): ('9142656558665bc866a845e5b26387497b2dc047cbd0d0343d719cda61ba0656',
                                                                     {'caveats': ['Only a completed scan '
                                                                                  'with consistent status '
                                                                                  'and counts is decisive. A '
                                                                                  'failed execution or '
                                                                                  'zero-count placeholder is '
                                                                                  'not a clean '
                                                                                  'assessment.']}),
 ('azure.claude2.app_gateway_min_tls_12', 'description'): ('1fbc19f3715b19226212f898cee003f57a610076ac0cc17c8aac256c93c096cf',
                                                           {'description': 'Resolves the explicit TLS '
                                                                           'minimum or recognized predefined '
                                                                           'policy. If no explicit policy '
                                                                           'exists, uses the returned '
                                                                           'default policy name; missing or '
                                                                           'unknown defaults remain '
                                                                           'unresolved.',
                                                            'fail_when': 'The explicit or native reported '
                                                                         'default policy permits TLS1.0 or '
                                                                         'TLS1.1.',
                                                            'pass_when': 'The explicit or native reported '
                                                                         'default policy requires TLS1.2 or '
                                                                         'newer.'}),
 ('azure.claude2.app_gateway_min_tls_12', 'remediation'): ('87abdaca185adf42e257b2d0cc128d75f93da324f6e58c6e7c17267289555529',
                                                           {'caveats': ['An omitted explicit policy is not '
                                                                        'enough: the native default policy '
                                                                        'must be known. No TLS handshake was '
                                                                        'performed.']}),
 ('azure.claude2.app_gateway_waf_enabled', 'description'): ('3533f870824f07a294b2985d669bdd71b6e2a9a94ee7730dfd48281657c18f1f',
                                                            {'description': 'Checks enabled inline WAF '
                                                                            'configuration or resolves the '
                                                                            'gateway’s attached WAF policy '
                                                                            'and its enabled state. A policy '
                                                                            'reference alone is '
                                                                            'insufficient; missing or '
                                                                            'ambiguous policy evidence '
                                                                            'remains unresolved.',
                                                             'fail_when': 'Complete native configuration has '
                                                                          'no WAF declaration or the '
                                                                          'resolved protection is disabled.',
                                                             'pass_when': 'Inline WAF is enabled or the '
                                                                          'exact attached policy resolves to '
                                                                          'an enabled native policy.'}),
 ('azure.claude2.app_gateway_waf_enabled', 'remediation'): ('d1e9a82379bcac1835f3d3c38b52ab4180d26a602d6725ee1ade253f82f5b399',
                                                            {'caveats': ['Enabled configuration does not '
                                                                         'establish listener coverage or '
                                                                         'effective request blocking. '
                                                                         'Missing or ambiguous '
                                                                         'attached-policy evidence remains '
                                                                         'unresolved.']}),
 ('azure.claude2.nsg_flow_logs_to_log_analytics', 'description'): ('249cff85022ea977ba9f8e2a1493f576bbc7ba26d1d647ff4a0861f5f3fbcda2',
                                                                   {'description': 'Checks for enabled NSG '
                                                                                   'or VNet flow logging '
                                                                                   'with Traffic Analytics '
                                                                                   'enabled and a workspace '
                                                                                   'reference. Each target '
                                                                                   'must resolve in the '
                                                                                   'selected subscription’s '
                                                                                   'network inventory.',
                                                                    'fail_when': 'Complete applicable '
                                                                                 'network and flow '
                                                                                 'inventories contain no '
                                                                                 'such enabled '
                                                                                 'configuration.',
                                                                    'pass_when': 'An enabled matching flow '
                                                                                 'log has enabled Traffic '
                                                                                 'Analytics and a workspace '
                                                                                 'reference.'}),
 ('azure.claude2.nsg_flow_logs_to_log_analytics', 'remediation'): ('bb2e759c2b72e0dbf28390a913b8b1b132b7470eaec1f593470c095e00ecdd37',
                                                                   {'caveats': ['A workspace reference alone '
                                                                                'is insufficient. Both '
                                                                                'collection flags must be '
                                                                                'enabled; configuration does '
                                                                                'not prove log ingestion or '
                                                                                'delivery.']}),
 ('azure.claude2.vnet_flow_logs_to_log_analytics', 'description'): ('249cff85022ea977ba9f8e2a1493f576bbc7ba26d1d647ff4a0861f5f3fbcda2',
                                                                    {'description': 'Checks for enabled VNet '
                                                                                    'flow logging with '
                                                                                    'Traffic Analytics '
                                                                                    'enabled and a workspace '
                                                                                    'reference. Each target '
                                                                                    'must resolve in the '
                                                                                    'selected subscription’s '
                                                                                    'network inventory.',
                                                                     'fail_when': 'Complete applicable '
                                                                                  'network and flow '
                                                                                  'inventories contain no '
                                                                                  'such enabled '
                                                                                  'configuration.',
                                                                     'pass_when': 'An enabled matching VNet '
                                                                                  'flow log has enabled '
                                                                                  'Traffic Analytics and a '
                                                                                  'workspace reference.'}),
 ('azure.claude2.vnet_flow_logs_to_log_analytics', 'remediation'): ('bb2e759c2b72e0dbf28390a913b8b1b132b7470eaec1f593470c095e00ecdd37',
                                                                    {'caveats': ['A workspace reference '
                                                                                 'alone is insufficient. '
                                                                                 'Both collection flags must '
                                                                                 'be enabled; configuration '
                                                                                 'does not prove log '
                                                                                 'ingestion or delivery.']})})

SUCCESSORS.update({
('azure.claude.iam_custom_role_administers_locks', 'description'): ('13c4c5562fc1200721bb84c3a2216c75c69593a8a465d5874b5a628787e4af53', {'description': 'Checks whether a custom role in the selected assignable scope declares both resource-lock write and delete, combining permission blocks after subtracting each block’s NotActions. This does not establish any user’s effective access.', 'pass_when': 'A native custom role declares both lock write and delete after its exclusions.', 'fail_when': 'Complete native role definitions contain no such custom role.'}),
('azure.claude.iam_custom_role_administers_locks', 'remediation'): ('6fc599b68c2fa61e5dd4efb1df266a6e9f8fe0128eea663a6e9b2ddd4cb395d5', {'steps': ['Use a dedicated custom role with the required resource-lock write and delete operations.', 'Review its assignments and exclusions before granting access.'], 'caveats': ['Read-only lock permissions do not administer locks. Role definitions alone do not establish role assignments or effective access; the pinned upstream literal-prefix interpretation is retained historically.']}),
})

SUCCESSORS.update({
('azure_application_gateway_app_http_logs_enabled_2de0361', 'description'): ('fcc1f9d4c57e1d38d37dd6fb09d4c8167f8745f8780488cf4fb1c5da1a54bfc8', {'description': 'Checks whether Application Gateway declares enabled HTTP access-log export to an inventoried workspace or storage account. Layer4 Load Balancer health logs are a separate criterion.', 'pass_when': 'Applicable gateways declare enabled ApplicationGatewayAccessLog export to an inventoried destination.', 'fail_when': 'At least one applicable gateway lacks that configured access-log export.', 'not_applicable_when': 'Complete selected inventories contain no Application Gateway.'}),
('azure_application_gateway_app_http_logs_enabled_2de0361', 'remediation'): ('267e193f3c508358e6b3b47486c80ed6f6fa107c31116df4f8a2b83ad26e995b', {'summary': 'Enable the gateway HTTP access-log category for the intended diagnostic destination.', 'steps': ['Enable ApplicationGatewayAccessLog for the intended workspace or storage account.', 'Verify that gateway logs arrive at that destination.'], 'caveats': ['This checks declared export configuration, not log delivery, destination permissions or retention. Layer4 Load Balancer health events do not constitute HTTP access logs.'], 'field_binding': {'kind': 'application_gateway', 'target': 'scope', 'fields': ['Native Application Gateway inventory', 'Diagnostic categories and settings bound to each exact gateway', 'Enabled ApplicationGatewayAccessLog and inventoried workspace/storage destination']}}),
('azure_application_gateway_11_5_1_1_1_f56bdc2', 'description'): ('b5ad657303a2b578a2bcccbc8422e20a9eda7c325bcfce910132a88176ae9afe', {'description': 'Checks declared DDoS protection for public IPs and applicable Prevention-mode WAF configuration. Native associations include gateway listener/path overrides and Front Door policy bindings; unresolved routes remain unknown.'}),
('azure_application_gateway_11_5_1_1_1_f56bdc2', 'remediation'): ('319617d8a9a572f8138b4bcccfb77a533d29072177fed8a99b830e8b88bd5338', {'summary': 'Configure the missing DDoS protection or applicable Prevention-mode WAF declaration.', 'steps': ['Enable the missing DDoS protection for the named public IP or its associated virtual network.', 'For the affected public gateway or Front Door endpoint, configure the intended WAF policy in Prevention mode.'], 'caveats': ['Native configured protection is assessed; traffic blocking and mitigation efficacy were not tested. Unsupported dynamic route or rewrite associations remain unresolved.']}),
})

def reviewed_fields(check_id, kind, predecessor):
    successor = SUCCESSORS.get((check_id, kind))
    if successor is None:
        return deepcopy(predecessor)
    expected, changes = successor
    digest = hashlib.sha256(json.dumps(predecessor, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    if digest != expected:
        raise ValueError('Reviewed Azure native guidance predecessor changed: ' + check_id)
    return {**deepcopy(predecessor), **deepcopy(changes)}
