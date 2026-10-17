"""Signed Azure wave 2 predicates; all evaluation is offline and read-only.

Supplemental azure_sw18_evidence rows are explicitly scoped, source-bound
measurements, not assignment-level compliance flags. Their complete schema
and required API/source reads are specified in sw18-collector-requests.md.
"""
from __future__ import annotations

import re
import json
from dataclasses import replace
from datetime import datetime

from . import CHECKS, register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects

EVIDENCE_KIND = "azure_sw18_evidence"
META = {'azure.cis.multifactor_auth_status_non_privileged_users': {'category': 'least_privilege',
                                                            'data_source': 'Paged Graph users, directory '
                                                                           'role assignments/definitions and '
                                                                           'group transitiveMembers identify '
                                                                           'enabled non-privileged users. '
                                                                           'GET Graph beta '
                                                                           '/users/{id}/authentication/requirements '
                                                                           'supplies perUserMfaState enum '
                                                                           'disabled/enabled/enforced. Also '
                                                                           'collect registration details, '
                                                                           'Conditional Access policies and '
                                                                           'named locations if evaluating '
                                                                           'equivalent effective MFA '
                                                                           'enforcement; resolve every '
                                                                           'condition and exclusion.',
                                                            'description': 'Require usable MFA for '
                                                                           'non-privileged users. A finding '
                                                                           'is raised when an enabled '
                                                                           'non-privileged user is not '
                                                                           'covered by an effective enabled '
                                                                           'MFA policy or '
                                                                           'isMfaCapable=false.',
                                                            'id': 'azure.cis.multifactor_auth_status_non_privileged_users',
                                                            'predicate': 'For each enabled non-privileged '
                                                                         'user, PASS only when '
                                                                         'perUserMfaState is enabled or '
                                                                         'enforced and usable MFA '
                                                                         'registration is present; or when a '
                                                                         'separately approved equivalence '
                                                                         'policy and fully resolved '
                                                                         'Conditional Access evidence prove '
                                                                         'MFA on every applicable sign-in '
                                                                         'path. FAIL when a fully measured '
                                                                         'user has disabled per-user MFA and '
                                                                         'a known unprotected sign-in path, '
                                                                         'or is unable to use required MFA. '
                                                                         'UNKNOWN when per-user state, '
                                                                         'registration, equivalence policy, '
                                                                         'role/group scope, CA conditions or '
                                                                         'pages are unresolved. MFA '
                                                                         'capability or broad CA policy '
                                                                         'presence alone cannot PASS the '
                                                                         'frozen status requirement.',
                                                            'proposed_spec_sha256': '16d8f33a65637ff304e0bb3c98228542712c3ff963be219a259bb289a558f6a7',
                                                            'provider': 'azure',
                                                            'remediation_hint': 'Entra admin center > '
                                                                                'Protection > Conditional '
                                                                                'Access: apply MFA or '
                                                                                'approved authentication '
                                                                                'strength to the affected '
                                                                                'users and sign-in paths; '
                                                                                'register an allowed strong '
                                                                                'method.',
                                                            'resource_kind': 'directory_user',
                                                            'severity': 'high',
                                                            'title': 'Require usable MFA for non-privileged '
                                                                     'users'},
 'azure.gap.network_security_group_rdp_access_restricted': {'category': 'hardening',
                                                            'data_source': 'Existing azure.py Windows '
                                                                           'vm.items[]; new Guest '
                                                                           'Configuration assignment reports '
                                                                           '2022-01-25 with exact '
                                                                           'organization User Rights '
                                                                           'Assignment baseline ID, '
                                                                           'parameter set, complianceStatus '
                                                                           'and latest report ID. Resolve '
                                                                           'effective assignment parameter '
                                                                           'values and report VM/assignment '
                                                                           'identity; a generic Compliant '
                                                                           'summary from another parameter '
                                                                           'set cannot prove this policy.',
                                                            'description': 'Checks Windows guest policy '
                                                                           'assignment compliance. Network '
                                                                           'security group rules do not '
                                                                           'provide User Rights Assignment '
                                                                           'evidence.',
                                                            'id': 'azure.gap.network_security_group_rdp_access_restricted',
                                                            'predicate': 'For each Windows VM, PASS only '
                                                                         'when a fresh report for the exact '
                                                                         'baseline, version and approved '
                                                                         'User Rights Assignment parameter '
                                                                         'set is Compliant; FAIL when that '
                                                                         'report is NonCompliant; UNKNOWN '
                                                                         'when assignment, baseline version '
                                                                         'or parameters, report, status or '
                                                                         'VM inventory is unavailable. No '
                                                                         'Windows VMs is not applicable.',
                                                            'proposed_spec_sha256': '9d9b5d50de6801be67cea9c3052883e0722b8e4e29b51721dda4941dc5ec8608',
                                                            'provider': 'azure',
                                                            'remediation_hint': 'Assign the approved Windows '
                                                                                'User Rights Assignment '
                                                                                'guest baseline in Azure '
                                                                                'Policy, inspect the latest '
                                                                                'report, and correct '
                                                                                'reported user rights.',
                                                            'resource_kind': 'vm',
                                                            'severity': 'medium',
                                                            'title': 'Windows VM User Rights Assignment '
                                                                     'baseline is compliant'},
 'azure.other.azure_role_review': {'category': 'least_privilege',
                                   'data_source': 'Paged ARM role assignments/definitions at all relevant '
                                                  'scopes with inherited assignments; Graph v1.0 paged '
                                                  'access review definitions, instances and per-instance '
                                                  'decisions, transitive groups/PIM, and policy '
                                                  'reviewMaxAgeDays and privileged-role set.',
                                   'description': 'Review privileged Azure RBAC assignments. A finding is '
                                                  'raised when a privileged Azure RBAC assignment lacks a '
                                                  'covering recurring review or a completed instance within '
                                                  'reviewMaxAgeDays.',
                                   'id': 'azure.other.azure_role_review',
                                   'predicate': 'For each effective privileged Azure RBAC '
                                                'principal/role/scope tuple, PASS only if a recurring review '
                                                'covers the exact tuple and a completed instance within '
                                                'reviewMaxAgeDays has an applied decision for that '
                                                'principal. FAIL only if complete assignment, review and '
                                                'decision inventories prove uncovered or overdue. UNKNOWN '
                                                'for policy, inheritance, group/PIM, scope-query '
                                                'interpretation, decision application, time window or '
                                                'pagination.',
                                   'proposed_spec_sha256': 'ea4e950d718ed402a7d1ac7c543d4a4ac19090694b083f1ea42a723160465d89',
                                   'provider': 'azure',
                                   'remediation_hint': 'Azure portal > Identity Governance > Access reviews: '
                                                       'schedule recurring reviews for privileged Azure RBAC '
                                                       'assignments and complete/apply decisions for each '
                                                       'assignee.',
                                   'resource_kind': 'role_assignment',
                                   'severity': 'high',
                                   'title': 'Review privileged Azure RBAC assignments'},
 'azure.other.clock_sync': {'category': 'hardening',
                            'data_source': 'azure.py VM guestConfigurationAssignments child LIST 2024-04-05: '
                                           'properties.complianceStatus and '
                                           'properties.guestConfiguration.name; add GET assignment reports '
                                           'using properties.latestReportId for current evidence. Policy '
                                           'approvedTimeSyncAssignmentNames.; GET '
                                           '/guestConfigurationAssignments/{name}/reports/{latestReportId} '
                                           'properties.endTime,complianceStatus,details; approved source IDs '
                                           'and maximum report age',
                            'description': "Uses a named Guest Configuration assignment to assess each VM's "
                                           'time source.',
                            'id': 'azure.other.clock_sync',
                            'predicate': 'For each scoped VM, PASS only if an approved time-sync assignment '
                                         'has a recent report whose detailed result measures the actual '
                                         'source and synchronization state, shows that source is approved, '
                                         'and is Compliant. FAIL for a current report proving drift or '
                                         'unapproved source. UNKNOWN if assignment is absent, report is '
                                         'stale/unreadable, source identity is missing, or policy inputs are '
                                         'unresolved.',
                            'proposed_spec_sha256': '5b40d1078c91a115e69a287a0ea7ebb6b1d3b02d9f827312d94cd719d37c6c08',
                            'provider': 'azure',
                            'remediation_hint': 'Assign a Guest Configuration time-source policy that '
                                                'reports the actual source and synchronization state, point '
                                                'the VM to an approved reference, and rerun assessment.',
                            'resource_kind': 'vm',
                            'severity': 'medium',
                            'title': 'VM guest time synchronization complies with approved policy'},
 'azure.other.credential_creation_role_scope': {'category': 'least_privilege',
                                                'data_source': 'Paged ARM roleAssignments, roleDefinitions '
                                                               'and denyAssignments 2022-04-01 at all '
                                                               'inherited scopes: principalId, '
                                                               'roleDefinitionId, scope, condition, '
                                                               'permissions '
                                                               'actions/dataActions/notActions/notDataActions. '
                                                               'Resolve transitive Graph groups, approved '
                                                               'administrator principals, and '
                                                               'credential/token issuance actions including '
                                                               'service-specific data-plane grants.',
                                                'description': 'Restrict credential creation permissions. A '
                                                               'finding is raised when a definitely '
                                                               'effective role assignment grants a '
                                                               'credential-creation action to a principal '
                                                               'outside approvedCredentialAdmins.',
                                                'id': 'azure.other.credential_creation_role_scope',
                                                'predicate': 'For each nonadministrative effective '
                                                             'principal, FAIL if a credential or '
                                                             'temporary-token creation action is '
                                                             'demonstrably allowed or an authorized negative '
                                                             'test succeeds. PASS only if complete '
                                                             'effective-access expansion and denied test '
                                                             'evidence establish denial across the approved '
                                                             'action inventory. UNKNOWN on incomplete action '
                                                             'inventory, group membership, condition, deny, '
                                                             'data-plane or test evidence.',
                                                'proposed_spec_sha256': '5037d68bf36db8cd02cda1aa53beeff0c853af409307d3a3a64660781e40cef1',
                                                'provider': 'azure',
                                                'remediation_hint': 'Azure portal > Subscriptions > Access '
                                                                    'control (IAM): Remove '
                                                                    'credential-creation permissions from '
                                                                    'unapproved principals and use scoped '
                                                                    'roles.',
                                                'resource_kind': 'role_assignment',
                                                'severity': 'high',
                                                'title': 'Restrict credential creation permissions'},
 'azure.other.database_backup_role_scope': {'category': 'recovery',
                                            'data_source': 'Paged ARM roleAssignments, roleDefinitions and '
                                                           'denyAssignments at each database and inherited '
                                                           'scope (2022-04-01): properties.principalId, '
                                                           'roleDefinitionId, scope, condition; '
                                                           'roleDefinition.properties.permissions[].actions/notActions/dataActions/notDataActions. '
                                                           'Resolve transitive Graph group membership and '
                                                           'approvedBackupPrincipalIds; use an authorized '
                                                           'negative backup/restore attempt if the '
                                                           'requirement is evaluated literally.',
                                            'description': 'Reviews effective backup and restore permissions '
                                                           'for in-scope Azure database resources.',
                                            'id': 'azure.other.database_backup_role_scope',
                                            'predicate': 'FAIL when an unapproved principal is proven able '
                                                         'to execute a backup or restore action or its '
                                                         'authorized test succeeds. PASS only when complete '
                                                         'effective-permission expansion and representative '
                                                         'denied attempts establish that every unapproved '
                                                         'tested identity is denied; UNKNOWN when the '
                                                         'identity universe, conditions, deny assignments, '
                                                         'dynamic group membership, action mapping or test '
                                                         'coverage is incomplete. No databases is '
                                                         'NOT_APPLICABLE.',
                                            'proposed_spec_sha256': '54511c636848c0b02b85e63208b255e0fb78bd5e7d10905e514a353ff6589a74',
                                            'provider': 'azure',
                                            'remediation_hint': 'In Access control (IAM) for the '
                                                                'database/server/subscription, remove '
                                                                'unapproved backup or restore grants or '
                                                                'narrow their scope and role definition.',
                                            'resource_kind': 'role_assignment',
                                            'severity': 'high',
                                            'title': 'Database backup roles are scoped'},
 'azure.other.sshv2_guest_configuration': {'category': 'hardening',
                                           'data_source': 'Per exposed Linux VM: paged Guest Configuration '
                                                          'assignment LIST/GET 2024-04-05, '
                                                          'properties.latestReportId, then GET '
                                                          '{assignmentId}/reports/{latestReportId} and '
                                                          'inspect properties.details.resources[] and '
                                                          'reasons; approved SSHv2 assignment definition and '
                                                          'report freshness policy; complete exposure '
                                                          'inventory.',
                                           'description': 'Require SSH protocol 2 on exposed Linux VMs. A '
                                                          'finding is raised when the current named SSHv2 '
                                                          'baseline reports NonCompliant.',
                                           'id': 'azure.other.sshv2_guest_configuration',
                                           'predicate': 'For each exposed Linux VM, PASS only if the exact '
                                                        'approved SSHv2 assignment has a current completed '
                                                        'report whose specific Protocol setting shows SSHv2 '
                                                        'or higher and no SSHv1. FAIL only when the current '
                                                        'report explicitly proves SSHv1 is allowed. UNKNOWN '
                                                        'for missing assignment/report, stale report, '
                                                        'ambiguous details, exposure, or incomplete paging. '
                                                        'An assignment-level Compliant flag alone is '
                                                        'insufficient.',
                                           'proposed_spec_sha256': '06c1a517fa3e969e449c8c3eff06c19be44d4d82ee9a7b547c1ce68627b6ffe6',
                                           'provider': 'azure',
                                           'remediation_hint': 'Set sshd_config to Protocol 2 where '
                                                               'applicable, restart sshd, then rerun the '
                                                               'assigned Machine Configuration baseline and '
                                                               'confirm a current Compliant report.',
                                           'resource_kind': 'vm',
                                           'severity': 'high',
                                           'title': 'Require SSH protocol 2 on exposed Linux VMs'},
 'azure_c5_am_04_01b': {'category': 'hardening',
                        'data_source': 'Paged Azure VM inventory and per-VM '
                                       'Microsoft.Security/softwareInventories ListByExtendedResource '
                                       '2021-05-01-preview; item.id embeds the exact VM ARM ID and '
                                       'properties.softwareName,version,deviceId are strings. Policy defines '
                                       'covered VMs, required inventory fields and maximum age; confirm '
                                       'Defender software-inventory coverage for every VM.',
                        'description': 'Checks identified installed software, versions and host linkage '
                                       'against the approved C5 inventory scope.',
                        'id': 'azure_c5_am_04_01b',
                        'predicate': 'For each in-scope VM, PASS only if an authoritative, current, complete '
                                     'guest software inventory lists every installed software asset with '
                                     'identity and version and joins each record to the exact VM; FAIL only '
                                     'for a proven missing required asset or required inventory field. '
                                     'UNKNOWN where guest inventory, completeness, age, VM join or policy is '
                                     'unmeasured. Endpoint-protection Healthy does not establish this C5 '
                                     'requirement.',
                        'proposed_spec_sha256': '3934f1625c2681d2b2a94eb0e2bdaa242963be62587dd30543ed8145f6cb4cc5',
                        'provider': 'azure',
                        'remediation_hint': 'Enable a complete guest software inventory for every in-scope '
                                            'VM; record each product, version and hosting VM and reconcile '
                                            'it with the asset register.',
                        'resource_kind': 'vm',
                        'severity': 'medium',
                        'title': 'C5 software asset inventory is complete for Azure VMs'},
 'azure_c5_ops_30_01ac': {'category': 'hardening',
                          'data_source': 'azure.py VM ARM LIST/GET 2023-09-01: id string, '
                                         'properties.securityProfile.securityType enum ConfidentialVM, '
                                         'properties.securityProfile.uefiSettings.vTpmEnabled boolean; '
                                         'classification comes from explicit confidentialVmIds policy, not '
                                         'an unverified tag.',
                          'description': 'Partial technical signal for C5 confidential computing: classified '
                                         'confidential VMs use ConfidentialVM and vTPM. Full C5 requires '
                                         'separate provider concept, attestation, monitoring and review '
                                         'evidence.',
                          'id': 'azure_c5_ops_30_01ac',
                          'predicate': 'For each VM in policy confidentialVmIds, FAIL for a fully read '
                                       'explicit non-ConfidentialVM securityType or false vTpmEnabled. Mark '
                                       'the VM technical signal PRESENT when ConfidentialVM and '
                                       'vTpmEnabled=true. Overall C5 OPS-30.01AC remains UNKNOWN until '
                                       'documentation of interfaces, TEE/key management, attestation, '
                                       'monitoring and dated annual/event-driven security reviews is '
                                       'verified; missing VM classification/profile is UNKNOWN.',
                          'proposed_spec_sha256': 'e72ee6c82fd9a51aa8fd4d716d9b21a5bc694bffe11579f8da512053eb8f46c7',
                          'provider': 'azure',
                          'remediation_hint': 'Enable Confidential VM security type and vTPM on classified '
                                              'VMs, and collect the C5 concept, interface, attestation, '
                                              'monitoring and review records needed for full assessment.',
                          'resource_kind': 'vm',
                          'severity': 'high',
                          'title': 'Classified confidential VMs enable vTPM'},
 'azure_c5_ops_33_03b': {'category': 'hardening',
                         'data_source': 'Paged Microsoft.Compute/virtualMachines GET 2023-09-01: id, '
                                        'properties.storageProfile.osDisk.osType and '
                                        'properties.osProfile.windowsConfiguration.patchSettings.patchMode. '
                                        'Dated third-party patch identification/test/deployment records and '
                                        'customer approval/update-rollout records for the mapped C5 '
                                        'requirements.',
                         'description': 'Checks automatic Windows patch orchestration on Azure virtual '
                                        'machines.',
                         'id': 'azure_c5_ops_33_03b',
                         'predicate': 'For each Windows VM, AutomaticByOS or AutomaticByPlatform proves only '
                                      'automatic patch configuration; Manual disproves that technical '
                                      'subcondition. An absent or unrecognized mode, OS type, or incomplete '
                                      'inventory yields UNKNOWN. For the mapped C5 requirements, PASS only '
                                      'if the applicable third-party patch identification, testing, '
                                      'deployment, customer approval and provider rollout records are also '
                                      'complete and satisfactory. FAIL when complete evidence proves a '
                                      'required obligation unmet. Otherwise UNKNOWN, including a VM with '
                                      'automatic patch mode but no process records. Linux VMs are '
                                      'NOT_APPLICABLE to the Windows configuration aspect.',
                         'proposed_spec_sha256': '2dc74608896ab02fce04c3909e33f36593ce72d2196cccf86a5da615d8737cdc',
                         'provider': 'azure',
                         'remediation_hint': 'In Virtual machine > Updates > Update settings, set patch '
                                             'orchestration to Azure orchestrated (AutomaticByPlatform) or '
                                             'OS orchestrated (AutomaticByOS).',
                         'resource_kind': 'vm',
                         'severity': 'medium',
                         'title': 'Windows VMs use an automatic patch mode'},
 'azure_management_group_7_2_1_12_3f8ec01': {'category': 'hardening',
                                             'data_source': 'ARM Microsoft.Authorization/roleAssignments '
                                                            'ListForScope 2022-04-01 with atScope() and '
                                                            'paging; compare each role-assignment '
                                                            'properties.roleDefinitionId ARM resource ID '
                                                            '(and properties.principalId, properties.scope) '
                                                            'to policy prohibitedRoleDefinitionIds. '
                                                            'Enumerate protected management-group and '
                                                            'subscription scopes.',
                                             'description': 'Checks direct and inherited RBAC assignments '
                                                            'for organization-prohibited role definitions.',
                                             'id': 'azure_management_group_7_2_1_12_3f8ec01',
                                             'predicate': 'For each protected scope, compare normalized '
                                                          'role-definition ARM IDs or their GUID segments '
                                                          'from direct and inherited role assignments in '
                                                          'properties.roleDefinitionId. FAIL on a prohibited '
                                                          'grant to any principal type; PASS after complete '
                                                          'scope enumeration and atScope() pagination prove '
                                                          'none; UNKNOWN for policy, inheritance or paging '
                                                          'gaps. Assignment fields are under properties.',
                                             'proposed_spec_sha256': '992b9961a5831bc9822b5f862a552a3dba2a89c00caa54d8185ca4ffddb0309b',
                                             'provider': 'azure',
                                             'remediation_hint': 'Azure portal > Management groups > Access '
                                                                 'control (IAM): Remove prohibited role '
                                                                 'assignments or replace them with approved '
                                                                 'least-privilege roles.',
                                             'resource_kind': 'role_assignment',
                                             'severity': 'medium',
                                             'title': 'Prohibited RBAC roles are not assigned at selected '
                                                      'scopes'},
 'azure_management_group_7_2_1_13_50babe4': {'category': 'hardening',
                                             'data_source': 'Paged ARM role assignments ListForScope '
                                                            '2022-04-01 at subscriptions and all '
                                                            'management-group ancestors, with role '
                                                            'definitions; read properties.roleDefinitionId, '
                                                            'principalId, principalType and scope. Resolve '
                                                            'each principal ID against Graph users, groups '
                                                            'or service principals and expand groups if '
                                                            'approvals are person-based. Policy supplies '
                                                            'required role/scope assignments and authorized '
                                                            'principals.',
                                             'description': 'Compares selected role assignments, including '
                                                            'inherited assignments, with role- and '
                                                            'scope-specific approved principals.',
                                             'id': 'azure_management_group_7_2_1_13_50babe4',
                                             'predicate': 'For every policy-required role and '
                                                          'subscription/management-group scope, PASS only if '
                                                          'at least one effective assignment exists to an '
                                                          'authorized, currently resolvable user, group or '
                                                          'service principal, and every selected-role '
                                                          'assignment at that scope is authorized for its '
                                                          'exact roleDefinitionId and inherited scope. FAIL '
                                                          'for a fully resolved missing required assignment, '
                                                          'unauthorized assignment, or deleted/nonconforming '
                                                          'principal. UNKNOWN if required role/scope policy, '
                                                          'ancestor pages, role definitions, principal '
                                                          'lookup, group expansion or assignment fields are '
                                                          'incomplete. An empty assignment set never '
                                                          'vacuously PASSes a required assignment.',
                                             'proposed_spec_sha256': '4bcc44c51db71494cdd3394e39f24274f8b80f07e52bbe66278bae8a4bc88335',
                                             'provider': 'azure',
                                             'remediation_hint': 'Azure portal > Access control (IAM) > Role '
                                                                 'assignments: remove the unauthorized '
                                                                 'assignment at its actual scope and grant '
                                                                 'the selected role only to an approved '
                                                                 'principal.',
                                             'resource_kind': 'role_assignment',
                                             'severity': 'medium',
                                             'title': 'Selected Azure RBAC assignments use approved '
                                                      'principals'},
 'azure_role_assignment_iam_user_with_owner_permission_on_subscription_mfa_enabled_8bf88f9': {'category': 'least_privilege',
                                                                                              'data_source': 'Paged '
                                                                                                             'ARM '
                                                                                                             'role '
                                                                                                             'assignments '
                                                                                                             'and '
                                                                                                             'definitions '
                                                                                                             'at '
                                                                                                             'subscription '
                                                                                                             'and '
                                                                                                             'ancestor '
                                                                                                             'scopes, '
                                                                                                             'active '
                                                                                                             'PIM '
                                                                                                             'assignments, '
                                                                                                             'Graph '
                                                                                                             'users/groups '
                                                                                                             'and '
                                                                                                             'transitive '
                                                                                                             'membership, '
                                                                                                             'and '
                                                                                                             'paged '
                                                                                                             'Conditional '
                                                                                                             'Access '
                                                                                                             'policies '
                                                                                                             'including '
                                                                                                             'users/apps/client '
                                                                                                             'and '
                                                                                                             'location/device/platform/risk '
                                                                                                             'conditions, '
                                                                                                             'exclusions, '
                                                                                                             'grant '
                                                                                                             'controls '
                                                                                                             'and '
                                                                                                             'authentication '
                                                                                                             'strengths.',
                                                                                              'description': 'Checks '
                                                                                                             'MFA '
                                                                                                             'Conditional '
                                                                                                             'Access '
                                                                                                             'coverage '
                                                                                                             'for '
                                                                                                             'direct '
                                                                                                             'and '
                                                                                                             'inherited '
                                                                                                             'subscription '
                                                                                                             'Owner '
                                                                                                             'users.',
                                                                                              'id': 'azure_role_assignment_iam_user_with_owner_permission_on_subscription_mfa_enabled_8bf88f9',
                                                                                              'predicate': 'For '
                                                                                                           'each '
                                                                                                           'enabled '
                                                                                                           'human '
                                                                                                           'user '
                                                                                                           'with '
                                                                                                           'effective '
                                                                                                           'subscription '
                                                                                                           'Owner '
                                                                                                           'permission, '
                                                                                                           'PASS '
                                                                                                           'only '
                                                                                                           'if '
                                                                                                           'all '
                                                                                                           'relevant '
                                                                                                           'Azure-management '
                                                                                                           'sign-in '
                                                                                                           'paths '
                                                                                                           'are '
                                                                                                           'covered '
                                                                                                           'by '
                                                                                                           'effective '
                                                                                                           'MFA '
                                                                                                           'or '
                                                                                                           'an '
                                                                                                           'approved '
                                                                                                           'authentication '
                                                                                                           'strength '
                                                                                                           'after '
                                                                                                           'resolving '
                                                                                                           'direct/inherited/group/PIM '
                                                                                                           'assignments '
                                                                                                           'and '
                                                                                                           'every '
                                                                                                           'CA '
                                                                                                           'condition, '
                                                                                                           'exclusion '
                                                                                                           'and '
                                                                                                           'grant '
                                                                                                           'operator. '
                                                                                                           'FAIL '
                                                                                                           'on '
                                                                                                           'a '
                                                                                                           'proven '
                                                                                                           'uncovered '
                                                                                                           'path; '
                                                                                                           'UNKNOWN '
                                                                                                           'on '
                                                                                                           'incomplete '
                                                                                                           'membership, '
                                                                                                           'role '
                                                                                                           'definitions, '
                                                                                                           'PIM, '
                                                                                                           'CA '
                                                                                                           'conditions '
                                                                                                           'or '
                                                                                                           'policy '
                                                                                                           'pages. '
                                                                                                           'No '
                                                                                                           'applicable '
                                                                                                           'owners '
                                                                                                           'is '
                                                                                                           'NOT_APPLICABLE.',
                                                                                              'proposed_spec_sha256': '0720d7ab43c56f6de10ed9596d4afee862eb5e0a6636ed9b503bd9a4913bfada',
                                                                                              'provider': 'azure',
                                                                                              'remediation_hint': 'In '
                                                                                                                  'Entra '
                                                                                                                  'admin '
                                                                                                                  'center '
                                                                                                                  '> '
                                                                                                                  'Conditional '
                                                                                                                  'Access, '
                                                                                                                  'require '
                                                                                                                  'MFA '
                                                                                                                  'for '
                                                                                                                  'all '
                                                                                                                  'effective '
                                                                                                                  'subscription '
                                                                                                                  'Owner '
                                                                                                                  'users '
                                                                                                                  'on '
                                                                                                                  'Azure '
                                                                                                                  'management '
                                                                                                                  'apps '
                                                                                                                  'and '
                                                                                                                  'remove '
                                                                                                                  'bypassing '
                                                                                                                  'exclusions.',
                                                                                              'resource_kind': 'role_assignment',
                                                                                              'severity': 'high',
                                                                                              'title': 'Subscription '
                                                                                                       'Owner '
                                                                                                       'users '
                                                                                                       'are '
                                                                                                       'covered '
                                                                                                       'by '
                                                                                                       'MFA '
                                                                                                       'policy'},
 'azure_role_assignment_iam_user_with_write_permission_on_subscription_mfa_enabled_d1806c1': {'category': 'least_privilege',
                                                                                              'data_source': 'ARM '
                                                                                                             'Microsoft.Authorization/roleAssignments '
                                                                                                             'ListForScope '
                                                                                                             'and '
                                                                                                             'roleDefinitions '
                                                                                                             'ListForScope '
                                                                                                             '(principalId,roleDefinitionId,scope,permissions[].actions/notActions/dataActions/notDataActions); '
                                                                                                             'Microsoft '
                                                                                                             'Graph '
                                                                                                             'GET '
                                                                                                             '/users?$select=id,accountEnabled '
                                                                                                             'and '
                                                                                                             '/identity/conditionalAccess/policies '
                                                                                                             '(state,conditions.users,conditions.applications,grantControls.builtInControls).',
                                                                                              'description': 'Checks '
                                                                                                             'effective '
                                                                                                             'MFA '
                                                                                                             'enforcement '
                                                                                                             'for '
                                                                                                             'Azure '
                                                                                                             'subscription '
                                                                                                             'writers.',
                                                                                              'id': 'azure_role_assignment_iam_user_with_write_permission_on_subscription_mfa_enabled_d1806c1',
                                                                                              'predicate': 'For '
                                                                                                           'each '
                                                                                                           'enabled '
                                                                                                           'effective '
                                                                                                           'subscription '
                                                                                                           'writer, '
                                                                                                           'including '
                                                                                                           'inherited/custom '
                                                                                                           'roles, '
                                                                                                           'transitive '
                                                                                                           'groups '
                                                                                                           'and '
                                                                                                           'active '
                                                                                                           'PIM, '
                                                                                                           'PASS '
                                                                                                           'only '
                                                                                                           'if '
                                                                                                           'MFA '
                                                                                                           'is '
                                                                                                           'enforced '
                                                                                                           'across '
                                                                                                           'required '
                                                                                                           'Azure '
                                                                                                           'management '
                                                                                                           'sign-in '
                                                                                                           'contexts '
                                                                                                           'by '
                                                                                                           'effective '
                                                                                                           'Conditional '
                                                                                                           'Access '
                                                                                                           'or '
                                                                                                           'separately '
                                                                                                           'proven '
                                                                                                           'security-default '
                                                                                                           'behavior. '
                                                                                                           'FAIL '
                                                                                                           'if '
                                                                                                           'complete '
                                                                                                           'role '
                                                                                                           'and '
                                                                                                           'policy '
                                                                                                           'evaluation '
                                                                                                           'proves '
                                                                                                           'an '
                                                                                                           'uncovered '
                                                                                                           'writer. '
                                                                                                           'UNKNOWN '
                                                                                                           'if '
                                                                                                           'role '
                                                                                                           'permissions, '
                                                                                                           'PIM, '
                                                                                                           'group '
                                                                                                           'membership, '
                                                                                                           'exclusions, '
                                                                                                           'auth '
                                                                                                           'strength, '
                                                                                                           'client/app '
                                                                                                           'conditions '
                                                                                                           'or '
                                                                                                           'inventory '
                                                                                                           'is '
                                                                                                           'unresolved.',
                                                                                              'proposed_spec_sha256': 'b59953ea3184738ed9f2697e6ee19932e9b2c6130dc5e5fd5d744103baf5c2a7',
                                                                                              'provider': 'azure',
                                                                                              'remediation_hint': 'In '
                                                                                                                  'Entra '
                                                                                                                  'admin '
                                                                                                                  'center '
                                                                                                                  '> '
                                                                                                                  'Protection '
                                                                                                                  '> '
                                                                                                                  'Conditional '
                                                                                                                  'Access, '
                                                                                                                  'require '
                                                                                                                  'MFA '
                                                                                                                  'for '
                                                                                                                  'every '
                                                                                                                  'subscription '
                                                                                                                  'writer '
                                                                                                                  'on '
                                                                                                                  'Azure '
                                                                                                                  'management '
                                                                                                                  'apps; '
                                                                                                                  'remove '
                                                                                                                  'bypasses, '
                                                                                                                  'enroll '
                                                                                                                  'users '
                                                                                                                  'and '
                                                                                                                  'test '
                                                                                                                  'effective '
                                                                                                                  'coverage.',
                                                                                              'resource_kind': 'role_assignment',
                                                                                              'severity': 'high',
                                                                                              'title': 'Multi-Factor '
                                                                                                       'Authentication '
                                                                                                       '(MFA) '
                                                                                                       'should '
                                                                                                       'be '
                                                                                                       'enabled '
                                                                                                       'for '
                                                                                                       'all '
                                                                                                       'subscription '
                                                                                                       'accounts '
                                                                                                       'with '
                                                                                                       'write '
                                                                                                       'privileges '
                                                                                                       'to '
                                                                                                       'prevent '
                                                                                                       'a '
                                                                                                       'breach '
                                                                                                       'of '
                                                                                                       'accounts '
                                                                                                       'or '
                                                                                                       'r'},
 'azure_vm_8_2_1_1_712e1ad': {'category': 'network',
                              'data_source': 'Complete paged Microsoft.Compute/virtualMachines GET and instanceView: properties.storageProfile.osDisk.osType, properties.osProfile.linuxConfiguration.ssh.publicKeys[] and PowerState status.',
                              'description': 'Checks the literal Azure PCI source criterion: a running Linux VM is noncompliant when its recorded launch configuration contains an SSH public key. This checks the stored launch configuration only; it does not measure guest SSH or password authentication.',
                              'id': 'azure_vm_8_2_1_1_712e1ad',
                              'predicate': 'For each running Linux VM with complete launch-configuration evidence, FAIL if properties.osProfile.linuxConfiguration.ssh.publicKeys is a nonempty array; PASS if that array is explicitly present and empty. UNKNOWN if OS type, running state, launch-key array, or inventory completeness is unresolved or malformed. Windows and nonrunning VMs are NOT_APPLICABLE. This is a literal launch-key presence criterion, not a claim about effective guest authentication.',
                              'proposed_spec_sha256': 'e64e5ce92cd6765844f89a8e02d607d9b573a8c3fb90bad70ccb5b8081e68337',
                              'provider': 'azure',
                              'remediation_hint': "Review the VM's recorded launch SSH public keys against the approved access policy. If this literal source criterion applies, use an approved deployment configuration without a launch SSH public key; assess guest authentication separately.",
                              'resource_kind': 'vm',
                              'severity': 'high',
                              'title': 'Running Linux VM launch configuration has no SSH public key'}}

IDS = tuple(META)


_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
_SCOPE = re.compile(r"/(?:subscriptions/[^/?#]+|tenants/[^/?#]+|providers/Microsoft.Management/managementGroups/[^/?#]+)", re.I)


def signed(check_id, *, supplemental=True):
    """Preserve signed categories using the reviewed wave-1 registration pattern."""
    meta = META[check_id]
    def decorate(function):
        category = meta['category']
        register(check_id, 'azure', category if category != 'recovery' else 'hardening',
                 meta['resource_kind'], meta['title'], meta['severity'], 'CM-6',
                 meta['remediation_hint'], dependencies=[meta['resource_kind']] +
                 ([EVIDENCE_KIND] if supplemental else []))(function)
        if category == 'recovery':
            CHECKS[-1] = replace(CHECKS[-1], category=category)
        return function
    return decorate


def _text(row, field):
    value = get(row, field, str)
    if not value.strip():
        raise Unavailable('empty identity or policy field: ' + field)
    return value


def _strings(row, field, *, nonempty=False):
    values = get(row, field, list)
    if (any(not isinstance(v, str) or not v.strip() for v in values)
            or len(values) != len(set(v.casefold() for v in values)) or nonempty and not values):
        raise Unavailable('malformed or empty policy/list: ' + field)
    return values


def _guid(value):
    if not isinstance(value, str) or not _GUID.fullmatch(value):
        raise Unavailable('malformed principal/role GUID')
    return value.casefold()


def _role(value):
    if isinstance(value, str) and _GUID.fullmatch(value):
        return value.casefold()
    if not isinstance(value, str) or not re.fullmatch(
            r'(?:/subscriptions/[^/?#]+|/providers/Microsoft.Management/managementGroups/[^/?#]+)?'
            r'/providers/Microsoft.Authorization/roleDefinitions/' + _GUID.pattern, value, re.I):
        raise Unavailable('malformed role-definition ARM identity')
    return _guid(value.rsplit('/', 1)[-1])


def _time(value):
    if not isinstance(value, str):
        raise Unavailable('missing timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError('timezone missing')
        return parsed
    except ValueError as exc:
        raise Unavailable('malformed timestamp') from exc


def _fresh(index, observed, age):
    if type(age) is not int or age <= 0:
        raise Unavailable('report freshness policy unresolved')
    elapsed = (_time(get(index, 'context.created_at', str)) - _time(observed)).total_seconds()
    if not 0 <= elapsed <= age:
        raise Unavailable('stale or future report')


def _scope(index):
    if get(index, 'context.provider', str) != 'azure':
        raise Unavailable('foreign provider')
    scope = _text(get(index, 'context', dict), 'scope')
    if not _SCOPE.fullmatch(scope):
        raise Unavailable('unsupported scope identity')
    return scope


def _policy(index):
    scope = _scope(index)
    policy = get(index, 'context.metadata.compliance_policy', dict)
    named = policy.get('sw18')
    if (isinstance(named, dict) and named.get('status') == 'collected'
            and str(named.get('scope', '')).casefold() == scope.casefold()
            and policy.get('status') == 'collected'
            and str(policy.get('scope', '')).casefold() == scope.casefold()):
        policy = {**named, **policy}
    policy = policy if policy.get('status') == 'collected' and 'scope' in policy else policy.get('sw18', policy)
    if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str).casefold() != scope.casefold():
        raise Unavailable('owner policy missing, incomplete, or foreign')
    return policy


def _graph(index, proof):
    metadata = get(index, 'context.metadata', dict)
    if get(metadata, 'tenant_verified', bool) is not True or get(proof, 'tenant_verified', bool) is not True:
        raise Unavailable('unverified Graph tenant')
    tenant = _text(metadata, 'tenant_id')
    for key in ('tenant_id', 'credential_context_id', 'customer_context_id'):
        if _text(proof, key).casefold() != _text(metadata, key).casefold():
            raise Unavailable('foreign Graph capture/customer/tenant context')
    scope = _scope(index)
    if scope.lower().startswith('/subscriptions/'):
        bindings = get(metadata, 'subscription_tenants', dict)
        if not isinstance(bindings.get(scope), str) or bindings[scope].casefold() != tenant.casefold():
            raise Unavailable('subscription tenant binding unavailable')
    elif scope.casefold() != '/tenants/' + tenant.casefold():
        raise Unavailable('Graph scope tenant binding unavailable')


def _items(index, kind):
    scope = _scope(index)
    envelopes = get(index, 'collections', dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable('collection authority missing or ambiguous: ' + kind)
    envelope = envelopes[0]
    if get(envelope, 'type', str) != kind or get(envelope, 'scope', str).casefold() != scope.casefold():
        raise Unavailable('foreign collection scope/type: ' + kind)
    rows = complete_items(index, kind)
    if get(envelope, 'items', list) != rows:
        raise Unavailable('collection envelope and resource projection disagree: ' + kind)
    seen = set()
    for row in rows:
        rid = _text(row, 'id').casefold()
        if rid in seen:
            raise Unavailable('duplicate native identity: ' + kind)
        seen.add(rid)
    if get(envelope, 'status', str) == 'empty' and rows:
        raise Unavailable('empty collection contains resources')
    if kind == 'directory_user':
        if get(envelope, 'service', str) != 'Microsoft.Graph':
            raise Unavailable('directory source unavailable')
        _graph(index, get(envelope, '_provenance', dict))
        for row in rows:
            _graph(index, get(row, '_provenance', dict))
    return rows


def _base(item, index, kind):
    rows = _items(index, kind)
    rid = _text(item, 'id')
    if not any(row == item for row in rows):
        raise Unavailable('subject differs from native scoped inventory')
    if kind == 'vm':
        scope = _scope(index)
        if not re.fullmatch(re.escape(scope) +
                r'/resourceGroups/[^/?#]+/providers/Microsoft.Compute/virtualMachines/[^/?#]+', rid, re.I):
            raise Unavailable('foreign or malformed VM identity')
    elif kind == 'directory_user':
        _guid(rid)
    elif kind == 'role_assignment':
        properties = get(item, 'properties', dict)
        assignment_scope = _text(properties, 'scope')
        allowed = [_scope(index)] + _strings(_policy(index), 'ancestorScopes')
        if assignment_scope.casefold() not in {v.casefold() for v in allowed}:
            raise Unavailable('assignment inheritance scope unresolved')
        if not re.fullmatch(re.escape(assignment_scope.rstrip('/')) +
                r'/providers/Microsoft.Authorization/roleAssignments/' + _GUID.pattern, rid, re.I):
            raise Unavailable('malformed or foreign role-assignment identity')
        _guid(_text(properties, 'principalId'))
        _role(_text(properties, 'roleDefinitionId'))
    return rid


def _resolved(item, index, check_id, dimensions=(), *, graph=False):
    rid = _base(item, index, META[check_id]['resource_kind'])
    rows = _items(index, EVIDENCE_KIND)
    matches = [row for row in rows if get(row, 'check_id', str) == check_id
               and get(row, 'subject_id', str).casefold() == rid.casefold()]
    if len(matches) != 1:
        raise Unavailable('exact supplemental subject/check evidence missing or ambiguous')
    row = matches[0]
    if (get(row, 'scope', str).casefold() != _scope(index).casefold()
            or get(row, 'id', str).casefold() != (rid + '#sw18:' + check_id).casefold()):
        raise Unavailable('foreign supplemental evidence identity')
    proof = get(row, '_provenance', dict)
    if get(proof, 'read_only', bool) is not True or get(proof, 'adapter', str) != 'sw18-resolved-v1':
        raise Unavailable('supplemental source provenance unavailable')
    _strings(proof, 'source_ids', nonempty=True)
    if graph:
        _graph(index, proof)
    for dimension in dimensions:
        if get(row, 'coverage.' + dimension, bool) is not True:
            raise Unavailable('unmeasured or incomplete evidence: ' + dimension)
    return row


def _vm_ids(policy, field, index):
    values = _strings(policy, field)
    for value in values:
        if not re.fullmatch(re.escape(_scope(index)) +
                r'/resourceGroups/[^/?#]+/providers/Microsoft.Compute/virtualMachines/[^/?#]+', value, re.I):
            raise Unavailable('classification VM identity malformed or foreign')
    return values


def _os(item):
    value = get(item, 'properties.storageProfile.osDisk.osType', str)
    if value not in ('Windows', 'Linux'):
        raise Unavailable('unrecognized VM OS')
    return value


def _na(reason):
    return 'NOT_APPLICABLE', {'reason': reason}


def _guest(item, index, check_id, policy_key):
    row = _resolved(item, index, check_id, ('assignments', 'reports', 'parameters'))
    expected = get(_policy(index), policy_key, dict)
    assignments = list_of_objects(get(item, 'guestConfigurationAssignments', list))
    if get(item, '_coverage.guestConfigurationAssignments.status', str) not in ('collected', 'empty'):
        raise Unavailable('guest assignment pagination incomplete')
    name, version = _text(expected, 'name'), _text(expected, 'version')
    parameters = get(expected, 'parameters', dict)
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in parameters.items()):
        raise Unavailable('malformed approved baseline parameters')
    assignment_id = _text(row, 'assignment_id')
    vm_id = get(item, 'id', str)
    if not re.fullmatch(re.escape(vm_id) +
            r'/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/[^/?#]+', assignment_id, re.I):
        raise Unavailable('foreign guest assignment')
    matches = [a for a in assignments if get(a, 'id', str).casefold() == assignment_id.casefold()]
    if len(matches) != 1:
        raise Unavailable('guest assignment unresolved or duplicate')
    assignment = matches[0]
    if get(assignment, 'parent_id', str).casefold() != vm_id.casefold():
        raise Unavailable('guest assignment parent identity differs from VM')
    guest = get(assignment, 'properties.guestConfiguration', dict)
    if get(guest, 'name', str) != name or get(guest, 'version', str) != version:
        raise Unavailable('unapproved baseline name/version')
    actual = {}
    for entry in list_of_objects(get(guest, 'configurationParameter', list)):
        key, value = _text(entry, 'name'), get(entry, 'value', str)
        if key in actual:
            raise Unavailable('duplicate guest parameter')
        actual[key] = value
    if actual != parameters or get(row, 'effective_parameters', dict) != parameters:
        raise Unavailable('approved effective parameter set unresolved')
    report = get(row, 'report', dict)
    report_id = _text(assignment, 'properties.latestReportId')
    expected_report_id = report_id if report_id.startswith('/') else assignment_id + '/reports/' + report_id
    prefix = assignment_id + '/reports/'
    if not expected_report_id.casefold().startswith(prefix.casefold()) or not re.fullmatch(r'[A-Za-z0-9_.-]+', expected_report_id[len(prefix):]):
        raise Unavailable('malformed latest report ID')
    if get(report, 'id', str).casefold() != expected_report_id.casefold():
        raise Unavailable('foreign or non-latest guest report')
    if get(report, '_provenance.representation', str) != 'full':
        raise Unavailable('guest report is a partial representation')
    props = get(report, 'properties', dict)
    _fresh(index, _text(props, 'endTime'), get(expected, 'maxAgeSeconds', int))
    status = get(props, 'complianceStatus', str)
    if status not in ('Compliant', 'NonCompliant'):
        raise Unavailable('report status unresolved')
    return row, props, status


def _measurement(props, baseline):
    """Only the policy-approved detailed report resource and reason are evidence.

    The approved organization guest baseline emits JSON measurement data in
    this exact reason's phrase. Other details and generic Compliant flags
    cannot supply source identity, drift, or Protocol values.
    """
    resource_id = _text(baseline, 'measurementResourceId')
    reason_code = _text(baseline, 'measurementReasonCode')
    resources = list_of_objects(get(props, 'details.resources', list))
    matches = [r for r in resources if get(r, 'resourceId', str) == resource_id]
    if len(matches) != 1:
        raise Unavailable('specific guest setting report resource missing or ambiguous')
    reasons = list_of_objects(get(matches[0], 'reasons', list))
    selected = [r for r in reasons if get(r, 'code', str) == reason_code]
    if len(selected) != 1:
        raise Unavailable('specific guest setting measurement reason missing or ambiguous')
    try:
        def unique(pairs):
            output = {}
            for key, value in pairs:
                if key in output:
                    raise ValueError('duplicate measurement field')
                output[key] = value
            return output
        value = json.loads(get(selected[0], 'phrase', str), object_pairs_hook=unique)
    except ValueError as exc:
        raise Unavailable('guest measurement JSON malformed') from exc
    if not isinstance(value, dict):
        raise Unavailable('guest measurement is not an object')
    return value


RDP_ID = 'azure.gap.network_security_group_rdp_access_restricted'
CLOCK_ID = 'azure.other.clock_sync'
SSH_ID = 'azure.other.sshv2_guest_configuration'
SOFTWARE_ID = 'azure_c5_am_04_01b'
CONFIDENTIAL_ID = 'azure_c5_ops_30_01ac'
PATCH_ID = 'azure_c5_ops_33_03b'
KEY_ID = 'azure_vm_8_2_1_1_712e1ad'
REVIEW_ID = 'azure.other.azure_role_review'
CREDENTIAL_ID = 'azure.other.credential_creation_role_scope'
BACKUP_ID = 'azure.other.database_backup_role_scope'
PROHIBITED_ID = 'azure_management_group_7_2_1_12_3f8ec01'
SELECTED_ID = 'azure_management_group_7_2_1_13_50babe4'
OWNER_ID = 'azure_role_assignment_iam_user_with_owner_permission_on_subscription_mfa_enabled_8bf88f9'
WRITER_ID = 'azure_role_assignment_iam_user_with_write_permission_on_subscription_mfa_enabled_d1806c1'
USER_MFA_ID = 'azure.cis.multifactor_auth_status_non_privileged_users'


@signed(RDP_ID)
def windows_user_rights(item, index):
    _base(item, index, 'vm')
    if _os(item) == 'Linux':
        return _na('VM is not Windows')
    _, _, status = _guest(item, index, RDP_ID, 'userRightsBaseline')
    return result(status == 'NonCompliant', report_status=status)


@signed(CLOCK_ID)
def clock_sync(item, index):
    _, props, status = _guest(item, index, CLOCK_ID, 'timeSyncBaseline')
    measurement = _measurement(props, get(_policy(index), 'timeSyncBaseline', dict))
    source = _text(measurement, 'sourceId')
    synchronized = get(measurement, 'synchronized', bool)
    drift = get(measurement, 'driftExceeded', bool)
    approved = _strings(_policy(index), 'approvedTimeSourceIds', nonempty=True)
    failed = source not in approved or drift
    if not failed and (status != 'Compliant' or not synchronized):
        return unknown('time synchronization or report compliance unresolved without measured drift or unapproved source')
    return result(failed, actual_source=source, synchronized=synchronized, drift_exceeded=drift)


@signed(SSH_ID)
def ssh_protocol(item, index):
    _base(item, index, 'vm')
    if _os(item) == 'Windows':
        return _na('VM is not Linux')
    exposure = _resolved(item, index, SSH_ID, ('exposure',))
    if not get(exposure, 'exposed', bool):
        return _na('complete exposure evidence proves Linux VM unexposed')
    _, props, _ = _guest(item, index, SSH_ID, 'sshBaseline')
    measurement = _measurement(props, get(_policy(index), 'sshBaseline', dict))
    versions = get(measurement, 'protocolVersions', list)
    if not versions or any(type(v) is not int or v < 1 for v in versions) or len(set(versions)) != len(versions):
        raise Unavailable('ambiguous SSH Protocol measurement')
    return result(1 in versions, measured_protocol_versions=versions)


def _obligations(row, required, index):
    """Dated, reference-backed process records; absence never means satisfied."""
    obligations = list_of_objects(get(row, 'obligations', list))
    by_name = {}
    for obligation in obligations:
        name = _text(obligation, 'name')
        if name in by_name or name not in required:
            raise Unavailable('duplicate or unknown process obligation')
        applicable = get(obligation, 'applicable', bool)
        satisfactory = get(obligation, 'satisfactory', bool)
        observed = _time(_text(obligation, 'observed_at'))
        if observed > _time(get(index, 'context.created_at', str)):
            raise Unavailable('future process record')
        _strings(obligation, 'record_ids', nonempty=True)
        by_name[name] = applicable and not satisfactory
    if set(by_name) != set(required):
        raise Unavailable('process obligation coverage incomplete')
    return any(by_name.values())


@signed(CONFIDENTIAL_ID)
def confidential_vm(item, index):
    rid = _base(item, index, 'vm')
    classified = _vm_ids(_policy(index), 'confidentialVmIds', index)
    if rid.casefold() not in {v.casefold() for v in classified}:
        return _na('VM excluded by explicit confidentialVmIds classification')
    security = get(item, 'properties.securityProfile.securityType', str)
    vtpm = get(item, 'properties.securityProfile.uefiSettings.vTpmEnabled', bool)
    if security not in ('ConfidentialVM', 'TrustedLaunch', 'Standard'):
        raise Unavailable('unrecognized VM security type')
    if security != 'ConfidentialVM' or not vtpm:
        return result(True, security_type=security, vtpm_enabled=vtpm, technical_signal='ABSENT')
    try:
        row = _resolved(item, index, CONFIDENTIAL_ID, ('process_records',))
        unmet = _obligations(row, ('interfaces', 'tee_key_management', 'attestation', 'monitoring',
                                  'annual_security_review', 'event_driven_security_review'), index)
        _fresh(index, get(row, 'reviewed_at', str), get(_policy(index), 'confidentialReviewMaxAgeSeconds', int))
    except Unavailable as exc:
        return unknown(str(exc), technical_signal='PRESENT')
    if unmet:
        return unknown('technical signal present; full C5 documentation is unsatisfactory', technical_signal='PRESENT')
    return result(False, technical_signal='PRESENT', process_records_verified=True)


@signed(PATCH_ID)
def windows_patch_mode(item, index):
    _base(item, index, 'vm')
    if _os(item) == 'Linux':
        return _na('Linux VM is outside Windows patch configuration aspect')
    mode = get(item, 'properties.osProfile.windowsConfiguration.patchSettings.patchMode', str)
    if mode not in ('Manual', 'AutomaticByOS', 'AutomaticByPlatform'):
        raise Unavailable('unrecognized Windows patch mode')
    row = _resolved(item, index, PATCH_ID, ('process_records',))
    _fresh(index, get(row, 'reviewed_at', str), get(_policy(index), 'patchReviewMaxAgeSeconds', int))
    failed = _obligations(row, ('third_party_identification', 'third_party_testing',
                               'third_party_deployment', 'customer_approval', 'provider_rollout'), index)
    return result(failed or mode == 'Manual', patch_mode=mode, process_obligation_unmet=failed)


@signed(KEY_ID, supplemental=False)
def contradictory_ssh_key_rule(item, index):
    _base(item, index, 'vm')
    if _os(item) == 'Windows':
        return _na('VM is not Linux')
    states = list_of_objects(get(item, 'instanceView.statuses', list))
    power = [get(s, 'code', str) for s in states if get(s, 'code', str).startswith('PowerState/')]
    if len(power) != 1 or power[0] not in ('PowerState/running', 'PowerState/stopped', 'PowerState/deallocated'):
        raise Unavailable('VM running state unresolved')
    if power[0] != 'PowerState/running':
        return _na('Linux VM is not running')
    proof = get(item, '_provenance', dict)
    if (get(proof, 'representation', str) != 'full' or
            get(proof, 'source_operation', str) != 'get' or
            get(proof, 'read_only', bool) is not True or
            get(proof, 'expand', str) != 'instanceView'):
        raise Unavailable('VM full GET with instance view unresolved')
    keys = list_of_objects(get(item, 'properties.osProfile.linuxConfiguration.ssh.publicKeys', list))
    for key in keys:
        _text(key, 'path')
        _text(key, 'keyData')
    return result(bool(keys), configured_bootstrap_ssh_public_key_count=len(keys),
                  interpretation='original-source-no-bootstrap-public-key',
                  observation='ARM configured VM SSH publicKeys; no guest runtime claim')


@signed(SOFTWARE_ID)
def guest_software_inventory(item, index):
    rid = _base(item, index, 'vm')
    policy = _policy(index)
    scoped = _vm_ids(policy, 'softwareInventoryVmIds', index)
    if rid.casefold() not in {v.casefold() for v in scoped}:
        return _na('VM excluded by explicit software inventory scope')
    row = _resolved(item, index, SOFTWARE_ID, ('software_pages', 'installed_asset_universe', 'required_assets'))
    _fresh(index, get(row, 'observed_at', str), get(policy, 'softwareInventoryMaxAgeSeconds', int))
    fields = _strings(policy, 'softwareInventoryRequiredFields', nonempty=True)
    if not {'softwareName', 'version', 'deviceId'} <= set(fields) or set(fields) - {'softwareName', 'version', 'deviceId'}:
        raise Unavailable('unsupported or incomplete software field policy')
    assets = list_of_objects(get(row, 'softwareInventories', list))
    seen, validated = set(), []
    for asset in assets:
        asset_id = _text(asset, 'id')
        if not re.fullmatch(re.escape(rid) + r'/providers/Microsoft.Security/softwareInventories/[^/?#]+', asset_id, re.I):
            raise Unavailable('software asset foreign to VM')
        if asset_id.casefold() in seen:
            raise Unavailable('duplicate software asset')
        seen.add(asset_id.casefold())
        if get(asset, '_provenance.representation', str) != 'full':
            raise Unavailable('software inventory representation is partial')
        validated.append((asset_id, get(asset, 'properties', dict)))
    names, missing, unavailable, names_unavailable = set(), [], False, False
    for asset_id, props in validated:
        coverage_entries = props.get('_coverage', {})
        for field in fields:
            # A full read proves an absent/null/empty field unless its selected
            # coverage marker says that particular field was unavailable.
            coverage = coverage_entries.get(field) if isinstance(coverage_entries, dict) else None
            if not isinstance(coverage_entries, dict) or field in coverage_entries:
                if (not isinstance(coverage, dict) or coverage.get('status') not in ('collected', 'empty')
                        or coverage['status'] == 'collected' and field not in props
                        or coverage['status'] == 'empty' and field in props and props[field] not in (None, '')):
                    unavailable = True
                    names_unavailable |= field == 'softwareName'
                    continue
            value = props.get(field)
            if value is not None and not isinstance(value, str):
                unavailable = True
                names_unavailable |= field == 'softwareName'
                continue
            if value is None or not value.strip():
                missing.append(asset_id + ':' + field)
            elif field == 'softwareName':
                names.add(value)
    required = _strings(policy, 'requiredSoftwareNames')
    absent = sorted(set(required) - names) if not names_unavailable else []
    if missing or absent:
        return result(True, missing_required_fields=missing, missing_required_assets=absent,
                      installed_asset_count=len(assets))
    if unavailable:
        raise Unavailable('software field unavailable')
    return result(False, missing_required_fields=missing, missing_required_assets=absent,
                  installed_asset_count=len(assets))


_ACCESS_DIMENSIONS = ('identity_universe', 'assignments', 'inheritance', 'role_definitions',
                      'groups', 'pim', 'conditions', 'deny_assignments', 'data_plane', 'action_inventory')


def _tuple(row, index):
    principal = _guid(_text(row, 'principalId'))
    role = _role(_text(row, 'roleDefinitionId'))
    scope = _text(row, 'scope')
    allowed = [_scope(index)] + _strings(_policy(index), 'ancestorScopes')
    if scope.casefold() not in {v.casefold() for v in allowed}:
        raise Unavailable('foreign or unresolved effective tuple scope')
    return principal, role, scope.casefold()


def _effective(row, index):
    tuples = list_of_objects(get(row, 'effectiveAssignments', list))
    seen = set()
    for entry in tuples:
        identity = _tuple(entry, index)
        if identity in seen or get(entry, 'effective', bool) is not True:
            raise Unavailable('ambiguous or unresolved effective tuple')
        seen.add(identity)
    return tuples


def _action_scope(item, index, check_id, policy_key, *, backup=False):
    dimensions = _ACCESS_DIMENSIONS + (('database_inventory',) if backup else ('resource_inventory',))
    row = _resolved(item, index, check_id, dimensions, graph=True)
    approved = {_guid(v) for v in _strings(_policy(index), policy_key)}
    if backup:
        databases = _strings(row, 'databaseIds')
        if not databases:
            return _na('complete database universe is empty')
        for database in databases:
            if not database.casefold().startswith(_scope(index).casefold() + '/resourcegroups/'):
                raise Unavailable('foreign database scope')
    actions = _strings(row, 'actionInventory', nonempty=True)
    if any('/' not in action or '*' in action for action in actions):
        raise Unavailable('action inventory is not fully expanded')
    resources = databases if backup else _strings(row, 'resourceIds', nonempty=True)
    if not backup and any(not (v.casefold() == _scope(index).casefold() or v.casefold().startswith(_scope(index).casefold() + '/')) for v in resources):
        raise Unavailable('foreign credential action inventory resource')
    expected_pairs = {(action, resource.casefold()) for action in actions for resource in resources}
    identities = list_of_objects(get(row, 'principals', list))
    seen, violations, tested = set(), [], 0
    for principal in identities:
        pid = _guid(_text(principal, 'id'))
        if pid in seen:
            raise Unavailable('duplicate effective principal')
        seen.add(pid)
        if pid in approved:
            continue
        decisions = list_of_objects(get(principal, 'actions', list))
        measured = set()
        for decision in decisions:
            action = _text(decision, 'action')
            resource = _text(decision, 'resourceId')
            pair = (action, resource.casefold())
            if pair not in expected_pairs or pair in measured:
                raise Unavailable('ambiguous action mapping')
            if backup:
                if resource.casefold() not in {v.casefold() for v in databases}:
                    raise Unavailable('foreign database action evidence')
            elif not (resource.casefold() == _scope(index).casefold()
                      or resource.casefold().startswith(_scope(index).casefold() + '/')):
                raise Unavailable('foreign credential action scope')
            measured.add(pair)
            effect = get(decision, 'effectiveAccess', str)
            if effect not in ('Allowed', 'Denied'):
                raise Unavailable('effective permission unresolved')
            if 'authorizedAttempt' not in decision and effect == 'Allowed':
                violations.append({'principalId': pid, 'action': action, 'resourceId': resource})
                tested += 1
                continue
            test = get(decision, 'authorizedAttempt', dict)
            if get(test, 'authorized', bool) is not True:
                raise Unavailable('attempt authorization unverified')
            if (_guid(_text(test, 'principalId')) != pid or get(test, 'action', str) != action
                    or get(test, 'resourceId', str).casefold() != resource.casefold()):
                raise Unavailable('test identity/action/scope mismatch')
            _text(test, 'record_id')
            _time(_text(test, 'observed_at'))
            outcome = get(test, 'outcome', str)
            if outcome not in ('Succeeded', 'Denied'):
                raise Unavailable('test failure is not a proven permission denial')
            if effect == 'Allowed' or outcome == 'Succeeded':
                violations.append({'principalId': pid, 'action': action, 'resourceId': resource})
            tested += 1
        if measured != expected_pairs:
            raise Unavailable('negative action-test coverage incomplete')
    if not identities or not tested:
        return unknown('no representative unapproved tested identity')
    return result(bool(violations), proven_unapproved_actions=violations, denied_attempt_coverage=tested)


@signed(CREDENTIAL_ID)
def credential_creation_scope(item, index):
    return _action_scope(item, index, CREDENTIAL_ID, 'approvedCredentialAdmins')


@signed(BACKUP_ID)
def database_backup_scope(item, index):
    return _action_scope(item, index, BACKUP_ID, 'approvedBackupPrincipalIds', backup=True)


def _scope_assignments(row, index, required_scopes):
    entries = list_of_objects(get(row, 'scopes', list))
    collected = {}
    ancestors = get(_policy(index), 'scopeAncestors', dict)
    for entry in entries:
        target = _text(entry, 'scope').casefold()
        if target in collected or target not in {s.casefold() for s in required_scopes}:
            raise Unavailable('foreign or duplicate protected scope')
        matching = [value for key, value in ancestors.items() if isinstance(key, str) and key.casefold() == target]
        if len(matching) != 1:
            raise Unavailable('missing or ambiguous protected-scope ancestor policy')
        allowed = matching[0]
        if not isinstance(allowed, list) or any(not isinstance(v, str) or not v for v in allowed):
            raise Unavailable('protected-scope ancestry unresolved')
        if _strings(entry, 'ancestorScopes') != allowed:
            raise Unavailable('collected ancestor chain differs from approved chain')
        assignments = list_of_objects(get(entry, 'assignments', list))
        seen = set()
        for assignment in assignments:
            aid = _text(assignment, 'id')
            props = get(assignment, 'properties', dict)
            scope = _text(props, 'scope')
            if scope.casefold() not in {target, *(v.casefold() for v in allowed)}:
                raise Unavailable('foreign inherited assignment')
            if not re.fullmatch(re.escape(scope.rstrip('/')) +
                    r'/providers/Microsoft.Authorization/roleAssignments/' + _GUID.pattern, aid, re.I):
                raise Unavailable('malformed native assignment ID')
            if aid.casefold() in seen:
                raise Unavailable('duplicate native assignment')
            seen.add(aid.casefold())
            _guid(_text(props, 'principalId'))
            _role(_text(props, 'roleDefinitionId'))
            _text(props, 'principalType')
        collected[target] = assignments
    if set(collected) != {s.casefold() for s in required_scopes}:
        raise Unavailable('protected scope enumeration incomplete')
    return collected


@signed(PROHIBITED_ID)
def prohibited_roles(item, index):
    row = _resolved(item, index, PROHIBITED_ID, ('protected_scopes', 'assignments', 'inheritance'))
    policy = _policy(index)
    scopes = _strings(policy, 'protectedScopes', nonempty=True)
    prohibited = {_role(v) for v in _strings(policy, 'prohibitedRoleDefinitionIds', nonempty=True)}
    assignments = _scope_assignments(row, index, scopes)
    violations = []
    for scope, values in assignments.items():
        for assignment in values:
            if _role(get(assignment, 'properties.roleDefinitionId', str)) in prohibited:
                violations.append({'protected_scope': scope, 'assignment_id': assignment['id']})
    return result(bool(violations), prohibited_grants=violations)


@signed(SELECTED_ID)
def selected_principals(item, index):
    row = _resolved(item, index, SELECTED_ID,
                    ('protected_scopes', 'assignments', 'inheritance', 'role_definitions',
                     'principal_lookup', 'group_expansion'), graph=True)
    policy = _policy(index)
    required = list_of_objects(get(policy, 'requiredRoleAssignments', list))
    if not required:
        raise Unavailable('required role/scope policy empty')
    approvals = list_of_objects(get(policy, 'authorizedRoleAssignments', list))
    approved = {}
    for approval in approvals:
        key = (_role(_text(approval, 'roleDefinitionId')), _text(approval, 'scope').casefold())
        if key in approved:
            raise Unavailable('duplicate role/scope approval')
        approved[key] = {_guid(v) for v in _strings(approval, 'principalIds')}
    pairs = set()
    for requirement in required:
        key = (_role(_text(requirement, 'roleDefinitionId')), _text(requirement, 'scope').casefold())
        if key in pairs:
            raise Unavailable('duplicate required role/scope')
        pairs.add(key)
    scopes = sorted({scope for _, scope in pairs})
    assignments = _scope_assignments(row, index, scopes)
    principals = {}
    for principal in list_of_objects(get(row, 'principals', list)):
        pid = _guid(_text(principal, 'id'))
        if pid in principals:
            raise Unavailable('duplicate principal resolution')
        if get(principal, 'resolved', bool) is not True:
            raise Unavailable('principal lookup incomplete')
        principals[pid] = principal
    failures = []
    for role, target in sorted(pairs):
        found_authorized = False
        for assignment in assignments[target]:
            props = get(assignment, 'properties', dict)
            if _role(get(props, 'roleDefinitionId', str)) != role:
                continue
            actual_scope = get(props, 'scope', str).casefold()
            if (role, actual_scope) not in approved:
                raise Unavailable('exact inherited role/scope approval absent')
            pid = _guid(get(props, 'principalId', str))
            principal = principals.get(pid)
            if principal is None:
                raise Unavailable('selected principal missing from lookup')
            ptype = get(principal, 'type', str)
            if ptype not in ('User', 'Group', 'ServicePrincipal') or ptype != get(props, 'principalType', str):
                raise Unavailable('principal type unresolved')
            deleted = get(principal, 'deleted', bool)
            conforms = get(principal, 'conforming', bool)
            authorized = pid in approved[(role, actual_scope)] and not deleted and conforms
            if not authorized:
                failures.append({'assignment_id': assignment['id'], 'principalId': pid})
            found_authorized |= authorized
        if not found_authorized:
            failures.append({'missing_required_role': role, 'scope': target})
    return result(bool(failures), unauthorized_or_missing_assignments=failures)


@signed(REVIEW_ID)
def privileged_role_review(item, index):
    row = _resolved(item, index, REVIEW_ID,
                    ('assignments', 'inheritance', 'role_definitions', 'groups', 'pim',
                     'reviews', 'instances', 'decisions', 'scope_queries', 'decision_application'), graph=True)
    policy = _policy(index)
    privileged = {_role(v) for v in _strings(policy, 'privilegedRoleDefinitionIds', nonempty=True)}
    age = get(policy, 'reviewMaxAgeDays', int)
    if age <= 0:
        raise Unavailable('review policy time window unresolved')
    effective = _effective(row, index)
    reviews = list_of_objects(get(row, 'reviews', list))
    covered, targets = set(), set()
    for review in reviews:
        identity = _tuple(review, index)
        recurring = get(review, 'recurring', bool)
        _text(review, 'definition_id')
        for instance in list_of_objects(get(review, 'instances', list)):
            _text(instance, 'id')
            status = get(instance, 'status', str)
            if status not in ('Completed', 'InProgress', 'NotStarted', 'Applying', 'Applied'):
                raise Unavailable('unrecognized review instance status')
            ended = _text(instance, 'endDateTime')
            elapsed = (_time(get(index, 'context.created_at', str)) - _time(ended)).total_seconds()
            decision = get(instance, 'decision', dict)
            if _guid(_text(decision, 'principalId')) != identity[0]:
                raise Unavailable('foreign review decision principal')
            apply_result = get(decision, 'applyResult', str)
            if apply_result not in ('AppliedSuccessfully', 'NotApplied', 'AppliedWithUnknownFailure', 'AppliedWithAccessDenied'):
                raise Unavailable('decision application unresolved')
            if get(decision, 'decision', str) not in ('Approve', 'Deny', 'DontKnow', 'NotReviewed'):
                raise Unavailable('review decision unresolved')
            if recurring and status in ('Completed', 'Applied') and 0 <= elapsed <= age * 86400 and apply_result == 'AppliedSuccessfully':
                applied = _time(_text(decision, 'appliedDateTime'))
                if not _time(ended) <= applied <= _time(get(index, 'context.created_at', str)):
                    raise Unavailable('decision application timestamp inconsistent')
                covered.add(identity)
    for entry in effective:
        identity = _tuple(entry, index)
        if identity[1] in privileged:
            targets.add(identity)
    if not targets:
        return _na('no effective privileged RBAC tuple in complete inventory')
    return result(bool(targets - covered), uncovered_or_overdue_tuples=sorted(targets - covered))


_MFA_DIMENSIONS = ('identity_universe', 'assignments', 'inheritance', 'role_definitions', 'groups',
                   'pim', 'ca_policies', 'ca_conditions', 'exclusions', 'grant_operators',
                   'authentication_strengths', 'sign_in_paths')


def _paths(row, index, *, security_defaults=False):
    """Resolve every measured path, with independent complete-path coverage."""
    paths = list_of_objects(get(row, 'paths', list))
    if not paths:
        raise Unavailable('applicable sign-in path universe empty')
    strengths = set(_strings(_policy(index), 'approvedAuthenticationStrengthIds'))
    seen, uncovered = set(), []
    for path in paths:
        identity = _text(path, 'id')
        if identity in seen:
            raise Unavailable('duplicate sign-in context')
        seen.add(identity)
        _text(path, 'applicationId')
        _text(path, 'clientAppType')
        # The adapter expands these concrete conditions and records contributing
        # CA policy IDs. Empty policy IDs are explicit uncovered-path evidence.
        conditions = get(path, 'conditions', dict)
        for field in ('location', 'device', 'platform', 'risk'):
            _text(conditions, field)
        controls = _strings(path, 'policyIds')
        allowed = get(path, 'allowed', bool)
        mfa = get(path, 'mfaRequired', bool)
        strength = get(path, 'authenticationStrengthId')
        if strength is not None and (not isinstance(strength, str) or not strength):
            raise Unavailable('malformed authentication strength')
        defaults = get(path, 'securityDefaultsProven', bool)
        if defaults:
            _strings(path, 'securityDefaultsEvidenceIds', nonempty=True)
        if (mfa or strength is not None) and not controls:
            raise Unavailable('MFA controls lack a resolved policy source')
        protected = mfa or strength in strengths or security_defaults and defaults
        if allowed and not protected:
            uncovered.append(identity)
    return uncovered


def _rbac_mfa(item, index, check_id, selector):
    row = _resolved(item, index, check_id, _MFA_DIMENSIONS, graph=True)
    tuples = _effective(row, index)
    active = []
    for entry in tuples:
        _guid(_text(entry, 'principalId'))
        if get(entry, 'principalType', str) != 'User':
            raise Unavailable('effective human-user expansion incomplete')
        selected = get(entry, selector, bool)
        if get(entry, 'effectiveSubscriptionScope', str).casefold() != _scope(index).casefold() or not _scope(index).casefold().startswith('/subscriptions/'):
            raise Unavailable('effective subscription permission scope unresolved')
        if get(entry, 'accountEnabled', bool) and selected:
            active.append(entry)
    failures = []
    for entry in active:
        uncovered = _paths(entry, index, security_defaults=check_id == WRITER_ID)
        failures.extend({'principalId': entry['principalId'], 'path': path} for path in uncovered)
    if not active:
        return _na('no enabled effective subscription ' + selector + ' users')
    return result(bool(failures), proven_unprotected_paths=failures, applicable_user_count=len(active))


@signed(OWNER_ID)
def owner_mfa(item, index):
    return _rbac_mfa(item, index, OWNER_ID, 'owner')


@signed(WRITER_ID)
def writer_mfa(item, index):
    return _rbac_mfa(item, index, WRITER_ID, 'writer')


@signed(USER_MFA_ID)
def non_privileged_mfa(item, index):
    _base(item, index, 'directory_user')
    if not get(item, 'accountEnabled', bool):
        return _na('directory user disabled')
    row = _resolved(item, index, USER_MFA_ID,
                    ('directory_roles', 'groups', 'registration', 'per_user_requirements'), graph=True)
    if get(row, 'privileged', bool):
        return _na('directory user is privileged')
    state = get(row, 'requirements.perUserMfaState', str)
    if state not in ('disabled', 'enabled', 'enforced'):
        raise Unavailable('unrecognized per-user MFA state')
    usable = get(row, 'registration.usableMfaRegistered', bool)
    if state in ('enabled', 'enforced'):
        return result(not usable, per_user_mfa_state=state, usable_mfa_registered=usable)
    # Disabled per-user MFA requires separately measured effective-path evidence.
    for dimension in ('ca_policies', 'ca_conditions', 'exclusions', 'grant_operators',
                      'authentication_strengths', 'sign_in_paths'):
        if get(row, 'coverage.' + dimension, bool) is not True:
            raise Unavailable('effective MFA path coverage incomplete: ' + dimension)
    uncovered = _paths(row, index)
    equivalence = get(_policy(index), 'nonPrivilegedMfaEquivalenceApproved', bool)
    if uncovered:
        return result(True, per_user_mfa_state=state, unprotected_paths=uncovered)
    if not equivalence:
        return unknown('disabled per-user MFA has no approved equivalence policy')
    return result(not usable, per_user_mfa_state=state, usable_mfa_registered=usable,
                  equivalent_mfa_enforcement=True)
