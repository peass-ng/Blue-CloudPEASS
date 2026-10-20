# AWS identity/account semantic review — 2026-10-19

157 active IDs across seven requested kinds are accounted for below. Every callback and family helper was source-reviewed; only named tests establish independent SDK-to-consumer evidence. This is not a semantic-completeness or effective-permission claim.

## Findings

- **missing_or_malformed_identity_statement — fixed**: GAAD default Document={} or missing/invalid Effect/selector returned PASS (two AgentCore engines returned MANUAL); SDK accepts Document as opaque JSON string. document_of now validates Statement list/object, exact Allow/Deny, exclusive nonempty string selectors and Condition dictionary before pattern engines. Empty Statement list remains empty; identity-only Resource validation does not apply to service trust.
- **invalid_credential_active_flags — fixed**: CSV both active=MALFORMED with dates=N/A returned PASS. Active=true with rotated=N/A previously shortcut to no keys. Validate both active slots through flag before early exits; active key date omission UNKNOWN. Four callbacks fixed; no-key false/false stays PASS.
- **default_version_flag_without_id_binding — fixed shared helper**: Contradictory imported GAAD row DefaultVersionId=v2 but sole IsDefaultVersion=true VersionId=v1 with narrow document returns PASS. Shared `default_document` now requires selected version ID, unique version IDs and one exact flagged default. Missing/duplicate/mismatched SDK-shaped version facts become UNKNOWN. Separate base/aws_a_iam_policies helpers remain open as described below.
- **admin_group_mfa_weak_row_validation — fixed**: Member mfa_active=MALFORMED returns PASS; duplicate same-user credential rows false then true overwrite first and return PASS. The authorized callback now rejects duplicate/empty credential usernames and validates strict member MFA flags. Actual native GroupList/CSV join tests cover positive, negative, missing, malformed and duplicate rows; complete ARN/schema validation remains outside this change.
- **hardware_mfa_serial_heuristic — bounded_source_limitation**: Unrecognized non-ARN SerialNumber string is classified hardware by Prowler split fallback; root subtracts virtual devices from summary rather than proving device assurance. Keep explicit device-type heuristic scope; validate malformed/empty serial strings separately and avoid assurance/certification claim.
- **report_freshness_identity_and_federation — unproven_boundary**: Parser retains ReportGeneratedTime but does not enforce freshness/schema/identity uniqueness globally; native credentials do not enumerate federated sessions. Consumer-specific strictness remains documented; no live report generation or federated evidence was inferred.

- **global_imported_subject_account_binding — subsequently corrected**: The original SDK receipt exposed PASS for contradictory foreign global provenance. The follow-up shared-engine guard now rejects known foreign `account_id`/`AccountId` both in scope dependency selection and before resource evaluation. `tests/test_aws_global_subject_binding_review.py` records 22 focused passing cases; these two original counterexamples now require UNKNOWN. The original 157-ID review remains bounded and does not certify unrelated default-version helpers.

- **separate_managed_document_default_joins — open other-owner proposal**: `aws.a.iam.attached_policy_no_star_star` and `aws.iam.no_full_admin` still PASS the contradictory v2-selected/v1-flagged SDK-shaped narrow document through their separate helpers. Exact tests and source locations are in JSON; no core/shared file edit was authorized.

## Evidence and scope

Production Requests plus installed botocore Stubber feed GAAD, password policy, credential CSV and account-contact/organization collectors into registered callbacks. Tests cover opt-in evidence paths without live AWS or report-generation calls. Existing 44-ID core review contracts are linked per ID, with overlap counted once.

The JSON stores deduplicated exact pinned catalog lineage, source hashes, callbacks, every available accessor field and its evidence limit. Historical catalog pins are distinguished from current cached Prowler and Steampipe source revisions. No source mappings were edited.

AWS documents [GAAD URL encoding and pagination](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html), [credential CSV sentinels and reporting limits](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html), and [password-policy response structure](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html). SDK Document members are opaque strings, so Stubber acceptance does not validate IAM JSON grammar.

## Family contracts

### managed_gaad

Producer: aws._iam -> Requests.pages(GetAccountAuthorizationDetails, Policies); _policy URL-decodes Document. Consumer: default_document -> SQL std or Prowler document_of -> literal/cached-action-catalog policy matcher.

Fields: Arn, AttachmentCount, DefaultVersionId, PolicyVersionList[].{IsDefaultVersion,VersionId,Document}; JSON Statement contents are opaque SDK strings, not modeled IAM policy grammar.

Limits: GAAD population is not the all-unattached policy universe. Shared default_document now binds IDs; separate base/aws_a_iam_policies helpers still have the recorded mismatch gap. Policy patterns and finite-catalog NotAction handling are not SCP/boundary/session/condition effective-access evaluation.

### inline_gaad

Producer: aws._iam -> GAAD UserDetailList/RoleDetailList/GroupDetailList; URL-decode *PolicyList[].PolicyDocument; _provenance marks complete response. Consumer: inline_policies -> std / Prowler document_of; matching principal-specific inline list.

Fields: UserPolicyList/RolePolicyList/GroupPolicyList PolicyName and PolicyDocument; API omission receipt can attest empty inline list, arbitrary absent native facts cannot.

Limits: Literal source algorithms differ among SQL/Prowler. Policy condition/deny/privesc patterns are bounded signals, not effective authorization. New independent SDK probes exercise admin pattern on all three native principal shapes.

### principal_gaad

Producer: aws._iam GAAD native details, AttachedManagedPolicies omission receipt, user ListAccessKeys/GetAccessKeyLastUsed/GetLoginProfile/ListMFADevices. Consumer: attached_arns, group_members(user.GroupList), trust std/is_service_role, AccessKeys/LoginProfile/MFADevices typed wrappers.

Fields: Principal Arn/name/path, GroupList, AttachedManagedPolicies[].PolicyArn, AssumeRolePolicyDocument, RoleLastUsed, typed credential detail wrappers.

Limits: No federated session/Identity Center inventory, no SCP/boundary/session effective-access solving. Managed names identify exact attached policies only; not proof of all granted actions. SDK admin-inline probes also prove attachment omission projection, not every trust/MFA/attachment branch.

### credential_csv

Producer: aws._credentials_report -> GetCredentialReport(Content bytes, ReportFormat text/csv, GeneratedTime) -> csv.DictReader; ReportGeneratedTime retained. Consumer: csv_boolean / flag and callback-specific report_time/parse_time/now; two key slots only.

Fields: CSV user/arn, password_enabled/mfa_active/access_key_N_active, ISO dates and documented N/A/no_information/not_supported sentinels.

Limits: Read-only download never generates missing/expired reports. Parser validates CSV framing but not complete schema/enums, row identity uniqueness or report freshness; consumers vary in strictness. IAM/root credential metadata excludes federated sessions and service-specific credentials; last-used data has historical/aggregation limits.

### password_scope

Producer: aws._single(GetAccountPasswordPolicy); NoSuchEntity explicitly empty; global account wrapper. Consumer: aws_a_iam.password_row -> complete_items -> unique PasswordPolicy; nine typed policy predicates.

Fields: MinimumPasswordLength, four Require* bools, PasswordReusePrevention, MaxPasswordAge. Omitted requested members UNKNOWN; proved absent policy FAIL.

Limits: IAM password policy does not evaluate root, federation, Identity Center or external IdP password strength. No new test claims all numeric domains; thresholds only.

### account_presence

Producer: aws._account_configuration GetAlternateContact(SECURITY) and DescribeOrganization; presence-only projection strips PII. Consumer: aws_a_account.security_contact/organization_member; declared not-found differs from denied.

Fields: Partition, SecurityContact.{NamePresent,AlternateContactType}, Organization.{OrganizationId,MasterAccountId}, detail status/absent wrappers.

Limits: Registration is not current contact correctness or organization governance. GovCloud security contact is MANUAL; ownership/governance cannot be inferred from organization ID alone.

### account_cloudtrail

Producer: global cloudtrail_account_inventory across enabled regions, GetTrailStatus; explicit region selection intentionally incomplete. Consumer: _account_trails -> complete_items; SourceRegion == HomeRegion and Status.IsLogging.

Fields: aws_account.Account matched context account; complete inventory with SourceRegion/HomeRegion/TrailARN and Status.IsLogging.

Limits: At least one home-region logging trail only; not all-region/all-event delivery or retention proof. Reuses prior core region-trail contracts, account-wide branch source-inspected but not independently SDK exercised here.

### account_metric_alarm

Producer: aws_account_configuration scope subject plus cloudtrail_account_inventory and metric_alarm_account_inventory. Consumer: aws_gap_metrics.coverage -> management_coverage -> bounded JSON pattern parser/probes -> metric namespace/name/dimensions alarm join -> optional confirmed SNS subscription.

Fields: All dependency collection statuses; same-account/region/group ARN binding; trail selectors and logging; MetricFilters/Alarms/Subscriptions status wrappers and match fields.

Limits: Thirty IDs have callback/helper source review, not thirty new SDK proofs. Finite pattern probes do not prove all event-language semantics; alarm threshold/comparison/action delivery health are not evaluated. Unsupported pattern/partial dependencies remain UNKNOWN.

### all_customer_policy_scope

Producer: aws_customer_policies.collect ListPolicies Scope=Local OnlyAttached=False -> exact GetPolicyVersion(default) join. Consumer: aws_all_policies.scan; six native IDs and two FedRAMP aliases use complete iam_customer_policy dependency, not selected GAAD item universe.

Fields: DefaultDocument.{collection_status,VersionId,Document}, DefaultVersionId exact equality, own-account unique policy ARN, provenance ListPolicies/Local/OnlyAttached=False.

Limits: Despite historical all-managed labels, corrected native scope is customer-managed attached+unattached only. No AWS-managed-wide assertion. NotAction/NotResource conservatively unresolved except known bounded positives; source-inspected existing contract, no new SDK probe here.

### pci_native_join

Producer: GAAD policies + own-account complete user/group/role inventories and native provenance; URL-decoded default documents. Consumer: compliance_new_sw40._one_policy/_managed_document/_statement; _native_policy_attachment joins attached ARN/count, GroupList, trust.

Fields: Unique exact scoped selected policy, default-version identity, every principal ARN/name, managed attachment lists, attachment count, user GroupList and role trust documents.

Limits: Attachment criterion is declared usable membership/trust metadata, not observed activity; MFA predicate checks explicit condition syntax rather than complete authorization. Legacy synthetic attachment branch is not a producer claim. Source-inspected; existing focused PCI tests supply separate regression evidence.

### service_access_unavailable

Producer: _services_last_accessed -> _sla_reports deliberately generation_disabled; no GenerateServiceLastAccessedDetails permitted. Role namespace exclusion can attest no Bedrock identity allow. Consumer: last_accessed -> ServicesLastAccessed list; _stale or user_temp_creds.

Fields: ServicesLastAccessed[].ServiceNamespace/LastAuthenticated needed; ServicesLastAccessedStatus records not_collected reason, not fictitious empty list.

Limits: Without a preexisting complete report collector path these are UNKNOWN, except valid role namespace exclusion is NOT_APPLICABLE. Useful automatic metadata signal remains unsupported under current no-generation profile.

### account_iam_scope

Producer: global complete IAM role/user/group inventories derived from GAAD, current caller identity and partition context. Consumer: support/SecurityAudit named role+policy presence, exact CloudShell attachment scope, or exact CloudWatch-CrossAccountSharingRole name.

Fields: Complete same-account global wrappers; role names/AttachedManagedPolicies, principal attachment lists; exact partition managed-policy ARN.

Limits: Name/policy presence is bounded configuration evidence, not effective permissions, support plan, actual active use or delegated-account correctness; not independently SDK-tested in this report.

## Per-ID disposition

SDK = named independent SDK-to-callback probes; source = inspected callback/helper/producer contract; prior = bounded evidence reused from core review. UNKNOWN on disabled report generation is an honest collection gap. Exact field/source details remain in the JSON.

| ID | Family | Evidence / disposition |
|---|---|---|
| `aws.a.account.organization_member` | account_presence | sdk_to_registered_callback_probed |
| `aws.a.account.security_contact_present` | account_presence | sdk_to_registered_callback_probed |
| `aws.a.cloudwatch.cross_account_role_absent` | account_iam_scope | source_traced_bounded_contract |
| `aws.a.iam.attached_policy_no_star_star` | managed_gaad | sdk_to_registered_callback_probed |
| `aws.a.iam.console_key_created_at_setup` | credential_csv | source_traced_bounded_contract |
| `aws.a.iam.group_no_cloudshell_full_access` | principal_gaad | source_traced_bounded_contract |
| `aws.a.iam.password_policy_expiry_at_most_90` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_lowercase` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_minimum_length_14` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_numbers` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_reuse_at_least_24` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_strong_min_length_14_reuse_24_age_90` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_strong_min_length_8` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_symbols` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.password_policy_uppercase` | password_scope | sdk_to_registered_callback_probed |
| `aws.a.iam.report_all_mfa` | credential_csv | sdk_to_registered_callback_probed |
| `aws.a.iam.report_console_mfa` | credential_csv | sdk_to_registered_callback_probed |
| `aws.a.iam.role_no_cloudshell_full_access` | principal_gaad | source_traced_bounded_contract |
| `aws.a.iam.unused_credentials_45_days` | credential_csv | source_traced_bounded_contract |
| `aws.a.iam.unused_credentials_90_days` | credential_csv | source_traced_bounded_contract |
| `aws.a.iam.user_no_cloudshell_full_access` | principal_gaad | source_traced_bounded_contract |
| `aws.a.iam.user_no_direct_policies` | principal_gaad | source_traced_bounded_contract |
| `aws.a.iam.user_no_managed_policies` | principal_gaad | source_traced_bounded_contract |
| `aws.c2b.bedrock.role_no_full_access_policy` | principal_gaad | source_traced_bounded_contract |
| `aws.claude2_a.cloudtrail.account_has_logging_trail` | account_cloudtrail | source_traced_bounded_contract |
| `aws.claude_a.iam.access_keys_rotated_90` | credential_csv | fixed_active_flag_unknown_sdk_probed |
| `aws.claude_a.iam.access_keys_used_45` | credential_csv | fixed_active_flag_unknown_sdk_probed |
| `aws.claude_a.iam.admin_user_has_mfa` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.attached_policy_no_star_star` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.aws_managed_policy_attached_to_role` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.cloudshell_full_access_not_attached` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.console_password_used_45` | credential_csv | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_attached_policy_no_star_star` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_attached_to_role` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_in_use` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_kms_decrypt_restricted` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_no_blocked_kms_actions` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_no_cloudtrail_star` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_no_kms_star` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_no_service_wildcard` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.custom_policy_no_star_star` | managed_gaad | sdk_to_registered_callback_probed |
| `aws.claude_a.iam.custom_unattached_policy_no_star_star` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.group_inline_kms_decrypt_restricted` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.group_inline_no_admin` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.group_inline_no_blocked_kms_actions` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.group_no_cloudshell_full_access` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.group_no_inline_policies` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.group_not_empty` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.no_unused_initial_access_key` | credential_csv | fixed_active_flag_unknown_sdk_probed |
| `aws.claude_a.iam.not_two_active_keys` | credential_csv | fixed_active_flag_unknown_sdk_probed |
| `aws.claude_a.iam.policy_in_use` | managed_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_admin_group_members_mfa` | principal_gaad | fixed_mfa_row_join_sdk_probed |
| `aws.claude_a.iam.prowler_aws_attached_policy_no_admin` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_console_password_used_45` | credential_csv | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_customer_attached_policy_no_admin` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_customer_policy_no_cloudtrail_full_access` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_customer_policy_no_kms_full_access` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_customer_policy_no_marketplace_subscribe` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_customer_policy_no_permissive_role_assumption` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_customer_unattached_policy_no_admin` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_group_inline_no_admin` | inline_gaad | sdk_to_registered_callback_probed |
| `aws.claude_a.iam.prowler_group_inline_no_cloudtrail_full_access` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_group_inline_no_kms_full_access` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_group_inline_no_marketplace_subscribe` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_group_inline_no_privilege_escalation` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_group_no_administratoraccess` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_policy_agentcore_token_scoped` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_policy_passrole_agentcore_restricted` | managed_gaad | fixed_missing_document_unknown_sdk_probed |
| `aws.claude_a.iam.prowler_role_confused_deputy_prevented` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_role_inline_no_admin` | inline_gaad | sdk_to_registered_callback_probed + prior core |
| `aws.claude_a.iam.prowler_role_inline_no_cloudtrail_full_access` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_role_inline_no_kms_full_access` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_role_inline_no_marketplace_subscribe` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_role_inline_no_privilege_escalation` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_role_no_administratoraccess` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_role_readonly_not_cross_account` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_role_service_trust_bound_to_account` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_root_hardware_mfa` | credential_csv | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_user_hardware_mfa` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.prowler_user_inline_no_admin` | inline_gaad | sdk_to_registered_callback_probed + prior core |
| `aws.claude_a.iam.prowler_user_inline_no_cloudtrail_full_access` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_user_inline_no_kms_full_access` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_user_inline_no_marketplace_subscribe` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_user_inline_no_privilege_escalation` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.prowler_user_no_administratoraccess` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.role_bedrock_access_not_stale` | service_access_unavailable | unsupported_generation_disabled |
| `aws.claude_a.iam.role_inline_kms_decrypt_restricted` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.role_inline_no_admin` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.role_inline_no_blocked_kms_actions` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.role_no_administrator_access` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.role_no_cloudshell_full_access` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.role_no_inline_policies` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.role_readonly_not_cross_account` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.role_trust_not_public` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.role_used_within_60_days` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.securityaudit_role_exists` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.support_role_exists` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.user_bedrock_access_not_stale` | service_access_unavailable | unsupported_generation_disabled |
| `aws.claude_a.iam.user_in_group` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.user_inline_kms_decrypt_restricted` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.user_inline_no_admin` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.user_inline_no_assume_role_text` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.user_inline_no_blocked_kms_actions` | inline_gaad | source_traced_bounded_contract + prior core |
| `aws.claude_a.iam.user_long_lived_keys_only_iam_sts` | service_access_unavailable | unsupported_generation_disabled |
| `aws.claude_a.iam.user_no_cloudshell_full_access` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.user_no_inline_policies` | inline_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.user_one_active_key` | principal_gaad | source_traced_bounded_contract |
| `aws.claude_a.iam.user_sagemaker_access_not_stale` | service_access_unavailable | unsupported_generation_disabled |
| `aws.gap.cloudwatch.cis_alarm.cloudtrail_configuration_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.cmk_disable_or_scheduled_deletion` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.config_configuration_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.console_authentication_failures` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.console_sign_in_without_mfa` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.iam_policy_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.network_acl_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.network_gateway_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.organizations_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.root_account_usage` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.route_table_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.s3_bucket_policy_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.security_group_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.unauthorized_api_calls` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.cis_alarm.vpc_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.cloudtrail_configuration_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.cmk_disable_or_scheduled_deletion` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.config_configuration_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.console_authentication_failures` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.console_sign_in_without_mfa` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.iam_policy_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.network_acl_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.network_gateway_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.organizations_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.root_account_usage` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.route_table_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.s3_bucket_policy_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.security_group_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.unauthorized_api_calls` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.cloudwatch.metric_alarm.vpc_changes` | account_metric_alarm | source_traced_bounded_contract |
| `aws.gap.iam.active_keys_used_within_45_days` | credential_csv | source_traced_bounded_contract |
| `aws.gap.iam.root_not_used_1_day` | credential_csv | source_traced_bounded_contract |
| `aws.gap.iam.root_not_used_90_days` | credential_csv | source_traced_bounded_contract |
| `aws.iam.access_key_count` | principal_gaad | source_traced_bounded_contract |
| `aws.iam.console_mfa` | principal_gaad | source_traced_bounded_contract + prior core |
| `aws.iam.no_full_admin` | managed_gaad | source_traced_bounded_contract |
| `aws.iam.restrict_public_trust` | principal_gaad | source_traced_bounded_contract + prior core |
| `aws.iam.root_mfa` | credential_csv | source_traced_bounded_contract |
| `aws.nist.all_iam_policies_no_star_star` | all_customer_policy_scope | source_traced_bounded_contract |
| `aws.nist.all_managed_policies_no_service_wildcard` | all_customer_policy_scope | source_traced_bounded_contract |
| `aws.pci.iam.nonconsole_mfa_policy` | pci_native_join | source_traced_bounded_contract |
| `aws.pci.iam.policy_attached_to_active_principal` | pci_native_join | source_traced_bounded_contract |
| `aws_fedramp_iam_all_policies_no_admin_star` | all_customer_policy_scope | source_traced_bounded_contract |
| `aws_fedramp_iam_all_policies_no_service_wildcard` | all_customer_policy_scope | source_traced_bounded_contract |
| `aws_g6_iam_all_policy_service_wildcard` | all_customer_policy_scope | source_traced_bounded_contract |
| `aws_g6_iam_all_policy_star_star` | all_customer_policy_scope | source_traced_bounded_contract |
| `aws_nist_iam_all_policy_no_service_wild_card` | all_customer_policy_scope | source_traced_bounded_contract |
| `aws_nist_iam_policy_no_star_star` | all_customer_policy_scope | source_traced_bounded_contract |

## Validation

344 focused tests passed after the final authorized fixes; the standalone review file passes **157 tests in 8.16s**. 232 earlier targeted IAM regression tests also passed, with the exact narrower evidence boundaries recorded there. No full suite, build, deployment, live cloud mutation or content download was performed.

Pinned cached SQL example: [IAM conformance pack at 803dda1](https://github.com/turbot/steampipe-mod-aws-compliance/blob/803dda1f7555ed5cea959aef30cfa0719b030d8c/conformance_pack/iam.pp#L1928) (SHA256 `4f21ae3e80dfe98d4071407e9416225ae724a2b388cb160c71495f0448eb91f1`); exact-star and attachment predicates remain bounded source semantics. [Current cached Prowler policy helper](https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/iam/lib/policy.py) treats absent statements as empty; malformed native-document UNKNOWN is an intentional correction. These selected upstream comparisons are not 376 independent evaluator equivalence proofs.
