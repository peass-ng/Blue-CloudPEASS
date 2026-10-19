# GCP identity and data review — 2026-10-19

Recorded all 154 exact assigned IDs: 130 active and 24 archived. Every ID has its actual callback/helper dispatch, native producer references and hashes, primary documentation receipts, observed test nodes/statuses, disposition and explicitly unproved branches in the [machine-readable review](identity-data-review.json). No ID is marked fully certified, and archived or owner-approved criteria are not counted as automated coverage.

Five active IDs received scoped runtime fixes: Workspace MFA now requires native enrollment and enforcement with an independent CRM project/customer binding; super-admin recovery consumes the selected Directory field and Cloud Identity membership/user join; the signed BigQuery reader check recognizes native iamMember=allUsers; the SQL reference variant normalizes the native trace-flag suffix; and the Storage public-read check now requires complete ancestor/folder evidence before PASS and fails inherited read grants. UI groups and signed catalog/copy metadata remain coordinator-owned.

Native schemas and omission boundaries were checked against primary Google references, including [Directory User](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users), [BigQuery Dataset](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/datasets), [SQL Server flags](https://docs.cloud.google.com/sql/docs/sqlserver/flags), [Cloud Storage Bucket](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets), [CryptoKey](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys) and [Secret](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets). The JSON contains 37 retrieved document receipts with response hashes; API schema agreement is narrower than upstream control equivalence.

Validation: 1,384 focused GCP-selected reused/directed tests passed; the final directed run passed 36 native pipeline cases. The unique merged node receipt contains 1,385 passing tests because the last run adds one semantic objectCreator/read distinction case.

The directed test file exercises native response → real collector → sealed snapshot → registered consumers. Reused tests are attributed per exact test node in JSON; callback observations are recorded only for passing tests. Partial inventories can carry an observed resource result alongside an UNKNOWN inventory finding, so a resource PASS must not be presented as a complete project all-clear.

The proposal history retains pre-fix observations and the corrected Storage-bridge finding under /tmp/peasso-gcp-review-20261019/identity-data-proposals. Complete native ACL metadata was already bridged into the signed callback; the confirmed new Storage defect was omission of inherited public-read grants, which is now fixed.

Remaining limits include indirect/external identity expansion, nested/external recovery members, multi-project customer binding, arbitrary CEL/deny/PAB semantics, custom roles and folder coverage outside supported paths, runtime database defaults, actual log delivery, completed rotation, and owner-approved classifications/schedules. These are per-ID limitations, not an assertion that every listed unsupported branch has a tested UNKNOWN path.

| Exact ID | Active | Disposition | Passing callback nodes |
|---|---|---|---|
| `gcp.bigquery.table_classification_tags` | archived | archived_external_criterion_retained | 0 |
| `gcp.claude.bigquery_dataset.no_gmail_access` | yes | bounded_native_declaration_review | 2 |
| `gcp.claude.bigquery_dataset.no_googlegroups_access` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.bucket.log_sink_not_public` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.bucket.log_sink_retention_locked` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.bucket.log_sink_retention_policy` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.bucket.log_sink_versioning` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.bucket.policy_shared_access` | archived | archived_external_criterion_retained | 2 |
| `gcp.claude.bucket.retention_90_days` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.iam_policy.no_all_users` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.iam_policy.no_project_sa_user_or_token_creator` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.kms_key.policy_shared_access` | archived | archived_external_criterion_retained | 1 |
| `gcp.claude.kms_key.rotation_100_days` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.kms_key.users_limited_to_3` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.project.audit_logs_configured` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.project.storage_data_access_audit_logs` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.secret.not_public` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.secret.rotation_90_days` | yes | bounded_native_declaration_review | 20 |
| `gcp.claude.service_account.policy_shared_access` | archived | archived_external_criterion_retained | 1 |
| `gcp.claude.service_account.recently_used` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.service_account_key.age_100_days` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.service_account_key.recently_used` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.sql_instance.private_ip_only` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.sql_instance.second_gen_no_public_ip` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude.workload_identity_provider.multi_tenant_condition` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude2.bigquery_dataset.default_cmek` | yes | bounded_native_declaration_review | 1 |
| `gcp.claude2.sql_instance.only_private_ip_addresses` | yes | bounded_native_declaration_review | 2 |
| `gcp.gap.iam_user_managed_sa_no_admin_roles` | yes | bounded_native_declaration_review | 0 |
| `gcp.gap.sql_3625_trace_flag_off_cis_v1` | yes | bounded_native_declaration_review | 6 |
| `gcp.htbp.iam.policy_no_pool_wide_workload_principal_set` | yes | bounded_native_declaration_review | 0 |
| `gcp.htbp.iam.sa_no_pool_wide_workload_principal_set` | yes | bounded_native_declaration_review | 0 |
| `gcp.htbp.kms.destroy_window_not_shortened` | yes | bounded_native_declaration_review | 0 |
| `gcp.htbp.storage.default_object_acl_not_public` | yes | bounded_native_declaration_review | 0 |
| `gcp.htbp.storage.hmac_key_not_stale_or_default_sa` | yes | bounded_native_declaration_review | 0 |
| `gcp.htbp.storage.notification_topic_in_bucket_project` | yes | bounded_native_declaration_review | 0 |
| `gcp.iam.avoid_basic_roles` | yes | bounded_native_declaration_review | 0 |
| `gcp.iam.data_access_audit` | yes | bounded_native_declaration_review | 1 |
| `gcp.iam.no_user_managed_sa_keys` | yes | bounded_native_declaration_review | 0 |
| `gcp.iam.restrict_public_members` | yes | bounded_native_declaration_review | 0 |
| `gcp.identity.non_service_account_mfa` | yes | fixed_native_enrollment_and_enforcement_with_crm_customer_binding | 10 |
| `gcp.identity.super_admin_recovery_group` | yes | fixed_selected_recovery_field_and_native_cloud_identity_user_join | 8 |
| `gcp.identity.super_admin_separation` | yes | bounded_native_declaration_review | 16 |
| `gcp.ports.alloydb_cluster_encrypted_with_cmk` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.alloydb_instance_log_min_messages_database_flag_error` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.bigquery_dataset_not_publicly_accessible` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.bigquery_table_encrypted_with_cmk` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.iam_corporate_domain_declaration` | archived | archived_external_criterion_retained | 6 |
| `gcp.ports.iam_service_account_gcp_managed_key` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.iam_service_account_key_age_90` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.iam_user_not_assigned_service_account_user_role_project_level` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.iam_user_separation_of_duty_scoped` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.kms_key_rotated_within_90_day` | yes | bounded_native_declaration_review | 10 |
| `gcp.ports.kms_key_separation_of_duties_enforced` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sql_pg_min_duration` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sql_pg_min_error` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sql_pg_min_messages` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sql_ssl_connections` | yes | bounded_native_declaration_review | 0 |
| `gcp.ports.reference_sqlserver_contained_database_authentication` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sqlserver_cross_db_ownership_chaining` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sqlserver_external_scripts_enabled` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sqlserver_remote_access` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sqlserver_trace3625` | yes | fixed_native_trace_suffix_normalization_and_alias_duplicate_guard | 8 |
| `gcp.ports.reference_sqlserver_user_connections` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.reference_sqlserver_user_options` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.service_account_mutating_role_declarations` | yes | bounded_native_declaration_review | 9 |
| `gcp.ports.sql_instance_mysql_binary_log_enabled` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.sql_instance_not_open_to_internet` | yes | bounded_native_declaration_review | 0 |
| `gcp.ports.sql_instance_not_publicly_accessible` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_duration_database_flag_on` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter` | yes | bounded_native_declaration_review | 7 |
| `gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_require_ssl_enabled` | yes | bounded_native_declaration_review | 0 |
| `gcp.ports.sql_instance_sql_3625_trace_database_flag_on` | yes | bounded_native_declaration_review | 14 |
| `gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_sql_remote_access_database_flag_off` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_sql_user_connections_database_flag_configured` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_sql_user_options_database_flag_not_configured` | yes | bounded_native_declaration_review | 6 |
| `gcp.ports.sql_instance_with_no_public_ips` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.sql_no_primary_address` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.sql_private_ip_assignments` | yes | bounded_native_declaration_review | 5 |
| `gcp.ports.storage_bucket_not_publicly_accessible` | yes | bounded_native_declaration_review | 5 |
| `gcp.reviewed.bigquery.cmek` | yes | bounded_native_declaration_review | 13 |
| `gcp.reviewed.bigquery.no_public_acl` | yes | bounded_native_declaration_review | 11 |
| `gcp.reviewed.kms.no_public_iam` | yes | bounded_native_declaration_review | 12 |
| `gcp.reviewed.kms.rotation_90_days` | yes | bounded_native_declaration_review | 8 |
| `gcp.reviewed.kms.rotation_enabled` | yes | bounded_native_declaration_review | 8 |
| `gcp.reviewed.sql.cmek` | yes | bounded_native_declaration_review | 6 |
| `gcp.reviewed.sql.high_availability` | yes | bounded_native_declaration_review | 7 |
| `gcp.reviewed.sql.mysql_local_infile` | yes | bounded_native_declaration_review | 7 |
| `gcp.reviewed.sql.mysql_skip_show_database` | yes | bounded_native_declaration_review | 6 |
| `gcp.reviewed.sql.postgres_log_connections` | yes | bounded_native_declaration_review | 6 |
| `gcp.reviewed.sql.postgres_log_disconnections` | yes | bounded_native_declaration_review | 6 |
| `gcp.reviewed.sql.postgres_log_error_verbosity` | yes | bounded_native_declaration_review | 7 |
| `gcp.reviewed.sql.postgres_log_statement` | yes | bounded_native_declaration_review | 7 |
| `gcp.reviewed.sql.postgres_pgaudit` | yes | bounded_native_declaration_review | 6 |
| `gcp.reviewed.storage.access_logging` | yes | bounded_native_declaration_review | 9 |
| `gcp.reviewed.storage.lifecycle` | yes | bounded_native_declaration_review | 7 |
| `gcp.reviewed.storage.soft_delete` | yes | bounded_native_declaration_review | 6 |
| `gcp.reviewed.storage.versioning` | yes | bounded_native_declaration_review | 9 |
| `gcp.sql.backups` | yes | bounded_native_declaration_review | 1 |
| `gcp.sql.deletion_protection` | yes | bounded_native_declaration_review | 1 |
| `gcp.sql.iam_database_authentication` | yes | bounded_native_declaration_review | 0 |
| `gcp.sql.mysql_admin_account_posture` | yes | bounded_native_declaration_review | 0 |
| `gcp.sql.no_public_ip` | yes | bounded_native_declaration_review | 1 |
| `gcp.sql.restrict_authorized_networks` | yes | bounded_native_declaration_review | 0 |
| `gcp.storage.no_public_iam` | yes | bounded_native_declaration_review | 0 |
| `gcp.storage.public_access_prevention` | yes | bounded_native_declaration_review | 4 |
| `gcp.storage.uniform_access` | yes | bounded_native_declaration_review | 0 |
| `gcp_bucket_logging_enabled_fb7cc594582a` | yes | bounded_native_declaration_review | 1 |
| `gcp_c5_backup_remote_location` | archived | archived_external_criterion_retained | 12 |
| `gcp_c5_classification_label` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_deletion_recoverability` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_iam_change_timeliness` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_iam_conditions` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_iam_expiry` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_iam_inventory` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_key_versions` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_kms_hsm` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_log_retention` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_restore_destination` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_restore_test` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_secret_access` | archived | archived_external_criterion_retained | 0 |
| `gcp_c5_sql_backup_run` | archived | archived_external_criterion_retained | 0 |
| `gcp_cloudsql_failed_attempts_lockout` | archived | archived_external_criterion_retained | 0 |
| `gcp_gcs_replication_status` | archived | archived_external_criterion_retained | 0 |
| `gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650` | yes | bounded_native_declaration_review | 0 |
| `gcp_pci_asset_6ee2fef37d98` | yes | bounded_native_declaration_review | 0 |
| `gcp_pci_bigquery_dataset_6017267cdf32` | yes | bounded_native_declaration_review | 0 |
| `gcp_pci_bigquery_dataset_a4e25dbf9640` | yes | fixed_iamMember_allUsers_READER_representation | 3 |
| `gcp_pci_bigquery_dataset_fb9fcc01d5b7` | yes | bounded_native_declaration_review | 0 |
| `gcp_pci_bucket_0742bd5dc32c` | yes | bounded_native_declaration_review | 0 |
| `gcp_pci_bucket_157fb0c69361` | yes | fixed_native_ancestor_read_grants_and_complete_hierarchy_PASS_gate | 35 |
| `gcp_pci_bucket_3d76b0b0701e` | yes | bounded_native_declaration_review | 0 |
| `gcp_pci_bucket_56c6b1b7f813` | yes | bounded_native_declaration_review | 34 |
| `gcp_pci_bucket_7dc6cb8c2e05` | archived | archived_external_criterion_retained | 34 |
| `gcp_pci_iam_policy_9a8ce875703d` | archived | archived_external_criterion_retained | 3 |
| `gcp_pci_iam_policy_ca1281da7ab2` | archived | archived_external_criterion_retained | 4 |
| `gcp_pci_kms_key_a3927a5f3b84` | yes | bounded_native_declaration_review | 26 |
| `gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6` | yes | bounded_native_declaration_review | 0 |
| `gcp_sql_trace3625_off` | yes | bounded_native_declaration_review | 0 |

All 24 archived reasons were reassessed individually. Viable automatic successors are deliberately narrower native metadata policies (public grants, tag presence, version state, placement, backup recency or service audit configuration); approved rosters, required scope, schedules, recovery-test validation and corporate trust remain external criteria. No archived ID was reactivated.
