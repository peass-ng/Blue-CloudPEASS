
## Independent verifier pass

Checked 1730 distinct framework requirements, 1001 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 1.2.8.34: MAPPING_FIX [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.2.8.35: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.3.1.18: MAPPED [gcp.ports.compute_firewall_rule_ssh_access_restricted] -> NEW_CHECK [gcp_pci_dataproc_cluster_d3bd2d8b2458]. A firewall check limited to TCP 22 cannot decide Dataproc web-interface exposure or BlockPublicHttps.
- pci_4.0_gcp 1.3.1.32: PARTIAL [gcp.reviewed.bigquery.no_public_acl, gcp_bigquery_dataset_access_field_dataset_configuration_item_f594175de84e] -> MAPPING_FIX [gcp.reviewed.bigquery.no_public_acl]. The dataset ACL evaluator reads access entries, including role and public principal; its broader public-grant finding covers the stated READER/WRITER condition.
- pci_4.0_gcp 1.3.1.34: MAPPING_FIX [gcp.storage.public_access_prevention, gcp.storage.no_public_iam] -> MAPPING_FIX [gcp.storage.public_access_prevention]. The requirement tests iamConfiguration.publicAccessPrevention=enforced. Other bucket access checks are not part of that predicate.
- pci_4.0_gcp 1.3.1.38: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.3.1.39: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.3.2.34: MAPPING_FIX [gcp.storage.public_access_prevention, gcp.storage.uniform_access, gcp.storage.no_public_iam] -> MAPPING_FIX [gcp.storage.uniform_access]. The requirement tests iamConfiguration.uniformBucketLevelAccess.enabled only.
- pci_4.0_gcp 1.3.2.38: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.3.2.39: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.4.2.36: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.4.2.37: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.4.5.1: MAPPING_FIX [gcp.ports.compute_instance_with_no_public_ip_addresses] -> NEW_CHECK [gcp_pci_instance_template_2e26bed500fc]. The mapped check evaluates running instance network interfaces, not instance templates.
- pci_4.0_gcp 1.5.1.30: MAPPING_FIX [gcp.storage.public_access_prevention, gcp.storage.uniform_access, gcp.storage.no_public_iam] -> MAPPING_FIX [gcp.storage.uniform_access]. The requirement tests iamConfiguration.uniformBucketLevelAccess.enabled only.
- pci_4.0_gcp 1.5.1.34: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 1.5.1.35: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 10.2.1.3.13: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> NEW_CHECK [gcp_pci_asset_993fb5743ecd]. The assigned check only inspects cluster.loggingService and cannot verify active workload logging.
- pci_4.0_gcp 10.2.2.21: NEW_CHECK [gcp_firewall_logging_specific_action_such_as_ff9959d8acff] -> MAPPING_FIX [gcp.claude.firewall.logging_enabled]. The firewall evaluator tests logConfig.enable.
- pci_4.0_gcp 10.3.2.12: MAPPING_FIX [gcp.ports.compute_firewall_rule_ssh_access_restricted] -> NEW_CHECK [gcp_pci_firewall_2080b14f1361]. The mapped SSH-only evaluator cannot detect unrestricted access to other allowed ports.
- pci_4.0_gcp 10.3.2.17: MAPPED [gcp.reviewed.bigquery.no_public_acl] -> NEW_CHECK [gcp_pci_bigquery_dataset_8944f64d935e]. The current dataset check flags any public grant, while this input specifies a viewer-role grant; the input role spelling also needs normalization to BigQuery dataset roles.
- pci_4.0_gcp 10.3.2.23: MAPPING_FIX [gcp.storage.no_public_iam] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 10.3.2.24: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 10.3.3.8: MAPPED [gcp.sql.backups] -> PARTIAL [gcp.sql.backups, gcp_pci_sql_instance_e95ac2afa5e4]. The evaluator tests backup enablement only; optional retention/window constraints are separate.
- pci_4.0_gcp 10.5.1.13: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_0742bd5dc32c]. The versioning check tests the wrong field. The lifecycle evaluator checks rule existence but does not gate the result on versioning.
- pci_4.0_gcp 10.6.3.17: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> NEW_CHECK [gcp_pci_asset_993fb5743ecd]. The assigned check only inspects cluster.loggingService and cannot verify active workload logging.
- pci_4.0_gcp 3.2.1.9: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_0742bd5dc32c]. The versioning check tests the wrong field. The lifecycle evaluator checks rule existence but does not gate the result on versioning.
- pci_4.0_gcp 3.3.1.3.9: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_0742bd5dc32c]. The versioning check tests the wrong field. The lifecycle evaluator checks rule existence but does not gate the result on versioning.
- pci_4.0_gcp 3.3.2.9: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_0742bd5dc32c]. The versioning check tests the wrong field. The lifecycle evaluator checks rule existence but does not gate the result on versioning.
- pci_4.0_gcp 3.3.3.9: MAPPING_FIX [gcp.reviewed.storage.versioning] -> NEW_CHECK [gcp_pci_bucket_3d76b0b0701e]. Object versioning says nothing about bucket retentionPolicy.
- pci_4.0_gcp 3.5.1.3.14: MAPPING_FIX [gcp.ports.compute_firewall_rule_ssh_access_restricted] -> NEW_CHECK [gcp_pci_firewall_2080b14f1361]. The mapped SSH-only evaluator cannot detect unrestricted access to other allowed ports.
- pci_4.0_gcp 3.5.1.3.28: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp 3.5.1.23: MAPPING_FIX [gcp.sql.backups] -> NEW_CHECK [gcp_pci_sql_instance_25f7886ad44c]. The existing backups check tests enablement only, not backup encryption.
- pci_4.0_gcp 7.3.2.20: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc3ac9a3584]. No-public-IAM detects only anonymous grants; it does not enforce an allowlist of principals, IP addresses or VPCs.
- pci_4.0_gcp A1.1.2.18: NEW_CHECK [gcp_bucket_these_configurations_met_56bb3f5d2b1a] -> MAPPING_FIX [gcp.reviewed.storage.versioning]. The bucket evaluator tests versioning.enabled on the collected bucket.
- pci_4.0_gcp A1.1.2.19: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp A3.4.1.15: PARTIAL [gcp.reviewed.bigquery.no_public_acl, gcp_bigquery_dataset_dataset_s_defaultaccessentry_has_role_28c9e07a3eaf] -> NEW_CHECK [gcp_pci_bigquery_dataset_a4e25dbf9640]. The existing evaluator also fails other public grants, so it is not equivalent to this role-specific predicate; defaultAccessEntry is not a native dataset field.
- pci_4.0_gcp A3.4.1.16: MAPPING_FIX [gcp.storage.public_access_prevention, gcp.storage.no_public_iam] -> MAPPING_FIX [gcp.storage.public_access_prevention]. The requirement tests iamConfiguration.publicAccessPrevention=enforced. Other bucket access checks are not part of that predicate.
- pci_4.0_gcp A3.4.1.20: NEW_CHECK [gcp_bucket_additional_authentication_required_dc152edee89b] -> MAPPING_FIX [gcp.reviewed.storage.versioning]. The bucket evaluator tests versioning.enabled on the collected bucket.
- pci_4.0_gcp A3.4.1.21: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- pci_4.0_gcp A3.4.1.22: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f]. Bucket IAM and uniform bucket-level access do not inspect effective bucket or object ACL grants when uniform access is disabled.
- gcp-compliance.benchmark.pci_dss_v321 gcp-compliance.control.require_bq_table_iam: MAPPED [gcp.reviewed.bigquery.no_public_acl] -> NEW_CHECK [gcp_pci_bigquery_table_53709e69e024]. The assigned check reads dataset.access, not table IAM; the input supplies no role/principal threshold, so assessment also needs that policy parameter.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 986 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 1.4.2.32: NEW_CHECK [gcp_bucket_uniform_access_controls_enabled_gcs_62e79f9172ea] -> MAPPING_FIX [gcp.storage.uniform_access]. The bucket evaluator checks iamConfiguration.uniformBucketLevelAccess.enabled.
- pci_4.0_gcp 10.2.1.2.7: NEW_CHECK [gcp_bucket_there_no_logs_recording_storage_4ba344bd3552] -> MAPPING_FIX [gcp.claude.project.storage_data_access_audit_logs]. The project evaluator checks effective Cloud Storage DATA_READ and DATA_WRITE audit configurations.
- pci_4.0_gcp 10.2.1.3.7: NEW_CHECK [gcp_bucket_there_no_audit_logs_recording_2f81acc4062c] -> MAPPING_FIX [gcp.claude.project.storage_data_access_audit_logs]. The project evaluator checks effective Cloud Storage DATA_READ and DATA_WRITE audit configurations.
- pci_4.0_gcp 10.2.1.4.7: NEW_CHECK [gcp_bucket_there_no_trails_recording_gcs_a21dfd7d0e06] -> MAPPING_FIX [gcp.claude.project.storage_data_access_audit_logs]. The project evaluator checks effective Cloud Storage DATA_READ and DATA_WRITE audit configurations.
- pci_4.0_gcp 10.2.1.5.7: NEW_CHECK [gcp_bucket_there_no_audit_logs_recording_e46ce95dd15d] -> MAPPING_FIX [gcp.claude.project.storage_data_access_audit_logs]. The project evaluator checks effective Cloud Storage DATA_READ and DATA_WRITE audit configurations.
- pci_4.0_gcp 10.2.1.7.7: NEW_CHECK [gcp_bucket_there_no_audit_logs_that_a2b28c303cf5] -> MAPPING_FIX [gcp.claude.project.storage_data_access_audit_logs]. The project evaluator checks effective Cloud Storage DATA_READ and DATA_WRITE audit configurations.
- pci_4.0_gcp 10.3.1.7: NEW_CHECK [gcp_bucket_there_no_audit_logs_recording_e46ce95dd15d] -> MAPPING_FIX [gcp.claude.project.storage_data_access_audit_logs]. The project evaluator checks effective Cloud Storage DATA_READ and DATA_WRITE audit configurations.
- pci_4.0_gcp 10.5.1.12: NEW_CHECK [gcp_bucket_there_no_active_lifecycle_configuration_e900fb579a47] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_5c651238b5c6]. The existing lifecycle evaluator tests rule existence; parameter matching and versioning applicability need a separate predicate.
- pci_4.0_gcp 3.2.1.8: NEW_CHECK [gcp_bucket_there_no_active_lifecycle_configuration_9418049b0af5] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_5c651238b5c6]. The existing lifecycle evaluator tests rule existence; parameter matching and versioning applicability need a separate predicate.
- pci_4.0_gcp 3.3.1.1.8: NEW_CHECK [gcp_bucket_there_no_active_lifecycle_configuration_7e13e019cbdb] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_5c651238b5c6]. The existing lifecycle evaluator tests rule existence; parameter matching and versioning applicability need a separate predicate.
- pci_4.0_gcp 3.3.1.1.9: NEW_CHECK [gcp_bucket_gcs_lifecycle_management_policies_enabled_191d10f7a4d4] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_5c651238b5c6]. The existing lifecycle evaluator tests rule existence; parameter matching and versioning applicability need a separate predicate.
- pci_4.0_gcp 3.3.1.3.8: NEW_CHECK [gcp_bucket_there_no_active_object_lifecycle_300f807e0364] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_5c651238b5c6]. The existing lifecycle evaluator tests rule existence; parameter matching and versioning applicability need a separate predicate.
- pci_4.0_gcp 3.3.2.8: NEW_CHECK [gcp_bucket_there_no_active_lifecycle_configuration_6dc3653afbb8] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_5c651238b5c6]. The existing lifecycle evaluator tests rule existence; parameter matching and versioning applicability need a separate predicate.
- pci_4.0_gcp 3.3.3.8: NEW_CHECK [gcp_bucket_there_no_active_lifecycle_configuration_7e13e019cbdb] -> PARTIAL [gcp.reviewed.storage.lifecycle, gcp_pci_bucket_5c651238b5c6]. The existing lifecycle evaluator tests rule existence; parameter matching and versioning applicability need a separate predicate.
- pci_4.0_gcp 3.5.1.3.20: NEW_CHECK [gcp_sql_instance_ipconfiguration_enablepublicip_field_instance_configura_85b27d7bf244] -> MAPPING_FIX [gcp.claude.sql_instance.private_ip_only]. The Cloud SQL evaluator reads instance IP addresses and rejects a public address.
- pci_4.0_gcp A1.1.3.28: NEW_CHECK [gcp_sql_instance_ipaddresses_field_contains_public_ip_8df193d5c906] -> MAPPING_FIX [gcp.claude.sql_instance.private_ip_only]. The Cloud SQL evaluator reads instance IP addresses and rejects a public address.
- pci_4.0_gcp A1.2.1.7: NEW_CHECK [gcp_bucket_there_no_audit_logs_configured_85a2b8f5edac] -> MAPPING_FIX [gcp.claude.project.storage_data_access_audit_logs]. The project evaluator checks effective Cloud Storage DATA_READ and DATA_WRITE audit configurations.
- pci_4.0_gcp A3.4.1.13: NEW_CHECK [gcp_sql_instance_publicip_field_enabled_instance_configuration_18dec324d2b8] -> MAPPING_FIX [gcp.claude.sql_instance.private_ip_only]. The Cloud SQL evaluator reads instance IP addresses and rejects a public address.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 993 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 1.2.8.33: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 1.2.8.34: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp 1.2.8.35: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f] -> NEW_CHECK [gcp_pci_bucket_56c6b1b7f813]. The no-public-IAM evaluator flags any public binding without checking whether its role permits write, and it omits ACLs.
- pci_4.0_gcp 1.3.1.37: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 1.3.1.38: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp 1.3.1.39: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f] -> NEW_CHECK [gcp_pci_bucket_56c6b1b7f813]. The no-public-IAM evaluator flags any public binding without checking whether its role permits write, and it omits ACLs.
- pci_4.0_gcp 1.3.2.37: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 1.3.2.38: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp 1.3.2.39: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f] -> NEW_CHECK [gcp_pci_bucket_56c6b1b7f813]. The no-public-IAM evaluator flags any public binding without checking whether its role permits write, and it omits ACLs.
- pci_4.0_gcp 1.4.2.35: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 1.4.2.36: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp 1.4.2.37: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f] -> NEW_CHECK [gcp_pci_bucket_56c6b1b7f813]. The no-public-IAM evaluator flags any public binding without checking whether its role permits write, and it omits ACLs.
- pci_4.0_gcp 1.5.1.33: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 1.5.1.34: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp 1.5.1.35: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f] -> NEW_CHECK [gcp_pci_bucket_56c6b1b7f813]. The no-public-IAM evaluator flags any public binding without checking whether its role permits write, and it omits ACLs.
- pci_4.0_gcp 10.2.1.1.17: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.1.2.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.1.3.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.1.4.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.1.5.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.1.6.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.1.7.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.1.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.2.2.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.3.1.14: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 10.3.2.21: MAPPED [gcp.storage.uniform_access, gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 10.3.2.23: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp 10.3.2.24: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f] -> NEW_CHECK [gcp_pci_bucket_56c6b1b7f813]. The no-public-IAM evaluator flags any public binding without checking whether its role permits write, and it omits ACLs.
- pci_4.0_gcp 10.3.3.23: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 10.3.4.8: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 10.3.4.9: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp 10.6.3.18: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 3.5.1.3.26: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp 3.5.1.3.28: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp 5.3.4.16: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp 8.2.2.10: MAPPING_FIX [gcp.claude.secret.rotation_90_days] -> NEW_CHECK [gcp_pci_secret_38dc851e8668]. The evaluator tests configured rotationPeriod and nextRotationTime against a fixed 90 days, not age of the newest secret version against the requested threshold.
- pci_4.0_gcp 8.3.10.1.1: MAPPING_FIX [gcp.ports.iam_service_account_key_age_90] -> NEW_CHECK [gcp_pci_service_account_key_d4f14e7286ba]. The existing evaluator hard-codes 90 days and includes disabled keys; the source specifies a configurable limit for active keys.
- pci_4.0_gcp 8.3.10.1.4: MAPPING_FIX [gcp.claude.secret.rotation_90_days] -> NEW_CHECK [gcp_pci_secret_38dc851e8668]. The evaluator tests configured rotationPeriod and nextRotationTime against a fixed 90 days, not age of the newest secret version against the requested threshold.
- pci_4.0_gcp 8.3.5.1: MAPPING_FIX [gcp.ports.iam_service_account_key_age_90] -> NEW_CHECK [gcp_pci_service_account_key_d4f14e7286ba]. The existing evaluator hard-codes 90 days and includes disabled keys; the source specifies a configurable limit for active keys.
- pci_4.0_gcp 8.3.5.4: MAPPING_FIX [gcp.claude.secret.rotation_90_days] -> NEW_CHECK [gcp_pci_secret_38dc851e8668]. The evaluator tests configured rotationPeriod and nextRotationTime against a fixed 90 days, not age of the newest secret version against the requested threshold.
- pci_4.0_gcp 8.3.7.4: MAPPING_FIX [gcp.claude.secret.rotation_90_days] -> NEW_CHECK [gcp_pci_secret_38dc851e8668]. The evaluator tests configured rotationPeriod and nextRotationTime against a fixed 90 days, not age of the newest secret version against the requested threshold.
- pci_4.0_gcp 8.3.9.1: MAPPING_FIX [gcp.ports.iam_service_account_key_age_90] -> NEW_CHECK [gcp_pci_service_account_key_d4f14e7286ba]. The existing evaluator hard-codes 90 days and includes disabled keys; the source specifies a configurable limit for active keys.
- pci_4.0_gcp 8.3.9.4: MAPPING_FIX [gcp.claude.secret.rotation_90_days] -> NEW_CHECK [gcp_pci_secret_38dc851e8668]. The evaluator tests configured rotationPeriod and nextRotationTime against a fixed 90 days, not age of the newest secret version against the requested threshold.
- pci_4.0_gcp 8.4.3.5: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp 8.6.3.1: MAPPING_FIX [gcp.ports.iam_service_account_key_age_90] -> NEW_CHECK [gcp_pci_service_account_key_d4f14e7286ba]. The existing evaluator hard-codes 90 days and includes disabled keys; the source specifies a configurable limit for active keys.
- pci_4.0_gcp 8.6.3.5: MAPPING_FIX [gcp.claude.secret.rotation_90_days] -> NEW_CHECK [gcp_pci_secret_38dc851e8668]. The evaluator tests configured rotationPeriod and nextRotationTime against a fixed 90 days, not age of the newest secret version against the requested threshold.
- pci_4.0_gcp A1.1.2.17: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp A1.1.2.19: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp A1.2.1.18: MAPPING_FIX [gcp.claude.gke.logging_enabled] -> PARTIAL [gcp.claude.gke.logging_enabled, gcp_pci_gke_cluster_58029a84da74]. The mapped evaluator only checks loggingService != none; it does not examine loggingConfig components.
- pci_4.0_gcp A1.2.1.31: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp A3.4.1.19: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05]. The existing IAM check ignores the exclusion parameter and bucket ACL grants; on an excluded bucket it may return a false failure.
- pci_4.0_gcp A3.4.1.21: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_12b4d5154449] -> NEW_CHECK [gcp_pci_bucket_157fb0c69361]. The no-public-IAM evaluator flags any public binding without checking whether its role permits read, and it omits ACLs.
- pci_4.0_gcp A3.4.1.22: PARTIAL [gcp.storage.no_public_iam, gcp_pci_bucket_cce54cebe63f] -> NEW_CHECK [gcp_pci_bucket_56c6b1b7f813]. The no-public-IAM evaluator flags any public binding without checking whether its role permits write, and it omits ACLs.
- gcp-compliance.benchmark.pci_dss_v321 gcp-compliance.control.kms_key_users_limited_to_3: MAPPED [gcp.claude.kms_key.users_limited_to_3] -> NEW_CHECK [gcp_pci_kms_key_a3927a5f3b84]. The mapped evaluator limits each binding to three members; four distinct users spread over bindings pass incorrectly.
- gcp-compliance.benchmark.pci_dss_v321 gcp-compliance.control.compute_ssl_policy_with_no_weak_cipher: MAPPED [gcp.ports.compute_ssl_policy_strict_declaration] -> PARTIAL [gcp.ports.compute_ssl_policy_strict_declaration, gcp_pci_ssl_policy_c29b7d3f998a]. The existing check imposes a strict profile and TLS minimum as well as cipher criteria; it can fail policies solely for those extra conditions.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 1000 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 1.3.1.32: MAPPING_FIX [gcp.reviewed.bigquery.no_public_acl] -> NEW_CHECK [gcp_pci_bigquery_dataset_6017267cdf32]. The existing evaluator flags any public role, so it can fail grants outside the stated READER/WRITER predicate.
- pci_4.0_gcp 1.5.1.29: MAPPED [gcp.reviewed.bigquery.no_public_acl] -> NEW_CHECK [gcp_pci_bigquery_dataset_fb9fcc01d5b7]. The existing evaluator also flags allAuthenticatedUsers; the source condition names allUsers only.
- pci_4.0_gcp 10.3.2.21: NEW_CHECK [gcp_pci_bucket_7dc6cb8c2e05] -> MAPPING_FIX [gcp.storage.uniform_access]. The bucket evaluator checks iamConfiguration.uniformBucketLevelAccess.enabled.
- pci_4.0_gcp 3.5.1.3.22: MAPPED [gcp.reviewed.bigquery.no_public_acl] -> NEW_CHECK [gcp_pci_bigquery_dataset_fb9fcc01d5b7]. The existing evaluator also flags allAuthenticatedUsers; the source condition names allUsers only.
- pci_4.0_gcp 3.5.1.3.29: MAPPED [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> NEW_CHECK [gcp_pci_bucket_ce6174bae04a]. The mapped public-IAM check does not distinguish read/write permission, and uniform access alone is not a public-grant decision.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp A1.1.2.18: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_4df2f1a70b3b]. The versioning evaluator does not inspect IAM permissions for version deletion.
- pci_4.0_gcp A1.1.2.20: MAPPING_FIX [gcp.storage.uniform_access] -> NEW_CHECK [gcp_pci_bucket_ce6174bae04a]. The mapped public-IAM check does not distinguish read/write permission, and uniform access alone is not a public-grant decision.
- pci_4.0_gcp A1.1.3.34: MAPPING_FIX [gcp.storage.no_public_iam, gcp.storage.uniform_access] -> NEW_CHECK [gcp_pci_bucket_4f5bd326cf57]. The mapped public-IAM check does not distinguish read/write permission, and uniform access alone is not a public-grant decision.
- pci_4.0_gcp A1.1.3.35: MAPPING_FIX [gcp.storage.no_public_iam, gcp.storage.public_access_prevention] -> NEW_CHECK [gcp_pci_bucket_ce6174bae04a]. The mapped public-IAM check does not distinguish read/write permission, and uniform access alone is not a public-grant decision.
- pci_4.0_gcp A3.4.1.20: MAPPING_FIX [gcp.reviewed.storage.versioning] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- gcp-compliance.benchmark.pci_dss_v321 gcp-compliance.control.allow_only_private_cluster: MAPPED [gcp.gke.private_endpoint] -> NEW_CHECK [gcp_pci_gke_cluster_3fcab9461e74]. The mapped evaluator can pass when enablePublicEndpoint=true and legacy enablePrivateEndpoint=true, which is not a reliable private-only result.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 1000 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 1.2.5.1: NEW_CHECK [gcp_url_map_http_s_load_balancers_do_983ce08ada71] -> NEW_CHECK [gcp_pci_url_map_9ed56c323a05]. A URL map alone cannot establish which HTTP frontend uses it; all forwarding rules and path matches must be joined.
- pci_4.0_gcp 1.2.5.3: NEW_CHECK [gcp_target_proxy_checks_cdn_configurations_using_minimum_6da9a9170f0f] -> PARTIAL [gcp.claude.target_proxy.https_min_tls_1_2, gcp_pci_backend_service_2ce96d36d0bf]. The existing proxy evaluator checks TLS minimum, but does not select only proxies serving CDN-enabled backends.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp 12.8.3.1: NEW_CHECK [gcp_asset_checks_that_gemini_api_k_9ef2e8a119a3] -> MAPPING_FIX [gcp.claude.project.gemini_api_disabled]. The project evaluator reads the Generative Language service state and fails when enabled.
- pci_4.0_gcp 12.8.4.1: NEW_CHECK [gcp_asset_checks_that_gemini_api_k_9ef2e8a119a3] -> MAPPING_FIX [gcp.claude.project.gemini_api_disabled]. The project evaluator reads the Generative Language service state and fails when enabled.
- pci_4.0_gcp 12.9.1.1: NEW_CHECK [gcp_asset_checks_that_gemini_api_k_9ef2e8a119a3] -> MAPPING_FIX [gcp.claude.project.gemini_api_disabled]. The project evaluator reads the Generative Language service state and fails when enabled.
- pci_4.0_gcp A1.1.3.33: MAPPING_FIX [gcp.storage.no_public_iam] -> NEW_CHECK [gcp_pci_bucket_a39e3e569bc4]. The existing evaluator ignores the stated exclusion criterion and does not inspect ACL grants.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 984 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 1.2.8.25: NEW_CHECK [gcp_subnetwork_route_internet_gateway_igw_has_c153694f9610] -> NEW_CHECK [gcp_pci_route_7798738c4a25]. Routes are collected as route resources; subnetwork/network/router metadata does not hold the route destination predicate.
- pci_4.0_gcp 1.3.1.28: NEW_CHECK [gcp_network_route_internet_gateway_has_destination_1a36ed6192e0] -> NEW_CHECK [gcp_pci_route_7798738c4a25]. Routes are collected as route resources; subnetwork/network/router metadata does not hold the route destination predicate.
- pci_4.0_gcp 1.4.1.6: NEW_CHECK [gcp_network_there_route_router_vpn_gateway_c0cce3785f8e] -> NEW_CHECK [gcp_pci_route_7798738c4a25]. Routes are collected as route resources; subnetwork/network/router metadata does not hold the route destination predicate.
- pci_4.0_gcp 1.4.2.26: NEW_CHECK [gcp_network_route_igw_has_destination_cidr_502c66ae5b93] -> NEW_CHECK [gcp_pci_route_7798738c4a25]. Routes are collected as route resources; subnetwork/network/router metadata does not hold the route destination predicate.
- pci_4.0_gcp 10.2.1.1.5: NEW_CHECK [gcp_target_proxy_gclb_desync_mitigation_mode_does_ce75fa5619cb] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 10.2.1.2.5: NEW_CHECK [gcp_target_proxy_session_affinity_setting_does_match_91aa53cc5cba] -> NEW_CHECK [gcp_pci_backend_service_a6db2acca805]. Session affinity is a backend service field, not a target proxy field.
- pci_4.0_gcp 10.2.1.3.5: NEW_CHECK [gcp_target_proxy_load_balancer_desync_mitigation_mode_6c01286ca184] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 10.2.1.3.16: NEW_CHECK [gcp_target_proxy_logbucket_set_does_match_fca2293e0cfa] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.2.1.4.5: NEW_CHECK [gcp_target_proxy_gclb_desync_mitigation_mode_does_834187f8c56a] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 10.2.1.4.16: NEW_CHECK [gcp_target_proxy_logging_disabled_logbucket_equal_specified_bd048b9b9a28] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.2.1.5.5: NEW_CHECK [gcp_target_proxy_http_s_load_balancer_desync_2f557dbdd10c] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 10.2.1.6.5: NEW_CHECK [gcp_target_proxy_https_load_balancer_s_desync_bd34f543960c] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 10.2.1.7.5: NEW_CHECK [gcp_target_proxy_load_balancer_s_desync_mitigation_9a2638eb21e6] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 10.2.1.5: NEW_CHECK [gcp_target_proxy_http_s_load_balancer_desync_fb81a4493360] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 10.2.2.16: NEW_CHECK [gcp_target_proxy_loggingconfig_enable_logbucket_equal_b4b371e5fe1f] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.3.1.5: NEW_CHECK [gcp_target_proxy_load_balancer_desync_mitigation_mode_d4b8ba25a686] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 5.3.4.5: NEW_CHECK [gcp_target_proxy_nlb_desync_mitigation_mode_does_fe5a3dde5f2a] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp A1.2.1.5: NEW_CHECK [gcp_target_proxy_load_balancer_s_desync_mitigation_c92c4fb256a5] -> NOT_APPLICABLE []. Desync mitigation mode is an AWS ALB/NLB attribute; Compute target proxies, URL maps and backend services expose no such GCP property to compare with the supplied mode.
- pci_4.0_gcp A1.2.1.20: NEW_CHECK [gcp_target_proxy_logging_property_logbucket_equal_provided_4b5cc593406d] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 933 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 10.2.1.1.1: NEW_CHECK [gcp_log_sink_accesslogs_present_api_configuration_843984175b80] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.1.2: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_7e3357b658ac] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.1.14: NEW_CHECK [gcp_log_sink_loggingenabled_set_99d65e9b2a48] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 10.2.1.1.18: NEW_CHECK [gcp_log_sink_value_enablestackdriverlogging_2a1911e2f205] -> NOT_APPLICABLE []. App Engine has no enableStackdriverLogging configuration field; automatic service logging and sink export are different predicates.
- pci_4.0_gcp 10.2.1.1.21: NEW_CHECK [gcp_log_sink_service_does_have_logging_enabled_705a739dfccd] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.2.1.1.32: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.2.1.1.35: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_a50dd16eaa32] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.1.36: NEW_CHECK [gcp_log_sink_loggingenabled_field_set_71c764259525] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.1.37: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_3b0df9d247f6] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.2.1: NEW_CHECK [gcp_log_sink_accesslogs_configuration_present_endpoints_settings_f7915ce3906d] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.2.2: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_neither_error_1b148a5e7c6b] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.2.4: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_set_neither_a54f465e7e89] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.2.9: NEW_CHECK [gcp_log_sink_all_logging_options_set_disabled_fa67f1980819] -> NEW_CHECK [gcp_pci_cloudbuild_trigger_bd17d32ea0a5]. Build logging is a trigger/build option, not a Cloud Logging sink field.
- pci_4.0_gcp 10.2.1.2.12: NEW_CHECK [gcp_log_sink_logging_set_d150bd2ab8af] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 10.2.1.2.15: NEW_CHECK [gcp_log_sink_value_enablestackdriverlogging_2a1911e2f205] -> NOT_APPLICABLE []. App Engine has no enableStackdriverLogging configuration field; automatic service logging and sink export are different predicates.
- pci_4.0_gcp 10.2.1.2.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_dc714e83d21b] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.2.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_7b8f61b2ba3f] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.3.1: NEW_CHECK [gcp_log_sink_accesslog_settings_present_openapi_configuration_6de827f340b2] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.3.2: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_neither_error_1b148a5e7c6b] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.3.15: NEW_CHECK [gcp_log_sink_value_enablestackdriverlogging_2a1911e2f205] -> NOT_APPLICABLE []. App Engine has no enableStackdriverLogging configuration field; automatic service logging and sink export are different predicates.
- pci_4.0_gcp 10.2.1.3.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_a50dd16eaa32] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.3.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_7b8f61b2ba3f] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.4.1: NEW_CHECK [gcp_log_sink_accesslogs_configured_service_s_endpoint_548fa27bf1ae] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.4.2: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_7e3357b658ac] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.4.4: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_neither_error_0a6ed125d109] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.4.9: NEW_CHECK [gcp_log_sink_status_all_present_log_configurations_2c9dcc8c036e] -> NEW_CHECK [gcp_pci_cloudbuild_trigger_bd17d32ea0a5]. Build logging is a trigger/build option, not a Cloud Logging sink field.
- pci_4.0_gcp 10.2.1.4.12: NEW_CHECK [gcp_log_sink_logconfig_enabled_set_ed457d245744] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 10.2.1.4.15: NEW_CHECK [gcp_log_sink_value_enablestackdriverlogging_2a1911e2f205] -> NOT_APPLICABLE []. App Engine has no enableStackdriverLogging configuration field; automatic service logging and sink export are different predicates.
- pci_4.0_gcp 10.2.1.4.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_1f21332bb11e] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.4.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_armor_security_07f850787f9d] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.5.2: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_d8aa6e71f505] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.5.4: NEW_CHECK [gcp_log_sink_logging_enabled_log_level_set_6bd883686f2d] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.5.12: NEW_CHECK [gcp_log_sink_loggingenabled_set_vpn_configuration_ec9fe60bf72e] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 10.2.1.5.18: NEW_CHECK [gcp_log_sink_pub_sub_service_does_have_0740c1f22df1] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.2.1.5.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_0e326a4b0b56] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.5.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_3b0df9d247f6] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.6.1: NEW_CHECK [gcp_log_sink_accesslogs_settings_present_endpoints_configuration_c9138d382da4] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.6.2: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_0d02ef6601d6] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.6.12: NEW_CHECK [gcp_log_sink_tunnel_logging_set_46e5e29c65e0] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 10.2.1.6.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_fce76f2a68ef] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.6.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_3b0df9d247f6] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.7.1: NEW_CHECK [gcp_log_sink_accesslogsettings_present_service_configuration_375e57e49df3] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.7.2: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_d8aa6e71f505] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.7.4: NEW_CHECK [gcp_log_sink_logging_enabled_log_level_set_9a3c534b2a56] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.7.15: NEW_CHECK [gcp_log_sink_value_enablestackdriverlogging_81f9c9e86bcd] -> NOT_APPLICABLE []. App Engine has no enableStackdriverLogging configuration field; automatic service logging and sink export are different predicates.
- pci_4.0_gcp 10.2.1.7.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_4226809aef3b] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.7.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_3b0df9d247f6] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.1: NEW_CHECK [gcp_log_sink_accesslogs_present_api_configuration_c862c5250392] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.2: NEW_CHECK [gcp_log_sink_logging_enabled_log_level_neither_90669f72ae62] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.4: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_neither_error_0a6ed125d109] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.1.9: NEW_CHECK [gcp_log_sink_status_all_present_log_configurations_2c9dcc8c036e] -> NEW_CHECK [gcp_pci_cloudbuild_trigger_bd17d32ea0a5]. Build logging is a trigger/build option, not a Cloud Logging sink field.
- pci_4.0_gcp 10.2.1.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_c798861842ce] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.1.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_3b0df9d247f6] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.2.1: NEW_CHECK [gcp_log_sink_accesslog_settings_present_api_configuration_78c51d8803b5] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.2.2: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_d8aa6e71f505] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.2.4: NEW_CHECK [gcp_log_sink_logging_enabled_log_level_neither_bca83b35e683] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.2.2.12: NEW_CHECK [gcp_log_sink_logconfig_enabled_set_ed457d245744] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 10.2.2.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_a50dd16eaa32] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.2.2.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_3b0df9d247f6] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.3.1.1: NEW_CHECK [gcp_log_sink_accesslogs_present_endpoints_configuration_0fcb7506dd38] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.3.1.2: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_7e3357b658ac] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.3.1.30: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_1f21332bb11e] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.3.1.31: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_3b0df9d247f6] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.4.1.1.6: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.4.1.5: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.4.2.6: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.6.3.1: NEW_CHECK [gcp_log_sink_accesslogsettings_present_api_gateway_configuration_b24988e1aa1d] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.6.3.2: NEW_CHECK [gcp_log_sink_logging_enabled_logginglevel_neither_error_a7219bb296d4] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.6.3.4: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_neither_error_db1d7cb24903] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 10.6.3.11: NEW_CHECK [gcp_log_sink_status_all_present_log_configurations_2c9dcc8c036e] -> NEW_CHECK [gcp_pci_cloudbuild_trigger_bd17d32ea0a5]. Build logging is a trigger/build option, not a Cloud Logging sink field.
- pci_4.0_gcp 10.6.3.14: NEW_CHECK [gcp_log_sink_logconfig_loggingenabled_set_20dd5a011792] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 10.6.3.19: NEW_CHECK [gcp_log_sink_value_enablestackdriverlogging_2a1911e2f205] -> NOT_APPLICABLE []. App Engine has no enableStackdriverLogging configuration field; automatic service logging and sink export are different predicates.
- pci_4.0_gcp 10.6.3.37: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.6.3.40: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_2a84e9f50b42] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.6.3.42: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_7b8f61b2ba3f] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 10.7.1.7: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 10.7.2.7: NEW_CHECK [gcp_log_sink_delivery_status_notifications_messages_enabled_49ee175a8f88] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 11.5.2.6: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 11.6.1.6: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 12.10.5.6: NEW_CHECK [gcp_log_sink_delivery_status_notifications_messages_enabled_cded0cfb0a43] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 5.3.4.2: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_neither_error_1b148a5e7c6b] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 5.3.4.4: NEW_CHECK [gcp_log_sink_logging_enabled_log_level_set_e4ec0de0d792] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp 5.3.4.14: NEW_CHECK [gcp_log_sink_loggingenabled_set_99d65e9b2a48] -> NOT_APPLICABLE []. Cloud VPN tunnel metadata has no per-tunnel loggingEnabled/logConfig.enabled toggle; a Logging sink cannot evaluate this source predicate.
- pci_4.0_gcp 5.3.4.21: NEW_CHECK [gcp_log_sink_audit_logging_enabled_d33fc4f3edc9] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp 5.3.4.35: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_0e326a4b0b56] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 5.3.4.36: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_b294132a5f0e] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp A1.2.1.1: NEW_CHECK [gcp_log_sink_accesslogsettings_present_service_configuration_375e57e49df3] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp A1.2.1.2: NEW_CHECK [gcp_log_sink_logging_enabled_log_level_neither_541762742499] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp A1.2.1.4: NEW_CHECK [gcp_log_sink_logging_enabled_loglevel_neither_error_503e1494c28c] -> NOT_APPLICABLE []. The described Endpoints/API Gateway per-method accessLogs or logLevel toggle is not a Cloud Logging sink property or a native configuration field on that GCP service; log presence cannot prove the proposed setting.
- pci_4.0_gcp A1.2.1.19: NEW_CHECK [gcp_log_sink_value_enablestackdriverlogging_2a1911e2f205] -> NOT_APPLICABLE []. App Engine has no enableStackdriverLogging configuration field; automatic service logging and sink export are different predicates.
- pci_4.0_gcp A1.2.1.35: NEW_CHECK [gcp_log_sink_logging_enabled_but_destination_eae6ae18cbca] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp A1.2.1.36: NEW_CHECK [gcp_log_sink_checks_logging_enabled_on_armor_7b8f61b2ba3f] -> NEW_CHECK [gcp_pci_backend_service_571fd0bfec67]. Cloud Armor policy does not own the request logging toggle; attached backend services do.
- pci_4.0_gcp A3.3.1.10: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.
- pci_4.0_gcp A3.5.1.10: NEW_CHECK [gcp_log_sink_delivery_status_notification_messages_enabled_07bc472f0ca8] -> NOT_APPLICABLE []. Pub/Sub has no service-wide Stackdriver logging or notification-delivery-status toggle on a topic/subscription; sink presence is not that predicate.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 894 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 10.2.1.1.10: NEW_CHECK [gcp_log_sink_equivalence_ensuring_logging_enabled_audit_2a0a985172e0] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.1.1.22: NEW_CHECK [gcp_log_sink_platform_equivalent_service_aws_cloudtrail_e19de05916ae] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.2.1.1.33: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.1.2.8: NEW_CHECK [gcp_log_sink_s_equivalent_rule_ensure_that_92cca830ec4b] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.1.2.10: NEW_CHECK [gcp_log_sink_logging_enabled_replication_task_12b7c12b495b] -> NOT_APPLICABLE []. The source describes per-job loggingEnabled/severity configuration not present on a GCP Database Migration Service migration job; a Logging sink cannot determine it.
- pci_4.0_gcp 10.2.1.2.19: NEW_CHECK [gcp_log_sink_platform_equivalent_service_aws_cloudtrail_30e0bb319378] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.2.1.2.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.1.3.8: NEW_CHECK [gcp_log_sink_equivalence_aws_rule_trail_enabled_05c63f0bba5a] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.1.3.10: NEW_CHECK [gcp_log_sink_logging_enabled_replication_task_12b7c12b495b] -> NOT_APPLICABLE []. The source describes per-job loggingEnabled/severity configuration not present on a GCP Database Migration Service migration job; a Logging sink cannot determine it.
- pci_4.0_gcp 10.2.1.3.19: NEW_CHECK [gcp_log_sink_platform_equivalent_service_aws_cloudtrail_5e71a04ea606] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.2.1.3.20: NEW_CHECK [gcp_log_sink_spanner_instance_does_have_stackdriver_128ae5736582] -> NEW_CHECK [gcp_pci_iam_policy_ca1281da7ab2]. Spanner audit logging is an IAM audit configuration at resource hierarchy scope, not a Spanner instance log-sink toggle.
- pci_4.0_gcp 10.2.1.3.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.1.4.19: NEW_CHECK [gcp_log_sink_rule_multi_region_trail_enabled_7e2e1cc6aa50] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.2.1.4.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.1.5.8: NEW_CHECK [gcp_log_sink_platform_equivalent_aws_cloudtrail_audit_6413f583af19] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.1.5.19: NEW_CHECK [gcp_log_sink_equivalent_enabling_multi_region_logging_1bc71bdaae20] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.2.1.5.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.1.6.8: NEW_CHECK [gcp_log_sink_logging_must_be_enabled_operational_bc9ae8bd037e] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.1.6.10: NEW_CHECK [gcp_log_sink_logging_enabled_migration_job_c56eaf598bbf] -> NOT_APPLICABLE []. The source describes per-job loggingEnabled/severity configuration not present on a GCP Database Migration Service migration job; a Logging sink cannot determine it.
- pci_4.0_gcp 10.2.1.6.19: NEW_CHECK [gcp_log_sink_equivalent_service_aws_cloudtrail_audit_cf63feb1e2db] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.2.1.6.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.1.7.8: NEW_CHECK [gcp_log_sink_equivalent_enabling_aws_cloudtrail_would_9361872fff54] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.1.7.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.1.8: NEW_CHECK [gcp_log_sink_platform_equivalent_aws_cloudtrail_audit_016365a0388a] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.1.18: NEW_CHECK [gcp_log_sink_service_does_have_audit_logging_8dec09a343f3] -> NEW_CHECK [gcp_pci_iam_policy_9a8ce875703d]. Pub/Sub audit log configuration is an IAM auditConfig, not a topic/subscription or log-sink toggle.
- pci_4.0_gcp 10.2.1.20: NEW_CHECK [gcp_log_sink_spanner_instance_does_have_logging_4aee634d2a48] -> NEW_CHECK [gcp_pci_iam_policy_ca1281da7ab2]. Spanner audit logging is an IAM audit configuration at resource hierarchy scope, not a Spanner instance log-sink toggle.
- pci_4.0_gcp 10.2.1.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.2.2.8: NEW_CHECK [gcp_log_sink_equivalent_enabling_audit_logs_project_49d347711c5d] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.2.2.10: NEW_CHECK [gcp_log_sink_logging_enabled_replication_task_d4462e48a55b] -> NOT_APPLICABLE []. The source describes per-job loggingEnabled/severity configuration not present on a GCP Database Migration Service migration job; a Logging sink cannot determine it.
- pci_4.0_gcp 10.2.2.18: NEW_CHECK [gcp_log_sink_service_does_have_audit_logging_8dec09a343f3] -> NEW_CHECK [gcp_pci_iam_policy_9a8ce875703d]. Pub/Sub audit log configuration is an IAM auditConfig, not a topic/subscription or log-sink toggle.
- pci_4.0_gcp 10.2.2.19: NEW_CHECK [gcp_log_sink_platform_equivalent_enabling_multi_region_7d59766a1df0] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.2.2.20: NEW_CHECK [gcp_log_sink_spanner_instance_does_have_stackdriver_de803e97a15a] -> NEW_CHECK [gcp_pci_iam_policy_ca1281da7ab2]. Spanner audit logging is an IAM audit configuration at resource hierarchy scope, not a Spanner instance log-sink toggle.
- pci_4.0_gcp 10.2.2.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.3.1.8: NEW_CHECK [gcp_log_sink_equivalent_rule_trail_enabled_ensure_456035bc2fca] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.3.1.19: NEW_CHECK [gcp_log_sink_equivalent_enabling_multi_region_logging_cc599acbe7c1] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 10.3.1.20: NEW_CHECK [gcp_log_sink_spanner_instance_does_have_stackdriver_de803e97a15a] -> NEW_CHECK [gcp_pci_iam_policy_ca1281da7ab2]. Spanner audit logging is an IAM audit configuration at resource hierarchy scope, not a Spanner instance log-sink toggle.
- pci_4.0_gcp 10.3.1.28: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_6015df51ffcc] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 10.3.2.2: NEW_CHECK [gcp_log_sink_checks_that_there_at_least_90c649944d29] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.3.3.4: NEW_CHECK [gcp_log_sink_checks_that_there_at_least_d03e3b6dc701] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.3.4.3: NEW_CHECK [gcp_log_sink_checks_that_there_at_least_367097b8674a] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.3.4.6: NEW_CHECK [gcp_log_sink_integrity_checking_enabled_43686410bbeb] -> NOT_APPLICABLE []. Cloud Audit Logs expose no CloudTrail-style per-trail integrity validation toggle; a Logging sink has no such setting.
- pci_4.0_gcp 10.5.1.3: NEW_CHECK [gcp_log_sink_checks_that_there_at_least_52d6e074e83c] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.5.1.4: NEW_CHECK [gcp_log_sink_retention_period_less_than_minretentiontime_cb55f0dd7f28] -> NEW_CHECK [gcp_pci_asset_6ee2fef37d98]. The collector lists log sinks, not LogBucket.retentionDays; the requirement needs the logging buckets API.
- pci_4.0_gcp 10.6.3.10: NEW_CHECK [gcp_log_sink_this_rule_checks_audit_logs_7077b48bb0c1] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 10.6.3.22: NEW_CHECK [gcp_log_sink_pub_sub_does_have_audit_0b3727e648ae] -> NEW_CHECK [gcp_pci_iam_policy_9a8ce875703d]. Pub/Sub audit log configuration is an IAM auditConfig, not a topic/subscription or log-sink toggle.
- pci_4.0_gcp 10.6.3.38: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_eaa49fde5293] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 11.5.2.4: NEW_CHECK [gcp_log_sink_log_sink_set_up_does_b12aa5800f01] -> NOT_APPLICABLE []. Cloud Audit Logs are written to Cloud Logging by the platform; there is no separate export sink needed to send them there.
- pci_4.0_gcp 11.6.1.4: NEW_CHECK [gcp_log_sink_corresponding_sink_creating_logs_logging_1e33511211bd] -> NOT_APPLICABLE []. Cloud Audit Logs are written to Cloud Logging by the platform; there is no separate export sink needed to send them there.
- pci_4.0_gcp 12.10.5.4: NEW_CHECK [gcp_log_sink_log_sink_configured_export_logs_66ae40b0d347] -> NOT_APPLICABLE []. Cloud Audit Logs are written to Cloud Logging by the platform; there is no separate export sink needed to send them there.
- pci_4.0_gcp 3.3.1.3.3: NEW_CHECK [gcp_log_sink_retention_period_less_than_minretentiontime_cb55f0dd7f28] -> NEW_CHECK [gcp_pci_asset_6ee2fef37d98]. The collector lists log sinks, not LogBucket.retentionDays; the requirement needs the logging buckets API.
- pci_4.0_gcp 5.3.4.8: NEW_CHECK [gcp_log_sink_checks_that_there_at_least_b3779aaf708c] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 5.3.4.9: NEW_CHECK [gcp_log_sink_logging_must_be_enabled_ensure_cf0dabe4c575] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp 5.3.4.11: NEW_CHECK [gcp_log_sink_retention_period_less_than_minretentiontime_cb55f0dd7f28] -> NEW_CHECK [gcp_pci_asset_6ee2fef37d98]. The collector lists log sinks, not LogBucket.retentionDays; the requirement needs the logging buckets API.
- pci_4.0_gcp 5.3.4.12: NEW_CHECK [gcp_log_sink_logging_enabled_replication_task_12b7c12b495b] -> NOT_APPLICABLE []. The source describes per-job loggingEnabled/severity configuration not present on a GCP Database Migration Service migration job; a Logging sink cannot determine it.
- pci_4.0_gcp 5.3.4.22: NEW_CHECK [gcp_log_sink_enabling_audit_logging_across_multiple_632c01d19c91] -> NOT_APPLICABLE []. Cloud Audit Logs have no CloudTrail-style per-region trail or multi-region enablement setting; the named comparison is not a GCP log-sink predicate.
- pci_4.0_gcp 5.3.4.33: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_eaa49fde5293] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp A1.2.1.8: NEW_CHECK [gcp_log_sink_checks_that_there_at_least_fd08b35e0f60] -> NEW_CHECK [gcp_pci_iam_policy_994a955563df]. Cloud Audit Logs Data Access configuration is in IAM auditConfigs; a Logging sink alone is not evidence that audit logging is enabled.
- pci_4.0_gcp A1.2.1.12: NEW_CHECK [gcp_log_sink_validation_enabled_57bfb5f87602] -> NOT_APPLICABLE []. Cloud Audit Logs expose no CloudTrail-style per-trail integrity validation toggle; a Logging sink has no such setting.
- pci_4.0_gcp A1.2.1.14: NEW_CHECK [gcp_log_sink_logging_enabled_replication_task_12b7c12b495b] -> NOT_APPLICABLE []. The source describes per-job loggingEnabled/severity configuration not present on a GCP Database Migration Service migration job; a Logging sink cannot determine it.
- pci_4.0_gcp A1.2.1.24: NEW_CHECK [gcp_log_sink_spanner_instance_does_have_stackdriver_de803e97a15a] -> NEW_CHECK [gcp_pci_iam_policy_ca1281da7ab2]. Spanner audit logging is an IAM audit configuration at resource hierarchy scope, not a Spanner instance log-sink toggle.
- pci_4.0_gcp A1.2.1.33: NEW_CHECK [gcp_log_sink_workflow_does_have_logging_enabled_2a5ab0395561] -> NEW_CHECK [gcp_pci_asset_d4f2c55a3210]. A Logging sink does not expose the workflow call logging configuration; read the Workflow resource.
- pci_4.0_gcp A3.3.1.6: NEW_CHECK [gcp_log_sink_log_sink_properly_set_up_25ce45979640] -> NOT_APPLICABLE []. Cloud Audit Logs are written to Cloud Logging by the platform; there is no separate export sink needed to send them there.
- pci_4.0_gcp A3.5.1.6: NEW_CHECK [gcp_log_sink_log_sink_properly_set_export_2383f6ef6dc6] -> NOT_APPLICABLE []. Cloud Audit Logs are written to Cloud Logging by the platform; there is no separate export sink needed to send them there.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 881 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 10.2.1.3.12: NEW_CHECK [gcp_log_sink_iapsettings_clientconnectionlogenabled_set_a710e7e3c487] -> NOT_APPLICABLE []. IapSettings.clientConnectionLogEnabled is not a native IAP setting; a Logging sink does not supply the requested toggle.
- pci_4.0_gcp 10.2.1.5.1: NEW_CHECK [gcp_log_sink_logs_configuration_present_endpoints_settings_5f82d6ccad3e] -> NOT_APPLICABLE []. The named Endpoints/API Gateway logs or access_log configuration field is not a native GCP API configuration or Logging sink property.
- pci_4.0_gcp 10.2.1.5.15: NEW_CHECK [gcp_log_sink_log_routing_settings_do_include_824d6f27236f] -> NOT_APPLICABLE []. The described App Engine serviceAccountManaged/logSeverity/logHealthChecks or per-service Cloud Logging export switch is not a native service field; sink inventory cannot establish it.
- pci_4.0_gcp 10.2.1.5.21: NEW_CHECK [gcp_log_sink_logging_type_configured_41e7a038444b] -> NEW_CHECK [gcp_pci_iam_policy_27e6a804202b]. The service logging type is an audit configuration, not a Logging sink field.
- pci_4.0_gcp 10.2.1.6.15: NEW_CHECK [gcp_log_sink_logging_configuration_set_df3f6af96cec] -> NOT_APPLICABLE []. The described App Engine serviceAccountManaged/logSeverity/logHealthChecks or per-service Cloud Logging export switch is not a native service field; sink inventory cannot establish it.
- pci_4.0_gcp 10.2.1.12: NEW_CHECK [gcp_log_sink_logging_enabled_set_ec2d3bb4252c] -> NOT_APPLICABLE []. The source requires a per-tunnel connection logging switch that Cloud VPN does not expose; sink inventory cannot prove it.
- pci_4.0_gcp 10.2.1.15: NEW_CHECK [gcp_log_sink_value_serviceaccountmanaged_0f0b82f07d2f] -> NOT_APPLICABLE []. The described App Engine serviceAccountManaged/logSeverity/logHealthChecks or per-service Cloud Logging export switch is not a native service field; sink inventory cannot establish it.
- pci_4.0_gcp 10.2.2.9: NEW_CHECK [gcp_log_sink_status_all_present_logging_configurations_fa5a491fab92] -> NEW_CHECK [gcp_pci_cloudbuild_trigger_3302edf7cb18]. Cloud Build logging is a build/trigger option, not a Logging sink field.
- pci_4.0_gcp 10.2.2.15: NEW_CHECK [gcp_log_sink_value_logseverity_set_configured_40e7f8bb3dea] -> NOT_APPLICABLE []. The described App Engine serviceAccountManaged/logSeverity/logHealthChecks or per-service Cloud Logging export switch is not a native service field; sink inventory cannot establish it.
- pci_4.0_gcp 10.3.1.4: NEW_CHECK [gcp_log_sink_logging_enabled_level_neither_401738eec26f] -> NOT_APPLICABLE []. The named Endpoints/API Gateway logs or access_log configuration field is not a native GCP API configuration or Logging sink property.
- pci_4.0_gcp 10.3.1.15: NEW_CHECK [gcp_log_sink_services_set_enable_logging_1bf2a8eb2f00] -> NOT_APPLICABLE []. The described App Engine serviceAccountManaged/logSeverity/logHealthChecks or per-service Cloud Logging export switch is not a native service field; sink inventory cannot establish it.
- pci_4.0_gcp 10.3.2.3: NEW_CHECK [gcp_log_sink_log_bucket_encrypted_cmek_a38e8dd83486] -> NEW_CHECK [gcp_pci_asset_b586c1e48fc8]. A Logging sink does not hold the destination bucket CMEK configuration.
- pci_4.0_gcp 10.6.3.24: NEW_CHECK [gcp_log_sink_equivalent_rule_identifier_multi_region_7e42a8180099] -> NOT_APPLICABLE []. Cloud Audit Logs have no AWS multi-region trail toggle; a GCP Logging sink cannot evaluate it.
- pci_4.0_gcp 3.2.1.3: NEW_CHECK [gcp_log_sink_retention_period_less_than_minretentiontime_cb55f0dd7f28] -> NEW_CHECK [gcp_pci_asset_ad3275f816e6]. The collector lists sinks, not Cloud Logging bucket retention metadata.
- pci_4.0_gcp 3.3.1.1.3: NEW_CHECK [gcp_log_sink_retention_period_less_than_minretentiontime_cb55f0dd7f28] -> NEW_CHECK [gcp_pci_asset_ad3275f816e6]. The collector lists sinks, not Cloud Logging bucket retention metadata.
- pci_4.0_gcp 3.3.2.3: NEW_CHECK [gcp_log_sink_retention_period_less_than_minretentiontime_cb55f0dd7f28] -> NEW_CHECK [gcp_pci_asset_ad3275f816e6]. The collector lists sinks, not Cloud Logging bucket retention metadata.
- pci_4.0_gcp 3.3.3.3: NEW_CHECK [gcp_log_sink_retention_period_less_than_minretentiontime_cb55f0dd7f28] -> NEW_CHECK [gcp_pci_asset_ad3275f816e6]. The collector lists sinks, not Cloud Logging bucket retention metadata.
- pci_4.0_gcp 5.3.4.1: NEW_CHECK [gcp_log_sink_access_log_present_api_configuration_9c9946edfbfe] -> NOT_APPLICABLE []. The named Endpoints/API Gateway logs or access_log configuration field is not a native GCP API configuration or Logging sink property.
- pci_4.0_gcp 5.3.4.18: NEW_CHECK [gcp_log_sink_value_loghealthchecks_1498e6af7a22] -> NOT_APPLICABLE []. The described App Engine serviceAccountManaged/logSeverity/logHealthChecks or per-service Cloud Logging export switch is not a native service field; sink inventory cannot establish it.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.
- pci_4.0_gcp A1.2.1.13: NEW_CHECK [gcp_log_sink_status_all_present_logging_configurations_fa5a491fab92] -> NEW_CHECK [gcp_pci_cloudbuild_trigger_3302edf7cb18]. Cloud Build logging is a build/trigger option, not a Logging sink field.
- pci_4.0_gcp A1.2.1.16: NEW_CHECK [gcp_log_sink_logging_enabled_set_ec2d3bb4252c] -> NOT_APPLICABLE []. The source requires a per-tunnel connection logging switch that Cloud VPN does not expose; sink inventory cannot prove it.
- pci_4.0_gcp A1.2.1.23: NEW_CHECK [gcp_log_sink_equivalent_enabling_multi_region_logging_82a3a7e2f5b8] -> NOT_APPLICABLE []. Cloud Audit Logs have no AWS multi-region trail toggle; a GCP Logging sink cannot evaluate it.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 879 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 10.2.1.7.12: NEW_CHECK [gcp_log_sink_logging_set_d150bd2ab8af] -> NOT_APPLICABLE []. The source requires a per-tunnel connection logging switch that Cloud VPN does not expose; sink inventory cannot prove it.
- pci_4.0_gcp 10.3.1.12: NEW_CHECK [gcp_log_sink_loggingenabled_set_99d65e9b2a48] -> NOT_APPLICABLE []. The source requires a per-tunnel connection logging switch that Cloud VPN does not expose; sink inventory cannot prove it.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.
- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae]. The versioning check does not evaluate the additional retention requirement.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` and generic `log_sink` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 879 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 8.4.3.5: PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_035c964949ae] -> PARTIAL [gcp.reviewed.storage.versioning, gcp_pci_bucket_d744122a225f]. The versioning evaluator says nothing about additional authentication or delete-operation safeguards.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` proposals must not count as assessed.

## Independent verifier pass

Checked 1730 distinct framework requirements, 857 unique proposed spec IDs, and all check references against inputs/check-index.json.

- pci_4.0_gcp 1.3.2.1: NEW_CHECK [gcp_backend_service_armor_security_policy_used_2af96e707863] -> NEW_CHECK [gcp_pci_backend_service_ccbc88f7bbb1]. The generated predicate named a parameter but did not identify the exact backendService.securityPolicy comparison.
- pci_4.0_gcp 1.3.2.28: NEW_CHECK [gcp_router_route_has_destination_cidr_block_97c7507ee12f] -> NEW_CHECK [gcp_pci_route_e4b88d4aadbe]. Route destination and next hop are properties of Compute Route, not Network or Router resources.
- pci_4.0_gcp 1.4.2.1: NEW_CHECK [gcp_backend_service_armor_security_policy_used_c3d6f85f6f9c] -> NEW_CHECK [gcp_pci_backend_service_ccbc88f7bbb1]. The generated predicate named a parameter but did not identify the exact backendService.securityPolicy comparison.
- pci_4.0_gcp 1.4.4.1: NEW_CHECK [gcp_backend_service_armor_security_policy_used_cb5555086c62] -> NEW_CHECK [gcp_pci_backend_service_ccbc88f7bbb1]. The generated predicate named a parameter but did not identify the exact backendService.securityPolicy comparison.
- pci_4.0_gcp 1.4.4.6: NEW_CHECK [gcp_network_route_cie_has_destination_cidr_db6d1e07313c] -> NEW_CHECK [gcp_pci_route_e4b88d4aadbe]. Route destination and next hop are properties of Compute Route, not Network or Router resources.
- pci_4.0_gcp 1.5.1.25: NEW_CHECK [gcp_router_route_router_has_destination_cidr_2964dc289b2c] -> NEW_CHECK [gcp_pci_route_e4b88d4aadbe]. Route destination and next hop are properties of Compute Route, not Network or Router resources.
- pci_4.0_gcp 10.2.1.1.19: NEW_CHECK [gcp_target_proxy_logging_enabled_log_bucket_set_a9dd8e29a700] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.2.1.2.16: NEW_CHECK [gcp_target_proxy_logging_settings_enabled_log_bucket_ad7df2bd526e] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.2.1.6.16: NEW_CHECK [gcp_target_proxy_logging_enabled_log_bucket_equal_f151649a2db7] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.2.1.7.16: NEW_CHECK [gcp_target_proxy_logging_disabled_log_bucket_does_a0aac7e675f4] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.3.1.16: NEW_CHECK [gcp_target_proxy_logging_configuration_disabled_log_bucket_052870c1e605] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 10.6.3.20: NEW_CHECK [gcp_target_proxy_logging_enabled_log_bucket_does_50b852adfd57] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 3.5.1.15: NEW_CHECK [gcp_kms_key_fileshare_encryptionkey_name_set_does_93ba8b2c40cf] -> NEW_CHECK [gcp_pci_asset_969340eeffeb]. The encryption reference is on a Filestore instance, not on a KMS key resource.
- pci_4.0_gcp 3.5.1.18: NEW_CHECK [gcp_kms_key_checks_memorystore_redis_instances_have_bc284ecfb7cc] -> NOT_APPLICABLE []. The described Redis instance encryption-at-rest toggle or redis_version test is not a native Memorystore for Redis setting; KMS key inventory cannot evaluate it.
- pci_4.0_gcp 5.3.4.19: NEW_CHECK [gcp_target_proxy_logging_enabled_log_bucket_equal_a810fbe17116] -> NEW_CHECK [gcp_pci_backend_service_4ceeeee2a9aa]. GCP load balancer target proxies have no logBucket field; logging is on backend services and export uses logging sinks.
- pci_4.0_gcp 6.4.1.2: NEW_CHECK [gcp_backend_service_armor_policy_used_442fbcc1e234] -> NEW_CHECK [gcp_pci_backend_service_ccbc88f7bbb1]. The generated predicate named a parameter but did not identify the exact backendService.securityPolicy comparison.
- pci_4.0_gcp 6.4.2.2: NEW_CHECK [gcp_backend_service_armor_security_policy_used_2af96e707863] -> NEW_CHECK [gcp_pci_backend_service_ccbc88f7bbb1]. The generated predicate named a parameter but did not identify the exact backendService.securityPolicy comparison.
- pci_4.0_gcp 7.2.1.1: NEW_CHECK [gcp_asset_project_part_organization_id_73219b9c36ab] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp 7.2.2.1: NEW_CHECK [gcp_asset_project_linked_organization_id_226c38f358ab] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp 7.2.5.1: NEW_CHECK [gcp_asset_account_part_organization_id_6cf8b9fe6350] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp 7.3.1.1: NEW_CHECK [gcp_asset_project_part_organization_id_5104dbf86bbd] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp 7.3.2.1: NEW_CHECK [gcp_asset_project_part_organization_id_cc4a21823e7a] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp 7.3.3.1: NEW_CHECK [gcp_asset_project_associated_organization_id_28f116580478] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp 8.2.7.1: NEW_CHECK [gcp_asset_project_associated_organization_id_a69aa8beddb9] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp 8.3.2.22: NEW_CHECK [gcp_kms_key_encryptionkey_parameter_filestore_instance_configuratio_ab586a72c188] -> NEW_CHECK [gcp_pci_asset_969340eeffeb]. The encryption reference is on a Filestore instance, not on a KMS key resource.
- pci_4.0_gcp 8.3.2.25: NEW_CHECK [gcp_asset_checks_memorystore_redis_instances_have_4987a23463f1] -> NOT_APPLICABLE []. The described Redis instance encryption-at-rest toggle or redis_version test is not a native Memorystore for Redis setting; KMS key inventory cannot evaluate it.
- pci_4.0_gcp 8.3.4.1: NEW_CHECK [gcp_asset_project_attached_organization_id_aea0c8e701ec] -> NEW_CHECK [gcp_pci_project_40343976c02a]. Organization ancestry belongs to Project/Folder metadata; arbitrary CAI assets are not the decision resource.
- pci_4.0_gcp A1.1.3.25: NEW_CHECK [gcp_router_route_router_nat_has_destination_db35676daf9a] -> NEW_CHECK [gcp_pci_route_e4b88d4aadbe]. Route destination and next hop are properties of Compute Route, not Network or Router resources.

### Evaluator and collector spot checks

- `peaso/checks/gcp_extended.py:450` reads BigQuery dataset `access`, not table IAM.
- `peaso/checks/gcp_ports_compute.py:129` tests broad ingress to TCP 22/3389 only.
- `peaso/checks/gcp_extended.py:267` tests lifecycle rule existence, not bucket versioning or retention adequacy.
- `peaso/checks/claude_gcp_k8s_iam.py:803` tests `loggingService`, not per-workload log delivery or all log types.
- `peaso/collectors/gcp.py:1204` collects bucket metadata and IAM, but not bucket/object ACL lists.
- Remaining generated NEW_CHECK specifications require API and field-level implementation review; broad CAI `asset` proposals must not count as assessed.

## Review inventory and residual doubts

- Corrections (unique requirements with changed decisions or check mappings): **339**. Earlier chronological entries include intermediate refinements.
- Every proposed resource kind is supported by the GCP collector; 857 distinct spec IDs remain. 24 proposed predicates retain ambiguous setting/parameter wording and require field-level design review.
- NOT_APPLICABLE source review, one entry per requirement:

  - pci_4.0_gcp 1.2.5.2: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 1.2.5.5: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 1.2.5.6: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 1.2.5.7: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.2.5.12: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.2.5.13: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.2.5.14: BigQuery dataset has no per-dataset require_ssl setting.
  - pci_4.0_gcp 1.2.8.7: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 1.2.8.9: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.2.8.11: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.2.8.13: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.2.8.22: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.2.8.26: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.2.8.30: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 1.2.8.39: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 1.3.1.12: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.3.1.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.3.1.25: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.3.1.29: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.3.2.8: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 1.3.2.10: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.3.2.12: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.3.2.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.3.2.25: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.3.2.29: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.4.2.10: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.4.2.12: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.4.2.14: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.4.2.23: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.4.2.27: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.4.3.1: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.5.1.13: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 1.5.1.22: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp 1.5.1.26: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 10.2.1.1.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.1.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.1.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.2.1.1.14: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.1.18: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.1.21: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.1.22: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.1.32: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.2.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.2.2: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.2.4: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.2.10: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.2.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.2.15: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.2.19: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.3.1: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.3.2: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.3.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.2.1.3.10: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.3.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.3.15: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.3.19: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.4.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.4.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.4.4: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.4.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.2.1.4.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.4.15: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.4.19: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.5.1: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.5.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.5.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.5.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.2.1.5.12: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.5.15: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.5.18: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.5.19: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.6.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.6.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.6.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.2.1.6.10: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.6.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.6.15: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.6.19: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.7.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.7.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.7.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.7.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.2.1.7.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.7.15: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.4: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.1.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.2.1.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.1.15: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.2.1: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.2.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.2.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.2.10: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.2.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.2.2.15: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.2.2.19: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.3.1.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.3.1.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.3.1.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.3.1.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 10.3.1.12: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.3.1.15: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.3.1.19: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.3.4.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.4.1.1.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.4.1.5: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.4.2.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.5.1.9: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 10.5.1.10: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 10.5.1.11: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 10.6.3.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.6.3.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.6.3.4: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.6.3.14: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.6.3.19: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 10.6.3.24: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.6.3.27: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 10.6.3.37: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.7.1.7: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 10.7.2.7: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 11.5.2.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 11.5.2.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 11.6.1.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 11.6.1.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 12.10.5.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 12.10.5.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 2.2.5.2: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 2.2.5.5: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 2.2.5.7: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 2.2.5.12: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 2.2.5.13: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 2.2.5.14: BigQuery dataset has no per-dataset require_ssl setting.
  - pci_4.0_gcp 2.2.7.2: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 2.2.7.3: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 2.2.7.9: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 2.2.7.16: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 2.2.7.17: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 3.5.1.18: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 3.5.1.19: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 3.5.1.24: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 4.2.1.1.7: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 4.2.1.1.13: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 4.2.1.1.24: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 4.2.1.1.25: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 4.2.1.1.26: BigQuery dataset has no per-dataset require_ssl setting.
  - pci_4.0_gcp 4.2.1.2: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 4.2.1.3: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 4.2.1.9: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 4.2.1.16: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 4.2.1.17: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 5.3.4.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 5.3.4.2: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 5.3.4.4: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 5.3.4.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp 5.3.4.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 5.3.4.14: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 5.3.4.17: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 5.3.4.18: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp 5.3.4.21: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 5.3.4.22: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 5.3.4.25: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 5.3.4.26: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 6.3.3.9: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 7.2.1.21: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 7.2.2.21: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 7.2.5.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 7.2.6.3: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 7.3.1.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 7.3.2.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 7.3.3.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.2.7.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.2.8.17: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.3.2.5: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 8.3.2.6: CloudFront-style CDN field absent from Cloud CDN.
  - pci_4.0_gcp 8.3.2.25: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp 8.3.2.27: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.3.2.28: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.3.2.39: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.3.2.40: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.3.2.41: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp 8.3.4.15: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp A1.1.3.13: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp A1.1.3.22: AWS peering/VPN/network-ACL field absent from GCP.
  - pci_4.0_gcp A1.1.3.26: fictional managed Search/OpenSearch domain or non-native deployment field.
  - pci_4.0_gcp A1.2.1.1: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp A1.2.1.2: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A1.2.1.4: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp A1.2.1.5: AWS load-balancer attribute absent from GCP.
  - pci_4.0_gcp A1.2.1.12: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A1.2.1.14: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A1.2.1.16: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A1.2.1.19: named service logging toggle is absent; see row reason.
  - pci_4.0_gcp A1.2.1.23: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A3.3.1.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A3.3.1.10: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A3.5.1.6: named resource or predicate field absent; see row reason.
  - pci_4.0_gcp A3.5.1.10: named resource or predicate field absent; see row reason.

## Repair pass

Reviewed all 1,730 requirements in both frozen-input frameworks, including the four `gcp-pci` spot-check corrections. Every requirement appears once, and all native, removed, and proposed references resolve against the check index or an in-row canonical proposal. No proposed ID remains in `native_checks`.

| Decision | Before | After | Change |
|---|---:|---:|---:|
| MAPPED | 63 | 63 | 0 |
| MAPPING_FIX | 68 | 61 | -7 |
| PARTIAL | 34 | 41 | +7 |
| MANUAL | 2 | 1,351 | +1,349 |
| NOT_APPLICABLE | 199 | 61 | -138 |
| NEW_CHECK | 1,364 | 153 | -1,211 |

Generic asset predicates, tautological pass conditions, unspecified log-type sets, and proposals needing an absent comparison parameter were removed. Rows without a sound field-level proposal now require manual evidence tied to the source condition; these remain open in the checklist. The 29 retained proposal IDs have named resource kinds, API fields, and Boolean predicates. `new-checks-gcp.json` was read for canonical IDs and not edited.

Validation: JSON parses; input order and counts match; all references resolve; decisions and summary counts agree; no MANUAL/NOT_APPLICABLE row carries a native or proposed check; no proposed ID has conflicting predicates within this ledger.
