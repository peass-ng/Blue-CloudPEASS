# Selected AWS service-family source review

Reviewed 121 active checks on 2026-10-19: cloudfront_distribution: 25, cognito_user_pool: 17, emr_cluster: 15, opensearch_domain: 23, redshift_cluster: 25, secret: 16.

Per-ID callback/helper and field/source review, exact consumer-fixture branch/path receipts, grouped installed-SDK-shaped producer-to-registered-consumer probes. Fixtures are not producer proof; optional model membership is not omission semantics.

The JSON is the per-ID evidence ledger. Each row records current dependencies, callback and helper hashes, native field to installed SDK relationships, pinned upstream executable/query hashes, captured closure parameters, and exact executed consumer lines/accessor paths for named fixture branches. Those consumer receipts are explicitly separate from actual SDK producer probes.

## Confirmed findings

- Two actual SDK producer-to-consumer probes reproduced unsafe PASS for a wildcard-only PrincipalArn condition in Secrets Manager and OpenSearch public policy checks. Fixed in the authorized shared helper and covered by SDK and condition-boundary regressions.
- CloudFront external origin bucket probes have no native producer. The current native result is conservatively UNKNOWN outside owned buckets; adding a producer requires fixing synthetic HTTP classification first.
- [AWS HeadBucket documentation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html) establishes existence on 200, while generic 400/403/404 cannot distinguish missing buckets from denied access. Current synthetic 403 PASS/404 FAIL assumptions must not become the native contract.

## Family boundaries

### cloudfront_distribution

ListDistributions inventory -> aws_b_services Config=GetDistributionConfig -> aws_facts_compute_edge LogDeliveries=Logs describe_delivery_sources + describe_deliveries; Requests.detail _safe then _metadata preserve configuration field names. collect.append supplies AccountId/Region/id. No OriginBucketProbes native stage.

- Full ListDistributions pagination and Logs v2 source/delivery join are source-inspected, not independently SDK-executed here.
- External origin HeadBucket facts have no producer; owned buckets are the only native positive existence witness.

### cognito_user_pool

ListUserPools -> aws_b_services Configuration=DescribeUserPool, Risk=DescribeRiskConfiguration, complete Clients list and each DescribeUserPoolClient; Requests.call removes ClientSecret and emits ClientSecretPresent; aws_facts_ext adds identity providers/MFA/groups; aws_facts_data_identity adds WebAcl through GetWebACLForResource.

- Extra MFA/provider/group and WebAcl stages are source-inspected, not independently SDK-executed here.
- Threat-response, writable-attribute and full client pagination combinations have consumer fixtures only.

### emr_cluster

ListClusters -> aws_privesc_facts DescribeCluster allowlist nested under Cluster.Cluster; Kerberos realm/user only, no passwords; RUNNING/WAITING list_instances MASTER produces complete MasterInstances plus primary resolution. Security configuration detail is parsed and only EncryptionConfiguration/InstanceMetadataServiceConfiguration retained.

- Running MASTER list_instances pagination, primary DNS resolution and joined EC2/subnet/security-group producer execution are not independently tested here.
- Security-configuration JSON fields are application contracts inside an SDK string; SDK schema cannot validate their semantics.

### opensearch_domain

ListDomainNames -> aws._enrich Domain=DescribeDomain; Requests.detail preserves DomainStatus including options and string AccessPolicies. Engine supplies account/Region context.

- Domain-list pagination, route-table joins, every logging/cluster option combination and all condition operators are not SDK-executed here.
- Optional SDK membership is not a documented absence/default contract.

### redshift_cluster

DescribeClusters native cluster fields copied; aws_b_services Logging=DescribeLoggingStatus; aws_facts_cb_ca LoggingStatus reuses shared cached same API, ParameterGroupValues from unique ClusterParameterGroups name and allowlisted DescribeClusterParameters. Missing/ambiguous group marks coverage unavailable.

- Snapshot/KMS/network joins are source and consumer-fixture reviewed, not independently SDK-executed here.
- No inference from omission of an optional native cluster scalar.

### secret

ListSecrets metadata copied; aws._enrich clears stale rotation/key fields then identity-bound DescribeSecret repopulates rotation/key facts with coverage; GetResourcePolicy JSON decoded. Rotation/KMS documented omissions have explicit proof; timestamps remain ListSecrets metadata.

- Full ListSecrets pagination, live eventual consistency, complete KMS join and date-boundary matrix are not independently SDK-executed here.
- ListSecrets date fields can lag DescribeSecret refresh and remain eventual; no live freshness assertion.

## Per-ID review index

SDK marks independent producer-to-that-consumer probes; all other rows have explicit source/field and consumer-only coverage limits.

| ID | Fields | Upstream references | SDK | Findings |
|---|---:|---:|---|---|
| aws.b.cloudfront.access_logging | 1 | 2 | shared contract only | none found in bounded review |
| aws.b.cloudfront.custom_acm_certificate | 1 | 2 | shared contract only | none found in bounded review |
| aws.b.cloudfront.custom_origin_encryption | 7 | 3 | shared contract only | none found in bounded review |
| aws.b.cloudfront.default_root_object | 1 | 3 | shared contract only | none found in bounded review |
| aws.b.cloudfront.field_level_encryption | 1 | 2 | shared contract only | none found in bounded review |
| aws.b.cloudfront.geo_restrictions | 1 | 2 | shared contract only | none found in bounded review |
| aws.b.cloudfront.no_sslv3_origin | 7 | 2 | shared contract only | none found in bounded review |
| aws.b.cloudfront.origin_group_metadata | 1 | 3 | shared contract only | none found in bounded review |
| aws.b.cloudfront.origin_secure_protocols | 7 | 1 | shared contract only | none found in bounded review |
| aws.b.cloudfront.sni | 1 | 2 | shared contract only | none found in bounded review |
| aws.b.cloudfront.viewer_encryption | 4 | 2 | yes | none found in bounded review |
| aws.b.cloudfront.waf_reference | 1 | 3 | shared contract only | none found in bounded review |
| aws.b.cognito.admin_only_signup | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.block_all_takeover_risks | 13 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.block_compromised_signin | 9 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.deletion_protection | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.enforced_threat_protection | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.password_lowercase | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.password_minimum_fourteen | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.password_number | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.password_policy | 2 | 2 | shared contract only | none found in bounded review |
| aws.b.cognito.password_symbol | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.password_uppercase | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.cognito.required_mfa | 3 | 1 | yes | none found in bounded review |
| aws.b.cognito.temporary_password_seven_days | 3 | 1 | shared contract only | none found in bounded review |
| aws.b.redshift.allow_version_upgrade | 1 | 1 | shared contract only | none found in bounded review |
| aws.b.redshift.audit_logging | 1 | 1 | yes | none found in bounded review |
| aws.b.redshift.enhanced_vpc_routing | 1 | 1 | shared contract only | none found in bounded review |
| aws.b.redshift.kms_key_declared | 2 | 1 | shared contract only | none found in bounded review |
| aws.b.redshift.no_public_endpoint | 1 | 1 | shared contract only | none found in bounded review |
| aws.b.redshift.nondefault_admin | 1 | 1 | shared contract only | none found in bounded review |
| aws.b.redshift.nondefault_database | 1 | 1 | shared contract only | none found in bounded review |
| aws.b.redshift.snapshots_seven_days | 1 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.custom_ssl_certificate | 3 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.default_behavior_https | 3 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.https_sni | 5 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.logging_any | 8 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.origin_no_deprecated_ssl | 9 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.origin_traffic_encrypted | 15 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.pqc_tls | 5 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.recommended_tls_policy | 4 | 3 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.s3_origin_access_control | 8 | 2 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.s3_origin_access_identity | 9 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cloudfront.s3_origin_bucket_exists | 13 | 3 | shared contract only | missing_native_origin_bucket_probes, ambiguous_headbucket_http_classification |
| aws.c2b.cognito.clients_prevent_user_existence_errors | 8 | 1 | shared contract only | none found in bounded review |
| aws.c2b.cognito.clients_token_revocation | 8 | 1 | yes | none found in bounded review |
| aws.c2b.cognito.waf_web_acl_associated | 5 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.cluster_at_rest_cse_custom | 9 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.cluster_at_rest_encryption | 9 | 1 | yes | none found in bounded review |
| aws.c2b.emr.cluster_at_rest_sse_kms | 9 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.cluster_in_transit_encryption | 9 | 1 | yes | none found in bounded review |
| aws.c2b.emr.cluster_kerberos_enabled | 5 | 1 | yes | none found in bounded review |
| aws.c2b.emr.cluster_local_disk_cmk | 9 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.cluster_local_disk_encryption | 9 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.cluster_not_publicly_accessible | 12 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.cluster_security_configuration | 5 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.master_no_public_dns | 6 | 1 | shared contract only | none found in bounded review |
| aws.c2b.emr.master_subnet_no_auto_public_ip | 8 | 3 | shared contract only | none found in bounded review |
| aws.c2b.es.all_logs_to_cloudwatch | 3 | 1 | shared contract only | none found in bounded review |
| aws.c2b.es.audit_logs_to_cloudwatch | 3 | 2 | shared contract only | none found in bounded review |
| aws.c2b.es.error_logs_to_cloudwatch | 3 | 2 | shared contract only | none found in bounded review |
| aws.c2b.es.in_vpc | 3 | 3 | shared contract only | none found in bounded review |
| aws.c2b.es.internal_user_database_enabled | 4 | 1 | shared contract only | none found in bounded review |
| aws.c2b.es.policy_prohibit_public_access | 3 | 1 | shared contract only | none found in bounded review |
| aws.c2b.es.tls_1_2_policy | 3 | 2 | shared contract only | none found in bounded review |
| aws.cb.opensearch.access_policy_not_public | 4 | 1 | yes | wildcard_principal_arn_false_pass |
| aws.cb.opensearch.audit_logs_enabled | 3 | 3 | shared contract only | none found in bounded review |
| aws.cb.opensearch.cognito_dashboards_auth | 4 | 2 | shared contract only | none found in bounded review |
| aws.cb.opensearch.cognito_or_saml_dashboards_auth | 7 | 1 | shared contract only | none found in bounded review |
| aws.cb.opensearch.data_node_fault_tolerance | 5 | 5 | shared contract only | none found in bounded review |
| aws.cb.opensearch.dedicated_master_nodes | 5 | 3 | shared contract only | none found in bounded review |
| aws.cb.opensearch.enabled_logs_have_log_group | 3 | 2 | shared contract only | none found in bounded review |
| aws.cb.opensearch.encryption_at_rest | 2 | 5 | shared contract only | none found in bounded review |
| aws.cb.opensearch.enforce_https | 2 | 3 | yes | none found in bounded review |
| aws.cb.opensearch.fine_grained_access_control | 4 | 3 | shared contract only | none found in bounded review |
| aws.cb.opensearch.in_vpc_private_subnets | 8 | 3 | shared contract only | none found in bounded review |
| aws.cb.opensearch.internal_user_database_disabled | 4 | 2 | shared contract only | none found in bounded review |
| aws.cb.opensearch.node_to_node_encryption | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.opensearch.node_to_node_encryption_region_skip | 2 | 4 | shared contract only | none found in bounded review |
| aws.cb.opensearch.service_software_current | 2 | 3 | shared contract only | none found in bounded review |
| aws.cb.opensearch.slow_logs_enabled | 3 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.allow_version_upgrade | 2 | 2 | shared contract only | none found in bounded review |
| aws.cb.redshift.audit_logging | 1 | 2 | yes | none found in bounded review |
| aws.cb.redshift.cmk_encryption | 5 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.encrypted | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.encrypted_and_logging | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.enhanced_vpc_routing | 2 | 2 | shared contract only | none found in bounded review |
| aws.cb.redshift.has_snapshot | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.internet_exposed | 18 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.kms_key_declared | 3 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.maintenance_settings | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.redshift.multi_az | 2 | 3 | shared contract only | none found in bounded review |
| aws.cb.redshift.non_default_database_name | 1 | 2 | shared contract only | none found in bounded review |
| aws.cb.redshift.non_default_master_username | 1 | 2 | shared contract only | none found in bounded review |
| aws.cb.redshift.not_publicly_accessible | 2 | 2 | shared contract only | none found in bounded review |
| aws.cb.redshift.require_ssl | 1 | 3 | yes | none found in bounded review |
| aws.cb.redshift.security_group_port_restricted | 8 | 2 | shared contract only | none found in bounded review |
| aws.cb.redshift.snapshot_retention_7_days | 1 | 1 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.accessed_within_90_calendar_days | 2 | 2 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.accessed_within_90_days | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.changed_within_365_days | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.changed_within_90_days | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.cmk_encryption | 5 | 1 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.policy_not_public | 1 | 1 | yes | wildcard_principal_arn_false_pass |
| aws.cb.secretsmanager.policy_prohibit_public_access_perimeter | 1 | 1 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.rotated_as_scheduled | 4 | 2 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.rotated_within_90_days | 2 | 1 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.rotation_lambda | 3 | 2 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.rotation_rules_present | 2 | 2 | shared contract only | none found in bounded review |
| aws.cb.secretsmanager.used_after_creation_day | 3 | 1 | shared contract only | none found in bounded review |
| aws.cb.shield.cloudfront_protected | 5 | 1 | shared contract only | none found in bounded review |
| aws.htbp.cognito.client_no_writable_authorization_attributes | 14 | 0 | shared contract only | none found in bounded review |
| aws.nist.emr_master_nodes_no_public_ip | 33 | 0 | shared contract only | none found in bounded review |
| aws.pci.secretsmanager.kms_encryption_any | 24 | 0 | shared contract only | none found in bounded review |
| aws.review.secretsmanager.explicit_principal_deny | 14 | 1 | shared contract only | none found in bounded review |
| aws.secretsmanager.rotation | 1 | 1 | yes | none found in bounded review |
| aws_cloudfront_origin_failover_configured | 15 | 0 | shared contract only | none found in bounded review |
| aws_fedramp_emr_master_no_public_ip | 34 | 0 | shared contract only | none found in bounded review |
| aws_g6_emr_master_nodes_no_public_address | 33 | 0 | shared contract only | none found in bounded review |
| aws_nist_emr_cluster_master_nodes_no_public_ip | 33 | 0 | shared contract only | none found in bounded review |
| aws_nist_secretsmanager_secret_automatic_rotation_enabled | 12 | 0 | shared contract only | none found in bounded review |

## Limits

- No cloud APIs, cloud writes, deployment, content downloads or full test suite.
- No execution of upstream Prowler/Steampipe runtimes; 58 per-ID Prowler source associations have no executable body in the bounded cache and retain metadata/digest provenance only. Cached Steampipe query bodies and the restrictive-secret-policy/helper bodies were source-inspected.
- Source callback inventory seeded from field-producers.json, then current source locations/hashes and every selected consumer re-executed on named fixture branches; prior witness-only labels are not defect evidence.
- SDK schemas validate structural response members, not AWS service invariants, exhaustive optional-member defaults or policy effectiveness.
- Family limits and per-ID absent SDK execution are serialized explicitly; do not promote all rows to semantically verified.

Validation: **1,103 passed**, no failures/errors/skips, across 54 new focused cases and existing shared-helper/producer caller regressions. XML receipt: `/tmp/peasso-aws-review-20261019/service-family-semantic-tests.xml`; its SHA-256 and exact command are in JSON. All 39 captured source-file hashes were rechecked unchanged after the test run.
