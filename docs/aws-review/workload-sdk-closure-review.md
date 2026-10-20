Workload SDK closure review — 2026-10-19

Exact scope: 74 existing IDs across six families, botocore 1.43.38. No new IDs or live cloud calls.

Owned suite: 171/171 passed, 0 failed, 0 errors. Receipt `/tmp/peasso-aws-review-20261019/workload-sdk-closure/accepted.xml`; SHA256 `d39939f7587cf4c39ea7ca20bf03fb3d4dda305dc231a48fd0502b081b76b193`.
Test source SHA256 `6fe719f0a38db865157357d139806af6bcdfcbbd773d747b45b8332fa638a53c`. Source-bound JUnit properties contain 427 field emissions and 323 engine/consumer outcomes.

All 74 IDs have tested denied-inventory outcomes. 59 IDs have directed resource predicate tests; 58 have passing positive and negative setting assertions. Inventory-only outcomes never certify resource semantics.

Runtime findings: 24 unbound detail false PASS/FAIL cases; one duplicate-service PASS; five missing/foreign container-instance join PASS cases; six foreign/missing EKS add-on subject cases. Root owns runtime installation; this worker edited only its new test and two reports. Red receipts and proposed patches remain in the assigned temporary directory.

The test harness uses native request/response validation and the actual SDK paginator metadata. It rejects malformed test payloads rather than allowing collector exception handling to disguise them as denied AWS reads. Synthetic configuration values are asserted absent from both public snapshots and shared successful request caches; no real secrets or external validation is used.

Resource-policy, role/catalog and package-content semantics not exercised here remain unproved. Complete semantic or branch coverage is not claimed for any ID. CodeBuild empty list inventory is not fabricated against its SDK minimum-one list shape; project-detail absence is exercised separately.

| Existing ID | Directed resource outcomes | Positive + negative | Remaining proof |
|---|---|---|---|
| aws.b.codebuild.artifact_encryption | FAIL, PASS | yes | unvisited branches |
| aws.b.codebuild.logs_enabled | FAIL, PASS | yes | unvisited branches |
| aws.b.codebuild.nonprivileged | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.b.codebuild.s3_artifact_encryption | FAIL, NOT_APPLICABLE, PASS | yes | unvisited branches |
| aws.b.codebuild.s3_log_encryption | FAIL, PASS | yes | unvisited branches |
| aws.b.ecs.all_readonly_roots | FAIL, PASS | yes | unvisited branches |
| aws.b.ecs.declared_nonroot_users | FAIL, PASS | yes | unvisited branches |
| aws.b.ecs.host_network_nonprivileged | FAIL, PASS | yes | unvisited branches |
| aws.b.ecs.no_host_pid | FAIL, PASS | yes | unvisited branches |
| aws.b.ecs.no_privileged_containers | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.b.ecs.some_logging_configuration | FAIL, PASS | yes | unvisited branches |
| aws.b.eks.disable_public_endpoint | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.b.eks.no_default_vpc | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.b.lambda.active_tracing | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.b.lambda.insights_layer | FAIL, PASS | yes | unvisited branches |
| aws.c2b.codebuild.buildspec_not_user_controlled | FAIL, PASS | yes | unvisited branches |
| aws.c2b.codebuild.buildspec_not_yml_file | FAIL, PASS | yes | unvisited branches |
| aws.c2b.codebuild.built_within_90_days | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.codebuild.invoked_last_90_days | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.codebuild.no_plaintext_sensitive_env_names | FAIL, PASS | yes | unvisited branches |
| aws.c2b.codebuild.project_private | FAIL, PASS | yes | unvisited branches |
| aws.c2b.codebuild.s3_logs_encrypted_when_enabled | FAIL, NOT_APPLICABLE, PASS | yes | unvisited branches |
| aws.c2b.codebuild.source_repo_oauth | FAIL, PASS | yes | unvisited branches |
| aws.c2b.codebuild.source_url_no_credentials | FAIL, PASS | yes | unvisited branches |
| aws.c2b.codebuild.webhook_filters_anchored | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.all_containers_logging | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.awsvpc_service_no_public_ip | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.cluster_has_active_services | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.cluster_has_registered_instances | inventory only | no | resource semantics and all branches |
| aws.c2b.ecs.cluster_instance_volumes_encrypted | FAIL, NOT_APPLICABLE, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.ecs.container_insights | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.ecs.container_insights_setting | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.container_instance_agents_connected | FAIL, NOT_APPLICABLE, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.ecs.fargate_latest_platform | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.host_network_root_user | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.logging_non_blocking | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.no_credential_named_env_vars | FAIL, PASS | yes | unvisited branches |
| aws.c2b.ecs.service_no_public_ip | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.eks.secrets_encryption_configured | FAIL, PASS | yes | unvisited branches |
| aws.c2b.eks.single_security_group | FAIL, PASS | yes | unvisited branches |
| aws.c2b.eks.vpc_cni_network_policy | FAIL, MANUAL, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.lambda.env_vars_cmk | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.c2b.lambda.invoke_cloudtrail_logged | inventory only | no | resource semantics and all branches |
| aws.c2b.lambda.no_cross_account_layers | FAIL, PASS | yes | unvisited branches |
| aws.c2b.lambda.policy_not_public | inventory only | no | resource semantics and all branches |
| aws.c2b.lambda.runtime_not_obsolete | FAIL, PASS | yes | unvisited branches |
| aws.c2b.lambda.url_cors_no_wildcard | FAIL, NOT_APPLICABLE, PASS, UNKNOWN | yes | unvisited branches |
| aws.cb.lambda.cloudtrail_data_events | inventory only | no | resource semantics and all branches |
| aws.cb.lambda.kms_key_configured | FAIL, PASS | yes | unvisited branches |
| aws.cb.lambda.logging_config_present | PASS, UNKNOWN | no | unvisited branches |
| aws.cb.lambda.policy_no_wildcard_allow | inventory only | no | resource semantics and all branches |
| aws.cb.lambda.policy_prohibit_public_access_perimeter | inventory only | no | resource semantics and all branches |
| aws.cb.lambda.runtime_not_deprecated_list | FAIL, PASS | yes | unvisited branches |
| aws.cb.lambda.vpc_multiple_az | inventory only | no | resource semantics and all branches |
| aws.htbp.ecs.exec_session_logging_not_disabled | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.htbp.ecs.no_sensitive_host_mounts | FAIL, PASS | yes | unvisited branches |
| aws.lambda.dead_letter_queue | FAIL, PASS | yes | unvisited branches |
| aws.lambda.vpc_configuration | FAIL, PASS | yes | unvisited branches |
| aws.nist.codebuild_exact_aws_key_env_names | FAIL, PASS | yes | unvisited branches |
| aws.pci.codebuild.aws_key_environment_vars | FAIL, PASS | yes | unvisited branches |
| aws.review.codebuild_project.configuration_secret_indicators | FAIL, PASS | yes | unvisited branches |
| aws.review.ecs_task_definition.configuration_secret_indicators | FAIL, PASS | yes | unvisited branches |
| aws.review.eks.native_version_supported | inventory only | no | resource semantics and all branches |
| aws.review.lambda.configuration_secret_indicators | FAIL, PASS, UNKNOWN | yes | unvisited branches |
| aws.review.lambda.execution_role_policy_admin_grants | inventory only | no | resource semantics and all branches |
| aws.review.lambda_function.package_content_secret_indicators | inventory only | no | resource semantics and all branches |
| aws_cis_lambda_config_recorded | inventory only | no | resource semantics and all branches |
| aws_cis_lambda_execution_role_exists | inventory only | no | resource semantics and all branches |
| aws_cis_lambda_execution_role_no_admin | inventory only | no | resource semantics and all branches |
| aws_cis_lambda_execution_role_unique | inventory only | no | resource semantics and all branches |
| aws_ecs_task_definition_credential_environment_names | FAIL, PASS | yes | unvisited branches |
| aws_g6_ecs_all_containers_logging | FAIL, PASS | yes | unvisited branches |
| aws_g6_ecs_fargate_storage_encryption | inventory only | no | resource semantics and all branches |
| aws_lambda_code_signing_configured | FAIL, PASS, UNKNOWN | yes | unvisited branches |

Primary AWS API contracts:

- codebuild_project: [API_BatchGetProjects.html](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BatchGetProjects.html)
- lambda_function: [API_GetFunctionConfiguration.html](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunctionConfiguration.html), [API_GetFunctionCodeSigningConfig.html](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunctionCodeSigningConfig.html)
- ecs_task_definition: [API_DescribeTaskDefinition.html](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTaskDefinition.html)
- ecs_service: [API_DescribeServices.html](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeServices.html)
- ecs_cluster: [API_DescribeClusters.html](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeClusters.html), [API_DescribeContainerInstances.html](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeContainerInstances.html)
- eks_cluster: [API_DescribeCluster.html](https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html), [API_DescribeAddon.html](https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeAddon.html)
