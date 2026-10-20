Workload resource follow-up review — 2026-10-19

Exact scope: 15 existing IDs, with IDs, groups and source unchanged. Native configuration support, declared IAM permissions and optional Lambda content remain distinct; no credential validation is performed.

New focused suite: 45 passed, 0 failed; five existing CloudTrail organization tests also passed. Botocore 1.43.38, inert SDK Stubber responses, real Requests, public aws.collect and registered evaluate_snapshot callbacks are used; no snapshot fields are fabricated from expected fixtures.

Receipt: `/tmp/peasso-aws-review-20261019/workload-resource-followup/accepted.xml` (SHA256 `7f3c417bd01a1afd2bc54da8ee74d8f60c47c077b2bb545ea681c0c23f1582d2`). New test source SHA256 `045842e87ab085f99e99d468d5b5b70951ef0cbc79ff5db14f7e7a4ec7f65d3d`; JUnit records 116 source-bound field emissions and 48 consumer outcomes. Field emission does not imply semantic read or branch completeness.

Existing evidence was reconciled first: role existence/uniqueness fixtures, role-policy SDK tests, native Config tests, EKS producer tests, optional content SDK/HTTP tests and receipts, CloudTrail organization tests, Lambda omission tests and ECS volume provenance tests. Tests stopping at helpers or constructed snapshots remain identified as such; only missing public collector-to-registered-evaluator contracts received new tests.

No runtime defect was found and no source patch is proposed. Earlier red development receipts came from incomplete native test payloads or a verdict helper combining inventory and resource outcomes, and are not defect receipts. No full suite, large scanner suite, live account/content access, cloud writes, build or deploy was run.

| Existing ID | New resource outcomes / existing proof | Remaining proof |
|---|---|---|
| aws.c2b.ecs.cluster_has_registered_instances | FAIL, NOT_APPLICABLE, PASS, UNKNOWN | Custom capacity providers, standalone task states and readiness are not exhaustively established. |
| aws.c2b.lambda.invoke_cloudtrail_logged | FAIL, PASS, UNKNOWN | Pinned selector-matching behavior does not establish successful delivery, invocation coverage in live AWS or organization-trail completeness. |
| aws.c2b.lambda.policy_not_public | FAIL, PASS, UNKNOWN | Ordinary private/public/denied policy cases are tested; exhaustive conditions, principals and effective authorization remain unproved. |
| aws.cb.lambda.cloudtrail_data_events | Existing suite refreshed: PASS, FAIL, UNKNOWN (5 passed) | Organization, selector-denied and shadow-trail cases are tested; exhaustive selector combinations and actual event delivery remain unproved. |
| aws.cb.lambda.policy_no_wildcard_allow | FAIL, PASS, UNKNOWN | Ordinary private/public/denied policy cases are tested; exhaustive conditions, principals and effective authorization remain unproved. |
| aws.cb.lambda.policy_prohibit_public_access_perimeter | FAIL, PASS, UNKNOWN | Ordinary private/public/denied policy cases are tested; exhaustive conditions, principals and effective authorization remain unproved. |
| aws.cb.lambda.vpc_multiple_az | FAIL, NOT_APPLICABLE, PASS, UNKNOWN | Subnet identity absence and denied inventory are tested; actual function availability and all partition/Region variants remain unproved. |
| aws.review.eks.native_version_supported | FAIL, PASS, UNKNOWN | Service support status is distinct from an owner-approved minimum version or extended-support spending policy. |
| aws.review.lambda.execution_role_policy_admin_grants | FAIL, PASS, UNKNOWN | Literal declared grants only; effective permissions, boundaries, SCPs, session policies and credential validity remain unassessed. |
| aws.review.lambda_function.package_content_secret_indicators | Default-off UNKNOWN; historical synthetic content PASS/FAIL and dual-detector engine receipt | Fresh public collection tests prove default-off UNKNOWN with no GetFunction request; existing synthetic content proofs do not certify the enabled public aws.collect route or live package retrieval. |
| aws_cis_lambda_config_recorded | FAIL, PASS, UNKNOWN | Running Success and stopped/denied recorder status are tested; exclusion/inclusion permutations and every recorder lifecycle are not exhaustive. |
| aws_cis_lambda_execution_role_exists | FAIL, PASS, UNKNOWN | Same-account global IAM existence is tested; trust policy, role assumability and execution success remain unproved. |
| aws_cis_lambda_execution_role_no_admin | FAIL, PASS, UNKNOWN | Exact AWS AdministratorAccess attachment fails; a possible custom all-action grant remains UNKNOWN, and transitive escalation/effective access is not assessed. |
| aws_cis_lambda_execution_role_unique | DENIED, FAIL, NOT_APPLICABLE, PASS | Complete enabled-Region discovery and observed duplicates under partial inventory are tested; concurrent changes and all cross-Region combinations remain unproved. |
| aws_g6_ecs_fargate_storage_encryption | FAIL, PASS, UNKNOWN | Managed EBS PRIMARY-deployment joins are tested; EFS alternatives and every service deployment transition remain unproved in this new suite. |

Complete resource semantics, branch coverage, provider-side truth and live certification are not claimed for any ID. Partial Lambda inventory can retain observed duplicate-role FAIL while its inventory outcome remains UNKNOWN; absence of duplicates proves PASS only after complete enabled-Region discovery.

Primary AWS contracts consulted:

- [API_DescribeClusterVersions.html](https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeClusterVersions.html)
- [API_ServiceManagedEBSVolumeConfiguration.html](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ServiceManagedEBSVolumeConfiguration.html)
- [API_RecordingGroup.html](https://docs.aws.amazon.com/config/latest/APIReference/API_RecordingGroup.html)
- [configuration-vpc.html](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html)
- [API_GetAccountAuthorizationDetails.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [API_GetEventSelectors.html](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html)
- [API_GetFunction.html](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html)
