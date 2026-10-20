# AWS service closure review — 2026-10-19

All **713 dispatched IDs** are explicitly accounted for in [the JSON review](services-closure-review.json): 570 shared callback contracts, 180 root resource kinds and 231 producer/dependency kinds. Every ID includes exact attributed producer/consumer fields, current callback source locations and hashes, primary reference links, fresh bounded fixture outcomes and unresolved reads. **None is certified as semantically complete.**

The directed offline review passes **62 tests**, exercising **38 in-scope consumers** and recording **129 SDK/public-pipeline field-emission receipts**. Field emission can support additional consumers, but it does not prove their other branches. The other IDs retain explicit bounded review dispositions and unresolved semantic contracts; they have not all been executed against independently specified SDK cases.

## Reproduced defects and integration

| Defect | Before | Required/current result | Scope |
| --- | --- | --- | --- |
| CodeBuild build details disappear between listing and detail read | A listed ID in `BatchGetBuilds.buildsNotFound` became `Builds.collection_status=empty`; both age checks returned FAIL as though the project had never been invoked | `partial`, preserving any retained items; both checks UNKNOWN | `aws.c2b.codebuild.invoked_last_90_days`, `aws.c2b.codebuild.built_within_90_days` |
| SNS policy omitted from a successful attribute map | `_topic_policy` interpreted missing `Attributes.Attributes.Policy` as no policy; four controls PASSed and perimeter returned NOT_APPLICABLE | UNKNOWN for all five consumers | `aws.cb.sns.policy_no_unrestricted_wildcard`, `policy_prohibit_public_access_perimeter`, `policy_no_public_publish`, `policy_no_public_subscribe`, `topic_not_publicly_accessible_prowler` |

AWS defines `buildsNotFound` as IDs whose information could not be found, so it cannot prove a project was never invoked. The collector must retain that missing detail boundary. [BatchGetBuilds](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BatchGetBuilds.html), [ListBuildsForProject](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ListBuildsForProject.html).

AWS explicitly documents that SNS properties returned by `GetTopicAttributes` can depend on authorization. A returned `TopicArn` authenticates identity, but cannot establish that an omitted policy is absent. [GetTopicAttributes](https://docs.aws.amazon.com/sns/latest/api/API_GetTopicAttributes.html).

The worker proposed both shared-source changes in `/tmp/peasso-aws-review-20261019/final-closure/services.patch`; the coordinator reviewed and integrated them. This worker modified only the owned test/report files. Both defects were reproduced before integration and their seven regressions pass afterward.

## Priority field contracts

| Family | Exact native/public contract reviewed | Directed evidence and limits |
| --- | --- | --- |
| S3 | `GetBucketVersioning.Status` -> `Versioning.Status`; successful empty response means never enabled; denied detail remains unavailable | Enabled PASS, Suspended FAIL, never-enabled FAIL, denied UNKNOWN. Other policy/ACL/PAB, ObjectLock, backup and replication branches retain their own gaps. [API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html) |
| RDS | `DBInstances[].AutoMinorVersionUpgrade`, `DBClusters[].IAMDatabaseAuthenticationEnabled`; parameter strings with literal key `rds.force_ssl` -> `ParameterGroupValues` / `ClusterParameterGroupValues` | Native booleans, TLS `1`/`0`, and unavailable parameter reads exercised. Effective pending-reboot state and all engine/version/capability joins remain separate questions. [DBInstance](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html), [DBCluster](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBCluster.html) |
| CodeBuild | `ListProjects.projects[]` string -> named item; `BatchGetProjects.projects[]` -> `Configuration.projects[]`, with exact project match | Native artifacts, logs, visibility, environment names/types, source/buildspec surrogates and webhook anchors exercised. The 16 high-fanout `Configuration.projects` witness gaps are not evidence of a missing producer; synthetic placeholder names fail its identity guard. [API](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BatchGetProjects.html) |
| Lambda | `GetFunctionConfiguration.TracingConfig.Mode` -> `Configuration.TracingConfig.Mode` | Active/PassThrough/absent branches exercised. Role, runtime, layer, package-content and environment default/error branches are not all covered by this receipt. [API](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunctionConfiguration.html) |
| Cognito | `DescribeUserPool.UserPool` -> `Configuration.UserPool`, including password policy, signup, deletion, MFA and threat protection | Native policy branches exercised. Risk overrides, all client options, returned-detail identity and every optional default remain independently bounded. [API](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPool.html) |
| SNS | Native string map `Attributes` -> `Attributes.Attributes`, with parsed `Policy` | Private/public/denied and missing-policy branches exercised. Botocore map keys are not fixed structure members, so absent modeled map keys are not a producer defect. [API](https://docs.aws.amazon.com/sns/latest/api/API_GetTopicAttributes.html) |
| Inspector | `accounts[].state.status` / `resourceState` -> `State.status` / `ResourceState`; audited account match | ENABLED/PASS, DISABLED/FAIL and denied/DENIED exercised with a real native Lambda inventory trigger. Transitional states and every finding/resource branch remain unproved. [API](https://docs.aws.amazon.com/inspector/v2/APIReference/API_BatchGetAccountStatus.html) |
| EMR | `DescribeSecurityConfiguration.SecurityConfiguration` JSON string -> `Configuration.SecurityConfiguration`, joined by the cluster security configuration name | At-rest true/false/denied branches exercised. The shared JSON producer serves eight input consumers; it does not certify every encryption provider or runtime branch. [API](https://docs.aws.amazon.com/emr/latest/APIReference/API_DescribeSecurityConfiguration.html) |
| Secrets Manager | `DescribeSecret.RotationEnabled` -> root `RotationEnabled` | Extra corroboration outside the 713 input: true/false/denied branches exercised with no secret-value API calls. Omitted defaults and service-owned exceptions are separate branches. [API](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html) |

The JSON also groups every remaining family and callback, including OpenSearch, Redshift, ECS, Glue, EFS, Neptune and GuardDuty, with exact source/field contracts and their unproved semantics. Fresh modeled public collector probes ran for all 231 producer/dependency kinds under botocore **1.43.38**. They remain modeled evidence: successful dispatch or an SDK member does not establish actual resource availability, field authority or complete semantic coverage.

## Receipts and reproduction

Tests: [test_aws_services_closure_review.py](../../tests/test_aws_services_closure_review.py).

```sh
.venv/bin/python -m pytest -q tests/test_aws_services_closure_review.py \
  -o junit_family=xunit1 \
  --junitxml=/tmp/peasso-aws-review-20261019/final-closure/services-directed.xml
```

Result: **62 passed**, no failures/errors/skips. The JUnit `aws_field_emission` properties record exact emitted paths, operations, test-source SHA256 and collector/snapshot pipeline fingerprint. The JSON embeds those receipts and marks whether each fingerprint still matches; a later source change requires re-execution before canonical admission. The coordinator owns runtime integration, canonical audit ingestion and final proof ledgers.

The review used local SDK stubs and primary documentation only. No resources were created or mutated, no external attack probes or secret validation occurred, and no full suite, build or deployment was run. A temporary shared SW39 source-digest mismatch blocked imports during integration; tests were rerun in a fresh process after coherence was restored.
