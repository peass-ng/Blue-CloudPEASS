# AWS data-service SDK closure review — 2026-10-19

The exact selected cohort is **123 AWS IDs**: 40 bucket, 29 RDS instance, 18 RDS cluster, 20 Redshift cluster and 16 Secrets Manager controls. The first 107 come from the prior service review; the 16 secret-kind IDs were selected from the current AWS registry because that prior input contained no secret-kind rows. KMS and AWS Backup are tested as native dependencies.

**88 selected consumers have current passing SDK/public-pipeline receipts; 35 remain explicitly unexecuted.** All 16 Secrets Manager controls have directed cases. This report does not certify all branches or treat shared field emission as execution of every consumer.

The owned directed file reports **142 tests, 142 passed, 0 failed, 0 errors, 0 skipped** under installed botocore 1.43.38. It records 423 field-emission properties and 298 actual registered-consumer execution properties; 423 field receipts passed and match the current test-source SHA256 and pipeline fingerprint. Any failed regression is an explicit pending runtime defect, not an accepted proof receipt.

## Installed-source acceptance

Fresh process acceptance: **142 passed in 17.83 seconds**, with no failures, errors or skips. All six defect classes now pass their directed regressions on the root-integrated source, including exact tag key/value matching, case sensitivity, OR conditions, denied detail and unsupported operators. This follow-up changed only the two reports; it added no IDs and changed no runtime, tests, UI groups, evidence prose or legacy reviewed-copy fixtures.

- Test-source SHA256: `2c50987983c8b5b89c37a92a6fb43aa767e71d6b4b4df23ea679f90667f2ef6f`
- Collector/snapshot pipeline fingerprint: `2862d386d79d073c49306dfc911966aa04554274c6f9ebd9b90254b5c8330888`
- Green JUnit receipt SHA256: `53d1c4d15757363302f35139599e787d3b9a63091b8f09ce0a477bc4f51aa3ee`

The historical receipt `/tmp/peasso-aws-review-20261019/final-closure/data-sdk-directed.xml` remains unchanged at **139 passed / 3 failed**. Its three backup tag-value counterexamples, prior hashes and prior finding statuses are retained under JSON `prior_review_lineage`; they are historical red evidence, while `receipt` and `acceptance` identify the fresh green run. The original before/required semantics of all six defect classes remain below and in JSON.

## Reproduced defects

| Class | SDK-valid counterexample | Required boundary | Current status |
| --- | --- | --- | --- |
| D-KMS-IDENTITY | PASS when ListKeys enumerates A but DescribeKey(A) returns B and the subject references B | UNKNOWN | root-integrated-directed-regressions-pass |
| D-REDSHIFT-PARAMETER | Missing require_ssl in successful response returns FAIL | UNKNOWN | root-integrated-directed-regressions-pass |
| D-RDS-PARAMETER | Missing rds.force_ssl in successful response returns FAIL | UNKNOWN | root-integrated-directed-regressions-pass |
| D-SECRET-POLICY-IDENTITY | Foreign GetResourcePolicy ARN/Name can PASS both exposure consumers and explicit-deny guardrail | UNKNOWN | root-integrated-directed-regressions-pass |
| D-BACKUP-EXCLUSION | Resources=[subject], NotResources=[subject] returns PASS | Conservative UNKNOWN until matching semantics resolved; exact evaluation may instead establish FAIL | root-integrated-directed-regressions-pass |
| D-BACKUP-TAG-VALUE | Same tag key with different or case-mismatched value, or unsupported condition type, returns PASS | Exact STRINGEQUALS key/value matching with OR across ListOfTags; mismatched values FAIL, unsupported operators UNKNOWN | root-integrated-directed-regressions-pass |

The six classes affect **12 selected IDs**. Each has exact IDs, native/public fields, source locations, primary references and a minimal runtime proposal in the JSON. The worker modified only the owned test/report files; the coordinator owns reviewing/applying shared runtime changes and final release.

KMS `ListKeys` identity must agree with `DescribeKey` before its metadata can classify a subject's key. The three CMK consumers previously accepted metadata for key B returned to a request for listed key A. [ListKeys](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html), [DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html).

The Redshift and RDS parameter responses contain named string values; a successful page that lacks the required parameter does not prove an explicit false setting. The Redshift `require_ssl` and the two standalone RDS `rds.force_ssl` consumers previously converted that missing evidence into FAIL. [Redshift parameters](https://docs.aws.amazon.com/redshift/latest/APIReference/API_DescribeClusterParameters.html), [RDS parameters](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBParameters.html).

Secrets Manager `GetResourcePolicy` returns the policy's ARN and name. A foreign response previously PASSed both public-policy consumers and the explicit-principal-deny guardrail, despite the producer already binding `DescribeSecret` identity correctly. [GetResourcePolicy](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetResourcePolicy.html).

AWS Backup explicitly defines `NotResources` as exclusions. The three legacy RDS selection checks ignored it and PASSed an ARN included in both `Resources` and `NotResources`; the installed conservative guard returns UNKNOWN until exclusion/condition matching is independently implemented. [BackupSelection](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_BackupSelection.html).

The tag-selection follow-up also reproduced a PASS when the RDS tag is `backup=daily` but `ListOfTags` requires `backup=weekly` or `backup=Daily`. The installed matcher compares both key and case-sensitive value for `STRINGEQUALS`, ORs the conditions, and leaves unsupported operators UNKNOWN; native matching, mismatched, OR, denied and unsupported cases are explicit tests. AWS documents these value and OR semantics in [BackupSelection](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_BackupSelection.html).

## Native contracts actually exercised

| Family | Native response → public field | Cases and remaining scope |
| --- | --- | --- |
| S3 encryption | `GetBucketEncryption.ServerSideEncryptionConfiguration.Rules` → `Encryption.ServerSideEncryptionConfiguration.Rules` | Named SSE-KMS versus AES256, documented missing configuration and denied reads. Configuration presence, named key reference and KMS algorithm are distinct consumers; an unavailable encryption configuration is not universally a FAIL. |
| S3 public policy / ACL / blocks | Native policy JSON, canonical/grantee ACLs, bucket and account block booleans → separate `Policy`, `Acl`, `PublicAccessBlock` detail containers and account inventory | Private/public/denied policy and ACL declarations, preventive block settings and exact TLS deny statement. No anonymous network probe or comprehensive effective-access claim. |
| S3 default metadata | Native empty versioning/logging/notification responses and documented missing lifecycle/ObjectLock errors | Enabled/configured, disabled/absent and denied cases. Replication status is exercised separately from destination Region and effective replication. |
| RDS TLS / backup | Native named parameter strings → literal dotted-key parameter maps; native backup selections → `Selections.items[].Selection.BackupSelection` | `1`/`0`, missing and denied parameters; exact ARN selection, another ARN, denied selection and explicit exclusion. Effective applied parameter state, every wildcard/tag/condition branch and recovery success remain unproved. |
| RDS base settings | `DBInstances[]` / `DBClusters[]` → retained settings | IAM auth flags, minor upgrades, tag copying, retention, supported Backtrack configuration, logs, username and Multi-AZ metadata. Engine/version/capability, routing, certificates and every member join retain separate contracts. |
| Redshift | `Clusters[]`, logging status, named parameters and KMS dependency → base fields, `Logging`, `ParameterGroupValues`, key metadata | Explicit booleans, native `MultiAZ` string, names, retention, key declaration, logging, TLS and key classification. Network/subnet/SG behavior and future enum/version branches are not certified. |
| Secrets Manager | `SecretListEntry`, bound `DescribeSecret` and `GetResourcePolicy`; optional KMS key → root metadata / `Policy` | Rotation/rules/function, date metadata, policies, default AWS-managed KMS omission, enabled/disabled key and foreign/denied details. No secret value API or credential validation. |

AWS documents omission of `KmsKeyId` when Secrets Manager uses `aws/secretsmanager`; the same successful bound metadata therefore FAILs a CMK-only policy while PASSing the policy that accepts an enabled AWS-managed key. The tests preserve this distinction instead of treating every omitted key as missing evidence. [DescribeSecret](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html).

## Evidence and explicit remainder

[The JSON report](data-sdk-closure-review.json) enumerates every selected ID, current callback/helper sources and hashes, exact bounded read paths, primary links, actual outcome receipts, unvisited accessor branches and exact fields without current SDK emission receipts. It is rebuilt from the current registry and actual SDK receipts, rather than copying prior review dispositions. All rows retain `semantic_completeness_proven=false` and `branch_completeness_proven=false`.

The tests use native botocore clients with `Stubber` request/response validation, then the actual `Requests` scheduler, public `aws.collect`, snapshot validation and registered engine consumer. Passing test properties record both exact emitted paths and the actual check ID/outcome, with the test-source SHA256 and current collector/snapshot pipeline fingerprint. Stale or failed properties remain visible but are not accepted as current proof.

```sh
.venv/bin/python -m pytest -q tests/test_aws_data_sdk_closure_review.py \
  -o junit_family=xunit1 \
  --junitxml=/tmp/peasso-aws-review-20261019/final-closure/data-sdk-directed-acceptance.xml
```

No resources were created or mutated, no external attack probes or secret validation occurred, and no full suite, build, deployment, UI taxonomy or other evidence prose was changed. The coordinator retains canonical receipt ingestion, runtime integration and final release proof.
