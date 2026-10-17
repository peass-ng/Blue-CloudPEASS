# AWS-B native coverage track

This track owns AWS service configuration checks outside the AWS-A IAM/account/Organizations/S3/EC2/VPC/network/KMS/CloudTrail/Config/GuardDuty/SecurityHub/CloudWatch partition. The authoritative source-ID assignment is `peaso/rulepacks/port_partitions.json`; the original AWS-B assignment contains 1,141 references; directive 13 transfers 367 exact IDs to Claude and retains 774 for this worker. Candidate groups are review aids, not evidence of equivalent semantics.

**Work remains in progress.** There is no claim of exhaustive AWS-B coverage or zero pending references. The implemented first waves contain 145 substantive native predicates in `aws_b_core.py`, `aws_b_loadbalancing.py`, `aws_b_regional.py`, `aws_b_cloudfront.py`, `aws_b_storage.py`, `aws_b_compute.py`, `aws_b_ecr.py`, `aws_b_apigateway.py`, and `aws_b_dms.py`. The twelve ready review shards cover 258 exact assigned references (516 retained references still require review); remaining references stay pending until substantive individual review. The source lead approves registry imports and active shards, validates provenance and merges the authoritative runtime catalog.

## Implemented behavior

Native predicates cover RDS instance/cluster log exports, backups, engine-specific snapshot tags, event subscriptions, endpoint policy and proxy TLS; Lambda tracing, concurrency, Insights layers and URL CORS; EKS audit logging, version-dependent envelope encryption, public endpoint configuration and VPC joins; ACM renewal/expiry-date thresholds, transparency, wildcard-domain and validation state; classic/modern load-balancer attributes, listeners and availability zones; CloudFront default/additional viewer behavior and custom-origin transport; Backup regional presence and report applicability; Inspector organization auto-enable configuration; SSM metadata encryption/sharing; DynamoDB PITR and encryption-description semantics; EFS customer-managed key joins; and DocumentDB/MQ configuration.

The metadata collector plugin uses only the main AWS `Requests` scheduler, its allowlist, authenticated session, cache, concurrency and retry accounting. Native SDK response fields and explicit denied/unknown/partial details are preserved. The plugin contains no client construction, resource creation, secret-value retrieval, document/function content retrieval or server execution. Literal environment values, commands, client secrets, origin custom headers and sensitive configuration content are discarded. The main collector remains AWS-A-owned.

Scope controls evaluate once per actual account/region and require complete dependency inventory. A successful empty Backup plan/vault list fails a requirement that the configuration must exist; denied, partial or missing inventory cannot become absence. Joined checks require uniquely resolved facts and complete dependency coverage. Global facts can cross region scopes only with verified matching account identity and explicit global-envelope evidence. Dates use the snapshot clock, never live wall time.

Every native security check maps to HackTricks Cloud Best Practices. Other compliance tags come only from reviewed pinned source references, preserving exact checklist/control/version metadata. Parameterized source queries remain pending until argument values and applicability are reviewed; matching evaluator hashes alone never proves equivalence.

## Substantive source exclusions

The first review shard separates 24 constant `manual_control` requirements into human questions. Their source returns an account identity, constant info status and a manual-verification reason; these are not automated predicates and do not increase native check counts.

Six source aliases contain verified predicate defects: the ACM RSA eligibility pattern excludes the only intended failure value; classic-ELB ACM certificate logic reverses its selected condition; and RDS parameter-group event status requires categories that contradict the source's reason and the documented category. Corrected native controls remain independent. One Lambda variable source inspects literal environment values for secret patterns and is unsuitable for the metadata-only data-access boundary; a names-only check would not be equivalent. Unimplemented checks or missing facts are not rejected.

The RDS category mismatch is evidenced by the [official event-category documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Events.Messages.html), which lists configuration-change events for parameter groups. ACM response enums and field semantics are documented in [CertificateDetail](https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html). Each reviewed source entry retains its revision, evaluator digest, exact query ID, reference URL and rationale.

## Validation checkpoints

```sh
.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_b_core.py tests/test_peaso_checks_aws_b_regional.py tests/test_peaso_checks_aws_b_metadata.py tests/test_peaso_checks_aws_b_ecr.py tests/test_peaso_checks_aws_b_apigateway.py
```

The native AWS-B service checkpoint is **135 passed in 1.85 seconds**. Fixtures cover pass/fail/manual/non-applicable states, missing and malformed data, denied details, input purity, engine eligibility, calendar boundaries, exact CORS equality, complete/partial joins, regional presence and cross-account isolation. The metadata suite validates every declared operation against installed official SDK models and confirms secret sentinels never enter returned facts.

Shared core changes for this track include `Check.target=scope`, dependency gating, frozen context, same-account global joins, native resource labels, manual questions and full-default collection planning. A focused isolated defensive run passed 116 tests before the latest service wave. The primary workspace also contains supervisor-owned escalation hooks, which this track does not author, validate or execute. Defensive testing and release export must exclude those hooks without changing the supplied primary files.

## Actual read-only metadata evidence

A live request used existing profile `naxusai-admin`, explicit `us-east-1`, four requested inventory types, and explicit limits of 40 calls, two pages and 30 resources. It completed in 6.0476 seconds, collecting 28 ACM certificates and one Lambda record, with complete empty DynamoDB/event-subscription inventories. The resource limit made Lambda inventory partial. Five selected native checks produced seven PASS, one FAIL, three UNKNOWN, two EMPTY and 21 NOT_APPLICABLE findings. These are configuration assessments, not exploit validation; no resources were created.

Private evidence is retained under `.cache/peaso-aws-b/task_eef1b206020a/metadata-live-report.json` and `metadata-live-summary.json`. This capped smoke is not the user-requested uncapped full-account scan. That full-default proof is owned by the collector/QA and isolated defensive release tracks.

## Default-full scan correction

The latest directive supersedes the initial bounded-default design. Default/no-filter or all-selected scans request every supported inventory, all supported accessible scopes/regions, and full pagination; calls/pages/resources/scopes limits are opt-in. Explicit caps remain visible as intentional partial coverage. Concurrency, throttling retries, repeated-token detection, cancellation and explicit hosted deadlines remain bounded. A targeted IMDSv2-only hardening request still plans instance facts only.

The shared budget now uses `None` for unlimited call/page/resource defaults. Tests prove 201 calls, 11 pages and 11,000 resources exceed the previous implicit limits without stopping, while explicit caps and cancellation retain honest coverage. The native legacy AWS bridge no longer injects an implicit `us-east-1` region filter. A safe defensive export delta with source hashes is retained in `.cache/peaso-aws-b/task_eef1b206020a/defensive-core-delta.json` for the release owner.

## Static customer metadata policy audit

The generator `scripts/peaso_deploy_customer_policy.py` verifies SDK operation mappings against a captured [AWS-published IAM action reference](https://awspolicygen.s3.amazonaws.com/js/policies.js) dated 2026-10-10, SHA256 `f8a0d6de023ec7ce1dbb2e65c88f11424f1f1e4d1ba45332c35b41da61ad36b9`. It handles S3 operation/action aliases and native namespaces including EFS, ELB, DocumentDB/Neptune, OpenSearch and Identity Center. New unreviewed operations fail closed. API Gateway GET grants use only the configured inventory/stage paths and partition-aware CloudFormation substitution. STS identity and configured credential exchange are excluded from this customer grant. Explicit value/content APIs are prohibited; configuration APIs can co-return literals, which collectors redact.

The static template contains 181 verified metadata actions, 5,890 compact policy characters and a separate, optional previously authorized `iam:GenerateCredentialReport` evidence-refresh statement. The generator validates the 10,240-character aggregate role-inline policy quota, including other existing inline policies, before writing. It does not deploy a role, modify live IAM or grant permissions.

```sh
.venv/bin/python scripts/peaso_deploy_customer_policy.py
.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_b_customer_policy.py
```

Result: **37 passed in 20.66 seconds**. Fixtures cover namespace/operation aliases, forbidden content and mutation APIs, current declared read completeness, STS omission, scoped Gateway paths, optional evidence refresh, unreviewed reads and aggregate policy limits. No cloud resources were created.

## Database and FSx wave

`aws_b_databases.py` adds 17 pure predicates over existing collected metadata: RDS instance minor upgrades/IAM/snapshot tags/Multi-AZ, cluster IAM/Multi-AZ, six Neptune cluster policies, and five FSx family-specific deployment/tag policies. Aurora instance exclusions, ONTAP generation-two Multi-AZ and the OpenZFS backup/volume conjunction are preserved explicitly. `reviewed_aws_b_databases.json` retains 26 exact source IDs, pinned revisions and query digests; no query parameters or narrower joins are silently merged.

```sh
.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_b_databases.py
```

Result: **24 passed in 2.42 seconds**. Ten ready shards now cover 238 retained references, leaving 536 of 774 requiring review; native B predicates total 120. Registry admission remains source-lead-owned. Existing collection facts suffice; no new SDK operation or live grant is required for this wave.

## Verified full-capture native diagnostics

Only ordinary defensive hardening findings and native metadata were inspected in the supervisor capture dated 2026-10-10T19:13:59.883245Z, containing 1439 resources and 6598 findings. Snapshot-file SHA256 `7af51da41afcd510075d3988b0d86b361e7e215c4014938339332eecd44187ab` was verified unchanged before/after re-evaluation. No separately owned escalation evaluator or graph was inspected or executed.

- ACM returned native `RSA-2048`, also shown in the [official DescribeCertificate CLI example](https://docs.aws.amazon.com/cli/latest/reference/acm/describe-certificate.html). The corrected native RSA policy now accepts only the enumerated hyphen/underscore spellings and retains raw evidence. Recheck: 36 UNKNOWN become 36 PASS.
- Successful named Lambda function configuration omitted optional Layers. Only positive successful detail plus function identity permits known-empty inference; missing/denied/malformed facts remain unknown. Recheck: 25 UNKNOWN become 25 FAIL for the literal layer-presence requirement. Image-baked monitoring is not asserted.
- ECS DescribeTaskDefinition succeeds, but omitted container user is inherited from uninspected image metadata. 21 nonroot and one host-network result remain UNKNOWN; no image contents are fetched or executed.
- Nine CodeBuild projects explicitly configure NO_ARTIFACTS. The literal upstream SQL lacks type eligibility and requires an explicit primary false encryptionDisabled flag; its known-success omission is FAIL. A separate `aws.b.codebuild.s3_artifact_encryption` defensive check evaluates primary and secondary S3 artifacts, handles default encryption only with positive native success and identity, and reports NOT_APPLICABLE when no S3 artifact is configured. Original mappings are not silently narrowed.

```sh
.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_b_capture.py tests/test_peaso_checks_aws_b_core.py
.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_b_inspector.py tests/test_peaso_checks_aws_b_metadata.py tests/test_peaso_checks_aws_b_customer_policy.py
```

Results: **144 passed in 4.96 seconds** and **66 passed in 9.45 seconds**, respectively. These are targeted defensive checks, not a fresh full repository result. Private sanitized receipts: `supervisor6-native-diagnostics.json`, `supervisor6-native-recheck.json`, `supervisor6-codebuild-recheck.json` in the ignored AWS-B cache directory. No cloud calls occurred during the captured native rechecks.

## Separate Inspector administrator applicability

`aws_b_inspector.py` defines four distinct admin-only variants using `inspector_organization_review`. The record preserves independent native GetDelegatedAdminAccount and DescribeOrganizationConfiguration statuses. Only positive ENABLED delegated-admin account proof bound to the authenticated caller can establish that another account owns organization configuration and produce NOT_APPLICABLE; missing, denied, disabled, malformed or ambiguous proof remains UNKNOWN/DENIED. Verified administrator configuration denial stays DENIED. Original four regional LEFT JOIN source variants and their mappings remain unchanged.

A minimal read-only smoke with existing credentials in us-east-1 took **2.5999 seconds / three calls**. Administrator lookup was unavailable and configuration read denied, so all four admin-only assessments honestly remained UNKNOWN. No cloud resources, live IAM grants or configuration writes occurred. Private receipts: `inspector-review-live-record.json` and `inspector-review-live-summary.json`. Static policy adds the officially verified `inspector2:GetDelegatedAdminAccount` action: current template **166 metadata actions / 5425 characters**.

## Current native core coordination and verification

Urgent CLI telemetry is implemented in `peaso/progress.py`, owned CLI/engine sections and shared collector dispatch/base. The existing run_scan/evaluate_snapshot call contracts are unchanged. Scan/collect/evaluate default to rate-limited stderr start/phase/settlement output with a 15-second heartbeat during blocked reads; `--quiet` suppresses it. Dynamic work uses unknown ETA. Runtime callback closure copies are kept out of original input and persisted outputs. Provider owners wire their actual schedulers; no SDK arguments, credentials or resource bodies enter progress events.

Unknown native coverage now reports missing fields, incomplete dependencies, denied/malformed metadata, unresolved applicability or observation windows, with an explicit no-conclusive-evidence fallback. Known machine error codes remain separately recorded, while arbitrary SDK text is omitted from coverage reasons. Narrow transferred Azure authentication allowlists permit optional vault_token and storage_token, encrypt them through the existing credential flow and redact normalized secret fields; the Azure owner implements audience-specific transport and no ambient fallback. Source lead now exclusively owns index/canonical-reference/Azure directory integration; this worker made no such index edits.

```sh
.venv/bin/python -m pytest -q tests/test_peaso_engine_progress.py tests/test_peaso_engine_coverage.py tests/test_peaso_engine_vault_auth.py
```

Result before the latest error-code compatibility adjustment: **31 passed in 8.87 seconds**. The focused read-only CLI ACM collection used explicit us-east-1/inventory/call/page/resource limits, returned valid snapshot JSON with 29 resources and 30 calls, produced eight stderr progress lines and persisted no callback. Its 98 envelopes include 96 intentionally omitted inventories; it is not a full-account collection. Private receipt: cli-progress-live-summary.json and associated snapshot/stderr/options under the ignored AWS-B cache. No cloud resources or live grants were created.

Cognito wave adds 12 individually reviewed Prowler predicates, preserving independent password flags, fourteen-character minimum and seven-day temporary-password limit, MFA ON (not OPTIONAL), deletion/signup policies, enforced threat protection and exact configured blocking responses. DescribeRiskConfiguration is a read-only metadata enrichment. Twelve source references are in reviewed_aws_b_cognito.json; native-ready B total **137**, reviewed retained references **250**, remaining **524**. Cognito+metadata+policy gate **68 passed in 12.29 seconds** before subsequent AWS-A operation additions.

Customer policy now also reviews CloudTrail LookupEvents as an exact read-operation exception, and IAM server-certificate/virtual-MFA metadata list actions against official API/action references. Current static template: **170 verified metadata actions / 5548 characters**. No deployment or live IAM grant occurs. Policy intentionally fails closed whenever other workers introduce a new unreviewed read operation, requiring a new mapping review rather than silent wildcard grants.

Orca orchestration send/check commands repeatedly timed out during this checkpoint. Recent coordinator updates may be undelivered; durable state is retained here, and runtime escalation is being retried. No worker_done has been sent for task_eef1b206020a. Exhaustive AWS-B work remains incomplete; do not settle it as succeeded or count pending rows as rejected.

## Latest combined owned defensive gate

```sh
.venv/bin/python - <<'PY'
import pytest
import peaso.engine as engine
from pathlib import Path
engine.CATEGORIES = ('hardening', 'exposure', 'least_privilege', 'iam_graph', 'network')
engine.privesc_techniques = lambda *args, **kwargs: []
def excluded(*args, **kwargs):
    raise AssertionError('Excluded separately owned evaluator')
engine._run_privesc = excluded
paths = ['tests/test_peaso_engine.py', 'tests/test_peaso_engine_scope.py',
         'tests/test_peaso_engine_progress.py', 'tests/test_peaso_engine_coverage.py',
         'tests/test_peaso_engine_vault_auth.py']
paths += [str(p) for p in sorted(Path('tests').glob('test_peaso_checks_aws_b*.py'))]
raise SystemExit(pytest.main(['-q', *paths]))
PY
```

Result: **392 passed in 19.48 seconds**, after correcting the known-machine error-code Markdown compatibility and reviewing three newly added AWS-A metadata actions. Native-only isolation is explicit and does not validate separately owned features. No broader full repository gate is claimed.

## Redshift and offline benchmark checkpoint

Redshift wave (`aws_b_redshift.py`, reviewed_aws_b_redshift.json) adds eight native predicates and eight exact retained source references: upgrade/routing/public-endpoint flags, audit-delivery configuration, seven-day automatic-snapshot threshold, exact default-name policies and encryption-plus-KMS-reference conjunction. The plugin hydrates DescribeLoggingStatus through the shared read scheduler; that permission was already audited. Missing KMS reference only becomes known absent after complete scoped inventory plus unique observed cluster identity; no database connection, log content, key ownership or effective transport claim is made. Multi-AZ interpretation and TLS parameter-group joins remain pending until their full native semantics are evidenced.

```sh
.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_b_redshift.py tests/test_peaso_checks_aws_b_metadata.py
.venv/bin/python examples/benchmark_peaso_aws_b.py --resources 50000 --output .cache/peaso-aws-b/task_eef1b206020a/native-benchmark-50000.json
.venv/bin/python -m pip check
```

Redshift/metadata result: **23 passed in 0.60 seconds**. Native-ready total is now **145**, reviewed retained source references **258**, pending **516**; registry admission remains lead-owned. Dependency integrity check: **No broken requirements found** in the existing installed environment.

The defined benchmark uses 50,000 independent synthetic RDS instances in one complete region, alternating encrypted and unencrypted, with one explicit defensive native check. It produced 50,000 findings in **3.829182 seconds** (13,057.62 findings/second). Provider SDK imports and socket connections were blocked and recorded zero attempts, cloud calls were zero, and snapshot content remained unchanged. Serialized report size was 87,093,644 bytes; this benchmark measures predicate evaluation, not full report serialization/Markdown rendering or other separately owned features. Private result retained in native-benchmark-50000.json.

## Final current-state checkpoint before coordinator recovery

Native-ready AWS-B count remains 145; twelve reviewed shards preserve 258 distinct retained references (195 ported, 20 merged, 43 substantive exclusions/manual), leaving **516 of 774** still requiring review. Exhaustive work is incomplete and must not be reported as succeeded. No unfinished reference has been reclassified merely to reach pending zero.

Additional regression fixes make ECS optional flags respect explicit field denial, recognize numeric UID-zero spellings, and reject malformed user formats; successful CodeBuild identity with denied name cannot infer missing optional encryption defaults. Capture/core fixtures: **157 passed in 0.53 seconds**. The engine checklist test now verifies actual pending-source counts/partial coverage, since incremental ports give every AWS checklist some native coverage; it no longer assumes a wholly unmapped checklist still exists.

The static policy audit now includes 181 verified metadata actions, 5890 compact characters: the Access Analyzer SDK namespace maps to IAM access-analyzer, with ListAnalyzers only (no creation), and newly declared account/Organizations/EC2 configuration/image/snapshot reads were reviewed against official APIs and the captured action reference. Gateway-only subsets contain no empty Action statement, STS authentication is not granted, and an empty permission selection fails closed. Latest policy-only gate: **42 passed in 7.03 seconds**. New future SDK operations still require explicit audit.

Read-only Cognito/Redshift metadata smoke: **2.2614 seconds / seven calls**, one Cognito pool with successfully hydrated Risk metadata, complete empty Redshift inventory. No resources or live grants were created; metadata-only private receipts are cognito-redshift-live-snapshot.json and cognito-redshift-live-summary.json under the ignored AWS-B cache directory. No provided-feature evaluator or graph was inspected or executed.

Orca coordination remains unavailable after the single recovery attempt: app process appears running, runtime stays starting/disconnected, and send/check/escalation commands reject runtime_unavailable. Registration/admission and shared owner coordination cannot be completed through the required channel. A failed-outcome worker_done will be attempted exactly once after the final checkpoint; if the runtime rejects it, completion is not recorded and the coordinator must recover this task from this durable handoff.

Latest final combined owned defensive-only gate: **417 passed in 9.93 seconds**, using the documented explicit isolation and test paths. Exhaustive AWS-B completion remains unfinished, with 516 assigned references pending; the unreachable Orca runtime prevents required coordinator reporting/admission.

### Native account-wide S3 Backup plan coverage

`aws.pci.s3.bucket_backup_plan` now has a native `s3_backup_plan_coverage` producer. It reuses the collector's actual, copied `DescribeRegions(AllRegions=True)` response for the authenticated account; validates every unique region name, partition and opt-in state; and visits every enabled region. Explicit region selections do not supply this full-account proof and remain UNKNOWN. Discovery failures and incomplete pages are never converted to empty coverage.

For each region the shared cached reader lists active Backup plans, gets the current plan and exact identity/version, lists selections, and gets each exact plan/selection pair. A plan must have complete uniquely named scheduled rules. List/Get version mismatch, deletion markers, duplicate identities, missing schedule fields and foreign ARNs prevent a completeness assertion. A complete native S3 bucket inventory and cached GetBucketLocation bind each own literal bucket ARN to its actual home region (absent location maps to us-east-1; EU to eu-west-1). A literal resource in a different selection region is removed before projection. Incomplete/denied locations or home regions outside the proved enabled universe prevent aggregate evidence. Native Resources absent/empty is implicit resource selection and remains UNKNOWN; it is never projected as a known empty selection. Selection resource lists, exclusions and optional native tag/condition fields come from full GET responses. No operator-supplied observation or completion flag is accepted. The aggregate sets AllEnabledRegionsCollected only after all these reads succeed, including a complete empty plan universe.

The frozen evaluator is unchanged: an exact literal bucket ARN in a current scheduled selection passes; complete literal selections without that bucket, or an explicit exclusion, fail. Wildcard/tag/condition selections the evaluator cannot resolve remain UNKNOWN. Provider permission failures retain denied inventory; the frozen predicate reports UNKNOWN for the unavailable dependency. This checks configured backup assignment, not completed backups, retention, object coverage, restore ability or actual IAM execution success.

Existing SDK/IAM actions are reused: ec2:DescribeRegions and backup:ListBackupPlans/GetBackupPlan/ListBackupSelections/GetBackupSelection, plus the existing bucket inventory permissions. No customer role, signed predicate, hash pin, catalog, owner policy or hosted input change is required. The implementation adds no threads and shares call/page/resource budgets and single-flight request cache with ordinary plan/selection reads. Tests use real botocore response validation through collect_live and the frozen engine; no real account, backup job or resource was created.

Primary schemas: [active plan listing and IncludeDeleted default](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListBackupPlans.html), [GetBackupPlan](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_GetBackupPlan.html), [ListBackupSelections](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListBackupSelections.html) and [GetBackupSelection](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_GetBackupSelection.html).

Region joins use [GetBucketLocation response semantics](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html); implicit selection limitations follow [BackupSelection](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_BackupSelection.html). Cross-region negative and same-region west-region positive are tested through the actual collector and unchanged predicate.
### Partial native Macie job coverage

The signed `aws_cis_s3_macie_classification_coverage` rule receives `s3_macie_region_coverage` from real account/Region API joins. This supports constrained job-configuration paths; it does not prove every object was classified or sensitive data is absent. No findings or scan history is manufactured.

The producer binds STS account/partition, complete `DescribeRegions(AllRegions=True)` and the scan's exact enabled-region set. Every required regional session, discovery, job page and detail must complete. Restricted subsets, denials, missing sessions, unsupported Regions and partial pages remain unavailable. A complete explicit region selection equal to the full native universe is permitted.

Automated discovery ENABLED stays UNKNOWN: classification-scope exclusions, including organization-admin scope, are not verified. GetClassificationScope is outside existing permissions; no synthetic DISABLED or new permission is introduced. Native PAUSED remains distinct from API denial.

With native automatic discovery DISABLED, exact RUNNING/COMPLETE jobs can cover a bucket only in its actual home Region, with explicit integer samplingPercentage=100 and absent/empty object scoping. Partial/omitted/invalid sampling, object filters, tag/unsupported criteria or foreign job ARN/account/Region remain UNKNOWN. Unresolved selections omit values and retain only a reason. Complete no-job configuration can FAIL. Global S3 ARNs never substitute for bucket-location joins.

Calls use existing read permissions and scan budgets/caches; no Macie enablement, job creation, IAM change, object/sample/secret retrieval or cloud mutation. Botocore-shaped tests run through the real collector/planner and frozen engine; no live-account success is claimed.

Primary: [session](https://docs.aws.amazon.com/macie/latest/APIReference/macie.html), [jobs](https://docs.aws.amazon.com/macie/latest/APIReference/jobs-jobid.html), [scope exclusions](https://docs.aws.amazon.com/macie/latest/APIReference/classification-scopes-id.html).

Conditional native Backup selections with no explicit Resources retain their actual nonempty Conditions or ListOfTags. The unchanged predicate marks these rows uncertain: they cannot prove literal coverage, but another independently validated scheduled literal selection may prove coverage. A complete collection containing only conditional selections or conditional plus explicit misses remains UNKNOWN. Native Resources absent/empty with no selectors still leaves the entire aggregate unavailable because it represents unresolved implicit all-resource selection. No wildcard, selector or tag resolution is synthesized.
