# AWS review — 19 October 2026

This is the acceptance index for the AWS review. It distinguishes source accounting, mapping integrity, synthetic execution, native SDK field evidence, and live collection. **This review does not certify every AWS predicate as exhaustively correct or live tested, and it is not a production publication receipt.**

## Inventory and source coverage

- **1,404 active AWS checks**, 1,556 registered including 152 archived definitions.
- **35 new native admissions**, with 175 explicit PARTIAL requirement links; unsupported historical listener and Lightsail-to-SSM identity contracts are archived instead of inferred from configuration or names.
- All **2,336** current source controls are enumerated: Prowler 662, Steampipe compliance 1,612 and perimeter 62. **2,248** have active native lineage; **88** have individual exclusions. A lineage match is not a proof of predicate equivalence.
- Prowler AWS pin: `7f9eb2cb11ea931f54acccb6e49152358ccf949d`. Other providers retain their own source pins.
- Steampipe compliance pin: `803dda1f7555ed5cea959aef30cfa0719b030d8c`; perimeter: `2fe878449fb0d83b23333e373ee73849b0049364`.

See [Prowler source accounting](prowler-parity.json), [Steampipe source accounting](steampipe-parity.json), and [individual exclusions](remaining-source-exclusions.json). Exclusions include manual attestations, customer trust/approval decisions, retired services, third-party intelligence, and demonstrably unsound source predicates. Secret content is an explicitly selectable collection scope, not a blanket exclusion.

## What has been checked

The [per-control checklist](checklist.csv) contains every active AWS ID. The exact inputs are hashed in [checklist.inputs.json](checklist.inputs.json). `/tmp/work.md` is the matching working copy.

| Evidence | Current result | What it proves |
|---|---:|---|
| Source-bound gate history plus directed rechecks | 12,885 passing nodes, one skipped | Includes historical receipts; current execution batches are recorded below |
| Registered callbacks executed in passing tests | 1,556/1,556 | Runtime invocation, not complete semantics |
| Active checks with observed PASS witness | 1,404/1,404 | A positive fixture exists and was executed |
| Numbered compliance mapping integrity | 1,182 checks | Bidirectional IDs and assurance match canonical decisions |
| Checks without numbered requirements | 222 checks | No fabricated numbered compliance claim |
| Reviewed HackTricks security membership | 1,061 checks | Security-scope membership and approved reference host |
| Outstanding source-association decisions | 0 | Every divergent association has an explicit disposition |
| Native-shape producer evidence | 56 checks | Bounded SDK/native-field contracts in the field ledger |
| Derived producer evidence | 235 checks | Derived evidence with the limits recorded per ID |
| Producer evidence remains witness-only | 1,113 checks | Fixture/source witnesses do not establish complete native field production |

[Native contracts](native-contracts.json), [field producers](field-producers.json), [mapping integrity](framework-mappings.json), and [requirement decisions](requirement-associations.json) retain these layers separately. No checklist row claims complete semantic verification. Nine active controls lack an observed FAIL in this selected gate; their negative expectations and reasons are listed in `native-contracts.json`, rather than replaced with artificial FAIL cases.

## Live AWS validation

[Live receipt](live-metadata-smoke.json): `example-audit-profile`, one account, `us-east-1`, 91.18 seconds. Collection returned 49 collected, 219 empty, eight partial, four unknown, one denied and 86 not-collected inventories. The 5,000-resource cap and inaccessible/unsupported services prevent complete live coverage. All 1,404 active IDs were selected for evaluation; absent-resource aggregates are distinct from emitted findings.

The harness rejected mutating operation names. **Zero attempted writes were observed, zero infrastructure resources were created, and no cleanup was needed.** Access Analyzer creation and IAM evidence generation were excluded from this smoke run; optional code/image/log content scans were disabled. The raw snapshot is private under `/tmp`, mode 0600, and is not committed. The public receipt contains operation names and aggregate/per-check statuses, not resource documents or credentials.

## Run AWS tests and scans

```bash
# Inventory of checks, framework mappings and collector capabilities
.venv/bin/python -m peaso catalog --format json --output /tmp/peasso-catalog.json

# Read-only configuration scan; use the AWS guide for regions and limits
.venv/bin/python -m peaso scan --provider aws --profile example-audit-profile \
  --options-file /path/to/aws-options.json --output /tmp/aws-report.json

# Re-evaluate an existing snapshot without AWS access
.venv/bin/python -m peaso evaluate --help
```

Use [AWS CLI guidance](../peaso-aws.md) and the [collector permissions/options guide](../peaso-aws-collector.md). The generated customer role contains 751 reviewed metadata actions in 5 policies below AWS's 6,144-character policy limit. Optional application content permissions remain outside the default role. Source scanning uses **Kingfisher SDK 1.4.0 and TruffleHog 3.92.5**, with secret-value deduplication and credential verification disabled; see [scanner validation and limitations](dual-scanner-review.md).

## Reproduce the review

```bash
.venv/bin/python scripts/audit_aws_prowler_parity.py --cache /path/to/pinned-prowler-cache
.venv/bin/python scripts/audit_aws_steampipe_parity.py --cache /path/to/pinned-steampipe-cache
.venv/bin/python scripts/audit_aws_framework_mappings.py
.venv/bin/python scripts/audit_aws_requirement_associations.py --cache /path/to/pinned-prowler-cache
.venv/bin/python scripts/audit_aws_review_checklist.py --work-log /tmp/work.md
.venv/bin/python scripts/peaso_compliance_materialize.py
```

The materializer checks by default; `--write` explicitly regenerates catalogs. To run the scoped native gate from scratch, use `scripts/audit_aws_native_contracts.py --run-gate --receipts /tmp/aws-native-review`. The wide gate remains a historical baseline; subsequent runtime changes have directed SDK and affected-callback rechecks, with original receipts retained. Original failures and explicit rechecks remain in the receipt chain.

## Remaining acceptance limits

- Source reconciliation and mapping consistency are complete at the recorded pins; **complete per-check native-field and semantic proof is not complete**. The 1,113 witness-only rows are limits of the field-level proof ledger, not 1,113 missing implementations or hidden passes. Source review and bounded consumer tests are recorded separately.
- One live account/region does not instantiate every AWS service or prove every positive and negative condition. Empty, denied, partial and unsupported inventories remain visible.
- PARTIAL mappings do not certify the complete compliance obligation. Customer-specific approvals and historical organizational processes are not inferred.
- Current changes are local. Production publication requires the separate release owner's reviewed infrastructure contract, source snapshot, final release gate and GitHub Actions apply. This report does not assert that publication happened.

## Directed closure follow-up

The 1,129 previously witness-only IDs were divided into three source-review cohorts: [identity](identity-closure-review.json) (204), [network](network-closure-review.json) (212), and [services](services-closure-review.json) (713). Each ID has an explicit disposition; review accounting does not establish complete semantics. Follow-up SDK cohorts independently exercised 105 identity, 45 network and 88 data-service consumers. The [identity](identity-sdk-closure-review.json), [network](network-sdk-closure-review.json) and [data](data-sdk-closure-review.json) reports retain exact tested branches and unproved contracts.

A consolidated affected SDK pipeline run passed 921 cases, and 241 affected callback fixture cases passed. Original failures and directed rechecks remain under `/tmp/peasso-aws-review-20261019/final-closure`. Subsequent edits by other agents can invalidate broad pipeline fingerprints; acceptance is tied to captured source hashes, not to an assertion that the shared working tree stopped changing. The bounded source archive is 378 KB and contains no cloud data or credentials.

Repairs include metric account binding, native protocol and method-setting representations, foreign resource identity joins, missing SNS policy evidence, CodeBuild missing builds, missing database TLS parameters, and Backup exclusion/tag-value matching. Four IAM usage-history checks now have selection-gated AWS Read-classified report producers with bounded polling and pagination. The current customer role includes exactly their two documented Read-classified report permissions; source capture and role tests use the project environment (botocore 1.43.38), not the older system SDK. Production publication is separate.

Every checklist row includes its existing UI group; 4,028 check/analysis IDs passed the group coverage audit, and the 17 group tests passed. New IDs must reuse those groups. Evidence explanations remain one to three brief natural-language sentences; the Backup explanation was updated to reflect exact tag-key/value matching. This follow-up created no new control IDs.

The newest Prowler HEAD comparison is recorded in [current upstream comparison](current-upstream-comparison.json): its AWS provider/check/compliance blobs match the accepted AWS pin, so the pin was retained. The [source conservation decisions](source-conservation-decisions.json) close eleven remaining source-association decisions, including one additional PARTIAL requirement link (175 total native-extension links).

The [48-ID CloudTrail/KMS follow-up](trail-kms-sdk-closure-review.json) independently executed all 48 selected consumers: 86 directed tests passed after two reproduced foreign-identity defects were fixed. Twenty-three adjacent KMS/CloudTrail cases passed. These contracts describe tested branches only; earlier broad pipeline receipts remain source-bound history after later edits. The [local IAM role acceptance](iam-report-role-acceptance.json) records the generated template, exact read-permission delta and targeted checks; no production deployment occurred.


## Latest accumulated acceptance

The AWS-only gate executed 10,638 passing cases, one skip and 34 failures. All 34 failures were reproduced and explicitly rechecked: 31 came from a Resource-only IAM test parser and stale analyzer AI-key isolation assertions, two from stale collector/worker test fixtures, and one from an invalid synthetic organization ID in an intended-PASS policy fixture. No runtime weakening was needed. The final combined recheck passed 64 cases, including 17 additional IAM-parser regressions; the original failed receipt remains available.

At the current collector source, the consolidated SDK-to-registered-consumer batch passed **1,205 tests**. The [15-ID workload follow-up](workload-resource-followup-review.md) closes its earlier resource-case gaps with 45 focused tests and five reconciled CloudTrail cases. The [optional Lambda public pipeline](optional-lambda-public-pipeline-review.md) adds eight passing cases with both installed, offline detectors: positive, negative, denied, integrity/incomplete, default-off and unselected. Its duplicate synthetic secret produces one merged leak. Those eight tests are separate from the 1,205-case batch.

The [latest acceptance record](latest-acceptance.json) binds the checklist, mappings, source accounting, current pipeline and exact test receipts. The aggregated 12,885 passing nodes combine current execution and retained historical supplements; they are not a fresh all-cloud or exhaustive-live suite. All 1,556 registered callbacks have passing execution evidence, including all 1,404 active IDs. The single skip and nine active IDs without an observed FAIL remain explained in the native ledger.

No confirmed active required-producer defect or unresolved source-association decision remains in this bounded review. Full branch coverage, exact equivalence to every upstream algorithm, and live behavior for every service/region remain unproved. Read-only configuration scans can be tested now; optional content requires explicit selection and its extra read permissions. No production deployment or new cloud infrastructure was performed by this acceptance.
