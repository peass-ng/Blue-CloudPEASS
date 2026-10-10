# AWS-A exhaustive review coverage

Authoritative partition: **1114 assigned source references** in **514 candidate groups** from `peaso/rulepacks/port_partitions.json`. Groups are review candidates, not proof of equivalence.

Current review: **108 closed, 1006 pending**; 13 ported references, 55 merged references, 40 manual-attestation automatic rejections. No invalid/obsolete predicate has yet been rejected in this track.

**13 new distinct automatic IAM predicates** are implemented, plus five existing GuardDuty feature predicates referenced by exact reviewed aliases. The 40 individually reviewed manual source questions are preserved in the separate manual catalog; none is registered or counted as an automatic check.

| Source service/file | Assigned | Ported | Merged | Manual automatic rejection | Pending |
| --- | ---: | ---: | ---: | ---: | ---: |
| accessanalyzer | 2 | 0 | 0 | 0 | 2 |
| account | 16 | 0 | 0 | 3 | 13 |
| autoscaling | 1 | 0 | 0 | 0 | 1 |
| cloudtrail | 84 | 0 | 0 | 0 | 84 |
| cloudwatch | 178 | 0 | 0 | 0 | 178 |
| config | 15 | 0 | 0 | 0 | 15 |
| ebs | 27 | 0 | 0 | 0 | 27 |
| ec2 | 172 | 0 | 0 | 0 | 172 |
| elb | 2 | 0 | 0 | 0 | 2 |
| guardduty | 31 | 0 | 5 | 0 | 26 |
| iam | 258 | 13 | 50 | 0 | 195 |
| kms | 30 | 0 | 0 | 0 | 30 |
| manual_control | 37 | 0 | 0 | 37 | 0 |
| networkfirewall | 22 | 0 | 0 | 0 | 22 |
| organization | 2 | 0 | 0 | 0 | 2 |
| organizations | 5 | 0 | 0 | 0 | 5 |
| s3 | 98 | 0 | 0 | 0 | 98 |
| securityhub | 9 | 0 | 0 | 0 | 9 |
| ssm | 3 | 0 | 0 | 0 | 3 |
| vpc | 122 | 0 | 0 | 0 | 122 |

Reviewed IAM variants retain the account LEFT JOIN: successful complete-empty password-policy collection fails, while missing/denied/partial/malformed collection remains unknown. SQL reuse >=24 is separate from Prowler exactly24; SQL age <=90 is separate from Prowler positive 1–90; compound length8 and length14/reuse/age/composition conditions remain distinct. Root-summary MFA/key counts and credential-report all-principal/console-only MFA predicates are also separate.

Source pins: Prowler `61d2cc55c4539a6b48a3cf9f3729d8f2af300882`, AWS compliance `803dda1f7555ed5cea959aef30cfa0719b030d8c`, AWS perimeter `2fe878449fb0d83b23333e373ee73849b0049364`. Shards preserve exact source keys, revisions and evaluator digests; the lead merges all root framework/control/version records.

## Release correctness work authorized during this track

- Default call/page/resource limits are `None`; only explicit requested caps produce intentional partial coverage. Default scan no longer has hidden account, region or assume-role truncation. SDK concurrency, retries, repeated-token detection, cancellation and explicit deadlines remain bounded.
- Default regions are discovered with `DescribeRegions(AllRegions=True)` per pinned credential/account context and filtered to opted-in or opt-in-not-required. Explicit region scopes/options are respected. Denied discovery never silently scans a default region.
- Credential-shaped tag/label/header values and typed environment values are redacted; benign tags and security booleans remain. Redacted values carry unavailable fact coverage so predicates cannot treat them as complete evidence.
- The coordinator explicitly authorized evidence-only `GenerateCredentialReport` after actual `ReportNotPresent`, `ReportExpired` or `ReportInProgress`; fresh cached GET polling is bounded. No IAM configuration, Access Analyzer or other resource creation is permitted.
- Inherited SCPs are collected from account through observed OU parents to root, using read-only list/describe operations. Policy documents are deduplicated; every attachment retains its target type and observed parent path. Denied/malformed/cyclic parent visibility remains incomplete, never an effective-policy completeness claim.

Verification includes the explicit 205-page/205-call/10,455-resource default pagination case, per-account enabled-region discovery, explicit cap and cancellation/deadline cases, authorized credential-report generation/readiness, and inherited-SCP path/dedup/denial/cycle tests. Targeted release/privacy/IAM tests were green; current final test count and actual default live CLI receipt are being updated.

Existing legacy AWS collector tests need expectation changes for explicitly authorized report generation and automatic region discovery; QA/coordinator has been notified. The exact default CLI live gate is delegated to QA and currently awaits core honoring the coordinator directive excluding supplied `peaso.privesc` exact-chain execution. No supplied modules were imported or edited by this track.

Remaining work: review and implement all pending assigned predicates and required declared facts, per-service semantic deduplication, all applicable pass/fail/unknown/denied/malformed/applicability/differential cases, final framework conservation, full-suite cooperation and captured live snapshot evidence. Missing collector facts or implementation remains pending and is not a rejection reason.
