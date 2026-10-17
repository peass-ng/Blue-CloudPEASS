# AWS-A retained review coverage

After directive13, this worker retains **620 exact references** from `port_partitions.json` minus all `claude_aws_a.check_ids`. **620 reviewed, 0 pending**. No transferred IDs or Claude-owned files are edited. One previously accepted GuardDuty row transferred; lead was notified to preserve the approved association.

Review dispositions: 64 ported, 263 merged, 293 rejected-as-automatic with substantive classification. Manual attestation questions remain separate; invalid/obsolete predicates retain source/counterexamples/official references. Missing implementation or facts remains pending.

| Source service/file | References | Native predicates | Ported | Merged | Automatic rejection | Pending |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AWS/CloudWatch | 1 | 1 | 1 | 0 | 0 | 0 |
| AWS/Config | 1 | 1 | 1 | 0 | 0 | 0 |
| AWS/EBS | 1 | 1 | 1 | 0 | 0 | 0 |
| accessanalyzer | 2 | 1 | 1 | 0 | 1 | 0 |
| account | 15 | 2 | 2 | 9 | 4 | 0 |
| autoscaling | 1 | 1 | 1 | 0 | 0 | 0 |
| cloudtrail | 81 | 15 | 14 | 29 | 38 | 0 |
| cloudwatch | 161 | 9 | 9 | 1 | 151 | 0 |
| config | 14 | 2 | 2 | 0 | 12 | 0 |
| ebs | 12 | 4 | 0 | 12 | 0 | 0 |
| ec2 | 24 | 11 | 2 | 22 | 0 | 0 |
| guardduty | 7 | 5 | 0 | 5 | 2 | 0 |
| iam | 166 | 27 | 25 | 116 | 25 | 0 |
| kms | 9 | 1 | 1 | 8 | 0 | 0 |
| manual_control | 37 | 0 | 0 | 0 | 37 | 0 |
| organization | 1 | 0 | 0 | 0 | 1 | 0 |
| s3 | 33 | 3 | 3 | 15 | 15 | 0 |
| securityhub | 7 | 0 | 0 | 0 | 7 | 0 |
| ssm | 1 | 1 | 1 | 0 | 0 | 0 |
| vpc | 46 | 8 | 0 | 46 | 0 | 0 |

Native implementations include 13 IAM password/MFA variants,2 credential-usage variants,6 IAM lifecycle variants,2 regional Config/GuardDuty presence rules,7 initial CloudWatch variants,4 initial CloudTrail rules and6 separate CloudTrail/CloudWatch SQL variants. New lifecycle/SQL shards await lead import/whitelist validation before active-registry coverage. The transferred GuardDuty association is not counted as newly retained work. Every automatic rule has pass/fail/unavailable/malformed/denied and applicable boundary/join fixtures; field presence is not substituted for different time/scope predicates.

Read-only collector fixes: unbounded default pagination/calls/resources with explicit opt-in limits; all enabled-region discovery; pinned contexts; exact request allowlist and pre-client mutation/value guards; documented report-generation exception; typed credential metadata redaction; inherited SCP and explicit organization_parent path/completeness; global plugin raw-fetch/common-one-enrichment dispatch; transport retries and explicit unsupported endpoint evidence; Identity Center ordinary user/permission metadata; CloudTrail Insights metadata. No supplied exact-chain files are changed or executed, no git mutations by worker.

Independently verified invalid source conditions include Config enum-case/cross-account CTE bugs, obsolete supported-region skips, 15 distinct SQL metric-filter predicates (134 retained aliases) joining alarms by name alone rather than namespace/region/account, and 3 advanced CloudTrail selector false-PASS branches. Shards retain each source ID/revision/digest and official-provider/counterexample evidence. They do not claim corrected predicates are source-equivalent.

Pinned sources: Prowler `61d2cc55c4539a6b48a3cf9f3729d8f2af300882`, AWS compliance `803dda1f7555ed5cea959aef30cfa0719b030d8c`, AWS perimeter `2fe878449fb0d83b23333e373ee73849b0049364`. Lead owns imports and master framework/control/version conservation.

## Verification and live evidence

Targeted baseline/AWS-A/privacy suite previously passed 170; current routing/report/transport/CloudWatch/privacy/metric subset passed 124; Identity Center + AWS/CloudTrail subset passed77. Latest complete owned targeted suite passed **409 tests in44.15 seconds** using `.venv/bin/python -m pytest -q tests/test_peaso_collectors_aws.py tests/test_peaso_checks_aws_a*.py tests/e2e/test_metadata_credential_redaction.py`. Full-suite gate belongs root/supervisor and is not inferred from these subsets.

QA immutable collector-only final run:18 enabled regions,94 types,1420 collections,1439 resources,2241 counted calls,414.6787s; UNKNOWN0, unsupported_inventory0, cap errors0, omitted inventory[]; 18 Inspector organization denials and1 MemoryDB unsupported region remain explicit. Network300 resources/544 structural relations, no reachability claim. Existing credential report reused/generation0. This frozen historical pin predates newer Identity Center/Insight metadata and must not be misrepresented as latest-source live coverage. No further broad rerun required; targeted metadata proofs suffice for new facts.

Source-manifest digest `a226f83360ecc21d1d347490cf2ef9d000d135d1a914ec91dff8f795b2b613f6`; QA private receipt `aws-default-collector-final/summary.json` contains its exact evidence. This document stores no private customer IDs or credential/event payloads. One fresh narrow GetInsightSelectors read reported InsightNotEnabledException, confirming known absence for appropriate native FAIL; no resource/configuration writes.

Live resource ledger for this worker remains empty; all generation fixtures are stubbed, no teardown needed. Remaining source0 pending in owned reviews; active master-registry integration and independent lead audits pending and applicability/data-contract questions are recorded in [the handoff](handoff/task_8b67c08815d2.md).

Latest additions include read-only IAM access-key metadata (fingerprinted IDs), virtual MFA metadata (seeds/QR stripped), server-certificate metadata and explicit proven optional policy-list omissions. New date variants preserve SQL UTC date versus rolling-time boundaries, home-region applicability and INNER JOIN destination absence. Activity projector/cache/window guards are tested; all3source activity predicates now have substantive invalid-predicate reviews for per-region/first-page false-PASS counterexamples, awaiting lead independent audit. Orca runtime currently reports disconnected; durable handoff records coordination attempts and remaining work.

Current additional predicates:2 account-presence DTO checks,root-console-only MFA,3 identity-kind CloudShell attachment branches,attached managed-policy wildcard variant,source KMS eligibility variant,2 analyzer presence/active variants and3 S3 presence/MFA/bucket-account OR variants. Six shared native predicate groups account for36retained aliases with full semantic review and independent fixtures. New source41+15+8 rejection reviews retain concrete valid-configuration counterexamples and await lead audit; no missing-facts rejections. New read-only metadata inventories include account configuration,EC2 regional settings,Access Analyzer declarations andFlowLog configuration. No service enablement/resources/probes, no raw contact values. New master-registry imports/whitelist and customer-policy actions remain lead/B integration work; this document does not claim they are active.

Final owned review covers **93 distinct referenced native predicate IDs** across620source references (66 IDs introduced by ported associations, including3 identity-kind CloudShell branches). All620source revision/digest proofs validated against pinned master rows; all supported associations resolve to real functions, fixtures, declared collector dependencies and HackTricks tags. Manual/invalid reviews retain auditable reasons; this is owned-shard review completion and does not claim lead activation or full-repository release validation.

Account-wide CloudTrail/Config derived inventories require successful all-enabled-region discovery. Explicit region subsets cannot assert full-account absence. Conditional sourceINFO staysMANUAL, with no inventedFAIL; trusted-account queries bind existing metadata.trusted_scope_ids rather than silently trusting source sample account defaults. Read-only AMI/snapshot queries explicitly use self-owner filters and include disabled/deprecated owned images; snapshot attribute denial affects only permission field coverage.

EC2 user-data source check stores only two indicator booleans computed transiently before request-cache/future/snapshot retention; scripts/base64/values are discarded, bounded to documented16KiB, and never executed or credential-validated. No live userdata read was performed. Heuristic false positives/negatives remain source limitations; its result is potential indicators, not proof of credential presence/absence.

Fresh narrow collector-only smoke:11read calls,1.9358seconds,4metadata resources,0writes/report-generation/probes. Six requested types explicitly collected/empty. Frozen snapshot SHA256`706d3a5d952c80fc1cb35ad12ba063866f48756ede87c0eef5193d96a87dd047`; private receipt /tmp/peaso-aws-a-ctx_f2b5ca158b85-metadata-smoke-summary.json. Its measured collector source SHA256`e54cb91ef91da6b4fcc91e83383da0a4934c465a65b34c06d711528905519e48` predates later metadata extensions and is not claimed latest code. No private resource IDs/credentials/raw values in this document.

Predicate counts in each source-service row count referenced native IDs and are not additive where one predicate is shared by services. Source rejection classes:252invalid-predicate reviews,1intrusive-unsuitable content test and40manual-attestation questions; all are classified separately and retain source evidence. New audits remain inactive until registry-lead acceptance. Every automatic predicate requires captured successful data or honest unavailable/manual outcome; no pending rule was relabeled because implementation/facts were absent.

IAM ServicesLastAccessed (user_long_lived_keys_only_iam_sts, user/role bedrock and user sagemaker staleness) is collected with `iam:GenerateServiceLastAccessedDetails` (Granularity `SERVICE_LEVEL` only) and paginated `iam:GetServiceLastAccessedDetails`. Both are granted by AWS managed `SecurityAudit` (v94: explicit Generate action, `iam:Get*`) and `ReadOnlyAccess` (v190: `iam:Generate*`, `iam:Get*`), checked read-only on 2026-10-11, and both are in `infra/aws/customer-role.json`. Generation creates only a report job. Reports are generated for every user, and for every role whose inline or attached managed policy documents could allow a `bedrock` action (a conservative match on wildcards, NotAction and unknown or malformed documents). Other roles carry `ServicesLastAccessedStatus.reason=identity_policies_cannot_allow_namespaces` and the role bedrock check is NOT_APPLICABLE for them. Collection is bounded by concurrency (default 4), adaptive pacing of IAM report calls, 1 to 5 s poll backoff and a 120 s deadline. A failed, denied or late job leaves only that principal UNKNOWN.
