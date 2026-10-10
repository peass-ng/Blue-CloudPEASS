# AWS-B native coverage track

This track owns AWS service configuration checks outside the AWS-A IAM/account/Organizations/S3/EC2/VPC/network/KMS/CloudTrail/Config/GuardDuty/SecurityHub/CloudWatch partition. The authoritative source-ID assignment is `peaso/rulepacks/port_partitions.json`; the current AWS-B assignment contains 1,141 references. Candidate groups are review aids, not evidence of equivalent semantics.

**Work remains in progress.** There is no claim of exhaustive AWS-B coverage or zero pending references. The implemented first waves contain 72 substantive native predicates in `aws_b_core.py`, `aws_b_loadbalancing.py`, `aws_b_regional.py`, `aws_b_cloudfront.py`, and `aws_b_storage.py`. The first two ready review shards cover 124 exact assigned references; later storage associations await individual source mapping. The source lead approves registry imports and active shards, validates provenance and merges the authoritative runtime catalog.

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
.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_b_core.py tests/test_peaso_checks_aws_b_regional.py tests/test_peaso_checks_aws_b_metadata.py
```

The current AWS-B checkpoint is **93 passed**. Fixtures cover pass/fail/manual/non-applicable states, missing and malformed data, denied details, input purity, engine eligibility, calendar boundaries, exact CORS equality, complete/partial joins, regional presence and cross-account isolation. The metadata suite validates every declared operation against installed official SDK models and confirms secret sentinels never enter returned facts.

Shared core changes for this track include `Check.target=scope`, dependency gating, frozen context, same-account global joins, native resource labels, manual questions and full-default collection planning. A focused isolated defensive run passed 116 tests before the latest service wave. The primary workspace also contains supervisor-owned escalation hooks, which this track does not author, validate or execute. Defensive testing and release export must exclude those hooks without changing the supplied primary files.

## Actual read-only metadata evidence

A live request used existing profile `naxusai-admin`, explicit `us-east-1`, four requested inventory types, and explicit limits of 40 calls, two pages and 30 resources. It completed in 6.0476 seconds, collecting 28 ACM certificates and one Lambda record, with complete empty DynamoDB/event-subscription inventories. The resource limit made Lambda inventory partial. Five selected native checks produced seven PASS, one FAIL, three UNKNOWN, two EMPTY and 21 NOT_APPLICABLE findings. These are configuration assessments, not exploit validation; no resources were created.

Private evidence is retained under `.cache/peaso-aws-b/task_eef1b206020a/metadata-live-report.json` and `metadata-live-summary.json`. This capped smoke is not the user-requested uncapped full-account scan. That full-default proof is owned by the collector/QA and isolated defensive release tracks.

## Default-full scan correction

The latest directive supersedes the initial bounded-default design. Default/no-filter or all-selected scans request every supported inventory, all supported accessible scopes/regions, and full pagination; calls/pages/resources/scopes limits are opt-in. Explicit caps remain visible as intentional partial coverage. Concurrency, throttling retries, repeated-token detection, cancellation and explicit hosted deadlines remain bounded. A targeted IMDSv2-only hardening request still plans instance facts only.

The shared budget now uses `None` for unlimited call/page/resource defaults. Tests prove 201 calls, 11 pages and 11,000 resources exceed the previous implicit limits without stopping, while explicit caps and cancellation retain honest coverage. The native legacy AWS bridge no longer injects an implicit `us-east-1` region filter. A safe defensive export delta with source hashes is retained in `.cache/peaso-aws-b/task_eef1b206020a/defensive-core-delta.json` for the release owner.
