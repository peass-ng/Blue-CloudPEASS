# Audit log attack analysis

The Attack Analysis tab is an investigation workflow. It uses a saved connector,
checks access to a specific audit source, then evaluates a bounded slice of
events. A result means that a reviewed rule matched observed evidence. It is
not an attribution of malicious intent, and an empty result is not proof that
the environment was attack free.

## Rule and event format

The canonical detection rules are Sigma YAML in the public
`peass-ng/peasso-cspm-detections` repository. The server loads an immutable,
reviewed commit by default. In Attack Analysis, **Detection rules** can instead
select **Latest version from detections main**. The access check resolves
`main` to a commit, downloads and validates its complete rule pack, and binds
that exact commit and pack digest to the short-lived analysis token. The run
uses the same commit even if `main` moves meanwhile. If the latest pack cannot
be read or parsed, the access check blocks analysis; it does not silently fall
back to an older pack. The result and downloaded JSON include the selected
commit and digest. Rule YAML is not shipped in
this public source repository or its Python package. If the pinned source
cannot be read, the access check blocks analysis instead of silently running
without detections. Public tests use synthetic rules only.

Hosted loading needs outbound HTTPS to `codeload.github.com`; the latest option
also needs `api.github.com` to resolve `main`. The latest option uses one bounded
GitHub REST request per access check, subject to GitHub's anonymous API quota,
then downloads the archive by immutable commit. The default pinned pack has an
expected SHA-256 digest over its rule files. No GitHub
token or AWS Secrets Manager access is needed. An operator may override the default with
`HACKTRICKS_CSPM_RULES_GITHUB_REF`; overriding the repository through
`HACKTRICKS_CSPM_RULES_GITHUB_REPO` also requires an exact commit ref. A custom
pack may set `HACKTRICKS_CSPM_RULES_PACK_SHA256` for its reviewed rule-file
digest. The first successful read is cached per process for that commit. Local development may
use `HACKTRICKS_CSPM_RULES_DIR` to point at a checkout; hosted Cognito mode
never falls back to this directory.

New Sigma rules can be used without a CSPM release when they match fields the
installed normalizers already produce. Simple account-scoped AWS CloudTrail
API rules can opt into `x_cloudtrail_raw: true` in the rules repository. These
rules must match an exact `event.source`, `event.name`, `event.category`,
`event.outcome: success`, and `resource.type`; they may also match
`event.read_only`. The adapter validates a successful CloudTrail envelope and
same-account resource ARN, and exposes only those bounded fields. Its target
reference is a stable hash of the ARN. It never copies request parameters,
responses, query text, or object contents into a finding. This lets future
simple service/action detections ship through the latest catalog alone.
An optional `x_cloudtrail_resource_path_prefix` can narrow such a rule to a
literal resource path such as `/keyspace/system`; the path is used only for
matching and is never included in the finding. Wildcards and arbitrary regular
expressions are rejected.
Techniques that require parsing request content, a new provider API read, or
correlation still require CSPM code. Historical S3 jobs retain their separate
pinned catalog contract; this selector applies to interactive Attack Analysis.

The current evaluator deliberately
accepts a small portable subset: one exact-match selection, conjunction across
fields, and OR lists within a field. Unsupported Sigma constructs fail closed.
Raw provider events are normalized to common `event.*`, `actor.*`, `target.*`
and `cloud.provider` fields before matching. Azure Activity Log first joins the Started
request with the Succeeded outcome for one role-assignment operation; the
pinned Sigma selection then decides which joined grants to report. This join
is application code, not portable Sigma correlation syntax. The event IDs and
source scope remain available for investigation. OCSF is the intended interchange schema
for stored large-scale batches; the interactive preview does not yet emit OCSF
or Parquet.

Sigma specification: <https://sigmahq.io/sigma-specification/>
OCSF in Security Lake: <https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html>

## Execution and coverage

The interactive preview uses bounded SDK/API reads and the in-process Sigma
subset evaluator. AWS Event History reads management events from one Region for
at most 90 days; S3 reads CloudTrail `.json.gz` objects under one selected
account, Region and day. GCP and GKE read Cloud Logging for a selected project
and recent 24-hour window. Azure reads one subscription's Activity Log for the
same window and reports a successfully correlated Owner or User Access
Administrator self-assignment at subscription scope. The Started event carries
the assignee and role, while a matching Succeeded event supplies the outcome.
This proves the assignment operation, not malicious intent or net new access.
The separate Microsoft Entra source checks the connector tenant's directory
audits and filters to `Add member to role`. Its reviewed rule reports a direct
Global Administrator self-assignment. Generic credential-add activity remains
excluded because routine rotation cannot be separated by event name alone.
The current
request stops at 2,000 events, and AWS S3 stops at five objects and rejects
any object above the decompression bound. The response reports read coverage
and truncation, including when S3 listing reaches its ten-page limit. Analysis
is synchronous and results are not stored as a durable investigation job.

The repository also contains historical ingestion, indexed matching and S3/SQLite history-store components with their own tests. These library components do not establish a hosted historical-analysis service: the interactive API remains a bounded preview. Parquet/DuckDB support is optional analytics functionality; synthetic benchmarks do not establish customer log throughput, recall or production cost.

## Access

- AWS Event History: `cloudtrail:LookupEvents`. The hosted customer-role
  template already grants this action.
- AWS S3 trail: `s3:ListBucket` on the log bucket and `s3:GetObject` on the
  selected prefix. An SSE-KMS object also needs `kms:Decrypt` in both IAM and
  the KMS key policy. A central logging account may need to add the customer
  role to its bucket policy. The access check probes a real object; listing
  an empty prefix does not prove object or KMS access.
- GCP Audit Logs: use `logging.entries.list` on an explicit project. Data
  Access records require additional private log visibility and may not be
  enabled. A GKE Kubernetes audit source lives in Cloud Logging, not in a
  generic Kubernetes API endpoint.
- Azure Activity Log: subscription-scoped reads do not include Entra audit
  records or management-group assignments. Historical Log Analytics data
  needs separate workspace access.
- Microsoft Entra directory audit: a bounded Microsoft Graph read checks
  `AuditLog.Read.All` application permission with tenant admin consent. The
  connector token must belong to its configured tenant. A read of 100 existing credential-add audit records
  found just two app actors affecting 100 targets, so a raw activity rule was
  withdrawn as too noisy; this pattern is not proof that those events were benign.
  The new role rule requires a successful direct Global Administrator grant
  from an actor to that same user. A bounded read of 17 existing `Add member to
  role` records established the Graph field shape and no positive self-grant;
  the positive branch remains synthetic only.
- Kubernetes: generic clusters may write audit events to a file or webhook;
  `kubectl get events` is not an audit-log source.

AWS: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html>
GCP: <https://docs.cloud.google.com/logging/docs/access-control>
Azure: <https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log>
Azure RBAC change history: <https://learn.microsoft.com/en-us/azure/role-based-access-control/change-history-report>
Kubernetes: <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>

## Detection quality and validation

The pinned pack contains **49 rules**. Its digest is `c0c465eb02dd91161c789832dedf1c8e3edfebb38f9e040f2d3db8d88b68ea98`. Runtime normalizers preserve source IDs, exact identities, successful/denied outcomes and correlation requirements. Unsupported, incomplete or contradictory evidence must not produce an accepted match.

Tests cover positive, negative, malformed and conflicting event shapes. Some rules also have bounded live audit evidence; that does not measure customer false-positive rates or complete technique coverage. Source-page links are navigation evidence rather than detection recall. Four experimental candidates for GuardDuty evasion, access keys, Key Vault purge and Kubernetes TokenRequest are excluded from this release because their signal or evidence was insufficient.

Run the affected tests in `tests/test_attack_detection_*.py`, plus provider readers and the Azure self-grant correlator when changing a source. `scripts/attack_detection_coverage.py` produces source-reference coverage; `scripts/attack_detection_technique_inventory.py` builds a review queue. Neither converts a technique heading into verified runtime support.

The public pack and runtime normalizers evolve together. Pin the exact reviewed commit and digest, keep unsupported Sigma constructs rejected, and verify positive and negative examples before changing a rule. Audit activity can be legitimate administration: results require investigation and do not establish malicious intent, executable escalation or newly effective access.
