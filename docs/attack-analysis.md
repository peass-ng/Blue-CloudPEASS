# Audit log attack analysis

The Attack Analysis tab is an investigation workflow. It uses a saved connector,
checks access to a specific audit source, then evaluates a bounded slice of
events. A result means that a reviewed rule matched observed evidence. It is
not an attribution of malicious intent, and an empty result is not proof that
the environment was attack free.

## Rule and event format

The canonical detection rules are Sigma YAML in the public
`peass-ng/hacktricks-cspm-detections` repository. The server can load the reviewed
pack at pinned commit `c4e533f4393c7633a8f320a845f79de59454be03` by
default. Rule YAML is not shipped in
this public source repository or its Python package. If the pinned source
cannot be read, the access check blocks analysis instead of silently running
without detections. Public tests use synthetic rules only.

Hosted loading needs outbound HTTPS to `codeload.github.com`. A single bounded
archive from the pinned commit avoids GitHub's anonymous REST API quota. The
default pack also has an expected SHA-256 digest over its rule files. No GitHub
token or AWS Secrets Manager access is needed. An operator may override the default with
`HACKTRICKS_CSPM_RULES_GITHUB_REF`; overriding the repository through
`HACKTRICKS_CSPM_RULES_GITHUB_REPO` also requires an exact commit ref. A custom
pack may set `HACKTRICKS_CSPM_RULES_PACK_SHA256` for its reviewed rule-file
digest. The first successful read is cached per process for that commit. Local development may
use `HACKTRICKS_CSPM_RULES_DIR` to point at a checkout; hosted Cognito mode
never falls back to this directory.

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

For a full historical service, stream normalized records into Parquet and
benchmark an embedded DuckDB scan against a persistent ClickHouse deployment
on identical logs, rules, CPUs, and network transfer. A local synthetic check
on one million already-normalized events and five equality rules took 1.84 s
in the current Python evaluator; writing Parquet took 0.53 s and querying
bounded evidence with DuckDB took 0.033 s. Both found the same 50 synthetic
matches. This excludes transfer, gzip/JSON parsing, normalization and real
rule complexity, so it is a direction for the batch prototype, not a
production speed or cost estimate. Keep the current in-process evaluator for
the 2,000-event interactive preview. DuckDB can push Parquet filters and
projections into scans, but no official general Sigma-to-DuckDB backend is
assumed. A supported Sigma compiler must reject unsupported rules and have
positive/negative conformance tests before replacing the preview evaluator.

DuckDB Parquet documentation: <https://duckdb.org/docs/data/parquet>
ClickHouse local documentation: <https://clickhouse.com/docs/operations/utilities/clickhouse-local>

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

## Detection quality

The current HackTricks Cloud corpus snapshot `fd9bf8863bf7a36de10b8695d366a53a9063c81c`
contains 1,710 AWS, GCP, Azure and Kubernetes pages. The page-reference
ledger generated by `scripts/attack_detection_coverage.py` links the current
23-rule pack to ten pages (AWS 4, GCP 3, Azure 2, Kubernetes 1). A linked
page can describe many distinct techniques, so these numbers are navigation
evidence, not measured detection recall. The remaining pages still need
technique-level review and, where log evidence exists, tested rules.

`scripts/attack_detection_technique_inventory.py` provides a reproducible
starting queue from the pinned local Markdown corpus. Its 8,330 candidate
sections on 1,650 pages are headings selected by path and title, not a count
of unique attacks or of detectable activity. Nested headings can multiply one
technique; prose-only techniques can be missed. Each candidate still needs a
review of the actual operation, available audit record, legitimate uses, and
positive and negative fixtures before it becomes a detection rule.

A separate AWS `PutEventSelectors` correlator can identify an observed change
from `All` to `ReadOnly` management selectors on the same trail when supplied
with a complete ordered window of selector writes. It is not an active rule in
the current pack. The general AWS preview reads bounded log slices and cannot
certify that all intervening writes were ingested. A dedicated Event History
reader exists for a bounded regional interval, but even exhausted pages cover
only currently visible records in the 90-day Event History window; recent
delivery can lag. No transition alert should claim attacker intent or loss of
logging across the account.

The pinned pack has twenty-three activity rules: twelve AWS, five GCP, two
Azure, and four Kubernetes. The AWS role attachment rule requires the exact
AdministratorAccess policy and evidence that the target is the issuing role.
The GCP Token Creator rule reports a binding in the resulting service-account
policy; a SetIAMPolicy log entry alone cannot prove the binding was newly
added. The uploaded-key rule retains only its key resource name. Successful
CloudTrail and GuardDuty disabling or deletion operations are reported as
requests, with no claim about present monitoring state. The GCP service-account
restore rule reports the returned identity, not retained permissions or usable
credentials. Kubernetes binding
updates are normalized as observed state, but do not emit a privilege-gain
detection without a before/after comparison.

The new AWS UpdateTrail rule requires one successful request and response
that both explicitly set validation, multi-Region coverage, and global-service
coverage to false. It cannot prove the prior settings. The GCP project Owner
self-grant rule requires an `ADD` policy delta and the returned direct binding;
an existing Owner editing unrelated policy does not match. Kubernetes rules
require a returned `cluster-admin` binding to the actor's user or a broad
system group. The Entra self-grant rule infers tenant scope from the exact
audit activity name; Microsoft has separate activity names for scoped grants.
Each still permits an approved administrative explanation and requires review.

The CloudTrail PutEventSelectors rule requires one basic selector with
management events enabled and `ReadWriteType=ReadOnly` in both the successful
request and response. This describes that trail's resulting selector, not its
previous configuration or the coverage of any other trail.

The rules require successful operations and concrete parameters. A denied API
call, incomplete policy document, foreign account event, or bare enumeration
cannot produce a privilege escalation finding. A legitimate administrator may
still perform a matching action. Each result therefore exposes its matched
evidence and names the investigation it supports. Future correlation should
join related events by account, principal, target and time, and should use
effective permission changes before labeling an escalation as confirmed.
