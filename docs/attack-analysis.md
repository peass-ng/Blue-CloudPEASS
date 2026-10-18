# Audit log attack analysis

The Attack Analysis tab is an investigation workflow. It uses a saved connector,
checks access to a specific audit source, then evaluates a bounded slice of
events. A result means that a reviewed rule matched observed evidence. It is
not an attribution of malicious intent, and an empty result is not proof that
the environment was attack free.

## Rule and event format

The canonical detection rules are Sigma YAML in the public
`peass-ng/hacktricks-cspm-detections` repository. The server can load the reviewed
pack at pinned commit `73503b614c029d413d7b64790ab9d8336effc682` by
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
The separate Microsoft Entra source reads the connector tenant's directory
audits and currently evaluates one service-principal credential-add activity.
The current
request stops at 2,000 events, and AWS S3 stops at five objects and rejects
any object above the decompression bound. The response reports read coverage
and truncation. Analysis is synchronous and results are not stored as a
durable investigation job.

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
  connector token must belong to its configured tenant. Its reviewed rule
  reports successful additions of service-principal credentials; it does not
  infer credential use, privilege gain or malicious intent.
- Kubernetes: generic clusters may write audit events to a file or webhook;
  `kubectl get events` is not an audit-log source.

AWS: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html>
GCP: <https://docs.cloud.google.com/logging/docs/access-control>
Azure: <https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log>
Azure RBAC change history: <https://learn.microsoft.com/en-us/azure/role-based-access-control/change-history-report>
Kubernetes: <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>

## Detection quality

The pinned pack has eighteen activity rules: ten AWS, four GCP, two
Azure, and two Kubernetes. The AWS role attachment rule requires the exact
AdministratorAccess policy and evidence that the target is the issuing role.
The GCP Token Creator rule reports a binding in the resulting service-account
policy; a SetIAMPolicy log entry alone cannot prove the binding was newly
added. The uploaded-key rule retains only its key resource name. Successful
CloudTrail and GuardDuty disabling or deletion operations are reported as
requests, with no claim about present monitoring state. The GCP service-account
restore rule reports the returned identity, not retained permissions or usable
credentials. The Entra rule reports a service-principal credential addition,
not subsequent use or elevated rights. Kubernetes binding
updates are normalized as observed state, but do not emit a privilege-gain
detection without a before/after comparison.

The rules require successful operations and concrete parameters. A denied API
call, incomplete policy document, foreign account event, or bare enumeration
cannot produce a privilege escalation finding. A legitimate administrator may
still perform a matching action. Each result therefore exposes its matched
evidence and names the investigation it supports. Future correlation should
join related events by account, principal, target and time, and should use
effective permission changes before labeling an escalation as confirmed.
