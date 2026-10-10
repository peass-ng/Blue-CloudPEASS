# Native AWS snapshot collector

`peaso.collectors.aws.collect(connector, requirements=None)` returns a sealed schema
1.0 snapshot. It collects AWS configuration and declared permissions for offline
defensive review. The operation allowlist contains 87 read/configuration APIs,
including STS authentication; it contains no resource mutations, secret-value
reads, object downloads, log-event reads, Access Analyzer creation, network probes,
or exploit/path validation. No Steampipe, Powerpipe or Prowler runtime is used.

## Selection, credentials and account identity

```python
from peaso.collectors.aws import collect

snapshot = collect({
    "provider": "aws",
    "auth": {"profile": "audit-sso"},
    "scopes": ["123456789012"],
    "options": {
        "regions": ["us-east-1", "eu-west-1"],
        "max_calls": 200,
        "max_pages": 10,
        "max_resources": 10000,
        "service_concurrency": 4,
        "region_concurrency": 2,
        "scope_concurrency": 2,
    },
}, ["bucket", "iam_user", "iam_role", "iam_policy", "security_group"])
```

`requirements` contains resource types; `None` requests all 52 supported types.
`options.inventories` can further restrict selection. The intersection is read;
every omitted supported inventory has a `not_collected` envelope. Unsupported
requirements receive `not_collected` with `unsupported_inventory`. Caller identity
is always required and represented by the `aws_account` collection and
`metadata.caller_identities`.

Scopes accept account IDs or precise `account/region` pairs. Account-only scopes
use `options.regions`; precise pairs are retained without expanding them into an
account/region Cartesian product. Legacy bare region scopes are accepted and
resolved to the verified caller account. With no account selection, the verified
selected credential context is scanned; the default region is `us-east-1`.
Global inventories occur once per account under its first selected region.
Collection scopes and resource identity include the verified account and region;
native items retain their fields and gain `id`, `AccountId`, and `Region`.
The input connector is not modified.

Authentication supports boto3's SDK credential chain: environment/shared-file
credentials, configured profiles and credential processes, cached IAM Identity
Center/SSO sessions, configured profile assume-role chains, web identity, container
task credentials, and instance credentials. The selected credentials are resolved
and frozen before concurrent clients are created. An expired or unavailable
selected profile/provider fails that context; no default-profile recovery occurs.
Credentials remain in memory inside the collector and never enter snapshots.
The frozen context does not renew during a long scan; expiry produces explicit
denial evidence rather than switching contexts.

`auth.profile` selects one exact SDK profile. Explicit key authentication uses
`aws_access_key_id`, `aws_secret_access_key`, and optional `aws_session_token`;
partial keys and simultaneous explicit keys/profile are rejected. `auth.method`
accepts `default`, `auto`, `sdk`, `profile`, `sso`, `access_keys`, `web_identity`,
`container`, `instance`, or `task_role`. Profile/SSO and access-key methods require
their corresponding configuration. Explicit metadata/web-identity methods select
only that SDK provider and fail if it cannot produce credentials. SSO login/token
refresh configuration remains the responsibility of the selected SDK profile.
`task_role` accepts temporary credentials from the runtime environment (including
Lambda), container, instance or web-identity role provider; it requires a session
token and rejects shared/profile credentials, avoiding profile fallback when the
selected scanner runtime role is unavailable.

`auth.role_chain` accepts up to ten role ARN strings or objects with `role_arn`,
`external_id`, and `role_session_name`. `auth.role_arn` appends a final role.
Default `auth.external_id` and `auth.role_session_name` apply unless overridden
per hop; the default session name is `peaso-read-only`. The platform scanner's
task role can supply the initial SDK/container context before assuming a target
role. These are credential exchanges; they do not create or modify cloud resources.

`auth.assume_roles` selects up to 100 independent cross-account targets from that
initial or chained context. Every target is verified with `GetCallerIdentity`
against the account embedded in the role ARN. Explicit account scopes are an
allowlist; unspecified accounts are not scanned. A selected account without a
configured/accessible role gets explicit unavailable coverage. Within an account,
the first successfully verified selected role context supplies collection;
permissions from multiple roles are never silently unioned.

For an authorized organization-wide inventory, set
`options.organization_role_name` to an explicitly configured accessible role name
or path. The collector lists organization accounts, selects active accounts, and
attempts only that role, up to 100 independent targets. It does not guess roles or
grant access. Per-target failures are retained in
`metadata.authentication_errors`. Organization account listing alone does not
enable cross-account collection. `options.trusted_scope_ids` contains explicit
12-digit account IDs for offline trust interpretation; selection never implies
trust.

See [boto3 credential provider documentation](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html)
and [STS AssumeRole](https://docs.aws.amazon.com/boto3/latest/reference/services/sts/client/assume_role.html)
for the SDK's credential/session semantics.

## Bounds and evidence semantics

| Option | Default | Accepted range | Meaning |
| --- | ---: | --- | --- |
| `max_calls` | 200 | 1–10000 | Total scanner-managed configuration/STS requests, including retries |
| `max_pages` | 10 | 1–100 | Maximum pages per native list operation |
| `max_resources` | 10000 | 1–100000 | Total emitted resources, including caller identity; also bounds each list projection |
| `service_concurrency` | 4 | 1–16 | Global concurrent work/request ceiling |
| `region_concurrency` | 2 | 1–8 | Maximum selected regions per account in a work batch |
| `scope_concurrency` | 2 | 1–8 | Maximum account contexts in a work batch |
| `retry_attempts` | 3 | 1–5 | Total attempts per identical request |
| `connect_timeout` | 5 seconds | 1–30 | SDK connection timeout |
| `read_timeout` | 15 seconds | 1–120 | SDK per-read timeout |

One thread pool bounds all service/scope/region work; these settings do not
multiply the global request concurrency. SDK automatic retries are disabled so
every attempt consumes the scan budget. Throttle/service-unavailable errors use
bounded exponential backoff. Identical context/service/region/operation/argument
requests share a single cached future, including failures. This avoids repeated
IAM authorization requests across four native projections and duplicate detail
reads within a scan; no cache persists across scans. Clients are created under
a lock, while reads run concurrently. Emission order is deterministic.
Initial SDK credential-provider resolution (for example SSO, metadata or
profile-configured role exchanges) occurs before collection and is managed by
the SDK; those provider requests are not counted in the collector request budget.
This is explicit in `metadata.credential_resolution_calls`.

Pagination uses the installed SDK's native pagination metadata, preserving IAM
Marker/IsTruncated, EC2 NextToken, S3 continuation, ELB NextMarker, and lowercase
CloudWatch tokens. Repeated or missing required tokens are malformed evidence;
page/call/resource caps never produce a complete collection. List responses are
validated, and resources are deduplicated using type-specific native identifiers.
Multiple subnets or instances in one VPC remain separate resources.

| Collection status | Meaning |
| --- | --- |
| `collected` | List/configuration retrieval completed and contains evidence |
| `empty` | Successful retrieval established no resources/configuration |
| `partial` | Evidence exists, but a page, resource, call limit or later failure prevents completeness |
| `denied` | AWS authorization or credential validity denied collection |
| `timeout` | SDK connection/read timeout prevented collection |
| `not_collected` | Inventory was omitted, unsupported, lacked a configured account role, or hit a budget before evidence |
| `malformed` | Native response/list/pagination validation failed without usable evidence |
| `unknown` | Other retrieval failure without usable evidence |

Resource detail failures have `{collection_status, error:{code}}` beside the
resource's successfully collected fields. A parent `collected` list does not imply
complete security details. Documented missing S3 policies/public-access-block
controls or Lambda URL/policy configuration have `collection_status:"empty"` and
`absent:true`; absence and denial remain distinct. Empty/unavailable collection
envelopes contain no items. Exception bodies and request values are never logged
or serialized, only bounded AWS error codes. Access-key metadata retains a SHA-256
`AccessKeyFingerprint`, status, creation and last-used evidence, not the key ID.
Lambda environment/code, STS credentials/tokens, secret values, VPN pre-shared
keys/customer gateway configuration XML, and binary content are removed at
serialization boundaries.

## Actual service coverage

| Service | Native resource types | Collected configuration and practical limits |
| --- | --- | --- |
| STS | `aws_account` | Mandatory verified account, caller ARN and user ID; chosen/assumed context fails closed |
| IAM | `iam_user`, `iam_group`, `iam_role`, `iam_policy` | Shared paginated account authorization details; inline policies, managed policy versions, attachments, group membership, trust documents, permissions boundaries, native role last-used metadata; `PolicySources` records declarations/attribution |
| IAM account/usage | `iam_account_summary`, `iam_password_policy`, `iam_credential_report` | Existing summary/password policy and existing credential report only; user access-key last use, login profile and MFA devices; never generates a report or creates an analyzer |
| S3 | `bucket`, `s3_account_public_access_block` | Region/location, bucket and account Public Access Block, policy/status, default encryption, versioning, ACL, ownership controls, logging; no objects, object ACLs, access points, replication or lifecycle inventory |
| EC2/network | `vpc`, `subnet`, `route_table`, `security_group`, `network_acl`, `network_interface`, `instance`, `ebs_volume` | Native configuration, associations, routes, SG rules, NACL order/direction, addresses, instance metadata options, EBS encryption and attachments; no user data |
| EC2 connectivity | `internet_gateway`, `nat_gateway`, `vpc_endpoint`, `vpc_peering`, `transit_gateway`, `transit_gateway_attachment`, `transit_gateway_route_table`, `vpn_connection`, `vpn_gateway` | Native connectivity declarations and endpoint policies; no transit route searches/propagation tables, firewall appliance semantics or active reachability validation |
| ELB | `load_balancer`, `classic_load_balancer`, `target_group` | Classic/v2 configuration and attributes; v2 listeners and target health; listener rules, target-group attributes and WAF associations are not collected |
| KMS | `kms_key` | Metadata, rotation and default key policy; no key material/decryption |
| CloudTrail | `cloudtrail` | Home-region trails, logging status and event selectors; shadow trails excluded, so selected regions do not prove account-wide trail coverage; no logs/events |
| AWS Config | `config_recorder`, `config_delivery_channel` | Existing recorder/channel configuration and recorder status; no rules/evaluation inventory or recorder creation |
| GuardDuty | `guardduty_detector` | Existing detectors and detector configuration; no findings, member graph or detector creation |
| RDS | `rds_instance`, `rds_cluster`, `rds_snapshot` | Native instance/cluster backup, encryption, public-access and network settings; snapshot sharing attributes; no cluster snapshot/parameter/security-option-group inventory or database contents |
| EKS | `eks_cluster` | Described cluster endpoint/access configuration, network, encryption and logging; no in-cluster objects, node groups, access entries or cluster credentials |
| Lambda | `lambda_function` | Listed function metadata, VPC configuration, policy and function URL; environment values and code removed; no invocations or downloads |
| ECR | `ecr_repository` | Native encryption/tag/scanning configuration, repository policy and lifecycle policy; no images/content or registry-level enhanced-scanning settings |
| CloudWatch | `log_group`, `cloudwatch_alarm` | Log-group retention/encryption metadata and metric alarms; no log events, dashboards or composite alarms |
| Secrets Manager | `secret` | Secret metadata, native rotation/KMS configuration and resource policy; **never retrieves secret values** |
| SNS/SQS | `sns_topic`, `sqs_queue` | Topic/queue attributes, parsed resource policies, native encryption and transport declarations; no subscriptions/messages |
| API Gateway | `rest_api`, `http_api` | Listed endpoint/configuration metadata; no stages, authorizers, routes, integrations or full method authorization semantics |
| OpenSearch | `opensearch_domain` | Described domain security/network/access policy configuration; no index data |
| DynamoDB | `dynamodb_table` | Table metadata/encryption/stream configuration; no records, backups, PITR or resource policies |
| Organizations | `organization_account`, `scp_policy` | Accessible account list and directly attached account SCP documents; inherited root/OU policies explicitly `not_collected`, so complete effective SCP permissions are unknown |

The IAM implementation reuses the legacy scanner's defensive read patterns
(managed/inline policy source attribution and credential last-use reads), without
importing its entrypoint, global credential/policy caches, signal handlers, or
Access Analyzer write lifecycle. Native declared grants are not asserted as
effective access: SCP inheritance, session policy, resource policies, explicit
denies, permission boundaries and conditions require further interpretation.

Native relationship evidence is retained in items and
`metadata.network_relationships`: VPC/subnet membership, SG references, route
targets, associations and gateway attachments. Every derived relationship has
`reachability:"unknown"`. Public addresses and listeners are inventory facts;
complete SG/NACL/routing/return path/endpoint/application semantics are not proven.
Incomplete inventory cannot establish isolation or end-to-end exposure.

Role and credential last-use data are AWS observations within service-dependent
tracking windows. Missing last-use values do not prove credentials or policies
are unused. Existing credential-report generation time is retained with each row;
missing/expired/not-ready reports produce `not_collected` coverage. Policy/action
usage evidence is not collected, and Access Analyzer unused-access findings are
not collected. See [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_account_authorization_details.html),
[GetAccessKeyLastUsed](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_access_key_last_used.html)
and [GetCredentialReport](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_credential_report.html).

## Verification and exact live evidence

Unit verification: `.venv/bin/python -m pytest -q tests/test_peaso_collectors_aws.py`.
The suite currently has 47 passing tests and uses validating botocore Stubber
responses and checks pagination,
single-flight cache behavior, throttling/retry exhaustion, denial, malformed/native
responses, timeout, call/resource caps, native ID preservation, account scope,
credential-context pinning, assume-role chains/external IDs/session names,
redaction, existing-only credential reports and blocked sensitive/write APIs.

Minimal authorized live smoke performed **2026-10-10 at
17:10:03.459485+00:00**, using exact profile `naxusai-admin`, selected region
`us-east-1`, requirements `vpc` and `iam_account_summary`, and bounds
`max_calls=4`, `max_pages=1`, `max_resources=50`, `service_concurrency=1`.

| Evidence | Observed value |
| --- | --- |
| Verified account/scope | `947247140022/us-east-1` |
| Caller ARN | `arn:aws:iam::947247140022:user/testenv` |
| Native calls | `sts:GetCallerIdentity`, `iam:GetAccountSummary`, `ec2:DescribeVpcs` |
| Actual request count | 3 |
| `aws_account` | `collected`, 1 resource |
| `iam_account_summary` | `collected`, 1 resource |
| `vpc` | `collected`, 4 resources |
| Snapshot content digest | `sha256:1cef31998fb012754e3f87ad66192f413e10de1758e8ef0708d858e6e4cfbdcb` |

Only those three live APIs were exercised. The smoke establishes real SDK auth,
account identity, sealed snapshot construction and the selected reads; it does
not establish live coverage for the other services, regions, organization roles,
SSO/web identity/metadata providers, throttling or denial paths. Those paths have
stubbed evidence or documented limitations. No credential values or resource
contents were persisted, and no cloud resources were created or modified.

## Reviewed native AWS check extension

`peaso/checks/aws_extended.py` adds **36 pure native checks** with no additional
cloud calls. `peaso/rulepacks/reviewed_aws.json` records **35 exact reviewed source
associations** and one pending broader source. Sources are pinned to Prowler
`61d2cc55c4539a6b48a3cf9f3729d8f2af300882` and AWS compliance queries
`803dda1f7555ed5cea959aef30cfa0719b030d8c`; the shard preserves each evaluator
digest, rationale and official API references. The catalog lead merges all
declared root framework/control/version mappings from those exact sources;
these mappings are reference coverage, not compliance certification.
The completed merge conserves **1,027 pinned framework/control/version records**
for the 35 supported associations, verified against the registry mappings.

| Native check group | Reviewed behavior |
| --- | --- |
| IAM password policy, 7 checks | Require uppercase/lowercase/numbers/symbols; minimum length at least 14; reuse prevention exactly 24; password age 1–90 days |
| RDS, 9 checks | Automatic minor upgrades, VPC declaration, enhanced-monitoring ARN, CloudWatch log export existence; instance tag-copy excludes Aurora engines; cluster IAM authentication, Multi-AZ, tag-copy; instance snapshot encryption |
| Lambda, 3 checks | VPC declaration, dead-letter target, existing URL AWS_IAM authentication; absent URL is not applicable |
| CloudTrail/SNS/SQS, 3 checks | Declared CloudTrail/SNS KMS configuration; SQS KMS or SQS-managed encryption, preserving both source alternatives |
| ELBv2, 5 checks | Deletion protection, access logging, application-only invalid-header dropping, application-only desync mitigation, at least two distinct availability zones |
| ECR, 1 check | Lifecycle policy presence; explicit policy-not-found fails and unavailable detail is unknown |
| KMS, 1 check | Customer-managed keys are not PendingDeletion; pinned source default excludes disabled/unused keys |
| AWS Config, 1 check | Recording recorders use their account/partition's AWSServiceRoleForConfig; non-recording recorders are not applicable |
| EKS, 1 check | Version 1.28+ service encryption defaults, otherwise explicit secret-encryption resources; retains the reviewed query's full version logic |
| GuardDuty, 5 checks | Existing detector EKS audit logs, Lambda network logs, RDS login events, S3 data events and runtime-monitoring feature status; complete empty feature list fails while missing/denied lists are unknown |

ELB desync mitigation preserves `defensive`/`strictest` **or** invalid-header
dropping, rather than incorrectly failing the source's allowed alternative. EKS
default encryption is based on the collected version, not the wall clock. Missing
or malformed fields and denied detail envelopes remain `UNKNOWN`; an available
parent resource never overrides denied child evidence. Configuration declarations
do not establish network isolation, invocability or effective authorization.

The native `aws.rds.snapshot_encryption` check covers instance snapshots only.
Its related source `aws-compliance.control.rds_db_snapshot_encrypted_at_rest`
remains **pending** with `native_checks:[]` because the source combines instance
and cluster snapshots in a UNION. Cluster snapshots are not currently collected,
so the shard does not claim complete source support or inherit that source's
framework mappings. Per-instance RDS Multi-AZ/IAM checks with cluster joins and
CloudTrail's last-24-hour CloudWatch delivery predicate are also not substituted
with narrower field checks.

Verification:
`.venv/bin/python -m pytest -q tests/test_peaso_checks_aws_extended.py tests/test_peaso_collectors_aws.py tests/test_peaso_checks.py tests/test_peaso_checks_batch.py`
passed **1,418 tests**, including 124 extension tests and 47 collector tests.
Every extended
check has passing, failing, missing, malformed and denied fixtures, with
applicability, nested-denial, threshold, compound-alternative and input-immutability
cases. Reviewed IDs/revisions are checked against the pinned manifest. No upstream
runtime code was executed and no extra live API requests were needed for these
checks.
