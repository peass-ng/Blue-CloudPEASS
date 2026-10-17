# Native Lightsail IAM attachment metadata

The private `aws_lightsail_iam_native` component supplies the existing
`lightsail_iam_policy_attachment` contract. It evaluates attached **management
policy configuration**, not effective IAM authorization, bucket object access,
credential usage, or the absence of every alternative access path.

The signed SW42 predicate is unchanged. Its owner requirements are explicit,
flat `status=collected`, exact `ACCOUNT/REGION` scope, original timezone-aware
`observed_at`, exact positive integer `max_age_seconds`, and three arrays:
`iam_required_lightsail_bucket_arns`, `approved_lightsail_principals`, and
`approved_lightsail_actions`. The separately owned integration validates the
public `compliance_parameters.aws_lightsail_bucket_iam` namespace and binds that
policy to `requests.lightsail_iam_policy`. The fetcher returns `not_collected`
without any IAM call if that binding is absent, foreign, stale/future, unknown,
missing an approval clock, or contains extra keys. The original approval time is
compared with the scan Requests observation instant and is never refreshed.
It never reduces the principal inventory to the owner's approved principals.

## Metadata requests and joins

`bucket_metadata(requests, session, region, account)` performs only paginated
Lightsail `GetBuckets`. The output allows native bucket ARN, name, region and
read-only provenance. Native `Bucket/ID`, account, partition, region, location
and unique name/ARN must agree. It does not infer a bucket ARN from a name, retain
URLs/tags, or call `GetBucketAccessKeys`. The caller already establishes the
account with its normal STS verification; this component adds no STS request.

`collect(requests, session, region, account)` reads all four complete cached
`GetAccountAuthorizationDetails` projections: users, groups, roles, and managed
policies. The identical underlying requests share the normal Requests cache.
Inline policies retain their actual full documents. Managed-policy attachments
join the exact ARN and unique default version, checking native
`DefaultVersionId`, `VersionId` and boolean `IsDefaultVersion`. Group attachments
expand through actual user `GroupList` membership; a group ARN is not treated as
an authenticating principal. Trust policies, unattached managed policies and
permissions boundaries are never converted into grants. A boundary on an
inventoried identity is unsupported and makes this projection unavailable.

Output provenance preserves the original IAM global scope and the exact target
bucket account/region, policy identity/version and inherited group identity.
Regional scope is a binding to the target contract, not a claim that IAM itself
is a regional service. Output IDs are digests of nonsecret principal and policy
identifiers; no credential is requested or hashed.

## Conservative semantics

All full attached policy documents are retained for supported constructs;
wildcard statements and unrelated wildcard statements are not discarded to
manufacture a successful result. The frozen evaluator returns UNKNOWN where it
cannot bound them. Resource patterns containing `?` or IAM `${...}` variables
are rejected before any complete projection, including in Deny statements: the
frozen evaluator cannot resolve those patterns and must not skip an unapproved
dynamic attachment while accepting a separate literal approved policy. Literal
`*` is retained unchanged for the frozen evaluator to reject conservatively. `Condition`, `NotAction`, `NotResource`, resource-policy
principals, unsupported policy syntax, ambiguous/default-version joins,
duplicate identities/attachments, or incomplete pages return unavailable.
Deny statements are preserved; the result is attachment configuration only and
does not assert an effective allowed action despite other denies or SCPs.

A supported exact bucket management statement for an approved principal/action
can PASS. Complete absence of a suitable attachment, or an explicit wider or
unapproved attachment targeting the bucket, can FAIL. Missing owner policy,
denied/truncated/malformed evidence and unsupported constructs do not PASS.
Native denied status is preserved; when only the auxiliary IAM dependency is
denied the frozen signed engine reports UNKNOWN rather than inventing evidence.

Bounds are 20,000 aggregate source entities, 50,000 expanded attachments,
131,072 bytes per decoded policy document, and 8 MiB serialized output, plus the
normal Requests call/page/resource/deadline budgets. No partial projection is
returned as complete. Optional missing native attachment/membership arrays mean
empty; explicit null or wrong types remain unavailable. Missing top-level
projection lists are conservatively unavailable through the shared reader.

## Integration boundary

This component owns only the new helper, its new portable tests and this file.
The integrator separately registers `SPECS`, `FETCHERS`, `NATIVE_IDS` and the two
existing read tuples, expands the new kind's bucket dependency, and invokes the
safe bucket route **only** for the narrow selected inventory set containing the
new kind and optionally `lightsail_bucket`. Existing default/other checks keep
their existing bucket path. No default role, permissions, signed callback, pins,
shared runtime files, or cloud resources are modified by this component.

Both `lightsail:GetBuckets` and `iam:GetAccountAuthorizationDetails` are already
explicitly granted by the existing customer template. No new permission is
proposed. This does not prove any particular customer's assigned role works.

The original SW42 test's `lightsail:GetBucket` spelling is not a real AWS action.
New fixtures use an actual resource-scoped `lightsail:UpdateBucket` statement as
**observed policy metadata only**; no update is executed. `GetBuckets` is a real
read but does not support Bucket resource-level IAM restrictions. S3 object
permissions use separate `s3` actions and S3 ARNs and cannot be relabeled as
Lightsail Bucket ARNs. AWS's documented mixed wildcard management example stays
outside this strict signed subset; it must not be rewritten to PASS.

## Validation

Portable tests use real botocore Stubber response models, normal Requests
pagination/cache/budgets, the two new native fetchers and a sealed snapshot fed
to the unchanged signed engine. Inline, URL-encoded, default managed and inherited
group configurations, explicit failures, unsupported syntax, duplicate/foreign
joins, paging/denial, safe bucket metadata and bounded output are exercised.
These are inert offline fixtures, not live AWS observations or hosted-intake
integration proof. Initial failed attempts remain in the private stage receipts.

## Primary sources

- [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [GetBuckets](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetBuckets.html)
- [Lightsail action/resource authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_lightsail.html)
- [Lightsail bucket management policies](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-bucket-management-policies.html)
