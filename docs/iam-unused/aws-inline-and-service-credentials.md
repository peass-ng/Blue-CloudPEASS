# AWS inline policies and service-specific credentials

## Group inline policies

`aws.iam.group_inline_policies_have_members` runs in Hardening and carries
HackTricks Cloud Best Practices membership. It identifies inline policies
embedded in groups with no current IAM user members. Evidence retains each
policy name and its complete captured policy document, including wildcard or
NotAction clauses. It does not compute effective permissions or invent an
inactivity duration.

The normal `GetAccountAuthorizationDetails` inventory supplies `GroupDetail`
with stable group identity and inline policies and `UserDetail` with each user's
`GroupList`. Current account, native operation, complete row provenance, scoped
projection and policy document shapes must match. A complete account-wide user
inventory is required before the absence of members can fail. A known valid
member remains positive evidence when unrelated user enumeration fails. Denied
membership reads produce Access denied; malformed or incomplete evidence remains
UNKNOWN. No inline policies means this control is not applicable.

The engine's existing scoped memo index shares current-group and user-membership
joins between evaluations; there is no new startup cache or source-admission
layer. The normal Hardening JSON path and registered regression cases cover the
new control. It uses existing read permissions and no additional AWS calls.

Inline policies on users and roles always belong to their parent identity; AWS
deletes an inline policy when the owning identity is deleted. They cannot be
standalone unattached objects. Their parent identity and service/action usage
must be reviewed through the corresponding activity and Access Analyzer evidence.
An inline policy on an empty group is a structural finding, not proof that a
particular action was never used. No formal framework is added solely from this
structural predicate; existing independently reviewed activity mappings remain.

## Service-specific credential inventory

`iam_service_specific_credential` now requests the complete paginated
`ListServiceSpecificCredentials(AllUsers=true)` inventory without a service-name
filter. The earlier Bedrock-only filter omitted credentials for other supported
services, including CodeCommit, Keyspaces and CloudWatch Logs. Bedrock-specific
checks still return NOT_APPLICABLE for other services.

Only credential ID, owner user name, service name, status, creation date and
optional expiration date are retained. This list operation does not retrieve or
validate a credential value. Pagination, read budgets and denied/partial status
are preserved. The same existing `iam:ListServiceSpecificCredentials` permission
is used; an account policy restricting that action to a service may still deny
the broader request, which must remain Access denied rather than an empty result.

The current `ServiceSpecificCredentialMetadata` API has **no last-used field**.
Neither credential creation age nor the owner's ordinary access-key last-used
date proves that a service-specific credential is unused. API metadata alone
cannot support an unused-day finding for an active CodeCommit/Keyspaces/API
credential. A separate credential-bound service activity source is needed before
that family can be claimed as fully inactivity-covered. Expiration and inactive
state remain credential state, not a fabricated last-use date.

Official API and policy-model source pages are retained, with individual hashes,
in `aws-inline-credential-sources.json.gz`.
