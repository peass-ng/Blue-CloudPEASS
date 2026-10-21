# GCP unused service accounts and keys

The native Hardening path uses three controls:

| Control | Evidence and interval |
| --- | --- |
| `gcp.claude.service_account.recently_used` | Bound Policy Analyzer service-account authentication; 180-day threshold |
| `gcp.claude.service_account_key.recently_used` | Bound Policy Analyzer key authentication and key creation time; 180-day threshold |
| `gcp.iam.service_account_no_active_unused_insight` | ACTIVE service-account usage insight matching both current email and immutable unique ID; at least 90 days |

The existing IAM account/key list reads provide the current identity and credential
metadata. Additional paginated GET requests use:

- `policyanalyzer.googleapis.com/v1/projects/PROJECT/locations/global/activityTypes/serviceAccountLastAuthentication/activities:query`
- The same endpoint with `serviceAccountKeyLastAuthentication` for keys.
- `recommender.googleapis.com/v1/projects/PROJECT/locations/global/insightTypes/google.iam.serviceAccount.Insight/insights`
- `cloudresourcemanager.googleapis.com/v3/projects/PROJECT` when a returned numeric
  project name needs binding to the selected project ID.

Permissions include `policyanalyzer.serviceAccountLastAuthenticationActivities.query`,
`policyanalyzer.serviceAccountKeyLastAuthenticationActivities.query`,
`recommender.iamServiceAccountInsights.list`, `resourcemanager.projects.get`, and the
existing `iam.serviceAccounts.list` / `iam.serviceAccountKeys.list` reads. No new
write permission or secret-value read is required. Connector roles must actually
grant these reads; missing authority produces Access denied or unavailable evidence.

Authentication observations must identify the resource, activity type, project and
source request. Stale-use failures require a complete observation interval longer
than 180 days, with its end within three days of capture. Recent positive use does
not require 180 days of history. Day-level timestamps retain their uncertainty at
the threshold. New keys use creation time to avoid a false stale-key finding.
Missing service-account authentication dates cannot alone establish its age; the
separate explicit unused-account insight supplies provider-classified evidence.

Insight failures require ACTIVE / SECURITY / SERVICE_ACCOUNT_USAGE, matching target
project, at least 90 days of observation and a refresh within three days of capture.
Matching recent authentication contradicts the unused classification and keeps it
unresolved. A complete list with no matching insight means no ACTIVE unused-account
insight was returned; it does not prove recent use. Accepted insights do not count
as ACTIVE. Disabled identities and Google-managed keys have explicit applicability.

Google does not track every authentication surface in these sources, including
Google Workspace domain-wide delegation. These checks report the recorded cloud
activity or explicit insight; they do not prove an identity can safely be removed.
The source snapshots and SHA256 provenance are retained in
`gcp-identity-sources.json.gz` from the official [authentication activity documentation](https://docs.cloud.google.com/policy-intelligence/docs/activity-analyzer-service-account-authentication)
and [service-account insight documentation](https://docs.cloud.google.com/policy-intelligence/docs/service-account-insights).

## Empty groups and unused role grants

`gcp.iam.static_group_has_members` runs against Cloud Identity groups and their
direct memberships. Each group retains its own complete-pagination marker, group
resource name, captured membership IDs and successful GET request references.
A completed empty list fails for a static Google directory group. A dynamic group
or external identity-mapped group remains unresolved. An observed member is a
structural consumer; it is not authentication history. Unrelated directory or
transitive-membership errors cannot erase a confirmed empty direct list.

Group discovery uses the existing explicitly authorized `cloud_identity_customers`
realms and IAM-referenced groups. Project authority alone does not enumerate every
Google Workspace group. Cloud Identity group/membership read permissions and the
appropriate OAuth scopes are required; the collector does not broaden a project
scan to an unselected directory. Membership requests remain paginated GET reads
of `cloudidentity.googleapis.com/v1/groups/GROUP/memberships` with `view=FULL`.

`gcp.iam.role_grant_has_observed_permission_use` consumes the existing paginated
`google.iam.policy.Insight` list for selected projects, folders and organizations.
It requires ACTIVE / SECURITY / PERMISSIONS_USAGE, a refresh within three days,
at least 90 days of observation, and exact current resource, role, principal and
condition-expression agreement with captured IAM policy. A grant with neither
exercised nor inferred permissions fails. Positive use means this particular
insight records use; it does not establish that every permission in a role is
needed. Inferred permissions prevent a zero-exercised-permissions failure because
the provider explicitly considers those permissions potentially necessary.

Numeric project names in insights require a verified Cloud Resource Manager
project ID/number binding. Changed grants, foreign targets, incomplete insights
and unavailable current policy remain unresolved. The exact source interval,
principal, role, condition, exercised and inferred permissions appear in evidence.
Reads use `recommender.iamPolicyInsights.list`, existing current-resource IAM reads
and, when necessary, `resourcemanager.projects.get`; no provider mutation or
credential-value read is added.

Both controls belong to HackTricks Cloud Best Practices. Empty-group evidence has
a partial PCI GCP 8.2.6.1 mapping; grant evidence has a partial NIS2 GCP 11.5.4
mapping. Neither claims to establish the whole organizational account-review
process. Official source snapshots are retained in
`gcp-authorization-sources.json.gz` with per-document SHA256 and source URLs.

## Directory recorded logins and federation pools

`gcp.iam.directory_user_recent_recorded_login` checks enabled, non-archived
Directory users whose project-to-organization-to-directory-customer binding is
independently established by the existing Cloud Resource Manager hierarchy reads.
Its additional `workspace_user_activity` inventory performs an individual
`GET admin.googleapis.com/admin/directory/v1/users/USER_ID` because Google's
users-list login field can be inaccurate. It requests only immutable user ID,
customer ID, email, suspended/archived state, creation time and last login time.
Existing Directory field projections and MFA checks are preserved; the individual
login reads run when this dedicated inventory is selected or required.

A real recorded login older than 90 days fails, provided it is within the current
user's lifetime. A recent login or an account younger than 90 days passes with
its actual reason. Suspended and archived users are not applicable. Missing dates,
a 1970 sentinel preceding creation, future dates, changed identities, foreign
customers or denied detail reads remain UNKNOWN or Access denied. Recorded login
is not comprehensive Google Cloud API/token usage, nor proof a password is unused.
The finding retains the actual date and elapsed days; it does not invent activity
for an account without a valid last-login date.

`gcp.iam.workload_identity_pool_has_enabled_provider` and
`gcp.iam.workforce_pool_has_enabled_provider` identify active federation pools
without an enabled ACTIVE provider after complete, unfiltered native IAM list
reads. Project aliases require an exact CRM identity read; workforce pool parents
must match the selected organization. Providers must belong to the exact pool.
Partial, denied or filtered enumeration cannot establish absence.

Disabled/deleted pools are not applicable. Workload pools in TRUST_DOMAIN mode
are also not applicable: Google managed workload identities use those pools, and
external federation providers cannot be created in them. The default and
FEDERATION_ONLY modes support the provider-availability check. This detects an
obsolete federation configuration candidate; it does not claim a pool with an
enabled provider has recently authenticated or that existing sessions expired.

These three native Hardening controls carry HackTricks membership and bounded
partial NIS2 GCP 11.5.4 identity-review mappings. The existing Directory readonly
permission/OAuth scope and IAM pool/provider list permissions are required. No
account, provider, IAM grant, API activation or credential is created or changed.
Official source documents, URLs, license attribution and SHA256 payload hashes are
retained in `gcp-directory-federation-sources.json.gz`.

## Recorded API-key and HMAC request activity

Two additional native Hardening controls query Cloud Monitoring by public metadata
identifier. API keys use the API key `uid` in `resource.labels.credential_id` with
the `apikey:` prefix. HMAC keys use `metric.labels.access_id` and the HMAC method
on the Cloud Storage authentication counter. Neither identifier is a key secret.

The dedicated `api_key_usage` and `storage_hmac_key_usage` inventories make
paginated GET requests to `monitoring.googleapis.com/v3/projects/PROJECT/timeSeries`.
Queries select the exact credential and metric, constrain the monitored project,
and aggregate daily sums while retaining credential, project and response-class
labels. The project selector prevents a larger Monitoring metrics scope from
silently including unselected projects. API key queries use the verified owning
project. HMAC queries cover every selected project because the bucket's project
owns the authentication metrics; the key's own project alone is insufficient.

The collector requests 365 days ending 30 minutes before capture to allow Service
Runtime reporting delay. Credential-level point limits, normal pagination, global
request budgets, cancellation and bounded parallel reads apply. Project IDs and
numbers are independently bound through CRM. Partial execution errors, denied
reads, foreign labels, changed request filters and invalid count intervals are
retained as unavailable observations. HTTP 2xx counts provide recorded successful
activity; failed or redirected requests are kept separate.

A recent successful interval passes. An old recorded successful interval with
complete selected views fails as a cleanup-review candidate, with its date range,
elapsed days, metric and project coverage in evidence. A daily interval crossing
the 90-day boundary stays unresolved. New credentials pass for their actual age;
inactive/deleted credentials have explicit applicability.

Empty series or failed requests alone remain UNKNOWN. Service Runtime does not
cover every Google API, and HMAC keys may access buckets in unselected projects.
These predicates report old recorded activity; they do not establish universal
key inactivity or safe removal. The evidence explicitly preserves this distinction.
The previous HMAC age/default-service-account control is separate from this usage
history and must not be described as an inactivity evaluator.

The controls carry HackTricks membership and a bounded partial NIS2 GCP 11.5.4
access-credential review mapping. Required reads include `monitoring.timeSeries.list`
in each metric project, `resourcemanager.projects.get`, and the existing API-key
or HMAC metadata-list permission. No key string, HMAC secret, signed request,
credential-validation attempt, monitoring configuration or provider mutation is
used. Source snapshots are retained in `gcp-key-usage-sources.json.gz`.

## Custom-role definitions with no captured grants

`gcp.iam.custom_role_has_declared_grants` checks current project and organization
custom roles in their owning scope. An observed grant to any principal, including
a conditional grant, is a structural consumer. This does not establish recent
permission use; the separate policy-insight check handles provider-observed usage.

A no-consumer finding requires a complete role definition, the direct owning-scope
IAM policy requested with policy version 3, and a complete unfiltered paginated
Cloud Asset `searchAllIamPolicies` result. A root policy alone is insufficient.
Filtered queries, asset-type filters, field projections, malformed policies,
denials and incomplete pages cannot establish absence. Cloud Asset's supported
resource coverage and eventual consistency remain the boundary of this inventory;
the finding does not assert universal provider-wide inactivity or safe deletion.

The finding includes the full current role permission list and any declared grant
resource, members and condition. Predefined roles, soft-deleted definitions and
roles referenced outside their owner are not cleanup candidates in that scope.
Unproven numeric project aliases remain unresolved. CRM-proven role aliases also
prevent the collector from fetching the same listed role again under a project-ID
alias and reporting a false duplicate. Genuine duplicate-role rejection remains.
The existing scan memo index shares the scoped policy join across role definitions.

This native Hardening control belongs to HackTricks Cloud Best Practices. No
additional formal mapping is asserted merely because a role definition is unused.
The original IAM and Cloud Asset read permissions suffice; no provider mutation
or additional IAM-analysis API is required. Official source payloads and hashes
are retained in `gcp-custom-role-sources.json.gz`.
