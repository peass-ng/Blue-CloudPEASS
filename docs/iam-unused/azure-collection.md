# Azure unused IAM collection

The native `azure_unused_iam_evidence` inventory reuses the current tenant's
application registrations, enterprise applications, groups and group memberships.
It requests these additional paginated read-only Microsoft Graph reports:

* `GET /beta/reports/servicePrincipalSignInActivities`
* `GET /beta/reports/appCredentialSignInActivities`

Both reports document `AuditLog.Read.All` as the least privileged delegated or
application permission. `Directory.Read.All` is a documented broader permission.
Delegated callers also need an appropriate directory role such as Reports Reader
or Security Reader. The connector's current Graph token is reused; the collector
does not create credentials, consent to permissions or modify tenant configuration.
These are preview Graph APIs; an unavailable or denied API remains visible as
unresolved evidence, rather than producing a clean or unused verdict.

For candidate empty static groups, the collector additionally performs a paginated
`GET /beta/groups/{id}/members?$select=id`. Microsoft documents that the v1.0 group
members endpoint may omit service principals. A v1.0 empty list alone therefore
cannot establish an empty group. Positive existing member evidence is reused.
Dynamic and hidden memberships are not inferred empty. Directory group read
permissions apply, and hidden membership has additional permission requirements.

The collector stores key IDs, credential origin, type, creation/expiry dates and
usage timestamps. It never requests, tests or stores a secret value. Each credential
is matched to its application or service-principal object and app ID. A recent
failed sign-in attempt is not successful use. Missing timestamps, no report row,
ambiguous identities and unsupported variants remain unresolved. New principals
and credentials cannot fail solely because they have no recent-use record.

All native inputs remain bound to the authenticated tenant, credential capture
and customer context. One denied activity report does not suppress an independently
confirmed empty group or another valid stale credential. The existing reader's
pagination, continuation-origin checks, cancellation, call limits and deadlines
also apply to these new reads.

The immutable Microsoft Graph source snapshots and hashes used for review are
retained in `azure-identity-sources.json.gz`. They cover the report schema, report
list endpoints and the v1.0 membership omission. Native source specifications live
in `../compliance-ledgers/native-extensions/unused-iam-azure-20261021.json`.

## Custom Entra role consumers

`azure.iam.custom_directory_role_has_declared_consumers` adds a Hardening finding
for a current custom Entra role with no declared assignment or PIM consumer. It
retains the complete captured `rolePermissions`, principal IDs and assignment
scopes. Microsoft built-in roles are excluded; disabled custom definitions can
still be structural cleanup candidates.

Selecting `azure_unused_role_evidence` requests the native directory role
inventory and three unfiltered, paginated Microsoft Graph v1.0 lists:

* `/roleManagement/directory/roleAssignments`
* `/roleManagement/directory/roleAssignmentSchedules`
* `/roleManagement/directory/roleEligibilitySchedules`

These are GET operations without request bodies or credential values. The shared
reader enforces pagination, read deadlines and request limits. The producer rejects
continuation links that introduce filters, projections, another path or host, and
retains only assignment IDs, role/principal references, scopes and PIM lifetime
metadata. A partial or denied list cannot establish that a role has no consumers.
An independently captured valid consumer remains positive when another list fails.

`RoleManagement.Read.Directory` is sufficient for these reads according to the
Microsoft Graph API permission tables; the schedule APIs also offer the narrower
`RoleAssignmentSchedule.Read.Directory` and
`RoleEligibilitySchedule.Read.Directory` permissions. Delegated access additionally
requires a supported Entra role. Lack of the necessary directory/PIM authority
produces Access denied or UNKNOWN; it does not certify an unassigned role. No write
permission is required by the collector.

The evaluator counts current assignments and unexpired or future PIM schedules.
Canceled, denied, failed, revoked and expired schedules do not count. Fixed ISO
8601 durations and explicit expiry dates are resolved against the capture time;
unknown calendar durations or conflicting metadata remain unresolved. A future
scheduled consumer is not mislabeled as an unused role. Joins use the engine's
existing scoped memo index, not another startup cache.

This check describes current declared consumers. It does not measure permission
use, establish business need or certify safe deletion. Pending assignment requests
must still be reviewed before removing a role. Azure Resource Manager custom
roles, their assignable scopes and their PIM assignments require a separate
consumer analysis and are not covered by this directory-role control.

The control carries HackTricks Cloud Best Practices membership. No additional
formal compliance mapping is inferred from an unassigned definition alone. Eight
official Microsoft source pages and their hashes are retained in
`azure-custom-role-sources.json.gz`.


## ARM custom-role consumers

`azure.iam.custom_arm_role_has_declared_consumers` reviews current custom
role definitions and retains their exact Actions, NotActions, DataActions and
NotDataActions. It reads unfiltered, paginated ARM role assignments and PIM
assignment/eligibility schedules at every declared assignable scope. Current,
future and unexpired consumers prevent an unused-definition finding.

Subscription reads bind each selected subscription to its owning tenant. A
management-group scope additionally requires a verified tenant and complete
descendant hierarchy; every descendant subscription must be selected. Roles with
DataActions are evaluated at descendant subscription scopes, because ARM does not
allow those roles to be assigned directly at management-group scope. Partial,
denied, foreign-tenant or unselected scope evidence cannot establish absence.
An independently verified consumer still establishes that the definition is used.

Collection uses GET operations only, with ARM API versions 2022-04-01 for role
assignments and 2020-10-01 for PIM schedules. The collector retains assignment,
principal, role, scope, condition and lifetime metadata, without credentials or
expanded principal names. One immutable source frame is shared across scope
evaluations. Microsoft built-in definitions are outside this cleanup control.

This is a Hardening check in HackTricks Cloud Best Practices. An unassigned
definition does not establish permission inactivity or safe deletion, so no other
compliance membership is inferred. Seven official Microsoft source pages and
their hashes are retained in `azure-arm-role-sources.json.gz`.
