# GCP Directory and federated / external identity completion helpers

The Directory user collector is integrated into the native GCP collection path.
The federation and Kubernetes external-subject helpers remain optional evidence
parsers, not registered unused-object controls. No absent audit event or object
creation date is interpreted as inactivity.

## GCP Directory multi-project binding

`peaso/collectors/gcp_unused_iam_directory_completion_20261021.py` provides
`bind_project(collector, scope)` and `collect_users(collector)`. Each selected
project gets its own CRM v3 project, folder and organization GET chain. The
organization's top-level `directoryCustomerId` binds that project to one
Workspace customer. The collector lists that customer within the matching
project scope, rejects foreign customer IDs and duplicates, and attaches the
verified chain to each user.

`GCPCollector` calls `collect_users(self)` when `workspace_user` is required.
`workspace_directory()` now collects only roles and role assignments, so it does
not duplicate user collection or put every user's evidence in the first project.
The existing `unused_iam_gcp_directory.evaluate_user` evaluator validates each
item's project/customer chain and CRM read receipts. Native two-project tests
verify separate customers and that a denied second project cannot invalidate
positive evidence for the first. This does not extend project-specific authority
to unrelated Directory role assignments.

## GCP federation audit usage

`peaso/collectors/gcp_unused_iam_federation_completion_20261021.py` performs
read-only, paginated Cloud Logging `entries:list` POST requests for a selected
project or organization, exact provider and explicit time interval. It retains
request IDs, partial errors and the interval. The matching evaluator in
`peaso/unused_iam_gcp_federation_completion_20261021.py` recognizes an STS
ExchangeToken audit event with the exact provider name, a Data Access log in
that source scope, success status and a timestamp before capture. A matching
success is PASS for **observed token exchange**, including if a later page
failed. No match is UNKNOWN, never FAIL.

Root can wire an optional inventory after selecting the intended Logging
resource scope and validating every POST receipt/body against the recorded
query. A project may log under a project ID while the IAM provider uses a
project number; prove that alias through the existing CRM binding before
associating them. Workforce organization and workload project log sources
must remain separate. The current helper recognizes the exact source log name;
it deliberately leaves logs routed to other authorized views unresolved.
Data Access logging is disabled by default and retention varies. Cloud Logging
pagination completeness therefore does not establish a provider's inactivity.
STS reads require Cloud Logging permissions, potentially including private
Data Access visibility. The native structural pool checks should remain
independent of this optional observation.

## Kubernetes external subjects

`peaso/unused_iam_k8s_external_completion_20261021.py` recognizes an exact
User name or Group in a successful `audit.k8s.io/v1` ResponseComplete event
from a matching cluster. It ignores impersonated requests and unsuccessful
responses. This establishes observed API activity for the named identity; it
does **not** identify which RoleBinding or ClusterRoleBinding authorized it.
No matching event remains UNKNOWN even with a complete local file, because
audit policy, collection and retention can omit requests. Kubernetes exposes
no standard API to list historic audit events from the cluster; root should
only wire this evaluator where a separately configured, read-only, cluster-bound
audit export is available. Do not turn a subject activity result into an RBAC
grant-usage result without bound authorization decision evidence.

## Source review

- [CRM Organization resource](https://docs.cloud.google.com/resource-manager/reference/rest/v3/organizations): `directoryCustomerId` is the immutable organization owner field.
- [Directory users.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list): customer-filtered pagination and read-only authorization scope.
- [Workload federation audit examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity): STS event provider name and success status; Data Access logging setup.
- [Workforce federation audit guidance](https://docs.cloud.google.com/iam/docs/best-practices-workforce-identity-federation): sign-in/exchange methods and default-disabled Data Access logs.
- [Cloud Logging entries.list](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list): POST filter, resourceNames and nextPageToken behavior, including empty intermediate pages.
- [Kubernetes audit Event v1](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/): authenticated user, groups, stage, response status and timestamps.
- [Kubernetes RBAC subjects](https://kubernetes.io/docs/reference/kubernetes-api/definitions/subject-v1-rbac/): User and Group are external subject references rather than Kubernetes identity objects.

Focused verification: `tests/test_unused_iam_provider_completion_20261021.py`
and existing GCP Directory/Kubernetes unused-IAM tests, 96 passed with the
specified Python 3.12 environment. No live reads, mutations or broad suite ran.
