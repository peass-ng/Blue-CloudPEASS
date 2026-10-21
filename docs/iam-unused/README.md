# Unused IAM coverage work

The target is native Hardening findings for unused identities, credentials and
permissions in AWS, GCP, Azure and Kubernetes. Every resulting control must carry
HackTricks Cloud Best Practices membership and any independently justified source
compliance mappings. A result in the Least Privilege table does not satisfy the
Hardening requirement. The implementation is **not complete**.

`coverage-review.json` is a reproducible inventory of 38 object families, generated
with:

```sh
python3 scripts/audit_unused_iam_coverage.py --output docs/iam-unused/coverage-review.json
```

Candidate matching identifies code to review. It does not prove detection,
collector completeness, native registration, API visibility or compliance
accuracy. An archived control does not count as an executed control. Rotation,
expiration and MFA checks do not substitute for inactivity checks.

## Work order

Finish unused IAM coverage across all four providers first. Then audit unused
network objects across all four providers, including unused security groups or
firewall policies, interfaces and addresses, routing/attachment objects, and
load-balancer/backend or service/endpoint objects supported by each connector.
The network work now includes 20 native controls across the four providers, plus corrections to existing reference checks. See the source dispositions under `docs/network-audit` and `docs/network-unused`; the changes still require composition with the current main release.

## Required evidence by provider

| Provider | Identity and credential evidence | Authorization objects and structural evidence |
| --- | --- | --- |
| AWS | Credential report, access-key last-use, role last-use and creation time; ACTIVE unused-access analyzer findings with each finding's detailed permission evidence and configured observation period | Complete group membership and policy attachment inventories, including policies attached only to empty groups; service/action last-access reports; separate Identity Center and service-specific credential evidence |
| GCP | Policy Analyzer service-account and key authentication observations with their actual observation periods; service-account insights; API/HMAC key activity when available; directory user activity requires directory authority | IAM Recommender policy insights and recommendations bound to the resource and principal; complete custom-role and binding inventories; directory groups require separately authorized membership evidence |
| Azure | Successful user sign-ins, service-principal sign-in activity and application credential usage by key ID; object creation dates, account state and tenant binding; application registration, enterprise application and managed identity are distinct identities | Complete role definitions and assignments, group memberships including supported transitive/dynamic membership, application links and federated credential assignments; permission usage requires activity evidence rather than resource existence |
| Kubernetes | ServiceAccount references from Pods and controller templates; metadata-only legacy-token last-used/invalid-since labels and tracking start where absence is interpreted; audit evidence for token or API use | Complete namespace/cluster Role, ClusterRole, RoleBinding and ClusterRoleBinding inventories; handle aggregation, indirect/external subjects and workload identity; no workload reference is a structural observation, not proof an identity never authenticates |

## Finding rules

* Report an object identifier, the exact relevant credential or permission, the
  observed last successful use and the actual measured inactivity period when
  available. Never display a fabricated number of unused days.
* A newly created object cannot fail an inactivity threshold solely because it
  has no usage record. Creation time and observation coverage must support the
  selected interval.
* A present but empty or null last-use field does not universally mean never
  used. Apply the provider's documented semantics and history limits.
* Denied, truncated, malformed, mismatched-scope or unavailable activity evidence
  is UNKNOWN or Access denied, not PASS. Positive bound stale-use evidence must
  survive unrelated inventory failures.
* Distinguish an empty group, unattached policy, unbound role or unreferenced
  ServiceAccount from a principal with confirmed observed inactivity. Preserve
  those exact structural reasons in findings.
* Use successful authentication where the provider exposes it. Failed sign-in
  attempts do not establish legitimate recent use.
* Disabled/deleted/invalidated credentials require explicit state treatment.
  Do not silently assume they remain usable or that every attached grant is safe
  to remove.
* Report through the normal Hardening API/table and CLI JSON. Findings must not
  depend on the optional AI workflow or appear only in Least Privilege.
* Keep evidence concise and natural, naming the affected object and dates.
  Do not imply that a dormant object has been exploited or can safely be deleted
  without reviewing its purpose.

## Implementation progress

`peaso/iam_usage_evidence.py` now provides tested inactivity-window handling and
a metadata-only Kubernetes legacy-token evaluator. The token evaluator requires
a matching ServiceAccount UID and a reciprocal Secret reference; a manually
created or unbound token with a last-used label is insufficient. Calendar-day
labels use the end of the day to avoid failing a token up to one day early.
Six Kubernetes controls now install through the native registrar and have
HackTricks membership, typed metadata, source reviews and packaged PASS/FAIL/
UNKNOWN fixtures. They cover ServiceAccount consumers, Role consumers,
ClusterRole bindings/aggregation, RoleBinding subjects, ClusterRoleBinding
subjects, and tracked legacy token activity. Seven existing AWS/GCP unused-IAM
checks now run in the Hardening category with their IDs and formal compliance
mappings preserved. The normal compiler and materializer accept this batch. Roles and ClusterRoles
carry partial PCI Kubernetes 8.2.6.1 mappings, and legacy token usage carries a
partial 8.2.6.2 mapping. These retain the reviewed requirement identifiers and
explicitly limit assurance to the captured declaration or tracked token subtype.

Five Azure controls now install through the same native registrar: static empty
groups, stale service-principal activity (including managed identity records when
available), application credential activity, service-principal credential activity,
and single-tenant application registrations without a local enterprise application.
They have HackTricks membership, typed descriptions, source reviews and packaged
PASS/FAIL/UNKNOWN cases. Static empty groups also carry partial PCI Azure
7.2.5.1.1 and 8.2.6.1 mappings; nonempty membership does not by itself establish
a human-user assignment. See [Azure collection](azure-collection.md) for exact read
APIs, permissions and the Graph v1.0 membership omission that requires beta
confirmation before declaring a group empty.

GCP service-account and user-managed-key activity now uses resource-bound native
Policy Analyzer observation windows and source freshness. Missing account dates
remain unresolved instead of falsely asserting inactivity; an old key without an
authentication date requires its known creation time and sufficient observation.
A separate native service-account check consumes ACTIVE usage insights with a
matching email and immutable unique ID, a fresh refresh time, and at least 90 days
of observation. It handles paginated results and verified numeric project aliases,
runs in Hardening, and carries HackTricks membership plus a partial NIS2 11.5.4
identity-review mapping. The 180-day authentication checks retain their existing
formal mappings. See [GCP collection](gcp-collection.md) for exact reads and limits.

Two additional GCP Hardening controls now cover static empty Cloud Identity groups
and current IAM role grants with no provider-observed permission use. Per-group
membership pagination and source proof preserve independent positives even when
other groups or transitive membership queries fail. Grant insights require a
fresh 90-day source interval and exact current resource, principal, role and
condition matching. Numeric project identities are verified through Cloud
Resource Manager. The controls have HackTricks membership and bounded partial
PCI group / NIS2 identity-review mappings. Both run through the normal collector
and Hardening JSON report path.

Three further GCP controls cover enabled Directory users with an old individual
recorded login and active workload/workforce federation pools without enabled
providers. Individual Directory reads avoid the documented inaccurate list-level
login field and bind the current user ID, lifetime and directory realm. Federation
checks require exact parent identity and complete unfiltered provider enumeration;
managed-workload TRUST_DOMAIN pools are explicitly excluded. The controls have
HackTricks and partial NIS2 identity-review mappings, and normal collector-to-JSON
tests include numeric project aliases, denied reads and misleading list timestamps.

API-key and HMAC-key recorded activity now uses separate native Cloud Monitoring
inventories and Hardening controls. Exact public credential IDs, project selection,
verified project aliases, query receipts, response classes, count intervals and
credential lifetimes are validated. The 365-day query window retains daily
precision and a 30-minute reporting lag. Recent success is positive evidence;
complete old recorded activity is a review candidate. Empty or failed-only series
remain UNKNOWN. HMAC queries cover selected bucket projects rather than assuming
all use is visible in the key owner's project. Provider-wide inactivity is not
inferred from metric absence. See [key usage review](gcp-key-usage-review.json).

GCP custom-role definitions now have a native Hardening consumer check using
complete direct owning-scope policy and unfiltered paginated Cloud Asset IAM
inventory. It retains each role's permission list and declared conditional or
unconditional grants; partial, filtered or denied reads cannot prove absence.
Verified project aliases also prevent a false duplicate-role collection error.
This is structural evidence within the captured supported-resource inventory.

The existing AWS 60-day role control now validates creation age and current-role
lifetime before assessing recorded use. Young roles without use no longer fail;
old roles with no date remain unresolved rather than asserting a complete inactive
interval. Its ID and formal mappings remain, with hash-bound updated current cases
and criteria. See [AWS role activity](aws-role-activity.md).

An additional AWS Hardening control now identifies group inline policies without
member identities. It retains the exact policy names and captured documents and
requires complete account-wide membership evidence before reporting absence.
The service-specific credential inventory also covers all supported services
instead of filtering only Bedrock; no last-use date is inferred from this metadata.
See [inline policies and service credentials](aws-inline-and-service-credentials.md).

A further Azure control now covers custom Entra role definitions without current
assignment or PIM consumers. It requests complete directory assignments and both
assignment/eligibility schedule lists, retains exact permissions and scopes, and
counts future or unexpired schedules. Current and scheduled grants are structural
consumers rather than activity history. Azure Resource Manager custom roles now have a separate native consumer check
covering every assignable scope, complete selected management-group descendants
and ARM assignments/PIM schedules. Incomplete or unselected scopes remain unresolved. See [Azure collection](azure-collection.md).

The current family-by-family review is in [implementation-review.json](implementation-review.json): 32 families have bounded native detections, and six retain explicit source limits rather than fabricated inactivity verdicts. The review validates current registration, Hardening routing and HackTricks membership; it does not certify a completed live scan. Structural consumers do not establish authentication use.

## Acceptance still required

For each of the 38 families, record one of: a tested native detection path, a
provider limitation with honest unavailable-evidence behavior, or an explicit
not-applicable reason grounded in that platform's identity model. Each implemented
path requires collector pagination/authority checks, registered evaluator tests
(recent, old, never observed, new object, denied/partial, malformed and foreign
scope), Hardening/API/CLI visibility and verified compliance mappings. No family
can be marked complete by catalog text alone.

## Provider references

* [AWS IAM unused-access findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings-unused-access.html)
* [GCP unused service-account insights](https://docs.cloud.google.com/policy-intelligence/docs/service-account-insights)
* [GCP IAM role recommendations](https://docs.cloud.google.com/policy-intelligence/docs/role-recommendations-overview)
* [Microsoft Graph service-principal sign-in activity](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipalsigninactivity)
* [Kubernetes legacy ServiceAccount token tracking and cleanup](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

## Final IAM source decisions

The IAM review now includes organization-wide IAM Identity Center permission-set
consumers, unreferenced SAML/OIDC providers, strict generated credential-report
windows, source-bound successful Entra user activity, custom Entra/ARM role
consumers, and independently bound Directory customers for multiple GCP projects.
The normal collector, native engine and CLI paths were exercised with native-shaped
read-only transports. Live authorization is still determined by the supplied
connector; denied or unavailable evidence cannot establish absence.

Some provider APIs cannot answer credential inactivity. AWS service-specific,
SSH/signing and federation configuration inventories lack a universal per-credential
successful-use timestamp. Azure federated credential listings expose configured
trust, and managed-identity resource attachments establish structural consumers.
GCP federation logs and Kubernetes external-user/group audit records can establish
observed successes, but absent events cannot establish a complete unused interval.
These are reviewed source limits, not reasons to fabricate an unused finding.
The optional positive-evidence helpers are separate from registered unused controls.

The local network batch now registers 20 source-supported controls across all four providers with Hardening and HackTricks membership. Native collector/evaluator, description, service-grouping and API presentation gates passed. Integration with the independently maintained provider/main checkout and final publication remain unfinished.

## Credential-report and analyzer review corrections

Six existing report-based inactivity IDs now share fresh report/identity/lifetime validation. Console-only checks assess passwords, and key-only checks assess keys; neither family borrows a passing or failing observation from the other. A newly created credential without recorded use cannot fail a 45-day inactivity interval. Exact enabled credential slots and recorded dates are retained.

The existing Access Analyzer findings control is included in HackTricks `unused_assets`; ACTIVE unused permissions remain Hardening evidence with exact provider permission detail and configured observation days, even when an unrelated analyzer read is partial. This is independent of the Least Privilege table.
