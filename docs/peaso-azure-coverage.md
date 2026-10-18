# Azure native source coverage

## Latest local checkpoint — 2026-10-11

The exclusive Codex partition is fully reviewed locally: **1,306 source
references**, with no duplicate or transferred Claude IDs and no pending local
review records. The 496-row Claude partition and the original 60 accepted Azure
references remain separate. Local review is **not central admission or full live
service coverage**: CHECKS imports, active shard admission, source-history
re-adjudication and fact-index activation remain coordinator/lead work.

Local dispositions are **364 ported, 208 exact merged,
734 rejected automation definitions**. Rejections comprise 412
constant-INFO manual attestation definitions, 258 invalid predicates with source
counterexamples, 63 substantively obsolete definitions and one secret-key retrieval
definition unsuitable for this collection policy. Manual questions and guidance
are retained. All **1,863 original framework references** remain addressable
through their original source IDs and pinned revisions.

There are **200 distinct referenced native predicate IDs**, including
**6 IDs / 13 references without claimed native runtime
coverage**: V1 authentication flags, nonsecret captured Function setting evidence,
complete-window APIM usage evidence, and the unproven legacy AttackPath
setting/contact context. These have genuine pass/fail/unknown predicates and
fixtures; no always-UNKNOWN stub is counted as supported. Missing constraints,
ambiguous joins, denial and partial inventories stay UNKNOWN.

The explicit native-only Azure gate passed **1,018 tests in 9.69 seconds** across
36 selected files. It excludes the file that invokes the supervisor-owned primary
evaluator and does not claim a full repository or supplied-feature pipeline pass.
A fresh current-Azure-CLI read-only scan finished in 3.52 seconds with verified
tenant binding and complete empty inventories for App Service, plans, Automation
variables, AKS and Search; this is no proof of nonempty child-service live coverage.
The live fixture-write ledger is `[]`.

Full pinned SQL counterexamples require corrective review of 72 previously mapped
alert references (global LIMIT 1 before subscription joins) and 28 directory/tenant
references (foreign-tenant policy attribution). Four consent references additionally
need the previously reported evaluator-version/source-history correction. Their
scope-correct native baselines remain independent; wrong sources are not silently
renamed as exact merges. Canonical complete query/control hashes were verified
against pinned upstream identities, with separate extracted-SQL proof hashes.

Collector additions cover the documented Azure facts using authoritative ARM
reconciliation, bounded concurrency/retries, coalesced successful reads and
complete pagination by default. Optional explicit caps mark partial coverage.
App config uses a safe field projection and known nullable metadata; VNet
connection certificate blobs, Automation values, logging SAS fields and credential
material are dropped. Read-only modern V2 authentication metadata does not stand
in for legacy V1 flags. No secret getter, workload probe, API enablement, grant or
cloud configuration modification is made.

The `embedded_refs_v1` conversion remains staged and unused. Concrete children and
parent views are retained until the owner proves the atomic scoped-index/resolver
transition, including exact alias deduplication and authorized same-tenant joins.
Orca reports the desktop process running but its runtime unreachable; attempted
heartbeats/checks/escalations have no delivery receipt. The durable handoff is
[task_66d382b1a714](handoff/task_66d382b1a714.md).

Per-service buckets below follow inspected source files; references can share a
native ID across buckets, so unique counts must not be summed as a global total.
The manual bucket contains governance/framework questions without native predicates.

| Source service bucket | References | Unique referenced native IDs | Ported | Exact merged | Rejected | Framework references |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| activedirectory | 195 | 2 | 4 | 0 | 191 | 179 |
| aisearch | 1 | 1 | 0 | 1 | 0 | 23 |
| aks | 4 | 3 | 3 | 0 | 1 | 50 |
| apim | 1 | 1 | 1 | 0 | 0 | 1 |
| apimanagement | 2 | 2 | 2 | 0 | 0 | 3 |
| app | 12 | 10 | 10 | 0 | 2 | 260 |
| app_client_certificates_on | 1 | 0 | 0 | 0 | 1 | 49 |
| app_ensure_auth_is_set_up | 1 | 1 | 1 | 0 | 0 | 16 |
| app_function_access_keys_configured | 1 | 0 | 0 | 0 | 1 | 14 |
| app_register_with_identity | 1 | 0 | 0 | 0 | 1 | 11 |
| appconfiguration | 3 | 3 | 3 | 0 | 0 | 6 |
| appinsights | 1 | 1 | 0 | 1 | 0 | 32 |
| appservice | 96 | 41 | 66 | 21 | 9 | 133 |
| automation | 1 | 1 | 1 | 0 | 0 | 5 |
| batch | 3 | 2 | 2 | 0 | 1 | 8 |
| cognitivesearch | 4 | 4 | 4 | 0 | 0 | 11 |
| cognitiveservice | 5 | 5 | 5 | 0 | 0 | 14 |
| compute | 28 | 10 | 24 | 2 | 2 | 38 |
| cosmosdb | 8 | 2 | 0 | 8 | 0 | 8 |
| databricks | 11 | 7 | 6 | 5 | 0 | 11 |
| datafactory | 4 | 4 | 4 | 0 | 0 | 7 |
| iam | 42 | 2 | 10 | 0 | 32 | 42 |
| keyvault | 71 | 15 | 53 | 18 | 0 | 80 |
| manual | 257 | 0 | 0 | 0 | 257 | 274 |
| monitor | 108 | 9 | 29 | 0 | 79 | 110 |
| mysql | 19 | 4 | 4 | 0 | 15 | 19 |
| network | 74 | 8 | 20 | 2 | 52 | 76 |
| postgres | 44 | 5 | 5 | 0 | 39 | 44 |
| public_access | 2 | 2 | 0 | 2 | 0 | 2 |
| redis | 5 | 5 | 5 | 0 | 0 | 12 |
| securitycenter | 150 | 19 | 32 | 84 | 34 | 176 |
| sql | 58 | 8 | 22 | 19 | 17 | 57 |
| storage | 93 | 26 | 48 | 45 | 0 | 92 |

Older sections below are historical checkpoints, superseded by the local figures and limitations above.

This track reviews the exact Azure partition in
`peaso/rulepacks/port_partitions.json`. Its initial checkpoint contains 1,862
source references: 60 previously supported and 1,802 pending. The corpus includes
489 named Turbot queries and 191 Prowler entries. A query identity groups review
candidates; actual conditions, arguments, resource scope, eligibility and joins
must agree before references share a native implementation. Hash equality alone
does not establish equivalence.

## Checkpoint 1

| Service | New unique automated predicates | Newly reviewed automated references |
| --- | ---: | ---: |
| Redis | 5 | 5 |
| Cognitive Services | 5 | 5 |
| App Configuration | 3 | 3 |
| Data Factory | 4 | 4 |
| API Management | 1 | 1 |
| Search | 4 | 4 |
| **Batch total** | **22** | **22** |

Separately, 412 individually inspected references delegate without arguments or
SQL overrides to queries that return constant INFO and have no automated security
condition: 243 `manual_control`, 155 `ad_manual_control`, and 14
`manual_control_hipaa`. They are rejected **as automated check definitions** and
preserved as manual-attestation requirements with their exact question/title,
guidance, control and query source locations, source revision, and framework
identifiers. They are not counted as automated predicates or discarded as invalid
compliance requirements. Selection must show MANUAL, never PASS/FAIL from an INFO
wrapper. The source lead owns extraction of the separate manual catalog and its
runtime integration.

The 434 newly reviewed references at this checkpoint leave 1,368 of the initial
assigned references for further substantive review. This is a progress checkpoint,
not a claim of exhaustive coverage. Unsupported automatic predicates remain
pending until implemented and verified; missing facts alone do not justify
rejection.

## Checkpoint 2

The Defender batch adds 19 distinct automated predicates and reviews 111 assigned
references: 97 SQL controls with inspected selectors/subscription joins and 14
Prowler definitions with individually inspected conditional scope. Pricing rules
cover 12 named plans; the four-database aggregate preserves its required-plan
condition. SQL integration selectors and Prowler's explicit missing-setting failure
are separate predicates. Contact role notifications and alert severity remain
individual-contact conditions rather than being merged with subscription-wide
aggregates. The batch passes 136 focused tests, including pinned source CASE
differentials, foreign-subscription rejection and denied/partial dependency gates.

At this checkpoint the new automated total is **41 predicates / 133 references**,
with **412 separate manual requirements**. Of the original 1,802 assigned pending
references, **1,257 remain for substantive review**. The source lead controls
accepted-shard integration; staged code never changes the approved runtime catalog
until its implementation, provenance and fixtures are ready.

## Predicate and fact boundaries

The first service batch preserves source distinctions that broad titles can hide:

- Redis subnet declaration and approved private endpoint are different predicates.
- Cognitive Services network and CMK rules preserve their capability gates;
  capability metadata absent or malformed is UNKNOWN.
- A Cognitive private-link inventory with zero connections retains the source's
  INFO/MANUAL outcome, which does not establish a successful configuration.
- App Configuration's Free SKU is excluded by the pinned private-link query.
- Search identity uses the source's exact `SystemAssigned` condition; a combined
  system/user identity is not silently treated as equivalent.
- API Management External virtual-network mode can satisfy the source's declared
  attachment condition without proving an internal-only gateway.
- CMK metadata does not imply that ordinary platform encryption is disabled.

All evaluators are pure snapshot predicates. Missing, denied, partial and malformed
facts are UNKNOWN; scope predicates additionally inspect dependency coverage before
interpreting known absence. A complete empty product inventory does not claim that
a required subscription/account setting is enabled. Snapshot capture time, rather
than live wall clock, is the reference for time-dependent review.

Collection adds native metadata for `redis_cache`, `cognitive_account`,
`app_configuration`, `data_factory`, `api_management` and `search_service`.
Resource Graph is discovery evidence; authoritative ARM lists establish inventory
membership and bounded detail reads. Collection never lists keys, exports
credentials, reads App Configuration data values, Redis contents, Data Factory
linked-service secrets or factory parameter values. Potentially sensitive service
settings are excluded from snapshots. Tenant/subscription IDs and origin pinning
remain explicit; portable supplied credentials do not fall back to ambient identity.

## Verification and provenance

`tests/test_peaso_checks_azure_ports_services.py` compares the reviewed pinned SQL
CASE expressions against independently stated source-table truth fixtures and
the corresponding native snapshots. Only isolated CASE expressions run against
one in-memory row during tests; no upstream runtime, cloud query or provider write
is invoked. Tests cover pass/fail, malformed/missing/denied/partial facts, capability
and eligibility branches, input immutability, and bounded read-only collector
metadata with secret-field exclusion. The initial batch passes 55 tests.

Readable `reviewed_azure_ports_services.json` records literal source IDs, source
conditions, per-control delegation proof and official provider documentation.
`reviewed_azure_ports_manual.json` retains each manual question individually.
The source lead merges reviewed shards and retains every framework/control/checklist
ID and version; references are not certification or complete framework coverage.

## Full collection and defensive identity facts

Directive 6 supersedes the earlier default budgets: Azure call, page, retained
resource and scope limits are now omitted by default. Explicit caller/hosted limits
remain available and are recorded with intentional-partial coverage. Concurrency,
service page size and retries remain bounded; repeated tokens and untrusted next
links are rejected. Both the core cancellation event/absolute deadline and explicit
runtime cancellation/deadline hooks are honored. Fake tests read beyond 205 calls,
10,005 records, 12 pages and 120 subscriptions without artificial truncation.

Directive 7 adds defensive Entra/identity metadata: actual resource-service-principal
app-role values, application/service-principal/group owners, PIM eligibility
schedules/instances, authorization and security-default policies, administrative
units and members, role-assignable/dynamic group properties, application audience,
domain authentication mode, managed identities and federated credential
issuer/subject/audiences. Resource Graph also preserves native identity fields.
App-role enrichment is cached by the actual resource service principal; denied,
missing or ambiguous role metadata remains explicit UNKNOWN/DENIED field coverage.
Ownership and grants are declared relationships, with effective access uncomputed.
Supplied privilege-chain code, chain evaluation and query routes are outside this
defensive track and are not imported or edited.

Credential-shaped tag/label names remain visible, while their values become
`[REDACTED]` with per-key redaction status. Ordinary resource names and configuration
flags such as `HttpTokens` are retained. Fake marker tests and read-only metadata
enrichment tests passed alongside the earlier collectors: 146 focused tests at the
latest checkpoint. The six new ARM service APIs were also read successfully using
the selected Azure CLI tenant in seven bounded calls; all six product inventories
were empty in that subscription. This does not imply any subscription security
configuration is enabled.

Provider schemas reviewed for this batch:
[Redis 2024-11-01](https://learn.microsoft.com/en-us/azure/templates/microsoft.cache/2024-11-01/redis),
[Cognitive Services 2024-10-01](https://learn.microsoft.com/en-us/azure/templates/microsoft.cognitiveservices/2024-10-01/accounts),
[App Configuration 2024-06-01](https://learn.microsoft.com/en-us/azure/templates/microsoft.appconfiguration/2024-06-01/configurationstores),
[Data Factory 2018-06-01](https://learn.microsoft.com/en-us/azure/templates/microsoft.datafactory/2018-06-01/factories),
[API Management 2024-05-01](https://learn.microsoft.com/en-us/azure/templates/microsoft.apimanagement/2024-05-01/service),
[Search 2023-11-01](https://learn.microsoft.com/en-us/azure/templates/microsoft.search/2023-11-01/searchservices).

The monitor checkpoint adds ten subscription alert declaration predicates tied to
72 exclusively owned source references. All31 isolated fixtures pass, including
complete-empty failure, cross-subscription/denial/partial uncertainty and exact
source leaf conditions. Activity alert collection uses the read-only
[2020-10-01 subscription list API](https://learn.microsoft.com/en-us/rest/api/monitor/activity-log-alerts/list-by-subscription-id?view=rest-monitor-2020-10-01);
webhook properties are removed. This does not test notification delivery.
Following the Claude source transfer and subsequent ready batches,525 owned
references remain unresolved; the exhaustive Azure port is still in progress.

## Current owned-source checkpoint (after Claude transfer)

The original1,802 assigned rows now split into496 Claude-owned rows and1,306
exclusively owned here. Ready review shards cover925 exact source references;
381 remain unfinished. Counts below are reviewed-source references, distinct
inspected query identities, and distinct native IDs referenced per service. They
do not imply that staged collector facts or pending sources are supported.

| Service | Automated refs | Manual refs | Substantive rejections | Pending refs | Inspected queries | Native IDs referenced |
|---|---:|---:|---:|---:|---:|---:|
| Azure/ActiveDirectory | 10 | 175 | 7 | 24 | 5 | 2 |
| Azure/ActiveDirectoryM | 0 | 2 | 0 | 0 | 1 | 0 |
| Azure/AppService | 18 | 19 | 0 | 31 | 4 | 3 |
| Azure/Compute | 0 | 23 | 0 | 26 | 1 | 0 |
| Azure/Databricks | 1 | 4 | 0 | 3 | 2 | 1 |
| Azure/KeyVault | 66 | 3 | 0 | 8 | 15 | 14 |
| Azure/Monitor | 74 | 23 | 0 | 40 | 12 | 11 |
| Azure/MySQL | 0 | 0 | 15 | 4 | 4 | 0 |
| Azure/Network | 0 | 6 | 0 | 59 | 1 | 0 |
| Azure/PostgreSQL | 0 | 3 | 39 | 5 | 9 | 0 |
| Azure/ResourceManager | 0 | 2 | 0 | 0 | 1 | 0 |
| Azure/SQL | 26 | 3 | 0 | 37 | 6 | 5 |
| Azure/SecurityCenter | 99 | 38 | 34 | 2 | 25 | 18 |
| Azure/Storage | 63 | 19 | 0 | 29 | 19 | 17 |
| aisearch | 0 | 0 | 0 | 1 | 0 | 0 |
| aks | 0 | 0 | 0 | 4 | 0 | 0 |
| apim | 0 | 0 | 0 | 1 | 0 | 0 |
| app | 0 | 0 | 0 | 16 | 0 | 0 |
| appinsights | 0 | 0 | 0 | 1 | 0 | 0 |
| unknown | 59 | 92 | 2 | 90 | 58 | 54 |

New ready batches since the monitor checkpoint include storage42refs/15queries
(11new predicates,4existing scalar reuses), legacyplans17refs/4queries
(3new predicates,1reuse), faultycontactscope24refs/3queries (demonstrated global
LIMIT1 bug), and vault61refs/13queries (10new predicates,3precise reuses).

The collector dependency expansion requested by the supervisor is staged. It
reads all documented service lists and parent metadata, with paginated concurrent
requests and field coverage; denied child reads omit the field, and partial reads
retain partial coverage. Diagnostics are embedded and request-coalesced. Current
concrete child/alias payloads remain during an explicitly authorized transition
to embedded_refs_v1, pending the source lead’s resolver and atomic fixture gate.
No final readiness claim applies to that transition yet.

[Graph users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0)
requires additional permission/license for signInActivity; denial retains base
users with denied field coverage. [Blob service properties](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-service-properties)
uses pinned OAuth and GET metadata; keys/SAS are never fetched. Vault key/certificate
listing and rotation/certificate policies read metadata at validated vault origins.
App credential arrays retain only keyId/endDateTime; ACI environment contents are
redacted while presence remains available. Tenant sharing requires verified token
tenant plus an authoritative subscription tenant binding.

A subsequent audit corrects four directory-source references: current Graph uses
`managePermissionGrantsForSelf`, while those pinned queries compare an uppercase
initial letter case-sensitively. The disallowed-consent query can falsely pass an
enabled current policy; the low-risk query can falsely alarm a hardened policy.
Those four definitions are now substantively rejected with SQL counterexamples.
The two corrected native baselines remain independent of these source mappings,
and also reject an additional broad self-consent policy. Directory fixtures15pass;
925 owned references remain reviewed,381 pending, with four fewer automated
references and four additional substantive rejections than the prior table.
The current [Graph role-permission schema](https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0)
and [consent configuration examples](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
support this casing correction.

Five additional pinned NSG queries join risky rules to groups by name alone.
Azure permits the same NSG name in different resource groups, so a safe group
can inherit another group’s alarm. Thirty exact owned references are rejected
for this demonstrated scope defect; eight isolated counterexample tests pass.
The original port/range/protocol conditions were individually inspected and are
not merged with the distinct priority-aware native checks.
[Azure naming scopes](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules)
and [the current NSG resource API](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/get?view=rest-virtualnetwork-2025-05-01)
confirm the scope and full-ID distinction. This brings local reviewed references
to955, with351 still unreviewed; central admission awaits restored coordination.

The next valid network batch ports three distinct predicates across15 exact owned
references: subscription Bastion presence, NSG-targeted enabled flow-log retention
of at least90 days, and VNet-targeted enabled retention of at least90 days or zero
for unlimited. Ten native/source truth fixtures pass. Zero deliberately differs
between the two source baselines, so they are not broadly merged. Existing NSG
metadata remains applicable before actual retirement; the check performs no new
flow-log creation and makes no delivery or storage-lifecycle enforcement claim.
Local reviewed references970;336 remain unreviewed.

The SQL batch adds four server-target predicates plus one precise public-network
scalar reuse across23 owned references. Seventeen fixtures pass, proving full-ID
child joins, current protector kind/key-type consistency, administrator presence,
the two firewall sentinels, and security-alert policy state. A complete empty
firewall list satisfies the exclusion baseline; an empty policy list cannot prove
an enabled configuration and returns UNKNOWN. These state checks remain distinct
from vulnerability-assessment configuration and scan scheduling. The current
[SQL protector API](https://learn.microsoft.com/en-us/rest/api/sql/encryption-protectors/get?view=rest-sql-2023-08-01)
and [administrator API](https://learn.microsoft.com/en-us/rest/api/sql/server-azure-ad-administrators/list-by-server?view=rest-sql-2023-08-01)
confirm the native fields. Local reviewed references993;313 remain unreviewed.

Recent local batches cover compute25refs, App Service21refs, service declarations
and exact reuse11refs, with source-truth fixtures and applicability guards.
Additional demonstrated source defects cover App Service10refs, Conditional
Access10refs, SQL5refs, and small service criteria4refs. Local reviewed references
are now1,079;227 remain pending. These are local readiness counts, with central
admission and the canonical-reference integration gate still outstanding.



### Native DPS customer-managed-key policy state

`azure.gap.iot_hub_encrypted_with_cmk` evaluates the frozen **Device Provisioning Service** policy-compliance contract. The new producer reads complete `Microsoft.Devices/provisioningServices` metadata, queries PolicyInsights `policyStates/latest/queryResults` using POST, and joins each actual resource/assignment/definition to current ARM GET responses. It does not establish IoT Hub encryption configuration, access to the customer key, or successful runtime encryption.

The owner supplies only a reviewed definition and freshness threshold:

```json
{"compliance_parameters":{"azure_iot_policy":{"scope":"/subscriptions/11111111-1111-1111-1111-111111111111","status":"collected","assignedDefinitionId":"/providers/Microsoft.Authorization/policyDefinitions/11111111-2222-3333-4444-555555555555","maxPolicyStateAge":3600}}}
```

The example definition UUID is illustrative, not an asserted DPS CMK built-in. Select the actual reviewed definition. The collector validates exact fields and bounds, binds the subscription at collection, and computes every observation itself. Hosted intake rejects this namespace for other providers before either authentication-mode return. It never accepts supplied compliance results, identity joins or completeness flags.

A complete fresh Compliant/NonCompliant state can produce PASS/FAIL only after exact native DPS, assignment, definition, effect, explicit parameter, enforcement and exemption checks. Optional native assignment-scope/action/parameter/version fields and modification timestamps must agree with current authority. Literal Audit/Deny effects and a single explicit String `effect` parameter are supported. Definition defaults that would require unmodeled effective-parameter substitution, initiatives, notScopes, overrides, resource selectors and unsupported exemption selectors remain unavailable. Missing, stale, future, duplicate, foreign, denied, unsupported or incomplete evidence never becomes empty compliant coverage. The complete empty DPS inventory is NOT_APPLICABLE without a policy query.

The subscription exemption list includes containing and child scopes. An exemption is joined only to actual inventoried DPS resources contained by its native scope; the projection retains that source scope and native exemption ID. Subscription/RG scopes are not relabeled as DPS resource identities. Active applicable exemptions remain UNKNOWN under the frozen predicate; expired exemptions can be assessed only after their native expiry and all pages are verified. Management-group assignment/definition origins remain unsupported by this subscription-bound model.

An explicit DPS-only inventory does not activate PolicyInsights queries. All reads share the existing reader call/page/resource budgets and authentication context; partial metadata is not promoted into a complete result. No mutation endpoint, listKeys call, DPS secret or SAS value is retained. Snapshot projections discard unrelated policy text, tags and optional key-bearing DPS fields immediately.

Required authorization is `Microsoft.Devices/provisioningServices/read`, `Microsoft.Authorization/policyAssignments/read`, `Microsoft.Authorization/policyDefinitions/read`, `Microsoft.Authorization/policyExemptions/read`, and **`Microsoft.PolicyInsights/policyStates/queryResults/action`**. The last is a read-only POST query, not covered merely by `*/read`; no role or customer template is changed by this candidate. No live credentials, resources or policy evaluations were created for its tests. Triggering evaluation is not supported.

Primary contracts: [DPS ListBySubscription, 2022-12-12](https://learn.microsoft.com/en-us/rest/api/iot-dps/iot-dps-resource/list-by-subscription?view=rest-iot-dps-2022-12-12), [PolicyInsights subscription query, 2024-10-01](https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/list-query-results-for-subscription?view=rest-policyinsights-2024-10-01), [policy definition ARM schema, 2023-04-01](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/resources/resource-manager/Microsoft.Authorization/policy/stable/2023-04-01/policyDefinitions.json), and [subscription exemptions, 2022-07-01-preview](https://learn.microsoft.com/en-us/rest/api/policy-authorization/policy-exemptions/list?view=rest-policy-authorization-2023-04-01).


Native Sentinel incident metadata (partial evidence only)

`azure_c5_ops_20_01b` now has a real native metadata path for an incident's classification or priority being outside an explicitly approved review policy. The collector lists all Log Analytics workspaces in the selected subscription (or reuses an already complete native workspace inventory), reads each workspace's Sentinel onboarding states, and lists all incidents for workspaces with an exact native default onboarding record. All reads use the existing ARM credential transport, budgets and continuation validation. An empty onboarding LIST is accepted as an actual absent onboarding record; a 403/404 or incomplete list is not converted into an absent service.

Only incident ID, status, classification, classificationReason, severity, createdTimeUtc and lastModifiedTimeUtc are retained. Free-form descriptions, titles, labels, owner details, comments and entity/event payloads are omitted. Onboarding state, workspace scope and incident child identity are joined explicitly. Duplicate IDs, foreign workspace/incident paths and partial pages cannot produce PASS. A partially read incident collection is marked partial and remains UNKNOWN even if one observed row would otherwise violate the owner policy.

This is deliberately partial functionality. Matching configuration, no incidents, no onboarded workspaces and absent response procedure records remain UNKNOWN. The collector does not invent process_evidence, triage dates, response completion, continuous detection coverage or human review. It cannot produce full-process PASS and does not close the entire Sentinel/C5 control.

Normative owner input already supported by frozen SW32:

```
options.compliance_policy.sw32 = {
  "status": "collected",
  "scope": "/subscriptions/<subscription UUID>",
  "incident_review": {
    "start": "<approved UTC start>",
    "end": "<approved UTC end>",
    "approved": true,
    "allowed_classifications": ["TruePositive", "FalsePositive", "BenignPositive", "Undetermined"],
    "allowed_priorities": ["High", "Medium", "Low", "Informational"]
  }
}
```

Those lists are approval criteria, not observations. An actual out-of-policy native classification/severity in the review window can FAIL; approved values alone cannot PASS the process requirement. No new IAM actions, no cloud resource creation, no writes and no signed predicate/pin changes.

Primary schemas:

- https://learn.microsoft.com/en-us/rest/api/securityinsights/sentinel-onboarding-states/list?view=rest-securityinsights-2025-09-01
- https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list?view=rest-securityinsights-2024-09-01
- https://learn.microsoft.com/en-us/rest/api/securityinsights/operations/list?view=rest-securityinsights-2025-09-01 (`Microsoft.SecurityInsights/onboardingStates/read` and incidents read)


Native assessment-definition severity criteria and real ARM extension identities

This candidate fixes one frozen SW32 ARM identity mismatch: Microsoft.Security/assessments is an extension resource. The official Assessments LIST example returns a VM scale set ID followed by `/providers/Microsoft.Security/assessments/<name>`; the prior regex selected the first provider and rejected this native response as foreign. The bounded parser now accepts the exact final assessment extension under the selected subscription, a resource group or a valid nested ARM resource. It rejects foreign subscriptions/tenant paths, ambiguous/repeated assessment extensions, incorrect final providers, child subassessments, traversal, percent encoding, query/fragment delimiters, backslashes and C0/DEL controls. Other SW32 resource-type validation is unchanged. The source pin is refreshed only in this private candidate. Native collection also rejects conflicting duplicate security assessment IDs instead of retaining an earlier NotApplicable row.

For `azure_c5_ops_25_02b`, the producer reads the complete native security assessment inventory and subscription assessmentMetadata LIST, including legitimate provider-global metadata IDs. It compares each applicable assessment definition's actual Low/Medium/High severity with an explicitly approved static mapping. This supports criteria that define the expected severity per assessment definition; it does not calculate CVSS, per-CVE vulnerability severity, business impact or risk criteria absent from the mapping. Missing native joins, denied/partial pages, invalid metadata states or uncovered active definitions remain unavailable.

Normative SW32 input:

```
options.compliance_policy.sw32 = {
  "status": "collected",
  "scope": "/subscriptions/<subscription UUID>",
  "vulnerability_severity_criteria": {
    "approved": true,
    "version": "v1",
    "expectedSeverityByAssessmentName": {"<native definition name>": "High"}
  }
}
```

`peaso.azure_sw32_policy.normalize_sw32(value, expected_scope=None)` validates and copies only normative approvals. incident_review and vulnerability_severity_criteria are optional independent features; either or both are accepted. A shared SW32 namespace preserves the Sentinel review when derived severity metadata is added. Invalid SW32 is rejected before Azure credential creation/requests, including direct collect_live library use. Scope is an exact subscription UUID and must be one of the selected explicit scopes. Hosted intake needs only to add sw32 to its Azure namespace allowlist and call normalize_sw32(review); native_policy_validation.py is untouched here.

The caller cannot submit finding_coverage_complete, assigned_severity_matches_criteria, observations, process_evidence, provenance or arbitrary result fields. The producer derives finding_coverage_complete only after complete actual assessment and metadata reads and complete applicable definition joins. assigned_severity_matches_criteria is computed from actual native severity and the approved mapping, with native source IDs and explicit comparison provenance. No caller-provided finding result is trusted.

Important limit: the unchanged frozen severity predicate returns PASS for an actually complete empty assessment inventory, and for exclusively NotApplicable assessments, when approved criteria and the derived native coverage exist. This is vacuous PASS; it is not evidence of an effective severity comparison and must not be counted as such. Without approved criteria or without complete native coverage these cases stay UNKNOWN. A future NOT_APPLICABLE outcome change requires separate owner review.

The native integration gate uses actual collect_live -> signed frozen engine paths. The original SW32 source-bound suite is run separately with its admitted SW32 registry entries isolated before import, as its module-level test registration otherwise collides with production bulk entries. This harness does not change source files or the running registry in another process.

Primary schemas:

- https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01 (official VMSS extension IDs)
- https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/extension-resource-types
- https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments-metadata/list-by-subscription?view=rest-defenderforcloud-2020-01-01

No shared source/pin edits, IAM changes, secret reads, cloud resources or mutable deployments are part of this private candidate.



### Native storage defaults and Azure Files recovery-point expiry

Two existing, unchanged signed predicates gain narrow read-only ARM evidence paths:

* `azure_storage_account_10_3_4_7_02943e9`: Storage API `2023-05-01` GET of each inventoried account, paged `blobServices/default/containers` LIST, exact container GET, and where `hasImmutabilityPolicy` is true, exact `immutabilityPolicies/default` GET. Actual account/container immutable-versioning modes, native policy presence, migration state, policy state and duration determine the effective default. Account defaults are inherited only when native account and container versioning modes both support that inheritance. A container policy overrides the account default. Contradictory embedded policy/detail/presence, unsupported or missing modes, migration, duplicate/foreign children, denied reads or incomplete pages remain UNKNOWN. Explicit Disabled or absent effective defaults can FAIL. Complete zero-container inventory is NOT_APPLICABLE. This measures configured defaults for new writes; it does not enumerate object-specific retention overrides or prove historical objects are protected.
* `azure_recovery_vault_10_3_3_3_45b190e`: Backup API `2024-04-01` complete native vault/protected-item inventories joined to exact protected-item recovery-point LIST/GET. This implementation accepts only `AzureStorage` / `AzureFileShare` / `AzureFileShareProtectedItem`, then `AzureFileShareRecoveryPoint`. It maps native `properties.recoveryPointProperties.isSoftDeleted` into the frozen evaluator's explicit deletion-state field, preserving source-field provenance. Retention is measured from actual `recoveryPointTime` to actual `recoveryPointProperties.expiryTime`; policy schedules and creation times cannot stand in for expiry. Missing dates, unknown deletion state, unavailable details, incomplete pages or unsupported workloads remain UNKNOWN. Short measured retention FAILs. No retained current recovery point remains UNKNOWN; inactive protected items can be NOT_APPLICABLE. Retention metadata does not prove restorability.

Privacy boundary: VM/SQL recovery points are rejected before LIST/GET. In particular the IaaS VM response model may contain `keyAndSecret`; this collector does not fetch it, restore data, list keys, retrieve secrets/private keys, probe applications, or create resources. Azure Files snapshot URI and unrelated fields are not copied into snapshots.

The optional, provider-bound normative namespace is `options.compliance_parameters.azure_storage_recovery`:

```json
{"scope":"/subscriptions/11111111-2222-3333-4444-555555555555","status":"collected","authorized_by":"security-owner","document_id":"retention-review","observed_at":"2026-10-15T00:00:00Z","expires_at":"2026-10-16T00:00:00Z","controls":{"defaultImmutability":{"accountIds":["/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account"]},"recoveryPointRetention":{"minRetentionDays":30}}}
```

Either control may be omitted. Approved account IDs and minimum retention are owner obligations, never API observations. Timestamp/completeness flags, native expiry values and arbitrary control properties are rejected at hosted and local intake. Missing/expired/foreign review cannot yield PASS. The derived SW13 check entry preserves existing raw SW13 sibling checks and authority; an existing tenant MFA review cannot be rebound to this subscription review. Conflicting authority conservatively leaves recovery retention UNKNOWN. SW23 sibling policy is unchanged. Snapshot capture time is generated after native reads, not supplied by the owner.

Read permissions: `Microsoft.Storage/storageAccounts/read`, `Microsoft.Storage/storageAccounts/blobServices/containers/read`, `Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read`, `Microsoft.RecoveryServices/vaults/read`, `Microsoft.RecoveryServices/vaults/backupProtectedItems/read`, and `Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/read`. No new write/data-plane/secret permission is introduced. Actual deployment-role availability and live positive evidence are not asserted by the SDK-shaped tests.

Primary contracts: [Storage account API schema](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/storage/resource-manager/Microsoft.Storage/Storage/stable/2023-05-01/storage.json), [blob container and immutability schema](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/storage/resource-manager/Microsoft.Storage/Storage/stable/2023-05-01/blob.json), [Backup API schema](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/recoveryservicesbackup/resource-manager/Microsoft.RecoveryServices/RecoveryServicesBackup/stable/2024-04-01/bms.json), [Recovery Points GET](https://learn.microsoft.com/rest/api/backup/recovery-points/get), [Storage account version-level defaults](https://learn.microsoft.com/en-us/azure/templates/Microsoft.Storage/storageAccounts).

This is partial native support for two existing conditional evidence contracts. It does not remove the unrelated structural scope/primary-dispatch backlog, guarantee all Azure recovery workloads, or establish global product completion.
