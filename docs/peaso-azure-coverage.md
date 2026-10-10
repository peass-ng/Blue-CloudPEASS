# Azure native source coverage

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
