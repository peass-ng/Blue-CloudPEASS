# Network inventory audit record

The service-family review is reconciled in `service-dispositions.json`, using
independent AWS SDK, Google discovery and Microsoft Private Link censuses.
The matrix records the reviewed boundaries rather than equating a finite
application catalog with every API or every future provider feature.

## Collected and published

- AWS: 188 additional native collection plans and 311 verified IAM action
  mappings, plus VPC DNS and existing connector detail enrichment. Native SDK
  structure fields are projected before caching; arbitrary SDK maps, application
  configuration, scripts and credentials are excluded. OpenSearch Serverless
  network policies and QuickSight network restriction keys have dedicated parsers.
  Parent discovery, detail pagination, composite identities, missing details,
  explicit ownership and region information survive collection and projection.
- AWS generated customer role: 1075 metadata actions in seven managed policies,
  all within IAM size/attachment quotas. Local template generation does not
  deploy new customer grants.
- Google: 106 additional metadata plans, native list/get field masks, documented
  regional hosts, real Compute zone expansion for zonal APIs, global resources,
  selected organization scopes and independent CRM project-alias evidence.
  Nested Service Directory, Workstations, VMware and Agent Engine resources are
  enumerated from native parents. Denied or missing details retain summaries and
  partial coverage. Empty location discovery cannot imply an empty service.
  Existing bucket IP filters, flow-log configuration, DNS and managed storage
  export clients are included in network projections.
- Azure: every one of the 71 resource types in the independent Private Link DNS
  census has a registered network inventory. The added manifest has 51 roots,
  alongside existing collectors. Child discovery covers transit routing,
  Cassandra, Grafana, Elastic SAN, healthcare services, Kusto private endpoints
  and Application Gateway for Containers subnet associations/frontends.
  Child versions are checked against their own resource references. Fabric's
  documented 2024-06-01 ARM resource version is recorded separately from the
  template catalog. DPS network data has a separate reader from the compliance
  observation that intentionally retains identities only.
- Synapse managed private endpoints and Load Testing definitions use native
  workspace/resource-bound data-plane origins and the correct token audiences.
  Only read-only network metadata routes are accepted. Test scripts, artifacts,
  environment values, secrets and free-form descriptions are excluded.
- Kubernetes: 65 reviewed CNI, mesh, ingress, load-balancer and OVN resources,
  in addition to core networking/storage/workloads and Gateway API. Served group,
  version, resource and scope are verified. The extra ingress/controller registry
  is separate from the admitted CNI/Multus registry. Exact cluster/namespace/UID
  joins preserve ownership, backend and Multus relationships. Absent APIs are
  distinguished from denied discovery.
- Network map inspectors and paginated views retain these resources and native
  network attributes. The same projected information, graph and coverage reach
  the agent's actual SQLite evidence database. Endpoint URL arrays also remove
  user information, query and fragment material. No structural link is presented
  as observed traffic or proof of effective reachability.

## Verification

- Broad backend/AI network regression: 1047 passed, 2 skipped, 15 deselected.
  This ran before the final URL-array hardening; the final handoff regression
  covers that change and all four actual agent database exports.
- Frontend network architecture, inspector completeness and managed-service
  suites: 44 passed. The final native-field label suite also passed (6 tests).
  TypeScript typecheck passed.
- Restored-state network/handoff regression: 363 passed, 1 skipped,
  5 deselected. The final network-only run after the CIDR/identity refinements
  passed all 231 tests. It
  includes real network SQLite exports for AWS, Google, Azure and Kubernetes.
  Known unrelated
  exclusions are the optional chack-loader environment, a pre-existing GCP token
  transport fixture and a legacy S3 metadata/content permission assertion. They
  are not represented as a completely green repository suite.
- Runtime integrity/admission checks pass on a fresh import after reconciliation
  of the concurrent shared AWS edit. Existing engine edits and admission receipts
  are preserved. Protected AWS request methods, Kubernetes collection/sanitization,
  Azure collect and the admitted CNI router manifest/matcher are unchanged by
  this pass's added collection paths.

## Review boundaries and rollout

`service-dispositions.json` explicitly records aliases, history/findings,
hypothetical configurations, hardware/logical networks, unrelated Google
products, discovery-unavailable products and separate SaaS identity domains.
CodeCatalyst developer-space bearer APIs are outside an IAM-role/account/region
scan; native EC2 endpoints are still collected. Arbitrary unreviewed CRDs are not
silently treated as supported or absent. Six preferred Google discovery entries
were unavailable; their retrieval status and non-native-VPC product disposition
remain visible in the matrix.

Customer permissions and a fresh scan are required to populate new data. Old
snapshots remain immutable. Azure ARM-only tokens cannot provide Synapse/Load
Testing audiences, and subscription Reader does not imply data-plane roles.
Explicit connector scopes, inventory selections, budgets, missing permissions,
API disablement and unread locations remain visible coverage limitations.

Reusable scanners: `scripts/audit_network_service_inventory.py` and
`scripts/audit_network_service_dispositions.py`. Temporary discovery schemas and
review generation helpers are under `/tmp/peaso-network-audit/`; the shipped
collection manifests and checked-in audit reports are the reviewable artifacts.
