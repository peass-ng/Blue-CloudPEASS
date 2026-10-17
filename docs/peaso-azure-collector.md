
### Resource diagnostic routes and actual table retention

`resource_diagnostic_setting` supplies native metadata to
`azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b`.
`azure_diagnostic_eligible_resource` supplies the same discovered resource universe
plus setting GET and table retention metadata to
`azure.cis.monitor_resource_logging_services_support_it` (SW16). Neither producer
reads log contents, executes queries, fetches credentials, or proves delivery.

Both paths enumerate the selected subscription with ARM Resources_List
(2021-04-01), then discover diagnostic categories/settings (2021-05-01-preview)
and resolve each declared Log Analytics workspace with Workspaces_Get
(2023-09-01). Exact ID/type GET proves existence. The supported tracked universe
is deliberately conservative: Key Vault vaults, Log Analytics workspaces and
Storage accounts only. A different tracked type leaves the aggregate incomplete;
its unlisted logging children cannot be assumed absent. Storage account GET
(2023-05-01) binds its identity/type/kind; the four actual BlobServices_List,
FileServices_List, QueueServices_List and TableServices_List calls enumerate
logging children, including successful empty lists. No ResourceGraph subset,
parent-only inventory or invented default service stands in for these lists.

SW21 requires an enabled supported Logs category or native category group routed
to an existing workspace. It does not require owner policy or table retention.
SW16 additionally requires explicit owner requirements in
`options.compliance_parameters.azure_resource_logging`:

```json
{
  "scope": "/subscriptions/11111111-1111-1111-1111-111111111111",
  "status": "collected",
  "resources": [{
    "resourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault",
    "requiredCategories": ["AuditEvent"],
    "requiredCategoryGroups": [],
    "approvedSinkIds": ["/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/workspace"],
    "minRetentionDays": 60
  }]
}
```

These fields express owner requirements only: exact subscription scope, required
categories/groups, approved destination IDs and positive minimum retention days
(up to 4383). The frozen evaluator requires this resource ID set to match the
complete native eligible set. Missing approval does not synthesize a baseline.
Unknown input fields and observation/proof fields are rejected; identities must
belong to the approved subscription. Existing SW16 policies and coverage/status
fields are preserved when this named entry is added.

For SW16, DiagnosticSettings_Get must agree with the independently observed LIST
projection. A Storage enabled StorageRead/StorageWrite/StorageDelete category
with explicit `logAnalyticsDestinationType: Dedicated` binds to the documented
StorageBlobLogs, StorageFileLogs, StorageQueueLogs or StorageTableLogs table.
Key Vault with the documented default AzureDiagnostics destination binds to
AzureDiagnostics. Other category/table or destination-mode mappings remain
UNKNOWN. Tables_Get (2023-09-01) must return the exact workspace/table ID and name,
Succeeded provisioning, an Analytics/Basic plan, explicit positive active and
total retention and consistent archive retention if present. The producer uses
actual `totalRetentionInDays`, including archive; it does not claim all that time
is interactive retention. A `-1` inheritance marker or missing effective value is
unresolved. No workspace/table retention default is invented.

A successful category discovery with no Logs excludes that resource; unsupported
or denied discovery does not. Empty complete eligible inventory is
NOT_APPLICABLE. Foreign/duplicate IDs, malformed or partial pages, resource/call
limits, unsupported tracked types, cross-subscription sinks, non-workspace sinks
and workspace lookup errors leave native coverage incomplete. Retention-only GET
errors or unknown mappings leave SW16 UNKNOWN while SW21 can still evaluate its
independent configuration/existence evidence. Table 404 also remains UNKNOWN:
a table may not exist until its first log arrives. A complete supported scope
with disabled logs/missing settings can FAIL; a proven table retention shorter
than owner requirements can FAIL. No delivery, historical coverage, global
service coverage or universal compliance follows from these configuration reads.

All added operations are read-only ARM metadata at the existing ARM audience:
Storage account/four service reads, Insights diagnostic settings/category reads,
and OperationalInsights workspace/table reads. No new role, permission grant,
data-plane credential, query operation, write or infrastructure is introduced.
Permission denial remains unavailable evidence.

Primary contracts and explicit category/table mappings:

- [Monitor diagnostic settings/categories REST schema](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/3f819f6fc843ddd081b700edeeb1e238443e4da6/specification/monitor/resource-manager/Microsoft.Insights/Insights/preview/2021-05-01-preview/openapi.json).
- Storage service LIST schemas: [blob](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/3f819f6fc843ddd081b700edeeb1e238443e4da6/specification/storage/resource-manager/Microsoft.Storage/stable/2023-05-01/blob.json), [file](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/3f819f6fc843ddd081b700edeeb1e238443e4da6/specification/storage/resource-manager/Microsoft.Storage/stable/2023-05-01/file.json), [queue](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/3f819f6fc843ddd081b700edeeb1e238443e4da6/specification/storage/resource-manager/Microsoft.Storage/stable/2023-05-01/queue.json), [table](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/3f819f6fc843ddd081b700edeeb1e238443e4da6/specification/storage/resource-manager/Microsoft.Storage/stable/2023-05-01/table.json).
- Supported resource-log tables: [blob](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-storage-storageaccounts-blobservices-logs), [file](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-storage-storageaccounts-fileservices-logs), [queue](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-storage-storageaccounts-queueservices-logs), [table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-storage-storageaccounts-tableservices-logs).
- [Tables_Get and effective retention fields](https://learn.microsoft.com/en-us/rest/api/loganalytics/tables/get?view=rest-loganalytics-2023-09-01).
- [Diagnostic destination type/default and first-log table creation](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings).



### Native Azure Monitor and shared-dashboard inventories

The native `data_collection_rule` inventory calls the subscription-wide DataCollectionRules LIST (`2024-03-11`), exhausts pages, and GETs every exact returned resource. `dashboard` independently uses Microsoft.Portal shared-dashboard subscription LIST and GET (`2020-09-01-preview`). These helpers deliberately do not use a generic `/resources` response or Resource Graph absence as proof that the service-specific universe is empty. Workbook, Grafana and Fabric dashboards are not silently treated as Portal shared dashboards.

Each native row must retain the selected subscription, exact resource-group/provider/type/name path, and matching LIST/GET identity/type. Duplicate identities, malformed detail responses, denied requests and partial pages remain explicit. Pagination requests are bounded to the original service-list path and API version before transport; foreign-subscription next links are rejected before making that request. Existing authenticated Azure transport and scan-local request budgets/caches are reused, with no new credential source. The read permissions are Microsoft.Insights/dataCollectionRules/read and Microsoft.Portal/dashboards/read; the patch changes no role, grant, hosted authentication option or resource.

Persisted DCR fields are an allowlist: native identity/location/state, immutable ID, DCE reference, declared column names/types, and stream/destination flow references. Arbitrary extension settings, KQL expressions and dashboard tile/metadata bodies are excluded. DCE/workspace references are observations only: they are not asserted to resolve or authorize access. Native tenant provenance remains bound to the existing credential transport; no payload tenant field replaces it.

A complete ARM inventory does not prove the four broad controls. Each item and collection explicitly lists unmeasured semantic requirements using not_collected coverage. Stream authentication still needs genuine authorized/anonymous/wrong-type ingestion observations; metric floods need effective throttle and delivered alert telemetry. Dashboard access still requires complete effective authorization, ancestor/deny/condition/group/sharing evidence and normative classification. Web App workload-wide secret storage was not modified because application metadata cannot establish the required complete classified secret inventory.

The signed predicates and pins are unchanged. Native metadata alone yields UNKNOWN for the three targeted checks, including when a caller tries to inject fabricated effectiveAccess or behavior fields into the ARM body. Empty service inventories produce native EMPTY envelopes, but do not fabricate operator policies or claim NOT_APPLICABLE when the existing predicate still requires that authority. No direct-assignment FAIL witness is emitted: an apparent grant can be removed by deny assignments or conditions, and the required effective-access proof is not collected here. This is a functional native-inventory improvement, not completion of behavioral control coverage. No live cloud validation was performed in this stage.

Primary contracts: https://learn.microsoft.com/en-us/rest/api/monitor/data-collection-rules/list-by-subscription?view=rest-monitor-2024-03-11 and https://learn.microsoft.com/en-us/rest/api/monitor/data-collection-rules/get?view=rest-monitor-2024-03-11 . Portal service LIST/GET and pageable nextLink schemas: https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/portal/resource-manager/Microsoft.Portal/preview/2020-09-01-preview/portal.json .


### Databricks account metadata (explicit opt-in)

`azure.cis.unity_catalog_configured_databricks` can collect native account metadata
when `auth.databricks_account_token` contains an explicitly supplied Databricks
Account OAuth bearer token, alongside the normal ARM credential. The credential
is typed, limited to 16 KiB, encrypted/redacted as a secret and never accepted as
an option or compliance-policy observation. There is no AAD fallback, token
exchange, account discovery, permission grant or resource creation.

Owner requirements use the existing scoped SW33 policy:

```json
{"compliance_policy":{"sw33":{"status":"collected","scope":"/subscriptions/11111111-1111-1111-1111-111111111111","databricksAccount":{"accountId":"33333333-3333-3333-3333-333333333333"}}}}
```

Only GET requests to `https://accounts.azuredatabricks.net` are supported:
`/api/2.0/accounts/{account_id}/workspaces` and each identified workspace's
`/metastore` assignment. A documented assignment 404 additionally requires a
fresh account workspace GET **after** that response, matching the original
workspace metadata. Tokens never follow redirects or environment proxies.
Responses are limited to 2,000,000 bytes and at most 1,000 account workspaces;
shared request/item/deadline budgets still apply. Socket timeouts are not a hard
whole-scan wall-clock guarantee.

The complete ARM workspace inventory and full ARM GET bind the subscription,
resource group, resource type, resource name and native `properties.workspaceId`
to the same account response's `account_id`, `workspace_id`, `cloud=azure` and
`azure_workspace_info`. Account workspaces in the selected subscription must
match that ARM universe exactly and be RUNNING; only that native state maps to
the predicate's ACTIVE state. Other subscriptions are excluded by their native
subscription ID, without borrowing their metadata or approvals.

A 200 assignment must return the exact workspace ID and a nonempty bounded
metastore identifier. The native response declares a string, not a UUID regex. An
exact, documented no-assignment 404 on the proven workspace is FAIL. Missing
approval/token, conflicting or partial inventories, changed workspace metadata,
non-running states, malformed identities and budget exhaustion never become a
compliant empty inventory. Actual authentication/authorization failures preserve
the engine's DENIED status; other missing proof remains UNKNOWN. The account
credential needs existing authorization for provisioning reads and Unity Catalog
reads; this adapter adds no default ARM or Databricks grants.

Only reviewed identity, state and assignment metadata is retained. Account
credential configuration IDs, catalog names, arbitrary tags/free text, response
bodies from errors and bearer tokens are excluded before native responses can
enter collection evidence. Native account ownership is an explicit operator trust
choice, checked against actual account and Azure identities; it is not inferred
from the ARM credential's principal.

Primary contracts:
- https://docs.databricks.com/api/workspaces/v1/list-workspaces-public
- https://docs.databricks.com/api/uc-metastores/v1/account-metastore-assignment
- https://learn.microsoft.com/en-us/rest/api/databricks/workspaces/get?view=rest-databricks-2024-05-01

The focused tests use actual REST response schemas and the ordinary live collector
and signed engine. No Databricks cloud account was accessed for this candidate;
that remains a separate credential/permission-dependent validation step.

### Explicit Azure DevOps Git URL metadata (phase 1)

`azure_devops_project_1_2_8_6_fb0e5a8` can read a declared Azure DevOps project
universe associated by the owner with an Azure subscription. This association
states applicability; DevOps projects are not ARM children. Supply exactly:

```json
{"compliance_parameters":{"azure_devops_git":{"subscriptions":[{
  "scope":"/subscriptions/11111111-1111-1111-1111-111111111111",
  "organization":"owned-org",
  "project_ids":["33333333-3333-3333-3333-333333333333"]
}]}}}
```

Supply the corresponding credential through encrypted connector authentication,
never options or reports:

```json
{"devops_credentials":[{"server":"https://dev.azure.com/owned-org",
  "method":"pat","token":"<provided securely>"}]}
```

`method` accepts `pat` or `bearer`. ARM authentication is separate and is never
reused or exchanged for DevOps authentication. The token needs project and code
read access (`vso.project`, `vso.code` for applicable OAuth/PAT scope choices).
The subscription must be selected and its actual ARM GET tenant must match the
verified Azure credential tenant. A missing token/applicability produces UNKNOWN;
unbound/malformed authentication is rejected before transport. No live DevOps
authentication has been demonstrated by the synthetic fixture tests.

The reader uses API 7.1 Projects List (`stateFilter=all`, numeric continuation
header) and exact project UUID GET. Every declared project must be accessible
and wellFormed. Repository List requests `includeHidden=true` and
`includeAllUrls=true`, followed by exact repository UUID GET, with strict parent
joins. It never follows URLs returned by the service. Projects List explicitly
lists projects accessible to the authenticated user: this is **not all-org
coverage**, and no excluded/inaccessible projects are treated as empty. The
report concerns declared projects and the repository metadata exposed by the
read API; `includeHidden` does not grant permission to otherwise inaccessible
repositories. Administrators must choose a credential with appropriate read
visibility for those declared projects. Owner configuration cannot submit
observations, completeness booleans or native provenance.

Only ordered typed URL parse facts are retained: source field/index, valid
parse, and userinfo presence. URL values, URL hashes, usernames, passwords,
query values, repository contents/descriptions and response error bodies are
never stored. A native schema/capture UUID and scan-local credential binding
select a separate strict validation path; malformed native evidence cannot fall
back to the legacy raw-URL path. The parse decisions preserve the authored predicate:
HTTP, HTTPS and SSH URL schemes are accepted, and a valid parsed netloc containing
`@` is a decisive FAIL. This detects **userinfo**, which can be a public username; it does
not prove a password was exposed. SCP syntax such as `git@host:repo`, malformed
ports, missing URL fields and unsupported representations remain UNKNOWN.
Within each repository the original URL order and first-malformed behavior are
preserved. Clean or empty native accessible results remain UNKNOWN: no API contract here proves a project-wide authorization-unfiltered repository universe. A verified unsafe-userinfo observation can produce FAIL, but this adapter does not close the complete control. There is no
HTTPS-only hardening assertion, pipeline-stage evaluation or SW14 credential
variable evidence in this phase.

Requests use fixed HTTPS `dev.azure.com` endpoints, default certificate
verification, disabled ambient proxies and redirects, at most 20 project pages,
256 declared projects, 1,000 repositories, 512 actual read attempts, 2 MB per
response, 16 MB total response bytes and a 120-second native phase deadline.
Existing shared Reader call/resource/page/deadline/cancellation limits also
apply. Undocumented repository pagination, repeated continuation, partial reads,
403 or identity drift cannot produce a complete PASS. Child read failures leave
that project's repository evidence unresolved; a separate completely verified
counterexample can still produce FAIL as in the original aggregation semantics.

Primary REST contracts: [Projects List](https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects/list?view=azure-devops-rest-7.1),
[Projects Get](https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects/get?view=azure-devops-rest-7.1),
[Repositories List](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories/list?view=azure-devops-rest-7.1),
[Repository Get](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories/get-repository?view=azure-devops-rest-7.1).

V2 completeness correction: `Repositories List` provides an accessible API view;
`includeHidden` and `includeAllUrls` are request options, not proof of unrestricted
repository Read permissions. Native repository coverage is explicitly `partial`
with `repository_authorization_universe_unverified`. `api_pages_complete=true`
records only successful exhaustion of the supported API response sequence. It is
not an approval or proof that all project repositories were returned. Native
empty results cannot yield N/A. The legacy complete-evidence URL path is unchanged.

[Repository-specific permissions and Deny precedence](https://learn.microsoft.com/en-us/azure/devops/repos/git/set-git-repository-permissions?view=azure-devops)
explain why a native authorization-unfiltered universe must not be assumed. This
is a conservative completeness limit, not a claim that a specific undocumented
Repositories List filtering behavior has been reproduced.


SW32 owner criteria use `options.compliance_policy.sw32`, with the existing `status: "collected"` approval envelope and exact `/subscriptions/<UUID>` scope. The envelope records a declared policy, not a cloud observation. Local collection and hosted connector validation share the same pure normalizer.

In addition to the existing incident review and severity mapping, the accepted criteria are:

- `acr_max_untagged_days` and `max_registry_scan_age_seconds`: positive integers.
- `later_stage_deployment_limit`: a nonnegative integer.
- `registry_vulnerability_assessment_key`: an expected assessment selector, 1–128 safe name characters; selecting a key does not prove a scan occurred.
- `approved_cosmos_workspaces`, `sensitive_dashboard_ids`, `approved_peer_ids`: exact ARM IDs for Log Analytics workspaces, Portal dashboards and VNets respectively. Cross-subscription destinations can be approved explicitly; this does not change the source subscription or prove destination existence.
- `approved_dashboard_viewers`: principal UUIDs.
- `required_role_assignments`: objects containing exactly `principalId`, `roleDefinitionId`, `scope`. Principal and role UUIDs must be explicit; role definition IDs support root, subscription and management-group scopes. Assignment scopes must be inside the policy subscription or an explicitly named management group. Approval does not establish management-group ancestry, actual assignments, or complete RBAC coverage.
- `approved_key_algorithms`: exactly `industry_standard_confirmed: true`, `minimum_rsa_bits` (at least 2048), and a nonempty `approved_ec_curves` list drawn from P-256, P-256K, P-384, P-521. This approves policy; it does not prove actual encryption use, imported-key provenance, certified HSM origin, or a key's compliance.

Integers reject booleans and must not exceed 2^53−1. ID arrays and assignment lists allow at most 256 entries and reject case-insensitive duplicates. Policy JSON remains capped at 50 KB; identifiers are bounded, literal, and reject query strings, fragments, encoded separators, traversal and malformed resource paths. Empty allowlists remain explicit restrictive policy, not complete empty inventories.

The normalizer continues rejecting observed facts, including `rbac_relevant_scopes_complete`, `unapproved_peering_prevention`, findings, coverage, and provenance. Native evidence remains independently required by every existing predicate; no predicate, signed pin or source contract is changed. In particular, required-role PASS and preventive VNet PASS remain UNKNOWN until their separate evidence requirements can be met.

### Explicit APIM protocol parameters

The native `apim_api_evidence` projection uses the existing APIM API inventory,
revision lists and GETs for online revisions absent from the list. It evaluates
all API rows in that complete inventory, including hydrated revisions. It adds
no network probe or IAM permission. The signed protocol evaluator is unchanged.

Supply `options.compliance_policy.sw23` with `status: "collected"`, the exact
subscription `scope`, nonempty `authorized_by` and `document_id`, and current
ISO timestamps `observed_at` / `expires_at`. Its `apim_protocols` object maps
exact service ARM IDs to `{ "proposed_spec_sha256":
"0d01a758e49f3c58bbb3c169ba87576979a3bfe01c97bc33859ee849b8d45f78",
"apis": { ... } }`. Each `apis` object maps every collected API/revision ARM ID
to an explicitly approved `expected_endpoint_type` and `forbidden_protocols`.
Accepted transport names are `http`, `https`, `ws`, `wss`. There is no default
HTTPS policy or wildcard service/API approval. Approval metadata represents the
operator's supplied policy, not an independent certification of that policy.

Missing, expired, contradictory or foreign approval, incomplete native pages or
revisions, ambiguous identities, and unknown native protocol values remain
`UNKNOWN`. A complete, approved empty API inventory is `NOT_APPLICABLE`.
An explicit empty protocols array is an observed mismatch, not missing evidence.
A matching configured protocol is not proof of TLS negotiation or WAF protection.
Native APIM list readers reject duplicate child identities across pages rather
than silently discarding contradictory observations.
