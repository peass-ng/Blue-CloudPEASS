# Native GCP snapshot collector

`peaso.collectors.gcp.collect(connector, requirements=None)` returns the engine's
sealed schema 1.0 snapshot. It reads GCP REST APIs directly using `google-auth`
and `requests`; it needs neither a container nor an external scanner runtime.
Install the project's `cloud` extra for live collection.

The collector never enables APIs, creates fixtures, changes IAM, or accesses
secret versions, private keys, SQL passwords or Kubernetes credentials. Its
transport permits HTTPS requests to an explicit Google API host list, refuses
redirects and accepts only GET and the read-only POST operations `getIamPolicy`,
`getAncestry` and Logging `entries:list`. Credential libraries can separately
exchange credentials and mint short-lived impersonation tokens.

## Selection and scopes

```python
from peaso.collectors.gcp import collect

snapshot = collect({
    "provider": "gcp",
    "scopes": ["projects/my-project", "organizations/123456"],
    "auth": {"method": "gcloud", "account": "auditor@example.com"},
    "options": {
        "inventories": ["bucket", "iam_policy", "network", "subnetwork"],
        "project_restrictions": ["my-project"],
        "max_calls": 100,
        "max_pages": 5,
        "max_resources": 2000,
        "concurrency": 4,
        "resource_iam": True,
        "include_inherited": True,
    },
})
```

Scopes are explicit `projects/ID_OR_NUMBER`, `organizations/NUMBER` or
`folders/NUMBER`; a bare project identifier is normalized to `projects/...`.
An organization selection permits that organization's resource inventory unless
`project_restrictions` is set. With restrictions, broad ancestor CAI asset and
resource-IAM searches are skipped; ancestor IAM policies can still be read.
An explicitly selected project outside the restrictions fails validation before
authentication. Neither inheritance nor Shared VPC references select other
projects automatically.

`options.all_projects=true` explicitly requests Resource Manager
`projects:search` discovery of accessible active projects. Use `scopes=["*"]`
for this selection when calling the collector directly, or an explicit project
with `all_projects=true` through the engine. Organization/folder descendant
project discovery is separately enabled by `discover_projects=true`, using
CAI Project assets, including projects beneath folders. Restrictions filter
discovered projects before service reads and remove excluded project records
from snapshot discovery evidence. Discovery remains subject to permissions,
eventual consistency and scope/page/call budgets; it is never a claim that every
project in an organization was visible.

`snapshot.scopes` retains the normalized user selection. Metadata records
`requested_scopes`, `resolved_scopes`, `inherited_scopes` and `scope_coverage`.
Every collection records its actual scope, including ancestor policies and
discovery results. Ancestry is deduplicated across selected projects, and only
ancestor IAM/custom-role/hierarchy reads are made implicitly.

`requirements` contains native resource type names. It intersects
`options.inventories`; `None` selects the configured inventory, and an empty
list makes no authentication or API requests. Parent inventories needed to
enumerate child resources are read once and recorded in
`metadata.supporting_inventories`, even when omitted from the output. These
dependencies include service accounts for keys, pools for providers, and key
rings for KMS keys. Built-in IAM role definitions are fetched once for roles
referenced by collected bindings. Cross-project custom role references outside
selected projects remain explicit coverage gaps.

## Authentication

Credentials are selected once, refreshed within the selected source and never
replaced by a different source after failure. `method=auto` means ADC; it does
not try gcloud first. A provided `auth.token` selects that token explicitly.
`auth.quota_project` pins the quota project; there is no guessed-quota retry.

| Method | Configuration and behavior |
| --- | --- |
| `adc` | `google.auth.default`; supports its ADC service-account, authorized-user, external-account, impersonated and metadata sources. Explicit ADC source errors are returned without CLI fallback. |
| `service-account` | `service_account_file` or `sa_json` (path, JSON string, or dictionary); the explicitly selected key must load and refresh successfully. |
| `gcloud` | Optional `account`; otherwise reads the configured named account before requesting a token. Pins account and configured or explicit `impersonate_service_account` for every token refresh, even if another terminal changes defaults. A blank explicit impersonation target disables it. |
| `external-account` | Local `external_account_file`/`credential_file`, or portable `external_account_json` plus `subject_token`; requires `type=external_account`. Uses Google's workload identity federation loader/supplier without replacement ADC lookup. |
| `metadata` | Explicit Compute metadata credentials, with optional `service_account_email` (default `default`); no ADC or gcloud lookup. |
| `impersonation` | Requires `source_auth`, `target_principal` (alias `impersonate_service_account`), optional ordered `delegates` and `lifetime` (300–3600 seconds; default 900). Sources can use ADC, explicit service-account, external-account, metadata or pinned gcloud credentials. |

For delegated impersonation from a logged-in gcloud identity:

```python
auth = {
    "method": "impersonation",
    "source_auth": {"method": "gcloud", "account": "auditor@example.com",
                    "impersonate_service_account": ""},
    "target_principal": "inventory@my-project.iam.gserviceaccount.com",
    "delegates": ["delegate@my-project.iam.gserviceaccount.com"],
}
```

Portable external-account authentication accepts a configuration dictionary or
JSON string in `external_account_json`, with the ephemeral external credential
in `subject_token`. It supplies that token directly to Google's identity-pool
credential class and removes the configuration's `credential_source`. It never
reads a server-local token file or executes a source URL in this mode. Local
file configurations support local subject-token files and AWS metadata sources
with fixed metadata/STS destinations. Arbitrary source URLs and executable
credential sources are rejected. The token exchange endpoint must be
`https://sts.googleapis.com/v1/token`; optional impersonation is restricted to
the Google IAM Credentials service. Inline subject tokens are finite-lived;
subsequent collection needs a fresh subject token after expiry. Hosted callers
should use portable inputs and gate operator-local credential modes separately.

Token refresh is serialized; HTTP sessions are reused per collection worker.
Gcloud tokens are retained for four minutes and refreshes always use the pinned
CLI account/impersonation settings. CLI calls are noninteractive and have a
30-second timeout. Authentication failure records a safe code, without CLI
stderr, file contents, token strings or exception messages.

The OAuth scope is `cloud-platform`: several metadata APIs, including
[CAI assets.list](https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/assets/list),
require this scope and do not accept `cloud-platform.read-only`. The collector's
explicit read-only request paths enforce its behavior; IAM permissions should
still be granted only for the reads required by selected facts.

## API and fact coverage

Native configuration fields retain their provider names. Sensitive fields are
removed before sealing. Token configuration objects (`oidcToken`, `oauthToken`) keep only
`serviceAccountEmail`, `audience` and `scope`; they never contain a token. Public/internal addresses, references and IAM identities
are configuration evidence, so treat snapshots as private inventory artifacts.

| Types | Reads and evidence |
| --- | --- |
| `asset` | CAI `assets.list`, `contentType=RESOURCE`, at one recorded `readTime`; broad service metadata, including services without a dedicated adapter. Optional `asset_types` narrows types/patterns. CAI is eventually consistent. |
| `iam_policy` | Resource Manager v3 project/org/folder `getIamPolicy` requesting version 3, plus CAI `searchAllIamPolicies` resource coverage. Native bindings, conditions, audit configs, owning project, folders and asset type are retained. `resource_iam=false` limits this to the hierarchy policies. |
| `iam_role` | Project/organization custom roles with `view=FULL`, including deleted definitions; referenced predefined roles use IAM role get. Included permissions and stage/deleted flags are preserved. |
| `iam_deny_policy` | IAM v2 attached deny-policy list; full policy get when list results omit rules. Denied principals, permissions, exceptions and conditions remain declared policy evidence. |
| `project`, `organization`, `folder` | Resource Manager v3 metadata; project Compute metadata provides sanitized common instance metadata, default service account and Shared VPC status. Project ancestry uses v1 `getAncestry`. |
| `service_account`, `service_account_key` | IAM account list and account policy get; key list retains name/type/origin/disabled/lifetime metadata, with no key material. Denied account discovery makes dependent key coverage unavailable rather than empty. |
| `activity` | Bounded Logging audit entries list over `activity_days` (default 30). Only timestamp, principal, service-account key name, service/method/log identity and the coverage window survive projection. Empty or incomplete logs do not prove inactivity. |
| `recommendation`, `insight` | IAM Policy Recommender recommendations/insights; native removed/unused-permission evidence. `recommender_locations` explicitly selects locations (default `global`), without refresh/mark/apply operations. |
| `network`, `subnetwork`, `firewall`, `firewall_policy` | Global VPCs/firewalls; aggregate regional subnets and global/regional network firewall policies; organization hierarchical firewall policies. Native ranges, priority, direction, tags, service accounts, disabled/deny/allow semantics and peering are preserved. |
| `firewall_policy_association` | Direct organization/folder association lists. These detect policies created elsewhere in the organization but applied to a project ancestor; denied or malformed reads cannot prove absence. |
| `instance`, `route`, `router`, `vpn_gateway`, `vpn_tunnel`, `address`, `instance_group` | Global routes and aggregate instance/router/VPN/address/group reads. Includes VM interfaces/access configs, service-account scopes, shielded/confidential configuration and declared network references. Both HA and classic VPN gateways are read. |
| `forwarding_rule`, `backend_service`, `backend_bucket`, `target_proxy`, `url_map`, `health_check` | Aggregate global/regional forwarding rules/backends/maps/health checks and HTTP/HTTPS/TCP proxies; global SSL/gRPC proxies/backend buckets. Backend group and health-check references retain relationships. |
| `shared_vpc` | Compute `getXpnHost` and paged `getXpnResources`; preserve host/service ownership references without traversing unselected host projects. A failed host/resources read is visible coverage evidence. |
| `bucket` | Storage list with full projection plus version-3 bucket IAM. Uniform bucket access, public prevention, ACL metadata, default KMS encryption, logging/versioning/retention configuration. No object listing or object reads. |
| `sql_instance` | SQL Admin instance list: IP configuration, backups, flags, encryption, IAM auth/settings metadata; passwords and certificate material are removed. |
| `gke_cluster` | GKE cross-location cluster list: networks, private/public endpoints, authorized networks, workload identity, shielding, encryption, control-plane and node configuration. Master authentication credential/certificate fields are removed. No Kubernetes data-plane connection. |
| `kms_key_ring`, `kms_key` | KMS locations and per-location key-ring lists, then crypto-key metadata and key IAM. `kms_locations` narrows locations explicitly; rotation, purpose, primary-version state/protection level and references remain metadata. No encrypt/decrypt/export. |
| `log_sink` | Project/folder/organization Logging sinks, destinations and writer identities. Audit-policy evidence is in `iam_policy.auditConfigs`. |
| `secret` | Secret Manager secret list and IAM policy metadata, replication/rotation/encryption configuration. No secret values or version access. |
| `bigquery_dataset` | BigQuery dataset list including hidden datasets, plus full dataset metadata with access-policy version 3. Dataset ACL, default encryption and location/retention metadata; no queries, table data or exports. |
| `artifact_repository` | Artifact Registry region/repository list plus repository IAM; format, immutable-tag, encryption, vulnerability-scanning and cleanup metadata. No image/package downloads. |
| `cloudrun_service` | Cloud Run v2 region/service list plus IAM; ingress, service identity, network/VPC, encryption and public URI metadata. Container environment values/commands are stripped. The v2 service list cannot use a wildcard location, so supported locations are enumerated, or explicitly selected with `cloudrun_locations`/`regions`. |
| `function` | Functions v2 cross-location function list and IAM; runtime, ingress, service identity, VPC and encryption references. Inline environment values are stripped; variable names survive as `environmentVariableNames` and secret-backed variables keep their Secret Manager reference. No source downloads or function invocations. |
| `workload_identity_pool`, `workload_identity_provider`, `workforce_pool`, `workforce_provider` | IAM workload/workforce pool/provider metadata including OIDC/AWS trust configuration, attribute mappings/conditions and state. Workforce pools are organization-scoped. |
| `cloudbuild_trigger` | Cloud Build `projects.locations.triggers.list` (GET `v1/{project}/locations/global/triggers`, plus each `cloudbuild_locations` region) as full resources. Inline build steps, scripts and substitution values are dropped (`substitutionNames`, `inlineBuild.stepCount` remain); source, PR comment control, approval and service account remain. Permission: `cloudbuild.builds.list`. |
| `storage_hmac_key` | Cloud Storage `projects.hmacKeys.list` (GET `storage/v1/projects/{project}/hmacKeys`): access ID, bound service account, state and timestamps only (the secret is only ever returned by create). Permission: `storage.hmacKeys.list`. |
| `composer_environment` | Cloud Composer `environments.list` per region (Compute `regions.list`, or `composer_locations`/`regions`). Airflow environment variable and config-override values are dropped (names kept); node service account remains. Permissions: `composer.environments.list`, `compute.regions.list`. |
| `workbench_instance` | Vertex AI Workbench (`notebooks.googleapis.com/v2`) `instances.list` with the `-` location wildcard; GCE setup service accounts and network flags. Metadata values are dropped except root/terminal/download/proxy flags. The wildcard is documented by the v2 `instances.list` reference ("`projects/{projectId}/locations/-` to list instances in all locations"); a non-empty `unreachable[]` makes the read unavailable coverage. Permission: `notebooks.instances.list`. |
| `org_policy_effective` | Org Policy v2 `projects.policies.getEffectivePolicy`, one GET per requested constraint per project (no list-all): `storage.publicAccessPrevention`, `compute.requireOsLogin`, `iam.disableCrossProjectServiceAccountUsage`, `iam.automaticIamGrantsForDefaultServiceAccounts`, `iam.disableServiceAccountKeyCreation`, `iam.disableServiceAccountKeyUpload`, `iam.allowedPolicyMemberDomains`, `essentialcontacts.allowedContactDomains`, and managed successors `iam.managed.disableServiceAccountKeyCreation`, `iam.managed.disableServiceAccountKeyUpload`, `iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts`, `iam.managed.allowedPolicyMembers`, `essentialcontacts.managed.allowedContactDomains`. Permission: `orgpolicy.policy.get`. |

Effective Org Policy responses are bound to the requested constraint suffix and project before collection is marked complete. The exact requested `projects/{projectId}` parent needs no additional read. A numeric `projects/{number}` response parent is accepted only after one cached, read-only Cloud Resource Manager v3 `projects.get` response for that selected project reports the same `projectId` and numeric `name`; the policy response and its requested-scope wrapper cannot establish that alias. Missing or mismatched policy names, and unavailable or contradictory alias evidence, leave the collection incomplete so inherited bucket prevention and OS Login remain UNKNOWN. This validates response identity; it does not prove bucket IAM exposure or guest OS Login enforcement.
| `domains_registration` | Cloud Domains `registrations.list` (GET `domains.googleapis.com/v1/{project}/locations/global/registrations`, `fields` mask): name, domainName, state, expireTime only; contact settings are never requested. Permission: `domains.registrations.list`. |
| `bucket_notification` | Cloud Storage `notifications.list` per collected bucket (GET `storage/v1/b/{bucket}/notificationConfigs`): id, topic, event types, payload format, object prefix, bucket project; custom attribute names only (values dropped). Incomplete bucket inventory makes it unavailable. Permission: `storage.buckets.get`. |
| `group.groupSettings` (opt-in) | Only with option `group_settings=true`: Groups Settings `groups.get` (GET `www.googleapis.com/groups/v1/groups/{email}`) per collected group, keeping `whoCanJoin` and `allowExternalMembers`. Needs the `apps.groups.settings` OAuth scope and a Workspace admin token, which default cloud-platform ADC lacks; denied reads are per-group coverage (UNKNOWN), never empty settings. |
| `scheduler_job` | Cloud Scheduler `locations.list` then `jobs.list` per location (or `cloudscheduler_locations`/`regions`). Target URI keeps scheme/host/path only (query dropped), method, OAuth/OIDC service account/scope/audience; bodies, header and attribute values are dropped (names kept). Permissions: `cloudscheduler.locations.list`, `cloudscheduler.jobs.list`. |

API paths were checked against Google's live
[Compute discovery document](https://www.googleapis.com/discovery/v1/apis/compute/v1/rest).
In particular, network firewall policies use `aggregated/firewallPolicies`, and
regional HTTP/HTTPS/TCP proxies use their aggregate paths. KMS key rings are
enumerated per location rather than assuming a wildcard key-ring list.
Artifact Registry locations can be narrowed with `artifactregistry_locations`
or `regions`; neither that adapter nor Cloud Run assumes undocumented wildcard
location support. A denied regional read does not hide evidence from another
readable region, but makes the collection partial.

## Limits, failures and provenance

| Option | Default | Range |
| --- | --- | --- |
| `max_calls` | 1000 | 1–100000 |
| `max_pages` | 10 | 1–100 per list operation |
| `max_resources` | 10000 | 1–100000 across output and supporting inventories |
| `max_scopes` | 100 | 1–1000 including discovered/inherited scopes |
| `page_size` | 100 | 1–1000 (Compute requests capped at 500) |
| `concurrency` | 4 | 1–16 |
| `retries` | 2 | 0–5 |
| `timeout` | 20 seconds | 1–120 seconds per HTTP attempt |

Identical requests are coalesced, including simultaneous detail reads and their
failures. Requests count against a shared attempt budget, including failed auth
attempts; `http_attempts` distinguishes requests actually submitted to the API.
Retries cover network failures, 429 and 500/502/503/504 responses with capped
backoff. Permission failures are not retried. Page caps cause partial coverage
without an extra speculative page; repeated continuation tokens are explicit
malformed coverage. Continuation tokens and bearer headers never enter
provenance. There is no single whole-scan time limit; the finite call/page/scope
budgets, attempt/CLI timeouts and concurrency bound the run.

Schema 1.0 collection `status` uses `collected`, `empty`, `partial`, `denied`,
`unknown` and `malformed`. `coverage_status` additionally distinguishes
`unavailable` and `unsupported`, encoded as wire `unknown` with
`error.kind` set accordingly. Disabled APIs (`SERVICE_DISABLED`) and billing
failures are unavailable; 401/403 permission failures are denied. HTTP status and
allowlisted Google error reasons are retained, while arbitrary provider messages
are omitted. Unsupported types at a scope are explicit records. Successful
pages remain available when a later page fails or a budget truncates collection.

`metadata.source_requests` records request IDs, endpoint/method/scope, safe
query/body fields, time, attempts, HTTP status, outcome and safe error metadata.
Collections name their `source_requests`; items have `_provenance` linking
listing and detail request IDs. `_coverage[field]` records detail-read outcomes,
and failed fields contain `{collection_status,error}` so pure checks can return
UNKNOWN/DENIED. A collected bucket does not imply its IAM policy was readable.
`_relationships` records explicit native references and their source field,
without asserting reachability or effective IAM access.

`native_id` and `_resource_id` are complete resource identities; the native
provider `id` remains unchanged. Cross-project and cross-zone names are distinct.
The engine includes scope and type in its final graph/resource identifiers.
Trusted boundary metadata is copied from explicit `trusted_scope_ids` and
`trusted_domains` options for offline analysis.

## Validation

Run the acceptance fixtures with:

```sh
python3 -m pytest tests/test_peaso_collectors_gcp.py -q
```

Fixtures cover authentication source selection/success/failure, account pinning,
delegated credentials, page/query preservation, request deduplication, retries,
limits, disabled APIs/permission denial, cross-project/zone collisions,
restriction/ancestry/Shared VPC boundaries, native service coverage, hydration
gaps and secret-value suppression. They never create cloud resources.

On 2026-10-10, a real read-only attempt selected the current gcloud account and
project `gcp-labs-ly3gvnn7`, requesting only global network metadata with
`max_calls=2`, `max_pages=1`, `retries=0`, `timeout=5`, `concurrency=1` and
inheritance disabled. The attempt produced `denied/gcloud_auth_failed` because
the selected CLI login required reauthentication; provenance recorded zero HTTP
attempts and one credential/request attempt. No fixture or API enablement was
performed, and no alternate identity was attempted. A successful live service
read must be repeated after that selected identity is refreshed; this attempt
does not establish live service coverage.

## Reviewed native checks

`peaso.checks.gcp_extended` adds 33 pure checks for explicit VM security and
availability configuration, declared identity/OAuth scope, SSH/serial metadata,
project OS Login 2FA, subnet/backend logging, storage versioning/soft deletion/
lifecycle/log destinations, primary SQL availability/CMEK and version-specific
database flags, symmetric KMS rotation/public policy, and BigQuery default
encryption/declared public ACL. Checks perform no API calls and do not mutate
input. KMS scheduling assessments use the immutable item collection timestamp,
not the wall clock at report reevaluation.

`peaso/rulepacks/reviewed_gcp.json` records exact upstream IDs, review rationale,
official provider documentation and applicability notes for the pinned Prowler
revision in `sources.json`. Twenty-two source associations are ported; eleven
remain pending with `related_native_checks` because their semantics differ.
These pending associations include a backend predicate without the upstream
frontend join, a per-network predicate without complete project-wide absence,
GKE name-based exemptions, purpose/time-bounded KMS predicates, ephemeral-disk
applicability, metadata default/case handling, and structured BigQuery
principals/encryption rather than upstream substring/truthiness tests. Related
checks do not establish upstream/framework support or certification.

Missing, malformed and denied resource/detail facts yield UNKNOWN. Explicit
read-replica/engine/key-purpose exclusions yield NOT_APPLICABLE. GKE naming
hints that could describe intentional forwarding/multiple interfaces/default
identities yield MANUAL rather than inferred permission or reachability claims.
SQL flags absent from metadata remain UNKNOWN: database-version defaults are
not guessed. A declared conditional KMS public binding is reported as a public
member configuration with its condition preserved, without an effective-access
claim. Run extended acceptance tests with:

```sh
python3 -m pytest tests/test_peaso_checks_gcp_extended.py -q
```

## Native GCP Storage, OS Config and KMS evidence

Storage public-access controls inspect literal public grants. Enforced public access prevention never masks raw public grants. Complete bucket and object ACL metadata, all versions/pages, actual bucket/root IAM policies and complete verified hierarchy are required. Object names and private ACL identities are hashed; object contents are never read. Uniform bucket-level access disables ACLs only when explicitly reported by the provider. Managed folders, hierarchical namespaces, conditional/custom public grants and incomplete sources remain UNKNOWN.

KMS uses complete verified project/folder/org policies plus key-ring/key policies, actual IAM roles.get permissions, and the native v3beta Policy Troubleshooter to resolve direct unconditional user/service-account cryptographic use, including deny and principal access boundary policies. Groups, public/domain/federated principals, conditional cryptographic grants, unknown access decisions and denied or incomplete sources remain UNKNOWN. Native v3 is insufficient because it excludes principal access boundary evaluation. The only new POST endpoint allowed is the read-only `https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot`. Role resolution is bounded to 128 distinct roles per project and 256 candidate principals per key, in addition to shared HTTP/resource/deadline limits.

Live account validation for these batches is blocked by interactive GCP reauthentication. No credentials were changed, no replacement service-account credentials were used, and no cloud resources were created. API-shaped collection-to-engine tests verify positive, negative, denial, partial and foreign-identity paths.

### OS Config evidence boundaries

Inspected the actual v1 REST discovery schema saved in `osconfig-discovery.json`, and the three frozen SW53 predicates. No guest command, agent installation, or cloud write was performed.

| Required fact | Native field and exact meaning | Safe use |
| --- | --- | --- |
| Latest full inventory observation | `Inventory.updateTime` | Inventory freshness only; not installation or fix publication. |
| Latest vulnerability scan | `VulnerabilityReport.updateTime` | Report freshness only. |
| First detection of CVE on this VM | `VulnerabilityReportVulnerability.createTime` | Detection history only; not CVE advisory publication or vendor fix availability. |
| Inventory item first detection/change | `InventoryItem.createTime/updateTime` | Observation/change history only. |
| Available fix identity | `VulnerabilityReportVulnerabilityItem.availableInventoryItemId` joined to FULL `Inventory.items[id]` | Confirms available package identity; not its publication date. Empty reference means no available fix per the provider, but unsupported cases conservatively remain UNKNOWN here. |
| Linux standard package identity/version | `InventoryVersionedPackage.packageName/version/architecture` | No install or publication timestamp exists in this schema. |
| Windows update publication | `InventoryWindowsUpdatePackage.lastDeploymentChangeTime` | Actual last publication date exists for WUA updates. A future extension can join the exact available WUA inventory item and revision, without using report time. |
| Windows QFE installation | `InventoryWindowsQuickFixEngineeringPackage.installTime` | Actual QFE install date exists. Cannot substitute this subset for all installed packages. |
| Windows application service date | `InventoryWindowsApplication.installDate` | Last service/repair date; not a universal original installation date. |
| Enabled patch deployment | `PatchDeployment.state` ACTIVE or PAUSED | Real API state; never invented `enabled` property. |
| Recurrence bounds | `RecurringSchedule.startTime/endTime/nextExecuteTime` | Proves active configured recurring schedule; not successful package installation. |
| VM targeting | `PatchInstanceFilter` | Actual `all` or explicit `instances` supported; other criteria remain UNKNOWN in this stage. |

The two vulnerability checks now have a concrete native PASS path: full current supported OS inventory and a current empty vulnerability report. The critical-only check can also ignore known noncritical findings. A nonempty relevant Linux vulnerability remains UNKNOWN because the predicate requires fix publication age. No report timestamp supplies that missing fact.

The patch-deployment check now has concrete native FAIL paths: current inventory plus a complete empty schedule roster, or only paused/expired/explicitly nonmatching supported schedules. A matching enabled schedule remains UNKNOWN when the package install times required by the second predicate are absent.

Feasible further read-only sources:

* Windows: extend FULL inventory normalization for actual WUA and QFE records, preserving package kind, update ID/revision, and complete package universe. Join the vulnerability's exact available inventory ID to WUA `lastDeploymentChangeTime`; QFE `installTime` proves only the specific installed QFE record. Unsupported mixed package kinds must stay UNKNOWN.
* Linux fix publication: ingest an authoritative vendor advisory/package feed that explicitly ties distro release, architecture, fixed version and release/publication date to the exact package referenced by the OS Config report. A CVE's NVD publication date by itself does not establish when a vendor fix became available. Missing exact version/date joins stay UNKNOWN.
* Linux installation: ingest an already-existing owner-provided inventory/export containing package-manager installation events with retained provenance and completeness. RPM databases can contain package install epochs; Debian status metadata alone generally cannot prove full installation history, and rotated/incomplete logs must not close the age check. This stage does not execute commands or deploy software inside VMs.

Primary schema references:

* https://osconfig.googleapis.com/$discovery/rest?version=v1
* https://docs.cloud.google.com/compute/docs/osconfig/rest/v1/projects.patchDeployments
* https://docs.cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports
* https://docs.cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.inventories


## Native SBOM metadata for an approved Cloud Run subset

The SBOM path reads Artifact Registry Docker-image metadata and Container Analysis `SBOM_REFERENCE` occurrence metadata. An explicit owner review selects the Cloud Run services whose deployed images are in scope; it supplies neither image digests nor SBOM observations. Hosted intake stores the review in encrypted connector input, and the worker reconstructs and validates the same collector options.

```json
{"sw52":{"status":"collected","scope":"projects/example-project","sbomCloudRunServices":["projects/example-project/locations/us-central1/services/example-service"]}}
```

Put this declaration directly in connector `options.sw52`, not `compliance_policy`. The actual selected project scopes must equal the single declared project. The collector joins each approved service's observed generation and serving or tagged revisions to a ready native Cloud Run v1 revision and its resolved `status.imageDigest`, then matches repository/image identity and SBOM occurrence metadata. Calls use literal registered regional metadata endpoints and bounded field masks.

Coverage is explicitly limited to the owner-approved service subset; it never implies that every workload in the project has an SBOM. Missing review, foreign project, unresolved traffic or digest, multiple containers, non-ready revision, inaccessible or incomplete inventories and unsupported image formats remain UNKNOWN. Container commands, environments, image layers, SBOM document contents and secret values are not fetched.
