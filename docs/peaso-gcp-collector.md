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
removed before sealing. Public/internal addresses, references and IAM identities
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
| `instance`, `route`, `router`, `vpn_gateway`, `vpn_tunnel`, `address`, `instance_group` | Global routes and aggregate instance/router/VPN/address/group reads. Includes VM interfaces/access configs, service-account scopes, shielded/confidential configuration and declared network references. Both HA and classic VPN gateways are read. |
| `forwarding_rule`, `backend_service`, `backend_bucket`, `target_proxy`, `url_map`, `health_check` | Aggregate global/regional forwarding rules/backends/maps/health checks and HTTP/HTTPS/TCP proxies; global SSL/gRPC proxies/backend buckets. Backend group and health-check references retain relationships. |
| `shared_vpc` | Compute `getXpnHost` and paged `getXpnResources`; preserve host/service ownership references without traversing unselected host projects. A failed host/resources read is visible coverage evidence. |
| `bucket` | Storage list with full projection plus version-3 bucket IAM. Uniform bucket access, public prevention, ACL metadata, default KMS encryption, logging/versioning/retention configuration. No object listing or object reads. |
| `sql_instance` | SQL Admin instance list: IP configuration, backups, flags, encryption, IAM auth/settings metadata; passwords and certificate material are removed. |
| `gke_cluster` | GKE cross-location cluster list: networks, private/public endpoints, authorized networks, workload identity, shielding, encryption, control-plane and node configuration. Master authentication credential/certificate fields are removed. No Kubernetes data-plane connection. |
| `kms_key_ring`, `kms_key` | KMS locations and per-location key-ring lists, then crypto-key metadata and key IAM. `kms_locations` narrows locations explicitly; rotation, purpose, primary-version state/protection level and references remain metadata. No encrypt/decrypt/export. |
| `log_sink` | Project/folder/organization Logging sinks, destinations and writer identities. Audit-policy evidence is in `iam_policy.auditConfigs`. |
| `secret` | Secret Manager secret list and IAM policy metadata, replication/rotation/encryption configuration. No secret values or version access. |
| `workload_identity_pool`, `workload_identity_provider`, `workforce_pool`, `workforce_provider` | IAM workload/workforce pool/provider metadata including OIDC/AWS trust configuration, attribute mappings/conditions and state. Workforce pools are organization-scoped. |

API paths were checked against Google's live
[Compute discovery document](https://www.googleapis.com/discovery/v1/apis/compute/v1/rest).
In particular, network firewall policies use `aggregated/firewallPolicies`, and
regional HTTP/HTTPS/TCP proxies use their aggregate paths. KMS key rings are
enumerated per location rather than assuming a wildcard key-ring list.

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
