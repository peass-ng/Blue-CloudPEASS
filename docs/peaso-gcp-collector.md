# Native GCP snapshot collector

`peaso.collectors.gcp.collect(connector, requirements=None)` returns the engine's
sealed schema 1.0 snapshot. It reads GCP REST APIs directly using `google-auth`
and `requests`; ordinary configuration checks need no external scanner runtime.
Install the project's `cloud` extra for live collection.

The collector never enables APIs, creates fixtures, changes IAM, or accesses
secret versions, private keys, SQL passwords or Kubernetes credentials. Its
transport permits HTTPS requests to an explicit Google API host list, refuses
redirects and accepts only GET and the read-only POST operations `getIamPolicy`,
`getAncestry` and Logging `entries:list`. Credential libraries can separately
exchange credentials and mint short-lived impersonation tokens.

## Optional secret inspection

Secret inspection is off by default. Enable `content_secret_scans` and explicitly
name each content check; selecting all checks, a category or a framework does not
enable inspection. Kingfisher 1.4.0 and TruffleHog 3.92.5 run offline with credential
verification disabled. Install `.[cloud,secrets]` and make the pinned TruffleHog executable available on `PATH`; unavailable or different versions remain UNKNOWN. Only redacted fingerprints, detector names and locations
are retained, and the same value produces one finding across both detectors.
Unavailable detectors, denied reads or incomplete scans remain UNKNOWN.

The check `gcp.review.function.literal_environment_secret_indicators` inspects
Cloud Functions v2 runtime and build literal environment values before transport
sanitization or caching. It never resolves Secret Manager references. A clean
result applies only to those returned values, rather than all source code or
deployed image layers.

Locally integrated optional checks use these exact IDs:

| Content | Check ID |
| --- | --- |
| Functions runtime/build environment | `gcp.review.function.literal_environment_secret_indicators` |
| VM metadata and startup/shutdown scripts | `gcp.review.instance.literal_configuration_secret_indicators` |
| Instance-template metadata | `gcp.review.instance_template.literal_configuration_secret_indicators` |
| Project common metadata | `gcp.review.project.literal_configuration_secret_indicators` |
| Cloud Run service literals | `gcp.review.cloudrun_service.literal_configuration_secret_indicators` |
| Cloud Run job literals | `gcp.review.cloudrun_job.literal_configuration_secret_indicators` |
| Inline Cloud Build triggers | `gcp.review.cloudbuild_trigger.literal_configuration_secret_indicators` |
| Returned Cloud Build configuration | `gcp.review.cloudbuild_build.literal_configuration_secret_indicators` |
| Bounded application log sample | `gcp.review.logging.application_log_secret_indicators` |
| Explicit Cloud Storage text objects | `gcp.review.storage.selected_object_secret_indicators` |
| Explicit Cloud Storage archives | `gcp.review.storage.selected_archive_secret_indicators` |
| Explicit immutable Artifact Registry images, including native GCR URLs | `gcp.review.artifact_image.content_secret_indicators` |
| Scheduler target literals | `gcp.review.scheduler_job.literal_target_secret_indicators` |
| App Engine deployed source files | `gcp.review.appengine.deployment_source_secret_indicators` |
| Cloud Build produced GCS artifacts | `gcp.review.cloudbuild.artifact_secret_indicators` |
| Cloud Deploy release source archive | `gcp.review.clouddeploy.release_source_secret_indicators` |
| Selected Cloud Source Repository files | `gcp.review.sourcerepo.selected_file_secret_indicators` |
| Selected Cloud Tasks FULL payloads | `gcp.review.cloudtasks.selected_payload_secret_indicators` |
| Selected BigQuery routine definitions | `gcp.review.bigquery.selected_routine_secret_indicators` |
| Cloud Build stored GCS logs | `gcp.review.cloudbuild.stored_log_secret_indicators` |
| App Engine version environments | `gcp.review.app_engine_version.literal_environment_secret_indicators` |
| Deployed Workflows source | `gcp.review.workflow.deployed_source_secret_indicators` |
| Explicit Dataform files | `gcp.review.dataform.selected_file_secret_indicators` |
| Functions resolved source archive | `gcp.review.function.resolved_source_archive_secret_indicators` |
| Composer DAG source files | `gcp.review.composer.dag_source_secret_indicators` |
| Explicit Artifact Registry package files | `gcp.review.artifactregistry.selected_file_secret_indicators` |
| Dataflow job environments | `gcp.review.dataflow_job.literal_configuration_secret_indicators` |
| Batch task configuration | `gcp.review.batch_job.literal_configuration_secret_indicators` |
| Dataproc cluster properties/metadata | `gcp.review.dataproc_cluster.literal_configuration_secret_indicators` |
| Dataproc job literals | `gcp.review.dataproc_job.literal_configuration_secret_indicators` |
| GKE ConfigMap/Pod literals | `gcp.review.gke_workload.literal_configuration_secret_indicators` |
| Composer environment/Airflow configuration | `gcp.review.composer_environment.literal_configuration_secret_indicators` |
| Workbench metadata/scripts | `gcp.review.workbench_instance.literal_configuration_secret_indicators` |

Configuration checks inspect returned literal values before sanitization. They
never follow script URLs, pull repository files or dereference managed-secret
references. Logs cover a bounded 15-minute project query and retain query/window
and message ordinals; they do not claim durable log-entry identifiers or a clean
history. Object inspection needs `selected_gcs_objects`, for example:

```json
{
  "content_secret_scans": true,
  "selected_gcs_objects": [{
    "project_scope": "projects/YOUR_PROJECT",
    "bucket": "YOUR_BUCKET",
    "object": "config/settings.env",
    "generation": "123456789"
  }]
}
```

Include the exact project in scan scopes and select the object check. It requires
native project/bucket ownership evidence and `storage.objects.get`. Only the
explicit generations are read; no object enumeration occurs. Current limits are
10 combined text-object/archive selections, 1 MiB per stored object, 8 MiB per collection
and a shared 30-second deadline. Unsupported binary or unreadable selections remain UNKNOWN.
Use `selected_gcs_archives` with the same fields plus `format` (`zip`, `tar` or
`tar.gz`) and the archive check to inspect bounded regular UTF-8 members without
extracting files; nested archives, links, encryption or exceeded expansion limits
remain UNKNOWN. Object owner
IDs are opaque references to the private selection because paths can contain
secrets.

Image scans require `selected_artifact_images`: 1–4 immutable
`LOCATION-docker.pkg.dev/PROJECT/REPOSITORY/IMAGE@sha256:DIGEST` references in one
explicit project scope. Only supported verified manifests, configurations and
bounded layers are inspected; unsupported registries or image layouts remain UNKNOWN.
No image is started or extracted to disk.

Package-file scans require `selected_artifact_files`: 1–8 objects containing
`project_scope`, canonical full File `name`, expected lowercase hex `sha256`, and
`format` (`utf8`, `zip`, `tar` or `tar.gz`). The selected digest must match both
native File metadata and downloaded bytes. Files are not installed or extracted
to disk. Only standard supported package repositories in the authorized project
are accepted; container images use the separate immutable image selector.

Functions source scans follow only the native immutable resolved Storage source
of a complete supported Functions v2 record, with independent project/bucket
ownership and generation proof. Composer source scans list only its native DAG
prefix and read observed immutable text-file generations. Both reuse bounded GCS
readers, preserve the owning service, and leave unsupported or incomplete source
relationships UNKNOWN; neither proves absence throughout deployed runtime code.

Dataform scans require `selected_dataform_files`, each with `project_scope`, full
`repository` name, exact relative `path` and either a 40-character `commit_sha` or
an explicit full `workspace` name (optionally with a `revision` SHA). This is a
selected-file read, not repository traversal. A workspace read without a revision
is an observation at collection time, not immutable history.

Task and routine inspection requires one explicit project ID scope and 1–8 exact,
unique native resource names per option. Select the corresponding exact check IDs
from the table and provide either or both options:

```json
{
  "content_secret_scans": true,
  "selected_cloudtasks_tasks": ["projects/PROJECT_ID/locations/us-central1/queues/QUEUE/tasks/TASK"],
  "selected_bigquery_routines": ["projects/PROJECT_ID/datasets/DATASET/routines/ROUTINE"]
}
```

The Cloud Tasks reader requests `responseView=FULL` and inspects the selected
HTTP/App Engine task's UTF-8 decoded body and literal headers. A BASIC response,
omitted body, denied or deleted task stays UNKNOWN. It never dispatches, leases
or runs a task, follows its target URL, or resolves OIDC/OAuth references.
The BigQuery reader inspects only `definitionBody` in the selected native routine;
SQL, JavaScript, Python, Java and Scala text are supported. It never runs queries,
calls routines, downloads imported libraries or reads table data. Remote-function
and Spark definitions remain UNKNOWN. Names use canonical project IDs and ASCII
identifier subsets; unsupported names require a future reader extension.

Each native JSON response is capped at 2 MiB and each task body plus headers or
routine definition at 256 KiB. Both readers share a 2 MiB inspected-content budget
and 60-second deadline per collection. Only selected content observed during the
read is covered; no queue/dataset enumeration or historical completeness is
claimed. Omitted, unsupported, oversized, partial or unread content and missing
engines remain UNKNOWN. Resource identities and detector locations are opaque;
content and credential values are not retained.

Generic object/archive selection can inspect a known source archive, DAG or build
artifact. It does not automatically discover every service-to-object relationship,
fetch Git repositories, or claim to cover every source deployment. Permissions
and complete reads are required independently for each selected target.

Dataflow, Batch and Dataproc scans require 1–5 explicit regions through
`dataflow_regions`, `batch_regions` and `dataproc_regions`, or a supported explicit
common `regions` list. They inspect returned literal configuration, not referenced
scripts, JARs or datasets. Dataflow requires the full detail read for each listed
job; its summary alone cannot establish a clean configuration.

GKE requires `selected_gke_clusters`: 1–3 exact
`projects/PROJECT/locations/LOCATION/clusters/CLUSTER` names in the requested
project scopes. Optional `selected_gke_namespaces` maps every selected cluster to
1–5 exact namespace names; otherwise bounded namespace discovery must complete.
The bridge needs both the Google cluster read and Kubernetes RBAC list access to
ConfigMaps/Pods (plus namespaces for discovery). It uses the native public IPv4
endpoint, native CA and existing Google token, without kubeconfig, Secret reads,
exec or mutation. Private-only/inaccessible clusters and native 401/403 remain
UNKNOWN; metadata IAM access alone does not demonstrate workload access.

Composer and Workbench inspect their returned literal maps and inline scripts.
Package specifications and script URLs are inspected as text only; no dependency,
DAG, script URL or notebook file is downloaded by those configuration checks.

With `content-options.json` containing `{"content_secret_scans":true}`:

```sh
hacktricks-cspm scan --provider gcp --scopes projects/YOUR_PROJECT \
  --options-file content-options.json \
  --checks gcp.review.function.literal_environment_secret_indicators \
  --output function-secret-report.json
```

Read-only function metadata permissions must include the relevant Functions
list/get operations. Additional GCP configuration and content surfaces are being
tracked in [the secret-surface review](gcp-review/secret-surfaces.md); a planned
adapter is not implemented coverage.

### Read permissions for optional content scans

Standard metadata collection and optional content reads are separate. Grant the
connector's existing Google identity access to the selected resources, then set
`content_secret_scans: true` and name the exact checks above. IAM permission alone
does not enable a scan. These reader permissions supplement the metadata plan;
location discovery and parent project/bucket/repository reads still need their
normal read permissions. Denied or incomplete reads remain UNKNOWN.

| Selected surface | Actual reads and required permissions |
| --- | --- |
| Private Artifact Registry/GCR images | Repository/DockerImage metadata: `artifactregistry.repositories.list`, `artifactregistry.dockerimages.list` (or `artifactregistry.dockerimages.get` for a direct metadata read); registry `GET /v2/.../manifests/...` and `/blobs/...`: `artifactregistry.repositories.downloadArtifacts`. |
| Artifact Registry package files | File metadata GET and `files:download`: `artifactregistry.files.get`. The reader does not enumerate all package files. |
| Selected GCS text/archives and service-resolved GCS sources | Object metadata GET and generation-pinned media GET: `storage.objects.get`; project/bucket ownership metadata must also be readable. Exact object/archive selectors do not need `storage.objects.list`; Composer DAG prefix discovery does. |
| Function environment/source | Functions v2 list/get: `cloudfunctions.functions.list` / `cloudfunctions.functions.get`; resolved source archives additionally need the GCS reads above. This adapter does not call `generateDownloadUrl` or require `cloudfunctions.functions.sourceCodeGet`. |
| Compute VM/template/project literals | Instance/template list or get: `compute.instances.list` / `compute.instances.get`, `compute.instanceTemplates.list` / `compute.instanceTemplates.get`; project common metadata: `compute.projects.get`. |
| Cloud Run service/job literals | Service/job list or get: `run.services.list` / `run.services.get`, `run.jobs.list` / `run.jobs.get`. Selected serving/tagged service image resolution additionally uses `run.services.get` and `run.revisions.get`, plus registry access above. |
| Cloud Build inline configuration, stored logs and artifacts | Build/trigger list and GET use `cloudbuild.builds.list` and `cloudbuild.builds.get`; stored GCS logs/artifact manifests and bytes additionally need `storage.objects.get`. |
| Application log sample | Logging `entries:list` (read-only POST): `logging.logEntries.list`. The fixed sample excludes audit logs; it is not a scan of all log history. |
| App Engine environments/deployment files | Application/service/version discovery and version GET: `appengine.applications.get`, `appengine.services.list`, `appengine.versions.list`, `appengine.versions.get`; deployment bytes additionally need the GCS reads above. |
| Scheduler targets / Workflows source | Scheduler list/get: `cloudscheduler.jobs.list` / `cloudscheduler.jobs.get`; Workflows list/get: `workflows.workflows.list` / `workflows.workflows.get`. Cloud Tasks task bodies are not scanned by the Scheduler check. |
| Selected Cloud Tasks payloads | Exact task GET `cloudtasks.googleapis.com/v2/projects/.../locations/.../queues/.../tasks/...?responseView=FULL`: `cloudtasks.tasks.get` and `cloudtasks.tasks.fullView`. No queue/task list, lease or dispatch permission is needed. |
| Selected BigQuery routine definitions | Exact routine GET `bigquery.googleapis.com/bigquery/v2/projects/.../datasets/.../routines/...`: `bigquery.routines.get`. No query execution or table-data permission is needed. |
| Selected Dataform files | Repository metadata GET: `dataform.repositories.get`; repository file GET: `dataform.repositories.readFile`; workspace metadata/file GET: `dataform.workspaces.get`, `dataform.workspaces.readFile`. No directory traversal permission is needed for the selected-file reader. |
| Dataflow / Batch / Dataproc literals | Dataflow job list plus `JOB_VIEW_ALL` GET: `dataflow.jobs.list`, `dataflow.jobs.get`; Batch job list: `batch.jobs.list`; Dataproc cluster/job list: `dataproc.clusters.list`, `dataproc.jobs.list`. Referenced scripts, JARs and datasets are not downloaded. |
| Composer / Workbench literals | Environment/instance list or get: `composer.environments.list` / `composer.environments.get`, `notebooks.instances.list` / `notebooks.instances.get`. Composer DAG source additionally needs GCS prefix list and object GET. |
| GKE ConfigMap/Pod literals | Cluster metadata: `container.clusters.list` / `container.clusters.get`; reachable control plane and Kubernetes RBAC `list` on ConfigMaps and Pods, plus `list` on namespaces when discovering them. No Kubernetes Secret contents are requested. |
| Selected Cloud Deploy / Source Repository content | Release GET: `clouddeploy.releases.get`, then GCS object reads; repository metadata GET and read-only Git advertisement/upload-pack: `source.repos.get`. |

For a private Artifact Registry repository, repository-scoped
`roles/artifactregistry.reader` includes the metadata and download access needed
for image inspection; a custom metadata-only role may lack download access.
Use the connector identity, not the scanned workload's service account. The
reader uses its Google access token and does not need Docker, a Docker login or
a Docker credentials file. Only immutable digests in the selected project are
accepted. Native `gcr.io`, `us.gcr.io`, `eu.gcr.io` and `asia.gcr.io` references need
matching Artifact Registry metadata; legacy GCS-backed Container Registry,
external private registries, mirrors, redirects and authentication challenges
remain unsupported. See Google's [Artifact Registry access control](https://docs.cloud.google.com/artifact-registry/docs/access-control),
[Reader role](https://docs.cloud.google.com/iam/docs/roles-permissions/artifactregistry#artifactregistry.reader)
and [file download API](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.files/download).

See the native [Cloud Tasks task GET and FULL view permissions](https://docs.cloud.google.com/tasks/docs/reference/rest/v2/projects.locations.queues.tasks/get)
and [BigQuery routine GET](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/routines/get).
These selected reads also need the existing Resource Manager project GET
(`resourcemanager.projects.get`) to bind the native identity to the chosen scope.

Do not grant Secret Manager payload access, KMS decrypt/sign access, database
password retrieval or Kubernetes Secret reads for leak scanning. Intended secret
stores are excluded. Kingfisher and TruffleHog inspect the selected bytes offline
without testing credentials; a clean result covers only the supported bytes read
within that adapter's bounds.

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

With customer-supplied credentials, `options.all_projects=true` explicitly requests Resource Manager
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
project `example-audit-project`, requesting only global network metadata with
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


### Shared hosted identity: explicit projects only

The shared HackTricks service account requires exact customer project IDs. Empty scopes, wildcards, `all_projects`, `discover_projects`, and hierarchy discovery are rejected by hosted validation and the native collector. Access checks also reject discovery before loading shared credentials. Each selected project must carry this connector's generated approval label; permission checks preserve and verify that label. Discovery remains available with customer-supplied credentials and respects project restriction lists.

Native `gcr.io`, `us.gcr.io`, `eu.gcr.io` and `asia.gcr.io` URLs are supported by the selected image check when Artifact Registry returns the exact image URI and matching native repository/project identity. The reader verifies original-host manifest/config/layer digests. It does not infer aliases or reconstruct legacy storage images; unsupported redirects/challenges remain UNKNOWN.

### Selected Cloud Run service images

With `content_secret_scans: true`, select the exact image secret check and provide `selected_cloudrun_services`, for example `["projects/YOUR_PROJECT/locations/us-central1/services/YOUR_SERVICE"]`. Use one matching explicit project ID scope. You can select up to four services; every positive-traffic and tagged revision is resolved, and the combined explicit/resolved image limit is four. Native service metadata is reread after inspection. Denied, changing or multi-container revisions remain UNKNOWN. No runtime/mounted content or historical revision completeness is claimed.

## Selected Cloud Build stored logs and App Engine deployment files

Both readers require `content_secret_scans: true`, the exact named check from the table,
and one explicit project scope. Supply one to four native names in collector options:

```json
{
  "content_secret_scans": true,
  "selected_cloudbuild_builds": [
    "projects/YOUR_PROJECT/locations/us-central1/builds/YOUR_BUILD_ID"
  ],
  "selected_appengine_versions": [
    "apps/YOUR_PROJECT/services/default/versions/YOUR_VERSION"
  ]
}
```

You can select either reader independently. Cloud Build reads a terminal build's
native GCS log object at its observed generation; this does not prove complete
historical logs or cover a Cloud Logging-only backend. App Engine reads only a
supported standard-environment `deployment.files` manifest and scans files after
their bytes match the native SHA1 values. It does not assess generated artifacts
or runtime contents. Both bind source buckets to the selected project and keep
signed source URLs out of cache and evidence. Missing bindings, unsupported
content, denied reads or exceeded budgets remain UNKNOWN.

For output artifacts, select `gcp.review.cloudbuild.artifact_secret_indicators` and
provide `selected_cloudbuild_artifact_builds`: one or two exact regional Build
names, using the same name format as stored logs. The reader scans only supported
records in the observed native output manifest and their pinned GCS generations;
it does not scan build inputs or infer outputs from requested path globs.

For Cloud Deploy source configuration, select
`gcp.review.clouddeploy.release_source_secret_indicators` and provide
`selected_clouddeploy_releases`, containing one to four exact names such as
`projects/YOUR_PROJECT/locations/us-central1/deliveryPipelines/YOUR_PIPELINE/releases/YOUR_RELEASE`.
It inspects the observed native GCS source tar.gz archive, without rendering or
deploying it. Neither reader attests historical build/release bytes. Both require
content opt-in, one explicit project and native bucket ownership; incomplete,
unsupported or denied reads remain UNKNOWN.

## Selected Cloud Source Repository files

Select `gcp.review.sourcerepo.selected_file_secret_indicators`, one explicit project ID, and these connector options:

```json
{
  "content_secret_scans": true,
  "selected_source_repository_files": [{
    "repository": "projects/PROJECT_ID/repos/REPOSITORY",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "paths": ["config/example.txt"]
  }]
}
```

The commit must be advertised by the repository. The reader checks the native repository identity, reads Git smart HTTP from the fixed Google host, and inspects only the selected regular UTF8 files with offline Kingfisher and TruffleHog. Matching leaks are deduplicated and values remain hidden. No credential validation is performed.

This is read-only: Git uses GET advertisement and POST `git-upload-pack` to fetch objects; it never pushes. Git traffic is capped at 8 MiB, native repository metadata separately at 16 KiB, with one shared 60-second deadline. At most eight files, 256 KiB each and 2 MiB combined, are inspected. Missing, denied, unsupported, partial or failed reads remain UNKNOWN. A negative result says nothing about unselected files or repository history. Current live-provider authentication compatibility has not been tested.

Optional [selected Dataproc referenced-source secret inspection](peaso-gcp-selected-dataproc-sources.md) requires exact source selection and separate object-read permission.

Optional [selected Workbench startup-source secret inspection](peaso-gcp-selected-workbench-sources.md) requires the exact named check, explicit source generation and separate object-read permission; notebook files and cached/executed scripts are excluded.

### Optional selected job source inspection (local)

Selected Dataflow package and Batch mounted-script readers are separate default-off checks. They require exact job/object selectors and object download authorization; the normal literal scans above do not follow these references. See [selectors, read permissions and bounds](peaso-gcp-selected-job-sources.md).

## Selected Cloud Run Job declared images

The optional [Job image reader](peaso-gcp-selected-job-images.md) inspects an explicitly selected immutable Artifact Registry image declared by a Job. Grant `run.jobs.get`, `resourcemanager.projects.get`, `artifactregistry.repositories.get`, `artifactregistry.dockerimages.get` and `artifactregistry.repositories.downloadArtifacts` at the selected scopes. This establishes the desired image declaration, not the image actually executed by a Job. Local native acceptance does not certify deployment.
