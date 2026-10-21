# Optional secret-content inspection

Configuration inventory and content inspection use different permissions. Reading a
resource's metadata does not establish access to its source files, settings or image
layers. Enable `content_secret_scans: true` and explicitly select the relevant content
check and targets. Bulk check selection does not enable content downloads.

Both Kingfisher and TruffleHog run offline. Native snapshots, shared caches, finding
lists and normal report downloads remain redacted. Matching values within a provider
report are merged by the existing exact-value HMAC fingerprint into one leak with
multiple locations. Detection does not test
whether a credential works. Incomplete reads or a missing detector cannot establish
a clean result. Coverage is limited to the selected objects and documented bounds.

## Currently implemented content readers

| Provider | Selected content | Additional read access |
| --- | --- | --- |
| AWS | EC2 user data | `ec2:DescribeInstanceAttribute` for user data, alongside instance inventory. |
| AWS | Lambda function/layer packages | `lambda:GetFunction` or `lambda:GetLayerVersion` and the bounded provider-issued package download. |
| AWS | Explicit Lambda environment literals | `lambda:GetFunctionConfiguration` on selected function ARNs. CMK-protected values can additionally require existing key-scoped `kms:Decrypt` authorization; the reader makes no direct KMS call or grant change. |
| AWS | CodeCommit default-commit files | `codecommit:GetRepository`, `GetBranch`, `GetFolder`, `GetFile` on the selected repositories. |
| AWS | Sampled CloudWatch log messages | `logs:FilterLogEvents` on the selected log groups. |
| AWS | Latest selected ECR image | `ecr:DescribeImages` for image inventory, plus `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` on the selected repositories. This API flow does not require registry login or push permission. |
| AWS | Explicit selected configuration literals (15 surfaces; locally integrated) | Exact selected read operations and scope limits are listed in the [AWS configuration-content table](peaso-aws-collector.md#optional-explicitly-selected-configuration-content-scanning). SSM ownership requires `ssm:DescribeDocument` alongside `ssm:GetDocument`; REST stages use exact `apigateway:GET`. |
| AWS | Exact ECS task-definition / classic Batch job-definition command literals | `ecs:DescribeTaskDefinition` and `batch:DescribeJobDefinitions`; both require `Resource: "*"`. The reader restricts requests to selected ARN revisions and account/Region scopes. [Selectors and limits](peaso-aws-selected-workload-commands.md). |
| AWS | Explicit selected inline CodeBuild buildspec | `codebuild:BatchGetProjects` on the exact selected project ARNs. No build, repository or artifact permission; missing or referenced sources stay undetermined. [Selectors and limits](peaso-aws-selected-codebuild-buildspecs.md). |
| AWS | Explicit selected S3 text object or supported source archive | `s3:GetBucketLocation` plus exact-object `s3:GetObject` or version-scoped `s3:GetObjectVersion`. Existing SSE-KMS key authorization can be necessary; no grants or KMS mutations are attempted. [Exact selectors and limits](aws-selected-s3-source-secret-permissions-20261020.md). |
| GCP | Private Artifact Registry images, including supported GCR-backed images | Repository/image metadata and `artifactregistry.repositories.downloadArtifacts`. `roles/artifactregistry.reader` is a suitable read role; restrict its scope to required repositories. |
| GCP | Immutable image declared by an exact Cloud Run Job container | `run.jobs.get`, `resourcemanager.projects.get`, `artifactregistry.repositories.get`, `artifactregistry.dockerimages.get`, and `artifactregistry.repositories.downloadArtifacts`. Repository metadata access alone does not grant image downloads. [Selectors and permissions](peaso-gcp-selected-job-images.md). |
| GCP | Exact selected Dataflow package or Batch GCS-mounted host script | `dataflow.jobs.get` or `batch.jobs.get`, plus `resourcemanager.projects.get`, `storage.buckets.get` and exact-object `storage.objects.get`. Explicit named opt-in and same-project bucket required; no list or execution permission. [Selectors and bounds](peaso-gcp-selected-job-sources.md). |
| GCP | Exact selected Workbench startup GCS source | `notebooks.instances.get`, `resourcemanager.projects.get`, `storage.buckets.get` and exact-object `storage.objects.get`. Explicit named opt-in and same-project bucket required. [Selectors and limits](peaso-gcp-selected-workbench-sources.md). |
| GCP | Other supported selected content | See the [GCP per-surface permission table](peaso-gcp-collector.md#read-permissions-for-optional-content-scans). Tasks FULL view and BigQuery routine definitions have separate explicit selectors. |
| Azure | Selected App Service/Function literal settings, including supported deployment slots | Site identity read plus `Microsoft.Web/sites/config/list/action`; corresponding slot read/list actions for slots. Assign at selected resource scopes. `Reader` alone is insufficient. |
| Azure | Exact selected configured deployment ZIP (local integration under validation) | Subscription/site/storage-account metadata reads, site-scoped `Microsoft.Web/sites/config/list/action`, and Blob `containers/blobs/read` DataAction, for example Storage Blob Data Reader. ARM and Storage OAuth are required. [Selectors and coverage](peaso-azure-selected-package-sources.md). |
| Azure | Explicit immutable ACR images | Registry identity read plus scoped image pull: `AcrPull` for classic registries or `Container Registry Repository Reader` for ABAC registries. |
| Kubernetes | Selected Pod and workload-template literal env/command/args, plus ConfigMap literals | Namespace-scoped RBAC `get` on only the selected resource names in the core, `apps` or `batch` API group. See the exact kinds and paths below; no list, Secret, log or exec permission is needed for this reader. |

These readers are registered in the source catalog and stay disabled without the required explicit selections.
The [review ledger](check-review/progress.json) records bounded acceptance; availability on a hosted
instance depends on its deployed version. Metadata access does not imply content-read permission.

## Private registry permissions and remaining coverage

AWS ECR and GCP Artifact Registry have bounded content readers. The ECR reader uses
AWS APIs and provider-issued layer URLs; it does not need registry-wide login or
push permissions. GCP image metadata access without repository download permission
is insufficient. See the [AWS](peaso-aws-collector.md) and [GCP](peaso-gcp-collector.md)
provider guides for the exact selection and byte limits.

The local ACR reader inspects explicitly selected immutable SHA256 images and
requires `AcrPull` for registries using classic registry RBAC. For registries using
ABAC repository permissions, use `Container Registry Repository Reader`, with a
condition limiting the selected repositories; `AcrPull` is not honored in that mode.
Repository catalog listing is a separate permission and is unnecessary when exact
repository names are supplied. See Microsoft's [repository permissions guide](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-abac-repository-permissions).

The reader requests a fixed ACR-scoped Entra token through the configured credential.
A connector containing only a pasted ARM token cannot authenticate to a hardened
registry that rejects that audience. Keep the policy hardened and use a credential
able to obtain the ACR audience; do not enable ARM acceptance to make a scan pass.
Unsupported multi-platform indexes, formats and download destinations remain
incomplete. The [native acceptance record](check-review/azure-acr-image-secret-implementation-20261020.json)
does not certify deployed availability or live customer authorization.

## Azure selected ARM configuration and source literals (locally integrated)

The locally integrated check `azure.review.configuration.selected_content_secret_indicators`
inspects ten explicitly selected management-plane surfaces: ACI and Container Apps
public literals, Logic Apps ARM workflow definitions, VM `userData`, VMSS model
`userData`, public VM extension settings, Image Builder inline customizers,
published Automation runbook source, unencrypted Automation variable values and
APIM global/API/operation policy XML. It requires `content_secret_scans: true`,
the exact named check, and 1–8 `{surface, resource_id}` selectors in explicitly
selected subscriptions. See the [Azure exact fields, API versions and read-action
table](peaso-azure-k8s-collectors.md#optional-selected-arm-configuration-and-source-literals-local-proposal).

Use only existing selected-resource read authorization. Automation requires
`runbooks/read` plus `runbooks/content/read`, or `variables/read`, under
`Microsoft.Automation/automationAccounts`; Azure documents Automation account
assignment scope. APIM requires the read action for the selected policy level.
The remaining surfaces use their exact ARM resource `read` action. No write,
credential validation, decrypt, list-secrets or runtime-execution permission is
needed or requested. This does not grant access to protected settings, encrypted
variables, Secret references or external source files.

Both pinned detectors run offline. Empty/masked/binary, malformed, denied,
partial or referenced-only content cannot establish PASS. An independently
observed trusted hit remains FAIL with explicit incomplete coverage. VMSS proof
is model-only; VM `customData` is not recovered; external scripts, inherited
policies and named values are not followed. Opaque locators and union redaction
keep raw content, matched values and selected resource names out of exported
evidence. Local native acceptance is recorded in the review ledger; production
publication remains a separate release step.

## Additional locally integrated Azure content readers

These are default-off. Select the exact content check, set `content_secret_scans`
and supply only the named targets. They use the configured credential; no reader
creates a role assignment or changes a service. The current implementation and
its offline acceptance remain separate from a production release.

| Selected surface | Minimum read access and setup |
| --- | --- |
| Blob/File text or supported source archives | Storage account/subscription metadata plus `Storage Blob Data Reader`, or the documented optional File privileged-read/backup semantics. [Exact selectors, current/versioned reads and limits](peaso-azure-selected-storage-secrets.md). |
| Azure DevOps files and pipeline declarations | Separate authorized organization credentials with Code/Build read scopes. ARM Reader does not authorize DevOps. [Exact commit/revision selectors and permissions](azure-devops-selected-content-secret-permissions.md). |
| App Configuration public key-values | Store metadata plus `App Configuration Data Reader` on the selected store; credential must obtain the `https://azconfig.io` audience. [Setup and selectors](peaso-azure-selected-declaration-secrets.md). |
| Data Factory pipeline/dataflow public literals | Exact pipeline/dataflow ARM read actions, included in ARM Reader. [Supported declarations and exclusions](peaso-azure-selected-declaration-secrets.md). |
| Synapse pipeline public literals | Workspace ARM read plus Synapse RBAC artifact read, such as scoped `Synapse Artifact User`; credential must obtain the Synapse development audience. [Setup and limits](peaso-azure-selected-declaration-secrets.md). |
| Log Analytics or Application Insights message samples | Selected resource metadata and scoped query read access; ARM Reader alone does not necessarily authorize message queries. Fixed preceding-hour window and at most100 rows total. [Exact actions, data roles and token audiences](peaso-azure-selected-log-samples.md). |
| ML environment inline Conda text and associated selected code file | Environment/version/workspace metadata reads; code also needs code-version/datastore/storage metadata plus separately scoped Blob/File content access. Stored datastore credentials are not read or used. File privileged-read semantics are explicitly optional. [Exact selectors, actions and limits](peaso-azure-selected-ml-assets-secrets.md). |
| Machine Learning Command-job literals | Exact subscription/workspace/job ARM read permissions, included in Reader. No source download or execution permissions. [Exact job selectors and limits](peaso-azure-selected-ml-secrets.md). |
| Exact Databricks notebook SOURCE export | Existing Entra principal already assigned to the selected workspace, notebook CAN READ/CAN VIEW and required workspace API authorization. ARM Reader alone is insufficient; no admin-onboarding fallback is used. [Exact selectors, audience and private access](peaso-azure-databricks-notebook-secrets.md). |

Key Vault references, encrypted variables, protected settings and credential
stores are not followed. A clean result describes only the supported selected
content. It does not certify an entire service, image history or runtime.

## Kubernetes selected workload literals

Use the existing check `k8s.review.selected_literals.secret_indicators`, set
`content_secret_scans: true`, and provide `selected_k8s_literal_resources`. Each of
the 1–8 selectors contains exactly `cluster_id`, `namespace`, `kind` and `name`.
All selectors must name one configured cluster and an exact namespace for each target.
The overall scan may select all namespaces (`["*"]`); this never expands the named
content targets. Mixed wildcard scopes, wildcard target namespaces, kind aliases
and unselected objects are rejected.

| Selector `kind` | API group/version | Exact named GET path after the API prefix | Inspected fields |
| --- | --- | --- | --- |
| `Pod` | core `v1` (`/api/v1`) | `/namespaces/{namespace}/pods/{name}` | `spec` container literals |
| `ConfigMap` | core `v1` (`/api/v1`) | `/namespaces/{namespace}/configmaps/{name}` | `data` and supported UTF-8 `binaryData` |
| `ReplicationController` | core `v1` (`/api/v1`) | `/namespaces/{namespace}/replicationcontrollers/{name}` | `spec.template.spec` container literals |
| `PodTemplate` | core `v1` (`/api/v1`) | `/namespaces/{namespace}/podtemplates/{name}` | `template.spec` container literals |
| `Deployment` | `apps/v1` (`/apis/apps/v1`) | `/namespaces/{namespace}/deployments/{name}` | `spec.template.spec` container literals |
| `DaemonSet` | `apps/v1` (`/apis/apps/v1`) | `/namespaces/{namespace}/daemonsets/{name}` | `spec.template.spec` container literals |
| `StatefulSet` | `apps/v1` (`/apis/apps/v1`) | `/namespaces/{namespace}/statefulsets/{name}` | `spec.template.spec` container literals |
| `ReplicaSet` | `apps/v1` (`/apis/apps/v1`) | `/namespaces/{namespace}/replicasets/{name}` | `spec.template.spec` container literals |
| `Job` | `batch/v1` (`/apis/batch/v1`) | `/namespaces/{namespace}/jobs/{name}` | `spec.template.spec` container literals |
| `CronJob` | `batch/v1` (`/apis/batch/v1`) | `/namespaces/{namespace}/cronjobs/{name}` | `spec.jobTemplate.spec.template.spec` container literals |

Container literals mean explicit `env[].value`, `command[]` and `args[]` in the
selected PodSpec, including init containers and Pod ephemeral containers when
present. These strings are scanned as data, never executed or expanded.
`valueFrom` and `envFrom` references are counted but not resolved. A referenced
ConfigMap is inspected only when separately selected; Secrets are never read.
Controller templates do not establish the contents of existing Pods or their
running process environments, and generated workloads are not followed.

For example, an existing namespace Role can restrict access to a selected
Deployment and CronJob with these rules, using the actual selected names:

```yaml
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    resourceNames: ["selected-deployment"]
    verbs: ["get"]
  - apiGroups: ["batch"]
    resources: ["cronjobs"]
    resourceNames: ["selected-cronjob"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["podtemplates"]
    resourceNames: ["selected-podtemplate"]
    verbs: ["get"]
```

Use separate rules for other selected resource kinds and names. This reader needs
no `list`, `watch`, `create`, update, delete, `pods/exec`, `pods/log` or Secret
permission. Other independently selected configuration checks can have different
inventory permissions. Kubernetes documents named-resource restrictions in its
[RBAC guide](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources).

Each selected object is read twice; its exact kind, API version, namespace, name,
UID, resourceVersion and selected literals must agree. There are at most 16 GETs,
2 MiB per response, 8 MiB total response bytes, 256 KiB of extracted content per
object, 512 nonempty supported literals and a 60-second reader deadline. Existing
shared scan budgets can stop the reader earlier. Both pinned offline detectors
must complete for a clean result; denied, changed, malformed, oversized or
incomplete content cannot establish absence of secrets. Raw literal values are
excluded from snapshots and shared result caches; matched values are retained only
in the separate encrypted private evidence described below.
An identity-bound hit from a completed detector remains a failure when the other
runner is unavailable, with coverage explicitly incomplete. Unknown source
identity or incomplete native reads remain unresolved.

Kubernetes API permission to read Pods or workload controllers does not grant access to registry manifests
or image layers. The selected literal reader does not download images or retrieve
`imagePullSecrets`. Private registry inspection needs separately scoped registry
authentication and an implemented image reader; do not grant broad Secret access as
a substitute. Kubernetes describes [private image authentication](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) separately from [API RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

Do not grant Contributor, image push, resource mutation or credential-store payload
access solely to run a secret-content check. Intended Secret Manager, Key Vault and
Kubernetes Secret storage is not a leak merely because it contains a secret.

## Optional selected Kubernetes log samples

The exact named log check and `content_secret_scans: true` require1–4 explicit namespace/Pod/container selections. Add only namespace-scoped `get` on the selected `pods` and `pods/log` resource names; no list, watch, exec, attach, previous-log or Secret permission is needed. [Selectors, RBAC and fixed-window limits](peaso-k8s-selected-log-secrets.md).

### Selected Dataproc referenced source

The two optional Dataproc source checks require `content_secret_scans: true`, exact named check selection and `selected_dataproc_referenced_sources` (1–4 targets combined). Grant `resourcemanager.projects.get`, the applicable `dataproc.jobs.get` or `dataproc.clusters.get`, `storage.buckets.get` and `storage.objects.get` on the selected project/resource/bucket/object. Metadata-only grants do not imply permission to download object contents. No object listing, job execution, cluster change, IAM change or secret-store read is required.

Only the current native reference and coherently pinned captured GCS generation are inspected. This does not prove original executed bytes, dependencies, archives, cross-project sources or whole-job coverage. [Exact selector and permission setup](peaso-gcp-selected-dataproc-sources.md).

### Selected Kubernetes object metadata

The optional `k8s.review.selected_metadata.secret_indicators` check requires `content_secret_scans: true` and 1–8 exact `selected_k8s_metadata_resources` targets. Grant only namespace/resourceNames-scoped `get` for the selected Pod, ConfigMap, PodTemplate, ReplicationController, apps workload, Job or CronJob kinds. It inspects top-level labels and annotations after two coherent native reads, without reading Secret objects, logs, mounted files, registry layers or resolving references. [Exact selectors, native bounds and minimal RBAC](peaso-k8s-selected-metadata-secrets.md).

### Admission configuration stored in a ConfigMap

Use the existing optional selected-literal check for an exact ConfigMap containing
admission YAML; it requires `get` on that ConfigMap, independently of the metadata-only
check above. It scans stored API-visible text with both detectors. It does not require
exec or node access and does not establish which file a process mounted or used.
[Read-only content boundaries](peaso-k8s-readonly-content-boundaries.md).

## Selected workload commands and Job images

- AWS: [ECS and classic Batch command literals](peaso-aws-selected-workload-commands.md), requiring the applicable definition read action. Images and referenced files are separate selections.
- GCP: [Cloud Run Job declared images](peaso-gcp-selected-job-images.md), requiring Job/project/repository/image metadata reads and repository download permission. Metadata-only access is insufficient.

Image vulnerability scanning uses Trivy, separately from Kingfisher/TruffleHog secret detection. Its optional runner is being validated locally; availability in a deployed collector is not yet established. No Snyk authentication is required.


## Full matched values and exact origins in finding detail

Fresh scans retain the actual matched value in a separate encrypted per-scan
secret-evidence artifact. The tenant-authorized individual finding and grouped
finding detail APIs/UI show that full value directly with its observed resource,
original file or archive-member path, native field, source version/commit, and
image manifest/layer digest when those identities were available. File lines are
reported only when they refer to the original inspected text. Configuration JSON
serialization and sampled logs do not establish an original file line; the detail
shows that line as unknown. This includes legacy configuration-pattern and literal
environment-name findings where the collector actually observed a value.
For a detector such as TruffleHog that reports both `Raw` and a complete `RawV2`
credential pair, private detail retains both representations and any exact observed
secret-key component. Each value has its own encrypted record linked to the original
public fingerprint. A detector-composed representation that does not occur verbatim
in the source is explicitly labeled as detector-derived: its scanned input is shown
separately, with no asserted observed native path/field or line. Its verified observed
components retain their actual paths, fields and lines.
Decoded-only matches likewise identify the scanned input without claiming a
literal native path/field or line. Privacy redaction still covers recognized
decoded credential components even when their literal bytes are absent; this
does not turn a detector representation into a literal-source witness.
The collector keeps an encrypted transient scrub set for such components, so
copies in other resource metadata are also removed before snapshot publication.
That scrub set is not a finding witness and is not included in persisted evidence.
References, masked fields and metadata-only findings never supply invented values,
and secret-store references are not resolved. Content inspection still requires
its existing explicit opt-in, named check and exact selectors.

Private evidence uses the deployment's credential encryption key, binds every
value to its tenant and scan, and is not included in native observations, generic
finding/member summaries, public JSON/Markdown report artifacts, normal downloads,
AI prompts or logs. Detail reads require the same tenant authorization as the
finding, including valid tenant API keys; responses use `private, no-store`.
The encrypted evidence object is never presigned or attached to report manifests.
Large private details have bounded pages; use `secret_offset=next_offset` from the
returned `secret_evidence` object. The UI's **Show more matched values and locations**
button loads the remaining pages without truncating a matched value or path.
Deleting the scan/workspace deletes its private artifact with the other scan data.

The CLI includes full values only when explicitly requested in an owned JSON file:

```sh
hacktricks-cspm scan --request request.json --include-secret-values --output private-findings.json
```

This option requires a JSON output file; stdout, Markdown, snapshots and normal
exports remain redacted. The file is created with mode `0600`; matched values are
inside finding observations (or the deduplicated secret detail) with their origins.
The local user who owns that file can read `secret_evidence.matches[].value` and
`secret_evidence.matches[].locations` directly; no hosted API or decrypt command is
required. Grouped findings place these objects under `findings[].observations[]`;
deduplicated secrets also expose them on the finding itself. A locally running web
server offers the same authenticated finding-detail endpoint as the hosted service:
`GET /api/scans/{scan_id}/findings/{finding_id}`. Listing findings does not reveal
values; the caller must retrieve the particular finding detail with a valid local
session or tenant API key. The CLI flag does not recover values from `--snapshot`.
The CLI uses an ephemeral encryption key during collection and does not persist a
separate decryptable evidence store.

A historic scan whose values or original paths were discarded cannot recover them.
Its detail explicitly reports that full values are unavailable and requests a fresh
scan. Capture is bounded to 10,000 distinct values, 50,000 locations, a 64 MiB
tracked witness/alias/scrub budget and 2 MiB per value; encryption and index
serialization add overhead. Exceeding a witness bound marks private capture
incomplete and never presents a truncated string as the full matched value.
If the bounded privacy scrub cannot retain the values needed for complete
redaction, the scan refuses snapshot/report publication rather than publishing
an unsafe partial result.
Detection does not validate whether a credential works.

Workload name checks retain values only from the exact admitted native workload
route, kind, scope and environment field, and only for checks in the requested
category/check/framework selection. Unrelated responses, metadata objects and
unselected name checks are not additional capture surfaces. Each finding detail
joins only its canonical resource/scope/path/layer and check association; a
deduplicated finding can show multiple origins only when its canonical witnesses
explicitly bind them. Ambiguous associations are withheld rather than guessed.
An individual finding cannot use a canonical location that contradicts its resource
or scope. Environment capture reads only immediate native entries, never nested
lookalike fields in entry metadata. The existing custom `secretKeys` policy check
covers both AKS Pods and ACI container groups; selecting it retains only matching
literal names on those native surfaces.
