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

## Local scanner versions

Use Kingfisher `1.4.0` (`kingfisher-secret-scanner` Python package), TruffleHog
`3.92.5`, and Trivy `0.68.1`, matching the worker image and the reviewed detector
contracts. Put the matching TruffleHog and Trivy executables on `PATH`; keep a
separate directory for them if other applications need newer versions. An
unavailable or different secret-detector version leaves clean coverage unresolved.
Trivy also requires a complete, fresh database; see the image setup below.

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
| Exact selected Synapse published notebook source cells | Subscription/workspace ARM reads and separate Synapse RBAC `Microsoft.Synapse/workspaces/artifacts/read`, such as scoped Synapse Artifact User. The existing principal needs a `https://dev.azuresynapse.net` audience token. ARM Reader alone cannot read the notebook. [Exact selector and limits](peaso-azure-synapse-notebook-secrets.md). |
| Log Analytics or Application Insights message samples | Selected resource metadata and scoped query read access; ARM Reader alone does not necessarily authorize message queries. Fixed preceding-hour window and at most100 rows total. [Exact actions, data roles and token audiences](peaso-azure-selected-log-samples.md). |
| ML environment inline Conda text, selected build Dockerfile and associated selected code file | Environment/version/workspace metadata reads; selected Dockerfile also needs datastore/storage-account metadata and separately scoped Blob content access. Code also needs code-version/datastore/storage metadata plus Blob/File content access. Stored datastore credentials are not read or used. ARM Reader alone does not grant Blob contents. [Exact selectors, actions and limits](peaso-azure-selected-ml-assets-secrets.md). |
| Machine Learning Command-job literals | Exact subscription/workspace/job ARM read permissions, included in Reader. No source download or execution permissions. [Exact job selectors and limits](peaso-azure-selected-ml-secrets.md). |
| Exact Databricks notebook SOURCE export | Existing Entra principal already assigned to the selected workspace, notebook CAN READ/CAN VIEW and required workspace API authorization. ARM Reader alone is insufficient; no admin-onboarding fallback is used. [Exact selectors, audience and private access](peaso-azure-databricks-notebook-secrets.md). |
| Exact Databricks workspace FILE RAW export | `Microsoft.Resources/subscriptions/read` and `Microsoft.Databricks/workspaces/read` for native ARM binding; the same existing Entra principal needs Databricks workspace API `workspace` scope and CAN READ/CAN VIEW on the selected file and parent folders. ARM Reader does not grant file access. [Selector, audience and bounds](peaso-azure-databricks-notebook-secrets.md#exact-selected-workspace-file-extension-az-6-candidate). |
| Exact Databricks terminal task output or log sample | `Microsoft.Resources/subscriptions/read` and `Microsoft.Databricks/workspaces/read` for ARM identity; existing workspace principal with Jobs API `jobs` scope and CAN VIEW on the selected job for results. Job run log visibility may require CAN MANAGE RUN and compute log access. ARM Reader alone cannot read task output. [Exact selector and limits](peaso-azure-databricks-notebook-secrets.md#exact-selected-terminal-task-run-result-or-logs-az-6-candidate). |

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

Image vulnerability scanning uses an available local Trivy executable and a complete fresh local database, separately from Kingfisher/TruffleHog secret detection. A missing or stale database leaves a clean image result unresolved. No Snyk authentication is required.


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


## Additional explicitly selected AWS content readers (2026-10-21)

These optional checks require both a named check and exact selected targets. The general metadata role does not grant arbitrary source or artifact reads. Grant only the selected resources; the collector never creates workloads or validates leaked credentials.

- **ECS environment files:** exact task-definition revision and container plus the selected S3 object. See [ECS environment-file setup](aws-ecs-selected-environment-file-setup.md).
- **Workload source:** Glue scripts, EMR and EMR Serverless references, HyperPod lifecycle scripts, and SageMaker script-mode training archives. The training profile additionally requires `sagemaker:DescribeTrainingJob` on the selected training-job ARN. All profiles need the documented selected S3 object access; encrypted objects may need `kms:Decrypt` on that key. See [workload source setup](aws-workload-referenced-source-setup.md).
- **Build/deployment source and artifacts:** selected CodeBuild, CodePipeline, Elastic Beanstalk, and Amplify native references plus their exact S3 objects. See [build/deployment setup](aws-build-deployment-referenced-source-setup.md). Selecting a service does not authorize every object in its artifact bucket.
- **Public registry images:** `ecr-public:DescribeRegistries`, `ecr-public:DescribeRepositories`, and `ecr-public:DescribeImages`, with exact selected account/active alias/repository/immutable digest. No registry token is forwarded. See [ECR Public image setup](aws-selected-ecr-public-images.md).

Image vulnerability checks use Trivy HIGH/CRITICAL results. A stale or unavailable vulnerability database cannot establish a clean result; supported positive findings remain visible. Secret checks use Kingfisher and TruffleHog and merge matching secret fingerprints rather than reporting one leak twice.


## Selected content setup for the additional provider readers

Each row below needs the exact named check, the matching default-off flag, an explicit connector scope, and the stated selector **before credentials are used**. Selector objects contain resource identities and immutable references only. Put bearer tokens, registry passwords and Kubernetes CA material in the connector's encrypted **authentication** document, never in options. These reads do not authorize execution, secret-store value access, registry writes or broad discovery. A clean result with denied, changed, truncated or unsupported content remains unresolved; a verified secret hit remains visible when later content is incomplete.

| Provider and selected content | Required selector and named check | Additional read access and boundary |
| --- | --- | --- |
| AWS ECS environment file | `selected_aws_ecs_environment_files` with `aws.review.ecs.selected_environment_file_secret_indicators`; pair each exact task revision/container/S3 `.env` ARN with its `selected_aws_s3_sources` text object and set `content_secret_scans: true`. | `ecs:DescribeTaskDefinition`, `s3:GetBucketLocation` and exact-object `s3:GetObject`; selected SSE-KMS data may need key-scoped `kms:Decrypt`. No task launch or S3 listing. |
| AWS workload source, including SageMaker training | `selected_aws_workload_sources` with `aws.review.workload.referenced_source_secret_indicators`, plus the same exact `selected_aws_s3_sources` object and `content_secret_scans: true`. For `sagemaker_training_script`, supply `training_job_arn`, `source_s3_uri` ending `.tar.gz`, and a relative `.py` `program` inside that archive. | Grant the selected native read action (`glue:GetJob`, `emr-serverless:GetJobRun`, `elasticmapreduce:DescribeStep`, `sagemaker:DescribeCluster`, or `sagemaker:DescribeTrainingJob`) and selected S3 bucket/object reads. No data-input or image inference. [Exact profiles](aws-workload-referenced-source-setup.md). |
| AWS build or deployment source/output | `selected_aws_build_deployment_sources` with `aws.review.build_deployment.referenced_source_secret_indicators` and `content_secret_scans: true`. S3 profiles require matching `selected_aws_s3_sources`; `codebuild_codecommit_source` instead requires exact `build_arn`, `repository_arn`, `commit_id`, and `file_path`. | Grant the matching `codebuild:BatchGetProjects`, `codebuild:BatchGetBuilds`, `codepipeline:ListActionExecutions`, `elasticbeanstalk:DescribeApplicationVersions` or `amplify:GetJob`. S3 profiles need selected S3 reads; the CodeCommit profile needs `codecommit:GetRepository` and `codecommit:GetFile` on the selected repository. [Exact profiles](aws-build-deployment-referenced-source-setup.md). |
| AWS selected private ECR workload image | `selected_aws_workload_image_secrets` with `aws.review.workload.selected_image_secret_indicators` and `content_secret_scans: true`, or `selected_aws_image_vulnerabilities` with `aws.review.ecr.selected_image_vulnerabilities` and `image_vulnerability_scans: true`; name the check and select the exact account/Region and at most four workload targets: ECS task revision/container or Batch job revision/profile with repository and immutable parent digest, or a Lambda function ARN whose resolved image remains single-platform. A direct ECR vulnerability target selects one repository and immutable parent digest without a workload declaration. | The reader uses `sts:GetCallerIdentity`, `ecs:DescribeTaskDefinition` or `batch:DescribeJobDefinitions`, `ecr:BatchGetImage`, and `ecr:GetDownloadUrlForLayer`. The current generic customer role has the ECS and Batch describe actions on `Resource: "*"` but intentionally omits ECR content reads; add a separate opt-in companion grant for the two ECR actions on each selected `arn:${Partition}:ecr:${Region}:${Account}:repository/${Repo}`. No registry login, ECR push or unselected repository read is needed. |
| AWS selected ECR Public image | `selected_aws_ecr_public_images` with `aws.review.ecr_public.selected_image_secret_indicators` or `aws.review.ecr_public.selected_image_high_vulnerabilities` and the matching `content_secret_scans` or `image_vulnerability_scans` flag. Select at most two exact digest images. | `ecr-public:DescribeRegistries`, `DescribeRepositories` and `DescribeImages` on the selected registry/repository; OCI bytes are anonymously read from `public.ecr.aws` without a registry credential. [Public image setup](aws-selected-ecr-public-images.md). |
| GCP Cloud Run worker pool | `selected_cloudrun_worker_pool_revision_images` with `gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators` and `content_secret_scans: true`: exact pool/revision names and UIDs, container index and digest reference, at most four. | `run.workerpools.get`, `run.revisions.get`, `resourcemanager.projects.get`, `artifactregistry.repositories.get`, `artifactregistry.dockerimages.get` and `artifactregistry.repositories.downloadArtifacts` on selected resources. The selected positive split and declared revision do not prove running instance bytes. [Setup](gcp_workerpool_selected_image_setup.md). |
| GCP Developer Connect file | `selected_developerconnect_files` with `gcp.review.developerconnect.selected_repository_file_secret_indicators` and `content_secret_scans: true`: exact link name/UID, public provider clone URI, immutable commit, relative path and Git blob SHA, at most four. | `developerconnect.gitRepositoryLinks.get`, `developerconnect.gitRepositoryLinks.fetchReadToken`, `resourcemanager.projects.get`, and repository read permission at the matching GitHub, GitLab.com or Bitbucket Cloud provider. Enterprise hosts, branches and tags remain unresolved; no Secret Manager payload read or clone. [Setup](gcp_developerconnect_selected_file_setup.md). |
| GCP Cloud Build stored log | `selected_cloudbuild_builds` with `gcp.review.cloudbuild.stored_log_secret_indicators` and `content_secret_scans: true`: exact selected build names, at most four. | `resourcemanager.projects.get` and `cloudbuild.builds.get`; for `CLOUD_LOGGING_ONLY`, `logging.logEntries.list` on the selected project (the reader uses read-only `POST /v2/entries:list`). For a GCS log object, `storage.buckets.get` and exact-object `storage.objects.get` are also needed. No log write or build execution permission. |
| GCP GKE Pod image | `selected_gke_pod_images` and `selected_registry_hosts` with `gcp.review.gke.selected_pod_image_secret_indicators` or `gcp.review.gke.selected_pod_image_high_vulnerabilities` and matching `content_secret_scans`/`image_vulnerability_scans` flag. Exact cluster, Pod UID/resourceVersion, container and digest are required. | `container.clusters.get`; separately authorized Kubernetes `get` on `namespaces/kube-system` and the selected Pod; selected repository manifest/blob pull rights. GCP IAM alone does not authorize Pod or registry reads. |
| GCP standalone Artifact Registry vulnerability image | `selected_gcp_registry_image_vulnerabilities` with `gcp.review.artifact_image.selected_image_vulnerabilities` and `image_vulnerability_scans: true`: exact project, repository and immutable digest. | `resourcemanager.projects.get`, `artifactregistry.repositories.get`, `artifactregistry.dockerimages.get` and `artifactregistry.repositories.downloadArtifacts` for manifest, config and layer bytes. Repository metadata alone cannot pull blobs. [Setup](gcp-portable-test-setup.md). |
| GCP App Engine Flex version image | `selected_appengine_flex_version_images` with `gcp.review.app_engine_flex.selected_version_image_secret_indicators` or `gcp.review.app_engine_flex.selected_version_image_high_vulnerabilities` and matching opt-in flag. Select at most four exact version names and same-project SHA256 image references. | `appengine.versions.get`, `resourcemanager.projects.get`, `artifactregistry.repositories.get`, `artifactregistry.dockerimages.get` and `artifactregistry.repositories.downloadArtifacts`. Mutable tags and running instance bytes remain unresolved. |
| Azure AKS Pod image | `selected_azure_aks_pod_images` and `selected_registry_hosts` with `azure.review.aks.selected_pod_image_secret_indicators` or `azure.review.aks.selected_pod_image_high_vulnerabilities` and matching opt-in flag. Select the exact ARM cluster, Pod UID/resourceVersion, container and digest, at most four. | ARM selected cluster read plus separate namespaced Kubernetes Namespace/Pod `get` and repository manifest/blob pull rights. `auth.aks_workloads` supplies the selected encrypted cluster bearer context; optional `auth.registry_auth` supplies exact repository credentials. ARM Reader alone is insufficient, and Arc image bytes remain unresolved. |
| Azure ML environment build Dockerfile | Add exact `datastore` and `storage` to an environment-version entry in `selected_azure_ml_environment_versions`; name `azure.review.machine_learning.selected_environment_conda_secret_indicators` and set `content_secret_scans: true`. The declared `build.contextUri` and `dockerfilePath` must bind that exact object. | Subscription, workspace, environment version, datastore and storage-account ARM reads plus exact Blob data read (`Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`, such as container-scoped Storage Blob Data Reader). File sources need their documented File data permission. ARM Reader cannot read Blob bytes. [Asset setup](peaso-azure-selected-ml-assets-secrets.md). |
| Azure ML selected code file | `selected_azure_ml_code_files` with `azure.review.machine_learning.selected_code_file_secret_indicators` and `content_secret_scans: true`: one exact file from a selected code version and datastore; optional exact Command job binding. | `Microsoft.Resources/subscriptions/read`, `Microsoft.MachineLearningServices/workspaces/read`, `Microsoft.MachineLearningServices/workspaces/codes/versions/read`, `Microsoft.MachineLearningServices/workspaces/datastores/read`, and `Microsoft.Storage/storageAccounts/read`; add `Microsoft.MachineLearningServices/workspaces/jobs/read` when binding a job. Blob content needs container-scoped Storage Blob Data Reader (including `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`); Azure Files needs Storage File Data Privileged Reader at the selected share. [Asset permissions](peaso-azure-selected-ml-assets-secrets.md). |
| Azure Flex configured deployment container | `selected_azure_flex_deployment_containers` with `azure.review.function.configured_deployment_container_archives_secret_indicators` and `content_secret_scans: true`: exact Function site, owned storage account and container, at most two. | `Microsoft.Web/sites/read`, `Microsoft.Storage/storageAccounts/read` and container-scoped Storage Blob Data Reader for bounded list and ZIP HEAD/GET. This inspects configured container archives, not a proven active package. |
| Kubernetes immutable Pod image | `selected_k8s_registry_images` and `selected_registry_hosts` with `k8s.review.selected_registry_image_secret_indicators` or `k8s.review.selected_registry_image_high_vulnerabilities` and its corresponding opt-in flag. Select the exact cluster, namespace, Pod UID/resourceVersion, container and `@sha256` image, at most two. | Namespaced `get` on the selected Pod and selected repository manifest/blob pull rights. `auth.registry_auth` may hold repository-scoped credentials; no Kubernetes Secret or node access is needed. |
| Kubernetes Flux artifact | `selected_k8s_flux_artifacts` with `k8s.review.selected_flux_artifact_secret_indicators` and `content_secret_scans: true`: exact GitRepository/HelmChart UID, generation, artifact revision/path/size/digest and source-controller Service UID/port, at most two. | Namespaced `get` on the selected `source.toolkit.fluxcd.io` `gitrepositories` or `helmcharts` object, core Service `source-controller`, and its core `services/proxy` subresource. The artifact is read through the authenticated Kubernetes API Service proxy, not through a user-supplied URL; no Git clone or source-controller Secret read. |

For GKE, supply `auth.gke_image_kubernetes` entries with exactly `cluster_id`, `server`, `ca_cert_data`, and `token`. The server and CA must match the native GKE cluster response; private endpoints are unsupported by this reader. For AKS, `auth.aks_workloads` uses the same explicit context fields and must bind the ARM cluster endpoint. For GKE, AKS and plain Kubernetes image pulls, optional `auth.registry_auth` entries use `{host, repository, method: "bearer", token}` or `{host, repository, method: "basic", username, password}`; these are encrypted connector credentials, never option fields. Anonymous pulls require no entry. Trivy checks require an existing executable and complete fresh local vulnerability database for a clean result.
