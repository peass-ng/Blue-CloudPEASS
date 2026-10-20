# Cloud Run v2 Job declared immutable image proposal

This new-only collector proposal is unregistered and default off. It adds no runtime hook, check, inventory registry, canonical evidence, ledger, progress entry, or UI behavior. Its source is `peaso/collectors/gcp_cloudrun_v2_job_declared_images_20261020.py`; the receipt and focused tests use the same basename. Existing accepted source files are read without edits.

The supported result concerns **bytes of an explicitly declared immutable image** in one selected Job configuration. The native v2 Job has `name`, `uid`, and an execution template containing a task template. Container names and images occur at `/template/template/containers/<index>/image`. Those fields describe configuration; they do not expose each container's executed or resolved runtime digest. `observed_runtime_digest` remains null, `runtime_association_status` remains UNKNOWN, and `deployed_bytes_proven` remains false for every outcome. This follows the [Job schema](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs), [TaskTemplate schema](https://docs.cloud.google.com/run/docs/reference/rest/v2/TaskTemplate), and [Container schema](https://docs.cloud.google.com/run/docs/reference/rest/v2/Container), browsed on 2026-10-20.

## Exact opt-in and scope

Call the standalone function only after an authorized caller has supplied an existing native GCP transport. This proposal does not add a connector option or public engine selection. The default call performs no I/O; only the literal boolean `enabled=True` enters the reader.

```python
from peaso.collectors.gcp_cloudrun_v2_job_declared_images_20261020 import collect_declared_images

# Independent operator selection; replace all identity placeholders before use.
selection = {
    'api_version': 'run.googleapis.com/v2',
    'kind': 'Job',
    'project_id': 'example-project',
    'resource_name': 'projects/example-project/locations/us-central1/jobs/nightly',
    'resource_uid': '<exact native UUID4>',
    'container_name': 'worker',
    'repository': 'projects/example-project/locations/us-central1/repositories/images',
    'digest': 'sha256:<64 lowercase hexadecimal digits>',
    'immutable_reference': 'us-central1-docker.pkg.dev/example-project/images/app@sha256:<same digest>',
}
# Illustrative authorized integration point; not executed by setup or proof.
result = collect_declared_images(
    transport, scope='projects/example-project', selectors=[selection], enabled=True)
```

Selectors are closed dictionaries with exactly these nine fields. One explicit project ID, exact Job name, native UUID4, named container, literal repository, and literal SHA256 image reference must agree independently. At most four distinct Job/container selections are allowed. Select each desired container separately; selecting one container does not claim complete Job, project, service, or all-service coverage. A multi-container Job can associate each named container without assuming list position is identity. Duplicate names, conflicting UIDs, unnamed containers, tags, aliases, implicit hosts, cross-project joins, and additional selector keys fail closed before byte reads.

## Native request and response contracts

Every metadata request is an ordinary streaming HTTPS GET with an empty body, no pagination or provider mutation, and a fixed `fields` parameter. All four are repeated over fresh HTTP after byte inspection; a cache hit is never used for revalidation.

| Read | Exact endpoint | Retained native fields |
| --- | --- | --- |
| Selected Job | `https://run.googleapis.com/v2/projects/PROJECT/locations/REGION/jobs/JOB` | `name,uid,etag,generation,observedGeneration,reconciling,deleteTime,expireTime,template(template(containers(name,image)))` |
| Independent project identity | `https://cloudresourcemanager.googleapis.com/v3/projects/PROJECT` | `name,projectId,state` |
| Independent repository | `https://artifactregistry.googleapis.com/v1/projects/PROJECT/locations/LOCATION/repositories/REPOSITORY` | `name,format,mode,updateTime` |
| Independent DockerImage | same repository endpoint plus `/dockerImages/ENCODED_IMAGE_ID` | `name,uri,mediaType,updateTime` |

The image ID is the exact image path plus `@sha256:...`, percent encoded as one URL segment, including nested-path slashes. The response is a native DockerImage object containing `name` and a literal digest `uri`; it has no invented `repository` or `digest` fields. Those two fields are derived locally only after independent binding. A native decoded name or its single percent-encoded image-ID representation is accepted. The [DockerImage schema](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages), [DockerImage GET](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages/get), [repository GET](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories/get), [Job GET](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs/get), and [project GET](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/get) support these reads and response shapes.

The project response must name a numeric project resource, match the exact selected `projectId`, and be ACTIVE. The repository must match its exact full name and have DOCKER format. Only standard repositories are supported; an absent optional mode is accepted, while explicit unspecified, virtual, remote, and other modes are refused. The repository contract distinguishes these [repository modes](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories#Mode). Job generation and observed generation must be equal positive strings, the etag must be present, `reconciling` must explicitly be false, and no deletion or expiry may be set. Missing required evidence yields UNKNOWN.

After binding, the unchanged native `gcp_image_secret_indicators.Reader` fetches only `/v2/PROJECT/REPOSITORY/IMAGE/manifests/sha256:...` and `/blobs/sha256:...` from the selected registry. It verifies descriptor sizes, SHA256 content, and uncompressed rootfs diff IDs before inspection. These are the [Distribution V2 manifest and blob GET contracts](https://distribution.github.io/distribution/spec/api/). No tag is resolved and no image is executed.

## Read-only access setup

Permissions belong to the **scanning principal**, separately from the Cloud Run execution service account. Reading a Job is not proof of registry pull access. An administrator can arrange the following access through their normal process; this proposal contains and executes no IAM changes:

| Scope | Permission needed |
| --- | --- |
| Exact selected Job | `run.jobs.get` |
| Exact project identity | `resourcemanager.projects.get` |
| Exact Artifact Registry repository | `artifactregistry.repositories.get` |
| Selected DockerImage metadata in that repository | `artifactregistry.dockerimages.get` |
| Manifest/config/layer bytes in that repository | `artifactregistry.repositories.downloadArtifacts` |

The official [Cloud Run IAM reference](https://docs.cloud.google.com/run/docs/reference/iam/roles) includes Job GET in Cloud Run Viewer, and [Artifact Registry IAM](https://docs.cloud.google.com/iam/docs/roles-permissions/artifactregistry) lists metadata and download permissions in Artifact Registry Reader. A repository-level `roles/artifactregistry.reader` grant is a predefined read-only alternative to a narrower custom permission set; it grants more read operations than this proposal uses. No writer, owner, administrator, service-agent, secret-accessor, runtime invocation, or source-deployment role is needed. The [Artifact Registry access-control guide](https://docs.cloud.google.com/artifact-registry/docs/access-control) supports repository-level grants. The DockerImage REST page spells the permission `artifactregistry.dockerImages.get`, whereas the IAM permissions catalog uses canonical lowercase `artifactregistry.dockerimages.get`; use the IAM spelling when configuring a custom role.

The existing transport supplies an already-authorized OAuth access token. Job GET documents the `cloud-platform` OAuth scope; IAM still bounds its permissions. Artifact Registry and project GET also document read-only scopes. Registry requests reuse the native reader's `oauth2accesstoken` Basic username and in-memory token password, as documented in [Artifact Registry token authentication](https://docs.cloud.google.com/artifact-registry/docs/docker/authentication). Setup and proof never generate or refresh real credentials, configure Docker, authenticate to GCP, or contact live cloud APIs. A later denied metadata or byte read remains incomplete; a successful metadata GET never substitutes for a successful byte GET.

## Bounds, findings, and cleanup

The adapter permits at most 32 metadata GETs, 32 KiB per metadata body, 1 MiB total metadata, 10 seconds per HTTP timeout, and a 180-second shared operation deadline. The unchanged native image reader imposes a 120-second content deadline, 64 registry GETs total, and 64 MiB total transferred image bytes across at most four selections. All calls also consume the existing transport's global call budget and honor cancellation. Limits may cause later selections to remain UNKNOWN.

Per image: one Linux amd64/arm64 OCI or Docker v2 single-platform manifest, at most 16 layers, a 256 KiB manifest, 1 MiB config, 8 MiB per layer, 16 MiB config/layer descriptors, 32 MiB cumulative expanded bytes, and 2,000 cumulative archive members. SHA256 and descriptor size checks precede scanning. TARs stay in memory; links, devices, archive extensions, nested archives, malformed paths, digest mismatch, and unsupported compression fail closed. Archive filename pseudonyms prevent secret-bearing names entering scanner caches. No filesystem extraction, image daemon, registry writes, secretstore reads, or credential validation occurs. Dedicated HTTP responses and sessions close on success, denial, cancellation, invalid selection, and partial reads.

Both unchanged local adapters run: Kingfisher 1.4.0 SDK detection with no validator/revoker, and TruffleHog 3.92.5 with no verification or updates. PASS requires every selected declaration to revalidate and every supported image byte scan to complete with both detectors. A real redacted positive survives later byte/detector failures and can yield FAIL while `complete` remains false. An earlier incomplete container cannot hide a later valid positive. If metadata changes or revalidation fails, the association remains UNKNOWN; retained `content.byte_status=FAIL` means only that verified bytes contained a finding during the capture. Never turn it into a current runtime association.

`config_engines` retains each config detector's complete/unavailable state. `layer_coverage` separately records complete or unavailable for each attempted layer, preserving incomplete native archive scans and allowing later layers to provide findings. The unchanged native archive scanner does not expose individual engine failure states through `PartialArchive`; this proposal records that limit without inventing detector status or retaining raw exception text.

Every native metadata body has a source-request ID, raw body SHA256, exact method/URL/fields/scope, HTTP attempt count, and retained minimal native capture. Registry receipts come directly from the existing native Reader and bind category/digest/scope. Each row owns only its request IDs. Receipts describe local fixture execution and are not evidence of customer cloud access or cryptographic authenticity of an imported snapshot.

## Unsupported and deferred

Mutable tags, multi-architecture indexes, external/GCR registries, remote/virtual repositories, cross-project aliases, App Engine, execution/task runtime claims, live filesystem state, mounted secret values, current serving state, effective runtime digest, and credentials verification are unsupported. Fresh matching GETs bound one capture interval; they cannot exclude an intervening change that reverted, or prove perpetual image availability. Scanning historical image layers may find bytes removed by a later layer; it is image-layer coverage, not a claim about the final runtime filesystem.

Runtime/engine/public-intake integration, new check registration, canonical evidence acceptance, policy/ledger updates, installed-wheel acceptance, UI copy, broad regression suites, commit/push, and deployment are deferred to the coordinator. The existing service-only image path and pure resolver remain unchanged.

## Focused local reproduction

```sh
.venv/bin/python scripts/verify_gcp_cloudrun_v2_job_declared_images_20261020.py
```

The verifier runs only the new focused test file, requires both real local detector versions, rejects skipped cases, records exact source hashes and before/after equality for unchanged dependencies, and writes a proposal receipt plus a concise proof log. Fixtures are native REST-shaped metadata responses and real in-memory OCI bytes; no authenticated or live cloud requests are made. The receipt is local proposal proof, not admitted all-service runtime coverage.
