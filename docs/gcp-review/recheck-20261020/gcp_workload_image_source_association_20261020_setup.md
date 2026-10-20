# Cloud Run image declaration association, 2026-10-20

The new `peaso/checks/gcp_workload_image_source_association_20261020.py` is an
unregistered pure resolver. It produces a bounded hint for one exact named
container whose native declaration already contains the selected immutable
Artifact Registry SHA256 pull reference. It does not establish runtime image
resolution, current traffic, active execution, repository access, captured image
bytes, secret presence or secret absence. No existing scanner, collector, control
registration, permission policy or receipt was changed.

## Verified Google REST contracts

Primary documentation was opened using browsing on 2026-10-20. Paths below refer
to decoded native REST JSON, not sanitized inventory or Kubernetes objects.

| Native resource | Image declaration path | Resolver evidence label |
| --- | --- | --- |
| Cloud Run v2 Service | `template.containers[].image` | `desired_digest_declaration` |
| Cloud Run v2 Revision | `containers[].image` | `resource_snapshot_digest_declaration` |
| Cloud Run v2 Job | `template.template.containers[].image` | `desired_digest_declaration` |
| Cloud Run v2 Execution | `template.containers[].image` | `resource_snapshot_digest_declaration` |
| Cloud Run v2 Task | `containers[].image` | `resource_snapshot_digest_declaration` |
| App Engine v1 Version, flexible | `deployment.container.image` | Runtime association unsupported; `UNKNOWN` |

The current [Revision](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services.revisions),
[Execution](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs.executions)
and [Task](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs.executions.tasks)
schemas contain container declarations and reconciliation metadata. They do not
declare per-container `containerStatuses[].imageDigest`, top-level `imageDigest`
or Kubernetes `status.containerStatuses[].imageID`. That absence is the basis
for leaving observed runtime resolution unsupported in this resolver.

[Container](https://docs.cloud.google.com/run/docs/reference/rest/v2/Container)
defines `name` and `image`.
[Service](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services)
and [Job](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs)
use nested templates; [TaskTemplate](https://docs.cloud.google.com/run/docs/reference/rest/v2/TaskTemplate)
contains the execution container declarations. The latter reference describes a
single container while exposing a list: accepting a bounded list here only
associates declarations by name and does not assert multi-container job runtime
support or any quota. Revision/Execution immutability does not turn a tag string
into a digest observation. Latest-ready/latest-created pointers and readiness
conditions do not establish per-container resolved digests or serving coverage.

The [Instance](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.instances)
resource does document `containerStatuses[].imageDigest`. This is a separate
resource contract; its status is never transplanted onto Revision, Execution or
Task. Cloud Run v1 singular `status.imageDigest` and Kubernetes Pod `imageID`
also supply no valid v2 multi-container association here. The Kubernetes helper
is not imported because its ownership and Pod status semantics do not apply.

[App Engine Version](https://docs.cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps.services.versions)
documents flexible `deployment.container.image` via `ContainerInfo`, whose
single image URI can include a tag or digest. It supplies no separately observed
runtime digest field. This implementation explicitly returns
`appengine_flexible_runtime_digest_association_unsupported` even when that
declaration contains a digest; it makes no GCR-to-Artifact-Registry mapping.

## Local input and output

Load the exact new file with `importlib.util.spec_from_file_location` and call:

```python
result = resolver.resolve_image_source(selection, native_get_body,
                                       project_id="example-project")
```

Supply one independently selected object, never a list/aggregation:

```json
{
  "api_version": "run.googleapis.com/v2",
  "kind": "Revision",
  "project_id": "example-project",
  "resource_name": "projects/example-project/locations/europe-west1/services/api/revisions/api-00001-xyz",
  "resource_uid": "00000000-0000-4000-8000-000000000001",
  "container_name": "api",
  "repository": "projects/example-project/locations/europe-west1/repositories/workloads",
  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "immutable_reference": "europe-west1-docker.pkg.dev/example-project/workloads/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

This is a synthetic identity example, not a real captured resource. Accepted
kinds are `Service`, `Revision`, `Job`, `Execution` and `Task`. A closed selector
must contain exactly the nine shown fields. The native object must match its
name and UUID4 UID and include a nonempty `etag`, matching positive decimal
string `generation`/`observedGeneration`, and explicit `reconciling: false`.
Missing reconciliation metadata is conservatively `UNKNOWN`, even where a REST
serialization might omit a default value. Deleted/expiring objects and parent
links to another Service/Job/Execution are rejected. No name, project alias,
unnamed-container identity or status identity is inferred.

Every declaration must have a unique DNS-label container name. The selected
container must match the exact pull reference, digest, registry host, project,
repository and image path. The resolver examines at most 16 declarations per
object and accepts image references of at most 512 characters. These are local
resolver bounds. Other containers are not inspected for secrets or runtime
state, and their unselected images do not supply the selected digest.

The supported URI subset is literal lowercase
`LOCATION-docker.pkg.dev/PROJECT/REPOSITORY/IMAGE@sha256:HEX` using a conventional
project ID. Numeric project aliases, domain-scoped IDs, GCR hosts, Docker Hub,
cross-project/cross-registry references, URLs, URI schemes, percent encoding,
query strings, tag-plus-digest syntax, other digest algorithms and mutable tags
remain `UNKNOWN`. A repository configured for immutable tags still needs an
independently captured digest; this resolver performs no tag lookup. Artifact
Registry documents the [name and digest formats](https://docs.cloud.google.com/artifact-registry/docs/docker/names).

Successful output uses `status: ASSOCIATED_DECLARATION` and includes exactly one
`selected_artifact_image_hint.selected_artifact_images` entry, the exact native
resource identity, generation/etag, container name and image JSON pointer. The
hint explicitly requires independent native repository and DockerImage binding.
It is not a fabricated DockerImage inventory row or an instruction to scan
automatically. `runtime_association_status` always remains `UNKNOWN`,
`observed_runtime_digest` is null, `deployed_bytes_proven` and `complete` remain
false, and `content_status` remains `not_inspected` on every path.

The input dictionaries are never modified, and output contains no references to
their mutable containers. Environment values, Secret Manager references,
commands, arguments, labels and annotations are not read or exported. The module
imports only `re`; it has no fetch, authentication, credential discovery,
execution, registry client or secret-scanner dependency.

## Repository permission boundary and remaining evidence

Workload metadata read authority does not establish repository content read
authority. Each hint separately names its repository and the independent
`artifactregistry.repositories.downloadArtifacts` permission used for manifest
and blob reads. It includes `roles/artifactregistry.reader` as an example and
reports access as `not_evaluated`. These contracts are documented in
[Artifact Registry audit logging](https://docs.cloud.google.com/artifact-registry/docs/audit-logging)
and [access control](https://docs.cloud.google.com/artifact-registry/docs/access-control).
No IAM policy is changed or evaluated here.

The existing selected Artifact Registry scanner remains separate. Its project,
repository and DockerImage bindings, authorization, manifest/index/platform
selection and captured digest-verified content evidence must be satisfied on
their own. Generic selected image inspection cannot prove that a named deployed
container used those bytes. No secret check should be registered from these
declaration hints; a real native per-container runtime association and captured
bytes bound to that exact resource/container remain outstanding.

The caller must establish native GET request/response provenance, exact API
version, capture time and consistent snapshot selection outside this function.
Matching generations only excludes internally stale status; it cannot detect an
old but internally consistent body or authenticate a fabricated dictionary.
This resolver makes no live collection or project-wide coverage claim.

## Reproduction and collection boundary

Run the finite local pure-module matrix:

```sh
.venv/bin/python -m pytest --noconftest -q tests/test_gcp_workload_image_source_association_20261020.py
```

The matrix covers native declaration paths for all five kinds, single/multiple
containers, reordering and distinct selected container digests/repositories,
mutable and malformed URIs, foreign identity, missing or stale status,
duplicates, wrong native parent links, synthetic aggregation and transplanted
digest status, explicit App Engine unsupported behavior, input immutability,
output isolation and I/O denial.

The dispatch described an earlier global registry import block from a network
router-map source guard. In the current shared workspace, targeted normal
`--collect-only` collected the initial 351 cases, and a separate
`.venv/bin/python -c 'import peaso.checks'` exited 0. No boundary, guard, receipt
or allowlist was edited to obtain that result. This direct-file test does not
import the global registry, and a successful targeted run does not establish
full-suite or registered-check acceptance. The companion source-bound report
records final test results, hashes and these scope limits.
