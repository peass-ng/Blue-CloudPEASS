# Cloud Run Job declared image secret inspection

The exact optional check is `gcp.review.cloudrun_job.declared_image_secret_indicators`, using the `cloudrun_job_declared_image` inventory, high severity, hardening category and existing Secrets group. It inspects bytes of an immutable image declared by a selected named Cloud Run v2 Job container. It does not establish an executed image digest or runtime filesystem state.

The normal scan request must name that check, set `content_secret_scans` to the boolean `true`, and provide `selected_cloudrun_job_declared_images` with 1–4 exact selectors in one explicit project. Default, category and framework selections do not enable this check or its content reads. Discovery, tags, other resource kinds, unnamed containers, duplicate selectors, cross-project images and additional selector fields are rejected before authentication.

```json
{
  "checks": ["gcp.review.cloudrun_job.declared_image_secret_indicators"],
  "connector": {
    "provider": "gcp",
    "scopes": ["projects/review"],
    "options": {
      "content_secret_scans": true,
      "selected_cloudrun_job_declared_images": [{
        "api_version": "run.googleapis.com/v2",
        "kind": "Job",
        "project_id": "review",
        "resource_name": "projects/review/locations/us-central1/jobs/batch-job",
        "resource_uid": "4c03895a-b5b4-4d6c-b8dd-f1979d8f044c",
        "container_name": "worker",
        "repository": "projects/review/locations/us-central1/repositories/images",
        "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "immutable_reference": "us-central1-docker.pkg.dev/review/images/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      }]
    }
  }
}
```

The example identifiers must be replaced with the selected native identities, and authentication uses the ordinary GCP connector. Only the engine creates the internal grant; connector JSON cannot provide it. The collector consumes that grant, bound to the exact scope and selector list, before constructing native credentials or transport. There is no separate customer evidence document, custom content input or process-local evidence store.

The producer directly reuses the accepted immutable proposal's `Capture`, `_requests`, `_shape`, `_bind` and `_inspect`, and the unchanged OCI `Reader`. It reads the selected Job, numeric project identity, standard Docker repository and exact DockerImage through native GETs, inspects actual digest-verified OCI bytes with both local detectors, then repeats all four metadata GETs. The existing [proposal setup](gcp_cloudrun_v2_job_declared_images_20261020_setup.md) records endpoints, field masks, permissions and transfer limits; its original proposal receipt remains a separate historical epoch.

One narrow native default is applied only to a binding copy after a complete Job GET: an omitted `reconciling` becomes false. The [official Job proto](https://raw.githubusercontent.com/googleapis/googleapis/master/google/cloud/run/v2/job.proto) declares an ordinary proto3 boolean, and [ProtoJSON default rules](https://protobuf.dev/programming-guides/json/#presence-and-default-values) allow omission of implicit-presence defaults. Raw captures and their response hashes retain the omission. Explicit null, true, numeric and string values remain unsupported, and generation equality, UID, etag, deletion, exact image identity and raw before/after equality remain required. This integration composition leaves the accepted proposal and association resolver unchanged.

Normal collection saves ordinary snapshot JSON with native request receipts, minimal raw metadata captures and actual redacted detector/path/layer observations. The registered pure consumer reconstructs the declaration and verifies request ownership before evaluation; it performs no cloud or detector calls. Public findings use the existing one-finding-per-secret union, retaining the actual detector rules, paths, layers, scope and selected Job/container identity. Layer member paths are the unchanged native scanner's privacy-preserving names such as `member-1`; original archive filenames are not reconstructed.

A real positive can remain FAIL when other content coverage is incomplete, provided the declaration revalidates. Clean partial, denied, changed or unbound observations remain UNKNOWN. Session cleanup failures prevent a clean PASS. Neither snapshots nor local receipts prove authenticity of externally modified JSON, cloud credential validity, a resolved runtime digest or all-service coverage.

Only `peaso/collectors/gcp.py` changes among the existing GCP collector files: three exact additions append the supported/content-only kind and route its collection to an ordinary subclass. Existing collector methods, service-image predicates, source association resolver, native OCI reader and detector adapters remain unchanged. New Functions and Workbench source successors verify reversal of these exact additions and preserve historical receipts, modules, function objects and cases. The AWScommands shared owner supplies the central engine, validation and registry hook successor; the integration receipt records both source epochs and that owner boundary.

Focused reproduction uses `tests/test_gcp_cloudrun_job_image_runtime_20261020.py`. Its native HTTP/OCI fixtures use the real GCP transport, fake in-memory credentials, and both installed offline detectors; no cloud authentication, live cloud request, IAM change, build or deployment is performed.
