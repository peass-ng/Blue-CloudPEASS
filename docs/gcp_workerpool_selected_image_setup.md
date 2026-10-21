# Selected Cloud Run worker pool revision image content

This default-off check reads an immutable image declared by one explicitly selected container of an observed positive worker pool revision split. It does not prove the image bytes loaded by a running instance, inspect other split revisions, or cover every container or repository. The fixed GCP-3 gap remains partially open for unselected pools, other revisions, mutable tags, unsupported image formats and runtime image identity; the fixed 29 technical-group denominator is unchanged.

Select `gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators` in the existing Secrets UI group, one `projects/PROJECT_ID` scope, `content_secret_scans: true`, and one to four entries in `selected_cloudrun_worker_pool_revision_images`. Each entry must have exactly `pool_name`, `pool_uid`, `revision_name`, `revision_uid`, `container_index` and `immutable_reference`; use the native UUIDs and an image reference ending in `@sha256:<64 lowercase hex digits>`. The revision must be in a positive observed `instanceSplitStatuses` entry, and the selected index must identify the container declaring that exact digest. The engine's named check selection sets `_content_secret_scan_kinds`; callers should not set that internal option.

```json
{
  "checks": ["gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators"],
  "connector": {
    "provider": "gcp",
    "scopes": ["projects/example-project"],
    "options": {
      "content_secret_scans": true,
      "selected_cloudrun_worker_pool_revision_images": [{
        "pool_name": "projects/example-project/locations/europe-west1/workerPools/pool-one",
        "pool_uid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "revision_name": "projects/example-project/locations/europe-west1/workerPools/pool-one/revisions/revision-one",
        "revision_uid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "container_index": 0,
        "immutable_reference": "europe-west1-docker.pkg.dev/example-project/example-repo/example-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }]
    }
  }
}
```

The reader issues only selected native GETs: worker pool and revision via Cloud Run v2, project via Cloud Resource Manager v3, repository and DockerImage via Artifact Registry v1, then exact digest manifest/config/layers through the accepted private stream reader. It repeats all five metadata GETs and requires equality before accepting the declaration. All HTTP sessions reject redirects and foreign response URLs; no listing, image tag resolution, execution, writes, or secret-store value reads occur. Temporary layer files are private and removed after inspection. Kingfisher and TruffleHog scan verified supported content; HMAC fingerprints merge duplicate detections and raw values remain private. A verified leak stays FAIL when later content is incomplete; clean but incomplete content is UNKNOWN. The separately selected Trivy vulnerability checks are available for image vulnerabilities and are not implied by this secret check.

Read permissions needed on selected resources: `run.workerpools.get`, `run.revisions.get`, `resourcemanager.projects.get`, `artifactregistry.repositories.get`, `artifactregistry.dockerimages.get`, and `artifactregistry.repositories.downloadArtifacts` for the OCI pull. Grant Artifact Registry Reader (`roles/artifactregistry.reader`) on the selected repository for registry metadata and bytes. Cloud Run/project metadata permissions alone do not grant registry bytes. The OAuth token needs the Cloud Platform scope; no execution, deploy or registry-write role is required.

Official references: [worker pool GET](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.workerPools/get), [revision GET](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.workerPools.revisions/get), [worker pool observed splits and reconciliation](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.workerPools), [Artifact Registry DockerImage GET](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages/get), [Artifact Registry read roles](https://docs.cloud.google.com/artifact-registry/docs/access-control), [Cloud Run IAM permissions](https://docs.cloud.google.com/run/docs/reference/iam/permissions).
