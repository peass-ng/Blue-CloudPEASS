# Selected Cloud Run Job image secret inspection

This check scans supported text in the immutable image declared by an
explicitly selected Job container. Kingfisher and TruffleHog run offline; detections
of the same secret are combined and values remain hidden. It does not establish
which image a running execution actually used.

Select `gcp.review.cloudrun_job.declared_image_secret_indicators`, use one explicit
`projects/PROJECT_ID` scope, and set `content_secret_scans: true`. The
`selected_cloudrun_job_declared_images` collector option accepts up to four exact
selectors in that project:

```json
{
  "api_version": "run.googleapis.com/v2",
  "kind": "Job",
  "project_id": "my-project",
  "resource_name": "projects/my-project/locations/us-central1/jobs/my-job",
  "resource_uid": "4dc68abc-4c01-4262-8364-922ef46bcd8f",
  "container_name": "worker",
  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "repository": "projects/my-project/locations/us-central1/repositories/my-repository",
  "immutable_reference": "us-central1-docker.pkg.dev/my-project/my-repository/my-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

Replace the example UUID and digest with the native Job UID and the exact digest
reference in its selected container declaration. Mutable tags and inferred runtime
digests do not establish this association. Default metadata, category and framework
selection do not authorize the content read; internal grants are engine-managed.

The connector needs `run.jobs.get`, `resourcemanager.projects.get`,
`artifactregistry.repositories.get`, `artifactregistry.dockerimages.get`, and
`artifactregistry.repositories.downloadArtifacts` on the selected resources.
`roles/artifactregistry.reader` on the repository is a predefined read-only option
for the registry permissions; project or Cloud Run metadata access alone does not
grant image downloads. No deployment, Job execution, image push or secret-store
payload permission is required.

The collector compares native Job, project, repository and image identity before
and after inspection. A clean result requires complete supported content and both
detectors. Missing, denied, changed or unsupported evidence remains undetermined;
detected secrets remain visible when other bound content inspection is incomplete.
Only supported single-platform image configuration and layer text is covered.

See the [native contract, permission spelling and size limits](gcp-review/recheck-20261020/gcp_cloudrun_v2_job_declared_images_20261020_setup.md)
and [content read permissions](secret-content-permissions.md). This check scans for secrets with
Kingfisher and TruffleHog; it does not run Trivy vulnerability scanning.
