# Optional image vulnerability scans

Image vulnerability scanning is separate from content secret scanning and defaults to off. Supported selections are private ECR images and Lambda container images in AWS, plus immutable Artifact Registry images declared by Cloud Run Jobs in GCP. It does not discover every image or prove which image a Job executed.

Select `gcp.review.cloud_run.selected_job_image_vulnerabilities`, set `image_vulnerability_scans` to `true`, and supply the existing `selected_cloudrun_job_declared_images` selectors. Each selector pins the project, full Job name, UID, container name, repository, SHA256 digest and immutable pull reference. One explicit project and up to four selectors are supported. `content_secret_scans` can remain `false`.

The connector requires `run.jobs.get`, `resourcemanager.projects.get`, `artifactregistry.repositories.get`, `artifactregistry.dockerimages.get` and `artifactregistry.repositories.downloadArtifacts` on those selected resources. A repository-scoped Artifact Registry Reader role is a predefined read-only choice for its registry metadata and downloads. The scanner sends no writes, runs no image and needs no deploy or registry-push permission. See [selected Job image setup](peaso-gcp-selected-job-images.md).

The collector uses pinned Trivy 0.68.1 to inspect downloaded image contents offline and reports HIGH and CRITICAL package vulnerabilities. Findings sharing the same provider, scope, immutable image digest, package, installed version and vulnerability ID are grouped, with their affected assets listed. Missing CLI, denied reads, unsupported image formats or size, stale/missing database and incomplete inventory remain unresolved; partial positive findings are retained.

The worker prepares the public Trivy schema-2 database only after explicit selection and native authorization. It reuses a fresh database or refreshes from `ghcr.io/aquasecurity/trivy-db:2`, with a ten-minute download deadline, aggregate disk monitoring, a four-GiB staging bound and reserved free space. The refresh subprocess receives no cloud credentials, workload metadata URI, user config or proxy credentials. A file lease protects the database generation during offline scanning. The API image does not receive Trivy or its database. Sampling limits detection latency; a filesystem quota is required for a hard aggregate ceiling between samples.

Operators can run `python scripts/peaso_trivy_db.py check --cache-root /tmp/peaso/trivy` or explicitly refresh with `refresh` instead of `check`. The runtime normally prepares this cache on demand. The CLI cache is private to the worker; no customer cloud permission or credential is used for the public database download.

Each scan covers its explicitly selected images within the documented byte, file and time budgets. Unsupported or incomplete coverage stays unresolved. Automatic discovery of every image, Azure and Kubernetes image-CVE collection, and other GCP image surfaces are not supported.

## Selected AWS ECR and Lambda container images

Select `aws.review.ecr.selected_image_vulnerabilities`, set
`image_vulnerability_scans` to `true`, and provide
`selected_aws_image_vulnerabilities`. Use 1–8 exact targets within explicitly
selected `ACCOUNT/REGION` scopes:

```json
{
  "image_vulnerability_scans": true,
  "content_secret_scans": false,
  "selected_aws_image_vulnerabilities": [
    {
      "scope": "111111111111/eu-west-1",
      "repository_name": "sample/app",
      "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    {
      "scope": "111111111111/eu-west-1",
      "function_arn": "arn:aws:lambda:eu-west-1:111111111111:function:sample"
    }
  ]
}
```

ECR selection requires existing read access to the selected repository's image
metadata and layers: `ecr:DescribeImages`, `ecr:BatchGetImage`, and
`ecr:GetDownloadUrlForLayer`. Lambda container selection additionally reads
`lambda:GetFunction` for the selected function and rechecks its declared image.
No authorization token, function invocation, image execution or AWS write is
needed. This identifies vulnerabilities in the selected immutable image; it
does not prove that every workload is currently running that image.

The AWS runtime and selector are delivered together. Merely enabling the flag
does not choose images, and an incomplete or unavailable scan must not appear
as clean. Azure and Kubernetes image-CVE collection are not implemented by this
release; their configuration and secret checks remain separate.
