# Selected Dataproc source secret inspection

This optional reader checks the plain GCS script or query currently referenced by an explicitly selected Dataproc job or cluster initialization action. It uses Kingfisher and TruffleHog offline, hides matched values, and combines duplicate detections into one leak. It does not establish the original bytes executed.

Set `content_secret_scans: true`, select one or both check IDs below, and supply `selected_dataproc_referenced_sources` with 1–4 targets combined. Default scans, categories and inventory selection do not enable content reads.

- `gcp.review.dataproc.selected_job_referenced_source_secret_indicators`
- `gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators`

```json
{
  "content_secret_scans": true,
  "selected_dataproc_referenced_sources": [{
    "profile": "job",
    "resource": "projects/my-project/regions/us-central1/jobs/my-job",
    "field": "pysparkJob.mainPythonFileUri",
    "bucket": "my-source-bucket",
    "object": "scripts/job.py",
    "generation": "12345"
  }]
}
```

For clusters, use `profile: cluster`, an exact `projects/PROJECT/regions/REGION/clusters/NAME`, and `field: config.initializationActions[0].executableFile` with the intended zero-based index (0–99). Supported job fields are `pysparkJob.mainPythonFileUri`, `sparkRJob.mainRFileUri`, `hiveJob.queryFileUri`, `pigJob.queryFileUri`, and `sparkSqlJob.queryFileUri`. The selected bucket must belong to the selected project.

Grant only the applicable read permissions:

| Resource | Permission |
| --- | --- |
| Selected project | `resourcemanager.projects.get` |
| Selected job or cluster | `dataproc.jobs.get` or `dataproc.clusters.get` |
| Selected bucket | `storage.buckets.get` |
| Exact selected source object | `storage.objects.get` |

Metadata access alone may not grant object reads. No list, submit, update, delete, execute, IAM change, or secret-store access is needed. The existing OAuth credential needs a supported read scope for each API; `cloud-platform` is supported, subject to IAM. Requester-pays authorization, if applicable, remains a prerequisite.

The reader verifies project, bucket ownership, native resource UUID and reference before and after a generation-pinned read. Latest object metadata must match the selected generation on both sides. This is a bounded observation, not an atomic transaction or proof of execution history.

Limits per batch: 4 targets, 36 calls, 120 seconds, 64 KiB per metadata response, 1 MiB per source and 8 MiB total wire bytes. Only nonempty UTF-8 plain text is supported. Archives, JARs, dependencies, inline query lists, driver logs, cross-project buckets and remote schemes are excluded. Missing, denied, changed, unsupported or incomplete negative samples remain unresolved; a bound detected leak can still be reported with incomplete detector coverage.

[Native APIs, detailed read contract and preserved original proposal](gcp-review/dataproc-referenced-source-secret-setup-20261020.md).
