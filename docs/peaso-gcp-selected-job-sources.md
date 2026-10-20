# Selected Dataflow and Batch source secret inspection

These optional checks inspect the current GCS source referenced by an explicitly selected job. Kingfisher and TruffleHog run offline; matched values are hidden and the same leak is reported once across both detectors and selected sources. The readers do not execute jobs or establish which bytes previously ran.

Enable `content_secret_scans: true`, name the exact check and select 1–4 targets in explicit owned projects. Normal configuration scans do not download these sources.

For `gcp.review.dataflow.selected_package_referenced_source_secret_indicators`:

```json
{
  "content_secret_scans": true,
  "selected_dataflow_referenced_sources": [{
    "resource": "projects/my-project/locations/us-central1/jobs/2026-10-20_01_23_45-123456789",
    "worker_pool": 0,
    "package": 0,
    "name": "workflow.py",
    "bucket": "my-source-bucket",
    "object": "staged/workflow.py",
    "generation": "12345",
    "format": "text"
  }]
}
```

The selected native worker-pool package must match its name and GCS reference. Supported formats are bounded UTF-8 text, ZIP, TAR and TAR.GZ. Templates, unrelated staging objects and container images are not traversed.

For `gcp.review.batch.selected_mounted_script_source_secret_indicators`:

```json
{
  "content_secret_scans": true,
  "selected_batch_referenced_sources": [{
    "resource": "projects/my-project/locations/us-central1/jobs/my-job",
    "task_group": 0,
    "runnable": 0,
    "volume": 0,
    "bucket": "my-source-bucket",
    "object": "scripts/main.sh",
    "generation": "12345"
  }]
}
```

Batch requires one task group and an unambiguous GCS-mounted host script with no mount options. Container-only mounts, overlapping mounts, substituted paths and missing native job identity remain undetermined. No mounted filesystem is accessed.

Grant `dataflow.jobs.get` or `batch.jobs.get`, plus `resourcemanager.projects.get`, `storage.buckets.get` and `storage.objects.get` on the selected same-project bucket and exact object. Object download needs its own permission; metadata access alone is insufficient. No list, write, execute, IAM change or Secret Manager permission is required. The shared platform service account still requires explicit project selection and proof.

Each source read is generation-pinned and bracketed by native identity/reference and current-generation metadata reads. Missing, denied, changed or incomplete samples cannot establish a clean result. A trustworthy detected hit remains a finding when another selected source is incomplete.

Bounds: four targets, 36 reads, 64 KiB per metadata response and 1 MiB source per target. Per-project captures retain a 120-second and 8-MiB wire budget; collector-wide limits may reduce coverage. These are local additions; publication is a separate release step.

[Detailed native contract and preserved test proofs](gcp-review/dataflow-batch-source-runtime-setup-20261020.md).
