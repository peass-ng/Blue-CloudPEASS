# Selected Workbench startup source secret inspection

This optional check inspects the current GCS script referenced by a selected Workbench instance. Kingfisher and TruffleHog run offline, matched values are hidden and duplicate detections become one leak. Cached scripts, notebook files and previously executed bytes are outside its scope.

Select `gcp.review.workbench.selected_referenced_source_secret_indicators_20261020`, enable content inspection and supply 1–4 exact targets in explicitly selected projects:

```json
{
  "content_secret_scans": true,
  "selected_workbench_referenced_sources": [{
    "resource": "projects/my-project/locations/us-central1-a/instances/my-instance",
    "field": "gceSetup.metadata.post-startup-script",
    "bucket": "my-source-bucket",
    "object": "scripts/startup.sh",
    "generation": "12345"
  }]
}
```

The other supported field is `gceSetup.metadata.startup-script-url`. The selected bucket must belong to the selected project. `systemMetadata` alone, inline scripts, arbitrary URLs and legacy notebook forms are unsupported. Default, inventory, category or framework selection does not enable content reads.

Grant only these read permissions at the selected resources:

| Resource | Permission |
| --- | --- |
| Selected project | `resourcemanager.projects.get` |
| Selected instance | `notebooks.instances.get` |
| Selected bucket | `storage.buckets.get` |
| Exact source object | `storage.objects.get` |

Metadata access alone may not grant object download. No list, execute, update, delete, IAM change or secret-store access is needed. Existing OAuth credentials need API access scopes such as `cloud-platform`, subject to IAM. The shared platform service account still requires explicit approved project IDs and project proof.

Native instance identity, script reference, startup behavior and current object generation must remain coherent around the generation-pinned read. Missing, denied, changed or incomplete negative samples remain undetermined; a trustworthy detected hit can remain a finding with incomplete inspection explicitly stated.

Limits: 4 targets, 36 calls, 120 seconds, 64 KiB per metadata response, 1 MiB per nonempty UTF-8 source and 8 MiB total wire bytes. Archives, images, VM files, cross-project buckets and execution history are excluded.

[Native field contract, runtime proof and preserved original proposal](gcp-review/workbench-source-runtime-setup-20261020.md).
