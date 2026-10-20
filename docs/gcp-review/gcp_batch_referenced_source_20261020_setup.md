# Selected Batch mounted script source proposal

This is an **unregistered, NEW-ONLY optional producer and pure consumer**. No production planner, collector scheduling, check registration, canonical catalog or existing inline-literal check is changed. The reconciliation's Batch gap is narrowed by a demonstrated native association proposal; container-image source and other host-file references remain unsupported.

The native [Batch Job API](https://docs.cloud.google.com/batch/docs/reference/rest/v1/projects.locations.jobs) supplies `name` and opaque `uid` strings, `taskGroups[]` objects and a `taskSpec` object. `taskSpec.runnables[]` and `taskSpec.volumes[]` contain objects. A runnable selects one of `script`, `container` or `barrier`; `script.path` and `script.text` are mutually exclusive strings. A volume selects `gcs`/`nfs`/`deviceName`; `mountPath` is a string and `mountOptions` is an array of strings. `gcs.remotePath` is a bucket or bucket/subdirectory string, without a `gs://` prefix. The native UID has no documented UUID requirement. `taskCount` and `parallelism` are int64 decimal strings; the local selector indexes below are integers, not invented API fields.

The [storage guide](https://docs.cloud.google.com/batch/docs/create-run-job-storage) describes automatic Cloud Storage FUSE mounting on job VMs. For this bounded subset, `/mnt/source/scripts/main.sh` plus volume `mountPath=/mnt/source` and `gcs.remotePath=review-source/code/` associates the host path with `gs://review-source/code/scripts/main.sh`. This demonstrates a configured relationship and a captured current object, not a successfully mounted runtime file, the job's original input or executed bytes. A local path such as `/tmp/test.sh` alone provides no GCS relationship.

Provide 1–4 unique targets combined, `content_secret_scans: true`, and the exact named check `gcp.review.batch.selected_mounted_script_source_secret_indicators`. Inventory/category/private-kind selections do not authorize reads. The proposal API is `collect(transport, options, scopes, named=[CHECK])`, followed by mandatory `finalize(transport, evidence, metadata=..., options=..., redactions=...)`; the pure consumer is `evaluate(item, finalized['evidence'], scope)`. These are review entrypoints, not installed CLI options. Use existing transport credentials; this proposal creates no authentication flow.

```json
{
  "selected_batch_referenced_sources": [{
    "resource": "projects/review/locations/us-central1/jobs/review-job",
    "task_group": 0,
    "runnable": 0,
    "volume": 0,
    "bucket": "review-source",
    "object": "code/scripts/main.sh",
    "generation": "12345"
  }],
  "content_secret_scans": true
}
```

`task_group` must be integer zero: the current API supports one group. `runnable` and `volume` are explicitly selected integer offsets 0–99. Job resources use the selected project ID; returned names may use that ID or the numeric project name independently obtained from Resource Manager. Require native task-group name under the returned job name, nonempty UID, an exact script-path union, the selected GCS-volume union, and an exact derived bucket/object. Unsupported/malformed references return UNKNOWN; there is no fallback to generic object inventory.

| Fixed native GET | Minimum reader permission | Evidence read |
| --- | --- | --- |
| [Resource Manager v3 projects.get](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/get) | `resourcemanager.projects.get` for selected project | Active project ID and numeric `name`, before/after |
| [Batch jobs.get](https://docs.cloud.google.com/batch/docs/reference/rest/v1/projects.locations.jobs/get), [permission reference](https://docs.cloud.google.com/iam/docs/roles-permissions/batch) | `batch.jobs.get` in selected project | Job name/UID, task-group name, selected script path and volume, before/after |
| [Storage buckets.get](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get) | `storage.buckets.get` on selected bucket | Exact name and matching project number, before/after |
| [Storage objects.get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get) | `storage.objects.get` on exact selected object | Latest metadata before/after; generation-pinned media |

The reader needs these four permissions, not broad predefined viewer roles. It requests no ACLs and needs no list, create, update, delete, submit, execute, IAM-policy or secret-payload permission. Batch jobs.get requires OAuth `cloud-platform`; that existing credential must also authorize the CRM/GCS reads. A job's execution service account and runtime mount permissions are separate from this reader; neither successful runtime mounting nor that account's effective access is inferred. Requester-pays/quota billing authorization remains external setup; only an explicitly validated quota-project header is forwarded. No IAM grants are made.

[GCS object metadata](https://docs.cloud.google.com/storage/docs/json_api/v1/objects) uses `generation` as a long decimal string and `size` as an unsigned-long decimal string. [Bucket metadata](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets) uses an unsigned-long decimal string for `projectNumber`. Numeric JSON values, stale generations and foreign ownership are rejected. Latest unversioned metadata must equal the selected generation before and after a media GET containing both `generation` and `ifGenerationMatch`; response headers and size must bind that same object. This rejects an old generation that is no longer current. The closing Batch, bucket and project reads must preserve the observed identities/reference. These reads are not atomic and do not detect changes away and back between observations.

Bounds are shared per explicit call: four targets, 36 native calls, 120 seconds, 64 KiB per metadata response, 1 MiB per source and 8 MiB aggregate wire bytes. Existing transport deadlines, cancellation and call limits also apply. GETs stream bounded chunks through isolated sessions with ambient proxy/netrc/cookies disabled, redirects disabled and declared exact identity-encoded lengths. Debug HTTP diagnostics prevent credential access and requests. No source or native response enters a raw-response cache. Sessions/responses close on failure.

Only nonempty supported plain UTF-8 text objects are inspected. Existing reviewed text/archive guards, GCS framing/metadata reads, isolated-session and scanner primitives are composed without changes. Archives, binary content, customer-supplied encryption, compressed responses and partial native responses are rejected. There is no extraction, dependency following, container exec, image download, filesystem mount/access, bucket listing or credential validation.

Both pinned offline detectors—Kingfisher 1.4.0 and TruffleHog 3.92.5—must complete for PASS. A completed-engine hit on fully bound source remains FAIL if another detector or selected target is incomplete; an incomplete negative is UNKNOWN. Findings use the shared canonical value HMAC, so the same detected value deduplicates across selected targets and other source types. No raw value, source content, native free text, path, UID or authorization is exported. Finalization scrubs the union of transient matches from metadata, transport cache/evidence/options and export, removes selectors, then destroys this reader's match set; other active readers must supply their transient union before their own cleanup.

Unsupported counterexamples are native local/relative/URI/environment-expanded/traversal paths, inline `script.text` (already covered by the literal reader), container/barrier runnables, NFS/disks, missing or overlapping volumes, foreign buckets, malformed unions, and custom mount options. Nonempty mount options, including `only-dir`, endpoint and cache options, are rejected without interpretation. GCS bucket roots and native subdirectory roots are supported; no arbitrary URL or path normalization is performed. Container-image code, symlink/runtime filesystem resolution, execution-time object generations and historical executed source remain gaps.

The immutable proposal receipt and primary-document capture live under the `gcp_batch_referenced_source_20261020` prefix. Run only the directed test module: `.venv/bin/python -m pytest -q tests/gcp_batch_referenced_source_20261020_test.py`. No live cloud, credentials, infrastructure, commits, pushes or deployment were used for this review; public primary documentation was retrieved without authentication.
