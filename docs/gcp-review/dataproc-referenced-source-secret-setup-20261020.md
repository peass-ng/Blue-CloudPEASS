# Proposed optional Dataproc referenced source reads

This local proposal is unregistered. It captures an explicitly selected plain GCS source currently referenced by a Dataproc job or cluster initialization action. It does not establish the original bytes executed, job creation content, execution history or whole-job coverage.

Enable `content_secret_scans: true`, name one or both checks below, and supply `selected_dataproc_referenced_sources` with 1–4 unique targets combined. The production planner must derive the private kind allowlist from these exact named checks; category, inventory and default scans must never authorize reads.

| Check | Private kind |
| --- | --- |
| `gcp.review.dataproc.selected_job_referenced_source_secret_indicators` | `dataproc_selected_job_source` |
| `gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators` | `dataproc_selected_initialization_source` |

```json
{
  "profile": "job",
  "resource": "projects/review/regions/us-central1/jobs/review_job",
  "field": "pysparkJob.mainPythonFileUri",
  "bucket": "review-source",
  "object": "scripts/source.py",
  "generation": "12345"
}
```

`profile: cluster` uses an exact `projects/PROJECT_ID/regions/REGION/clusters/NAME` resource and `config.initializationActions[0].executableFile` (an explicitly selected zero-based index, 0–99). Job fields supported are `pysparkJob.mainPythonFileUri`, `sparkRJob.mainRFileUri`, `hiveJob.queryFileUri`, `pigJob.queryFileUri` and `sparkSqlJob.queryFileUri`. Python and R suffixes must match native requirements. Only exact `gs://BUCKET/OBJECT` references are supported; query strings, fragments, encoded aliases, directories and traversal are rejected. Each bucket must belong to the selected Dataproc project.

A user-selected old generation does not prove a current unversioned reference. The reader requires latest object metadata to equal that generation before and after a generation-pinned media GET, then rechecks resource ID/UUID/reference, bucket project number and Resource Manager project identity. Reads bracket an observation rather than form an atomic transaction: changes away and back between reads, and content originally executed, are not established.

| Native read | Minimum permission | Returned evidence |
| --- | --- | --- |
| [Resource Manager v3 projects.get](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/get) | `resourcemanager.projects.get` on selected project | Active numeric `name` and matching `projectId`, before/after |
| [Dataproc jobs.get](https://docs.cloud.google.com/dataproc/docs/reference/rest/v1/projects.regions.jobs/get) | `dataproc.jobs.get` on selected job | `reference.projectId/jobId`, `jobUuid` and exact supported field, before/after |
| [Dataproc clusters.get](https://docs.cloud.google.com/dataproc/docs/reference/rest/v1/projects.regions.clusters/get) | `dataproc.clusters.get` on selected cluster | `projectId/clusterName/clusterUuid`, selected initialization executable, before/after |
| [GCS buckets.get](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get) | `storage.buckets.get` on selected bucket | `name/projectNumber`, before/after; no ACL request |
| [GCS objects.get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get) | `storage.objects.get` on selected object | Latest metadata and generation-pinned `alt=media`; no ACL request |

The existing ordinary OAuth credential must have read authorization for all selected resources. The APIs support `cloud-platform`; Dataproc also supports `dataproc.read-only`, Resource Manager `cloud-platform.read-only`, and GCS `devstorage.read_only` for separately scoped credentials. This proposal introduces no authentication flow or IAM grants. Metadata-only access can be insufficient for object bytes; request the exact object read permission, without list, submit, update, delete, execute or secret-store permissions. Requester-pays billing/quota authorization remains an external setup requirement; only an explicit validated quota project is forwarded.

Per batch: 4 targets, 36 calls, 120 seconds shared deadline, 64 KiB per metadata response, 1 MiB per plain object and 8 MiB aggregate wire bytes. Declared Content-Length, identity encoding and exact response route are required. The reader streams bounded chunks, uses no raw-response cache, rejects archives, binary/non-UTF-8/empty content and customer-supplied encryption, and neither executes nor downloads dependencies. Responses and isolated sessions are closed. Detector processes use bounded stdin and offline flags; no credential validation occurs. Scanner cleanup follows the existing audited runner; this adapter creates no source files.

Both pinned offline engines must finish for a clean captured sample. A completed-engine hit from a fully bound capture remains a finding if the other engine is unavailable, with incomplete coverage. Denied, partial, malformed, changed, oversized, unbound or incomplete negative reads are UNKNOWN. Raw source, matched values, authorization, native free text and reference paths are not retained; locations use opaque HMAC identities. The integration must run the proposed final metadata/cache/option redaction hook together with other active content readers' ephemeral union sets before cleanup.

This does not inspect JARs, archives, dependency lists, inline query lists, driver output, remote HCFS schemes, cross-project buckets, notebooks, Dataflow, Batch or Workbench sources. An intended credential store is not a leak source. Existing generic selected GCS reads do not automatically establish a Dataproc relationship.
