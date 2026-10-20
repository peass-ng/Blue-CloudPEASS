# Selected Workbench startup source proposal — 2026-10-20

This is an **unregistered, default-off proposal**, with a standalone optional producer and pure consumer. It does not modify the engine, registry, GCP collector, canonical review, tracking or UI. The directed tests use fake native HTTP responses and the actual pinned offline detectors; no authenticated cloud collection was performed.

The consumer ID proposed is `gcp.review.workbench.selected_referenced_source_secret_indicators_20261020`, for the new kind `workbench_selected_referenced_source_20261020`.

## Native association and supported scope

[Current Notebooks API guidance](https://docs.cloud.google.com/gemini-enterprise-agent-platform/notebooks/workbench/reference) identifies v2 as the current Workbench API. [The v2 Instance schema](https://docs.cloud.google.com/gemini-enterprise-agent-platform/notebooks/workbench/reference/rest/v2/projects.locations.instances) returns `name`, unique resource `id`, and `gceSetup.metadata`; `createTime` and the underlying VM's `gceSetup.instanceId` are additional identity evidence when present. A missing `id` is UNKNOWN. Names and timestamps alone never substitute for native identity.

[The current metadata guide](https://docs.cloud.google.com/gemini-enterprise-agent-platform/notebooks/workbench/instances/manage-metadata) documents the Cloud Storage `post-startup-script` URI, and also describes `startup-script-url` in the startup order. The only selected field paths supported here are `gceSetup.metadata.post-startup-script` and `gceSetup.metadata.startup-script-url`. Exact native equality to `gs://{selected bucket}/{selected object}` is required, with no interpretation of arbitrary URLs or URI fragments.

The `gceSetup.systemMetadata` map is documented generically as a system-managed subset. That does not guarantee any particular selected key is returned there: **no standalone systemMetadata selector or positive fixture is admitted**. If either selected key is also actually returned in that map, a conflicting value is UNKNOWN. A response containing only systemMetadata is UNKNOWN. Other keys, inline `startup-script`, top-level legacy `postStartupScript`, and arbitrary metadata URIs are unsupported.

For post-startup scripts, the producer also binds the actually returned behavior across both reads. The accepted values are `run_once`, `run_every_start`, and `download_and_run_every_start`; absence uses the documented `run_once` default and its absence is itself bound. Conflicting maps, invalid values or a changed returned behavior are UNKNOWN. **A current GCS source read never proves which bytes are already cached on the VM or were originally executed**, including with download-every-start behavior.

[The retirement notice](https://docs.cloud.google.com/vertex-ai/docs/deprecations) states that managed notebooks were deleted on March 30, 2026, and user-managed notebooks were converted to ordinary Compute Engine VMs on that date. Legacy v1 instance/runtime forms are excluded; their API documentation is not evidence of current Workbench support. The proposal does not inspect notebook files, cells, execution history, stored credentials, filesystem, images, Secret Manager or Jupyter endpoints.

## Exact selection and proposed caller contract

The caller must already have an explicitly selected owned project scope. Validate all supplied selectors using `selected_targets(options, scopes)` **before credentials are acquired**. Each target must contain exactly these five keys, with one through four distinct targets in total:

```json
{
  "resource": "projects/review/locations/us-central1-a/instances/review-instance",
  "field": "gceSetup.metadata.post-startup-script",
  "bucket": "review-source",
  "object": "scripts/source.sh",
  "generation": "12345"
}
```

The optional configuration uses `content_secret_scans: true` and `selected_workbench_referenced_sources: [target]`. A future trusted planner must derive `_content_secret_scan_kinds: ["workbench_selected_referenced_source_20261020"]` and `_workbench_source_named_checks: ["gcp.review.workbench.selected_referenced_source_secret_indicators_20261020"]` exclusively from exact explicit named-check selection. A default/category request or inventory-only selection supplies neither authorization. The existing engine does not yet install or schedule this proposal.

`collect_sources(collector, scope)` requires the existing transport interface and returns only redacted source items. The enclosing collection contains the genuine returned item/request IDs and `type`, `scope`, `status`, `items`, `source_requests`. It must not fabricate successful source receipts or project/bucket parent collections. Call `final_snapshot(collector, snapshot, redactions=other_ephemeral_union)` after all readers complete, then use the pure `referenced_source(item, index)` consumer. The finalizer adds the real capture ledger/opaque selections, scrubs matched values across the snapshot, collector collections, transport cache/evidence/options, removes raw target selectors and clears its transient state in a finally block. Other readers' transient match unions must likewise receive `redaction_values(transport)` before any reader clears them. Call `clear_pending(transport)` in an outer teardown if collection fails before finalization.

## Read sequence, permissions and limits

Each target uses exactly nine uncached GETs: project, v2 instance, bucket, latest object metadata, pinned media, latest object metadata, v2 instance, bucket, project. Native project ID/number and ACTIVE state must match the selected scope; the actual bucket `projectNumber` must match that project on both reads. [The bucket schema](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets) defines that ownership field. No parent collection is synthesized.

[Objects.get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get) selects a specific revision using `generation`; without it the metadata read selects latest. Both latest reads must equal the selected generation and unchanged metadata. The media read uses `generation` plus `ifGenerationMatch`, checks the native generation response header, exact size/type and complete framing, and only then permits scanning. Closing native identity/reference, behavior, bucket and project observations must match before scanning starts. These observations bracket a point-in-time capture; they are not a transactional snapshot and cannot rule out an unobserved change-and-revert between GETs.

Required permissions are only [notebooks.instances.get](https://docs.cloud.google.com/gemini-enterprise-agent-platform/notebooks/workbench/reference/rest/v2/projects.locations.instances/get), [resourcemanager.projects.get](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/get), [storage.buckets.get](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get), and [storage.objects.get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get), on the selected resources. No list, ACL, IAM-policy, write or credential-validation permissions are requested. This setup describes permissions; it creates no IAM or infrastructure resources.

Bounds: four targets, 36 total GETs, 120 seconds for the capture, 64 KiB per metadata response, 1 MiB per plain UTF-8 script, 8 MiB aggregate bytes, 256 redacted leaks and 512 locations. Transport cancellation, deadline, maximum calls and per-read socket timeouts also apply. Missing lengths, truncation, redirects, partial-native markers, duplicate JSON keys, compression, archives, binary text, unsupported encryption/type, unsafe wire debugging, denied/deleted reads, principal changes or unresolved identity/reference yield UNKNOWN. No retries, lists, arbitrary URLs or source execution are performed. The only subprocess use is the unchanged pinned local detector contract.

The producer reuses the existing reviewed low-level project/GCS `_read`, object selection/metadata/plain-text validators and shared `scan_content`/`merge_leaks` HMAC contract without editing those files. Shared-reader receipt IDs retain their genuine `dataproc-source-read:` prefix; only the two new instance reads issue `workbench-source-read:` IDs. Both are validated against exact origin, ordered operation, scope, capture, principal and closed request digests. They are never relabeled as new native calls.

PASS requires both pinned detectors to complete cleanly and all selected collection evidence to be complete. A bound detected secret is FAIL, including when another detector or sibling collection is incomplete; unavailable binding or an incomplete negative is UNKNOWN. Neither detector validates credentials. Persisted output contains only opaque HMAC references, static reasons, bounded redacted detector metadata and genuine read receipts; raw source, authorization headers and native instance metadata are not retained.

## Local verification

```sh
.venv/bin/python -m pytest -q tests/gcp_workbench_referenced_source_20261020_test.py
```

The immutable proposal receipt pins the new source/consumer/test/proof/setup files, unchanged dependencies, public documentation byte hashes and installed detector evidence. Its validator is `peaso.checks.gcp_workbench_referenced_source_20261020_proposal.validate_proposal`. Evidence is offline and scope-limited; no cloud execution, production integration, notebook-wide clean state or original-execution proof is claimed.
