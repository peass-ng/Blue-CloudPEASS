# Local selected Dataflow and Batch referenced-source controls

This local integration adds two default-off controls in the existing Secrets group. It is not deployed. Select the exact public check ID, set `content_secret_scans: true`, and provide 1–4 exact targets for that control in explicit owned project scopes. Categories, frameworks, private option strings, inventories and a serialized grant cannot authorize source reads. The engine issues a separate opaque selection- and scope-bound grant for each explicitly named control before credential construction; the collector consumes it before authentication. Existing platform shared-service-account project/proof-label restrictions still apply.

| Check ID | Native kind | Public selector option |
| --- | --- | --- |
| `gcp.review.dataflow.selected_package_referenced_source_secret_indicators` | `dataflow_selected_package_source` | `selected_dataflow_referenced_sources` |
| `gcp.review.batch.selected_mounted_script_source_secret_indicators` | `batch_selected_mounted_script_source` | `selected_batch_referenced_sources` |

Dataflow selector shape:

```json
{"resource":"projects/review/locations/us-central1/jobs/2026-10-20_01_23_45-123456789","worker_pool":0,"package":0,"name":"workflow.py","bucket":"review-source","object":"staged/workflow.py","generation":"12345","format":"text"}
```

Dataflow binds the actual `environment.workerPools[worker_pool].packages[package]` name/location (and native SHA256 if returned) to selected GCS bytes. The actual job `projectId`, `id`, `location`, `createTime` and supported current state must remain stable. `format` supports bounded UTF-8 text, ZIP, TAR or TAR.GZ under the sealed parser's limits. A missing native package reference stays UNKNOWN; unrelated staging directories, templates and pipeline execution history are not traversed.

Batch selector shape:

```json
{"resource":"projects/review/locations/us-central1/jobs/review-job","task_group":0,"runnable":0,"volume":0,"bucket":"review-source","object":"code/scripts/main.sh","generation":"12345"}
```

Batch binds the actual native Job name/opaque `uid`, native task-group name, selected `taskSpec.runnables[runnable].script.path` and `taskSpec.volumes[volume].gcs.remotePath`/`mountPath`. The supported form is a host script file in one unambiguous GCS mount, with one task group and no mount options. Inline scripts, container-only mounts, overlapping/ambiguous mounts, substituted paths, extra task groups and missing native UID stay UNKNOWN. No job execution, mounted filesystem or container/image inspection occurs.

Minimum read permissions are `dataflow.jobs.get` for Dataflow or `batch.jobs.get` for Batch, plus `resourcemanager.projects.get`, `storage.buckets.get` and `storage.objects.get` on the selected same-project bucket/object. No list permission is required by either source reader. The existing hosted project proof uses the same project GET. Sources are exact internally constructed HTTPS GETs, never arbitrary URLs; content is pinned with both `generation` and `ifGenerationMatch`, bracketed by latest-generation metadata and stable project/bucket/native-reference GETs before and after. Receipts retain actual producer prefixes, including the Dataproc low-level GCS receipt prefix used by Batch; that reuse conveys no Dataproc or generic GCS control credit.

Each control selects at most four targets, at most 36 native reads total, 64 KiB metadata per response and 1 MiB source per target. Each real per-project capture retains the sealed 120-second/8-MiB read budget and native archive limits; at most four selected project captures occur per control. Existing global collector call/deadline/cancellation/resource limits can reduce coverage, producing UNKNOWN or incomplete FAIL. Normal metadata-only Dataflow/Batch scanning never reads source.

Kingfisher **1.4.0** and TruffleHog **3.92.5** inspect the captured bytes offline without credential validation. A clean PASS requires both detectors, every selected same-project row and every native receipt/reference bracket to validate. A trustworthy own hit survives detector unavailability or a malformed sibling as FAIL with incomplete coverage. The new Batch row successor changes only safe sibling completeness aggregation; the sealed original null-marker regression remains reproducible. The corrected Dataflow consumer additionally requires opening/closing request-hash equality; its original predecessor remains unchanged.

Raw source, native script locations, authorization headers and raw matched values are never exported. A shared ephemeral HMAC/match union scrubs all returned collections, options, metadata, retained caches/evidence and tuple dictionary keys before clearing. Logging/debug and framing checks fail closed. No credential validation, execution, filesystem/Jupyter access, Secret Store access, writes or live cloud/auth tests are performed. These results concern current captured referenced bytes and do not prove originally executed or cached bytes.

Package admission consists of `gcp_dataflow_batch_source_runtime_admission_20261020.{py,json}`, its native CASES and package-only predecessor archive. It validates source bytes and actual executing callables, atomic registration of both controls, the exact added GCP branches, and the combined shared-function successor over the unchanged Workbench/K8s proof. It never reads tests or documentation. Do not refresh a receipt to accept unexplained source drift.

Primary field/permission evidence and original document hashes remain in the sealed Dataflow `gcp_dataflow_referenced_source_20261020_primary_contract.json` and Batch `gcp_batch_referenced_source_20261020_primary.json.gz` under `docs/gcp-review/recheck-20261020/`; the runtime report references their unchanged hashes. The runtime native proof/public findings are actual engine/collector outputs from fake HTTP and real pinned detectors, with synthetic test routes reduced to origins and HMAC fingerprints. No full test suite, cloud call, commit, push or deployment is part of this admission.
