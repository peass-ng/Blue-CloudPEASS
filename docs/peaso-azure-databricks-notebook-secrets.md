# Optional selected Databricks notebook source inspection

This optional reader is integrated locally; publication is tracked separately in [review progress](check-review/progress.json). It creates no permission grants or infrastructure. The check is `azure.review.databricks.selected_notebook_source_secret_indicators`, in **Secrets**, severity **high**, with no numbered compliance mappings.

Reading requires the exact named check, `content_secret_scans: true` and `selected_azure_databricks_notebooks`, containing 1–4 exact `{workspace_resource_id, path}` targets inside explicitly selected subscription scopes. The workspace is a native ARM ID; the notebook path is absolute and case-sensitive. The selector cannot supply a host, URL, object ID, bearer, token audience, export format, query or remote reference.

```json
{
  "content_secret_scans": true,
  "selected_azure_databricks_notebooks": [
    {
      "workspace_resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Databricks/workspaces/selected",
      "path": "/Shared/Selected notebook"
    }
  ]
}
```

| Read | Native route | Minimum authorization |
| --- | --- | --- |
| Subscription identity | `GET https://management.azure.com/subscriptions/{id}?api-version=2022-12-01` | `Microsoft.Resources/subscriptions/read`; ARM token audience |
| Exact workspace identity | `GET https://management.azure.com/subscriptions/{id}/resourceGroups/{group}/providers/Microsoft.Databricks/workspaces/{workspace}?api-version=2026-01-01` | `Microsoft.Databricks/workspaces/read`; ARM audience |
| Notebook identity before/after export | `GET https://{native_workspace_host}/api/2.0/workspace/get-status?path={encoded_exact_path}` | Existing workspace-entitled principal with notebook/folder CAN READ, shown as CAN VIEW in the UI; workspace API scope |
| Captured source | `GET https://{native_workspace_host}/api/2.0/workspace/export?path={encoded_exact_path}&format=SOURCE&direct_download=false` | Same native object read authorization; no run, edit or manage permission |

The reader uses the customer's existing supported Azure SDK credential. The SDK requests `https://management.azure.com/.default` for ARM and **`2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default`** for Databricks. Token tenant, object ID and client ID must be present and coherent across both audiences; configured explicit client credentials must match that client. These defensive JWT checks rely on SDK token acquisition, not local JWT signature validation. Opaque/missing/expired or foreign claims stay unresolved. A pasted ARM-only token, Databricks account bearer or PAT cannot complete this reader; no alternate credential field or fallback is introduced.

The principal must already be assigned and entitled in the workspace. ARM Reader permits metadata reads, not notebook access. The documented Contributor/Owner management-token fallback can onboard a principal as workspace admin; this reader never sends that management token or either onboarding header, creates a principal, grants a role or calls a token/key-list API. It sends only the ordinary Databricks bearer after the native workspace host is bound.

Native subscription tenant/state must match the authenticated Azure tenant/scope. The exact workspace GET must match its ARM id/name/type, be provisioned, and return `workspaceId` and the standard **`adb-{sameWorkspaceId}.{digits}.azuredatabricks.net`** host. No caller endpoint override, arbitrary URL, proxy discovery, sovereign/custom suffix, redirect or auth challenge is followed. Existing private DNS and network reachability to that standard host are required when front-end Private Link blocks public access. No new endpoint, DNS zone or network change is made.

For notebook targets, `get-status` must return the selected exact path, `object_type=NOTEBOOK`, native positive integer `object_id` and supported `language`. The export is bounded base64 JSON SOURCE, with compatible optional `file_type`. A closing status read must name the same native object/language and optional native `resource_id`. If that read is denied or changes identity, the captured bytes are not scanned and the result is unresolved. Directory/repository objects, known Repos/Volumes/DBFS namespaces, explicit repository metadata, remote URL/ref selectors, outputs, run output and Secret Scope APIs are unsupported. Exact workspace FILE objects are supported only through the separate selector below. No ancestor enumeration or Git origin association is claimed for an otherwise returned NOTEBOOK. Source code may contain references, but the reader does not follow or execute them.

The after-status read does **not** prove an immutable notebook content revision. The API's documented `modified_at` and size fields apply to files; this notebook-only subset rejects unexpected file-only status fields. Source edits can occur while the object ID remains the same. A result covers only the captured point-in-time SOURCE bytes, not current cells, execution, outputs, all workspace content or a Git commit. Independently selected Blob/File copies and immutable ACR images do not establish this notebook association.

Bounds are 4 targets, 20 native GETs, 2 MiB per wire response, 8 MiB total response bytes, 1 MiB decoded source per notebook, 16 KiB read chunks, and a 120-second checked deadline including scans. Existing shared caller call/cancellation budgets also apply. The service's 10 MB export ceiling is larger than this local subset. Empty/whitespace, invalid UTF-8, NUL-containing, oversized, noncanonical/invalid base64, partial, malformed and error responses cannot establish clean PASS. No directory/archive export, import, notebook/script execution or filesystem extraction occurs.

Both pinned Kingfisher 1.4.0 and TruffleHog 3.92.5 inspect source offline without credential verification. Both must complete before a clean negative. A fully bound completed-engine hit remains FAIL with incomplete coverage if the other detector or another selected notebook is unavailable; incomplete negatives remain UNKNOWN. HMAC locations and exact-value dedup hide source/path matches. Transient matched values join `configuration_secret_redactions`; the proposed finalization merges this ledger before the unchanged ML → logs → declarations → five-reader union and cleanup. Raw source, base64, paths, auth and native error bodies are not exported or kept in content caches.

Every native connection sets HTTP debug level zero. Directed tests enable global stdlib HTTP DEBUG and Azure HTTP-policy/identity loggers, use the real HTTP serializer/response parser with inert wire sockets, and require source/auth/error values to remain absent from logs. SDK-internal OAuth telemetry, TLS/network behavior and third-party credential transports are outside that inert-credential proof; SDK OAuth timeout/retry behavior also prevents a hard cancellation promise for in-flight token acquisition.

Primary references: [Entra token and already-assigned principal path](https://learn.microsoft.com/en-us/azure/databricks/dev-tools/auth/aad-token-manual), [workspace ARM GET](https://learn.microsoft.com/en-us/rest/api/databricks/workspaces/get?view=rest-databricks-2026-01-01), [get-status and SOURCE export](https://docs.databricks.com/api/workspace-objects/v1/export), [native notebook/folder ACLs](https://learn.microsoft.com/en-us/azure/databricks/security/auth/access-control/) and [Private Link reachability](https://learn.microsoft.com/en-us/azure/databricks/security/network/concepts/privatelink-concepts).

## Exact selected workspace FILE extension (AZ-6 candidate)

`selected_azure_databricks_files` adds 1–4 exact `{workspace_resource_id, path, object_type: "FILE"}` targets, shared with notebook selections under the four-target limit. It uses the same default-off check, explicit `content_secret_scans: true` and selected check ID. The selector accepts an absolute file path in the selected workspace; `/Repos`, `/Volumes`, `/dbfs` and `/Workspace/Repos` are excluded because this candidate does not bind a Git HEAD or external object. No directory listing, repository clone, history, execution, outputs or Secret Scope read occurs.

```json
{
  "content_secret_scans": true,
  "selected_azure_databricks_files": [{
    "workspace_resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Databricks/workspaces/selected",
    "path": "/Shared/config/example.txt",
    "object_type": "FILE"
  }]
}
```

The native route sequence is subscription GET, exact workspace ARM GET, exact `workspace/get-status`, `workspace/export?format=RAW&direct_download=false`, and the same status GET again. The existing ARM audience is used only for the first two requests; the Databricks audience is used only for the three requests on the ARM-derived workspace host. Subscription read requires `Microsoft.Resources/subscriptions/read`; workspace identity read requires `Microsoft.Databricks/workspaces/read`. The same Entra principal must already be assigned to the Databricks workspace and have workspace API `workspace` scope plus CAN READ/CAN VIEW on the exact file and containing folders. ARM Reader alone does not grant those data-plane permissions. Private network connectivity to the native workspace host may also be required.

The file must have native `object_type=FILE`, exact path, positive object ID, modification timestamp and size at most 1 MiB. The second status must repeat those values and optional resource ID. The bounded RAW base64 export must decode to exactly the recorded size and valid nonempty UTF-8 without NUL. This binds the captured bytes to one selected file and a status interval; concurrent same-size edits or later changes remain possible. Clean PASS requires both offline engines to finish; a supported hit is FAIL even if another selection is incomplete. HMAC fingerprints and redacted metadata preserve the existing private-value handling. The existing 20-call, 2 MiB response, 8 MiB aggregate, 120-second and four-target limits still apply. This is local fixture proof pending live workspace authorization and release integration.

API reference: [Workspace export and FILE get-status](https://docs.databricks.com/api/workspace-files/v1/export).

## Exact selected terminal task-run result or logs (AZ-6 candidate)

`selected_azure_databricks_task_outputs` selects an exact `{workspace_resource_id, job_id, parent_run_id, task_run_id, task_key, content}` target. `content` is either `notebook_result` for `notebook_output.result`, or `task_logs` for the standard-stream `logs` field of one JAR, Python script, or Python wheel task. All IDs are positive native integers and the task key is exact. This shares the four-target total with selected notebooks and files. The named Databricks check and `content_secret_scans: true` must both be selected before authentication; the default is off.

```json
{
  "content_secret_scans": true,
  "selected_azure_databricks_task_outputs": [{
    "workspace_resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Databricks/workspaces/selected",
    "job_id": 66,
    "parent_run_id": 77,
    "task_run_id": 88,
    "task_key": "selected_task",
    "content": "notebook_result"
  }]
}
```

The exact read sequence is ARM subscription GET, ARM workspace GET, Databricks `GET /api/2.2/jobs/runs/get?run_id={parent}`, the same GET for the selected task, `GET /api/2.2/jobs/runs/get-output?run_id={task}`, task and parent GETs again, and the same ARM workspace GET again. No run listing, pagination, repair history, execution, job edit or URL returned in a response is followed. The ARM token is sent only to `management.azure.com`; the Databricks audience token is sent only to the standard ARM-derived `adb-{workspaceId}.{digits}.azuredatabricks.net` host. Redirects, alternate hosts and compressed/error responses are rejected.

The parent run must contain the exact selected task ID and key in its first, unpaginated task page. Parent, task and output metadata must agree on job/run IDs, task type, terminal state, start/end time, attempt and original attempt when present. Parent and task are re-read after output, and the ARM workspace ID/host is re-read last. A mismatch leaves the content unresolved. This cannot prove no same-metadata concurrent edit or later change occurred.

Only a nonempty UTF-8 result or log sample up to 1 MiB is scanned. The native API limits notebook results to the first 5 MiB and supported standard-stream logs to the last 5 MiB; `truncated` or `logs_truncated` makes a clean finding UNKNOWN. A supported secret in an otherwise bound truncated sample remains FAIL with incomplete coverage. Missing output, denial, expired run, unsupported task type, pagination, malformed response and local wire-limit failure are UNKNOWN. Even a clean complete result describes one selected task field, not a whole job or all logs. Error traces, SQL results, notebook cell outputs and external log storage are outside this subset.

Setup needs ARM `Microsoft.Resources/subscriptions/read` and `Microsoft.Databricks/workspaces/read`, plus an existing principal assigned to the Databricks workspace with Jobs API `jobs` scope and at least CAN VIEW on the selected job/run for results. The Azure Databricks job ACL table distinguishes results from job run logs: viewing the latter may require CAN MANAGE RUN and applicable compute log access. ARM Reader alone cannot read these task outputs. Native workspace private connectivity may be necessary. The reader does not onboard a principal or elevate permissions. It shares the existing private Kingfisher/TruffleHog HMAC union and final redaction cleanup.

Official references: [Jobs get-run and pagination](https://docs.databricks.com/api/jobs/v2/get-run), [Jobs get-output fields, limits and retention](https://docs.databricks.com/api/jobs/v2/get-run-output), and [Azure job permissions](https://learn.microsoft.com/en-us/azure/databricks/security/auth-authz/access-control/).
