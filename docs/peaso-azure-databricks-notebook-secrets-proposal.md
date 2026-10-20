# Selected Databricks notebook SOURCE inspection proposal

This is a local **unregistered** optional reader proposal. It adds no production collector, registry, hosted selector, permission grant or infrastructure. The proposed check is `azure.review.databricks.selected_notebook_source_secret_indicators`, in **Secrets**, severity **high**, with no numbered compliance mappings.

After separate admission, reading requires the exact named check, `content_secret_scans: true` and `selected_azure_databricks_notebooks`, containing 1–4 exact `{workspace_resource_id, path}` targets inside explicitly selected subscription scopes. The workspace is a native ARM ID; the notebook path is absolute and case-sensitive. The selector cannot supply a host, URL, object ID, bearer, token audience, export format, query or remote reference.

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

`get-status` must return the selected exact path, `object_type=NOTEBOOK`, native positive integer `object_id` and supported `language`. The export is bounded base64 JSON SOURCE, with compatible optional `file_type`. A closing status read must name the same native object/language and optional native `resource_id`. If that read is denied or changes identity, the captured bytes are not scanned and the result is unresolved. Directory/repository/file objects, known Repos/Volumes/DBFS namespaces, explicit repository metadata, remote URL/ref selectors, outputs, run output and Secret Scope APIs are unsupported. No ancestor enumeration or Git origin association is claimed for an otherwise returned NOTEBOOK. Source code may contain references, but the reader does not follow or execute them.

The after-status read does **not** prove an immutable notebook content revision. The API's documented `modified_at` and size fields apply to files; this notebook-only subset rejects unexpected file-only status fields. Source edits can occur while the object ID remains the same. A result covers only the captured point-in-time SOURCE bytes, not current cells, execution, outputs, all workspace content or a Git commit. Independently selected Blob/File copies and immutable ACR images do not establish this notebook association.

Bounds are 4 targets, 20 native GETs, 2 MiB per wire response, 8 MiB total response bytes, 1 MiB decoded source per notebook, 16 KiB read chunks, and a 120-second checked deadline including scans. Existing shared caller call/cancellation budgets also apply. The service's 10 MB export ceiling is larger than this local subset. Empty/whitespace, invalid UTF-8, NUL-containing, oversized, noncanonical/invalid base64, partial, malformed and error responses cannot establish clean PASS. No directory/archive export, import, notebook/script execution or filesystem extraction occurs.

Both pinned Kingfisher 1.4.0 and TruffleHog 3.92.5 inspect source offline without credential verification. Both must complete before a clean negative. A fully bound completed-engine hit remains FAIL with incomplete coverage if the other detector or another selected notebook is unavailable; incomplete negatives remain UNKNOWN. HMAC locations and exact-value dedup hide source/path matches. Transient matched values join `configuration_secret_redactions`; the proposed finalization merges this ledger before the unchanged ML → logs → declarations → five-reader union and cleanup. Raw source, base64, paths, auth and native error bodies are not exported or kept in content caches.

Every native connection sets HTTP debug level zero. Directed tests enable global stdlib HTTP DEBUG and Azure HTTP-policy/identity loggers, use the real HTTP serializer/response parser with inert wire sockets, and require source/auth/error values to remain absent from logs. SDK-internal OAuth telemetry, TLS/network behavior and third-party credential transports are outside that inert-credential proof; SDK OAuth timeout/retry behavior also prevents a hard cancellation promise for in-flight token acquisition.

Primary references: [Entra token and already-assigned principal path](https://learn.microsoft.com/en-us/azure/databricks/dev-tools/auth/aad-token-manual), [workspace ARM GET](https://learn.microsoft.com/en-us/rest/api/databricks/workspaces/get?view=rest-databricks-2026-01-01), [get-status and SOURCE export](https://docs.databricks.com/api/workspace-objects/v1/export), [native notebook/folder ACLs](https://learn.microsoft.com/en-us/azure/databricks/security/auth/access-control/) and [Private Link reachability](https://learn.microsoft.com/en-us/azure/databricks/security/network/concepts/privatelink-concepts).
