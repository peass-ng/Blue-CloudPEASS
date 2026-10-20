# Selected Azure ML asset text (local integration)

These two optional controls inspect captured text with pinned offline Kingfisher and TruffleHog. They are registered locally; current production-hook acceptance and deployment status are tracked separately in the [review ledger](check-review/progress.json). Each requires `content_secret_scans: true`, its exact named check and explicit targets in selected subscription scopes; validation must run before credential discovery. Neither control executes Conda, Python or containers, resolves packages or secret references, or validates detected credentials.

| Optional check | Option (1–4 targets, four combined) | Inspected bytes |
| --- | --- | --- |
| `azure.review.machine_learning.selected_environment_conda_secret_indicators` | `selected_azure_ml_environment_versions` | Returned inline `properties.condaFile` text from an exact workspace environment version |
| `azure.review.machine_learning.selected_code_file_secret_indicators` | `selected_azure_ml_code_files` | One exact selected plain file associated with a native code-version URI, named datastore and explicit storage account |

An environment selector is `{ "resource_id": "/subscriptions/SUB/resourceGroups/RG/providers/Microsoft.MachineLearningServices/workspaces/WS/environments/NAME/versions/VERSION" }`. Names and versions retain case. The supported inline subset is nonempty UTF-8 text containing a `dependencies:` declaration; pointers, empty/masked text, unsupported text and missing fields remain unresolved. Image and build-context declarations are ignored. The [Environment Versions Get API](https://learn.microsoft.com/en-us/rest/api/azureml/environment-versions/get?view=rest-azureml-2026-05-01) defines the returned field; reading it does not install anything.

A code selector uses this structure:

```json
{
  "resource_id": "/subscriptions/SUB/resourceGroups/RG/providers/Microsoft.MachineLearningServices/workspaces/WS/codes/NAME/versions/VERSION",
  "datastore": "source_store",
  "storage": {
    "service": "blob",
    "resource_id": "/subscriptions/SUB/resourceGroups/STORAGE_RG/providers/Microsoft.Storage/storageAccounts/ACCOUNT",
    "container": "sources",
    "object": "code/main.py",
    "format": "text"
  }
}
```

For Azure Files use `service: "file"` and `share` instead of `container`. Optional `storage.version` is an existing Blob version timestamp or File share-snapshot timestamp, following the existing selected-storage contract. No snapshot is created. Only supported plain files are admitted here; archives remain a separate manually selected stored-source surface.

The native [Code Versions Get API](https://learn.microsoft.com/en-us/rest/api/azureml/code-versions/get?view=rest-azureml-2026-05-01) returns `codeUri`. Supported forms are `azureml://datastores/NAME/paths/PATH`, the documented long datastore form with the exact selected workspace, and `https://ACCOUNT.blob.core.windows.net/CONTAINER/PATH` or the corresponding `file.core.windows.net/SHARE/PATH`. A trailing slash selects a declared folder prefix, within which the customer still selects exactly one file; it never authorizes listing. Without a trailing slash the object path must match exactly. The [datastore URI documentation](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-access-data-interactive?view=azureml-api-2) describes the long form.

The selected datastore's [ordinary ARM Get](https://learn.microsoft.com/en-us/rest/api/azureml/datastores/get?view=rest-azureml-2026-05-01) must return a coherent AzureBlob/AzureFile account, container/share, `https` protocol, standard `core.windows.net` endpoint and explicit subscription/resource-group parent matching the storage selector. Missing parent metadata is unresolved. A full storage-account Get must independently bind its selected ARM ID and native primary endpoint. Percent-encoded aliases, traversal, double decoding, SAS/query/fragment links, foreign workspaces, external URLs, registry assets, ADLS, local/Git/job references and unsupported metadata are not followed.

Stored datastore authentication does not grant this reader access. Safe returned AccountKey/Sas/ServicePrincipal/Certificate/None discriminators are discarded; the reader uses the customer's existing Azure credential for the selected storage object. An unexpected protected credential payload is rejected without scanning or exporting it. The official [SDK Get contract](https://learn.microsoft.com/en-us/python/api/azure-ai-ml/azure.ai.ml.operations.datastoreoperations?view=azure-python) defaults to excluding secrets; the separate `listSecrets` operation is never used.

## Minimum existing read access

| Read operation | Required action or data access | Audience |
| --- | --- | --- |
| Subscription Get and ML workspace Get | `Microsoft.Resources/subscriptions/read`, `Microsoft.MachineLearningServices/workspaces/read` | `https://management.azure.com` |
| Exact environment version Get | `Microsoft.MachineLearningServices/workspaces/environments/versions/read` | ARM |
| Exact code version and datastore Get | `Microsoft.MachineLearningServices/workspaces/codes/versions/read`, `Microsoft.MachineLearningServices/workspaces/datastores/read` | ARM |
| Selected storage account full Get | `Microsoft.Storage/storageAccounts/read` | ARM |
| Named Blob properties/content | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`; scoped Storage Blob Data Reader, preferably constrained to the intended source | `https://storage.azure.com` |
| Optional named File properties/content | Storage File Data Privileged Reader at the intended share, including privileged read/backup semantics | Storage |

ARM Reader can cover the metadata actions; it does not grant object contents. The [ML action reference](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/ai-machine-learning) distinguishes version/datastore reads from secret-listing and writes. Blob [Get authorization](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob) and File [Get authorization](https://learn.microsoft.com/en-us/rest/api/storageservices/get-file) define the data reads. FileREST OAuth uses `x-ms-file-request-intent: backup`; this optional privileged read bypasses file ACLs and is broader than ordinary file access. Reuse only an intentionally authorized existing source scope. No account keys, SAS creation, decrypt, builds, grants or write roles are requested.

Both [ARM and Storage OAuth](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory) use the existing Azure SDK credential. Tenant and principal must remain coherent across audiences. Existing private endpoint routing and DNS must already work; custom endpoint overrides are ignored.

## Evidence and limits

The reader binds native subscription/tenant/workspace identity, repeats asset/workspace metadata, and repeats datastore metadata for code. Blob/File content uses the accepted bounded HEAD/GET/HEAD reader with ETag and optional native version coherence. Closing metadata mismatch prevents scanning. This provides a point-in-time association, not an atomic transaction, immutable asset-at-creation source, original job source, executed bytes or whole-folder coverage. File snapshots and Blob versions identify captured objects, not when the code asset first referenced them.

A shared 120-second checked deadline, 48 native calls, 8 MiB total wire bytes, 512 KiB per ARM response and 256 KiB per selected text body bound this reader. Reads are uncached, named GET/HEAD only and never redirect. SDK OAuth acquisition has its own timeout/retry behavior; the checked content deadline does not hard-cancel an in-flight SDK credential request.

Clean PASS requires supported nonempty text, full native binding and both engines completing. Unreadable, partial, denied, changed, malformed, masked, empty or unsupported negatives remain UNKNOWN. A bound completed-engine hit remains FAIL when another detector or selected source cannot complete. Values are hidden and never externally validated. HMAC locations and exact-value dedup feed the existing transient union-redaction recipe before cleanup. Manually selected Blob/File copies or ACR images alone do not establish ML asset association.
