# Selected Azure configured package source — unregistered proposal

This local proposal has no CLI, hosted option, check registration or collector hook. It reads a configured stored ZIP source only; runtime bytes and continuous immutability remain UNKNOWN. It supports exact root classic Function sites and classic Windows App Service code sites with sufficient native hosting fields. Slots, Flex, containers, Linux App Service, missing hosting fields, local `WEBSITE_RUN_FROM_PACKAGE=1`, secret references, external/custom/sovereign endpoints and ambiguous URLs remain unsupported.

Call `preflight(options, scopes, named_checks, shared_service_account=...)` before constructing credentials or discovering resources. The strict boolean `content_secret_scans=true`, the exact check `azure.review.function.selected_package_source_secret_indicators` and an explicit native selection are all required. Wildcards, framework selection, private kinds and generic inventories grant no permission. Supplied malformed selections fail even while disabled. Do not enable this using a shared platform service account: the proposal rejects `shared_service_account=True`; future hosted wiring must derive that trusted flag from server authentication, never request options. Existing hosted option allowlisting and provider-specific platform-account restrictions stay unchanged.

Example selection, with illustrative IDs only:

```json
{
  "content_secret_scans": true,
  "selected_azure_function_package_sources": [{
    "site_resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Web/sites/selected-function",
    "blob": {
      "service": "blob",
      "resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount",
      "container": "packages",
      "object": "release/function.zip",
      "version": "2026-10-19T12:00:00.0000000Z",
      "format": "zip"
    }
  }]
}
```

Select one or two sites, each with one exact same-subscription Blob object. Include `version` only when the native URL contains that same `versionid`; omit it for a current-object URL. The native setting must match the selected canonical account/container/path and optional version. SAS parameters may appear in the native setting; they remain private and are discarded for all requests. Public accessibility, SAS validity, the app's managed identity permissions and application loading are never tested.

Use an existing caller-owned Azure transport able to obtain both ARM and Storage OAuth tokens for the same tenant and principal. An ARM-only pasted token is insufficient. The isolated entrypoint takes a fresh real Azure reader, transport, scopes, options, named check list, and trusted customer/credential context IDs. It refuses mixed inventory readers. No auth, token acquisition, grant, cloud deployment or permission change was performed for this proposal.

| Grant location | Required permission | Purpose |
| --- | --- | --- |
| Selected subscription | `Microsoft.Resources/subscriptions/read` | Exact subscription identity/tenant read |
| Selected site | `Microsoft.Web/sites/read` and `Microsoft.Web/sites/config/list/action` | Exact site GET and appsettings list POST |
| Selected storage account | `Microsoft.Storage/storageAccounts/read` | ARM ownership and primary Blob endpoint |
| Selected Blob container | DataAction `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` | Exact object HEAD/GET; Storage Blob Data Reader includes this |

The appsettings permission is security sensitive and broader than this reader's sole appsettings route; ordinary ARM Reader does not supply it. The documented list operation is a read despite using POST. See [Web Apps list application settings, 2025-03-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings?view=rest-appservice-2025-03-01) and [Microsoft.Web permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/web-and-mobile). Scope the grants as above; a Blob role can additionally use an appropriate Azure ABAC condition for selected objects. The implementation requests no listing, account-key export, SAS delegation, publishing credentials or secret-store access. [Get Blob permissions](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob) document the data read action and built-in role; [Storage permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/storage) document the account read action, and [Resources permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance) document subscription read.

The native read sequence is subscription GET → account GET → site GET → appsettings POST → Blob HEAD → conditional Blob GET with `If-Match` → Blob HEAD → appsettings POST → site GET. Appsettings/hosting projections must match at the two observations; Blob ETag, length and optional native version must match across HEAD/GET/HEAD. No redirect is followed. See [Get Blob Properties](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties), [Get Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob), [Storage account GET 2025-06-01](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2025-06-01), [Site GET 2025-03-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get?view=rest-appservice-2025-03-01), and [subscription GET 2022-12-01](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/get?view=rest-resources-2022-12-01).

Only captured supported regular text members are inspected, in memory, with Kingfisher SDK 1.4.0 and TruffleHog 3.92.5 using existing offline adapters. A clean result requires both engines and complete archive coverage. A bound positive survives partial inspection with incomplete coverage; denied, changed, unsupported or unbound sources cannot pass. Remove exposed literals, rotate confirmed exposed credentials, and rebuild using managed identities or supported references. No extracted credential is validated.

Azure documents that replacing a package at the same URL requires an app restart to load it. Consequently even an unchanged setting and a coherent Blob capture cannot prove which package is mounted. See [Functions package deployment](https://learn.microsoft.com/en-us/azure/azure-functions/deployment-zip-push) and [App Service run from package](https://learn.microsoft.com/en-us/azure/app-service/deploy-run-package). The proposal makes no mounted/executed-byte, atomic settings snapshot, lifetime retention or continuous immutability claim.
