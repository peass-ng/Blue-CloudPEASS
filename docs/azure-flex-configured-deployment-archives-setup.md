# Selected Flex configured deployment-container archives

Name `azure.review.function.configured_deployment_container_archives_secret_indicators`, set `content_secret_scans: true`, and select at most two exact Flex Function sites with `selected_azure_flex_deployment_containers`. Each selection contains `site_resource_id`, `storage_account_resource_id`, and `container` in the same selected subscription. The check is off by default and uses the existing Secrets group.

```json
{
  "checks": ["azure.review.function.configured_deployment_container_archives_secret_indicators"],
  "connector": {
    "provider": "azure",
    "scopes": ["/subscriptions/11111111-1111-1111-1111-111111111111"],
    "options": {
      "content_secret_scans": true,
      "selected_azure_flex_deployment_containers": [{
        "site_resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Web/sites/selected-function",
        "storage_account_resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount",
        "container": "packages"
      }]
    }
  }
}
```

The reader checks the selected subscription tenant and storage account endpoint, then reads the exact site with `Microsoft.Web/sites/read`. The site must be a Linux Function with `properties.functionAppConfig.deployment.storage.type=blobContainer` and the exact selected account/container HTTPS endpoint in `value`. It lists at most four current BlockBlob ZIP objects in that container with `maxresults=5`, rejects a continuation marker, and reads each with bounded HEAD → ETag-conditioned GET → HEAD through the existing ZIP and two-detector helper. It compares the site, account, and container listing again afterward. An unsupported object, unreadable archive, unstable source, missing permission, or extra listing leaves a clean result UNKNOWN; a supported positive remains FAIL when other content is incomplete.

Grant `Microsoft.Web/sites/read` on the selected Function app and `Microsoft.Storage/storageAccounts/read` on the selected storage account for ARM provenance. Grant the **Storage Blob Data Reader** role at the selected container scope, `/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Storage/storageAccounts/{account}/blobServices/default/containers/{container}`, for OAuth List Blobs and Get Blob/Properties. Subscription read access is also needed to bind the tenant. A management-plane Reader role alone does not grant Blob data access. No account key, SAS, publishing credential, Kudu endpoint, secret store, deployment write, or arbitrary URL is read.

The finding describes **configured deployment-container archives**. The site configuration names a container, while the native deployment status API does not identify an active ZIP package. The reader does not choose the latest blob or claim which archive is running. The four-object and ZIP/text bounds are deliberate; unsupported archive members prevent a clean PASS. No historical object-version or execution guarantee is inferred.

Microsoft references: [Flex deployment storage](https://learn.microsoft.com/en-us/azure/azure-functions/flex-consumption-how-to), [Function ARM configuration example](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/create-or-update?view=rest-appservice-2025-03-01), [List Blobs REST API](https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs), [Storage Blob Data Reader role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage#storage-blob-data-reader).

This is a source-only handoff for the coordinator's guarded integration. The fixed technical denominator remains 29.
