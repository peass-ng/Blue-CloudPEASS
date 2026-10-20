# Optional Azure deployment-package inspection

Accepted locally for bounded native review; this addition is not yet published.
It is off by default and requires the exact selected check below.
See the [final local acceptance](check-review/azure-function-package-final-acceptance-20261020.json).

Select `azure.review.function.selected_package_source_secret_indicators` explicitly
and enable `content_secret_scans: true`. The reader inspects supported text in the
exact selected owned remote Blob ZIP referenced by the selected site's package
setting, using Kingfisher and TruffleHog offline. It does not execute code or
validate detected credentials.

Add this selector to the Azure collector options, replacing the example IDs and
object name with your resources:

```json
{
  "content_secret_scans": true,
  "selected_azure_function_package_sources": [
    {
      "site_resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/apps/providers/Microsoft.Web/sites/example",
      "blob": {
        "service": "blob",
        "resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/apps/providers/Microsoft.Storage/storageAccounts/examplepackages",
        "container": "packages",
        "object": "release.zip",
        "format": "zip"
      }
    }
  ]
}
```

Select the exact subscription scope. One or two site/object pairs are supported;
the storage account must belong to the same subscription as its site. Add `version`
inside `blob` to select an existing Blob version. Broad check selection does not
authorize package downloads. Do not put credentials or SAS URLs in these options.

## Read permissions

| Scope | Permission |
| --- | --- |
| Selected subscription | `Microsoft.Resources/subscriptions/read` |
| Selected site | `Microsoft.Web/sites/read`, `Microsoft.Web/sites/config/list/action` |
| Selected storage account | `Microsoft.Storage/storageAccounts/read` |
| Selected Blob container | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` DataAction; included in Storage Blob Data Reader |

ARM Reader alone cannot read application settings or Blob contents. The credential
must obtain both ARM and Storage OAuth tokens. The app-settings list API uses POST
to read settings; the scan does not change them. The reader does not retrieve
account keys or secret-store content, generate keys or SAS tokens, contact Kudu,
or execute application bytes. Detected credentials are not validated.

## Coverage

The selected site setting and Blob observations must agree across the capture.
Only supported regular text members are inspected in memory. PASS requires both
offline detectors to complete without detecting a supported secret across all
supported selected archive text. A supported associated positive remains FAIL
with an explicit incomplete-coverage notice. Missing, denied, changed, unsupported
or unbound evidence is UNKNOWN without a decisive supported positive.

Classic Function sites and supported Windows App Service code sites are covered.
Slots, Flex, container hosting, Linux App Service, local packages, external/custom
endpoints and unreadable or changed sources remain outside this reader's scope.
The current stored ZIP does not prove which package the app mounted or executed;
App Service can require a restart after replacing a package at the same URL.

## Saved JSON replay

Ordinary CLI replay of the saved JSON needs no companion state or custom criteria.
It labels the evidence `context_provenance: supplied_snapshot_assertions` and
`cloud_authenticity: not_established`. This checks the coherence of supplied
snapshot assertions; it does not establish cloud authenticity, and a coherently
replaced dataset can fabricate assertions. Offline replay does not authorize
credentials or package downloads.

References: [package configuration](https://learn.microsoft.com/en-us/azure/app-service/deploy-run-package),
[settings reads](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings?view=rest-appservice-2025-03-01),
[Blob reads and permissions](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob).
