# Native perimeter and Query storage declarations

These two ordinary read-only metadata controls are registered locally. Their
current integration acceptance and production publication are tracked separately
in the [review ledger](progress.json). No content flag, company policy document,
role assignment or write operation is required.

The Network control examines existing native NSP associations with Storage
accounts in each selected subscription. It joins the association to its owning
perimeter and profile and to a full Storage account GET. Successful provisioning,
`hasProvisioningIssues: "no"` and `accessMode: "Enforced"` establish the declared
configuration. `Learning` and `Audit` are opposite configurations. Other PaaS
families, cross-subscription references, incomplete reads and unknown enums remain
unresolved. An empty association inventory does not establish that every PaaS
resource has an association. Traffic and access-rule suitability are untested.

The Encryption control lists each workspace's linked storage. A complete list
without a Query entry is not applicable. Existing Query entries require full GETs
of their owned Storage accounts. A customer-managed declaration needs
`encryption.keySource: Microsoft.Keyvault`, a valid key reference and
`encryption.services.table.keyType: Account`, because saved queries use Table
storage. A provider-managed account key or explicit Table `Service` key is the
opposite declaration. Missing account, key-reference or Table metadata is
unresolved. Key usability, grants, existing data, query packs, saved-query
migration and effective encryption are outside this check.

Reuse the existing Azure metadata credential. A scoped Reader role ordinarily
provides the following management-plane read actions; a custom role can instead
contain only the actions needed for the selected proposal:

| Control | Read actions |
| --- | --- |
| NSP | `Microsoft.Network/networkSecurityPerimeters/read`, `Microsoft.Network/networkSecurityPerimeters/resourceAssociations/read`, `Microsoft.Network/networkSecurityPerimeters/profiles/read`, `Microsoft.Storage/storageAccounts/read` |
| Query CMK | `Microsoft.OperationalInsights/workspaces/read`, `Microsoft.OperationalInsights/workspaces/linkedStorageAccounts/read`, `Microsoft.Storage/storageAccounts/read` |

The local production adapter supports all exact selected subscription scopes
under the existing scan budgets. The two controls require the native subscription
inventory: the adapter replaces its selected Subscription GET with one strict,
source-bound GET, derives tenant ownership from the actual row, and reuses that
row without an extra subscription request. Nine-subscription captures cover both
success and shared-budget exhaustion.

The ARM routes use NSP 2026-01-01, workspace 2023-09-01, linked storage
2025-07-01, Storage 2023-05-01 and Subscription 2022-12-01. Each metadata response
is limited to256KiB; each native list is limited to eight pages and64rows. The
existing reader owns total call/resource/deadline limits and cancellation; it is
not reset or replaced. Requests have a20second timeout. Exhausted or incomplete
coverage stays unresolved. Same-scope account/profile reads are reused.

No Storage data role, `listKeys`, Key Vault key/secret read, unwrap/decrypt grant,
workspace query permission, content flag or custom policy list is required.
Unknown response fields, tags, raw provider errors and CMK URI/name/version are
discarded. Only native IDs, safe setting indicators and fixed operation receipts
reach the snapshot. A dedicated GET guard reuses `AzureTransport` authentication,
requires HTTP 200, rejects duplicate/nonfinite JSON and bounds response bytes.

The source-bound admission preserves the original proposals and native fixtures.
These declarations are related narrower criteria: they do not replace archived
requirements for organizational approvals, effective traffic or proven key use.

References: [NSP association API](https://learn.microsoft.com/en-us/rest/api/network-security-perimeter/network-security-perimeter-associations/get?view=rest-network-security-perimeter-2026-01-01),
[workspace linked-storage API](https://learn.microsoft.com/en-us/rest/api/loganalytics/linked-storage-accounts/list-by-workspace?view=rest-loganalytics-2025-07-01),
[Query storage behavior](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/private-storage),
[Table account-key configuration](https://learn.microsoft.com/en-us/azure/storage/common/account-encryption-key-create),
[Storage 2023-05-01 schema](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/storage/resource-manager/Microsoft.Storage/Storage/stable/2023-05-01/storage.json).
