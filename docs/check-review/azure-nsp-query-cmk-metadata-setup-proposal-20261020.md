These two metadata proposals are unregistered. Importing their modules adds no
check, collector kind, permission, content read or production behavior.

The Network proposal examines existing native NSP associations with Storage
accounts in each selected subscription. It joins the association to its owning
perimeter and profile and to a full Storage account GET. Successful provisioning,
`hasProvisioningIssues: "no"` and `accessMode: "Enforced"` establish the declared
configuration. `Learning` and `Audit` are opposite configurations. Other PaaS
families, cross-subscription references, incomplete reads and unknown enums remain
unresolved. An empty association inventory does not establish that every PaaS
resource has an association. Traffic and access-rule suitability are untested.

The Encryption proposal lists each workspace's linked storage. A complete list
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

| Proposal | Read actions |
| --- | --- |
| NSP | `Microsoft.Network/networkSecurityPerimeters/read`, `Microsoft.Network/networkSecurityPerimeters/resourceAssociations/read`, `Microsoft.Network/networkSecurityPerimeters/profiles/read`, `Microsoft.Storage/storageAccounts/read` |
| Query CMK | `Microsoft.OperationalInsights/workspaces/read`, `Microsoft.OperationalInsights/workspaces/linkedStorageAccounts/read`, `Microsoft.Storage/storageAccounts/read` |

The finite bridge discovers metadata only within one to eight selected
subscriptions. It uses fixed ARM GET routes: NSP 2026-01-01, workspace 2023-09-01,
linked storage 2025-07-01 and Storage 2023-05-01. Limits are 128 calls, 128 output
items, eight pages and 64 rows per list, 256 KiB per response, one worker and a
120-second scheduling deadline. Each in-flight HTTP call has a 20-second timeout;
it can finish after the scheduling deadline. Budget exhaustion is unresolved.
Account/profile GETs are reused within a subscription capture.

No Storage data role, `listKeys`, Key Vault key/secret read, unwrap/decrypt grant,
workspace query permission, content flag or custom policy list is required.
Unknown response fields, tags, raw provider errors and CMK URI/name/version are
discarded. Only native IDs, safe setting indicators and fixed operation receipts
reach the snapshot. A dedicated GET guard reuses `AzureTransport` authentication,
requires HTTP 200, rejects duplicate/nonfinite JSON and bounds response bytes.

Coordinator integration must atomically admit the two new kinds, exact source
and native-fixture hashes, registration and canonical copy. Existing archived
manual requirements remain recorded; these declarations are related narrower
checks, not equivalent evidence for a complete organizational requirement.

References: [NSP association API](https://learn.microsoft.com/en-us/rest/api/network-security-perimeter/network-security-perimeter-associations/get?view=rest-network-security-perimeter-2026-01-01),
[workspace linked-storage API](https://learn.microsoft.com/en-us/rest/api/loganalytics/linked-storage-accounts/list-by-workspace?view=rest-loganalytics-2025-07-01),
[Query storage behavior](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/private-storage),
[Table account-key configuration](https://learn.microsoft.com/en-us/azure/storage/common/account-encryption-key-create),
[Storage 2023-05-01 schema](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/storage/resource-manager/Microsoft.Storage/Storage/stable/2023-05-01/storage.json).
