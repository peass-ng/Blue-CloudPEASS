# Optional selected Azure stored-source inspection

This local, unregistered proposal reads explicitly selected source objects in
Azure Blob Storage or Azure Files. It can inspect a deployment artifact shared by
App Service, Functions, ML or Synapse when you already know its native storage
account, container/share and object path. A selection does not prove that a
particular application deployed or executed those bytes. SCM/publishing endpoints,
arbitrary package URLs and referenced artifacts are not followed.

Select `azure.review.storage.selected_source_secret_indicators`, set
`content_secret_scans: true`, and supply `selected_azure_storage_sources` with
1–4 exact targets. Broad categories, frameworks and metadata collection do not
permit these reads. Root registration and hosted validation admission remain
separate; this document does not assert deployed availability.

```json
{
  "connector": {
    "provider": "azure",
    "scopes": ["/subscriptions/11111111-1111-1111-1111-111111111111"],
    "options": {
      "content_secret_scans": true,
      "selected_azure_storage_sources": [
        {
          "service": "blob",
          "resource_id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/sourceaccount",
          "container": "sources",
          "object": "functions/source.zip",
          "format": "zip"
        }
      ]
    }
  },
  "checks": ["azure.review.storage.selected_source_secret_indicators"]
}
```

Use `service: "file"` and `share` instead of `container` for Azure Files. The
optional `version` is the exact native Blob `versionid` or existing File
`sharesnapshot` timestamp, for example `2026-10-19T12:00:00.0000000Z`. Omit it to
inspect the current named object. The reader never enables versioning or creates a
snapshot. Only conservative ASCII names/paths are supported: no URL, SAS, escaped
alias, leading slash, empty path segment, traversal or trailing dot/space. Blob
paths remain case sensitive; File path case aliases identify the same selection and
are rejected as duplicates. Select 1–8 explicit matching subscription scopes.

`format` is exactly `text`, `zip`, `tar` or `tar.gz`. It is an explicit parser
selection, not permission to execute code. Plain files and regular archive members
must be nonempty UTF-8 text. Binary files, nested archives, encrypted/unsupported
ZIP entries, duplicate paths, traversal, symlinks, special files, invalid CRCs and
incomplete archives cannot establish a clean result. No archive is extracted to
the filesystem. Formats such as 7z, RAR, xz, bzip2, PAX/GNU extension records and
application-specific package formats are unsupported.

## Minimum reads and OAuth

| Read | Fixed native operation | Minimum authorization |
| --- | --- | --- |
| Subscription identity | `GET management.azure.com/subscriptions/{id}?api-version=2022-12-01` | `Microsoft.Resources/subscriptions/read` on the selected subscription |
| Account identity | Exact account ARM `GET`, API `2025-06-01` | `Microsoft.Storage/storageAccounts/read` on the selected account |
| Blob properties/content | Named `HEAD`, `GET`, closing `HEAD`, service version `2023-11-03` | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`; **Storage Blob Data Reader** at the intended container, with supported object-path conditions when narrower access is required |
| File properties/content | Named `HEAD`, `GET`, closing `HEAD`, service version `2023-11-03`, `x-ms-file-request-intent: backup` | `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read` **and** `Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action`; optional **Storage File Data Privileged Reader** |

Management `Reader` alone does not authorize content. FileREST OAuth backup intent
bypasses file/directory ACL checks and is more privileged than normal SMB reads.
Keep it optional and restrict its RBAC assignment to the intended supported share
scope; do not describe it as one-object ACL-limited access. Microsoft's FileREST
OAuth guide specifies the data-plane share scope spelling `fileshares`, for example
`.../storageAccounts/{account}/fileServices/default/fileshares/{share}`. Review
existing inherited assignments because backup semantics can provide broad read
access. This reader does not need File Data Privileged Contributor, writes,
listKeys, account keys, SAS generation, decrypt, leases or publishing credentials.
It performs no role or permission changes.

Both ARM and Storage OAuth tokens must bind the same tenant and principal. Native
subscription metadata must name that tenant. The storage token audience is fixed
at `https://storage.azure.com`; an ARM-only pasted token cannot read storage data.
Use the configured identity's existing Storage audience access, or the connector's
existing separate Storage token input. No new credential field is introduced.
Custom endpoints, cloud suffixes, redirects, authentication challenges and
user-supplied hosts are rejected. ARM must return the exact account's standard
primary `blob.core.windows.net` or `file.core.windows.net` endpoint. Private DNS
routing for that standard host is compatible; alternate endpoint names, sovereign
cloud suffixes, DFS endpoints and NFS FileREST are outside this versioned reader.

## Captured content and limits

HEAD/GET/HEAD must agree on ETag and length. Blob reads also agree on any returned
version ID and use documented `If-Match` on GET. File reads agree on the native
file ID; the official Azure Files SDK compares response ETags rather than relying
on an undocumented FileREST `If-Match` header. A single bounded File GET and closing
HEAD provide the same conservative consistency check. Changed, overwritten,
partial, missing, denied, expired, malformed or oversized responses stay UNKNOWN.
Current-object evidence covers only the captured bytes, not future versions or a
lease/transactional snapshot. Explicit immutable versions/snapshots remain scoped
to their selected native version.

Limits are 4 objects, 24 reads, 120 seconds checked around reads/scans, 512 KiB per
ARM response, 4 MiB per transferred object and 12 MiB total response bytes. Plain
files and individual text members are limited to 1 MiB. Archives allow 128 members
and 8 MiB expanded bytes per object, 256 members and 16 MiB expanded bytes across
the scan, with expansion-ratio checks. Existing shared call/resource/deadline
budgets can stop collection earlier. Only unencoded full HTTP 200 responses with
bounded lengths are supported; no partial/ranged/chunked download is joined.

Pinned Kingfisher 1.4.0 and TruffleHog 3.92.5 inspect bytes offline without
credential verification. Both must finish before PASS. A bound observed hit from
a completed engine remains FAIL with incomplete coverage if another engine or
later supported-file coverage cannot finish. A no-hit incomplete scan is UNKNOWN.
Only redacted typed evidence and opaque HMAC object/member locations survive.
Matches are deduplicated across engines and sources. A bounded union scrub removes
matched values from mixed snapshot metadata and reader projections, including
common textual encodings; if that scrub cannot finish, affected projections are
withheld. This does not promise exhaustive decoding or detection of every secret.

Native contracts: [account GET](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2025-06-01),
[subscription GET](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/get?view=rest-resources-2022-12-01),
[Blob GET](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob),
[Blob properties](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties),
[File GET](https://learn.microsoft.com/en-us/rest/api/storageservices/get-file),
[File properties](https://learn.microsoft.com/en-us/rest/api/storageservices/get-file-properties),
[File OAuth scope and privilege](https://learn.microsoft.com/en-us/azure/storage/files/authorize-oauth-rest),
[per-operation data actions](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory),
and [official Files SDK ETag comparison](https://github.com/Azure/azure-sdk-for-python/blob/main/sdk/storage/azure-storage-file-share/azure/storage/fileshare/_download.py).
