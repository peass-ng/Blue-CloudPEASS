# Native Key Vault key-version metadata (private V27 proposal)

This producer adds `vault_key` using a complete ARM vault inventory, paged data-plane key and version inventories, and an exact-version public-key GET. It uses the existing explicit Azure credential and Vault audience; it creates no credentials, grants, resources or endpoints. No network or cloud test was performed for this proposal.

Endpoints (2025-07-01): `GET /keys`, `GET /keys/{name}/versions`, and `GET /keys/{name}/{version}` on the ARM-verified vault hostname. Required permissions are `keys/list` and `keys/get`; no secret read, key release, backup, crypto operation or certificate private-key read is performed. Existing credentials without these permissions produce DENIED/UNKNOWN; no role template changes are proposed.

Each complete subscription collection contains one aggregate per native vault. A normalized child ID is `{vault ARM id}/versions/{key name}/{version}`; `native_key_id` and the projected JWK `kid` retain the exact native version URL. These IDs represent evidence hierarchy, not additional ARM resources. Current-version selection is deliberately unnecessary for the frozen algorithm predicate: it evaluates **every version**, not just the latest version. List order and creation timestamps are never used to guess the current version.

Only `kid`, `kty`, `crv`, public RSA `n`, `key_ops` and typed lifecycle attributes survive projection, before shared reader retention. Symmetric key bytes, private RSA/EC components, tags, release policies and attestation blobs are omitted. Native key operations are capability metadata and do not establish actual encryption use. `managed` would describe lifetime management, not generation/import provenance, and is not converted into provenance.

Scope, vault hostname, key name, version identity, duplicate detection, list/GET attribute agreement, reader call/page/resource bounds and explicit denial are checked. Incomplete pages, changed or foreign identity and empty version inventory for a listed key cannot become a complete collection. No fields named `encryption_use`, `algorithm_policy_approved`, `import_provenance` or `certified_hsm_provenance` are fabricated. Existing policy metadata and sibling namespaces are unchanged.

## Exact supported outcome boundaries

`azure.other.vault_key_approved_algorithm` still needs the explicit approved SW32 algorithm policy. Enabled versions lack measured encryption use and provenance from these endpoints, so they remain UNKNOWN. A fully measured inventory whose versions are all explicitly disabled passes the unchanged signed predicate under the approved policy; that is its literal disabled-version branch, not proof that any enabled encryption key is approved. Empty vaults remain UNKNOWN under the existing nonempty-version requirement. Missing policy remains UNKNOWN; denied native reads remain DENIED.

`azure.other.certificate_rotation_90_days` and `azure.other.certificate_rotation_180_days` are **not closed** by this patch. Their frozen predicates require a complete approved exposed-TLS service universe, live active endpoint binding by thumbprint/serial, and authoritative issuance. Vault object `attributes.created` is import/object creation time and cannot establish certificate issuance. Even reading public X.509 `cer` would not prove it is the active certificate deployed at every endpoint. No `vault_certificate` alias, fabricated issuance record or endpoint coverage flag is introduced.

This is safe supporting evidence, not a claim that three hard controls or all Key Vault controls are completed.

## Primary sources

- [Get Keys](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys?view=rest-keyvault-keys-2025-07-01): base key identifiers, attributes, pagination, keys/list.
- [Get Key Versions](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key-versions/get-key-versions?view=rest-keyvault-keys-2025-07-01): individual version identifiers and attributes, keys/list.
- [Get Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key?view=rest-keyvault-keys-2025-07-01): public key metadata and exact version lookup, keys/get.

Local validation: 19 new public collector → signed engine cases plus the unchanged draft-isolation guard, 20 PASS and zero skips. Original failed launch and initial DENIED expectation mismatch remain in separate JUnit files; neither changes product semantics. Tests use API-shaped responses, not real cloud observations.

## V2 pagination repair

The original candidate is superseded and its root HOLD remains immutable: a malformed falsy `nextLink=0` could terminate the generic reader and falsely PASS a disabled-only inventory. This helper now validates continuation presence/type/content and exact HTTPS hostname/path/port before the generic reader sees the projected response. Only omitted/null is terminal; `0`, false, arrays, objects, empty/whitespace strings and foreign URLs are rejected. Documented explicit `:443` continuations are accepted. No global Reader behavior changed.

V2 ran only the 26 new directed pagination regressions (both key and version lists) with normal conftest, 26 PASS/zero skips; the original 20-case gate was not repeated. Earlier failures and V1 HOLD remain in their original directories.
