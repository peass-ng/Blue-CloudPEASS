# Selected configured package runtime adapter (local, unregistered)

The new adapter exposes an actual callable collection path and a pure item/index consumer for the shared-hook owner. It does not register a check, add public CLI/hosted/server allowlists, or edit engine, collector, validation or registry hooks. Its declaration is a proposed public named check, not evidence of production integration. Explicit registry admission and shared-owner review are still required.

`azure.review.function.selected_package_source_secret_indicators` is the exact public check. Collection is default-off and requires the strict boolean `content_secret_scans: true`, that exact name in `named_checks`, and `selected_azure_function_package_sources`. A wildcard, framework, private collector kind, inventory or `_content_secret_scan_kinds` supplies no authority. Malformed supplied selectors fail even when disabled. Shared platform service-account use is rejected from a trusted owner argument; request options must never control that argument. Request-supplied `grant`, `plan`, and `_azure_function_package_runtime_plan` are rejected.

The existing native preflight accepts one or two exact root site IDs with one owned same-subscription Blob ZIP per site. Select lowercase canonical subscription scopes, the full site resource ID, full storage account resource ID, exact container and object, `format: zip`, and an optional exact native `version`. See the original [selector example](azure-function-package-source-setup-20261020.md). No discovery, object listing, user-supplied URL, slots, external/custom/sovereign endpoint, local package reference, container hosting, Flex or Linux App Service fallback is added. A native setting's SAS query parameters are discarded rather than used for authentication. There are no Kudu, publishing credentials, account-key, SAS-generation or secret-store reads.

## Owner integration sequence

```python
from peaso.collectors import azure_function_package_runtime_20261020 as runtime
from peaso.checks import azure_function_package_runtime_consumer_20261020 as check

# BEFORE constructing credentials, tokens, discovery clients or inventories.
plan = runtime.prepare(options, scopes, explicitly_named_public_checks,
    customer_context_id=trusted_customer_context,
    credential_context_id=trusted_credential_context,
    tenant_id=trusted_expected_tenant, principal_id=trusted_expected_principal,
    shared_service_account=trusted_platform_account_flag)
if plan is not None:
    planned = runtime.selection_context(plan)  # retain independently
    try:
        pending = runtime.collect(plan, authenticate=lambda: owner_azure_transport())
        expected = runtime.captured_context(pending,
            expected_selection_context=planned)
        # Retain expected through the owner's trusted run/index channel.
        # Never recover it from saved snapshot metadata.
        runtime.retain_union(pending, other_detectors_transient_matched_values)
        safe = runtime.finalize_union(pending, surfaces={
            "collections": mixed_collections,
            "metadata": mixed_metadata,
            "options": export_options,
            "errors": pending_errors,
            "cache": json_ready_cache_entries,
            "pending_writes": pending_exports,
        })
        package_snapshot = safe["package_snapshot"]
        # Replace EVERY owner surface with safe["surfaces"] before caching,
        # logging, returning, persisting, forwarding or building the final index.
        selected_scope = next(s for s, ids in expected["selection"].items() if ids)
        index = check.build_index(package_snapshot, scope=selected_scope,
            expected_index_context=expected)
        item = index["collections"][runtime.KIND][0]["items"][0]
        status, evidence = check.evaluate(item, index,
            expected_index_context=expected)
    finally:
        runtime.discard(plan)
        if "pending" in locals():
            runtime.discard(pending)
```

The opaque handles have no exported state and are not copyable or serializable. Plan consumption is atomic and one-use; malformed, replayed or fork-inherited handles fail before the authentication callback. Prepare copies the selectors and pins the exact local sources. Collection rechecks that pin before auth, creates an isolated real Azure reader and invokes the original native `collect` callable directly. There is no dynamic native execution, UUID override, global monkeypatch or scanner/parser implementation in the adapter.

Capture UUID generation remains inside the native producer. Its original same-process seal must validate before that return is associated with the retained plan. The independent expected selection, customer, credential, tenant, principal and request locators come from prepare, not envelope fields. The only added context field is the authentic controlled invocation's own capture ID. The original exporter then verifies the complete independent context and native facts before producing ordinary portable JSON. `captured_context` requires the separately retained planned context, and rejects any mismatch. An arbitrary saved native envelope is never an input to the runtime entrypoint.

The pure consumer imports only the existing standard-library portable contract and standard-library modules. `build_index` validates the exact package slice and `evaluate` verifies item membership, scope, provider and collection/snapshot agreement, then delegates to the accepted portable consumer. The expected index context is a separate argument. Save and reload both artifacts through separately owned channels; copying the snapshot's asserted metadata into that argument grants no independent provenance.

## Metadata union contract

An isolated native reader prevents native settings/Blob bodies from entering the shared inventory cache. Its specialized transient match set retains only HMAC-and-length descriptors before the original source clears matched plaintext. The native HTTP, ZIP parser, scanners and redacted result implementation remain unchanged. Other detector matches may join the same bounded union with `retain_union` before release.

`finalize_union` consumes the pending handle once and scrubs string keys and values across the package slice and every JSON-ready surface supplied by the owner, including mixed metadata, options, errors, cache entries and pending writes. It merges overlapping matched spans, rejects key collisions, bounds traversal at 65,536 nodes/32 levels/8 MiB of strings and scanning at 2,000,000 windows, and enforces the native 256-value/64-KiB-per-value/256-KiB-total match bounds. Overflow, unsupported objects or invalidated package assertions raise a fixed error and release no output. Native redaction overflow is carried forward even when native cleanup removes the transient flag. Descriptors are cleared on finalization, capture failure or explicit cancellation.

The owner must pass the **complete** union, replace all originals with the returned copies, and prohibit early cache/export/logging. This adapter cannot discover hidden shared caches or sanitize surfaces it is not given. That is an explicit integration contract still needing shared-hook-owner implementation and testing. Raw native settings, headers, URLs, package contents and exception text are never exposed by this adapter. Finalization removes the raw package-selection option from `surfaces["options"]`; the owner should omit raw selectors from other persisted surfaces too. The match union only removes detector-observed values and does not classify arbitrary strings as secrets.

## Permissions and native sequence

No permission changes, live credentials, authentication, cloud reads, infrastructure or deployment were performed. An owner-supplied transport must support ARM and Storage OAuth for the independently expected same tenant/principal. An ARM-only bearer token is insufficient.

| Selected scope | Required action | Native use |
| --- | --- | --- |
| Subscription | `Microsoft.Resources/subscriptions/read` | Exact subscription identity and tenant |
| Root site | `Microsoft.Web/sites/read` | Hosting before/after |
| Root site | `Microsoft.Web/sites/config/list/action` | Appsettings list before/after |
| Owned storage account | `Microsoft.Storage/storageAccounts/read` | ARM ownership and primary endpoint |
| Blob container/object condition | DataAction `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` | Exact selected HEAD/GET |

Appsettings permission is broader and more sensitive than ordinary ARM Reader. The adapter uses its one documented read operation despite the POST method: [Web Apps list application settings, 2025-03-01](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-application-settings?view=rest-appservice-2025-03-01). The action names are listed in [Microsoft.Web permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/web-and-mobile), [Storage permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/storage), and [Resources permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance). [Get Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob) identifies the Blob read DataAction and Storage Blob Data Reader role. Scope grants narrowly and consider a selected-object ABAC condition; this work provisions none.

The original nine operations remain subscription GET → account GET → site GET → appsettings POST → Blob HEAD → conditional Blob GET → Blob HEAD → appsettings POST → site GET. ETag/length/version and reference/hosting observations must agree. ZIP/member/byte/time/request bounds and detector versions remain those of the accepted native and portable sources. Kingfisher 1.4.0 and TruffleHog 3.92.5 run offline; credential validation is never attempted.

PASS requires complete, bound, clean coverage from both detectors. A bound detected secret is FAIL, including incomplete archive coverage. Incomplete clean, denied, mismatched, changed or unsupported sources are UNKNOWN. Coverage is the configured stored source only, and runtime bytes and continuous immutability remain unknown. [App Service package documentation](https://learn.microsoft.com/en-us/azure/app-service/deploy-run-package) states that replacing a package at the same URL requires an app restart to load it. The coherent stored capture cannot prove mounted or executed bytes.

## Local evidence and remaining admission

`peaso/collectors/azure_function_package_runtime_binding_20261020.json` pins exact runtime, consumer and reused native dependency bytes. It is a local consistency gate, not a remote signature or production admission. `peaso/checks/azure_function_package_runtime_cases_20261020.json` contains saved, sanitized native-derived CASES with independent retained index contexts. The source-bound receipt records focused test commands, results, artifact hashes and known failures.

```sh
.venv/bin/python -m pytest -q tests/test_azure_function_package_runtime_20261020.py
```

To explicitly regenerate the new fake-HTTP CASES without changing source pins, run `.venv/bin/python -m scripts.azure_function_package_runtime_proof_20261020`. After a reviewed local source edit, `--refresh-local-binding` replaces only the new consistency manifest before regenerating CASES; it does not admit the source to any registry. Neither command edits accepted predecessor files or receipts.

Tests use the original fake HTTP fixture with real native collection and both real offline detectors, then execute the pure consumer in fresh isolated interpreters. Denials, wrong references, changed sources, partial coverage, pre-auth default-off/deny paths, union bounds and independent-context failures are directed local evidence. No cloud authenticity follows from fake HTTP, a native process seal exported to JSON, a public digest or a self-asserted exporter flag. Portable evidence continues to report `cloud_authenticity: not_established`.

The shared owner still must review and install its explicit pre-auth dispatch, hosted option allowlist/platform-account guard, full union/cache replacement, trusted index-context persistence, registry/metadata admission and public engine/hosted tests. No active/production integrated claim is made until that explicit admission occurs.
