# Portable Azure Function package source proposal

This successor adds a same-process exporter at
`peaso/collectors/azure_function_package_portable_20261020.py` and a standalone
pure consumer at `peaso/azure_function_package_portable_20261020.py`. It leaves
the original collector/check, original 73-case test file and original receipts
unchanged. It has no registered control, collector hook, CLI/hosted option,
engine/index hook or validation/catalog change.

The portable output describes a configured stored ZIP source associated with a
selected classic Function site or supported App Service site. Runtime bytes and
continuous immutability remain `unknown`; credentials are never validated.

## Trust boundary

The original native collector signs its already-redacted projection with the
process-local `peaso.secret_scanning._KEY` through its existing `authentic()`
contract. A saved original envelope cannot validate in a fresh process, and the
existing fork handler replaces that key in the child. The exporter requires that
original seal to validate **before** constructing a portable snapshot. It does
not call `_seal()`, re-sign an input, recreate a native seal for the old check or
export the key. The original consumer remains unchanged and process-local.

The successor emits an ordinary `schema_version: "1.0"`, `provider: "azure"`
snapshot, with collections and a SHA256 `snapshot_id` compatible with
`peaso.snapshot.validate()`, including read-only item views. A public content
digest establishes consistency, not collector identity or cloud authenticity.
The pure consumer therefore reports
`cloud_authenticity: "not_established"` and the explicit boundary
`collector_assertions_content_digest_not_cloud_authentication`. The
`native_projection_verified_at_export` flag is a collector assertion, not an
offline cryptographic proof. It must not become an online-authentication claim.

This contract currently accepts an isolated snapshot containing only these
portable collections and their exact metadata. It does not admit an arbitrary
mixed inventory snapshot. The future shared index adapter must preserve the
validated source/context binding when integrating such a slice; generic format
compatibility alone does not complete that admission.

`expected_index_context` is a separate caller-owned input. It must come from the
controlled run's retained selection, subscription scopes, customer/credential
context, tenant/principal and capture association. Never extract the context
from supplied snapshot metadata and then present that copy as trusted. The
consumer compares the complete expected context, including exact ordered target
and request locators, with the snapshot's asserted context. It also checks every
row and receipt, including rows other than the selected one.

An attacker who can replace both a snapshot and its independently expected
context can manufacture coherent assertions. A checksum cannot solve that;
offline supplied snapshots have the same provenance limit as the existing CSPM
snapshot architecture. Recomputed checksums do not bypass the structural and
context checks tested here, but those tests do not claim cryptographic detection
of all coherent forgeries. Any future stronger authenticity requirement needs
an externally anchored signer/trust store owned by the integration layer.

## Same-process local adapter sequence

This is a design/example API sequence, not a new collection entrypoint:

```python
# The trusted owner performs existing source.preflight before constructing
# credentials and invokes the original native collector with a fresh reader.
native = source.collect(reader, transport, scopes, options, named_checks,
    customer_context_id=trusted_customer_context,
    credential_context_id=trusted_credential_context,
    shared_service_account=trusted_shared_account_flag)

# These identities and selections are retained caller inputs. Capture belongs
# to the caller's controlled native invocation; export verifies its old seal.
expected = portable_export.build_expected_context(targets, scopes,
    capture=native["capture"],
    customer_context_id=trusted_customer_context,
    credential_context_id=trusted_credential_context,
    tenant_id=trusted_tenant, principal_id=trusted_principal)
snapshot = portable_export.export_native_projection(native,
    expected_index_context=expected)

# Persist snapshot and retain expected context through an independently owned
# run/index admission path. A later process needs no process-local HMAC key.
status, evidence = portable.evaluate(saved_snapshot, selected_identity,
    expected_index_context=retained_expected)
```

`build_expected_context()` validates the existing explicit selection and derives
HMAC locators using the current process's existing helpers. It is a structure
builder, not permission to collect, and performs no fetching/authentication. It
accepts canonical lowercase subscription scopes; mismatched aliases are not
repaired. Raw target site/blob identifiers and principal IDs are not persisted.
The context contains the opaque selected site/blob identities, selection mode,
run IDs and nine exact request locators in native order. The capture ID is minted
inside the original collector and must be retained only from that controlled
invocation; a capture copied from an unverified saved envelope grants nothing.

The exporter takes a bounded copy, checks the original seal and exact envelope
schema, authorization, context and selection, then validates all native projected
facts against the independent context. Invalid input raises only the fixed
`native_package_export_rejected` error. It never repairs flags, populates missing
provider identity, creates detector successes or relabels an unknown capture as
complete. Valid denied/malformed/changed/unsupported native captures can be
exported as partial collections whose consumer result remains `UNKNOWN`.

## Checked native facts and bounds

The original source already validates native HTTP bodies, subscription/tenant,
account ownership and endpoint, site hosting and appsettings association, Blob
ETag/length/version coherence, content byte bounds and actual scanner results.
The adapter's same-process seal check is the boundary for those private native
reads; it does not claim to re-read raw bodies from the redacted projection.
Raw native bodies, headers, URLs, matched values and exceptions are absent from
the portable evidence. Web receipts do not expose an HTTP status field in the
original schema: their collected/bound assertions inherit the original sealed
collector's explicit HTTP-200 validation. No missing field is fabricated.

At export and consume time the successor requires closed native row/receipt
shapes, exact original schema/constants, trusted target order and complete index
selection, customer/credential/capture/tenant/principal equality and exact
site/blob request identities. The ledger is partitioned exactly by each row's
ordered receipt IDs with no duplicates, extras, orphans or unaccounted receipts.
Native operations are:

1. Subscription GET.
2. Storage account GET.
3. Site GET before capture.
4. Appsettings list POST before capture, with no request body.
5. Blob properties HEAD before capture.
6. Conditional Blob content GET.
7. Blob properties HEAD after capture.
8. Appsettings list POST after capture, with no request body.
9. Site GET after capture.

Method/origin/API version, request locator, native response locator type,
receipt identity/scope/capture, status/bound flags, authority, integer byte counts
and totals are checked. The original seal binds the original collector's fixed
body-free native request implementation; the redacted receipt schema does not
add a separately invented request-body digest.

Both detector names and pinned versions must match (Kingfisher 1.4.0 and
TruffleHog 3.92.5). Each part has exact opaque storage path, positive integer byte
count, a strict boolean completion flag and exactly two engine records. Leak
detectors must have completed in that part, locations must bind that exact part,
and the aggregate must equal the canonical merged redacted observations.
Unexpected error/raw fields, detector versions/statuses, free URLs and additional
locations are rejected. The consumer imports only standard-library modules and
does not import the key, collectors, old check, scanner adapters or registry.

| Limit | Value |
| --- | --- |
| Selected sites | 2 |
| Subscription scopes | 8 |
| Native requests | 18 |
| ARM response bytes | 512 KiB each |
| Captured ZIP bytes | 4 MiB each |
| Total transferred body bytes | 12 MiB |
| Text member bytes | 1 MiB each |
| Expanded bytes | 8 MiB each; 16 MiB total |
| Archive members | 128 each; 256 total |
| Aggregate redacted leaks | 128 per selected source |
| Leak locations | 512 per selected source |
| Portable JSON | 2 MiB, with bounded traversal/depth |

Original partial archive projections may retain scanned parts while final
expanded/member counters remain zero because parsing aborted. These facts remain
unchanged. A fully associated positive can therefore remain `FAIL` with
`complete: false`; an incomplete clean scan remains `UNKNOWN`. Complete clean
evidence alone can produce `PASS`. Redaction-incomplete projections export no
parts/leaks and cannot pass. Oversized or structurally invalid projections are
rejected rather than repaired.

## Finite local verification

```sh
.venv/bin/python -m pytest -q tests/test_azure_function_package_portable_20261020.py
.venv/bin/python -m pytest -q tests/test_azure_function_package_source_20261020.py
```

The new test file reuses the original fake native HTTP fixture and real offline
detectors for positive/clean/partial capture, then writes JSON and starts fresh
`python -I` interpreters loading only the pure consumer. The child asserts that
neither collectors nor `peaso.secret_scanning` were imported. Additional tests
cover actual native denials, malformed JSON, truncation, changed ETag/reference,
cross-subscription account response, wrong tenant/reference, unavailable second
detector, independent expected context, row/receipt/ref/flag/detector/error
tampering, normal snapshot read-only validation and input/output isolation.
Separate tests show that a fresh interpreter cannot export an old native seal
and a forked child cannot validate its parent's original seal while still being
able to consume portable JSON. No scanner signing key is persisted or exchanged.

## Remaining owner-controlled integration

The independent proof/receipt is a proposal review artifact. The AWS runtime
owner retains exclusive control of common engine/validation hooks. Before any
registration, the integration owners still need the actual before-auth explicit
selector path, trusted shared-account exclusion and customer/credential/tenant
context admission, native scheduling, same-process export placement, independent
expected index retention, and final mixed-metadata union redaction. Then they
must review collector/check registration, permissions, hosted/server option
allowlists, public engine/hosted tests and directed native admission for the
integrated source. None of those hooks are supplied or bypassed by this work.
