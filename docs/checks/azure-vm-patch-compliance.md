# Azure VM patch evidence

`azure.gap.compute_vm_system_updates_installed` evaluates each observed VM.
A configured patch mode or a successful installation request is insufficient.
The approved control policy supplies `maxReportAgeSeconds` and the required
installation/compliance evidence flags.

## Assessment

The VM must have a readable, current, successful
`instanceView.patchStatus.availablePatchSummary` (or the corresponding
`properties.instanceView` shape). A positive `criticalAndSecurityPatchCount`
proves missing security patches and yields FAIL. An unavailable, stale,
future-dated, or malformed assessment yields UNKNOWN.

A zero count establishes only the assessment condition. The remaining policy
requirements must also hold before PASS.

## PCI compliance evidence

When `requirePciCompliance` is true, the separate
`vm_patch_installation_compliance` record must bind to the same VM and capture.
Its `operationId` must match the readable native latest installation summary's
`installationActivityId`; that summary must report success. The record's
`installedAt` must be no earlier than the operation's reported start and
strictly before the successful assessment, with all timestamps within policy.

A matched, complete `NON_COMPLIANT` record proves failure. A `COMPLIANT` record
is necessary for PASS. A record for another operation, missing operation
identity, partial source, or unresolved chronology yields UNKNOWN. The record
is independently supplied compliance evidence; native VM configuration cannot
manufacture this organizational conclusion.

## Actual installation evidence

When `requireActualInstallation` is true, the native installation evaluator
also needs a completed, VM- and operation-bound Update Manager result, a
positive installed-patch count, consistent successful completion/counts,
resolved maintenance-window and reboot state, and a subsequent successful
zero-pending assessment. The latest native summary's start timestamp alone
does not prove completion.

When both flags are true, both requirements apply. A PCI COMPLIANT record does
not replace the completed native installation result. Unavailable required
proof remains UNKNOWN.

## Verification and limits

The focused tests use inert native API responses and the registered evaluator:

- `tests/test_peaso_azure_patch_cmk_postrelease_review.py`
- `tests/test_peaso_azure_patch_installation_hosted_pipeline.py`
- `tests/test_peaso_sw17_patch_ingress_next.py`

The tests do not install patches, execute guest commands, or modify a provider.
Their result proves the bounded evaluator behavior, not a guest package
inventory or complete PCI compliance for a live account.
