# Optional Cloud Run deployed image inspection

Use `selected_cloudrun_services` with one explicit project, `content_secret_scans=true` and the named `gcp.review.artifact_image.content_secret_indicators` check. The installed collector resolves every positive-traffic and tagged revision of the selected services, binds its immutable image to native repository/project metadata, and scans each unique image through the existing dual offline detectors. Native GCR references use the shared verified URI parser.

The collector performs a fresh service HTTP read after image inspection; a cached replay cannot establish consistency. Native resource UIDs also prevent deletion/recreation from looking like an unchanged service. Changed service state, denied/missing active revisions, multi-container revisions, unsupported content or forged request provenance remain UNKNOWN. The consumer independently reconstructs the plan from scoped GET receipts and verifies the source requests belong to that image.

Bounds: 1–4 selected same-project services, up to 16 active revisions and four combined explicit/resolved images; existing image byte/platform/deadline limits apply. Negative results cover only the inspected immutable images, not mounted data, runtime-generated files or all project workloads. No credential verification or cloud writes.

The affected cohort passed 119 tests with one public-engine admission regression. Its directed selection recheck passed 47 tests and resolves that exact failure: 166 distinct latest passing nodes. These local native-schema HTTP and real offline detector receipts are not live-cloud or production validation. [Hashes, receipts and precise limits](cloudrun-image-integration.json).

Final acceptance: 175 combined integration/default-boundary/adapter tests passed; 61 later UID/default-boundary tests passed. The mixed Artifact Registry format fix passed 54 affected tests. These are separate cohorts, not a new complete suite.
