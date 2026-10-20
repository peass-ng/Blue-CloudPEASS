# Selected Artifact Registry image secret review

Implemented an **unregistered** image predicate and bounded memory-only reader for explicitly selected immutable Artifact Registry images. Root owns registration, intake validation, shared hooks, canonical copy and admission. Existing AWS, Functions and configuration-scanning modules were not edited.

The native ID is `gcp.review.artifact_image.content_secret_indicators`, using the existing `secrets` finding type and dependencies `artifact_image`, `artifact_repository`, and `project`.

## Selection and authority

Inspection requires `content_secret_scans=true`, the exact named image check through the engine-owned `_content_secret_scan_kinds` gate, and a unique list of one to four bare immutable `LOCATION-docker.pkg.dev/PROJECT/REPO/IMAGE@sha256:digest` entries within one explicit project. Disabled/unselected scans create no reader and make zero additional calls. Tags, arbitrary hosts, GCR names, schemes, traversal and cross-project selections are rejected.

Existing `gcp_sbom_native._digest_uri` and native DockerImage rows bind URI, digest, repository and percent-decoded native image name. One complete native Docker repository and one matching CRM project must also exist. Numeric project authority uses the actual CRM v3 shape, `name=projects/123456789` plus `projectId`; no `projectNumber` field is invented.

## Native registry reads and integrity

A dedicated streaming session issues only fixed selected-host HTTPS GETs to `/v2/PROJECT/REPO/IMAGE/manifests/DIGEST` and `/blobs/DIGEST`. It disables environment proxies, ambient auth and redirects, clears cookies, and refuses changed response URLs, non-identity encodings, denied responses and auth challenges. The native Google access token is transiently supplied using the documented `oauth2accesstoken` Basic-auth form. No challenge realm, descriptor URL or redirected host receives credentials.

Manifest bytes must hash to the explicitly selected digest. Every descriptor has a bounded size and supported media type; config and layer streams must match their sizes and SHA256 digests before detection. The config must identify one supported Linux platform and an ordered `rootfs.diff_ids` list; every uncompressed TAR also hashes to its corresponding DiffID. All config/layer checks must finish before any complete verdict.

Supported formats are OCI image manifests and Docker schema-2 manifests, OCI/Docker config JSON, and uncompressed OCI TAR or OCI/Docker gzip TAR layers for Linux amd64/arm64. OCI indexes/manifest lists are UNKNOWN; no platform is guessed. Foreign/nondistributable layers, zstd, external descriptor URLs, malformed or missing layers, links, devices, unsupported archive extensions, unsafe/duplicate paths, nested archives and truncated/compressed bombs are UNKNOWN.

The existing bounded `aws_package_content_indicators.scan_tar` is reused unchanged, with a safe deadline facade and an additional nested-archive preflight. Files are read through memory streams; nothing is extracted to the filesystem or executed. All layers are scanned independently, including files removed by later layers. No final runtime filesystem, deployment or credential validity is inferred.

## Bounds and privacy

Limits are four selected images, 16 layers per image, 256 KiB manifests, 1 MiB configs, 8 MiB per compressed or expanded layer, 16 MiB compressed and 32 MiB expanded per image, and 2,000 archive members per image. A shared selected-project budget caps registry calls at 64, streamed bytes at 64 MiB and elapsed time at 120 seconds. Native transport call limits and cancellation apply to every GET; the TAR deadline facade reserves the existing dual-adapter timeout bound. Binary inspection never lists tags or pages through platforms; native metadata enumeration retains its existing collector bounds.

Only native immutable identity, descriptor digest/size/type, safe completion/count data and redacted leak observations survive. After verifying original layer digests, TAR header filenames are replaced with ordinal labels before the reused scanner; file bytes and layer order remain unchanged. Original paths are still checked for traversal and duplication. This prevents a credential embedded in a filename from leaking through the detector result cache, even when the file contains a different credential. Raw manifests/configs/layers, freeform descriptor annotations, credential values, response snippets and auth headers never enter Transport JSON caches or snapshots. Engine errors are replaced with a constant unavailable marker. Every successful or failed registry read has a safe method/operation/scope/category/digest/status request receipt without raw URL, content or auth strings. The exact per-image request IDs are retained in native row provenance, marker coverage and the image envelope, and receipts appear in final snapshot metadata, including denied reads.

Kingfisher 1.4.0 and TruffleHog 3.92.5 use the shared offline APIs with verification and updates disabled. Existing process-HMAC fingerprints and value deduplication yield one finding for the same leak across detectors, configuration, layers and services. PASS means no supported detector match in the complete bounded supported image. Any incomplete acquisition, tool failure or unsupported content yields UNKNOWN.

Failure evidence:

> A likely secret was detected in the selected immutable image configuration or a layer. The value is hidden; credentials were not validated.

## Integration artifacts and validation

Root proposal directory: `/tmp/peasso-gcp-review-20261019/image-secret-proposals`.

- `native-enrichment-and-selection.patch`: invoke enrichment after existing SBOM/native image collection and add the exact named-check mapping.
- `selection-validation.patch`: validate required immutable selection and its single project at intake.
- `admission.json`: declaration, existing secrets type, dependencies and root actions; no compliance mappings asserted.
- `runtime-cases.json`: real source-produced PASS/FAIL/UNKNOWN items with full native parent indexes; no raw synthetic secret retained.

The focused suite uses installed pinned detectors, synthetic OCI/Docker config/layers and streaming HTTP fixtures. It tests cross-tool/config/layer value deduplication, digest/size/DiffID mismatches, unsupported platforms/indexes/archives, limits, denial/redirect/challenge behavior, cancellation, native authority, selection gates and privacy. An actual GCPCollector mock-HTTP test follows the native CRM/repository/DockerImage pipeline, proposed hook, registry streams and final snapshot serialization.

Primary references: [Google immutable image naming and access-token authentication](https://docs.cloud.google.com/artifact-registry/docs/docker/pushing-and-pulling), [Google authentication](https://docs.cloud.google.com/artifact-registry/docs/docker/authentication), [OCI distribution protocol](https://github.com/opencontainers/distribution-spec/blob/main/spec.md), [OCI manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md), [descriptors](https://github.com/opencontainers/image-spec/blob/main/descriptor.md), [config and DiffIDs](https://github.com/opencontainers/image-spec/blob/main/config.md), and [layers](https://github.com/opencontainers/image-spec/blob/main/layer.md).

Focused acceptance: **64 tests passed in 16.67 seconds, no skips**, including real pinned dual tools and actual collector streaming-HTTP provenance/privacy tests. Both root proposal patches pass `git apply --check`.
