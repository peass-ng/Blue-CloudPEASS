# Cloud Source Repositories content contract — 2026-10-19

**Historical pre-implementation contract review.** The selected-file reader has since been installed and passed 58 adapter/integration tests: see [current acceptance](sourcerepo-secret-review.json) and [current surface inventory](secret-surfaces.json). Live provider authentication compatibility remains unverified. The original findings below describe the earlier baseline, not current registration.

**Original disposition at initial review:** The inventory row `source_repositories_legacy` remains `proposed`, with `content_scan_integrated=false`. A restricted in-memory Git adapter is technically possible as new work, but neither the current transport nor declared dependencies supply it. No content capability is completed by this review.

Google's [release notes](https://cloud.google.com/source-repositories/docs/release-notes) restrict eligibility to existing customers, including organizations using CSR before June 17, 2024; new projects outside an organization cannot enable it. Current [migration guidance](https://cloud.google.com/source-repositories/docs/migration-guides) anticipates shutdown with at least one year notice. This review asserts no shutdown date or customer eligibility proof.

## Documented reads

| Surface | Documented contract | Content implication |
| --- | --- | --- |
| Native REST | [`projects.repos.get`](https://cloud.google.com/source-repositories/docs/reference/rest/v1/projects.repos/get): `GET https://sourcerepo.googleapis.com/v1/{name=projects/*/repos/**}`, permission `source.repos.get`, scope `cloud-platform` | Returns [Repo](https://cloud.google.com/source-repositories/docs/reference/rest/v1/projects.repos): `name`, `size`, `url`, `mirrorConfig`, `pubsubConfigs`. Metadata only. |
| Provider-hosted Git | [HTTPS cloning](https://cloud.google.com/source-repositories/docs/cloning-repositories) at `https://source.developers.google.com/p/{PROJECT_ID}/r/{REPOSITORY_NAME}` | Read access uses Git, not a REST file method. [`source.repos.get`](https://cloud.google.com/source-repositories/docs/configure-access-control) permits clone/fetch/browse. |
| Git smart HTTP | [Git specification](https://git-scm.com/docs/http-protocol): GET `{clone_base}/info/refs?service=git-upload-pack`, then POST `{clone_base}/git-upload-pack` | Upload-pack POST reads repository data. These protocol routes are not sourcerepo discovery methods or selected-file APIs. |

[Authentication documentation](https://cloud.google.com/source-repositories/docs/authentication) describes CLI local authentication, manually generated Git credentials, and SSH keys; SSH does not support service accounts. It does not establish that forwarding this application's REST Bearer header to the Git host works. Helper-free authentication for the chosen native identity is an unresolved admission gate. No credential-generation scripts were opened or executed.

Cached discovery revision `20261019`, SHA-256 `d57af046be45a2c792bc8295cd60bf703a03b92ea760f86e994f4ac7f78ed9f6`, contains no file/content REST method. Its artifact is `/tmp/peasso-gcp-review-20261019/secret-surfaces-sources/sourcerepo.json`. `Repo.url` is a clone locator. Neither Gitiles/raw/archive routes, arbitrary-SHA fetch, partial-clone filtering nor protocol v2 support is established by the reviewed provider sources.

## Current implementation and proposed minimum

`peaso/collectors/gcp.py:source_repositories()` lists metadata and hydrates IAM. Its transport allowlists Google API hosts, explicitly gates read POST routes, sends/parses JSON and caches projected metadata; it rejects the Git host and upload-pack POST. The dependency manifests declare requests/google-auth, with no Dulwich, pygit2/libgit2 or GitPython. Dataform's separate streaming content adapter and `peaso.secret_scanning.scan_content` offer reusable patterns for in-memory bytes and offline redaction, not a CSR reader.

A future implementation must pass these gates, in order:

1. Establish official helper-free HTTPS authentication compatibility. Admit only explicit opt-in, one canonical project/repository, one full immutable commit SHA and at most eight normalized relative file paths; reject invalid selections before credentials. Do not expand the generic REST host/POST allowlist.
2. Build an isolated binary smart-HTTP transport restricted to the constructed Google Git origin and upload-pack routes. Disable redirects, ambient netrc/proxies/cookies, alternate hosts, SSH, credential helpers and receive-pack. Bind repository metadata and clone locator to the selected canonical identity.
3. Support a deliberately narrow protocol subset: the exact commit must be advertised; never replace it with a branch tip. Unsupported older/unadvertised commits remain incomplete. Do not depend on provider filtering/shallow capabilities. A full pack is permitted only under the same hard limits; selected-file scanning cannot promise selected-file-only transfer.
4. Use a reviewed decoder or audited pinned library that enforces limits **before** allocation/inflation. A minimal version may accept only self-contained PACK v2 undeltified commit/tree/blob objects and reject all deltas, thin packs and tags. This intentionally rejects some ordinary repositories. [Pack formats](https://git-scm.com/docs/pack-format) include both offset/reference deltas and potentially external bases; a wire-size cap alone cannot bound expansion.
5. Validate framing, complete pack/checksum, object sizes/hashes and selected commit → tree → exact path → regular blob binding. Reject symlinks, gitlinks, LFS pointers and malformed/missing objects; never follow submodules, LFS or attributes/filters. Keep all packs and code in memory; no clone/fetch subprocess, checkout, temporary pack or object store. Scan only selected text blobs under opaque identities and retain only redacted results/static reasons.

Proposed ceilings, **not enforced today**: 8 MiB total wire, 256 KiB advertisement/1,024 refs, 4,096 objects, 1 MiB per object, 16 MiB cumulative inflated bytes, zero delta depth, 32 tree levels, 256 KiB per selected file/2 MiB selected total, four HTTP calls/no retries, 128 MiB isolated decoder address space, and 60 seconds including detectors with at most 10 seconds each. Count unselected objects and all intermediate expansion; check cancellation throughout. Reject excess rather than retrying with wider scope.

Acceptance must use offline protocol fixtures: exact commit/file success with both pinned detectors; scope/URL/redirect rejection before credential use; malformed/truncated framing, huge varints, compressed bombs, hash mismatch, delta/thin packs and unsupported entry types; bounded memory/time/calls and cancellation; no raw disk/log/cache/evidence retention or helper/hook/filter/LFS execution. Any unsupported contract, budget exhaustion or detector failure yields incomplete/unknown. Zero findings applies only after complete selected reads and both detectors succeed. Planner/check registration and cross-surface redacted dedup follow these gates; all are proposed.

## Evidence and limits

The [JSON companion](source-repositories-native-contract-review.json) records current local source hashes, the canonical inventory-row hash, primary URLs, downloaded documentation SHA-256 hashes and cache paths. Hashes describe the review snapshot; concurrent changes may supersede them. Public documentation was retrieved without authentication. Validation was limited to static inspection, JSON parsing and hash verification: no parser implementation, repository fetch, credentials, cloud query, pytest, runtime/shared/catalog/inventory edits, freeze or commit.

## Authentication follow-up

A [Google-owned helper implementation](https://raw.githubusercontent.com/google/googlesource-auth-tools/bcf66f086d941724b77eac6eb7d8eba085efc34e/git-credential-googlesource/main.go) explicitly supplies username `git-service-account` and the existing OAuth2 access token as password. The uninstalled binary transport now uses that fixed-host HTTPS Basic mapping directly; it does not execute a credential helper or change the general REST allowlist. Its 33 inert fixture tests pass. This is historical primary implementation evidence, not a live CSR authentication result. Decoder and native collector/check integration remain pending.
