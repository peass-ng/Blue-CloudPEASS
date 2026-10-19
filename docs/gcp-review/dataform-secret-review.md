Selected Dataform file scanning is implemented as an **unregistered candidate**. Root still owns intake, named-check planning, collector admission, registry, canonical copy and existing `secrets` group integration. No shared production files were edited.

The candidate check is `gcp.review.dataform.selected_file_secret_indicators`, using the new `dataform_selected_file` inventory. It requires `content_secret_scans: true`, the exact explicitly named check, and 1–8 exact `selected_dataform_files` selectors. Category, framework or default selection must never authorize these reads.

```json
{
  "project_scope": "projects/review",
  "repository": "projects/review/locations/us-central1/repositories/review",
  "path": "definitions/example.sqlx",
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

For a workspace, replace `commit_sha` with `workspace`, using the full resource name under the same repository. An optional `revision` must be a lowercase 40-hex Git SHA. Omitting it explicitly selects the current observed workspace file, recorded with a timestamp. Symbolic revisions are rejected.

Google documents repository `readFile` with `commitSha` and a base64 `contents` response; remote-backed repositories are excluded from this method. The adapter first checks native project identity and the exact repository name. It never falls back to a remote Git URL. [Repository readFile](https://docs.cloud.google.com/dataform/reference/rest/v1/projects.locations.repositories/readFile).

Workspace `readFile` uses `fileContents` and supports an optional Git `revision`; without it, the method returns current contents. The adapter also checks the exact native workspace name. Neither response echoes the path, revision or parent, so the evidence binds the exact HTTPS request to the native parent reads rather than claiming an independently verified Git object hash. A workspace negative concerns that selected read only. [Workspace readFile](https://docs.cloud.google.com/dataform/reference/rest/v1/projects.locations.repositories.workspaces/readFile).

The public discovery documents were fetched on 2026-10-19 without credentials. Dataform revision **20261011**, SHA256 `6585370be3b29ce84bc75d9f862b43be3138ee1d5951705447f98cf75f587bad`, confirms both schemas. Cloud Source Repositories revision **20261019**, SHA256 `1536fe81db6bb2f5ac02ee93fd00037f338c7975be9500aab61340f23f96b87f`, confirms metadata methods and the absence of a file-content REST method. Exact cached specifications and source URLs are recorded in [the machine-readable report](dataform-secret-review.json).

The reader uses a dedicated uncached HTTPS session with ambient proxy/auth disabled, no redirects, cleared cookies, a fixed native host and exact response URL checks. It bounds the raw stream before JSON, canonical base64 and strict UTF8 parsing. Content and selected names never enter normal transport JSON parsing, snapshots, request receipts or detector cache entries. Selector hashes provide opaque resource references; detector paths are constant. HTTP debug settings capable of printing query names or auth cause UNKNOWN before credential acquisition.

Kingfisher SDK **1.4.0** and TruffleHog **3.92.5** run through existing detection-only APIs. Shared fingerprints and finding deduplication collapse the same leak across both engines, repository/workspace reads and other services. No credential verification, managed-secret reads, checkout, compilation or execution occurs. Every read attempt has a safe receipt; the marker, coverage, item provenance, envelope and final snapshot link the exact per-file request IDs.

| Boundary | Limit |
|---|---:|
| Selected files | 8 |
| Decoded file | 256 KiB |
| File JSON response | 350,552 bytes |
| Parent metadata response | 16 KiB |
| All raw response bytes, including base64/JSON | 2 MiB |
| Content calls across selected files/scopes | 24 |
| Content time, also bounded by native deadlines | 60 seconds |
| Leaks / locations per selected file | 256 / 512 |

Repository files require two calls; workspace files require three. There are no list or directory-page requests. Native call, resource, cancellation and deadline limits still apply. The native page limit affects paginated supporting inventories; these unpaged file GETs have independent call and file bounds. Socket timeouts tighten before each bounded read, and detector timeouts share the remaining budget.

PASS requires the complete selected UTF8 text file, native binding, linked provenance and both pinned tools complete. FAIL requires complete detection and redacted indicators. Denied/missing parents, malformed identity or response schema, unsupported revision or remote repository, missing Content-Length, truncation, byte/time/call limits, noncanonical base64, binary content, tool errors and cancellation yield UNKNOWN. An omitted content field also yields UNKNOWN, including services that omit an empty default bytes field. PASS never establishes whole-repository, workspace or history secret absence.

Validation: **80 tests passed** with `.venv/bin/python -m pytest -q tests/test_gcp_dataform_secret_review_20261019.py`. Real installed tools detected synthetic indicators and merged one leak across both APIs. Tests also cover clean reads, defaults, malformed/denied streams, exact identities, bounds, cancellation, debug refusal, name/content/auth canaries and full native collector snapshots. The collector tests compile the exact proposed job hook into the actual collector and mock HTTP only; content is asserted absent at the real sanitize boundary.

Root delivery is in `/tmp/peasso-gcp-review-20261019/dataform-secret-proposals`: `integration.patch`, `patch-bases.json`, `admission.json`, public discovery specifications and `runtime-cases.json`. The full-index PASS/FAIL/UNKNOWN cases and snapshots were produced by the actual native collector with the proposed hook and real pinned detectors. `export_runtime_cases.py` reproduces them. Shared allowlist changes, if desired, must keep file reads on this dedicated reader rather than the JSON cache path.

A separate feasible follow-up concerns **legacy Cloud Source Repositories**. First bind `projects/PROJECT/repos/REPO` through native metadata and CRM identity, checking its Google-generated clone URL. Repository names can contain slashes; reject traversal or ambiguous encodings and derive only `https://source.developers.google.com/p/PROJECT_ID/r/REPO`. Do not follow mirror URLs. Google documents this HTTPS repository form and Git authentication; a noninteractive token flow must be verified before admitting a reader. [Native repository metadata](https://docs.cloud.google.com/source-repositories/docs/reference/rest/v1/projects.repos/get), [Google cloning documentation](https://docs.cloud.google.com/source-repositories/docs/cloning-repositories), [authentication](https://docs.cloud.google.com/source-repositories/docs/authentication).

The proposed protocol would GET that fixed base's `/info/refs?service=git-upload-pack`, then POST read-only upload-pack negotiation for an explicit immutable commit. This POST fetches objects and does not push changes. A bounded pack parser must verify commit/tree/blob hashes and selected paths, limit compressed and expanded bytes, delta depth, objects, files, calls and time, and return UNKNOWN when the server cannot provide the selected commit. It must prohibit receive-pack, arbitrary hosts, ambient credential helpers, checkout, hooks, submodules and LFS. This protocol is **proposed only**: no Git content adapter or Git call is included here. [Git HTTP upload-pack specification](https://git-scm.com/docs/http-protocol).
