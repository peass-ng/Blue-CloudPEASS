# PEASO web workspace

The React 19 / TypeScript / Vite frontend lives in `frontend/`. It uses same-origin `/api` calls, TanStack Query for API state, TanStack Table and Virtual for findings, and React Flow with ELK in a Web Worker for maps. Provider SVGs and the generic fallback are local assets. There are no remote icon or font requests and no Steampipe/Powerpipe integration.

## Reproducible local launch

Use Node 22.12 or newer and the Python environment described in the backend deployment documentation. From the repository root:

```sh
npm --prefix frontend ci
npm --prefix frontend run typecheck
npm --prefix frontend run build
python -m peaso.server
```

Start the collector and analyzer in separate terminals with the **same** `PEASO_STATE_DIR`, `PEASO_IDENTITY_DIR`, and authentication settings as the API:

```sh
python -m peaso.worker collector
python -m peaso.worker analyzer
npm --prefix frontend run dev
```

The development workspace is `http://127.0.0.1:5173`; `/api` proxies to `http://127.0.0.1:8000`. Override the backend with `PEASO_API_ORIGIN`, and the UI port with `PEASO_UI_PORT`. The backend must allow the actual UI origin for writes. Production assets are emitted into `frontend/dist`; the API image copies these into its static asset directory and serves the workspace and API from one origin.

Open Settings and enter the local server bearer token. Only this token is stored in `sessionStorage`, scoped to the tab. Cloud credentials remain in the form only until submission, are removed from mutation variables, and never enter localStorage or sessionStorage. Closing the dialog drops the remaining form state. Responses must be redacted by the backend.

Hosted sign-in, registration and recovery redirect to the existing HackTricks identity pages:

- `https://tools.hacktricks.wiki/login.html`
- `https://tools.hacktricks.wiki/register.html`
- `https://tools.hacktricks.wiki/forgot-password.html`

All API fetches include cookies; hosted authentication and entitlement remain server-verified. The UI does not fabricate a paid plan or bypass weekly quotas.

## Supported UI scope

Dashboard, Connectors, Scans, Hardening Findings, Exposure, Least Privilege, IAM Risk Map (declared defensive relationships), Network Map, and Settings are implemented. Scan history supports report downloads, status and cancellation; schedules support create/edit/pause/resume/delete. Failed requests have retry controls. Empty scan/findings/graph states distinguish absent evidence from passing security checks. Collector coverage remains visible beside results.

Connector forms map to native collector field names, with additional native auth and collector-options JSON for role chains, delegated credentials, discovery and collection budgets. The API's `/api/me` runtime capabilities gate hosted methods. Local CLI sessions, profiles, ambient identities and filesystem paths are clearly local-server features. Portable service-account JSON, access/session tokens, service-principal secrets/certificates, and safe inline Kubernetes configuration are available when the backend advertises them. Hosted AssumeRole uses approved onboarding and server-generated ExternalID, displayed in its connector inspector.

The catalog presents the live API's supported native checks and explicit upstream coverage totals. It also lists exact framework/checklist versions, reviewed source revisions, native/source check counts and pending coverage; the launch form can select exact checklist IDs alongside family names. Unported upstream checks are explicitly unavailable. Framework mappings, including HackTricks Cloud Best Practices, provide review guidance and do not imply certification. Unknown, denied, manual and empty check statuses are distinct from PASS.

Navigation uses compact scan summaries and paginated coverage, without loading complete reports. Findings use 200-row server-filtered pages, global facets and stable service/check/asset ordering, with an explicit loaded/total count and lazy evidence inspectors. Metadata search covers the complete assessment; evidence is fetched only when an inspector is opened. Hosted signed artifact responses are consumed with credentials omitted, no Authorization/cookies/referrer and no browser-storage persistence. Complete report downloads retain all evidence.

Finding names and evidence are rendered as React text, never injected HTML. When the API provides resource_name/native_resource_id, the asset table and inspector show those human/native labels while retaining the global digest for routing and selected configuration queries. Filters cover metadata search, severity, status, service, framework family and exact checklist/version IDs; grouping covers service/check/asset. The table virtualizes rows and remains horizontally scrollable on small screens. Dialogs use native modal semantics, Escape dismissal and visible keyboard focus; reduced motion and transparency preferences are honored.

The IAM view is labeled IAM Risk Map and shows declared access relationships only. The separate Privilege Escalation Map (`frontend/src/PrivescMap.tsx`) renders `GET /api/scans/{id}/graphs/privesc` with ELK in a web worker. It collapses aggregates by default, caps the initial render at 150 nodes, and supports search, neighbourhood focus, a minimap, provider/severity/confidence/hide-unknown filters, principal and technique cards, and query buttons backed by `/privesc/admins`, `/privesc/paths`, `/privesc/broad` and `/privesc/principals/{id}`. Scans without the `privesc` category show an empty state that suggests rescanning.

Graphs retain all ELK routed edge sections. Scope, network/namespace, subnet and service grouping use observed native relationships and preserve scope identities; GCP global/shared networks and Kubernetes namespaces retain their semantics. Display aggregates retain member IDs, underlying edge records, references and counts. Internal relationships remain available in group inspectors. Search and IAM risk filters include defensive high-risk grants, external trust and inactive identities, with adjacent context. A virtualized asset table and inspectors provide an accessible table alternative. The initial API projection can be expanded explicitly to retrieve complete underlying graph evidence, without routing large JSON through the hosted function response. Group inspectors retain internal relationships and references; large evidence previews are bounded with a full-evidence download. Collection caps are not injected by this UI; native full-inventory behavior and any explicit opt-in limits remain the API/collector contract. Display and API page budgets do not truncate the captured inventory. Map views are limited to 120 visible nodes and 400 edge groups, with pagination and explicit omissions. Effective authorization and routed reachability are never inferred from a drawn edge.

The Network Map also offers an explicit selected configuration-path assessment using captured global source/destination resource IDs, TCP/UDP, address family, destination port and optional source port. It shows allowed/blocked/unknown decisions and dependencies while stating application listening is unknown. It uses the owned immutable network snapshot, performs no cloud calls or probes, and does not automatically explore paths. Older reports without captured network facts produce an actionable API error.

The default mode is live API. The explicit Fixture demo switch is read-only, clearly labeled, and never persists across reloads. API scans marked `demo` or `offline_snapshot` display a separate non-live-evidence banner.

## Browser verification

```sh
cd frontend
npx playwright install chromium
npm run test:e2e -- --workers=2 tests/ui.spec.ts
```

Smoke coverage includes honest live empty states, explicit fixture mode, finding/compliance filters, inspectors, routed maps, bounded large graphs and the table alternative, native connector payloads, credential clearing after failed submissions, API errors/session authentication, escaped HTML-shaped names, mobile overflow and Escape dismissal. Screenshots are written into `frontend/evidence/` and were visually inspected during implementation.

The integration test uses a real API and native workers, an isolated **free** account, and explicitly identified offline snapshot evidence; it makes no cloud SDK calls. Provide a fresh account/state so the single free scan remains available:

```sh
PEASO_API_ORIGIN=http://127.0.0.1:8000 \
PEASO_LIVE_TOKEN="$YOUR_LOCAL_TEST_TOKEN" \
PEASO_LIVE_SNAPSHOT_PATH=/absolute/path/to/sanitized-snapshot.json \
npm run test:e2e -- --workers=1 tests/live.spec.ts
```

`PEASO_LIVE_TOKEN` is passed to the child process and never printed by the harness. Omit `PEASO_LIVE_SNAPSHOT_PATH` to exercise the native engine's explicitly labeled offline demo snapshot. `PEASO_KEEP_CONNECTOR=1` preserves the validation connector for coordinated persistence checks. The integration flow covers authentication, connector create/edit, schedules, scan launch/completion, report download, uppercase status filters, finding evidence, both real graph endpoints, and actual quota rejection. Set `PEASO_TEST_REACHABILITY=1` against fresh current workers to include the actual offline configuration-path endpoint. `frontend/evidence/live-run.json` records only scan/connector identifiers and the backend origin, never tokens.

## Validation limits

Browser fixture tests validate UI behavior; real API tests validate the native runtime using supplied offline evidence. They do not prove production cloud permissions, completeness of live collectors, effective IAM access or network reachability. Hosted identity/login redirect and cloud-provider authentication require deployment-specific validation. Validation evidence from 2026-10-10:

- `npm install`, `npm run typecheck` and `npm run build` passed. The final build emitted a 412.50 KB initial JS bundle, a 204.41 KB lazy graph bundle and a separate 1,593.72 KB ELK worker, without a bundle warning.
- Fifteen Playwright smoke tests passed in 15.7 seconds, including pagination across the complete dataset, signed artifact credential isolation, lossless graph relationship references, hosted capability gating and explicit unknown configuration decisions and removal of cached private data when authentication changes, human asset labels with global routing IDs retained, and exact checklist filtering.
- The latest real native API/collector/analyzer workflow, including the offline configuration endpoint, passed in 14.4 seconds. Scan `7164b73f132a4f9fbc366a541c78b12f` used an explicitly labeled native demo snapshot and the real free-account quota; the second scan was rejected by the API.
- Actual queued cancellation against a separate fresh native API passed in 5.8 seconds. No report or passing result appeared for the cancelled job.
- The actual complete Azure snapshot was analyzed by native workers and tested through the real API. Scan `14f032e8856349bf8a55d284eb3487b9` contained 9,153 resources and 8,666 findings. Browser navigation loaded a 2,650-byte summary and issued zero full-report requests. Search targeted a result beyond the first 500 records; lazy evidence, projected IAM, complete graph expansion and the virtualized table passed. The original report is approximately 47 MB, so this is a concrete large-dataset check, not a synthetic row-count test. The native run identifiers/counts are preserved in `frontend/evidence/large-native-run.json`. The rebuilt real Docker Compose run also passed in 54.4 seconds using the actual frozen Azure snapshot: scan `5a9297de3d7648a485959003c83df8ae` contained 9,146 resources and 8,666 findings, with a 3,671-byte summary and zero full-report navigation requests; its exact non-secret identifiers/counts are in `frontend/evidence/large-live-run.json`.
- Desktop/mobile, filters, both graphs, actual large-dataset views, checklist coverage and configuration dialogs were inspected as real browser screenshots under `frontend/evidence/`. Review caught and corrected hidden-checkbox horizontal overflow, service text overlap and clipped status labels.

Exact checklist finding filters use immutable version-to-native-check mappings captured at publication; older reports without those mappings cannot infer new version coverage. Hosted deployment, browser cookie flow, provider credentials and the public identity pages' challenge handling are being validated by the coordinator's infrastructure/QA workers. Local/native and signed-transport tests do not imply those external deployment checks have passed.

## Additional reproducible integration checks

```sh
# Fresh real API without workers: the job must remain queued until cancelled.
PEASO_API_ORIGIN=http://127.0.0.1:8000 PEASO_CANCEL_TOKEN="$YOUR_LOCAL_TEST_TOKEN" \
npm run test:e2e -- --workers=1 tests/cancel.spec.ts

# Fresh real API and native workers, using an actual sanitized complete Azure snapshot.
PEASO_API_ORIGIN=http://127.0.0.1:8000 PEASO_LARGE_TOKEN="$YOUR_LOCAL_TEST_TOKEN" \
PEASO_LARGE_SNAPSHOT_PATH=/absolute/path/to/azure-snapshot.json \
npm run test:e2e -- --workers=1 tests/large.spec.ts

# Read-only screenshot review of the existing scan in evidence/large-live-run.json (use its backend origin).
PEASO_API_ORIGIN=http://127.0.0.1:8000 PEASO_REVIEW_TOKEN="$YOUR_LOCAL_TEST_TOKEN" \
npm run test:e2e -- --workers=1 tests/review.spec.ts
```

Supply test tokens through process environment without logging them. The large test prepares its supplied snapshot through the real API so the browser does not paste a 13 MB snapshot into a credential form; normal connector form behavior is covered separately. Dedicated temporary local validation state can be removed after evidence review; it is not part of the repository or source release.

## Validated defensive release boundary

The last validated defensive frontend bundle is `index-BgqNVPw1.js` (412.50 KB), with `GraphView-D3qPoY68.js` (204.41 KB) and the separate ELK worker. All fifteen smoke checks passed in 15.7 seconds after the IAM Risk Map naming correction. The coordinator's matched source snapshot is the reproducible release boundary; later supervisor-owned App/API/engine additions are preserved in the shared workspace but were not authored, executed, validated or fixed by this worker. Those additions are not part of the defensive validation claims above. Do not substitute the mutable working tree for the matched validated source archive when reproducing this release.

All local API/collector/analyzer processes started by this frontend worker were stopped after validation. Temporary native state remains under the dedicated `/tmp/peaso-ui-worker-*` directories for the owner to review or remove; the coordinator's independently managed Docker Compose/cloud resources remain under its QA cleanup ownership. No commits were made by this worker, and no `untitled*.md` files were changed.
