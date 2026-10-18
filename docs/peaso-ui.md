# PEASS'o CSPM web workspace

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

On a local API that reports `auth_mode: local`, a 401 on Settings offers a separate local-token dialog; an authenticated Settings view shows the account and supplied weekly quota without sign-in links. Only a token entered through that dialog is stored in `sessionStorage`, scoped to the tab. Cloud credentials remain in the form only until submission, are removed from mutation variables, and never enter localStorage or sessionStorage. Closing the dialog drops the remaining form state. Responses must be redacted by the backend.

Hosted sign-in, registration and recovery redirect to the existing HackTricks identity pages:

- `https://tools.hacktricks.wiki/login.html`
- `https://tools.hacktricks.wiki/register.html`
- `https://tools.hacktricks.wiki/forgot-password.html`

All API fetches include cookies; hosted authentication and entitlement remain server-verified. The UI does not fabricate a paid plan or bypass weekly quotas.

## Supported UI scope

Dashboard, Connectors, Scans, Hardening Findings, Exposure, Least Privilege, Privilege Escalation Map, Network Map, and Settings are implemented. Scan history supports report downloads, status and cancellation; schedules support create/edit/pause/resume/delete. Failed requests have retry controls. Empty scan/findings/graph states distinguish absent evidence from passing security checks. Collector coverage is in completed Scan details.

Connector forms map to native collector field names, with additional native auth and collector-options JSON for advanced role chains, delegated credentials, discovery and collection budgets. AWS access/session-key connectors accept up to 50 distinct role ARNs, one per line, with an optional per-role External ID; these become independent `auth.assume_roles` targets. The source account is included by default and can be excluded. One role is selected per AWS account. After the first successful context, later roles for that account are skipped before STS and appear as `duplicate_account_target` / `not_collected` credential-target coverage. Uncheck the source-account checkbox to audit that account through an assumed role. The API's `/api/me` runtime capabilities gate hosted methods. Local CLI sessions, profiles, ambient identities and filesystem paths are local-server features. Portable service-account JSON, access/session tokens, service-principal secrets/certificates, and safe inline Kubernetes configuration are available when the backend advertises them. Hosted AWS roles use the HackTricks CSPM IAM collector role with a server-generated ExternalID. The onboarding inspector provides target ARNs, trust JSON, a CloudFormation quick-create link when public S3 template hosting is enabled, a CSPM-hosted template download and CLI fallback, and StackSets guidance.

The catalog presents the live API's supported native checks and explicit upstream coverage totals. It also lists exact framework/checklist versions, reviewed source revisions, native/source check counts and pending coverage; the launch form can select exact checklist IDs alongside family names. Unported upstream checks are explicitly unavailable. Framework mappings, including HackTricks Cloud Best Practices, provide review guidance and do not imply certification. Unknown, denied, manual and empty check statuses are distinct from PASS.

Navigation uses compact scan summaries and paginated coverage, without loading complete reports. Findings use 200-row server-filtered pages, global facets and stable service/check/asset ordering, with an explicit loaded/total count and lazy evidence inspectors. Metadata search covers the complete assessment; evidence is fetched only when an inspector is opened. Hosted signed artifact responses are consumed with credentials omitted, no Authorization/cookies/referrer and no browser-storage persistence. Complete report downloads retain all evidence.

Finding names and evidence are rendered as React text, never injected HTML. When the API provides resource_name/native_resource_id, the asset table and inspector show those human/native labels while retaining the global digest for routing and selected configuration queries. Filters cover metadata search, severity, status, service, framework family and exact checklist/version IDs; grouping covers service/check/asset. The table virtualizes rows and remains horizontally scrollable on small screens. Dialogs use native modal semantics, Escape dismissal and visible keyboard focus; reduced motion and transparency preferences are honored.

The Privilege Escalation Map (`frontend/src/PrivescMap.tsx`) renders `GET /api/scans/{id}/graphs/privesc` with ELK in a web worker. It collapses aggregates by default, caps the initial render at 150 nodes, and supports search, neighbourhood focus, a minimap, provider/severity/confidence/hide-unknown filters, principal and technique cards, and query buttons backed by `/privesc/admins`, `/privesc/paths`, `/privesc/broad` and `/privesc/principals/{id}`. Scans without the `privesc` category show an empty state that suggests rescanning. Unresolved placeholders (`unresolved: true` aggregates) render grey and dashed with a "?" icon; their card explains the missing facts and what to collect. "Hide unknown" hides them, and they start hidden when a map has more than 20. The admin query lists proven paths (derived or conditional, from `include_unknown=false`) separately from principals that reach admin only over unknown edges. The initial view anchors on the admin targets at a readable zoom (at least 0.62), and the query sidebar can be collapsed. `tests/privesc-live.spec.ts` runs against a real backend when `PEASO_LIVE_TOKEN` and `PEASO_LIVE_PRIVESC_SCAN` are set. The backend still records declared IAM relationships in reports for analysis and CLI consumers; there is no dedicated IAM Risk Map page.

The Network Map (`frontend/src/NetworkMap.tsx`) uses provider tabs only when that provider has collected resources in the returned graph. AWS VPCs, GCP global/shared VPC networks, Azure VNets, and Kubernetes clusters are distinct network compounds. Subnets/subnetworks are network children; Kubernetes namespaces are workload groups, never subnets. A selected network opens its own compound and adjacent boundary groups, and a selected subnet or namespace opens its contained interfaces and workloads. Group and asset nodes use React Flow `parentId` geometry with ELK positioning of top-level network compounds. Collapsed groups carry explicit resource counts; supplied inter-network edges remain visible on collapsed boundaries. Identical CIDRs in separate account or project scopes remain separate networks.

The initial map requests the server's bounded 500-node network projection. Modest inventories preview multiple network compounds with subnets and security controls; selected networks retain named linked peer boundaries. The map renders at most 280 rich nodes and 400 edge groups, retains ELK root routes, and uses cross-hierarchy React Flow routes for child relationships. Network, subnet and resource pages expose all loaded groups beyond the first canvas page; the virtualized table searches loaded resource names, types, scopes and IDs and can open the matching subnet. Inventory pages accumulate until the server's `page_count` is exhausted, and projected resource groups can expand separately. Projection omissions, folded resources, hidden relationships and canvas edge-group overflow are shown as counts, and they never imply that an absent path is blocked. Network inspectors lazily request `/scans/{id}/resources/{resource_id}` when native configuration is stored by reference, then show identifiers, addresses, attachment relationships and provider rule rows as readable fields. Raw graph records are available under collapsed Technical details. Uncollected references remain visibly unresolved.

This map renders observed references and conditional rule candidates as lines
without arrowheads. Directional arrows are reserved for explicitly assessed
flows with a selected source, destination, protocol and port. Peering, a route
next hop, a firewall allow or overlapping CIDRs do not establish endpoint
reachability. The map can request a single captured-snapshot configuration
assessment or a batch of up to 24 loaded targets. The live map also automatically assesses both
directions among up to 12 loaded endpoints in the current view for IPv4
TCP/54321→443. It displays the sampled endpoint count and full directed-pair
decisions; larger loaded views expose further 12-endpoint windows and a final
single endpoint is paired with the previous window's last endpoint. A
selected second window can be compared in both directions through the bounded
grid API; cross-window results remain inspectable when their arrow is outside
the visible asset page. A collapsed-group arrow represents only those named pairs. Other
ports, protocols, address families and endpoints need explicit assessment or
another view. It performs no cloud calls or probes.

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

A historical defensive frontend bundle was `index-BgqNVPw1.js` (412.50 KB), with `GraphView-D3qPoY68.js` (204.41 KB) and the separate ELK worker. Its fifteen smoke checks passed in 15.7 seconds before removal of the dedicated IAM page. The coordinator's matched source snapshot is the reproducible boundary for that historical validation; later changes require their own test evidence. Do not substitute the mutable working tree for that matched archive when reproducing the older release.

All local API/collector/analyzer processes started by this frontend worker were stopped after validation. Temporary native state remains under the dedicated `/tmp/peaso-ui-worker-*` directories for the owner to review or remove; the coordinator's independently managed Docker Compose/cloud resources remain under its QA cleanup ownership. No commits were made by this worker, and no `untitled*.md` files were changed.
