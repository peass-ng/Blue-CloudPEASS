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

Dashboard, Connectors, Scans, Hardening Findings, Exposure, Least Privilege, defensive IAM relationships, Network Map, and Settings are implemented. Scan history supports report downloads, status and cancellation; schedules support create/edit/pause/resume/delete. Failed requests have retry controls. Empty scan/findings/graph states distinguish absent evidence from passing security checks. Collector coverage remains visible beside results.

Connector forms map to native collector field names, with additional native auth and collector-options JSON for role chains, delegated credentials, discovery and collection budgets. The API's `/api/me` runtime capabilities gate hosted methods. Local CLI sessions, profiles, ambient identities and filesystem paths are clearly local-server features. Portable service-account JSON, access/session tokens, service-principal secrets/certificates, and safe inline Kubernetes configuration are available when the backend advertises them. Hosted AssumeRole uses approved onboarding and server-generated ExternalID, displayed in its connector inspector.

The catalog presents only the live API's supported native checks and preserves its coverage limitations. Unported upstream checks are explicitly unavailable. Framework mappings, including HackTricks Cloud Best Practices, provide review guidance and do not imply certification. Unknown, denied, manual and empty check statuses are distinct from PASS.

Finding names and evidence are rendered as React text, never injected HTML. Filters cover search, severity, status, service and framework; grouping covers service/check/asset. The table virtualizes rows and remains horizontally scrollable on small screens. Dialogs use native modal semantics, Escape dismissal and visible keyboard focus; reduced motion and transparency preferences are honored.

Graphs retain all ELK routed edge sections. Scope, network/namespace, subnet and service grouping use observed native relationships and preserve scope identities; GCP global/shared networks and Kubernetes namespaces retain their semantics. Display aggregates retain member IDs, underlying edge records, references and counts. Internal relationships remain available in group inspectors. Search and IAM risk filters include defensive high-risk grants, external trust and inactive identities, with adjacent context. A virtualized asset table and inspectors provide a nonvisual alternative. Map views are limited to 120 visible nodes and 400 edge groups, with pagination and explicit omissions. Effective authorization and routed reachability are never inferred from a drawn edge.

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

`PEASO_LIVE_TOKEN` is passed to the child process and never printed by the harness. Omit `PEASO_LIVE_SNAPSHOT_PATH` to exercise the native engine's explicitly labeled offline demo snapshot. `PEASO_KEEP_CONNECTOR=1` preserves the validation connector for coordinated persistence checks. The integration flow covers authentication, connector create/edit, schedules, scan launch/completion, report download, uppercase status filters, finding evidence, both real graph endpoints, and actual quota rejection. `frontend/evidence/live-run.json` records only scan/connector identifiers and the backend origin, never tokens.

## Validation limits

Browser fixture tests validate UI behavior; real API tests validate the native runtime using supplied offline evidence. They do not prove production cloud permissions, completeness of live collectors, effective IAM access or network reachability. Hosted identity/login redirect and cloud-provider authentication require deployment-specific validation. Final test counts and any deployment limitations are recorded in the worker's completion report.
