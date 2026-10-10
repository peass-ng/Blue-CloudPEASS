# API, storage, authentication and worker handoff

- Task: `task_b13bbe13d50d`
- Current Dispatch: `ctx_114af9a3e95b`
- Worker terminal: `term_00c1a881-0a7f-46bf-aa95-fd929bf494d1`
- Coordinator terminal: `term_4d001b06-87f6-41e1-af9c-f350fbaa525d`
- Primary checkout: `/Users/carlospolop/git/Blue-CloudPEASS`
- No worker commits or stages. No `worker_done` has been sent for this Dispatch.
- This handoff contains no credentials or private inventory.

## Owned files

`peaso/server/{app,config,models,bootstrap,lambda_handler,scheduler_handler,__init__,__main__}.py`, `peaso/auth/{identity,billing,secrets,__init__}.py`, `peaso/storage/{sqlite,dynamodb,artifacts,reports,runtime,cost,__init__}.py`, `peaso/worker.py`, `Dockerfile.peaso`, `docker-compose.yml`, `.dockerignore`, `.env.example`, `tests/test_peaso_api*.py`, and `docs/peaso-local.md`. Coordinator separately authorized adding only `/.peaso/` to root `.gitignore` and this handoff.

Do not touch user `untitled*.md`. Engine, collectors, native checks, UI and infrastructure have separate owners. The supervisor team owns its later additions to the shared engine, Markdown/CLI, API query routes, report publication and artifact kinds. Preserve those primary additions and keep them outside this worker's defensive implementation, execution and feature validation.

## Completed defensive implementation

- FastAPI tenant checks on every connector/job/schedule/report/evidence lookup; local bearer identity with private persistent token, loopback default and allowed Origin/Host checks.
- Existing Cognito ID JWT verification: RS256 signature, issuer, audience, expiration, issued time, subject and token use. Existing secure refresh cookie is refreshed server-side; cookie writes require an allowed Origin.
- Live enabled/subject eligibility is checked before cached billing. Disabled/deleted/mismatched identities cannot be admitted. Schedules pause an ineligible account and continue processing others; identity service outages leave occurrences due.
- Stripe verifies the live enabled Cognito subject and verified email against customer email/metadata, the existing tools source, exact configured price, and active/trialing subscription. Browser flags and `custom:plan` do not grant paid quota. Paid billing cache is server-side for one hour, free for one minute.
- Fernet-encrypted connector auth and inline options, private key/token files, credential-free API errors, provider child output suppression and recursive credential redaction. Redaction preserves IMDS/security facts and handles credential-shaped Key/Name plus Value metadata and private PEM text.
- SQLite WAL/full sync, atomic quota + job + idempotency + connector checks, durable timeline, cancellation/deadlines, fenced heartbeat leases and reclaim on restart. Free one/paid ten per UTC Monday week across manual and scheduled runs. No refund for cancellation/failure.
- DynamoDB tenant repository with transactional quota/job/idempotency/connector revision and schedule occurrence; thirty-day job/idempotency retention, fourteen-day quota retention, logical expired job hiding. Private S3 adapter validates tenant-hashed references and can issue exact owned five-minute download URLs.
- Large complete JSON/Markdown reports published in the child, with manifests, bounded evidence-free finding indexes, lazy detail chunks, summary/coverage, complete graphs and precomputed projection. API lists use immutable tenant/report caches, not full evidence downloads.
- Exact framework version filtering uses native check ID mappings captured in each bundle. Human resource names/native IDs are retained beside globally scoped routing IDs.
- Pure TCP/UDP selected configuration query uses an owned sealed network sidecar; source report binding overrides untrusted imported ancestor metadata and the response must match the owned report digest.
- Customer-provided AWS keys retain strictly validated authorized role chains and existing ExternalIDs, with no platform fallback. Platform role source requires approved role ARNs and server-generated ExternalID. Hosted auth rejects arbitrary files/helpers/ambient customer identity; safe inline Kubernetes destinations are revalidated/pinned by the provider collector.
- User directive 6: API does not inject resource/page/call caps; those are explicit opt-in positive integers. Removed implicit 100-scope and 20-role-target admission caps. Job deadline remains visible in `/api/me.scan_timeout_seconds` and job `deadline_at`. Core/provider owners implement default full inventory/regions/scopes/pagination.
- Three Compose services, private state and identity volumes, root initialization followed by UID/GID 10001, health-gated workers, read-only filesystems and analyzer `network_mode: none` without the identity mount.

## Verification and exact limitations

Fresh isolated test environment: `/tmp/peaso-api-venv`. Package installation used editable project with test/hosted extras plus Moto. The last complete defensive source checkpoint passed 70 API/lifecycle/metadata checks. The current independent auth/storage run passed 39 checks. Official AWS DynamoDB Local independently passed nine checks, including concurrent one/ten quota reservations and duplicate-key single charging; its temporary container has been removed.

```sh
/tmp/peaso-api-venv/bin/python -m pytest tests/test_peaso_api_auth.py tests/test_peaso_api_hosted.py -q
```

Full integration command must run against the approved isolated defensive export, not the mixed primary engine:

```sh
python -m pytest tests/test_peaso_api*.py tests/e2e/test_api_lifecycle.py tests/e2e/test_credential_fact_preservation.py tests/e2e/test_metadata_credential_redaction.py -q
```

Actual Compose build/start completed a supplied snapshot scan, preserving IMDSv2 optional as FAIL. JSON 3,555 bytes and Markdown 3,023 bytes downloaded, duplicate key replay charged once, another scan returned 429, and all-container restart preserved report identity and quota. Analyzer inspection showed no network, no identity mount, no boto3, and offline `iam:PassRole` critical classification. The inert credential marker was absent from downloads/logs.

Actual QA Azure report transport measurement: 46,720,109 bytes, 8,614 findings, 9,153 resources; publication 1.679 seconds locally. Summary 1,660 bytes, finding page 200 rows 132,194 bytes, coverage 19,121 bytes and signed-style graph/report descriptors approximately 230 bytes. Detail evidence matched exactly. Publisher peak approximately 700 MB; independent cold API process including catalog peaked 98,238,464 bytes. This measurement used local validated references with simulated signed URL envelopes, not deployed S3/CORS. Separate Moto checks cover S3 encryption/reference behavior. Real hosted Cognito/S3/DynamoDB workflow and paid live billing have not been claimed by this worker.

Private/generated evidence paths, without credential contents:

- `/tmp/peaso-api-all-tests.log` — latest mixed-primary test run, not a release pass.
- `/tmp/peaso-auth-storage-only-tests.log` — 39 independent passes.
- `/tmp/peaso-dynamodb-local-tests.log` — nine official emulator passes.
- `/tmp/peaso-docker-results.json` and `/tmp/peaso-docker-verification.log` — local integration/restart proof.
- `/tmp/peaso-large-api-results.json` and `/tmp/peaso-large-cold-api-results.json` — bounded transport/memory measurements.
- `.cache/peaso-api-export-ready.json` — exact hashes of 31 primary files, with the overlap warning below; not whole-file approval for supervisor additions.
- Other owners' inventory/identity/resource ledgers remain private under `.cache/peaso-qa/task_02a312b5ac1f`; do not copy their contents into reports or delete their resources.

## Current blocker, failures and defensive section export

The supervisor additions are now in primary engine defaults and in three shared files. A transient undefined catalog hook caused 14 failed integration checks; a subsequent mixed run had 68 passes/two failed worker cases. Stop those whole-pipeline tests here: no supervisor chain feature is being authored, executed, validated or repaired by this worker. Earlier valid defensive proofs remain recorded separately.

Exact two current mixed-source failures from `/tmp/peaso-api-all-tests.log`:

```text
tests/test_peaso_api.py::test_worker_end_to_end_offline_report_and_downloads
  tests/test_peaso_api.py:225
  assert status["status"] == "completed", status
  AssertionError: 'failed' == 'completed'

tests/test_peaso_api.py::test_reachability_uses_owned_scoped_facts_and_rejects_invalid_ports
  tests/test_peaso_api.py:264
  assert response.status_code == 200 and response.json()["decision"] == "unknown"
  AssertionError: 409 == 200
```

The second case never obtained a completed report because its prerequisite analyzer job failed. These results are distinct from the 39 independently passing authentication/storage tests and the earlier 70 passing defensive checkpoint. No supervisor feature implementation was repaired to make these cases pass.

Export worker `ctx_19ab5df23d14`, Task `task_dd96221c2e73`, was reported failed by Orca. Its terminal is unavailable. Its advertised child `/Users/carlospolop/orca/workspaces/Blue-CloudPEASS/peaso-defensive-release` now fails process creation with `No such file or directory`; no testable immutable child manifest was received. Coordinator escalation `msg_fe85d4a3e8b0` records this. Question `msg_13a1190aa28e` initially proposed a replacement, but coordinator's later directive at 18:44 supersedes that: export was explicitly cancelled under directive 9 and removed, with **no replacement**. Continue only isolated auth/storage/quota/request-validation work, preserve supplied primary hooks, and record integration failures without executing or repairing the separate feature. Do not retry/relaunch the cancelled export.

Ready manifest hashes match primary content at capture but three files contain later supervisor sections. Safe export boundaries, without changing primary:

- `server/app.py`: retain owned auth, connectors, scans, bundles, summary indexes, finding details, summary, coverage, reachability and schedules. The owned graph handler supports only network/iam. Omit the added graph kind branch and the added helper/query route block between graph handling and schedules.
- `storage/reports.py`: retain `chunks`, `finding_summary`, `publish_report`, network/iam publication/projections and the sealed owned network sidecar. Omit the supervisor projection helper and added publication branch between graph projections and network sidecar.
- `storage/artifacts.py`: retain private storage/reference checks/presigning with defensive reference kinds only.
- Current other owned modules have no such references in the static check. Always verify new primary edits and hashes before export.
- Frozen engine/reports/analysis/checks/collector/UI must be supplied by their owners with approved native-only defaults and latest full inventory changes. Do not use dummy stubs, silently remove primary additions, or deploy mismatched source/image/UI.

Current permitted remaining work: isolated authentication, storage, quota and request validation fixes/checks, preserving all supervisor-owned primary sections. Whole-pipeline integration/exports are suspended by directive 9. Overall acceptance still requires a coordinator-approved tested source plus real hosted JWT/cookie auth, isolation, quota/idempotency, scheduled/cancelled transitions, private signed JSON/Markdown/CORS and large graph/finding transport; document actual limits and unverified paid/public signup gates. Those release and integration decisions remain with the coordinator and supervisor owners.

Latest isolated milestone after the initial handoff checkpoint: **46 tests passed** in authentication, hosted repository and new `tests/test_peaso_api_storage_edges.py`. Fixed DynamoDB `pause_schedule` so concurrent deletion returns false without recreating a row or halting other tenants; cross-tenant pause remains ineffective. Added deleted-identity rejection before cached paid lookup, concurrent durable credential-key initialization, conflicting same-key idempotency single charging, immutable encrypted input after connector deletion, rollback of a deliberately aborted job transaction and expired lease publication/renewal rejection. The new pause test is Moto verification; the earlier nine official emulator checks predate it. No engine evaluation or supervisor feature validation was performed in this isolated run.

```sh
/tmp/peaso-api-venv/bin/python -m pytest tests/test_peaso_api_auth.py tests/test_peaso_api_hosted.py tests/test_peaso_api_storage_edges.py -q
```

## Live resources and teardown

This worker created only local resources, no AWS deployment or cloud IAM mutations. Default Docker project `peaso` remains on `127.0.0.1:8000` with `peaso-api-1`, `peaso-collector-1`, `peaso-analyzer-1`, volumes `peaso_state` and `peaso_identity`. Owned completed offline validation scan is `352cd1a27143434fb7952f48d39beb59`; three connector attempts used an inert supplied fixture after a source-manifest build race. They consume the local free reservation one. Preserve for review or clean only proven owned fixtures once the coordinator authorizes cleanup; do not reset an actual user's quota.

```sh
# Inspect and stop this exact project; preserve private volumes by default.
docker compose -p peaso -f /Users/carlospolop/git/Blue-CloudPEASS/docker-compose.yml ps
docker compose -p peaso -f /Users/carlospolop/git/Blue-CloudPEASS/docker-compose.yml down
# Delete ONLY after confirming these are exclusively disposable task volumes.
docker volume rm peaso_state peaso_identity
```

Do not tear down other `peaso-test-qa-*`, native UI runner, or unrelated Docker projects. Temporary official emulator `peaso-dynamodb-verification` was already removed; port 8004 was released. Temporary actual-large local bundle directory is named in `/tmp/peaso-large-api-results.json`; remove only that validated temporary directory if no longer needed. The isolated `/tmp/peaso-api-venv` may also be deleted after handoff checks finish.

## Syntax state

No owned file is intentionally mid-edit. Syntax compilation passed for all 21 owned Python files immediately after this handoff write, using `compile(source, path, "exec")` without module execution. Syntax compilation is distinct from executing or validating supervisor feature logic. Preserve all uncommitted primary additions; coordinator is the sole Git committer.
