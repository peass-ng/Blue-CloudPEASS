# PEASO coordinator handoff

Updated 2026-10-10. This is a work checkpoint, not a release acceptance report.

## Workspace and coordination

- Repository: `/Users/carlospolop/git/Blue-CloudPEASS`, branch `feat/peaso-cspm`.
- Code checkpoint: `2c865928e0711c24c7972ad681e4dcbdf1591485`. Earlier checkpoint: `3d9b19f`.
- Orca run: `run_405fd85cc6f5`; coordinator: `term_4d001b06-87f6-41e1-af9c-f350fbaa525d`.
- Root is the sole Git staging/commit owner. Never stage `untitled*.md`, credentials, Terraform state/variables, caches or build output.
- Workers share the checkout with the supervisor's team. Preserve their additive changes. Supervisor owns `peaso/privesc/**` and its engine, report, API and UI integration. Those supplied files are preserved in the checkpoint; this coordinator has not validated their evaluator or deployed the combined feature.
- Directives 9/10 require the full current HEAD in any release and forbid privesc exclusions. The rejected separate export task `task_dd96221c2e73` / `ctx_19ab5df23d14` was cancelled, released, and its child checkout removed. There is no replacement export. Old export readiness manifests are historical only.
- The user authorized one quota reset only after current usage exceeds 98%. Latest verified account rate read was 95% weekly with two reset credits; no reset was consumed. Account UUID: `a2ad32d7-3deb-4598-bcf2-94097213b892`. A private six-hour monitor polls every minute at `.cache/peaso-quota-monitor/monitor.py`; its PID, event log and persistent idempotent reset state are in that directory. It verifies the exact account home, uses a process lock, and stops after consuming at most one reset. Do not launch a duplicate or erase its reset state. This local coordination process is not product code or a cloud resource.

## Tasks and owners

| Task | Owner / active dispatch at this checkpoint | Handoff |
|---|---|---|
| API, authentication, storage, Compose | `ctx_114af9a3e95b` | [task_b13bbe13d50d.md](task_b13bbe13d50d.md) |
| AWS infrastructure/deployment | Original `ctx_4e2ff508fd91` settled failed on release blocker; documentation follow-up `ctx_737ca796b174` | [task_4075664c8e66.md](task_4075664c8e66.md) |
| Native registry and source audit | `ctx_b7fd18004ec0` | [task_71139019f73c.md](task_71139019f73c.md) |
| Live QA and temporary resources | `ctx_e2284cf3ad99` | [task_02a312b5ac1f.md](task_02a312b5ac1f.md) |
| Selected configuration reachability | Original `ctx_cb751dfa5df4` succeeded; documentation follow-up | [task_1658a0f448fe.md](task_1658a0f448fe.md) |
| AWS-A checks and main AWS collector | `ctx_f2b5ca158b85` | [task_8b67c08815d2.md](task_8b67c08815d2.md) |
| GCP/Kubernetes checks and collectors | `ctx_b9797ff7c175` | [task_bb3e099733d3.md](task_bb3e099733d3.md) |
| AWS-B checks and native engine/CLI | `ctx_741938b42211` | [task_eef1b206020a.md](task_eef1b206020a.md) |
| Azure checks and collector | `ctx_924afa35a1d8` | [task_66d382b1a714.md](task_66d382b1a714.md) |

The original frontend task `task_93da6f778646` succeeded and was released. Its build/type checks and 15 browser tests passed; see `docs/peaso-ui.md`. Later supervisor-owned UI additions require their own acceptance. Original core, collectors and analysis dispatches were settled and their terminals reused for the tasks above.

Use `orca orchestration worker-list --run run_405fd85cc6f5 --include-remote --json` for current authority; these IDs are a checkpoint. Consume coordinator mail with `orca orchestration check --json`; acknowledge only after processing every message and making any settled worker's reuse/release decision.

## Native engine and coverage

Shared immutable snapshots, bounded concurrent provider collectors, native offline checks, JSON/Markdown reports, database-free CLI operation, SQLite local job state, and DynamoDB/S3 hosted adapters are implemented. No upstream scanner runtime is required. Source URLs/licenses remain as provenance for reviewed native predicates.

Accepted materialized inventory at 18:45 UTC, from `upstream_manifest.json` and `native_catalog.json`:

| Provider | Unique native predicates | Ported references | Merged references | Rejected references | Pending references | Out of scope |
|---|---:|---:|---:|---:|---:|---:|
| AWS | 154 | 175 | 94 | 92 | 1975 | 0 |
| Azure | 98 | 77 | 116 | 412 | 1257 | 0 |
| GCP | 89 | 113 | 59 | 47 | 545 | 0 |
| Kubernetes | 787 | 626 | 11 | 111 | 134 | 0 |

All 561 references for other providers are `out_of_scope`. References and native predicates are different counts; compliance controls may share predicates. Rejected references include preserved manual attestations and individually reviewed invalid/obsolete predicates. Missing implementation or collection is not a valid rejection reason. Pending is not zero and comprehensive coverage has not been achieved. See [coverage.json](coverage.json) for the capture digest. Workers' unaccepted shards do not establish supported coverage; older `catalog_summary.json` may lag.

Source audit leader alone owns `active_reviews.json`, registry admission and regenerated catalogs. Each provider worker owns separate modules/review shards/tests. Pass, fail, missing/denied/unknown semantics are required before admission.

Directive 13 transfers pending IDs listed in `peaso/rulepacks/port_partitions_claude.json` to supervisor Claude workers: AWS-A 494, AWS-B 367, Azure 496, GCP/Kubernetes 326. The four existing owners were told to skip those exact IDs. Claude owns only `peaso/checks/claude_*.py`, `reviewed_claude_*.json` shards and `tests/test_peaso_checks_claude_*.py`; registry lead reviews/adopts complete modules and shards, conserving every source/control mapping and avoiding duplicate ownership. Collector ownership remains with the existing provider owners. Counts above predate this transfer's new implementations; a transfer itself does not close pending rows.

## Verification and release blockers

- Initial preservation syntax check: 161 Python files in coordinator work scope parsed successfully. Supervisor-owned privesc paths were not inspected by that check.
- Supervisor's latest reported full suite: **10971 passed, 4 failed, 1 error**. A fully green suite remains a release gate.
- AWS owner has received the four collector regressions: selected-profile region bootstrap expectation; non-read operation guard must run before SDK side effects; credential-report missing state/updated generation fixtures; leftover Organizations stub during teardown.
- GCP owner has received missing fixture stubs/expectations for new group, group-membership and principal-access-boundary facts. Do not fabricate successful empty collection.
- After the handoff commit, the coordinator independently reran `.venv/bin/python -m pytest -q tests/test_peaso_collectors_aws.py tests/test_peaso_collectors_gcp.py`: **145 passed in 2.98 seconds**. The reported collector regressions above are resolved in this targeted run; the full suite remains unverified. AWS owner subsequently reported 170 targeted tests passed, including parent metadata and guards that reject forbidden operations before client creation even if accidentally placed in an allow-list.
- Two earlier API e2e failures: `tests/test_peaso_api.py::test_worker_end_to_end_offline_report_and_downloads` (failed status versus completed), and `tests/test_peaso_api.py::test_reachability_uses_owned_scoped_facts_and_rejects_invalid_ports` (409 versus 200). Prior log: `/tmp/peaso-api-all-tests.log`, 2 failed/68 passed. API owner isolated auth/storage run passed 39 tests. Supervisor integration may have changed those results; no later full validation is claimed here.
- Selected offline reachability owner reported 204 integration tests passed and a 5010-resource selected query around 0.1 seconds; unsupported routing/policy context remains explicitly unknown.
- Real AWS/Azure/local-kind collections and older CLI round trips passed their stated scoped gates. They are not the new full-default gate. Large Azure UI and Compose artifacts were tested; original QA Compose projects have now been removed.
- GCP CLI and ADC require interactive reauthentication; no successful current live GCP/GKE acceptance is claimed.
- Combined-feature full-HEAD packaging/deployment remains outside this coordinator's permitted work scope. Preserve the supplied feature and do not reinstate exclusions. The supervisor owns its further validation/publication.

## Directive 6: default full collection

Default planning now selects supported inventory, with all enabled AWS regions and uncapped pagination/call budgets; limits are opt-in. Provider owners are auditing all accessible GCP projects, Azure subscriptions and Kubernetes namespaces. This still needs live acceptance.

The supervisor's previous failing AWS run had only `us-east-1`, 3 collected, 79 not collected, 58 unknown and 8 partial collections, 72 checks and an empty network graph. Those are the **old failing numbers**.

The exact new unfiltered CLI has not been rerun by this coordinator because its current default executes the supervisor-owned feature. QA is now assigned a direct collector-only full AWS run with `naxusai-admin`, without evaluator calls, to measure regions, collection states, API calls, pagination, resource/network inventory and duration. Label that evidence collector-only; it does not establish exact end-to-end CLI acceptance. New numbers are pending at this handoff.

Directive 11 read-only facts have been routed: Organizations parent records and ECR mutability to AWS; identity federation to Azure; Workspace admin-role metadata to GCP; metadata-only Kubernetes service-account Secret identities to Kubernetes. The Kubernetes collector must never fetch secret values and then redact: supported metadata negotiation must fail closed. Each change needs fixtures and truthful denied/unsupported coverage.

Milestone after the initial handoff: Organizations parent collection and Azure managed-identity federation have fixture evidence. GCP Workspace admin-role metadata and Kubernetes Secret metadata use explicit projections, denial/unsupported semantics and annotation scrubbing before cache. The coordinator independently ran the two new GCP/Kubernetes collection test files: 17 passed in 1.96 seconds. The owner reported a broader 308-test checkpoint. No successful live GCP/GKE run is implied.

## Hosted deployment state and continuation

Account `202533532952`, region `us-east-1`. Use the legitimate session wrapper:

```sh
assume wiki --exec 'aws sts get-caller-identity'
assume wiki --exec '/private/tmp/peaso-terraform-1.14.3/terraform -chdir=/Users/carlospolop/git/Blue-CloudPEASS/infra/aws init'
/private/tmp/peaso-terraform-1.14.3/terraform -chdir=infra/aws fmt -check
assume wiki --exec '/private/tmp/peaso-terraform-1.14.3/terraform -chdir=/Users/carlospolop/git/Blue-CloudPEASS/infra/aws validate'
assume wiki --exec '/private/tmp/peaso-terraform-1.14.3/terraform -chdir=/Users/carlospolop/git/Blue-CloudPEASS/infra/aws plan -out=/Users/carlospolop/git/Blue-CloudPEASS/.cache/cspm-continuation.tfplan'
```

The backend is the existing encrypted `terraform-state-hacktricks-wiki` bucket with dedicated key `cspm/terraform.tfstate`; never use or change `wiki/terraform.tfstate`. System Terraform 1.5.7 is too old for this backend configuration. Private `infra/aws/deployment.auto.tfvars.json` is ignored and must not be committed.

Only the reviewed two-create ECR bootstrap was applied: repository `hacktricks-cspm-worker` and its lifecycle policy. Repository ARN: `arn:aws:ecr:us-east-1:202533532952:repository/hacktricks-cspm-worker`. These are intended permanent application infrastructure, not temporary tests. No source, image, API, frontend or DNS was published by this worker. The 61-create scaffold plan has not been applied. `cspm.hacktricks.wiki` is not an accepted running deployment.

Existing Cognito pool/client and shared login/register cookie integration were inspected; they were not replaced. Paid quota uses server verification of existing Stripe ownership/subscription; no paid test entitlement was fabricated. The deleted temporary customer role was removed from the private allow-list, which is empty.

To continue deployment, first complete runtime/tests, provide actual immutable artifacts from full current HEAD under the supervisor's ownership, regenerate and review the exact dedicated plan, then apply only the reviewed saved plan. Stale frozen/export artifacts are ineligible. Do not apply the draft placeholder plan or mutate existing wiki infrastructure. Exact packaging/apply command details and current implementation limitations belong in the infrastructure handoff and `docs/peaso-aws.md`; historical export instructions there are superseded by directives 9/10.

## Temporary resources and teardown

Private ledgers live under `.cache/peaso-qa/task_02a312b5ac1f/`, mode 0600 inside a 0700 directory. Never commit raw ledgers containing credentials or owner tokens. At this handoff, all recorded original fixtures have explicit absence verification:

| Environment | Recorded fixtures | Ledger | State |
|---|---|---|---|
| AWS test account `947247140022` | Empty bucket, unattached VPC, security group | `resource-ledger.json` | All `not_found` |
| AWS test account | `peaso-test-622b8d3c82d54e02` SecurityAudit role | `audit-role-ledger.json` | `not_found` / independently `NoSuchEntity` |
| Wiki Cognito | Three suppressed free fixture users | `cognito-ledger.json` | All `not_found`; private credentials removed |
| Azure subscription `cfbcdcf4-cb4f-4e4e-9f3e-a6b3b3abadfc` | Five dedicated resource groups and recorded NSGs/VNets, 11 ledger records | `azure-resource-ledger.json` | All `not_found` |
| Local kind | Unique cluster, private kubeconfig, exact empty Docker network | `local-k8s-ledger.json` | All removed/verified |
| Local Compose | Original QA and cancellation projects | `compose-ledger.json`, `cancel-compose-ledger.json` | Containers/volumes/networks absent; unique images removed |
| GCP/GKE | None created | No resource ledger | Reauthentication blocker; nothing to tear down |

Repeat cloud cleanup safely through the ownership-checking helper if necessary:

```sh
AWS_PROFILE=naxusai-admin .venv/bin/python scripts/peaso_test_resources/session.py cleanup --ledger .cache/peaso-qa/task_02a312b5ac1f/resource-ledger.json
AWS_PROFILE=naxusai-admin .venv/bin/python scripts/peaso_test_resources/session.py cleanup --ledger .cache/peaso-qa/task_02a312b5ac1f/audit-role-ledger.json
.venv/bin/python scripts/peaso_test_resources/session.py cleanup --ledger .cache/peaso-qa/task_02a312b5ac1f/azure-resource-ledger.json
assume wiki --exec '/Users/carlospolop/git/Blue-CloudPEASS/.venv/bin/python /Users/carlospolop/git/Blue-CloudPEASS/scripts/peaso_test_resources/cognito_session.py --directory /Users/carlospolop/git/Blue-CloudPEASS/.cache/peaso-qa/task_02a312b5ac1f --cleanup'
```

These helpers reject unexpected contents, policies, resources and identity mismatches. Never use wildcard deletion, delete the existing user pool, or destroy application infrastructure to clean tests. Refresh ledger status before any new fixture lifecycle; write the ledger before creation and install a bounded finally/watchdog teardown. The QA task handoff is authoritative for exact resource identifiers and new measurements after this checkpoint.

### New isolated authentication fixture assignment

At 18:59 UTC the API owner was authorized to create one fresh suppressed **free** Cognito fixture using the existing QA helper, solely to verify real JWT and refresh-cookie authentication. Original users cannot be reused because they were deleted. This new lifecycle is planned at this update; check the API handoff and the new private ledger before deciding whether it is live. No existing users, pool/client, billing, entitlements, scanning pipeline or supervisor evaluator may be changed or invoked.

Directory: `.cache/peaso-api-live-auth/task_b13bbe13d50d/`; exact native identity is recorded in `cognito-ledger.json` before/after creation. The shared helper retains its original QA task tag; the API owner owns this separate invocation and must record it in its handoff before creation. The helper has a 40-minute bounded finally cleanup, and the worker must release/clean it immediately after validation. Repeat teardown if needed:

```sh
assume wiki --exec '/Users/carlospolop/git/Blue-CloudPEASS/.venv/bin/python /Users/carlospolop/git/Blue-CloudPEASS/scripts/peaso_test_resources/cognito_session.py --directory /Users/carlospolop/git/Blue-CloudPEASS/.cache/peaso-api-live-auth/task_b13bbe13d50d --cleanup'
```

Verify `not_found` for the exact ledger identity and deletion of `hosted-test-identities.json`; never print its token/password values. This fixture does not establish public Turnstile signup or live paid-user acceptance.
