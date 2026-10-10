# Peaso integration validation

This report records actual execution evidence for the supervised QA dispatch
`ctx_e2284cf3ad99` on 2026-10-10. Pending gates are not completion claims.
No secret values are recorded in this report or the private resource ledger.

## Access prerequisites (initial checkpoint)

| Provider/runtime | Actual command | Result | Remaining prerequisite |
| --- | --- | --- | --- |
| AWS disposable target | `aws --profile naxusai-admin sts get-caller-identity` | Account `947247140022`, IAM user `testenv` | Read permissions and fixture writes to be tested separately |
| Wiki hosting account | `assume wiki --exec 'aws sts get-caller-identity'` | Account `202533532952`, assumed `LabManagementOutOfScope`, one-hour session | Hosting belongs to infra; no QA writes performed |
| GCP | `gcloud config list --format=json` and active auth identity listing | Project `gcp-labs-ly3gvnn7`, region `us-central1`, active CLI account | Collector must explicitly select gcloud auth; API/service permissions not yet verified |
| Azure | `az account show` (metadata only) | Subscription `cfbcdcf4-cb4f-4e4e-9f3e-a6b3b3abadfc`, tenant `fdd066e1-ee37-49bc-b08f-d0e152119b04`, user auth | ARM/Graph permission coverage not yet verified |
| Kubernetes | `kubectl config current-context` | Exit 1: current-context is not set | Dedicated GKE fixture needed if no scoped private alternative becomes available |
| Docker | `docker info --format '{{.ServerVersion}}'` | Server `29.1.3` available | Compose definitions still being implemented |
| Python baseline | `.venv/bin/python -m pytest -q` | `10 failed, 179 passed, 8 errors in 20.37s` | All observed failures/errors import missing `termcolor`; install declared requirements and retest |
| Fresh CLI | Read package entry point and filesystem | `pyproject.toml` references `peaso.cli:main`; `peaso/cli.py` absent at initial checkpoint | Core implementation in progress |

## Evidence gates

| Gate | Status | Evidence / outstanding work |
| --- | --- | --- |
| Existing valid tests + integration suite | Passing checkpoint | After declared dependencies: `197 passed in 19.48s`; full native suite later `937 passed in 33.58s`; latest QA suite `34 passed in 3.84s`. Final full native suite awaits source freeze |
| Fresh real CLI scan, JSON + Markdown, four providers | Partial | AWS and Azure real fresh CLI + exact offline roundtrip + Markdown pass; actual local Kubernetes CLI pass. Real GCP/GKE pending expired credentials |
| Directive 6 DEFAULT full-scope release gate | Pending new requirement | Coordinator relayed new user requirement at 18:03 UTC: exact default CLI/API must enumerate all accessible regions/scopes, every supported inventory and complete pages; collection caps only explicit opt-in. Earlier bounded runs do not satisfy this gate. Exact default AWS command pending owner readiness |
| Immutable offline evaluation of identical snapshot | Passing checkpoint | Four provider tests deny socket connect and subprocess calls during offline evaluation, preserve input and compare exact repeated reports. Real AWS and Azure reports also matched exact reevaluation of saved snapshots |
| Category/check/framework selection | Passing checkpoint | Four providers tested category + check + framework intersections; unknown selectors rejected. Confirmed public empty lists default to all (coordinator/core contract), including all three selectors empty together |
| Native runtime removal | Passing Compose analyzer checkpoint | Actual container `shutil.which` found no steampipe/powerpipe/prowler/turbot binaries, installed distribution names contain none. Native deployment Python/build sources have no execution references; upstream source/catalog provenance remains data only |
| Compose API/UI connector → scan → status → report | Passing actual Compose checkpoint | UI Playwright consumed reserved free slot: actual saved Azure snapshot 9146 resources/8666 findings; 54.4-second workflow, lazy evidence, full dataset search and complete graph expansion passed. Input explicitly offline snapshot of real prior cloud collection |
| Persistence/restart/cancel/schedules | Passing actual Compose checkpoint | Completed large scan and full JSON/Markdown persist after API+collector+analyzer restart; quota remains 1 and second scan 429. Separate fresh free API-only Compose fixture proves queued cancellation → cancelled/report409, quota429 and schedule create/pause/delete; fixture containers/volumes/network removed |
| Hosted login/register and quota enforcement | Pending | Infra deployment and UI cooperation required; no fake paid entitlements |
| Tenant isolation and absence of secrets | Passing local test checkpoint | Two distinct free test subjects receive 404 for foreign connector/job/report/schedule reads and mutations; list results empty. Inert sentinel absent from API/errors/artifacts/SQLite; connector auth encrypted. Eight simultaneous scan requests produced one 201 and seven 429; hosted validation remains pending |
| Real provider section coverage | Pending | Explicit unavailable/unsupported evidence required |
| Playwright flows | Pending | Coordinate UI worker `ctx_ad1f69544b10` |
| Performance | Measured checkpoint | Actual measurements below; implementation still changing |
| Disposable teardown verified | Pending | Private ledger initialized before creation; zero creations at initial checkpoint |

## Fixture ownership

Private machine-readable ledger: `.cache/peaso-qa/task_02a312b5ac1f/resource-ledger.json`
(directory mode 0700, file mode 0600). Only exact unique `peaso-test-*` resources
entered there may be removed. Permanent infra and existing cloud resources are
outside QA ownership. No identities, credentials, resources or clusters have been
created at the initial checkpoint. Fixture operations verify identity before each
write and cleanup verifies resource absence. Additional private ledgers in the
same directory: `audit-role-ledger.json`, `azure-resource-ledger.json`,
`local-k8s-ledger.json`, `compose-ledger.json` (all 0600).
The same private directory also contains `cognito-ledger.json`, initialized
before the first temporary identity creation. Three new unique test emails
`peaso-test-*@example.invalid` were created in the existing authorized wiki
pool with `MessageAction=SUPPRESS` (no email delivery). Their native usernames
and immutable `sub` values are ledgered; random passwords/tokens remain only in
a separate private 0600 credential file, removed by the finally watchdog.
Each creation/password/auth/signout/delete write verifies the current AWS
account first. No pool/client configuration or plan attributes were changed.

## Actual live evidence (intermediate checkpoint)

| Run | Actual result | Coverage limitation | Teardown |
| --- | --- | --- | --- |
| AWS native live collector, disposable private bucket/VPC/security group | 259 resources, 307 findings; all three fixture IDs found; exact snapshot reevaluation matched | 23 collected, 24 empty, 1 unknown (`ReportNotPresent` for existing credential report), 2 not_collected and 2 partial (IAM page cap). Collector never generates credential report | All three ledger entries `deleted`, verification `not_found` |
| Azure broad collector initial bounded run | 1500 resources, 1436 findings; existing metadata populated | Global resource cap reached before dedicated RG; truthful partial statuses. Fixture-presence assertion failed, so gate not passed | Dedicated RG deleted; `not_found` |
| Azure native planned scan retest | 4912 resources, 8589 findings; exact saved snapshot reevaluation matched | During concurrent implementation default dependency planning changed; RG intentionally omitted by plan. Root `/` role_assignment returns HTTP 400 (reported Azure owner); exact inventory override support being added by core | Dedicated RG deleted; `not_found` |
| Kubernetes actual localhost kind cluster | `python -m peaso.cli scan --request ... --snapshot-output ... --output ...`; then offline `evaluate --format markdown`; 155 resources, 280 findings and actual inert Pod present | Local Kubernetes evidence only, not GKE. Restricted pause Pod, token automount disabled, deny ingress/egress policy, ClusterIP service, read-only namespaced role | Cluster containers not found; private kubeconfig removed, ledger children marked removed with cluster |
| GCP auth explicit ADC | SDK default credentials refresh attempted separately from selected gcloud credentials; `RefreshError` | Both explicit ADC and gcloud identity need refresh; no silent fallback and no credential material printed | No GCP resources created |
| AWS frozen fresh CLI | 254 resources, 356 findings, 36 native checks; JSON + Markdown generated; full offline report exactly equal with cloud credential config files absent | 23 collected, 24 empty, 1 unknown, 2 not_collected, 2 partial; all five categories populated. IAM graph 340 nodes/350 edges; network 70/111 | Earlier disposable bucket/VPC/SG already absent |
| Azure frozen fresh CLI after collector fix | 9146 resources, 8027 findings, 30 native checks; JSON + Markdown generated; exact offline report equality. All newly created RG/NSG/VNet found immediately | 27 collected, 27 empty, 1 unknown, 3 partial; IAM graph 5461 nodes/269 edges, network 4/1. Root assignments fixed with `atScope()`; root deny-assignment HTTP 400 and directory page caps remain explicit | Every Azure ledger row now `deleted`, `not_found`; one transient post-delete CLI error was retried and absence verified |

Fresh/offline CLI runs freeze one source build with a verified SHA256 before
execution, so concurrent implementation changes cannot mix evaluator versions.
AWS build digest `2617da1718d16c2c3922ea09a87b203fea14f4c2deadf13cbbb5fd8e33c507e3`;
Azure build digest `4bba25ea2ed0bb4ac307f10ceed0c4fb4dcfff36a5b70eb525fc5998d8a2fc5f`.
An earlier unfrozen comparison changed only graph output and a newly introduced
stats field during source edits; native findings were identical. That comparison
does not establish a product nondeterminism defect.

The initial kind invocation generated a shared Docker `kind` network implicitly.
QA preserved it until the coordinator independently verified its exact ID,
creation timestamp and zero attached endpoints and explicitly authorized cleanup
in message `msg_d1aeac9860c8`. Its dependency provenance was then recorded in the
ledger before deletion; exact-ID removal and not-found verification passed. The
fixture runner now preledgers and creates a unique tagged `peaso-test-*` network.

Temporary AWS SecurityAudit role `peaso-test-622b8d3c82d54e02` in authorized test
account was removed by its bounded guard at 18:06:51 UTC; exact IAM absence was
verified. All three original Cognito test users were globally signed out, deleted
and verified not found; private identity tokens/passwords and role-connector files
were removed. Both guard sessions exited 0. No static access key was created.
Only after actual hosted readiness may a fresh bounded lifecycle recreate the
same previously owned role ARN, after verified deletion, and new unique test users.

## Performance measurements

Wall-clock measurements use `time.perf_counter`, record collection/evaluation/
JSON canonical serialization separately, and exclude fixture creation/deletion.
These are single runs, not benchmark distributions. Bounds, SDK caches, provider
latency and concurrent implementation affect comparisons.

| Actual run | Collection seconds | Evaluation seconds | Serialization seconds | JSON bytes |
| --- | ---: | ---: | ---: | ---: |
| AWS 259 resources / 307 findings | 30.4811 | 4.6150 | 0.0095 | 1,242,149 |
| Azure 1500 cap / 1436 findings | 17.1833 | 9.7704 | 0.0412 | 3,647,451 |
| Azure 4912 resources / 8589 findings | 5.9691 | 27.6330 | 0.4511 | 37,130,508 |

Frozen fresh CLI total times (including collection, evaluation and writing):
AWS 27.4445 seconds; Azure 26.9091 seconds. The Azure full report plus embedded
snapshot and expansive policy evidence can be tens of megabytes; UI/API owners
are implementing paginated summaries, lazy graph details and bounded downloads.

## Defect routing and retests

| Actual defect or contract issue | Owner | Evidence / outcome |
| --- | --- | --- |
| Azure stale ResourceGraph index reported existing VNet as EMPTY | Azure/K8s | Independent `test_azure_eventual_inventory.py` reproduces stale-index / authoritative-ARM present case. Owner reconciles against ARM list; actual fresh fixture CLI now finds VNet, NSG and RG; retest passed |
| Azure root role assignments HTTP 400 | Azure/K8s | Owner added required `atScope()` filter; actual retest succeeds |
| Empty selectors changed during implementation | Core/coordinator | Confirmed contract: empty lists default all. QA adjusted this expectation, preserving denied/missing/tamper assertions |
| Explicit inventory request intersected away RG/directory fixtures | Core | Exact `options.inventories` override and `collect_all` added; frozen CLI broad collection now exercises all supported inventories |
| Worker redaction erased `MetadataOptions.HttpTokens` and routing/provider strings | API | Independent regression now passes: required IMDS retains PASS, optional retains FAIL, routing/profile/provider metadata preserved and actual credential sentinel absent. Included in latest 34 passing QA tests |
| Credential-shaped tag values survive native sanitizers | Current AWS/Azure/GCP/API owners via coordinator | Inert-only regression initially 4 failed/1 passed; after owner fixes targeted `5 passed in 0.34s`. Ordinary Name labels and HttpTokens preserved. No real secrets inspected and no cloud writes |

## Hosted prerequisites and limitations

The read-only Cognito prerequisite probe verified the existing pool
`us-east-1_7rbhezdKX`, app client `3g2u5ilb7kbte92lra40ji2ht0`, allowed
`USER_PASSWORD_AUTH`, SRP and refresh auth, username-by-email, and no app client
secret. Three disposable free identities successfully authenticated through
this existing client. A suppressed administrative fixture creation does not
prove public registration: public login/register submits require the existing
Turnstile flow, and that acceptance gate is separate.

Hosted API accepts a verified existing-pool ID JWT or the existing
`__Secure-ht_refresh` cookie; cookie writes require the configured CSPM Origin.
API owner confirms live paid entitlement uses verified email and Stripe
subscription, ignoring customer-controlled plan claims. No genuine paid
customer credentials were provided, so live paid-10 quota acceptance is pending
and cannot be replaced by a fabricated entitlement. Free-1 quota and isolation
will use only the new owned test identities once deployment is ready.

At this checkpoint hosted CSPM deployment is still owned by the infra worker;
QA has not created hosted connectors, jobs, schedules or report objects yet.
The original temporary role, three Cognito identities and both Compose projects
are now removed; exact container/volume/network absence verified for each
project. Hosted acceptance remains pending endpoint readiness, and fresh minimal
fixtures may be recreated only for that gate. No original credentials remain.

Latest QA suite: `34 passed in 3.84s`, including redaction preservation and
enqueueing a published exact framework checklist ID through the API.
Latest full suite before newly added regression cases: `937 passed in 33.58s`.
These checkpoints do not claim current source passes while owners still edit.

## Actual Compose and browser evidence

UI owner ran Playwright against the real owned Compose API with the sealed
previous real Azure snapshot. Scan `5a9297de3d7648a485959003c83df8ae`, connector
`3c635e8a27454f199e33fa393cd46d84`, 9146 resources and 8666 findings. The entire
workflow took 54.4 seconds; navigation fetched a 3671-byte summary and did not
fetch the complete report. Full-dataset search beyond the first 500 findings,
lazy evidence, projected IAM graph and full graph expansion/table all passed
with no page errors. UI evidence: `frontend/evidence/large-live-run.json`.

QA restarted API, collector and analyzer with the owned project volumes retained.
The same scan stayed completed; full JSON was 76,488,493 bytes and Markdown
68,890,724 bytes, snapshot IDs matched, hardening filter returned only hardening
findings, IAM graph remained available and free usage stayed 1. A second scan
returned HTTP 429; cancelling the already completed job preserved completed
state. Actual summaries: private `compose-before-restart.json` and
`compose-after-restart.json`.

For queued cancellation, a separate uniquely named free API-only Compose project
was created with its own fresh identity/state volumes. Its explicit offline
snapshot job stayed queued until cancellation; status became cancelled, report
returned 409, second scan returned 429, schedule create/pause/delete succeeded,
and no collector was started. This does not reset or bypass the primary or
hosted quota. Exact container ownership was checked and all project containers,
volumes and networks were removed and verified absent in
`cancel-compose-ledger.json`; actual result `cancel-compose-summary.json`.

Private actual outputs are in `.cache/peaso-qa/task_02a312b5ac1f/`:
`baseline.log`, `e2e.log`, provider `*-snapshot.json`, `*-report.json`,
`*-summary.json`, `local-k8s.log`, `k8s-cli-report.json` and
`k8s-cli-report.md`. Only count/status/timing evidence is reproduced here; private
cloud configuration snapshots are not committed.
