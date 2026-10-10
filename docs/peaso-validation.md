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
| Existing valid tests + integration suite | Passing checkpoint | After declared dependencies: `197 passed in 19.48s`; QA suite `21 passed in 3.51s`. Full native suite rerun pending ongoing owner edits |
| Fresh real CLI scan, JSON + Markdown, four providers | Pending | Core CLI and live fixture runs |
| Immutable offline evaluation of identical snapshot | Passing checkpoint | Four provider tests deny socket connect and subprocess calls during offline evaluation, preserve input and compare exact repeated reports. Real AWS and Azure reports also matched exact reevaluation of saved snapshots |
| Category/check/framework selection | Passing checkpoint | Four providers tested category + check + framework intersections; unknown selectors rejected. Confirmed public empty lists default to all (coordinator/core contract), including all three selectors empty together |
| Native runtime removal | Pending | Inspect deployment and runtime path; legacy tests may mock historical runtimes |
| Compose API/UI connector → scan → status → report | Pending | API/Compose owners implementing |
| Persistence/restart/cancel/schedules | Passing local API checkpoint | Real SQLite/FileArtifacts/worker subprocess lifecycle survived recreated API/analyzer. Queued cancellation prevents work, report before completion is 409, due schedules consume server free quota. Compose restart validation pending |
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

## Actual live evidence (intermediate checkpoint)

| Run | Actual result | Coverage limitation | Teardown |
| --- | --- | --- | --- |
| AWS native live collector, disposable private bucket/VPC/security group | 259 resources, 307 findings; all three fixture IDs found; exact snapshot reevaluation matched | 23 collected, 24 empty, 1 unknown (`ReportNotPresent` for existing credential report), 2 not_collected and 2 partial (IAM page cap). Collector never generates credential report | All three ledger entries `deleted`, verification `not_found` |
| Azure broad collector initial bounded run | 1500 resources, 1436 findings; existing metadata populated | Global resource cap reached before dedicated RG; truthful partial statuses. Fixture-presence assertion failed, so gate not passed | Dedicated RG deleted; `not_found` |
| Azure native planned scan retest | 4912 resources, 8589 findings; exact saved snapshot reevaluation matched | During concurrent implementation default dependency planning changed; RG intentionally omitted by plan. Root `/` role_assignment returns HTTP 400 (reported Azure owner); exact inventory override support being added by core | Dedicated RG deleted; `not_found` |
| Kubernetes actual localhost kind cluster | `python -m peaso.cli scan --request ... --snapshot-output ... --output ...`; then offline `evaluate --format markdown`; 155 resources, 280 findings and actual inert Pod present | Local Kubernetes evidence only, not GKE. Restricted pause Pod, token automount disabled, deny ingress/egress policy, ClusterIP service, read-only namespaced role | Cluster containers not found; private kubeconfig removed, ledger children marked removed with cluster |
| GCP auth explicit ADC | SDK default credentials refresh attempted separately from selected gcloud credentials; `RefreshError` | Both explicit ADC and gcloud identity need refresh; no silent fallback and no credential material printed | No GCP resources created |

Temporary AWS SecurityAudit role `peaso-test-622b8d3c82d54e02` in authorized test
account is alive under a one-hour finally-cleanup watchdog for forthcoming hosted
scan. Trust restricts the exact future permanent collector principal in the wiki
account and requires an external ID; no static access key was created. API-owned
onboarding will generate a connector-specific external ID, requiring a ledger-owned
trust update before the hosted scan. This role is not yet deleted, so final cleanup
gate is still pending.

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

Private actual outputs are in `.cache/peaso-qa/task_02a312b5ac1f/`:
`baseline.log`, `e2e.log`, provider `*-snapshot.json`, `*-report.json`,
`*-summary.json`, `local-k8s.log`, `k8s-cli-report.json` and
`k8s-cli-report.md`. Only count/status/timing evidence is reproduced here; private
cloud configuration snapshots are not committed.
