# GCP check review — 19 October 2026

## Current follow-up — 20 October 2026

The GCP follow-up is **accepted locally for its recorded offline scope**. The current local registry has 527 GCP checks: 420 selectable and 107 archived. Every registered ID now has a source or exclusion-disposition entry in the [current ledger](recheck-20261020/checks.csv). This includes 292 strengthened reviews and a separate 133-ID recheck; the overlapping archived decisions are not counted as functional PASS results. Three further defects in BigQuery principal handling and federated identity conditions were corrected and integrated with 48 focused passing tests. The final 57 native collector-to-engine reviews are now integrated: IAM/KMS328 and SQL/BigQuery383 directed cases pass. The affected GCP cohort initially passed14,930 tests with56 failures; every one of those56 exact failed nodes subsequently passed in a620-test focused retest. The [final integration receipt](recheck-20261020/native57-integration-acceptance.json) preserves both results and the exact source/fixture successors. No complete live-provider certification is claimed.

Two new default-off controls inspect explicitly selected Cloud Tasks FULL payloads and BigQuery inline routine definitions with both offline detectors. Their [native review](recheck-20261020/task-routine-secret-implementation.json), reviewed source admission and [setup permissions](../peaso-gcp-collector.md) describe the bounded reads. The existing optional-secret audit now has 33 controls; it does not claim that every referenced source archive or deployed image has been inspected.

All current follow-up changes are local and outside the previously released commit. Native API-shaped fake transports, actual offline detectors where recorded, and directed compatibility tests provide the listed evidence. Authenticated provider behavior, event delivery, effective workload access and complete all-cloud acceptance are not certified by these receipts. Azure/Kubernetes full check review and remaining cross-cloud secret readers remain open in the [master checklist](../check-review/checks.csv).

The dated evidence below records earlier accepted scopes and their limitations.


Status: **local review and directed integration accepted; release handoff pending**. This records current implementation and evidence; registration, source lineage, fixtures, native pipeline tests and live validation are separate claims. No production publication or live GCP test is claimed here.

[Every registered check](checklist.csv) is recorded individually, including archived controls. The current inventory is **525 registered / 422 active / 103 archived**, with **31 optional secret checks**. [Exact checklist inputs](checklist.inputs.json), [per-ID extension reviews](native-extension-integration.md) and the [execution ledger](native-contracts.json) retain source/test references. All 525 callbacks executed in passing tests; the accumulated baseline and directed acceptances record **19,560 distinct latest passing nodes**, with no unresolved recorded failures. The final GCP-wide run passed 18,916 tests with 27 failures; all 27 subsequently passed in an exact directed recheck (39 acceptance tests including source, wheel and surface guards). The historical/collector affected cohort passed 213 tests and exact named secret selection passed 31. Seven initial real-detector availability failures did not reproduce in direct or central rechecks; no production timeout increase or claimed runtime fix hides that intermittence. Overlapping cohort totals are not added together.

See the installed [Cloud Build log](cloudbuild-log-integration.json), [App Engine file](appengine-source-integration.json) and [Cloud Build artifact / Cloud Deploy source](followup-content-integration.json) acceptance reports. Installed-wheel and source-accounting regression acceptance passed eight tests; generated catalog verification reports `stale: []` across six artifacts. This is accumulated local acceptance with native-schema HTTP fixtures and offline detectors, not a fresh complete all-cloud suite or authenticated live-cloud certification.

## Upstream sources

The independently fetched official source inventory contains **766 IDs**: Prowler 112, Steampipe GCP compliance 621, and Steampipe GCP perimeter/exposure 33. See the [source accounting](source-parity.md) and [per-source JSON](source-parity.json). Every omitted or archived-only mapping is recorded; a mapped ID does not establish algorithm equivalence.

The two new Workbench checks evaluate public-IP disabling and notebook root-access disabling without customer-specific classification/exception requirements. Their [review](workbench-review.json) records 20 native collector-to-consumer tests. All thirteen upstream PCI associations were separately reviewed: [nine justified PARTIAL links and four explicit rejections](workbench-requirement-decisions.json). No numbered claim is invented for unrelated audit-log protection, PAN storage protection or tenant isolation.

## Review ownership and evidence

| Cohort | Registered IDs | Evidence |
|---|---:|---|
| Compute/network/services | 262 | [Per-ID review](compute-network-review.md) |
| Identity/data/storage | 154 | [Per-ID review](identity-data-review.md) |
| Project/logging | 75 | [Per-ID review](project-logging-review.md) |
| New Workbench controls | 2 | [Native review](workbench-review.json) |
| Optional secret inspection | 31 | [Surface contracts](secret-surfaces.md), [per-ID integration](native-extension-integration.md), [first Functions review](function-secret-review.json) and [independent acceptance](secret-integration-acceptance.md) |
| Native OS Config assessment | 1 | [Assessment-only review](os-security-update-review.json) |

The first GCP-only baseline executed every then-registered callback: 16,160 tests passed, with one historical source-reconstruction failure. That exact failure subsequently passed using immutable historical inputs; it was not a runtime predicate defect. The original receipt remains under `/tmp/peasso-gcp-review-20261019/native/`. Targeted Workbench and historical rechecks are recorded separately. The merged ledger is not a claim that a full suite ran against every latest shared-tree edit.

Confirmed fixes in review include template IPv6 access, firewall source-selector OR semantics, current GKE authorized-network representation, Workspace enrollment/enforcement and recovery evidence, BigQuery public READER representations, SQL Server flag aliases, and inherited bucket public-read grants. The cohort reports retain exact affected tests and unproved branches. The integrated source, source bindings, short copy and native fixtures now have accumulated acceptance; the semantic follow-ups below remain explicit.

`gcp_cloudsql_backup_failure_alert` is corrected with a [bounded native local configuration contract](backup-alert-native-review.md), accepted by 70 final directed tests. Complex filters remain UNKNOWN; notification delivery and centralized alerting are outside this declaration check.

The unsupported historical `gcp_logging_detect_t1110` contract is [explicitly archived](authentication-contract-review.md), with 623 directed tests proving public exclusion and preservation of signed provenance. An organization-scoped login detector is not implemented or claimed.

## Native semantic follow-up

Thirteen existing controls received further native contract corrections: eleven log-metric/alert associations and two Cloud SQL TLS controls. The [metric review](metric-alert-semantic-followup.md) records false PASS counterexamples from regex substring matching, narrowed/negated filters, foreign selectors, MQL mentions and invalid policies. The [TLS review](sql-transport-semantic-followup.md) records native mode/engine applicability, incompatible pairs, explicit legacy fallback and unresolved settings. Their affected source/presentation cohort passed 11,637 tests; the six added native TLS examples and source guards passed 42. The final installed-wheel/source-accounting acceptance passed eight tests and generated catalog verification was clean. These are configuration declarations, with no event delivery or runtime TLS attestation.

The per-ID CSV now exposes the reported code/producer review scope and links these follow-ups. A bounded source trace is explicitly distinguished from full semantic certification; the old absent disposition field no longer mislabels an existing trace as an unstarted review.

## Explicit remaining work

- [Cloud Source Repository selected files](sourcerepo-secret-review.json) now have an installed, explicitly selected native-bound Git reader; 58 adapter/integration tests passed. Current live authentication/provider compatibility remains unverified. The negative result covers only selected files at the advertised immutable commit, never repository history. The final local gate/rechecks and publication acceptance are recorded separately.
- Cloud Build logs/output artifacts, Cloud Run images, App Engine deployment files and Cloud Deploy source archives now have installed bounded readers. Their explicit scopes and limitations remain in the [surface matrix](secret-surfaces.md). Four intended secret-store payload surfaces remain excluded.
- Production publication and authenticated GCP validation were not performed by this audit.

GCR-hosted immutable native Artifact Registry images are now [covered by the existing image check](gcr-image-review.md), with 112 distinct latest passing tests.

Integrated optional checks cover Functions environments/resolved archives, Compute metadata/scripts, Run, Build literals, sampled logs, selected GCS objects/archives, immutable images, selected Artifact Registry package/Dataform files, Scheduler, App Engine environments/deployment files, Workflows, Dataflow, Batch, Dataproc, GKE, Composer configuration/DAGs and Workbench metadata. They require explicit selection and content opt-in. Disabled exclusive content inventories now remain UNKNOWN, never complete empty evidence. The OS Config assessment-only successor passed 65 focused tests; its four current CIS 4.12 links remain PARTIAL.

Validation uses native-schema mocked HTTP and inert test data, with real pinned offline secret detectors where stated. One failed intermediate job-adapter fixture sent a fixed fake token to a Google endpoint and received401; the owner report records this, and final fixtures block unmocked Python sockets/DNS. No real credential or user content was sent by that fixture, and no cloud resources were created. Shared work continues without a source freeze. Existing UI groups and one-to-three brief natural-language evidence sentences remain required for new checks.

## Reproduction

```sh
.venv/bin/python scripts/audit_gcp_source_parity.py
.venv/bin/python scripts/audit_gcp_native_contracts.py
.venv/bin/python scripts/audit_gcp_review_checklist.py
```

Use `audit_gcp_native_contracts.py --run-gate` for a new accumulated baseline only when warranted. Add `--supplement /path/to/execution.json` to retain directed rechecks without rerunning unrelated tests. The baseline excludes unpublished registrar tests that require repository-mandated isolation, plus separate privilege-path/attack-detection suites; these are not silently mixed into the posture registry.

## Final release acceptance

The complete GCP per-ID ledger and current source hashes are captured in [final release acceptance](final-release-acceptance.json). The initial failed run is preserved alongside directed passing receipts; latest passing results are not presented as a fresh all-cloud suite. Production publishing belongs to the coordinated release agent.
