# Recorded provider review

[checks.csv](checks.csv) records each GCP, Azure and Kubernetes check, plus newly admitted AWS source readers, by exact ID,
source, review result, receipt and next action. [progress.json](progress.json)
records current ownership. A registry entry, an upstream mapping and a passing
native-response test are separate claims.

Current local checkpoint: AWS 1,559 registered / 1,407 active; GCP 532 / 425; Azure 1,001 / 712; Kubernetes 1,016 / 938. Workbench, Dataflow and Batch source readers have individual bounded local native acceptance. No GCP native runtime integration or individual acceptance remains queued; the root owns final catalog/prose/native-coverage consistency, browser and package verification. The full goal remains incomplete; these changes are not deployed and no live-cloud proof is claimed.

The [AWS roster and evidence-strength reconciliation](../aws-review/current-roster-reconciliation-20261020.json) distinguishes 1,404 historical active records, three later optional readers and 152 excluded definitions. Of the historical active records, 1,113 have witness-only producer evidence, 235 derived producers and 56 proven native response shapes; none certifies complete semantics or live-cloud verification. A recorded ID is not an assurance certificate.

The [Kubernetes compatibility closure](k8s-public-observation-compatibility-20261020.json) closes 38 previous failures with 4,038 directed tests. [Public observation fixes](k8s-native-observation-closure-20261020.json) cover the two secret-display exceptions and exact eight-ID ConfigMap UNKNOWN statements. Earlier receipts below retain their original scope and counts.

GCP has 532 registered IDs recorded individually: the immutable 529-ID reconciliation retains its original per-ID records, and three later IDs have separate [Workbench](workbench-current-acceptance-20261020.json), [Dataflow](dataflow-current-acceptance-20261020.json) and [Batch](batch-current-acceptance-20261020.json) acceptance receipts. The new Dataflow/Batch runtime review records 540 distinct passing nodes and one preserved historical registry-absence failure; the exact historical/current bridge separately proves the admitted behavior. These receipt scopes are not added together as a new test total. Each reader covers only selected captured current source, with no previously executed or cached-byte claim.
The [earlier integration receipt](../gcp-review/recheck-20261020/native57-integration-acceptance.json)
preserves the initial 14,930 passing tests and 56 failures, and proves that all
56 exact failed nodes passed in a focused 620-test retest. This is bounded offline
acceptance, including actual offline secret detectors where recorded. It does
not certify authenticated provider behavior, effective access or deployed availability.

Azure's [bounded provider integration](azure-provider-integration-acceptance-20261020.json)
accounts for all 984 registered definitions: 695 active accepted locally and
289 archived or excluded with explicit reasons. The [exact queue](azure-review-queue-20261020.json)
has no remaining active semantic integration in that recorded scope. Native
configuration does not prove effective access, log delivery or mitigation efficacy.
Twelve additional optional selected-content controls, two Function declarations and one SAS-policy declaration extended that checkpoint to 999 registered and 710 active. Two subsequent NSP/Query declaration checks bring the current total to 1,001 registered and 712 active. Their [selected-content integration](azure-current-integration-acceptance-20261020.json) and [declaration extension](azure-declaration-current-acceptance-20261020.json) accepts the directed native/registry/compatibility gates and the cross-resource secret redaction correction; it extends the earlier 984-ID receipt.
Original failures, exact successful retests and newer native fixtures are linked
in the receipt; authenticated live-cloud behavior remains unverified.
The [current source inventory](azure-current-source-inventory-20261020.json)
found nine newer Prowler AI Services controls. Their
[individual semantic dispositions](azure-ai-services-source-review-20261020.json)
added four native configuration controls and distinguish five existing controls,
including explicitly related but non-equivalent criteria. Numbered framework
requirements are attached only when supported by the source.

All 928 active Kubernetes IDs have individual worker review receipts: components518, workloads192 and cluster/native218. Their [current registered-ID integration](k8s-current-native-integration-acceptance-20261020.json) is locally accepted with directed source, compatibility and native tests. Eight new ConfigMap-based kubelet declaration controls and one selected log sampler extend that baseline to 937 active and 1,015 registered IDs. Their [current acceptance](current-kubelet-azure-log-acceptance-20261020.json) records the directed native, source and browser gates. These declarations do not prove node adoption or effective runtime enforcement. The [new log, notebook and SAS acceptance](log-databricks-sas-current-acceptance-20261020.json) records the later narrow gates. Optional secret-reader integration is also tracked separately. The [recorded native review](k8s-review-queue-20261020.json)
places every one of its 928 active IDs in exactly one of 12 cohorts. Related
predicate variants share a cohort while retaining each workload kind and scope.
Queue preparation is not native acceptance. Its
[source inventory](k8s-current-source-inventory-20261020.json) conserves all 882
reviewed upstream IDs; this establishes source accounting, not native correctness.
The [archive selection review](azure-k8s-archived-selection-review-20261020.json)
retains the original 263 Azure and 78 Kubernetes exclusions. Later
[native replacements](azure-automation-aci-native-admission-20261020.json) and
[retired Single Server dispositions](azure-single-server-retirement-20261020.json)
plus [MariaDB/HPC retirement](azure-mariadb-hpc-retirement-20261020.json) and
explicit native-criterion successors bring current Azure exclusions to 289. Archived predicates remain available for
historical inspection; exclusion is never a requirement PASS.

[secret-coverage.json](secret-coverage.json) distinguishes implemented selected
content readers from partial pattern checks and unsupported surfaces. The GCP
secret review is linked separately there. Both Kingfisher and TruffleHog must
complete for a clean dual-engine result. Matching detected values are hidden and
merged within a provider report; credentials are never tested. See
[minimum content-read permissions](../secret-content-permissions.md), including
private registry access. Metadata permissions alone do not imply image/source access.

All current follow-up changes remain local. The release owner separately manages
publication from an exact accepted commit. Original failed receipts, historical
source pins and frozen fixtures are retained; current native successor cases are
recorded separately.

The [current log/declaration acceptance](current-kubelet-azure-log-acceptance-20261020.json) also covers the two optional Azure message-sample readers. [Kubernetes source parity](k8s-upstream-parity-20261020.json) assigns a reviewed disposition to all882 pinned source rows; related or excluded sources remain explicit. Selected content surfaces still in progress are listed individually in [secret coverage](secret-coverage.json).

[Azure upstream association accounting](azure-upstream-parity-20261020.json) conserves all1,871 current source IDs:1,304 native associations,9 individually reviewed new sources and3 excluded native contracts. The555 formerly rejected source rows now have individual usefulness reassessments for70 distinct predicates; proposed replacements remain separate from registered implementations. [Original-rationale errata](azure-rejected-source-original-reason-errata-20261020.json) preserves17 provenance corrections without replacing the old report.

The optional [selected S3 reader](aws-s3-current-acceptance-20261020.json) is locally accepted with226 native production cases,592 affected compatibility/guard cases,10 typed observation cases and3 browser cases. Default metadata IAM policy and the published PR33 tag preservation are unchanged. This does not assert a new complete AWS review.

The [selected ML Command-job literal acceptance](azure-ml-current-acceptance-20261020.json) adds one opt-in reader with265 directed production/compatibility cases,10 typed observation cases and5 browser/format cases. It does not inspect referenced code, environment assets, notebook source or images.

The [ML environment/code asset acceptance](azure-ml-assets-current-acceptance-20261020.json) records467 directed worker cases,20 brief-evidence cases and8 browser/format checks. It adds inline Conda and one exact associated code-file reader; it does not infer a whole folder, executed source or original asset-creation bytes. [Setup](../peaso-azure-selected-ml-assets-secrets.md) distinguishes ARM metadata access from Blob/File data permissions.

The [Function and transport acceptance](azure-function-transport-current-acceptance-20261020.json) records512 distinct Function native/source/affected cases and160 transport/SAS cases. The shared reader rejects partial, duplicate-key and nonfinite JSON evidence. Function declarations assess settings, not telemetry delivery or resolved runtime builds. [Setup](../peaso-azure-selected-function-declarations.md) explains sensitive-read consent and the narrowly scoped appsettings permission.

The earlier pre-Workbench/Dataflow/Batch checkpoint recorded GCP529, Azure1001 and Kubernetes1016; current GCP is532 registered and425 active. The new selected metadata reader has local bounded production-hook acceptance. The two Dataproc readers are accepted locally in the [current integration receipt](dataproc-tde-current-acceptance-20261020.json); the [NSP/Query2 checkpoint](azure-nsp-query-current-acceptance-20261020.json) records495 native/source cases and215 affected cases. These are bounded local evidence reviews, not live-account certification. The SQL TDE documented identity correction passes its native ownership matrix; successor admission-consumer compatibility passes33 directed source/lineage cases.

The [latest Dataproc/TDE receipt](dataproc-tde-current-acceptance-20261020.json) verifies652 distinct GCP directed nodes, including all43 previously failing fixture nodes, plus154 Azure TDE/compatibility nodes. [Dataproc setup](../peaso-gcp-selected-dataproc-sources.md) lists exact optional object-read permissions. No authenticated live account or publication claim is implied.

The [current GCP source reconciliation](../gcp-review/recheck-20261020/current-source-reconciliation-20261020.json) joins766 pinned upstream source IDs to529 definitions at its exact historical checkpoint and their individual records, with8 directed conservation tests. It distinguishes692 active mappings,24 archived-only mappings and50 rejected sources; a mapping is not a proof of full semantic equivalence. BigQuery classification advisory and service-to-code/image association limits remain explicit.

The [three-reader accounting extension](../gcp-review/recheck-20261020/current-source-extension-accounting-20261020.json) passes11 targeted conservation checks for the current532 GCP IDs. It preserves the exact529-ID report and35 native receipt pins, every prior master row, all prior evidence rows and the original1,000 supplemental descriptions. Its three new evidence records are drawn from actual admitted PASS/FAIL/UNKNOWN runtime cases. A final24-case gate combines those11 checks with13 current shared-hook checks, closing six earlier binding expectations and proving that seven tamper tests reject their intended changes after a passing baseline. The original601 passing nodes and six failures remain archived; the entire607-node gate was not repeated. This bounded acceptance does not establish live-cloud behavior.

The [selected metadata acceptance](k8s-selected-metadata-current-acceptance-20261020.json) brings Kubernetes to1,016 registered and938 active IDs. Its300 native/runtime/affected tests,191 shared renderer tests and7 browser/format cases include actual consolidated and incomplete public findings; incomplete hits stay FAIL without inventing clean coverage. [Setup](../peaso-k8s-selected-metadata-secrets.md) requests only exact namespaced GETs.

## Final local GCP referenced-source acceptance

Workbench, Dataflow and Batch source controls are accepted locally in the existing Secrets group. The current GCP roster is **532 registered, 425 active and 107 explicitly excluded**. Every registered GCP ID has an individual review or disposition; native source association and content coverage remain bounded as documented.

The combined native/history run recorded 601 passes and six stale successor expectations. A focused 24-case gate closed those six and verified seven live tamper guards plus 11 accounting checks; the full run was not repeated. Root presentation checks passed 267 Python cases, 101 browser cases and 29 final format/public-dedup cases; the source-free installed package passed both tests. Generated artifacts report no stale files and the copy inventory has no missing entries. Counts across these overlapping gates must not be added.

[Consolidated source, tests, setup and limits](gcp-three-referenced-sources-final-acceptance-20261020.json). These changes remain local and outside separately deployed main `376e6ee`; this acceptance does not certify exhaustive live cloud or whole-product completion.
