# OS Config fixable-vulnerability assessment review

Prepared a **pure native candidate with explicit idempotent installation**, `gcp.compute.os_config_fixable_vulnerabilities`, in `peaso/checks/gcp_os_security_update_review_20261019.py`. It evaluates a VM’s collected assessment at its native generation time. The normal `install()` and compressed native CASES are ready; shared registry import, requirement mapping and canonical evidence copy remain root-owned. The exact desired-state title is “VM assessment has no fixable known vulnerabilities,” with high severity in the verified existing `vulnerabilities` group.

FAIL means the matched complete assessment contains a supported finding with an available package fix reference. PASS means that precise assessment has no such references, including a complete generated report with zero findings. Missing/empty report collections, empty report objects, denied/partial data, malformed/future timestamps and ambiguous or foreign subjects remain UNKNOWN.

The consumer joins independent project ID/number metadata, native VM zone/numeric ID/name, report identity and exact read-operation provenance. Assessment timestamps are compared at nanosecond precision against native capture time. No owner SLA/grace period, custom policy metadata, package-age inference or freshness threshold is required.

Google documents [report generation time and fix references](https://docs.cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.instances.vulnerabilityReports). The existing producer retains only severity and availableInventoryItemId for findings; it strips CVE details and full package metadata. An available package reference can outlive its inventory entry, so this candidate does not invent publication/installation dates or require a current inventory package join.

Validation: **37 directed cases passed**, plus **27 reused native collector cases**. Directed cases cover fix/no-fix and omitted fix references, complete zero-finding assessments, old assessments with bounded wording, numeric project aliases, native severity limits, denied/partial collection, wrong subject identity, duplicate subjects/source requests, field denial and future-by-one-nanosecond timestamps. Source hashes, native case exports and XML receipts are in [the JSON review](os-security-update-review.json).

The earlier requested current-behavior overlay export is `/tmp/peasso-gcp-review-20261019/identity-data-proposals/runtime-cases.json`: ten real-collector synthetic cases for the two Workspace IDs and Storage public-read ID, each with complete MemoIndex-compatible item/context/collections/resources and verified actual outcomes. The historical behavior bundle and shared runtime were not changed in this follow-up.

| Manual SQL source ID | Candidate coverage | Remaining requirement |
|---|---|---|
| `gcp-compliance.control.cis_v130_4_12` | **PARTIAL** | Latest updates, freshness, installation verification and complete project/VM coverage require separate evidence. |
| `gcp-compliance.control.cis_v200_4_12` | **PARTIAL** | Latest updates, freshness, installation verification and complete project/VM coverage require separate evidence. |
| `gcp-compliance.control.cis_v300_4_12` | **PARTIAL** | Latest updates, freshness, installation verification and complete project/VM coverage require separate evidence. |
| `gcp-compliance.control.cis_v400_4_12` | **PARTIAL** | Latest updates, freshness, installation verification and complete project/VM coverage require separate evidence. |

The task mentioned three manual SQL source IDs; the current captured ledger has four distinct CIS 4.12 wrappers, so all four are recorded. Each invokes the same constant-INFO project-level manual query. The new per-VM assessment predicate is useful narrower automation; none of those manual wrappers becomes an equivalent PASS/FAIL check, and none is counted as fully automated requirement coverage.

Remaining limits: supported report/feed and OS coverage, live cloud behavior, temporal consistency across independent reads, deprecated or unsupported report representations, and every malformed import/type/calendar permutation are not fully certified. A PASS must be presented with assessment time and the bounded claim, since vulnerabilities without available fixes and newer patch changes may still exist.

Admission preparation verified **65 focused tests**: the original 64 native producer/consumer tests plus one idempotent installation/native fixture smoke. The new `peaso/checks/gcp_os_security_update_fixtures.json.gz` contains full native PASS/FAIL/UNKNOWN items and indexes produced by the existing `native_case` helper (`no_fix`, `fixable`, `report_denied`), through actual normalized native production, engine indexing and `MemoIndex`. The export and updated source/fixture/JUnit hashes are in `/tmp/peasso-gcp-review-20261019/os-config-admission-proposals/` and the JSON review. Historical primary-document and 64-test receipts remain separately attributed.

PASS/FAIL evidence now directly states the fixable finding count and native assessment timestamp, followed by the sentence “Current patch state and assessment freshness were not assessed.” Remediation is to apply applicable updates for the assessed fixable findings and collect a new assessment. This adds no owner criteria, runtime collector change, current patch/freshness/SLA claim or new numbered compliance link. All four reviewed CIS source comparisons remain PARTIAL-only candidates with their explicit limitations; root owns final source parity and canonical admission.
