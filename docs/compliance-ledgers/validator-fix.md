# Compliance validator repair — 2026-10-12

## Failures and root causes

| Gate | Initial result | Root cause |
| --- | --- | --- |
| `scripts/peaso_compliance_audit.py` | Passed | Pinned source inventory was consistent: 160 framework versions and 22,212 requirements. |
| `tests/test_peaso_compliance_requirements.py` | 25 passed | Fixture tests did not cover the real proposal catalogue versus ledger definitions. |
| `scripts/peaso_compliance_compile.py` on the repository | Failed before reading a ledger | `docs/compliance-ledgers/manifest.json` is absent. The README reserves this signed completeness and verification gate for the supervisor after review and spot checks. |
| Staged compile with a temporary manifest | Initially failed | 1,337 ledger proposal occurrences differed from the canonical provider catalogues, including 44 IDs with conflicting bodies within ledgers; 5,507 requirement rows had no evidence reference; 14 rows listed an accepted check as removed; seven Azure framework rows claimed unscoped Kubernetes checks; two descriptions were too short and two pairs shared identical prose. |
| `azure-pci/.work/validate.py` | Failed | It required every predicate to start with `FAIL when`, accepted only `peaso/*.py` evidence, and counted only `azure_` proposal headings. These assumptions predate canonical predicates, pinned source citations, and dotted Azure IDs. Its checklist had 95 stale decisions, 34 stale marks, and proposal headings inconsistent with the ledger. |
| `azure-nist-hipaa-rbi-soc2/.work/validate.py` | Failed | It rejected repeated proposal IDs with different bodies, source citations, and candidate checks rejected during review if absent from the frozen mapping. Its checklist had 125 stale decisions and 119 stale marks; the old parser counted proposal tasks as requirement tasks. |

## Fixes

- Replaced the core ten fields of every ledger proposal with the matching `new-checks-<provider>.json` definition. The 889 catalogue IDs remain unique; all 3,126 ledger occurrences now resolve to a single catalogue definition. A real-ledger regression test enforces exact core-field equality and rejects duplicate catalogue IDs.
- Added the pinned audit matrix `source_path` as evidence for 5,507 previously empty rows. These are exact references to the frozen requirement text; existing evaluator citations remain in place. Removed 14 accepted IDs from `removed_checks` where the same row retained them.
- Removed eight Kubernetes-provider IDs from seven Azure framework mappings. The rows now require manual AKS-scoped review until a mapping proves the Kubernetes snapshot belongs to the Azure cluster under assessment. No cross-provider result is counted as an Azure automatic pass.
- Expanded the two short Azure networking descriptions to identify the evaluated SKU field and security significance. The two exact Job and Pod description pairs use a justified duplicate allowlist in the **temporary** manifest because each pair describes the same evaluator behavior.
- Allowed reviewed ledger titles to enrich the 2,043 requirements whose pinned source title is empty, while requiring exact equality for every nonempty pinned title. Accepted structured source evidence only when check ID, source, positive line number, and predicate are present. Tests cover both changes and reject malformed evidence.
- Kept unknown JSON rejection in the compiler, while excluding the four named proposal catalogues, five named verifier problem files, and `.work` scratch files from runtime-manifest inventory. A test confirms that a genuinely unlisted root JSON file is still rejected.
- Rebuilt the two Azure checklists from their current ledger rows and proposal specifications. Their local validators now check source citations against the pinned matrix and check the complete proposal ID set, regardless of ID prefix. The Azure NIST validator still requires every removed ID to exist in the check index and to be disjoint from accepted IDs; it permits a reviewer-rejected candidate that was not in the frozen mapping.

## Final serial results

- Pinned audit: **pass**, 160 frameworks and 22,212 requirement units (AWS 9,455; Azure 5,989; GCP 4,200; K8s 2,568).
- `pytest -q -o addopts='' tests/test_peaso_compliance_requirements.py tests/test_catalog_review.py`: **31 passed**, zero skipped, no xdist.
- Azure PCI repair validator: **pass**, 1,705 requirement IDs and 129 distinct proposed IDs.
- Azure NIST/HIPAA/RBI/SOC 2 repair validator: **pass**, 939 requirement IDs, 62 distinct proposed IDs, and 1,536 evidence references.
- Full compiler CLI against a separate temporary ledger copy with a generated manifest: **pass**, 160 frameworks, 22,212 requirements, and 3,112 descriptions. Runtime states: 9,075 automated; 4,216 partial; 5,957 manual; 651 not applicable; 2,313 not assessed.
- Full compiler CLI against `docs/compliance-ledgers`: **blocked at the existing missing-manifest gate**. The temporary manifest has not been published as `verified: true`: the handoff records a pending Azure proposal review and supervisor spot check. A production compile and published pass cannot be claimed until that review signs the manifest. The existing fail-closed manifest requirement remains intact.
