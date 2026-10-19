# AWS Steampipe parity review — 2026-10-19

All **1,674 current controls** reconcile: **1,612 compliance** and **62 perimeter**. There are **1,597 active native source lineages** and **77 precise exclusions** after admission; no absent source ID, stale source/query hash, framework/benchmark drift, missing native reverse reference or removed upstream ID remains. The former eight archived-only source mappings now have explicit excluded/manual dispositions and do not count as automatic coverage.

Official GitHub HEAD APIs were refreshed: [compliance](https://api.github.com/repos/turbot/steampipe-mod-aws-compliance/commits/HEAD) remains `803dda1f7555ed5cea959aef30cfa0719b030d8c`; [perimeter](https://api.github.com/repos/turbot/steampipe-mod-aws-perimeter/commits/HEAD) remains `2fe878449fb0d83b23333e373ee73849b0049364`. These match the manifest pins. Only **555 `.pp`/`.sp`/`.sql` files, 3,600,642 bytes** were fetched into `/tmp/peasso-aws-review-20261019/steampipe`; every blob matches the complete pinned Git tree. Declaration enumeration is independently checked against parsed control rows; duplicate definitions and unresolved query references fail closed.

| Verdict | Controls |
|---|---:|
| corrected_native_lineage_semantics_not_reexecuted | 312 |
| current_lineage_active_native_semantics_not_reexecuted | 1285 |
| justified_customer_trust_input | 13 |
| justified_invalid_upstream_predicate | 1 |
| justified_manual_interpretation | 1 |
| justified_manual_only | 61 |
| justified_retired_service | 1 |

Each of the **61 manual-only controls** was inspected individually and invokes `query.manual_control`, which emits constant info and “Manual verification required.” This means no automatic predicate exists in that source; it does not imply that its topic lacks useful native evidence. Existing native Lambda execution-role uniqueness/existence/admin checks, code signing, runtime, Lightsail logging/private buckets and Beanstalk controls remain active separate evidence.

The other exclusions are **13 customer-trust comparisons**, **one CloudWatch sharing interpretation**, **one invalid identity-policy query** and **one retired Inspector Classic query**. Every excluded SQL/control block was read individually. Supplied trusted account/organization/OU parameters encode customer approval that provider inventory cannot infer. CloudWatch's named cross-account role emits info and can be legitimate monitoring. [AWS IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html) forbids Principal in identity-based policies, invalidating that query's intended alarm. [AWS's lifecycle notice](https://docs.aws.amazon.com/managedservices/latest/userguide/inspector.html) confirms Inspector Classic ended support on May 20, 2026; active Inspector2 evidence has a different resource/status/applicability contract.

The five prior sensitive-configuration exclusions now map to active bounded native evidence. Broad keyword/password-shape SQL and selected high-confidence native configuration detectors are not equivalent. Optional package/code/log scanning uses real Kingfisher SDK 1.4.0 and TruffleHog 3.92.5; that does not silently broaden every configuration detector into a full-content scan. Disabled/incomplete negative scans remain UNKNOWN.

All **1,597** active lineages explicitly retain semantic uncertainty; **312** carry previously reviewed source-correction lineage and **1,285** ordinary native lineage. This audit checks source/current registration and provenance, not complete SQL/native differential equivalence, live collector completeness, every exemption or customer approval. `remaining-source-exclusions.json` reconciles all current exclusions and admissions and preserves the archived exact-listening contract separately from bounded public-route configuration alternatives.

Reproduce with `.venv/bin/python scripts/audit_aws_steampipe_parity.py`; add `--refresh` to resolve current API HEADs and refetch bounded sources. The JSON records one row per source control, exact query/source links, framework and benchmark ancestry, active/archived references, manual lineage and local input hashes. Focused validation uses the three parity review test files; no live cloud calls, full suite, build or deploy was performed.

Directed parity validation: **21 tests passed**, zero failures, errors or skips; receipt `/tmp/peasso-aws-review-20261019/current-parity-tests.xml`.
