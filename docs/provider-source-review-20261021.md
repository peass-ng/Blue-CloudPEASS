# Provider source review — 21 October 2026

This records the current source recheck of the fixed inventory. Earlier native review and test receipts remain valid only for their recorded scope; they are not claims of complete live-cloud certification. New selected-content checks are tracked separately and do not change the fixed inventory.

| Provider | Fixed IDs | Current source recheck | Final integrated release |
| --- | ---: | --- | --- |
| GCP | 430 | All 430 have individual source, native-field and verdict records | Pending |
| Azure | 714 | All 714 have individual source records; 23 alert-coverage corrections are locally composed | Pending |
| Kubernetes | 938 | All 938 reconciled; seccomp, component and image-reference corrections locally composed | Pending |

The [pinned upstream accounting](provider-upstream-review-20261021.json) records the reviewed Prowler and Steampipe revisions and the retained per-source disposition ledgers. It does not turn a source mapping into a behavior guarantee.

The [GCP per-ID record](gcp-review/source-recheck-20261021.jsonl) consolidates four disjoint blocks without missing or duplicate IDs. Each entry describes actual evaluator/producer fields, applicability, incomplete-evidence handling and applicable prior review. Primary API sources are recorded where relevant. Passing fixture replay is recorded separately from source review and authenticated service behavior.

The Azure review identified activity-log alerts that can report compliance despite a foreign scope or narrower event conditions. These defects are corrected in the local candidate and await the final integrated gate. The Kubernetes review also corrected three old review descriptions: literal `Always` pull-policy checks differ from separate digest-or-Always checks. Their current evaluator behavior remains unchanged.

The [Azure per-ID record](azure-review/source-recheck-20261021.jsonl) covers all 714 fixed IDs. The [Kubernetes per-ID record](k8s-review/source-recheck-20261021.jsonl) covers all 938 fixed IDs. Original recorded predicates and later corrections are distinguished; old receipt paths remain evidence references for their original scope, not claims that an old fixture validates a changed function.

The [exact source-correction record](provider-source-corrections-20261021.json) links these post-review fixes to before/after files and changed functions. The per-ID records retain their original review epoch.

Current source corrections include BigQuery consumer-domain grants, default-network firewall identity, GKE modern network identity, and ephemeral-container seccomp evaluation. Focused regression tests cover the changed behavior. Current source changes still require the final guarded registry, metadata generation and affected integration gate before publication.

Selected-content implementations and [setup permissions](secret-content-permissions.md) cover bounded named sources and immutable image references. Kingfisher and TruffleHog observations merge by secret fingerprint; Trivy reports HIGH/CRITICAL packages and requires a complete fresh database for a clean result. New readers retain scoped private evidence and reject foreign resource/scope joins. Intentionally stored secret-store values, unselected repository history, arbitrary external references and runtime execution are outside this read-only assessment.

Local source composition, offline native transports and a deployed release are different evidence. This document does not claim that every provider API was called live or that the current local changes are already in production.
