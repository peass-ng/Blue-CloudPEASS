# HackTricks Cloud Best Practices membership review

Reviewed on 2026-10-19 against the owner's security/privacy configuration scope.
The review covers all 4,021 registered native checks and seven analysis checks,
including archived checks so their public metadata follows the same policy.
3,165 entries retain the tag and 863 lose it. Of the 3,433 currently active
native/analysis entries, 2,761 retain the tag and 672 lose it. No group decision
is pending. Privilege-escalation techniques retain their existing tag because
they evaluate dangerous permissions, trust and privilege paths.

The [complete receipt](hacktricks-checklist-review.csv) records every check ID,
provider, title, active status, decision, group and rationale. The authoritative
membership ledger is [hacktricks_scope.json](../peaso/checks/hacktricks_scope.json).
Membership uses explicit IDs, never runtime keyword matching, service names,
source framework membership or the existence of a HackTricks page reference.

| Provider | Retain | Remove |
| --- | ---: | ---: |
| AWS | 1,162 | 394 |
| Azure | 723 | 246 |
| GCP | 368 | 123 |
| Kubernetes | 906 | 99 |
| Cross-provider analysis | 6 | 1 |

The original criteria retain encryption, secret protection, access restrictions,
IAM/least privilege, service hardening, backups and unused-asset checks. They
exclude plain CloudWatch alerts/log delivery and IAM Access Analyzer presence,
health and findings. Analysis inventory completeness also loses the tag.

The owner resolved the ambiguous groups together:

| Group | Decision |
| --- | --- |
| Security tools | Keep protection/scanning enablement, including GuardDuty, Inspector/ECR scanning, Defender and integrity monitoring. Exclude findings/status and scan-recency predicates. The explicit Access Analyzer exclusion remains. |
| Log protection | Keep retention periods, validation, immutable storage and tamper protection, as well as encryption/access restrictions. Exclude logging, delivery, tracing, metrics and notifications alone. |
| Resource exhaustion | Keep limits, quotas and throttling. Exclude CPU/memory requests, including request quotas. Ordinary replicas, scaling, health checks and availability remain outside scope. |
| Governance metadata | Keep approved resource/data locations. Exclude classification labels, asset/software inventories and organization structure. Actual access restrictions remain eligible. |
| Mixed predicates | Keep a compound check when it contains a concrete hardening requirement, even if it also requires logging/monitoring. |
| Backup verification | Keep backup freshness, successful recovery points and completed restore verification as well as backup configuration/protection. Exclude backup failure alerts and reporting alone. |
| Generic lifecycle | Owner delegated the decision. Keep explicit cleanup/deletion, untagged-image cleanup, session lifetime bounds and backup/log protection. Exclude generic policy existence or arbitrary data-retention minima that establish none of those. |
| Generic baselines | Exclude arbitrary expected-setting or drift checks unless the predicate names security settings. Concrete OS security baselines, firewall rules and password policies remain eligible. |

Checks requiring IAM permission restrictions on CloudTrail/logging remain
eligible; logging enablement does not. Likewise, Auto Scaling template IMDSv2,
secret protection and public-IP restrictions remain eligible while scaling
capacity and zone redundancy do not. Empty load balancers, scale sets, groups
and unassociated resources remain eligible as unused assets. Findings that
inspect collected content for exposed secrets remain eligible; asking whether
another tool has unresolved findings does not.

Removing this checklist changes its scan selection and finding labels. It
does not remove an evaluator or alter another framework's requirement tags.
An excluded check remains available through its other frameworks, category
or explicit ID, subject to its existing automation admission rules. Stored
historical report labels are preserved; new reports use reviewed membership.

Run the membership gate and reproduce the receipt with:

```sh
python scripts/audit_hacktricks_scope.py
python scripts/audit_hacktricks_scope.py --write
python scripts/peaso_compliance_materialize.py --write
```

Both catalog materialization and manifest validation require an explicit
decision for every registered native/analysis check. Unknown IDs are untagged;
missing, stale or pending review entries fail the build gate. When adding a
check or changing its predicate, review its membership and reason, regenerate
the CSV/catalogs, and run `tests/test_hacktricks_checklist_scope.py` plus the
affected provider/selection tests. The membership tests exercise both retained
and removed groups, actual checklist selection, analysis findings and
preservation of other requirement mappings.

Validation: 23,745 regression tests passed, one reference-checkout test skipped,
and three unrelated failures were deselected after being run separately:

- `test_manifest_validator_and_mapping_conservation`: a launch-configuration
  secret-indicator source association is absent from the signed requirement
  row. The updated checklist manifest validator itself passes.
- `test_api_hydrates_per_check_fields_for_filters_facets_summary_and_detail`:
  the API returns an additional `evidence_summary_format` field.
- `test_unsupported_listener_contract_is_separate_from_customer_inputs`:
  two unsupported contracts exist where the fixture expects one.

The historical backup-admission suite also stops during collection on its
existing registry-baseline count assertion. The membership audit passes for
all 4,028 entries, the AWS framework audit passes for all 1,404 active AWS
checks, and all six materialized catalog views are current. The broader
catalog audit still reports four source-cost metadata inconsistencies for
launch-configuration/user-data secret checks; none concerns HackTricks
membership. Those source, API and historical-fixture issues were left outside
this checklist-scoping change.
