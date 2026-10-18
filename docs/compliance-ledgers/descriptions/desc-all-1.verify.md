# desc-all-1 independent verification

Evaluator sources: `peaso/analysis/__init__.py`, `iam.py`, `network.py`, `trust.py`, `common.py`, and `internet_exposure.py` under `peaso/analysis/`. Each input ID was checked against its evaluator and receives one decision below.

| Check ID | Decision | Changed fields | Reason |
| --- | --- | --- | --- |
| `analysis.coverage` | Corrected | description, evaluated, fail_when, not_applicable_when, pass_when | Clarified the least-privilege inventory gate and separately identified malformed facts and unknown/partial permission criticality. |
| `analysis.federated_trust` | Corrected | description, evaluated, fail_when, not_applicable_when, pass_when | Added AWS Cognito and GitHub audience nuances, GCP MANUAL, Azure UNKNOWN, and both Azure credential types. |
| `analysis.grant_review` | Corrected | description, evaluated, fail_when, not_applicable_when, pass_when | Clarified high-or-higher declared grant predicate, GCP role-name limit, Azure assignment resolution, and UNKNOWN criticality branch. |
| `analysis.inactive_identity` | Corrected | description, evaluated, fail_when, not_applicable_when, pass_when | Clarified precedence of Usage over usage and separated activity_count predicate from evidence-only telemetry fields. |
| `analysis.internet_exposure` | Corrected | description, evaluated, fail_when, not_applicable_when, pass_when | Added assessed-asset PASS/UNKNOWN branches, secondary gap behavior, and scope-level inventory UNKNOWN condition. |
| `analysis.network_review` | Corrected | description, evaluated, fail_when, not_applicable_when, pass_when | Added exact unrestricted-source set, Kubernetes absent/empty peer behavior, and GCP default source range. |
| `analysis.principal_exposure` | Corrected | description, evaluated, fail_when, not_applicable_when, pass_when | Added public condition distinctions, network-bound exception, AWS Service and Kubernetes discovery exceptions, and mixed-verdict precedence. |

Validation: 7 unique input IDs; 7 unique description keys; each ID occurs exactly once in the check index; output key set equals input ID set; each entry has exactly the five required fields.
