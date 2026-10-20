Finding types
=============

Hardening Findings → Group by → Type groups findings across services by their primary security purpose. Type groups preserve severity/status filtering, counts, expandable rows and pagination. Service and Check grouping remain available.

Every registered AWS, Azure, GCP and Kubernetes native/analysis check has an explicit primary assignment in `peaso/checks/finding_types.json`. The categories are authentication; permissions and IAM; encryption; keys and certificates; secrets; network and exposure; backups and recovery; logging; monitoring and alerts; security tool enablement; vulnerabilities and malware; patching; service and workload hardening; supply chain; data privacy; unused assets and lifecycle; availability; governance; inventory and coverage.

A single primary type keeps group counts additive. Engine execution categories and compliance checklist membership remain separate concepts. For example, logging checks can be grouped under Logging while remaining excluded from HackTricks Cloud Best Practices. Existing archived findings are annotated from the current check mapping when read, so rescanning is unnecessary. Unknown legacy check IDs appear as Unclassified; privilege-escalation findings use Permissions & IAM.

[The complete review CSV](finding-type-review.csv) lists each check, provider, title and assignment. New check IDs require an explicit assignment: catalog materialization and tests reject missing or stale entries. Labels/descriptions used by the UI are generated from the same registry.

```
.venv/bin/python scripts/audit_finding_types.py
.venv/bin/python scripts/audit_finding_types.py --write
```

Validation for this change: 353 focused tests pass across explicit assignments, inline/chunked report APIs, policy collectors and role scope; the production frontend build and two browser tests pass. A separate signed-source policy suite passes 27 tests. The broader suite is not green: historical registry-baseline assertions stop five modules during collection, and unrelated RDS/Secrets Manager SDK-closure expectations and archived report/template expectations fail. These are not evidence of a completed full-suite run; the interrupted broad run reached 2,769 passing tests. The focused suites and coverage audits are the validation for this implementation.
