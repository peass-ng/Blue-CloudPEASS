# Provider read-only automatic checks

Automatic scans evaluate facts obtainable through read-only AWS, Google Cloud, Azure and Kubernetes APIs. Fixed criteria from the reviewed source standard are supported. Controls requiring a company-selected allowlist, internal business classification, approval record, host filesystem attestation or externally verified process outcome are outside the automatic scan scope.

`peaso/checks/native_only.json` records each excluded check and its mandatory external requirement. Exclusion is an explicit source review decision; a failed API read never causes exclusion. A check with a sufficient native alternative remains available, and denied, missing, partial or malformed native evidence remains DENIED or UNKNOWN. Excluding a custom control does not remediate a resource or prove compliance.

The engine applies the same admission decision to default scans, framework filters, explicit check selections and collection planning. The console selector and complete API catalog expose the active checks. An explicit request for an excluded check or manual attestation is rejected before collection. The engine no longer generates attestation questionnaires as findings.

Archived evaluator definitions remain available for interpreting existing reports and source mappings. Materialized `native_catalog.json` separates active `checks` from `archived_checks` and records the exclusion reasons. The catalog auditor validates both partitions, their disjointness and their original source provenance. Framework requirement totals and reviewed statuses describe the source reference; they do not certify the automatic scope or an account. Stored scan results are not rewritten.

The scope change does not add cloud operations or grant permissions. In particular, inaccessible native facts remain evidence gaps; the scanner does not generate IAM usage or credential reports to fill them.
