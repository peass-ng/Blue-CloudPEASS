# Native snapshot checks

Peaso evaluates immutable schema-1.0 JSON snapshots offline. Its registry contains actual Python predicates and optional native DuckDB scalar predicates; it never loads Prowler, Steampipe or Powerpipe runtimes. Provider collection is a separate read-only phase. Reusing a snapshot does not make cloud calls.

`peaso.checks.CHECKS` holds frozen `Check` objects. The stable entrypoint is `peaso.checks.evaluate_check(check_id, native_resource, scoped_index) -> (status, evidence)`. The engine owns snapshot validation, deterministic finding IDs, scope isolation, coverage accounting and reporting. A check declares its native collection dependencies, version, severity, rationale, remediation and reference sources in its public catalog entry. Index collections and resources are limited to the resource's scope; a namespace or account dependency must be explicitly collected and joined.

PASS and FAIL describe the specific collected configuration predicate. UNKNOWN describes missing, denied detail, malformed, unsupported or ambiguous facts. DENIED, EMPTY and UNKNOWN inventory findings represent collection coverage, not security passes. Partial inventories preserve observed resource evidence and add an UNKNOWN remainder. MANUAL preserves conditional declarations, inherited controls and policies that need additional context. NOT_APPLICABLE requires affirmative applicability evidence; it never means that a collection failed. Missing securityContext fields use documented Kubernetes defaults only when a native Pod/container specification was collected.

Every security check carries `HackTricks Cloud Best Practices`. Other frameworks are attached only through reviewed upstream references. Framework selection uses family names; exact framework names, versions, control IDs, source paths and nested benchmark IDs remain mapping metadata. A framework control does not create another executable check: selecting several frameworks evaluates the native predicate once and attaches all of its verified mappings. These tags do not assert certification or complete framework coverage.

The reference inventory is `peaso/rulepacks/upstream_manifest.json`. Each upstream catalog check/control has an explicit `ported`, `merged`, `pending` or `rejected` disposition, reason and native associations. Pending and rejected rows cannot identify executable support. A narrower related native predicate uses `related_native_checks` and stays pending until the upstream predicate has been ported. The full Prowler source inventory is retained, including providers outside Peaso's AWS/GCP/Azure/Kubernetes runtime; those entries remain pending and have `runtime_provider_supported=false`. Framework-only controls and catalog references are not counted as executable native predicates.

`sources.json` pins repository revisions and Apache-2.0 licenses, including license and reference-corpus hashes. `reviewed.json` and provider review shards record explicit associations; the generator never matches titles heuristically. The source directories are reference material only. `native_catalog.json` is a reproducible export of executable check metadata. The manifest retains upstream Python/SQL source hashes, source paths, versions, dependencies, rationale and framework associations, plus native evaluator versions and expected offline cost.

`framework_catalog.json` lists source checklist/version selectors separately from family filters. Each has its exact root ID, declared name/version, provider, source revision, supported native IDs and pending source count. A version with no native predicates is `pending`, and a version with some predicates is `partially_supported`; the catalog never labels an entire checklist complete. `Check.framework_ids` supplies the verified selectors associated with that native predicate.

The accepted registry/source state is updated in `peaso/rulepacks/catalog_summary.json` and `runtime_metadata.json`; the full audit master and `active_reviews.json` remain authoritative. During expansion, native binding counts and source dispositions can change with each reviewed batch. Native resource/scope bindings are actual tested evaluators, while unsupported, unreviewed or staged source rows remain pending. Non-target providers are explicitly `out_of_scope`; human-attestation requirements are retained separately from automatic predicates and invalid/obsolete exclusions.

Reproduce the manifest from local copies of the pinned archives, then validate it:

```sh
python scripts/peaso_review_catalog.py --sources-root /path/to/pinned-sources --write
python scripts/peaso_review_catalog.py --validate
python -m pytest tests/test_peaso_checks*.py -q
```

The generator verifies the source corpus against the pinned hashes before parsing. It reads JSON metadata and Turbot declaration blocks, hashes source text, walks framework roots and preserves control ancestry; it executes none of the reference code. A missing provider review, changed source corpus or unknown supported native ID is an error, rather than a supported catalog entry.

Native semantic choices follow current official provider documentation. Examples reviewed on 2026-10-10:

| Predicate | Provider semantics and limitation | Official reference |
| --- | --- | --- |
| S3 default encryption | New object uploads are automatically encrypted; unavailable legacy configuration is UNKNOWN, rather than an unencrypted-bucket failure. Existing object encryption requires separate facts. | [S3 encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html) |
| S3 ACL/public controls | A declared public ACL is separate from effective public access; account/bucket controls and object ownership can suppress its effect. | [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) |
| Root MFA | Root accounts with no active password or access keys are not required to maintain login MFA. Missing credential-report fields remain UNKNOWN. | [IAM credential-report fields](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html) |
| EKS logging | Five documented control-plane categories are reviewed; enabled logging is configuration evidence, not proof of delivery. | [EKS control-plane logging](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html) |
| GCS public access prevention | Only `enforced` and `inherited` are valid states. Inheritance requires organization-policy evidence; it is UNKNOWN without it. | [GCS public prevention](https://docs.cloud.google.com/storage/docs/public-access-prevention) |
| GKE network policies | Autopilot and Dataplane V2 provide a policy engine without the legacy Calico enable flag. Policy coverage and runtime enforcement are separate. | [GKE network policy](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/network-policy) |
| Cloud SQL TLS | Native `sslMode` distinguishes encrypted-only and trusted-client-certificate modes. Legacy `requireSsl` alone does not establish the full modern mode. | [Cloud SQL TLS](https://docs.cloud.google.com/sql/docs/mysql/authorize-ssl) |
| Azure storage TLS | TLS 1.3 connections are supported, but the minimum-version setting currently accepts TLS1_0, TLS1_1 and TLS1_2. Unrecognized values stay UNKNOWN. | [Azure minimum TLS](https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version) |
| Azure secure transfer | The HTTPS requirement is a REST transfer setting; individual SMB/NFS encryption controls need their own facts. | [Azure secure transfer](https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer) |
| Kubernetes workload hardening | Pod and container contexts inherit according to API semantics; init and ephemeral containers also matter. Linux-only controls are inapplicable to explicit Windows Pods. | [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) |

The implemented scope includes storage configuration, IAM credential posture, logging, databases, managed Kubernetes, VM hardening, declared network rules, RBAC declarations and workload security contexts. Declared grants are not effective permissions, and public configuration is not proven reachability. Kubelet/control-plane flags, secret contents, CNI enforcement, organization inheritance, historical activity and unsupported services cannot be inferred from missing facts. Source checks requiring those facts remain pending unless equivalent evidence is available.

The optional batch backend is `peaso.checks.batch.evaluate_many(check_ids, native_items, backend="duckdb")`; semantic rules continue to use Python. It accepts only registered strict scalar predicates, loads JSON into an in-memory database and runs Peaso-authored SQL. Its SQL verifies object/primitive types and per-field coverage before comparing values. DuckDB absence or an unsupported backend/check is explicit, and Python remains the default.

```sh
python -m pip install 'peaso[analytics]'
python scripts/peaso_review_catalog.py --benchmark
```

The fixed performance fixture has 100,000 EBS records, missing fields and denied records. Python and DuckDB must produce identical status arrays: 35,136 UNKNOWN, 32,432 PASS and 32,432 FAIL. The benchmark includes JSON conversion and database loading, so it can be slower than Python for a single simple rule. It makes no claim about provider collection throughput or guaranteed speedup.

The recorded local run in `peaso/rulepacks/performance.json` took 0.098 seconds for Python row results, 0.190 seconds for DuckDB row results and 0.059 seconds for DuckDB set-based summary counts; all statuses/counts matched. `summarize_many` avoids materializing Python findings for every row and is useful for large snapshot facets. These single-run timings are reproducible fixtures, not throughput guarantees.

Validation ran 1,845 registry, scalar-backend and provider-extension assertions, including passing/failing fixtures where applicable, unavailable/malformed facts, purity, source associations, version/applicability boundaries and framework conservation. Captured live AWS, Azure and local Kubernetes snapshots were re-evaluated through the current engine without authentication or cloud calls: respectively 259/1,500/155 resources and 439/2,551/333 findings. Exact repeated reports matched and the input snapshots remained unchanged. Coverage remained explicitly incomplete. Count/timing evidence is in `peaso/rulepacks/integration_summary.json`; raw private snapshots are not included in the rulepacks. No authenticated live GCP snapshot was available, so GCP live validation remains unfinished.
