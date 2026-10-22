# Peaso native snapshot engine

Peaso separates bounded read-only collection from offline evaluation. `peaso.engine.collect_snapshot(request)` produces a content-addressed snapshot; `evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None)` evaluates collected facts without credentials or provider calls. `run_scan(request)` returns the report plus its snapshot, and `peaso.reports.render_markdown(report)` exports all findings, structured evidence, native inventory, coverage, and both defensive graphs.

The original IAM/RBAC scanner entrypoints now delegate configuration review to this native engine. External hardening runtimes, images, database workers, credential materializers and their image/runtime/timeout flags have been removed. Historical Prowler/Turbot source definitions are provenance for reviewed native adaptations only; they are not executable coverage. Existing scanner authentication and IAM behavior remain intact, including the legacy AWS scanner's opt-in/out Access Analyzer behavior: supply `--no-access-analyzer` for a read-only legacy invocation. The native AWS collector can request IAM access reports and manage temporary Access Analyzers when the connector enables those operations; collection records their lifecycle and cleanup evidence. See the [AWS collector guide](peaso-aws-collector.md) for the required permissions and options.

## Install and reproducible commands

From the repository root:

```sh
python3 -m pip install -e '.[cloud,test,hosted,analytics]'
peaso catalog -o /tmp/peaso-catalog.json
peaso scan --provider aws --demo --snapshot-output /tmp/aws-snapshot.json -o /tmp/aws-report.json
peaso evaluate /tmp/aws-snapshot.json --format markdown -o /tmp/aws-report.md
peaso report /tmp/aws-report.json --format markdown -o /tmp/aws-export.md
peaso diff /tmp/aws-report.json /tmp/aws-report.json --format markdown -o /tmp/aws-diff.md
peaso scan --provider gcp --demo --format markdown -o /tmp/gcp-report.md
peaso scan --provider azure --demo --format markdown -o /tmp/azure-report.md
peaso scan --provider k8s --demo --format markdown -o /tmp/k8s-report.md
```

The offline demos contain authored synthetic data and denied/missing coverage; they are not live cloud assessment evidence. [AWS sample snapshot](../examples/aws-demo-snapshot.json), [JSON report](../examples/aws-demo-report.json), and [full Markdown report](../examples/aws-demo-report.md) are durable examples.

`scan`, `collect` and `evaluate` emit progress to stderr by default; redirected JSON/Markdown stdout remains machine-readable. Updates show phase, provider, selected scope, settled inventory/check count, resource count and elapsed time. ETA is estimated only when a fixed total is known; discovery and expanding child inventories report unknown ETA. A background heartbeat continues during blocked provider reads. Use `--quiet` to suppress progress. The callback is runtime-only and is absent from connectors, snapshots and reports. Existing processes load their prior code; the new behavior applies to new invocations.

For live operation, select `--provider`, `--scopes`, and provider authentication through `--profile`, `--context`, or a private JSON/YAML `--auth-file`. Full JSON/YAML requests can be supplied with `--request`. An existing JSON snapshot can be evaluated through `--snapshot` without cloud calls. Supported auth field names and scope formats are documented in the [AWS](peaso-aws-collector.md), [GCP](peaso-gcp-collector.md), and [Azure/Kubernetes](peaso-azure-k8s-collectors.md) collector guides; hosted availability depends on those portable credential contracts.

A complete request has this shape:

```json
{
  "connector": {
    "provider": "aws",
    "name": "audit",
    "auth": {"profile": "auditor"},
    "scopes": ["111111111111"],
    "options": {"regions": ["us-east-1"], "max_pages": 10, "max_resources": 10000, "max_calls": 200}
  },
  "categories": ["hardening"],
  "checks": ["aws.ec2.imdsv2"],
  "frameworks": ["hacktricks"]
}
```

Common categories include `hardening`, `exposure`, `least_privilege`, `iam_graph`, and `network`; `peaso catalog` lists the complete current selection. Missing or empty category/check/framework lists mean the default selection, matching the API. Check IDs and framework names come from `peaso catalog`; unknown IDs and unsupported frameworks fail early. `hacktricks` aliases `HackTricks Cloud Best Practices`; NIST aliases are available only where reviewed mappings support that family.

## Planning, bounds and immutable facts

Default live collection unions selected native-check dependencies with selected graph and defensive-review prerequisites. A hardening scan containing only `aws.ec2.imdsv2` plans `instance` inventory. Explicit `connector.options.inventories` overrides the plan to exactly the requested supported types, allowing inventory-only resources to be requested; selected checks whose facts are omitted remain unknown. `options.collect_all=true` requests all supported inventories and cannot be combined with an explicit inventory list. Snapshot metadata records whether collection followed dependencies, an explicit inventory override, or complete inventory selection.

Adapters bound total calls, page counts, resources, concurrency and retries. They deduplicate provider requests and native IDs, validate continuation tokens/origins, and preserve successful facts when later pages fail or reach a cap. Native payloads keep provider fields, constraints and conditions. Snapshots contain no connector credentials; collectors redact literal workload secrets and sensitive metadata where appropriate. Configuration inventory does not execute workloads or apply remediation. Optional selected-content checks download the explicitly selected artifacts and run offline secret/CVE scanners; private secret values are stored separately from public snapshots. AWS report generation and temporary Access Analyzer operations follow the connector configuration and permissions.

Schema `1.0` uses collections `{type,scope,service,status,items,error?}` with `collected`, `empty`, `partial`, `denied`, `unknown`, `malformed`, `timeout`, and `not_collected` states. Unavailable and empty collections have no items; partial collections retain observed facts. A missing detail remains unknown rather than inheriting a safe default. Successful facts can have a resource-level PASS while incomplete inventory also produces an explicit UNKNOWN coverage result.

Snapshots are canonical JSON addressed by a SHA-256 content digest. Validation rejects inconsistent digests, duplicate collection keys, unsupported schemas and malformed envelopes. Evaluation copies its input and does not rewrite the source snapshot. Caller-owned JSON remains editable; edited content must be sealed as a new snapshot. Resource IDs are stable global digests of provider, authoritative scope, type and native identity; `native_id` retains the provider reference. Account/region, project/location and cluster/namespace identities prevent similarly named resources from aliasing.

## Report and coverage semantics

Reports have `schema_version`, `snapshot_id`, `provider`, `scopes`, `created_at`, `resources`, `findings`, `coverage`, `graphs`, and `stats`. Findings include stable IDs, category/check/title, service/resource/scope, severity/status, framework names, structured evidence and remediation. Native statuses are PASS, FAIL, UNKNOWN, DENIED, EMPTY, MANUAL and NOT_APPLICABLE. EMPTY is an inventory result, never a security pass. Framework tags identify reviewed reference relationships and are not compliance certification.

`stats.coverage_complete` describes the selected check assessments, including unknown and manual prerequisites. `stats.inventory_complete` describes the broader declared collection envelopes, including deliberately uncollected inventory. Neither field establishes that an entire upstream catalog or compliance framework has been implemented. The catalog's `upstream_coverage` counts actual reference dispositions, and pending references do not count as supported. Native per-check fixtures and semantic scope define implemented behavior; see the native rules tests and generated manifest in `peaso/rulepacks/` for the current count.

Registered check definitions and framework mappings are distinct from evidence that a live collector can produce. `catalog_summary.json` reports `inventory_coverage` with native types, reviewed aliases and unavailable projections separately. A scan records requested unavailable projections under `snapshot.metadata.bulk_evidence.unavailable_projections`; their collections have `status=not_collected` and error code `native_evidence_projection_unavailable`. Checks that need those facts remain UNKNOWN. A declared evidence type, a positive unit fixture, or a complete framework mapping does not establish live collection coverage.

Network graph edges describe observed topology references and separately identified modeled rule relationships. They do not establish end-to-end reachability, route priority, ACL/CNI enforcement, or active service exposure. IAM graph edges describe declared policy, trust, membership and binding evidence with confidence and preserved constraints. They do not resolve all AWS SCP/boundary/session-policy intersections, GCP deny/inherited/conditional access, Azure PIM/deny inheritance, or Kubernetes external authorizers. Reference-only principals are labeled as such. Defensive review annotations provide mitigation/manual-review metadata; there are no exploit actions or executable escalation chains.

Diffs compare stable finding IDs, statuses and collected evidence within the same provider and scope selection. A source snapshot-digest change alone is ignored; configuration/evidence changes remain visible. Added/removed findings can reflect coverage or selection differences, so before/after coverage is included in every diff.

## Incremental results and performance

Hosted collectors commit bounded batches of settled inventories (64 envelopes, one second, or 8 MiB by default) before publishing their results. Completed sections become available independently; a later timeout retains the last durable partial snapshot and report. An interrupted process can lose the uncommitted batch. Section completion describes finished collection, and denied or incomplete evidence keeps its existing status.

Privilege evaluation indexes native collections once per model. Network evaluation indexes Kubernetes labels and AWS subnet associations within each evaluation, preserving native order, per-resource evidence and uncertain matches. These changes remove repeated work without reducing the selected checks, pages, resources or graph relationships. Offline phase benchmarks do not establish a cloud scan completion time.

## Validation and maintenance

Run focused tests for the changed component before the release gate:

```sh
.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_peaso_engine.py tests/test_peaso_analysis.py
.venv/bin/python scripts/peaso_compliance_materialize.py
.venv/bin/python examples/benchmark_peaso.py --resources 30000
.venv/bin/python examples/benchmark_peaso_k8s.py --resources 10000
.venv/bin/python examples/benchmark_peaso_saved_snapshot.py /path/to/private-snapshot.json
```

Benchmarks measure the supplied snapshot or synthetic fixture on the current host. They do not establish provider collection latency, effective access or production capacity. Keep live snapshots and generated results outside the repository. Do not interpret old test totals as acceptance of current source.

For an installed-package check, build and install the wheel into temporary directories, then run the offline verifier:

```sh
python -m pip wheel --no-deps --wheel-dir /tmp/peaso-wheels .
python -m pip install --no-deps --target /tmp/peaso-installed /tmp/peaso-wheels/*.whl
python -I examples/verify_installed_peaso.py /tmp/peaso-installed
```

The verifier exercises bundled native rules without network access. Provider collection, tenant isolation, API lifecycle and UI flows have separate tests. CI runs the broader Python and frontend gates; a mocked fixture proves its stated contract, not successful live collection across an entire account.

Compliance inputs and reviewed descriptions live in [compliance-ledgers](compliance-ledgers/README.md). Unsupported organizational, historical or unavailable evidence must remain excluded or explicitly unassessed; a complete mapping is not a complete live assessment.
