# Peaso native snapshot engine

Peaso separates bounded read-only collection from offline evaluation. `peaso.engine.collect_snapshot(request)` produces a content-addressed snapshot; `evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None)` evaluates collected facts without credentials or provider calls. `run_scan(request)` returns the report plus its snapshot, and `peaso.reports.render_markdown(report)` exports all findings, structured evidence, native inventory, coverage, and both defensive graphs.

The original IAM/RBAC scanner entrypoints now delegate configuration review to this native engine. External hardening runtimes, images, database workers, credential materializers and their image/runtime/timeout flags have been removed. Historical Prowler/Turbot source definitions are provenance for reviewed native adaptations only; they are not executable coverage. Existing scanner authentication and IAM behavior remain intact, including the legacy AWS scanner's opt-in/out Access Analyzer behavior: supply `--no-access-analyzer` for a read-only legacy invocation. The native AWS collector never creates or deletes an analyzer.

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

Categories are `hardening`, `exposure`, `least_privilege`, `iam_graph`, and `network`. Missing or empty category/check/framework lists mean the default selection, matching the API. Check IDs and framework names come from `peaso catalog`; unknown IDs and unsupported frameworks fail early. `hacktricks` aliases `HackTricks Cloud Best Practices`; NIST aliases are available only where reviewed mappings support that family.

## Planning, bounds and immutable facts

Default live collection unions selected native-check dependencies with selected graph and defensive-review prerequisites. A hardening scan containing only `aws.ec2.imdsv2` plans `instance` inventory. Explicit `connector.options.inventories` overrides the plan to exactly the requested supported types, allowing inventory-only resources to be requested; selected checks whose facts are omitted remain unknown. `options.collect_all=true` requests all supported inventories and cannot be combined with an explicit inventory list. Snapshot metadata records whether collection followed dependencies, an explicit inventory override, or complete inventory selection.

Adapters bound total calls, page counts, resources, concurrency and retries. They deduplicate provider requests and native IDs, validate continuation tokens/origins, and preserve successful facts when later pages fail or reach a cap. Native payloads keep provider fields, constraints and conditions. Snapshots contain no connector credentials; collectors redact literal workload secrets and sensitive metadata where appropriate. No Secret values, object contents, Pod exec, remediation, API enablement, credential-report generation or cloud resource creation is part of collection.

Schema `1.0` uses collections `{type,scope,service,status,items,error?}` with `collected`, `empty`, `partial`, `denied`, `unknown`, `malformed`, `timeout`, and `not_collected` states. Unavailable and empty collections have no items; partial collections retain observed facts. A missing detail remains unknown rather than inheriting a safe default. Successful facts can have a resource-level PASS while incomplete inventory also produces an explicit UNKNOWN coverage result.

Snapshots are canonical JSON addressed by a SHA-256 content digest. Validation rejects inconsistent digests, duplicate collection keys, unsupported schemas and malformed envelopes. Evaluation copies its input and does not rewrite the source snapshot. Caller-owned JSON remains editable; edited content must be sealed as a new snapshot. Resource IDs are stable global digests of provider, authoritative scope, type and native identity; `native_id` retains the provider reference. Account/region, project/location and cluster/namespace identities prevent similarly named resources from aliasing.

## Report and coverage semantics

Reports have `schema_version`, `snapshot_id`, `provider`, `scopes`, `created_at`, `resources`, `findings`, `coverage`, `graphs`, and `stats`. Findings include stable IDs, category/check/title, service/resource/scope, severity/status, framework names, structured evidence and remediation. Native statuses are PASS, FAIL, UNKNOWN, DENIED, EMPTY, MANUAL and NOT_APPLICABLE. EMPTY is an inventory result, never a security pass. Framework tags identify reviewed reference relationships and are not compliance certification.

`stats.coverage_complete` describes the selected check assessments, including unknown and manual prerequisites. `stats.inventory_complete` describes the broader declared collection envelopes, including deliberately uncollected inventory. Neither field establishes that an entire upstream catalog or compliance framework has been implemented. The catalog's `upstream_coverage` counts actual reference dispositions, and pending references do not count as supported. Native per-check fixtures and semantic scope define implemented behavior; see the native rules tests and generated manifest in `peaso/rulepacks/` for the current count.

Network graph edges describe observed topology references and separately identified modeled rule relationships. They do not establish end-to-end reachability, route priority, ACL/CNI enforcement, or active service exposure. IAM graph edges describe declared policy, trust, membership and binding evidence with confidence and preserved constraints. They do not resolve all AWS SCP/boundary/session-policy intersections, GCP deny/inherited/conditional access, Azure PIM/deny inheritance, or Kubernetes external authorizers. Reference-only principals are labeled as such. Defensive review annotations provide mitigation/manual-review metadata; there are no exploit actions or executable escalation chains.

Diffs compare stable finding IDs, statuses and collected evidence within the same provider and scope selection. A source snapshot-digest change alone is ignored; configuration/evidence changes remain visible. Added/removed findings can reflect coverage or selection differences, so before/after coverage is included in every diff.

## Validation and measured limits

Core validation commands:

```sh
.venv/bin/python -m pytest -q tests/test_peaso_engine.py tests/test_hardening.py tests/test_hardening_grouping.py
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q peaso bluepeass scripts
.venv/bin/python -m pip wheel --no-deps --wheel-dir /tmp/peaso-core-wheels .
.venv/bin/python examples/benchmark_peaso.py --resources 30000
.venv/bin/peaso scan --request examples/aws-live-minimal-request.json -o /tmp/peaso-live-minimal.json
```

The focused core suite exercises passing/failing native facts across four providers, denied/empty/partial/malformed/missing facts, content tampering, global IDs, selection planning, explicit inventory overrides, stable diffs, graph endpoints, Markdown fences and all one-shot CLI paths. Per-provider collectors, native check predicates, API tenancy and defensive analysis have separately owned tests in the same full suite.

The defined benchmark evaluates one native IMDSv2 predicate against 30,000 synthetic EC2 instance facts in one authoritative scope: 15,000 PASS and 15,000 FAIL, zero cloud calls. [Recorded result](../examples/benchmark-result.json) on Python 3.13.11/macOS arm64: 1.013751 seconds, approximately 29,593 resources/second. This includes snapshot validation, resource indexing and finding construction; it excludes live collection, graph generation, other predicates and export rendering. The measurement is host-specific and not a universal performance guarantee.

The core live smoke used existing AWS profile `naxusai-admin`, region `us-east-1`, instance-only inventory and strict call/resource/page bounds. Two read calls succeeded, account identity was collected and the region had no instances; the result was EMPTY rather than PASS. [Sanitized evidence](../examples/aws-live-smoke-summary.json) and [exact request](../examples/aws-live-minimal-request.json) are retained. This validates successful read access and honest empty reporting, not a live instance predicate. Broader live provider fixtures, reauthentication limitations and cleanup evidence are recorded by QA in [peaso-validation.md](peaso-validation.md).

### Extended Kubernetes controls and installed rulepack verification

The core extension adds 32 native predicates: four distinct security checks on each of Deployment, DaemonSet, StatefulSet, ReplicaSet, Job and CronJob Pod templates, plus Pod host-port/proc/SELinux-identity controls, ServiceAccount default automount, and four namespace quota relationships. Templates use the correct CronJob nesting, preserve Pod-level `runAsNonRoot` inheritance, reject explicit UID0, and inspect init and ephemeral containers. HostPort0 is permitted according to the current [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/). ServiceAccount token defaults remain distinct from Pod overrides. Quota controls require complete scoped inventory; scoped-only quotas are MANUAL rather than a namespace-wide pass. No removed PodSecurityPolicy API or unobserved host/control-plane setting is claimed assessed.

The reviewed extension shard preserves 30 upstream references. Six host-network predicates have equivalent native adaptations; the other 24 remain pending with related native check IDs because upstream SQL differs in container selection, defaults, inheritance, hostPort0 or quota scope handling. Corrected native controls remain implemented without fabricated upstream migration claims. The remaining two original Pod controls use official documentation rather than claiming an unrelated upstream mapping.

```sh
.venv/bin/python -m pytest -q tests/test_peaso_checks_k8s_extended.py
.venv/bin/python examples/benchmark_peaso_k8s.py --resources 10000
.venv/bin/python -m pip install --no-deps --target /tmp/peaso-core-isolated-wheel /tmp/peaso-core-wheels/peaso-0.1.0-py3-none-any.whl
.venv/bin/python -I examples/verify_installed_peaso.py /tmp/peaso-core-isolated-wheel
.venv/bin/python examples/benchmark_peaso_saved_snapshot.py .cache/peaso-qa/task_02a312b5ac1f/azure-uncapped/azure-snapshot.json
.venv/bin/python examples/benchmark_peaso_saved_snapshot.py .cache/peaso-qa/task_02a312b5ac1f/aws-snapshot.json
```

The [Kubernetes benchmark result](../examples/benchmark-k8s-result.json) measured 10,000 synthetic Deployment templates and 40,000 findings from four predicates in 1.942389 seconds, with zero cloud calls. [Isolated wheel verification](../examples/installed-wheel-verification.json) ran outside the checkout with socket connections blocked, produced offline reports for all four providers, and confirmed known critical AWS/GCP/Azure standalone classifications from bundled audited YAML. `risk_rules` and its source metadata now ship as a data package; missing native rulepack data remains unknown without a remote fallback. YAML uses PyYAML's safe C loader when available, retaining the safe Python fallback.

Full saved real-snapshot evaluation, with all five categories and scan-scoped analysis indexes/cache, measured [Azure](../examples/benchmark-azure-saved-result.json): 4,912 resources, 8,641 findings, 62 selected checks, cold 2.058202s / warm 2.407373s; [AWS](../examples/benchmark-aws-saved-result.json): 259 resources, 439 findings, 72 selected checks, cold 0.408448s / warm 0.118538s. Each cold/warm pair produced identical reports and left its input unchanged, with zero cloud calls. These current-catalog counts differ from earlier QA timing runs because the implementation and catalog have expanded; they are not a claim that earlier and current catalogs produce identical reports. Private cloud facts remain outside committed examples.

Exact pinned source checklist/version IDs are exposed as `catalog.framework_versions`, independently from family names. Pass an ID through `--frameworks` to select its reviewed native predicates. Pending checklists produce explicit UNKNOWN framework coverage and no invented check findings; partially implemented checklists stay incomplete. Foreign-provider checklist IDs fail early. Selected version titles, declared versions, revisions, supported counts and pending source counts are retained in both JSON and full Markdown.

The final installed-wheel smoke also blocks imports of cloud SDKs and request transports, establishing that native evaluation and bundled risk classification work without provider clients. An explicit `offline=True` classifier mode and engine-scoped context reject missing/corrupt/wrong-provider YAML without downloading fallback data. Legacy scanner classification keeps its original default fallback behavior.

Final full shared-suite checkpoint: **2,386 passed, one skipped in 46.53 seconds** using `.venv/bin/python -m pytest -q`. [Sanitized core validation summary](../examples/peaso-core-validation-summary.json) records native/reference counts, installed-wheel verification and live-smoke limits. The release wheel was built with `.venv/bin/python -m pip wheel --no-deps --wheel-dir /tmp/peaso-core-release-wheel .`, installed into `/tmp/peaso-core-release-installed`, and verified with `.venv/bin/python -I examples/verify_installed_peaso.py /tmp/peaso-core-release-installed`.
