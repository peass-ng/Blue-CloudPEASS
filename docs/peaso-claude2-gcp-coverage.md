# PEASO claude2_gcp coverage

Partition `claude2_gcp` in `peaso/rulepacks/port_partitions_claude2.json`: 105 upstream rows (Steampipe
gcp-compliance CIS v1.2.0 to v4.0.0 controls, four policy-bundle controls and seven Prowler GCP checks).

## Artifacts

- `peaso/checks/claude2_gcp.py`: the loader, registered with `from . import claude2_gcp  # noqa: E402,F401`.
- `peaso/checks/claude2_gcp_common.py`: the strict helpers and the `gcp.claude2.` registrar.
- `peaso/checks/claude2_gcp_logfilter.py`: a three-valued Cloud Logging query-language evaluator.
- `peaso/checks/claude2_gcp_logging.py`: the CIS 2.4-2.11 metric/alert predicates and the CIS 2.2 all-entries sink predicate.
- `peaso/checks/claude2_gcp_services.py`: the Cloud Functions, Cloud Run, API key, BigQuery and Cloud SQL predicates.
- `peaso/rulepacks/reviewed_claude2_gcp.json`: the review shard. There is no `_manual.json`, because no row needed manual attestation.
- `tests/test_peaso_checks_claude2_gcp.py`: tests for shard integrity, PASS/FAIL/UNKNOWN/MANUAL/NOT_APPLICABLE fixtures and filter semantics.

## Counts

| Disposition | Rows |
| --- | --- |
| ported | 54 |
| merged | 51 |
| manual | 0 |
| rejected | 0 |
| dropped (owned by another active shard) | 0 |

Unique predicates: 29 in total. Of these, 17 are new `gcp.claude2.*` predicates and 12 are existing natives used as merge targets.

`prowler.gcp.bigquery_dataset_cmk_encryption` was pending in `reviewed_gcp.json`. It is ported here with `supersedes`.

### Ported predicates

| Predicate | Rows |
| --- | --- |
| `logging.metric_alert_project_ownership_changes` | CIS 2.4 x5 |
| `logging.metric_alert_audit_configuration_changes` | CIS 2.5 x5 |
| `logging.metric_alert_custom_role_changes` | CIS 2.6 v1.2-v3.0 x4 |
| `logging.metric_alert_custom_role_changes_with_undelete` | CIS 2.6 v4.0 x1 |
| `logging.metric_alert_firewall_rule_changes` | CIS 2.7 x5 |
| `logging.metric_alert_route_changes` | CIS 2.8 x5 |
| `logging.metric_alert_network_changes` | CIS 2.9 x5 |
| `logging.metric_alert_bucket_iam_changes` | CIS 2.10 x5 |
| `logging.metric_alert_sql_instance_configuration_changes` | CIS 2.11 x5 |
| `logging.sink_all_log_entries` | CIS 2.2 x5 |
| `function.ingress_not_allow_all` | policy-bundle |
| `function.not_publicly_accessible` | policy-bundle and Prowler `cloudfunction_function_not_publicly_accessible` |
| `function.vpc_connector_configured` | policy-bundle and Prowler `cloudfunction_function_inside_vpc` |
| `cloudrun_service.invoker_not_public` | policy-bundle |
| `api_key.created_within_90_days` | Prowler `apikeys_key_rotated_in_90_days` |
| `bigquery_dataset.default_cmek` | Prowler `bigquery_dataset_cmk_encryption` |
| `sql_instance.only_private_ip_addresses` | Prowler `cloudsql_instance_private_ip_assignment` |

### Merged rows

| Rows | Native predicate |
| --- | --- |
| CIS 2.3 x5 | `gcp.claude.bucket.log_sink_retention_locked` |
| CIS 2.12 x5 | `gcp.claude.network.dns_logging` |
| CIS 3.3 x5 | `gcp.claude.dns_zone.dnssec_enabled` |
| CIS 3.4 x5 | `gcp.claude.dns_zone.ksk_not_rsasha1` |
| CIS 3.5 x5 | `gcp.claude.dns_zone.zsk_not_rsasha1` |
| CIS 1.9 x5 | `gcp.reviewed.kms.no_public_iam` |
| CIS 5.1 x5 | `gcp.storage.no_public_iam` |
| CIS 6.6 x5, Prowler `cloudsql_instance_public_ip` | `gcp.claude.sql_instance.second_gen_no_public_ip` |
| CIS 7.1 x5 | `gcp.reviewed.bigquery.no_public_acl` |
| CIS v2.0 6.2.9 | `gcp.claude.sql_instance.private_ip_only` |
| CIS v3.0/v4.0 1.12, Prowler `apikeys_key_exists` | `gcp.claude.project.no_api_keys` |
| CIS v3.0 8.1 | `gcp.ports.dataproc_cluster_encryption_with_cmek` (upstream mapping corrected, see below) |

## Notable corrections

### CIS log-metric controls (2.4-2.11)

Steampipe and Prowler match the CIS filter with a literal regex. That approach has two problems:

- It misses equivalent filters, such as reordered terms, an implicit AND, value groups like `methodName:("a" OR "b")`, snake_case field names, or the unparenthesized `type AND a OR b` form. In the Logging language that form means `type AND (a OR b)`.
- It ignores whether the alert notifies anyone.

The native evaluator instead parses each metric filter and evaluates it with three-valued logic. It runs the filter against synthetic Admin Activity entries for every change the CIS filter captures, including both the v1 and beta Compute methods.

- **Metric match:** a metric counts only when it provably matches every entry.
  - The following are uncertain: undecidable comparisons, case-only differences under `=`, bare text that is not found, filters that cannot be parsed, and bucket-scoped metrics.
  - An uncertain metric can lead to MANUAL, never PASS.
- **Alert:** the metric must have an enabled alert policy with a `metric.type="..."` threshold condition.
  - The following lead to MANUAL: MQL or PromQL references, AND-combined multi-condition alerts, and log-match alerts.
  - `conditionAbsent` does not count.
- **Notification:** the alert needs at least one enabled notification channel.
  - If an alert lists channels but the channel inventory was not collected, the result is UNKNOWN.
- **FAIL** requires all of the following. Otherwise the result is MANUAL, or UNKNOWN when a required inventory is incomplete.
  - The project's `_ancestry` shows no folder or organization ancestors. If it does have ancestors, the (future) `_inherited_sinks` fact must be collected and must show no includeChildren sink to a log bucket.
  - No project sink routes to another project's log bucket.
  - If a local metric exists, the (future) `_monitoring_metrics_scopes` fact proves that no other scoping project exists.

### Other corrections

- **CIS 2.2:** upstream alarms whenever a project has no local empty-filter sink, even when an organization aggregated sink exports everything. The native returns MANUAL for projects with uncollected ancestor sinks, and MANUAL when an empty-filter sink has active exclusions.
- **CIS v3.0 8.1:** the upstream control maps the Dataproc CMEK title to the `bigquery_dataset_not_publicly_accessible` query. The row is merged onto the Dataproc CMEK predicate that implements the CIS recommendation.
- **API key age:** this follows Prowler's `.days > 90` boundary. It is not merged onto `gcp.ports.iam_api_key_age_90`, which uses a different calendar cutoff.
- **Cloud Functions public access:** 2nd-gen functions are joined to their backing Cloud Run service, as Prowler does. Public `roles/run.invoker` or `invokerIamDisabled` gives FAIL. A missing join gives UNKNOWN.

## Rejections

None.

## COLLECTOR FACTS NEEDED

The GCP collector is Codex-owned and was not edited. Every item below is read-only.

1. **`monitoring_notification_channel`** (project scope)
   - API: `GET https://monitoring.googleapis.com/v3/projects/{project}/notificationChannels`
   - Fields: `notificationChannels(name,type,enabled,verificationStatus)`
   - Effect: until this is collected, every log-metric predicate whose alert lists channels returns UNKNOWN. It never returns PASS in that case.
2. **`project._inherited_sinks`**
   - API: for every folder and organization ancestor of a project, `GET https://logging.googleapis.com/v2/{ancestor}/sinks`
   - Fields: `sinks(name,destination,filter,disabled,includeChildren,interceptChildren,exclusions)`
   - Format: attached as a list to the project item, absent when not collected.
   - Effect: without it, projects that have ancestors are MANUAL for CIS 2.2 and for the metric FAIL path.
3. **`project._monitoring_metrics_scopes`**
   - API: `GET https://monitoring.googleapis.com/v1/locations/global/metricsScopes:listMetricsScopesByMonitoredProject?monitoredResourceContainer=projects/{project}`
   - Fields: `metricsScopes(name)`
   - Effect: without it, "local metric exists but there is no notifying alert" stays MANUAL, because an alert may live in a scoping host project.
4. **`logging_metric.bucketName`**
   - Change: add `bucketName` to the existing `metrics(...)` field mask of `projects.metrics.list`.
   - Effect: lets bucket-scoped metrics, which only count entries routed to that bucket, be treated as uncertain.
