# Proposed new checks

The catalogues list proposed controls and their collection needs. Controls with the same provider, resource kind, and predicate intent share one canonical ID; `aliases` lists merged proposed IDs. A different threshold, scope, field, or condition remains a separate control.

| Provider | Distinct controls | Need new collection | Top resource kinds / services |
| --- | ---: | ---: | --- |
| AWS | 287 | 260 | `iam_policy` (11), `cloudtrail` (11), `wafv2_web_acl` (11), `lambda_function` (9), `ssm_managed_instance` (9), `kms_key` (8), `cloudwatch_alarm` (7), `instance` (7) |
| AZURE | 369 | 295 | `scheduled_query_rule` (31), `vm` (27), `storage_account` (15), `postgresql_single_server` (8), `ml_compute` (8), `api_management` (8), `application_gateway` (8), `directory_user` (7) |
| GCP | 129 | 101 | `audit_log` (11), `bucket` (10), `sql_instance` (9), `instance` (7), `iam_policy` (6), `workbench_instance` (6), `project` (5), `backend_service` (5) |
| K8S | 104 | 43 | `file_metadata` (27), `pod` (17), `admission_policy` (12), `networkpolicy` (10), `component_configuration` (5), `namespace` (5), `ingress` (5), `service` (5) |

**Research inventory total:** 889 controls; 699 marked as needing new collection. The verified ledger embeds **884 distinct signed proposals** (AWS 286, Azure 365, GCP 129, K8s 104). The five research-only IDs are `aws_backup_plan_cross_region_copy`, `azure_c5_ops_05_01ac`, `azure_c5_ops_31_01b`, `azure_c5_ops_31_02b`, and `azure_c5_pss_03_03b`; they are not signed runtime proposals. The collection flag is a research estimate, not proof that an evaluator can currently run.

`needs_new_collection` is conservative: it is false only when the source explicitly says the evidence is already collected. A new or extended read-only call, or an unspecified collection status, is true.
