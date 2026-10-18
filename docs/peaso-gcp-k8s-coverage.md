# GCP and Kubernetes native source coverage

The worker reviewed every retained assigned reference: **500 GCP and 769
Kubernetes rows (1,269 total)**, with no overlaps against the 326 source IDs
transferred to Claude. The initial partition was GCP725/Kubernetes870. Exact
source IDs, revisions, query/evaluator hashes and source URLs are retained in
owned review shards; references include every associated framework/checklist
lineage. These are authored dispositions. Registry lead admission and master
regeneration remain separate gates; this document does not declare provider-wide
pending0 before those gates and the delegated partitions are complete.

## Semantic deduplication

There are **107 distinct native IDs associated with retained GCP source rows**
and **621 associated with Kubernetes source rows**, after exact equivalent
same-entity references are merged. Another 34 GCP/109 Kubernetes IDs provide
corrected alternatives to substantively invalid source predicates. Partition
counts overlap when canonical IDs are shared. Additional QA signals and modern
intent policies are separately labeled and do not become fake upstream ports.

A native ID includes its actual entity/application scope. Pod declarations and
desired Deployment/Job/CronJob templates remain distinct applications. Shared
implementation families are not counted as extra framework references. Equality
requires the same entity, field/operator/threshold, source exceptions, version
and missing/default behavior; normalized hashes or titles alone never establish
it. Calendar-midnight and elapsed-day age thresholds, explicit declarations and
known defaults, any-role and invoker-only bindings remain separate predicates.

Existing KMS public-principal and BigQuery default-CMEK/public-ACL predicates
are reused after semantic review. Binding conditions are preserved as declared
evidence; public prevention, denies, PAB and inherited conditional grants are
never flattened into an effective-access claim.

## Retained source partitions

| Provider/partition | Source rows | Ported/merged associations | Other outcomes | Distinct associated native IDs |
| --- | ---: | ---: | --- | ---: |
| gcp / compute | 71 | 45 | 26 invalid predicates | 9 |
| gcp / configuration | 20 | 20 | — | 17 |
| gcp / iam | 28 | 10 | 18 invalid predicates | 2 |
| gcp / keys | 45 | 35 | 10 invalid predicates | 7 |
| gcp / logging | 55 | 5 | 50 invalid predicates | 1 |
| gcp / manual | 44 | 0 | 44 manual requirements | 0 |
| gcp / metadata | 50 | 50 | — | 19 |
| gcp / perimeter | 25 | 14 | 11 invalid predicates | 10 |
| gcp / relationships | 26 | 5 | 21 invalid predicates | 1 |
| gcp / services | 136 | 133 | 3 invalid predicates | 42 |
| k8s / cluster | 46 | 44 | 2 invalid predicates | 39 |
| k8s / components | 513 | 413 | 100 invalid predicates | 413 |
| k8s / reference config | 33 | 23 | 10 invalid predicates | 23 |
| k8s / workloads | 177 | 159 | 18 invalid predicates | 159 |

Manual-only INFO source controls retain their questions and complete source
lineage and must produce MANUAL presentation. Invalid predicates retain specific
counterexamples/provider evidence and applicable replacement guidance. Missing
implementation, inaccessible data or absent APIs are never rejection reasons.
No always-UNKNOWN evaluator is counted as a port.

## Native service/entity counts

Counts below are unique associated IDs in this worker's retained source scope,
not all checks already present in the repository or delegated worker coverage.

| Provider | Native service/entity | Unique associated IDs |
| --- | --- | ---: |
| gcp | alloydb_cluster | 1 |
| gcp | alloydb_instance | 3 |
| gcp | api_key | 3 |
| gcp | app_engine_application | 1 |
| gcp | bigquery_dataset | 2 |
| gcp | bigquery_table | 1 |
| gcp | bigtable_instance | 1 |
| gcp | billing_account | 1 |
| gcp | bucket | 1 |
| gcp | cloudrun_job | 1 |
| gcp | cloudrun_service | 4 |
| gcp | dataproc_cluster | 1 |
| gcp | disk | 1 |
| gcp | dns_managed_zone | 3 |
| gcp | function | 6 |
| gcp | gke_cluster | 12 |
| gcp | iam_policy | 2 |
| gcp | instance | 7 |
| gcp | kms_key | 2 |
| gcp | log_sink | 1 |
| gcp | network | 2 |
| gcp | project | 3 |
| gcp | service_account | 1 |
| gcp | service_account_key | 1 |
| gcp | sql_instance | 44 |
| gcp | subnetwork | 2 |
| k8s | clusterrole | 2 |
| k8s | clusterrolebinding | 1 |
| k8s | configmap_metadata | 1 |
| k8s | cronjob | 65 |
| k8s | daemonset | 65 |
| k8s | deployment | 65 |
| k8s | ingress | 1 |
| k8s | job | 65 |
| k8s | namespace | 10 |
| k8s | networkpolicy | 2 |
| k8s | pod | 72 |
| k8s | podsecuritypolicy | 7 |
| k8s | podtemplate | 61 |
| k8s | replicaset | 65 |
| k8s | replicationcontroller | 66 |
| k8s | role | 2 |
| k8s | rolebinding | 2 |
| k8s | secret_metadata | 1 |
| k8s | service | 2 |
| k8s | serviceaccount | 1 |
| k8s | statefulset | 65 |

## Fact and applicability boundaries

GCP supports 70 selected native inventory types, with broad CAI resource/IAM
coverage plus direct hydration. Project/org/folder selection, ancestry, shared
VPC ownership, builtin/custom role definitions, denied/empty/partial/unavailable
states, source requests and explicit limits remain visible. No implicit call,
page, resource or scope caps apply; concurrency/retries/timeouts/cancellation
remain bounded. Auth sources are selected explicitly and never fall back to
unrelated credentials or enable APIs. Inline federation is tested against real
google-auth2.45 and2.61 SDK transport behavior. Service account policy hydration
uses the official read-only POST with empty body and version3 query options.
[Service account IAM API](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/getIamPolicy).

GCP includes metadata-only API keys, BigQuery dataset/table encryption and ACLs,
AlloyDB, Dataproc, DNS, selected service state, logging metrics/alert policies,
Essential Contacts, Access Approval, Billing/Bigtable/Cloud Run metadata, Cloud
Identity groups/direct+transitive membership and Workspace user/role flags.
API-key strings, secret values, raw/wrapped keys and credential-shaped fields
are excluded. Conditions and collection limitations remain evidence.

Kubernetes uses actual Pod/controller/Job/CronJob/PodTemplate paths with regular,
init and ephemeral containers. Namespaces are administrative scopes, never
subnets. Ordinary workloads are outside component-flag applicability; ambiguous
actual components remain UNKNOWN. Approved PodSpec executable/flag projections
and supplied metadata do not prove host/runtime configuration. No node exec,
host filesystem read, pod logs or Secret values are performed.

Secret/ConfigMap inventory negotiates PartialObjectMetadataList and exact-version
namespace Table type metadata, with no full-object JSON fallback. Annotation
scrubbing occurs before the shared reader boundary.
[Kubernetes API representations](https://kubernetes.io/docs/reference/using-api/api-concepts/).
PSP absence is NOT_APPLICABLE only with observed modern server version and
resource advertisement evidence; denied discovery stays a gap. PSP alternatives
require separate PSA/SCC guidance and do not imply secure admission.

Pod automount precedence is explicit Pod setting, then the exact same-cluster/
namespace ServiceAccount, then documented default true. Missing/denied/ambiguous
SA metadata stays UNKNOWN. The owned helper is ready for registry-owner adoption
under the existing canonical ID; this worker did not edit checks/k8s.py.
[Service account configuration](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/).

Bound RBAC signals inspect full roleRef/subject scope, resourceNames, supported
wildcards and aggregation selectors. Namespace bindings do not grant
cluster-scoped user/group/UID impersonation or nodes/proxy. Universal authenticated,
unauthenticated and all-SA groups remain risk; trusted addon exemptions require
matching identity metadata. Signals do not execute actions, construct privilege
chains or certify least privilege. Manual CIS requirements remain manual with
related signals. Verified 5.1.8 requirements in pinned versions1.8/1.10/1.11.1/
1.12/2.0.1 have Checks=[] and cover Bind/Escalate too; no scanner ID is invented.
[RBAC semantics](https://kubernetes.io/docs/reference/access-authn-authz/rbac/),
[RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

The pinned pull-policy SQL literally requires Always and has no digest exception.
It is retained with an explicit literal title. A separate immutable intent
variant accepts valid SHA256 pins with IfNotPresent/default pull-on-miss; those
policies are not misrepresented as equivalent upstream evaluators.
[Image digest and pull-policy behavior](https://kubernetes.io/docs/concepts/containers/images/).

## Validation and remaining integration

The owned native aggregate most recently passed **5,147 tests**; exact retained
routing/revision/hash checks passed 3. Original GCP **294 tests passed independently**
after collector changes. Actual SDK auth transport acceptance passed 10 on2.45
and the workspace2.61 acceptance plus original collector checkpoint passed 98.
Successful and failed exchanges remain isolated, with no identity fallback.

Direct pure recheck of the captured directive13 Kubernetes snapshot (346 native
resource rows, immutable digest verified) produced 1,278 PASS/492 FAIL/1,538
NOT_APPLICABLE/40 UNKNOWN. Component subset: 22 PASS/3 FAIL/1,523 NA/24 UNKNOWN.
Bound RBAC signals: 435 PASS/49 FAIL/15 NA. Automount helper: 1 PASS/17 FAIL.
419 entity-template checks had no target rows and were not declared clean.
Only native metadata/check functions were invoked, without combined evaluator
hooks or feature graphs. Private snapshot/fixture details are not published.

The coordinator confirmed refreshed explicit gcloud login and assigned a separate
live GCP/GKE acceptance owner. This worker does not claim that live acceptance
passed and created no cloud resources. The live owner maintains its disposable
fixture/cleanup ledger. Full repository/commit gates are supervisor owned; this
worker performed no Git mutations.

Remaining lead/core integration: admit ready review shards, preserve all
framework/manual lineage during master regeneration, apply accepted-history
source corrections, adopt canonical automount and related RBAC mappings, and
expose explicitly proven GCP ancestor/Kubernetes global metadata in scoped joins.
Orca runtime connectivity is currently unavailable; attempted lifecycle updates
are recorded in the durable handoff until coordination resumes.

```sh
.venv/bin/python -m pytest tests/test_peaso_checks_gcp_ports*.py tests/test_peaso_checks_k8s_ports*.py tests/test_peaso_collectors_gcp.py tests/test_peaso_checks_gcp_extended.py -q
.venv/bin/python -m pytest tests/test_peaso_collectors_gcp.py tests/test_peaso_checks_gcp_extended.py -q
python3 -m pytest tests/e2e/test_gcp_auth_acceptance_transport.py -q
```
