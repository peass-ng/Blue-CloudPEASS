# PEASO gap audit (2026-10-10)

Branch `feat/peaso-cspm`, worktree state as of 2026-10-10 (HEAD `3d9b19f` plus uncommitted edits by other agents).

This audit was read-only. No repo files were changed apart from this document. AWS was accessed through `--profile naxusai-admin` using only get/list/describe calls.

Scratch scripts and raw outputs are in `/private/tmp/claude-501/-Users-carlospolop-git-Blue-CloudPEASS/32170eee-6a9b-41b2-90e5-63caa171ca85/scratchpad/audit/` (`q1/`, `q2/`, `q34/`, `q5/`). Every number below can be reproduced from those scripts.

## Answers at a glance

| Owner question | Answer | Key number |
|---|---|---|
| All privescs (AWS/GCP/K8s/Azure) in the YAMLs? | **Against the pinned HackTricks revision, nearly. Against current HackTricks, no.** | Pinned rev: 1,435 technique headings, ~20 real gaps (16 of them Azure). Current upstream: 145 privesc pages with no entry; 250 headings name permissions absent from catalog and exclusions; EKS has 0 entries. External tools: Pacu/Rhino, PMapper and Rhino-GCP fully covered; AzureHound 3 missing; KubeHound 3 missing. |
| All checks of every checklist supported? | **No** | 1,089 of 5,844 in-scope upstream rows (18.6%) have a native evaluator; 4,116 pending. Latest CIS automated: AWS v7 15%, GCP v5 18%, Azure v6 15%, K8s v2.0.1 2.5%. CIS EKS/GKE/AKS not vendored. 130 of 233 collected inventory types have 0 checks. |
| Engine as fast as possible without losing checks? | **No** | Privesc ~O(n²) in principals: 3,130 principals took 378 s and 3.4 GB. 63% of CPU at 1x is `deepcopy`. Admin edges are computed and then discarded: 11.7M at 10x. |
| Maps scalable to thousands of assets/principals? | **No** | Privesc map: 4.3 s layout at 150 nodes, 216 s at ~600, "Show more" unbounded. IAM projection turns 5k principals into 4 nodes. Network paging drops cross-page edges. |
| 0 false positives everywhere? | **No** | 6 FP out of 30 sampled FAILs (20%), all in privesc (6 of 16 = 37.5%). Pattern-matched across all 200 privesc FAILs: 53 (26.5%). 155 of 200 privesc FAILs rest on unevaluated conditions. |
| Detecting every network/permission exposure? | **No** | Of 73 exposure scenarios, 27 (37%) have a FAIL-capable check; 15 get generic MANUAL/UNKNOWN only; 31 are not evaluated or not collected. Cross-account trusts in the real account are UNKNOWN/info by default. No internet-to-asset path model. |

## 1. Privesc catalog completeness

**Short answer.** Against the HackTricks revision the catalog was written from (`a53b46392c`), AWS, GCP and K8s are essentially complete, and Azure has about 16 real gaps. Against **current upstream HackTricks (`171e422`, 2026-10-09)** the catalog is well behind:

- **145 privesc pages have no catalog entry.**
- **250 technique headings name permissions that appear in neither the catalog nor any exclusion file.**
- **EKS IAM-to-cluster-admin escalation is entirely missing.**

Against public tools, coverage is complete for Pacu/Rhino AWS, PMapper and Rhino GCP. It is incomplete for BloodHound/AzureHound (3 missing, 1 partial) and KubeHound (3 missing, 1 partial).

**Method.** Scripts are in `scratchpad/audit/q1/`: `privesc_cov.py`, `semantic.py` and `extcheck.py`.

- `privesc_cov.py` walks `{aws,gcp,azure,kubernetes}-security/**` pages matching `*privesc*`, plus the Entra ID privesc/abuse pages, the K8s RBAC-abuse, namespace-escalation, pivot-to-cloud and inside-pod pages, and OpenShift privesc. It extracts H2–H6 headings using mdBook anchors, ignores code blocks, and drops generic headings.
- A heading counts as **mapped** when its anchor, or an ancestor's anchor, matches a catalog `source` or an `_excluded*.yaml` line.
- `semantic.py` re-checks each unmapped heading: are the permission names it mentions present anywhere in the catalog or exclusions?
- Catalog `source_revision`: 551 references point to `a53b46392c` and 5 to `6bdd8e89e6`. The local checkout is at `6bdd8e89e6`, which has no `src/` diff from `a53b46392c`. Upstream is `171e422`, cloned fresh into the scratchpad.

### 1a. Coverage against the pinned revision (local checkout)

| Provider | Catalog entries | Exclusion lines | Pages | Technique headings | → catalog (+children) | → excluded (+children) | Unmapped | Real gaps after triage |
|---|---|---|---|---|---|---|---|---|
| AWS | 155 | 179 | 59 | 398 | 143 (+23) | 173 (+3) | 10 | **0** |
| GCP | 123 | 428 | 63 | 469 | 115 | 346 | 7 | **~2** |
| Azure | 128 | 235 | 57 | 450 | 105 (+14) | 223 (+21) | 51 | **~16** |
| K8s | 61 | 55 | 23 | 118 | 36 (+1) | 30 (+8) | 32 | **0–2** |
| **Total** | **467** | **897** | 202 | 1,435 | | | 100 | **~20** |

Unmapped, by provider:

- **AWS.** All 10 are sub-sections of mapped techniques: RDS extensions (`aws-rds-privesc/README.md:80,131`), Redshift external services (`:86-128`), Step Functions task resources, MediaPackage discovery and the Organizations intro.
- **GCP.** Two headings in `gcp-dataform-privesc.md` are unmapped: `invocationConfig.serviceAccount` override (line 87) and release/workflow configs (line 104).
- **Azure.** Permissions with neither an entry nor an exclusion line:
  - App Configuration `ListKeyValue`/`keyValues/read`/`RegenerateKey` (`az-app-configuration-privesc.md:34,46,89`)
  - Storage Queue `messages/process|add|write` (`az-queue-privesc.md:27,44,54`)
  - Service Bus send/receive with keys (`az-servicebus-privesc.md:193,248,357`)
  - Digital Twins query/read (`az-digital-twins-privesc.md:25,39,67`)
  - InferenceService `regenerateKeys` (`az-cosmosDB-privesc.md:230,240`)
  - `Microsoft.Maps/accounts/regenerateKey/action` (`az-maps-privesc.md:32`)
  - `automationAccounts/schedules/write` (`az-automation-accounts-privesc.md:151`)

  These need manual review: Functions Remote Debugging (`az-functions-app-privesc.md:624`), CA/MFA bypass (`az-entraid-privesc/README.md:668`), Data Factory trigger redirect (`az-data-factory-privesc.md:162`) and Video Indexer.
- **K8s.** Mostly mitigation headings, lab duplicates and host-level steps run inside a pod.
- **Broken anchor.** `peaso/privesc/catalog/azure/automation.yaml:61` points at a code-block comment, not a heading. No test in `tests/` validates catalog `source` anchors.

### 1b. Coverage against current upstream HackTricks (`171e422`)

| Provider | Privesc pages (pinned → upstream) | Upstream pages with no entry | Unmapped technique headings | Of which name permissions absent from catalog and exclusions | Broken `source` anchors |
|---|---|---|---|---|---|
| AWS | 59 → 135 | **76** | 322 | **143** | 19 |
| GCP | 63 → 86 | **25** | 135 | **32** | 308 (headings rewritten) |
| Azure | 57 → 85 | **29** | 349 | **75** | 11 |
| K8s | restructured into `kubernetes-privilege-escalation/` (15 pages) | **15** | 130 (no permission names; need manual review) | n/a | 14 (13 cited pages moved) |

New upstream pages with no catalog entry:

- **AWS:** eks, ecscape, cognito-user-pools, iot, lake-formation-grants, codeconnections, datazone, quicksight, verified-permissions, emr-serverless, managed-grafana, memorydb, elasticache, s3-tables, s3-credential-brokers, workspaces, control-tower.
- **GCP:** pam, beyondcorp, eventarc, looker, managed-kafka, vmwareengine, security-command-center.
- **Azure:** pim, intune, policy, arc-enabled-servers, hdinsight, machine-learning, spring-apps, devtest-labs, vm-code-execution, vm-managed-identity-token.
- **K8s:** helm-template-injection, validating-admission-policies, storage-and-networking, controllers-and-admission, node-permissions-and-status.

High-impact upstream techniques with **zero** catalog hits:

- **EKS.** `grep -ril 'eks:' peaso/privesc/catalog/{aws,k8s}` returns nothing. Missing (`aws-eks-privesc/README.md:29,82,117,144,182,259`):
  - `eks:CreateAccessEntry` + `eks:AssociateAccessPolicy` (IAM to cluster-admin)
  - `UpdateAccessEntry`
  - `Create/UpdatePodIdentityAssociation` + PassRole
  - `CreateNodegroup`/`CreateFargateProfile` + PassRole
- **IAM identity planting** (`aws-iam-privesc/README.md:1037-1183`): `CreateOpenIDConnectProvider`/`CreateSAMLProvider`, `AddClientIDToOpenIDConnectProvider`, `UploadSigningCertificate`, `UpdateUser`/`UpdateGroup` path moves.
- **Organizations:** `CreateAccount`, `RegisterDelegatedAdministrator`, `PutResourcePolicy`, SCP `DetachPolicy`.
- **Identity Center:** `sso:CreatePermissionSet`, `identitystore:CreateUser`, `CreateTrustedTokenIssuer`.
- **GCP:** BigQuery `datasets/tables/connections.setIamPolicy`, `routines.create` + `connections.delegate`, and Workload Identity Federation (10 headings).

### 1c. Escalations from public tools

| Source | Techniques | Covered | Excluded (with reason) | Missing |
|---|---|---|---|---|
| Pacu `iam__privesc_scan` / Rhino AWS list | 26 | 23 | 3 (CodeStar discontinued, `aws/_excluded_a.yaml`) | **0** |
| PMapper `*_edges.py` (autoscaling, CFN, CodeBuild, EC2, IAM, Lambda, SageMaker, SSM, STS, cross-account) | 24 | 24 | 0 | **0** |
| Rhino GCP-IAM-Privilege-Escalation | 23 | 20 | 3 (`orgpolicy.policy.set` treated as a guardrail, `_excluded.yaml:1028-1036`; 2 API-key methods, `:695-700`) | **0** |
| BloodHound `azure.cue` abuse edges | 42 | 36 | 2 (`AZExecuteCommand`/Intune, `SyncedToEntraUser`, `_excluded_entraid.yaml:69-74`) | **3** + 1 partial |
| KubeHound attack reference | 26 | 18 | 4 structural edges (not applicable) | **3** + 1 partial |

What is missing or partial:

- **BloodHound:**
  - Missing: **AZRoleApprover** (PIM approval), **AZGetKeys** (Key Vault keys) and **AZMGServicePrincipalEndpoint_ReadWrite_All**.
  - Partial: **AZAKSContributor**. `listClusterAdminCredential` is covered; `managedClusters/runCommand/action` is not.
  - Unverified: `AZAvereContributor`. It is covered only if built-in role actions get expanded.
- **KubeHound:**
  - Missing: **CE_MODULE_LOAD** (capabilities never parsed), **SHARE_PS_NAMESPACE** (no `shareProcessNamespace` handling) and **ENDPOINT_EXPLOIT** (an exposure edge, not a privesc one).
  - Partial: CE_SYS_PTRACE, which is detected only via hostPID.
  - Root cause: `peaso/privesc/effective_permissions/k8s.py:258-260` treats "privileged" as any of hostPID, hostNetwork, hostIPC, *any* hostPath, or a privileged container. It ignores capabilities and init/ephemeral containers. This causes both FNs and FPs, for example a hostNetwork-only pod or a read-only harmless hostPath.

## 2. Hardening checks coverage

**Short answer: No.** Of the 5,844 upstream rows that fall in a provider PEASO supports, 1,089 (18.6%) are backed by a native evaluator. 4,116 (70.4%) are still `pending`, and 639 are rejected (520 of those 639 are manual attestations). For the CIS requirements in the latest vendored version of each provider, 10 to 17% are automated. CIS EKS, GKE and AKS are not vendored at all.

### 2.1 What the engine exposes (`python3 -m peaso catalog`)

Command: `python3 -m peaso catalog --format json -o audit/q2/catalog.json` (1.2 s). The counting scripts are `audit/q2/counts.py`, `audit/q2/up.py`, `audit/q2/up2.py` and `audit/q2/svc.py`.

| Provider | Native checks (runtime) | Unique predicates¹ | Checks with ≥1 framework control | Distinct framework IDs hit | Inventory types collected | Collected types with 0 checks | Privesc techniques |
|---|---|---|---|---|---|---|---|
| AWS | 143 | 129 | 109 (76%) | 79 | 90 | 51 | see §1 |
| GCP | 89 | 87 | 57 (64%) | 28 | 50 | 36 | |
| Azure | 98 | 91 | 44 (45%) | 32 | 67 | 37 | |
| K8s | 787 | **147** | 85 (11%) | 11 | 26 | 6 | |
| all (analysis) | 5 | 5 | – | – | – | – | |
| **Total** | **1,122** (1,117 native + 5 analysis) | **454** | | | 233 | 130 | 467 |

¹ Unique predicates are distinct check-ID suffixes after removing the resource kind. The K8s count is inflated about 5.4x: the same container predicate is registered once for each of `pod`, `deployment`, `daemonset`, `statefulset`, `replicaset`, `job`, `cronjob`, `replicationcontroller` and `podtemplate`. For example, `k8s.ports.<kind>.container_argument_anonymous_auth_disabled` appears 9 times. In real terms PEASO has about 454 predicates, not 1,117.

`peaso/rulepacks/catalog_summary.json` is **stale**. It still reports 1,002 native checks (aws 118, gcp 59, azure 79, k8s 746) and 919 supported upstream rows, while the live catalog reports 1,117 and 1,089. Two in-progress modules are not imported by `peaso/checks/__init__.py:505-519`, so the counts above exclude them: `peaso/checks/azure_ports_paas.py` (container registry, databricks, cosmosdb, ...) and `k8s_ports_reference_config.py`.

**Category skew.** Hardening accounts for 133/143 AWS checks, 81/89 GCP, 94/98 Azure and 781/787 K8s. The other categories have few native checks:

| Category | AWS | GCP | Azure | K8s |
|---|---|---|---|---|
| exposure | 7 | 6 | 1 | 1 |
| network | 1 | 1 | 1 | 1 |
| least_privilege (the rest is analysis-level MANUAL review) | 1 | 1 | 2 | 2 |

### 2.2 Upstream rows by provider and source (`upstream_manifest.json`, 6,405 rows, reviewed 2026-10-10)

| Provider / source | ported | merged | pending | rejected | total | supported % |
|---|---|---|---|---|---|---|
| aws / steampipe-mod-aws-compliance | 113 | 92 | 1,339 | 68 | 1,612 | 12.7% |
| aws / prowler | 37 | 0 | 622 | 3 | 662 | 5.6% |
| aws / steampipe-mod-aws-perimeter | 0 | 0 | 62 | 0 | 62 | **0%** |
| gcp / steampipe-mod-gcp-compliance | 89 | 59 | 426 | 47 | 621 | 23.8% |
| gcp / prowler | 24 | 0 | 86 | 0 | 110 | 21.8% |
| gcp / steampipe-mod-gcp-perimeter | 0 | 0 | 33 | 0 | 33 | **0%** |
| azure / steampipe-mod-azure-compliance | 34 | 24 | 1,187 | 412 | 1,657 | 3.5% |
| azure / prowler | 24 | 0 | 167 | 0 | 191 | 12.6% |
| azure / steampipe-mod-azure-perimeter | 0 | 0 | 14 | 0 | 14 | **0%** |
| k8s / steampipe-mod-kubernetes-compliance | 578 | 11 | 92 | 109 | 790 | 74.6% |
| k8s / prowler | 4 | 0 | 88 | 0 | 92 | 4.3% |
| other providers (m365, gws, oci, ...) | – | – | – | – | 561 | out_of_scope |

**None of the perimeter mods (109 rows across AWS, GCP and Azure) are ported.** Those mods are the upstream source most directly about public and network exposure.

### 2.3 CIS and official frameworks (requirement-level)

A requirement counts as *automated* if at least one mapped upstream row is `ported` or `merged`. It counts as *manual* if the row carries `manual_requirement`. The catalog itself says the mapping assurance is "predicate scope may be narrower", so "automated" is an upper bound.

| Framework (latest vendored) | Requirements | Automated | Manual | Pending | Rejected |
|---|---|---|---|---|---|
| CIS AWS Foundations v7.0.0 (prowler `cis_7.0_aws`) | 66 | 10 (15%) | 2 | 54 | 0 |
| AWS CIS v6.0.0 (steampipe) | 63 | 7 (11%) | 3 | 53 | 0 |
| AWS Foundational Security Best Practices (steampipe) | 339 | 49 (14%) | 0 | 287 | 3 |
| AWS FSBP (prowler) | 206 | 30 (15%) | 1 | 175 | 0 |
| CIS AWS Compute Services v1.0.0 | 53 | 1 (2%) | 27 | 25 | 0 |
| CIS GCP Foundations v5.0.0 (prowler) | 71 | 13 (18%) | 0 | 58 | 0 |
| GCP CIS v4.0.0 (steampipe) | 84 | 20 (24%) | 8 | 56 | 0 |
| CIS Azure Foundations v6.0.0 (prowler) | 93 | 14 (15%) | 0 | 79 | 0 |
| Azure CIS v5.0.0 (steampipe) | 155 | 5 (3%) | 42 | 108 | 0 |
| CIS Kubernetes v2.0.1 / v1.12.0 (prowler) | 81 | **2 (2.5%)** | 0 | 79 | 0 |
| Kubernetes CIS v1.20 (steampipe) | 35 | 8 (23%) | 0 | 27 | 0 |
| Kubernetes NSA/CISA v1.0 | 100 | 77 (77%) | 0 | 23 | 0 |
| **CIS Amazon EKS** (CIS index: v2.0.0) | – | **not vendored, 0** | | | |
| **CIS GKE / GKE Autopilot** (CIS index: v2.0.0 / v1.3.0+) | – | **not vendored, 0** | | | |
| **CIS AKS** (CIS index: v2.0.0) | – | **not vendored, 0** | | | |

Across all frameworks in scope, these are the requirement-mapping totals:

| Provider | Frameworks | Requirement mappings | Automated | Manual | Pending |
|---|---|---|---|---|---|
| AWS | 82 | 8,245 | 1,584 (19%) | 104 | 6,531 |
| Azure | 35 | 4,110 | 453 (11%) | 429 | 3,228 |
| GCP | 32 | 2,457 | 650 (26%) | 44 | 1,760 |
| K8s | 11 | 1,351 | 118 (9%) | 0 | 1,233 |

CIS Kubernetes is node and control-plane configuration: kube-apiserver flags, kubelet config and etcd file permissions. The K8s collector reads only API objects. The 578 ported steampipe K8s rows are pod-spec greps for control-plane flags, which apply only to self-hosted static pods. That is why CIS K8s scores 2/81 even though K8s has 787 checks.

Latest-version references come from a web search of the CIS index, not a confirmed read, and need confirming: [CIS Kubernetes Benchmarks](https://www.cisecurity.org/benchmark/kubernetes), [CIS June 2026 update](https://www.cisecurity.org/insights/blog/cis-benchmarks-june-2026-update), [CIS AWS](https://www.cisecurity.org/benchmark/amazon_web_services).

### 2.4 Services with zero checks

These are **collected but with zero native checks**: the inventory type appears in no check `type` or `dependencies`.

- **AWS (51/90):** `cloudwatch_alarm` (blocks the CIS 4.x metric-filter alarms), `codebuild_project`, `codepipeline_pipeline`, `cognito_identity_pool`, `cognito_user_pool`, `config_delivery_channel`, `dms_replication_instance`, `docdb_*`, `ecs_cluster`, `ecs_task_definition`, `efs_file_system`, `elasticache_*`, `fsx_file_system`, `glue_job`, `glue_security_configuration`, `http_api`, `rest_api`, `iam_group`, `internet_gateway`, `memorydb_cluster`, `mq_broker`, `nat_gateway`, `neptune_cluster`, `network_acl` (blocks CIS 6.1 NACL), `network_interface`, `opensearch_domain`, `organization_account`, `rds_certificate`, `rds_cluster_snapshot`, `redshift_cluster`, `redshift_snapshot`, `route53_*`, `route_table`, `s3_account_public_access_block`, `scp_policy`, `ssm_managed_instance`, `ssm_service_settings`, `subnet`, `target_group`, `transit_gateway*`, `vpc_endpoint`, `vpc_peering`, `vpn_*`.
  - 33 of these are not read by checks, analysis or privesc at all, for example `opensearch_domain`, `rest_api`, `http_api`, `cognito_identity_pool`, `s3_account_public_access_block`, `ecs_task_definition`, `codebuild_project` and `redshift_snapshot`.
- **GCP (36/50):** `artifact_repository`, `cloudrun_service`, `function`, `forwarding_rule`, `backend_bucket`, `url_map`, `target_proxy`, `log_sink` (blocks the CIS 2.x sink/metric checks), `kms_key_ring`, `secret`, `service_account`, `iam_role`, `organization`, `folder`, `firewall_policy`, `route`, `router`, `vpn_*`, `workload_identity_pool/provider`, `workforce_pool/provider` and `principal_access_boundary_policy`.
  - Of these, 18 are not read anywhere. Examples: `cloudrun_service`, `artifact_repository`, `log_sink`, `workload_identity_provider`.
- **Azure (37/67):** `activity_log`, `diagnostic_setting` (blocks the CIS 5.x diagnostic settings), `application_gateway`, every `directory_*` type (users, guests, apps, authorization policy and security defaults, which block the CIS 1.x Entra controls), `managed_identity`, `managed_identity_federated_credential`, `sql_database`, `dns_*`, `private_dns_*`, `private_endpoint`, `route_table`, `subnet`, `vnet_peering`, `subscription`, `management_group` and `tenant`.
  - Of these, 13 are not read anywhere, including `managed_identity_federated_credential`, `directory_security_defaults` and `diagnostic_setting`.
- **K8s (6/26):** `node`, `endpointslice`, `admission_configuration`, `api_discovery`, `network_interface` and `securitycontextconstraint`.

These are **not collected at all**, so neither checks nor exposure are possible. Each one has pending upstream rows:

- **AWS:** SageMaker (31 rows), Bedrock (17), Kinesis, MSK, EMR, WAF/WAFv2/Shield, Network Firewall, Athena, AppSync, Transfer, WorkSpaces, Elastic Beanstalk, Lightsail, CloudFormation, EventBridge, Step Functions, Directory Service, IAM Identity Center, Access Analyzer, Security Hub, Macie, ECR Public, EBS/AMI snapshot attributes, autoscaling, and CloudWatch metric filters (needed by CIS 4.1-4.15).
- **GCP:** Pub/Sub, Dataproc, Bigtable, AlloyDB, API keys, Org Policy constraints (needed by CIS 1.x/4.x), DNS/DNSSEC, compute images/snapshots/disks, and logging metrics.
- **Azure:** PostgreSQL, MySQL and MariaDB flexible servers, Cosmos DB (module not imported), Container Registry (module not imported), Event Hub, Service Bus, Event Grid, Databricks, Synapse, Monitor alerts and log profiles (needed by CIS 5.x/6.x), Logic Apps, Automation, Recovery Services, Front Door, Batch, HDInsight and IoT.
- **K8s:** `secret`, `configmap`, `persistentvolume`, mutating and validating webhook configurations, CRDs, `csr`, `podsecuritypolicy`, and any node/kubelet configuration.

## 3. Performance

**Short answer: No.** Non-privesc evaluation scales at about n^1.2. Privesc evaluation scales at about **n^1.94–2.3 in principals**. On the real AWS snapshot replicated 10x (3,130 principals), privesc took **378 s and 3.4 GB of peak memory**. About 63% of CPU time at 1x is spent in `copy.deepcopy`.

**Method**

- Input: the largest snapshot available, the one embedded in `scratchpad/aws-privesc.json`, extracted to `audit/q34/snap1x.json`. It is 28.5 MB, with 583 resources and 1,365 collections (302 roles, 242 policies, 25 Lambda functions).
- Scaling: 3x and 10x copies made by `audit/q34/scale.py`. Each copy keeps all resources and renames their identity fields (name and ARN).
- Driver: `audit/q34/t2.py <snap> {full|noprivesc|privesc}` calls `evaluate_snapshot`, the same path `python3 -m peaso evaluate` takes.
- Caveats:
  - The 10x wall time overlapped with another profiling run. User plus system CPU time (166 s + 59 s) is the better figure.
  - Other agents edited the evaluator during the audit, so some line numbers may have drifted.

### 3.1 Timings

| Snapshot | Mode | Wall (s) | Report (MB) | Peak RSS | Notes |
|---|---|---|---|---|---|
| 1x (583 res, 313 principals) | full | 4.25 (cold 5.3, warm 3.4) | 74.1 | 405 MB | 4,446 findings |
| 1x | non-privesc | 2.40 | 68.6 | 373 MB | |
| 1x | privesc | 1.90 | 34.2 | 299 MB | 984 edges; **123,994 admin edges computed then suppressed** |
| 3x (1,749 res, 939 principals) | full | 24.1 | 216 | 862 MB | |
| 3x | non-privesc | 13.8 | 200 | 912 MB | |
| 3x | privesc | 18.2 | 102 | 891 MB | 1,068,470 suppressed |
| 10x (5,830 res, 3,130 principals) | privesc | **378.6** (CPU 225 s) | 339 | **3.4 GB** | 11,688,751 suppressed |
| 10x | non-privesc | 39.0 | **660** | 1.9 GB | |
| Synthetic 5k principals + 5k network | privesc | 82.0 | 22.6 | 1.4 GB | uniform policies |
| Synthetic 5k + 5k | non-privesc | 3.3 | 59.5 | 307 MB | |

**100x was not run.** Extrapolated, privesc would take about 1.9 s × 100^1.94 ≈ **4 hours** and well over 16 GB. Non-privesc would take about 640 s and produce a report of about 6.6 GB.

Privesc for the other providers was measured with `scratchpad/bench.py` on synthetic data:

| Provider | Synthetic principals | Time |
|---|---|---|
| K8s | 10k service accounts | 1.8 s |
| Azure | 10k users + 500 VMs | 6.6 s |
| GCP | 8k users + 2k service accounts | 0.67 s |

These results are optimistic. The synthetic principals have identical permissions, so they collapse in the cache. Real AWS roles carry distinct policies.

`peaso/rulepacks/performance.json` covers only a single check (`aws.ebs.encryption`, 100k volumes, 0.10 s), so it does not represent the engine as a whole.

### 3.2 Hotspots (cProfile)

**1x full run, 10.48 s under the profiler:**

1. `copy.deepcopy` takes **6.59 s cumulative (63%)**. Its callers:

   | Call site | Time |
   |---|---|
   | `analysis/projection.py:15`: deep-copies the whole graph even when nothing collapses | 1.54 s |
   | `engine.py:328`: per-check copy of resource data | 1.27 s |
   | `snapshot.py:31` `validate` | 1.10 s |
   | `snapshot.py:101` `resources` | 1.01 s |
   | `analysis/common.py:103` `node()`: embeds the full native resource in every graph node | 1.09 s |
   | `analysis/iam.py:258` | 0.38 s |

2. Privesc `analyze` takes 3.48 s, mostly `evaluator._evaluate_source` (2.80 s over 4,568 calls).
3. In `privesc/effective_permissions/__init__.py`, small objects and helpers called very often:

   | Function | Calls | Time |
   |---|---|---|
   | `Grant.__init__` (`:34`) | 674k | 0.96 s |
   | `downgrade` (`:67`) | | 1.08 s |
   | `combine` (`:43`) | | 0.58 s |
   | `check_targets_shared` (`:289`) | | 0.94 s |

   Plus `aws.py:606` `check_targets` (0.74 s) and `aws.py:734` `resolve` (0.57 s).

**3x privesc-only run, 49.9 s under the profiler:**

| Function | Calls | Time |
|---|---|---|
| `_evaluate_source` | | 37.6 s |
| `check_targets_shared` | | 12.3 s |
| `combine` | 1.69M | 9.9 s |
| `downgrade` | 4.0M | 8.5 s |
| `Grant.__init__` | 5.78M | 6.9 s |
| `resolve` | | 7.4 s |

**3x non-privesc run:**

| Function | Calls | Time |
|---|---|---|
| `build_graphs` | | 21.5 s |
| `validate` | | 17.5 s |
| `build_iam` | | 11.2 s |
| `project_graph` | | 10.3 s |
| `node()` | | 9.5 s |
| `scripts/cloud_permission_risks.py:105` `_load_yaml` | 22,349 | 2.5 s |

`_load_yaml` runs `Path.resolve()` (`:54`) and `stat` (`:111`) on every call before its LRU cache is consulted.

### 3.3 Superlinear code (AST scan `audit/q34/nest.py`, 31 nested-loop hits, reviewed by hand)

| Location | Pattern |
|---|---|
| `peaso/privesc/evaluator.py` (`evaluate` loop ~`:319`, `_evaluate_source` `:398`) | techniques × sources × targets. **This is the main quadratic term.** |
| `peaso/privesc/graph.py:165`, `:252`, `:292` | Sources that are already admin are evaluated in full against every target and only dropped afterwards. That is 11.7M wasted edges at 10x. |
| `peaso/privesc/effective_permissions/azure.py:221` | For each principal, scans all of `membership_status.values()`. |
| `peaso/privesc/effective_permissions/k8s.py:217-221` | Aggregated ClusterRoles × all roles, plus a list membership test on `rules`. |
| `peaso/privesc/effective_permissions/gcp.py:687-697` | Per-source BFS over service-account delegation, calling `_sas_with` at every hop. |
| `peaso/analysis/projection.py:30` | `annotation not in annotations`: a list search inside a loop. |
| `peaso/analysis/common.py:73` | Linear `next(...)` over collections on every `source()` call made outside the analysis context. |
| `peaso/analysis/__init__.py:91-100` | One malformed resource makes the graph build re-run once per resource. |
| `peaso/checks/__init__.py:77` `evaluate_check` | Linear `next(c for c in CHECKS ...)` over 1,117 checks on every call. |
| `peaso/engine.py:362` | `build_graphs(max_nodes=max(500, len(inventory)*100))`, so stored graphs are never collapsed. The IAM graph alone is 34.7 MB of the 74 MB report at 1x. |

## 4. Map scalability

**Short answer: No.** The backend projects 5k network assets in 0.25 s. The UI does not cope:

- **ELK layout** (the layered graph-layout engine both maps use) is the failure point. The privesc map takes 4.3 s at its default 150-node cap on a real dense graph and **216 s at about 600 nodes**, and "Show more" has no upper bound.
- The **IAM projection collapses 5k principals into 4 nodes**.

### 4.1 Caps and layout (evidence)

| Component | Cap / behaviour |
|---|---|
| `peaso/analysis/projection.py:10` `project_graph` | Groups by provider/scope/type/parent/VPC or namespace with a soft budget. Linear. Deep-copies the graph when nothing collapses (`:15`). |
| `peaso/server/app.py:302` `GET /graphs/{kind}` | `max_nodes` between 1 and 100,000. Hosted mode allows only 500 or the full graph (`:307`, `:319`). |
| `peaso/privesc/graph.py` | Aggregates targets (`MEMBER_SAMPLE=20`, `SUBSET_MIN=5`). Sources are never aggregated. Aggregate `members` lists are unbounded (up to 905 at 3x). |
| `peaso/storage/reports.py:34` `privesc_projection` | Truncates whole edges and never aggregates. |
| `frontend/src/GraphView.tsx` (network/IAM) | 120 nodes / 400 edges per page (`:36`). Fetches `?max_nodes=500` (`:113`), or the full graph when "complete evidence" is on. ELK layered via `graphProjection.ts` `projectView`, paginated (`:176`). |
| `frontend/src/PrivescMap.tsx` | `INITIAL_CAP=150`, `CAP_STEP=150` (`:57`), with **no upper bound** (`:1038`). Expanding an aggregate shows `MEMBER_CAP=40`. **Always fetches the full privesc graph** (`frontend/src/api.ts:166`). ELK layered with `separateConnectedComponents=false`. |

### 4.2 Synthetic 5k network nodes + 5k principals (`audit/q34/synth.py`)

The snapshot has 10 VPCs, 100 subnets, 300 security groups, 2,300 instances and 2,300 ENIs, plus 2,500 roles and 2,500 users.

| Step | Result |
|---|---|
| `build_graphs` (no collapse; the engine's path) | 2.31 s. Network: 5,011 nodes, 16,560 edges, 12.2 MB. IAM: 10,001 nodes, 7,500 edges, 18.4 MB. |
| `project_graph(500)` network | 0.25 s, giving 231 nodes and 722 edges. Instances and ENIs collapse per subnet. |
| `project_graph(500)` IAM | 0.01 s, giving **4 nodes** (`iam_role (2500)`, `iam_user (2500)`, ...). No individual principal is visible. |
| Frontend `structuralIndex` + `projectView` on the full 5k/10k graphs | 5–16 ms. Not a bottleneck. |
| "assets" level on the 5k network graph | 42 pages of 120 nodes. **Page 0 shows 0 edges**, because relationships that cross pages are dropped (`graphProjection.ts:176-180`). |

ELK timings were measured in Node with single-threaded elkjs, standing in for the browser worker.

**Network-map options, connected subgraph:**

| Nodes / edges | Layout time |
|---|---|
| 410 / 400 | 0.5 s |
| 860 / 1,000 | 0.64 s |
| 1,660 / 2,500 | 4.5 s |
| 2,910 / 5,000 | 22.8 s |
| 5,010 / 16,000 | 59.5 s |

**Privesc-map options, real 3x privesc graph (493 nodes, 2,906 edges):**

| View | Layout time |
|---|---|
| Cap 150 (1,204 edges) | **4.3 s** |
| Cap 300 | 17.9 s |
| All 493 | 25.1 s |

**Privesc graph replicated to 4,921 nodes / 29,060 edges:**

| View | Layout time |
|---|---|
| Cap 150 (70 edges) | 0.11 s |
| Cap 600 (4,437 edges) | **216 s** |
| Cap 1,500 | did not finish within 550 s |

### 4.3 Failure points

1. **Privesc-map layout.** Cost tracks edge density. There is no per-view edge cap, and "Show more" is unbounded.
2. **IAM projection is all-or-nothing.** At 500 nodes, each principal type becomes one bucket. "Complete evidence" downloads the uncapped graph, which is 18.4 MB at 5k principals and an estimated ~350 MB IAM graph for the real 10x snapshot.
3. **Asset paging drops relationships that cross pages.**
4. **The privesc map always downloads the full graph.** That is 6.5 MB at 493 nodes, and aggregate `members` lists are unbounded.
5. **The backend projection itself is fine** (0.25 s for 5k nodes).
6. **Tests.** `frontend/tests/large.spec.ts` is skipped unless `PEASO_LARGE_*` environment variables are set. No Playwright or unit test exercises 1k+ nodes on either map.

## 5. False positives (30 sampled FAILs, real AWS account 947247140022, live read-only verification)

**Short answer: No, false positives are not at zero.** Of 30 sampled FAILs:

| Verdict | Count |
|---|---|
| True positive | 22 |
| **False positive** | **6** |
| Non-actionable (source is a service-linked role) | 1 |
| Undetermined | 1 |

Every FP is in privesc: **6 of 16 sampled privesc FAILs (37.5%)**. Hardening, exposure and least privilege showed 0 FPs out of 14. Those 14 are thin coverage, though: the capped report (`max_calls=200`) has only 6 distinct FAIL checks among its 39 non-privesc FAILs. Scaled to all 200 privesc FAILs, the same root causes match **53 (26.5%)**. That figure comes from pattern matching and was not verified finding by finding.

### Method

- **Inputs**
  - `aws-report.json`: 784 findings, of which 39 FAIL.
  - `aws-privesc.json`: 1,252 findings, of which 200 FAIL.
- **Sample:** `random.seed(20261010)`, stratified so that every FAIL check is represented:
  - Hardening 10: `s3.access_logging` 4, `s3.versioning` 3, `iam.console_mfa` 2, `iam.access_key_count` 1.
  - Exposure 3: all of `s3.public_access_block`.
  - Least privilege 1: `iam.no_full_admin`.
  - Privesc 16: `admin-equivalent` plus 15 distinct techniques.
- **Verification:** live `aws --profile naxusai-admin` get/list/describe calls only, run on the same day as both snapshots.
- **Drift:** none of the 30 had changed state, so no verdict is a drift artefact.
- **Scripts:** `scratchpad/audit/q5/` (`sample.py`, `verdicts.json`, `v1-v5.sh`, `passedto.py`).

| # | Check | Resource | Cat | Verdict | Evidence (read-only call → result) |
|---|---|---|---|---|---|
| 1-4 | aws.s3.access_logging | beaki-terraform-state-…-eu-west-1, beaki-dev-raw-aac449d2, bealy-dev-assets-aac449d2, elasticbeanstalk-us-east-1-… | hard | TP ×4 | `s3api get-bucket-logging` → empty |
| 5-7 | aws.s3.versioning | naxus-frontend-test, naxusai-dashboard-static-website, hacktrics-vpn-3ea1b185-downloads | hard | TP ×3 | `get-bucket-versioning` → no Status |
| 8-9 | aws.iam.console_mfa | user/slayer, user/Jaime | hard | TP ×2 | `get-login-profile` exists; `list-mfa-devices` → [] |
| 10 | aws.iam.access_key_count | user/testenv | hard | TP | 2 active keys |
| 11-13 | aws.s3.public_access_block | elasticbeanstalk-eu-west-1-…, naxus-frontend-test, elasticbeanstalk-us-east-1-… | expo | TP* ×3 | Bucket PAB all false; account PAB absent. However, `IsPublic:false` and there is no public ACL or policy. |
| 14 | aws.iam.no_full_admin | policy/InfraDeployFullAccess | LP | TP | `Action:* Resource:*`, attached to a GitHub Actions role |
| 15 | admin-equivalent | group/AdministratorAccess | priv | TP | Members Abel, carlos, Jaime, slayer |
| 16 | ecs-passrole-registertaskdefinition-starttask | AWSBatchServiceRole | priv | **FP** | 0 ECS container instances in any cluster or region, so StartTask has no host to run on |
| 17 | lambda-passrole-createfunction-invokefunction | AmazonSageMakerProvisioning-… | priv | UNDET | CreateFunction is constrained by a tag condition. The evidence cites the wrong PassRole statements (36 and 31). |
| 18 | ssm-startsession | LambdaSlackNotification | priv | **FP** | The only target is stopped (also stopped in the snapshot) and there are 0 SSM managed nodes. Reported with `confidence: derived`. |
| 19 | ec2-autoscaling-create-update-asg-passrole | AWSServiceRoleForBatch (SLR) | priv | NON-ACT | Service-linked role: only batch.amazonaws.com can assume it |
| 20 | cognito-creategroup-passrole | HT-SM-Exec-1759853443 | priv | **FP** | Every PassRole is restricted by `iam:PassedToService` to sagemaker, glue, robomaker and states |
| 21 | sagemaker-passrole-createnotebookinstance | HT-SM-Exec-1759853443 | priv | TP | Evidence cites statement 29 instead of 30. Targets include the source itself and an SLR. |
| 22 | lambda-updatefunctioncode | beaki-dev-github-infrastructure-deploy-role | priv | TP | inline statement 9 on `function:beaki-dev-*`; 10 functions |
| 23 | ssm-sendcommand | LambdaSlackNotification | priv | **FP** | Same cause as #18 |
| 24 | organizations-management-to-member-accounts | datazone_usr_role_… | priv | **FP** | All targets are in the **same** account; this duplicates `aws-sts-assumerole-trusted` |
| 25 | ec2-passrole-associate-instance-profile | HackerMate-CI-Build-Pipeline-role | priv | TP | `ec2:*` plus PassRole to ec2 |
| 26 | ecs-passrole-registertaskdefinition-service | same | priv | TP | Fargate needs no container instance |
| 27 | ssm-createassociation | AWSServiceRoleForAWSLicenseManagerRole (SLR) | priv | **FP** | SLR source, and the target is stopped and unmanaged |
| 28 | ec2-modifyinstanceattribute-userdata | HackerMate-CI-Build-Pipeline-role | priv | TP | `ec2:*`; EBS-backed instance with a profile |
| 29 | iam-putrolepolicy-self | beaki-dev-github-infrastructure-deploy-role | priv | TP | PutRolePolicy on `role/beaki-dev-*`, which includes the role itself |
| 30 | iam-createrole-attach-assume | same | priv | TP | CreateRole plus PutRolePolicy |

\* #11-13: the check's literal claim holds, since PAB is not fully configured. It is filed under **exposure**, though, and none of the three buckets is actually public.

| Stratum | n | TP | FP | Non-act | Undet | FP rate |
|---|---|---|---|---|---|---|
| Hardening | 10 | 10 | 0 | 0 | 0 | 0% |
| Exposure | 3 | 3 | 0 | 0 | 0 | 0% (none actually exposed) |
| Least privilege | 1 | 1 | 0 | 0 | 0 | 0% |
| Privesc | 16 | 8 | 6 | 1 | 1 | **37.5%** (43.8% counting non-actionable) |
| **Total** | 30 | 22 | 6 | 1 | 1 | **20%** (23.3% counting non-actionable) |

**Population scan of all 200 privesc FAILs** (pattern-matched, not verified one by one). Some findings match more than one cause, so the rows overlap.

| Cause | FAILs |
|---|---|
| Source is a service-linked role (11 distinct SLRs) | 27 |
| SSM technique whose only target is the stopped, unmanaged instance | 17 |
| ECS StartTask with 0 container instances | 8 |
| No PassRole with a matching `iam:PassedToService` | 7 |
| Org technique with targets in the same account | 3 |
| **Union of the above** | **53 (26.5%)** |

Separately, **155 of 200 FAILs (77.5%) are `confidence: conditional` but still reported as FAIL**.

### FP root causes

1. **IAM conditions are never evaluated.**
   - Any `Condition` key, or a `${}` variable in a resource, marks the statement `conditional` (`peaso/privesc/effective_permissions/aws.py:75`).
   - `_evaluate` then takes the first unconditional hit, or else `hits[0]` (`aws.py:485-486`).
   - `graph.py:301` maps every non-`unknown` confidence to FAIL.
   - **Effect:** `iam:PassedToService` mismatches survive (#20, plus 7 more), and the wrong granting statement is cited (#17, #21).
2. **Technique preconditions are free text.**
   - Conditions such as `instance_managed` and `container_instance_exists` (`catalog/aws/ssm.yaml:55-61`, `catalog/aws/ecs.yaml:91-93`) are never checked against inventory.
   - Host resolution ignores the instance `State` (`aws.py:660-679`, `:814-815`, `:867`).
   - `ssm_managed_instance` (`collectors/aws_b_services.py:47`) is not requested by the privesc collection plan.
3. **Service-linked roles are accepted as sources** (`aws.py:324-352`): 27 of 200.
4. **`scope: org` does not require a different account** (`aws.py:603-604`, `:910-911`; `catalog/aws/organizations.yaml`).
5. **Noise, not counted as FP:**
   - Aggregate target sets include the source itself and SLRs.
   - S3 findings are scoped to the collection region instead of the bucket region, because `bucket` is in `GLOBAL_TYPES` (`collectors/aws.py:382`). 7 of the 13 sampled bucket findings carry the wrong region.

## 6. Exposure completeness

**Short answer: No.** Exposure is detected per resource, in three ways:

- declarative checks;
- one generic network-rule candidate scan;
- one generic "principal in a policy document" scan.

There is no internet-to-asset path composition. Nothing combines public IP, IGW route, NACL, SG and listener into one result. The two generic scans never produce FAIL; they produce MANUAL or UNKNOWN. On the real AWS report, **cross-account trusts are not raised at all at the default configuration**.

### 6.1 How exposure is computed today (evidence)

| Mechanism | Where | Behaviour |
|---|---|---|
| Network rule candidates | `peaso/analysis/network.py:17-58` (`public_rules`), `:61-71` (`exposure_findings`) | Looks at SG, GCP firewall, NSG and K8s NetworkPolicy rules whose source is `0.0.0.0/0`, `::/0`, `*` or `Internet`. It emits `analysis.network_review` with status **MANUAL**, `reachability: "unknown"`. It does not consider attachment, public IP, route or NACL. |
| Pairwise reachability | `peaso/analysis/reachability.py:1062` `evaluate_reachability`; only caller is `peaso/server/app.py:292` | Runs only on demand, for one source→destination TCP/UDP flow between **private** endpoints. AWS endpoints must be an instance or ENI (`reachability.py:215-221`), and there is no "Internet" source. It is never run in batch, so it never produces findings. |
| Principal exposure | `peaso/analysis/iam.py` `principals()` + `review_findings()` (`:240-254`), `peaso/analysis/common.py:150-167` `externality()` | Walks every `Policy`/`policy`/`Attributes`/`Domain`/`policyText`/`ResourcePolicy`/`AccessPolicies` document, plus GCP `bindings` and K8s `subjects`. `*`, `allUsers`, `allAuthenticatedUsers`, `system:anonymous` and `system:unauthenticated` are classed `public` (MANUAL, high). Any other principal is `external` **only if `trusted_scope_ids` was supplied**; otherwise it is `unknown`, giving status UNKNOWN at severity info. `Condition` blocks are copied into the evidence but not evaluated. |
| Declarative exposure checks | `peaso/checks/*` (15 checks, category `exposure`/`network`) | See the matrix. |

`trusted_scope_ids` defaults to `[]` (`peaso/collectors/aws.py:847-850`; the same in gcp.py:1200, azure.py:424 and k8s.py:479), and the scanned account itself is **not** auto-trusted. In the real `aws-report.json`, all 76 `analysis.principal_exposure` findings are `UNKNOWN/info` and all 80 principals are classed `unknown`:

| Principal | Count |
|---|---|
| same-account `Federated` (OIDC/SAML providers) | 47 |
| same-account `AWS` | 14 |
| `cognito-identity.amazonaws.com` | 10 |
| **six foreign AWS accounts plus one CloudFront OAI** | 9 |

The real third-party trusts are mixed into 71 benign entries at info severity.

### 6.2 Network and public-endpoint exposure matrix

Legend:
- **C**: covered by a FAIL-capable native check.
- **G**: only the generic MANUAL/UNKNOWN review (`analysis.network_review` or `analysis.principal_exposure`).
- **col**: collected but not evaluated.
- **✗**: not collected.

| Cloud | Exposable resource / setting | Status | Evidence |
|---|---|---|---|
| AWS | SG ingress 0.0.0.0/0 | C | `checks/__init__.py:240` `aws.ec2.restrict_internet_ingress`. Matches only `/0` (`prefixlen == 0`); ignores whether the SG is attached. |
| AWS | EC2 public IP / EIP + open SG + IGW route (composite) | **✗ missing** | No check reads `PublicIpAddress`/`Association`; reachability has no Internet source. |
| AWS | ENI with public IP (incl. unattached/EIP) | col | `network_interface` has 0 checks. |
| AWS | NACL allow 0.0.0.0/0 on admin ports (CIS 6.1) | col | `network_acl` has 0 checks. |
| AWS | ALB/NLB/CLB `Scheme=internet-facing` and listeners | **col, missing** | `load_balancer` has 11 checks, all hardening; no check uses `Scheme`. |
| AWS | API Gateway REST/HTTP public endpoint, `authorizationType=NONE` | col / G (resource policy only) | `rest_api` and `http_api` are not read by any check. |
| AWS | Lambda Function URL `AuthType=NONE` | C | `aws_extended.py:109-115`. |
| AWS | Lambda resource policy `*` | G | `lambda get_policy` → `Policy`. |
| AWS | S3 Block Public Access (bucket) | C | `checks/__init__.py:212-226`. |
| AWS | S3 account-level BPA | **col, not evaluated** | `s3_account_public_access_block` is unused, so a bucket without its own BPA FAILs even when account-level BPA blocks it (FP source). |
| AWS | S3 ACL public / bucket policy `*` | C / G | `aws.s3.no_public_acl`, plus `principal_exposure`. `PolicyStatus.IsPublic` is collected and unused. |
| AWS | RDS `PubliclyAccessible` | C | `checks/aws.py:28`. |
| AWS | RDS/Aurora snapshot shared `restore=all` | **col, missing** | `describe_db_snapshot_attributes` is collected (`collectors/aws.py:524`); no check. |
| AWS | EBS snapshot / AMI public (`createVolumePermission`/`launchPermission`) | **✗** | Not collected. |
| AWS | Redshift / DMS / DocDB / Neptune `PubliclyAccessible` | col | 0 checks on these types. |
| AWS | ECR private repository policy `*` | G | `policyText`. |
| AWS | ECR Public | ✗ | |
| AWS | SNS / SQS / KMS / Secrets Manager policy `*` | G | MANUAL only, never FAIL; `aws:SourceArn`/`PrincipalOrgID` conditions not evaluated. |
| AWS | OpenSearch public (non-VPC) domain / access policy `*` | col / G | `opensearch_domain` is read by no check. |
| AWS | EKS public API endpoint | C | `aws.b.eks.disable_public_endpoint` and `aws.eks.private_endpoint`. `publicAccessCidrs` is ignored, so a public endpoint restricted to specific CIDRs still FAILs. |
| AWS | SSM document public | C | `aws.b.ssm.document_not_public`. |
| AWS | Cognito identity pool `AllowUnauthenticatedIdentities` | col | Not read anywhere. |
| AWS | CloudFront origin exposure (S3 without OAC, custom origin open) | col | 12 hardening checks; none on origin exposure. |
| AWS | EFS / Glacier / Backup vault / EventBridge bus / CodeArtifact / Glue resource policies | ✗ | Policies not collected. |
| GCP | Firewall ingress 0.0.0.0/0 | C + G | `checks/__init__.py:320`, `network.py:28-34`. |
| GCP | Instance external IP | C | `gcp.compute.no_external_ip`. |
| GCP | External forwarding rules / LB / backend buckets | col | `forwarding_rule` and `backend_bucket` have 0 checks. |
| GCP | GCS `allUsers` / public access prevention | C | `gcp.storage.no_public_iam`, `public_access_prevention`. |
| GCP | Cloud SQL public IP / authorized networks 0.0.0.0/0 | C | `gcp.sql.no_public_ip`, `restrict_authorized_networks`. |
| GCP | BigQuery dataset public | C | `gcp.reviewed.bigquery.no_public_acl`. |
| GCP | KMS key `allUsers` | C | `gcp.reviewed.kms.no_public_iam`. |
| GCP | Cloud Run / Cloud Functions `allUsers` invoker | G | `iamPolicy` is hydrated (`collectors/gcp.py:950,962`); 0 native checks. |
| GCP | Cloud Run `ingress=all` | col | 0 native checks. |
| GCP | Artifact Registry `allUsers` | G | 0 checks. |
| GCP | Secret Manager / service-account IAM `allUsers` | G | |
| GCP | Pub/Sub topic/subscription `allUsers` | ✗ | |
| GCP | Compute image / snapshot / disk IAM public | ✗ | |
| GCP | GKE public endpoint / master authorized networks | C | `gcp.gke.private_endpoint`, `authorized_networks`. |
| GCP | App Engine without IAP | C | `app_engine_application_iap_enabled`. |
| Azure | NSG inbound Internet / `*` | C + G | `checks/__init__.py:408`. |
| Azure | VM + public IP + NSG (composite) | **✗ missing** | Only `azure.network.public_ip_standard` (SKU). |
| Azure | Public LB / Application Gateway frontends | col | `application_gateway` has 0 checks. |
| Azure | Storage `allowBlobPublicAccess` / `publicNetworkAccess` / default action | C | `azure.storage.no_blob_public_access`, `no_public_network`, `default_deny`. |
| Azure | Container-level anonymous access | ✗ | Containers not collected. |
| Azure | SAS / shared key | partial C | `azure.storage.no_shared_key`; SAS tokens issued from account keys are not discoverable. |
| Azure | App Service / Functions `publicNetworkAccess`, `ipSecurityRestrictions`, SCM restrictions | **col, missing** | Only `https_only`, `client_certificates`, TLS, FTPS and CORS checks. |
| Azure | AKS public API server | C | `azure.aks.private_cluster`; `authorizedIPRanges` not considered. |
| Azure | SQL public network / firewall 0.0.0.0-255.255.255.255 | C | `azure.sql.no_public_network`, `restrict_firewall`. |
| Azure | Key Vault / Cognitive / Search / Data Factory public network | C | |
| Azure | Cosmos DB / Container Registry public network | written, **not imported** | `peaso/checks/azure_ports_paas.py`. |
| Azure | PostgreSQL / MySQL flexible public access | ✗ | |
| Azure | Managed disk public export | C | `azure.disk.private_export`. |
| Azure | API Management / Event Hub / Service Bus public | 1 C / ✗ | |
| K8s | Service `LoadBalancer`/`NodePort`/`externalIPs` | C | `checks/__init__.py:474-485`. `loadBalancerSourceRanges` and internal-LB annotations are ignored, so internal or CIDR-restricted LBs FAIL (FP source). |
| K8s | Ingress public host / no TLS / default backend | **missing** | Only `ingress_default_namespace_used`. |
| K8s | NetworkPolicy allow-all / no default-deny | C + G | |
| K8s | `system:anonymous` / `system:unauthenticated` bindings | G (public, MANUAL high) | `common.py:152`. |
| K8s | hostNetwork / hostPort pods | C | `k8s_ports_workloads.py`. |
| K8s | Kubelet anonymous auth / read-only port, dashboard exposure | ✗ | Node config not collected. |

### 6.3 Permission-based exposure

| Topic | Status | Notes |
|---|---|---|
| `*`/`allUsers`/`allAuthenticatedUsers` principal in a resource policy | G (MANUAL high) | Never FAIL. Conditions are not evaluated, so `"Principal":"*"` with `aws:PrincipalOrgID` is still flagged (FP-prone). |
| AWS role trust `*` | C | `aws.iam.restrict_public_trust` (`checks/__init__.py:173-190`); conditioned `*` gives MANUAL. |
| AWS cross-account role trust / resource policy | **effectively missing by default** | UNKNOWN/info unless `trusted_scope_ids` is set. Own account not auto-trusted. Organizations accounts (`organization_account` is collected) are not used as the trusted set. |
| AWS OIDC federation trust without `sub`/`aud` condition (GitHub Actions, EKS IRSA, Cognito) | **missing** | No code references `token.actions.githubusercontent.com` or OIDC condition keys. 47 Federated trusts in the real report are UNKNOWN. |
| AWS `sts:ExternalId` missing on third-party trust (confused deputy) | **missing** | |
| AWS Cognito unauthenticated role | **missing** | Identity pools collected, not evaluated. |
| GCP external-domain members / cross-project SAs | G | `external` only if `trusted_domains`/`trusted_scope_ids` set (`common.py:162-166`). |
| GCP Workload Identity Federation providers with no attribute condition | **missing** | `workload_identity_provider` collected, not read. |
| Azure guest users with roles | privesc-only | `userType` is read in `privesc/effective_permissions/azure.py`; no exposure finding. |
| Azure multi-tenant apps / service principals from foreign tenants | privesc-only | `signInAudience` is read in privesc only. |
| Azure federated identity credentials on managed identities | **missing** | `managed_identity_federated_credential` collected, read nowhere. |
| Azure role assignment to a foreign-tenant principal | G | Requires `trusted_scope_ids`. |
| K8s bindings to `system:authenticated` | G (`everyone_authenticated`) | |
| K8s bindings to external OIDC groups | **missing** | |

### 6.4 Coverage count

I scored 73 rows: 59 in the network and public-endpoint matrix (§6.2) and 14 in the permission table (§6.3). Rows marked "col, missing" (collected, but the check that would use the data does not exist) are counted as missing.

| Status | Network rows | Permission rows | Total | Share |
|---|---|---|---|---|
| Covered by a FAIL-capable native check (incl. partial) | 26 | 1 | 27 | 37% |
| Generic MANUAL/UNKNOWN review or privesc-only | 9 | 6 | 15 | 21% |
| Collected but not evaluated | 8 | 0 | 8 | 11% |
| Not collected, not imported, or no logic | 16 | 7 | 23 | 32% |

## 7. Prioritised gap list

- **P0**: produces wrong answers (FPs or missed critical paths) or does not finish at realistic scale.
- **P1**: a material coverage or usability hole.
- **P2**: hygiene or a smaller gap.

Owner areas: privesc catalog, checks, collector, engine perf, engine (correctness), UI, exposure.

### P0

| # | Owner | Gap | Evidence |
|---|---|---|---|
| P0-1 | engine (privesc) | IAM conditions are never evaluated. `iam:PassedToService`, `AssociatedResourceArn` and `CalledVia` mismatches still produce edges; the cited grant is `hits[0]`; conditional edges are reported as FAIL. Accounts for FPs #20, #17 and #21 plus at least 7 more; 155 of 200 FAILs are conditional. | `privesc/effective_permissions/aws.py:75`, `:485-486`; `privesc/graph.py:301` |
| P0-2 | privesc catalog / engine | Technique preconditions (`instance_managed`, `container_instance_exists`, running state) are free text and never checked against inventory. `ssm_managed_instance` is not requested by the privesc collection plan. Accounts for 25 FAILs (SSM/ECS). | `catalog/aws/ssm.yaml:55-61`, `catalog/aws/ecs.yaml:91-93`, `aws.py:660-679,814-815,867` |
| P0-3 | engine perf (privesc) | Privesc cost grows about n² in principals: 378 s / 3.4 GB at 3,130 principals; extrapolated to ~4 h at 100x. Admin-equivalent sources are fully evaluated and then suppressed (11.7M edges at 10x). | `privesc/evaluator.py:319,398`; `privesc/graph.py:165,252,292` |
| P0-4 | privesc catalog | Catalog is pinned to HackTricks `a53b46392c`; upstream `171e422` has 145 privesc pages with no entry (76 AWS, 25 GCP, 29 Azure, 15 K8s) and 250 permission-bearing headings unmapped. | `audit/q1/upstream.json`, `upstream_semantic.txt` |
| P0-5 | privesc catalog | Missing: EKS access-entry and pod-identity escalation; IAM identity planting (OIDC/SAML provider, `AddClientIDToOpenIDConnectProvider`, `UploadSigningCertificate`); Organizations `CreateAccount`/`RegisterDelegatedAdministrator`; Identity Center `CreatePermissionSet`/`CreateTrustedTokenIssuer`. | `grep -ril eks: peaso/privesc/catalog` returns nothing; `aws-eks-privesc/README.md:29-259` |
| P0-6 | exposure | No internet-to-asset composition. Public IP/EIP, IGW route, NACL, SG and listener are never combined, and `evaluate_reachability` has no Internet source and is never run in batch. Internet-facing ELB `Scheme`, API GW auth, public snapshots and AMIs are not evaluated. | `analysis/reachability.py:215-221,1062`; `analysis/network.py:61-71` |
| P0-7 | exposure / collector | Cross-account and external principals are UNKNOWN/info unless `trusted_scope_ids` is configured; the scanned account and Organizations accounts are not auto-trusted. In the real account, 9 foreign-account principals sit unprioritised among 80 entries. OIDC trusts lacking a `sub`/`aud` condition (GitHub Actions) are not detected. | `analysis/common.py:150-167`; `collectors/aws.py:847-850` |
| P0-8 | UI | Privesc-map ELK layout: 4.3 s at the default cap on a real graph, 216 s at ~600 nodes; "Show more" is unbounded; no per-view edge cap. | `frontend/src/PrivescMap.tsx:57,1038` |

### P1

| # | Owner | Gap | Evidence |
|---|---|---|---|
| P1-1 | checks | CIS coverage at the latest vendored versions: AWS 10/66, GCP 13/71, Azure 14/93, K8s 2/81. CIS EKS, GKE and AKS benchmarks are not vendored. The three perimeter mods (109 rows) are 0% ported. | §2.2–2.3 |
| P1-2 | collector + checks | 130 collected types have 0 checks. Of these, 64 are not read anywhere: 33 AWS (e.g. `opensearch_domain`, `rest_api`, `cognito_identity_pool`, `s3_account_public_access_block`), 18 GCP (e.g. `cloudrun_service`, `log_sink`, `workload_identity_provider`), 13 Azure (e.g. `diagnostic_setting`, `managed_identity_federated_credential`). | `audit/q2/svc.py` |
| P1-3 | collector | Services not collected at all: AWS SageMaker, Bedrock, Kinesis, MSK, EMR, WAF, Network Firewall, Identity Center, Access Analyzer, CloudWatch metric filters, EBS/AMI attributes; GCP Pub/Sub, Org Policy, DNS, images and snapshots; Azure PostgreSQL/MySQL, Event Hub, Service Bus, Monitor alerts; K8s secrets, configmaps, webhooks, CRDs, node config. | §2.4 |
| P1-4 | engine (privesc) | Service-linked roles are accepted as privesc sources and targets (27 of 200 FAILs). `scope: org` does not require a different account (3 duplicate FAILs). | `aws.py:324-352,603-604,910-911`; `catalog/aws/organizations.yaml` |
| P1-5 | checks / exposure | Exposure checks fail on configuration rather than on actual exposure. `aws.s3.public_access_block` ignores account-level BPA, and 3 of 3 FAILs were not public. `k8s.service.review_public_type` ignores `loadBalancerSourceRanges` and internal-LB annotations. EKS ignores `publicAccessCidrs`; AKS ignores authorized IP ranges. | `checks/__init__.py:212-226,474-485` |
| P1-6 | exposure | `analysis.network_review` and `analysis.principal_exposure` never FAIL (always MANUAL or UNKNOWN), so `*` resource policies on SNS/SQS/KMS/Secrets/ECR/Lambda/OpenSearch and Cloud Run/Functions/Artifact Registry `allUsers` are never FAIL. | `analysis/network.py:66`, `analysis/iam.py:249` |
| P1-7 | engine perf | Native data is deep-copied 4–5 times per run (63% of CPU). Stored graphs are never collapsed and embed native resources, so reports are about 2.6x the snapshot (660 MB at 5.8k resources). | `snapshot.py:31,101`; `engine.py:328,362`; `analysis/common.py:103`; `projection.py:15` |
| P1-8 | UI / projection | IAM projection groups only by type: 5k principals become 4 nodes, and the only fallback is the full multi-MB graph. Asset paging drops cross-page edges (page 0 of 42 shows 0 edges). The privesc map always fetches the full graph and aggregate `members` lists are unbounded. | `projection.py`; `graphProjection.ts:176-180`; `api.ts:166` |
| P1-9 | privesc catalog | Azure: ~16 headings with no entry or exclusion (App Configuration, Queue, Service Bus, Digital Twins, InferenceService, Maps, Automation `schedules/write`). AzureHound: `AZRoleApprover`, AKS `runCommand`, `AZGetKeys` and `ServicePrincipalEndpoint.ReadWrite.All` are missing. | `audit/q1/local_unmapped.txt` |
| P1-10 | engine (privesc K8s) | Escape detection ignores capabilities (SYS_ADMIN, SYS_MODULE, SYS_PTRACE), init and ephemeral containers, and `shareProcessNamespace`. It treats any hostPath or hostNetwork as privileged, so it produces both FNs and FPs. | `effective_permissions/k8s.py:258-260` |
| P1-11 | privesc catalog | `source` anchors are rotting (19 AWS, 308 GCP, 11 Azure and 14 K8s are broken against upstream; 1 is broken locally, `azure/automation.yaml:61`), and no test validates them. | `audit/q1/upstream.json` |
| P1-12 | exposure | Permission-exposure gaps: no `sts:ExternalId` (confused-deputy) check; Cognito unauthenticated roles not evaluated; GCP WIF providers without an attribute condition not checked; Azure guests and multi-tenant apps only feed privesc, with no exposure finding; managed-identity federated credentials not evaluated. | §6.3 |

### P2

| # | Owner | Gap | Evidence |
|---|---|---|---|
| P2-1 | checks | `catalog_summary.json` is stale (1,002 vs 1,117 checks). `azure_ports_paas.py` and `k8s_ports_reference_config.py` exist but are not imported. | `checks/__init__.py:505-519` |
| P2-2 | checks | K8s predicate inflation: 787 checks but only 147 distinct predicates, because predicates are repeated across 9 workload kinds. Headline counts overstate breadth. | §2.1 |
| P2-3 | collector | S3 findings are scoped to the collection region rather than the bucket region (7 of 13 sampled were mislabelled). | `collectors/aws.py:382` |
| P2-4 | engine perf | Hot small objects: `Grant`, `combine` and `downgrade` (5.8M allocations at 3x). `_load_yaml` stats files on each of 22k calls. `evaluate_check` does a linear search over CHECKS. Minor quadratic loops in `azure.py:221`, `k8s.py:217`, `projection.py:30` and `common.py:73`. | §3.2–3.3 |
| P2-5 | engine (privesc) | Guardrail tampering (SCP detach, `orgpolicy.policy.set`) is excluded as "blocker only", and no edge lifts the blocker. Aggregates include the source itself. | `gcp/_excluded.yaml:1028-1036` |
| P2-6 | tests | No 10x or multi-account benchmark (`.benchmarks/` is empty). `frontend/tests/large.spec.ts` is env-gated and skipped. The FP sample for non-privesc checks rests on only 6 FAIL checks (capped `max_calls=200` run). | |
| P2-7 | process | The local HackTricks checkout (`6bdd8e89e6`) is behind origin (`171e422`); refresh it before re-authoring. | `git ls-remote` |
| P2-8 | UI | `view.nodes.find` inside the layout callback is O(n²). Harmless at 120 nodes, but it will hurt if the caps are raised. | `frontend/src/GraphView.tsx` |
