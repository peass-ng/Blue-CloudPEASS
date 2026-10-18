# Schema extensions requested by catalog authors (evaluator must implement in registry)

## Azure RBAC (catalog/azure/authorization|automation|virtual_machines|app_services ...)
- placeholder `{target.host_resource}`: ARM id of resource the managed identity is attached to
- `{pivot}` + `pivot_resource_type`: all requirements using {pivot} must be covered on the same resource of that type (may be newly created)
- selector `managed_identity_type: user_assigned|system_assigned`
- selector `custom_role_assigned_to_source`: scopes where custom roles assigned to source apply
- selector `credential_stored_in_scope`: principals whose secrets live in that resource (always conditional)
- selector `azure_host_linked_to_pivot: automation_hybrid_worker|...`
- `attached_to_service` values may be full ARM resource types (Microsoft.Web/sites/slots)
- requirement `data_action: true`: must be granted via DataActions
- blockers: azure_deny_assignment, role_assignment_condition_is_allowlist, scm_and_ftp_basic_auth_disabled

## Entra ID (catalog/azure/entraid_*.yaml)
- target kind `entra_group` (membership -> its Entra roles if role-assignable, RBAC, app roles)
- requirement keys: `graph_app_permission: <name>`; `entra_owner_of: <id>` + `object_type: application|servicePrincipal|group`; `entra_pim_eligible_role: <id>`; `entra_tenant_setting: guest_invites_allowed_for_source`; `scope:` on entra_permission/entra_role ("/", "/administrativeUnits/<id>", "/<objectId>")
- placeholder `{target.application_id}`; `{target.scope}` = Entra directory scope
- selectors: entra_reset_matrix_column (password_admin|helpdesk_admin|authentication_admin|user_admin|privileged_auth_admin|non_admin_only, per MS "who can reset passwords" table + role-assignable-group and restricted-AU exclusions); entra_role_assignment_scope_covers_target; entra_target_not_in_restricted_au; entra_sp_has_tenant_application; entra_app_sign_in_audience; entra_sp_type_in; entra_source_is_owner_of_application|service_principal|group; entra_custom_role_assigned_to_source; entra_pim_eligible_for_source; entra_agent_blueprint_principal_or_child_identity; entra_user_upn_on_federatable_custom_domain; entra_group_role_assignable; entra_group_membership_type; entra_group_type_covered_by_permission; entra_dynamic_rule_attributes_writable_by_source; entra_dynamic_rule_satisfiable_by_invited_guest (parse membershipRule); entra_role_assignable: any
- blockers: restricted_management_au, role_assignable_group_member_or_owner, sp_lock_configuration_credentials, service_principal_conditional_access_block, pim_approval_required_by_other_principal, target_upn_on_initial_onmicrosoft_domain
- severity: raise when an Entra "non-admin" target holds Azure RBAC Owner

## AWS part B (catalog/aws/lambda|ssm|glue|sagemaker|emr|... )
- placeholder `{target.resource_arn}`: existing resource carrying the target role; all requirements using it in an entry must cover the SAME resource
- placeholder `{target.artifact_arn}`: executable artifact (S3 object, ECR repo, SSM doc) consumed later by the target workload
- selector `via_resource_type: <type>`: target = role attached to existing resource of that type. Types: lambda_function, ec2_instance, ecs_task, ssm_automation_document, glue_job, glue_dev_endpoint, glue_session, emr_cluster, elasticbeanstalk_environment, sagemaker_notebook_instance, sagemaker_user_profile, stepfunctions_state_machine, fis_experiment_template, synthetics_canary, servicecatalog_product (launch-constraint role), rds_db_instance, redshift_cluster, redshift_serverless_workgroup (via namespace roles), transfer_user
- selector `via_artifact_type: s3_object|ecr_repository|ssm_document|terraform_state_object` (tfstate consumer ≈ principals with s3:GetObject+PutObject on same key)
- selector `name_prefix: <str>`: role name and instance-profile name start with prefix (AWSRDSCustom)
- `attached_to_service` new values: cloudformation, stepfunctions
- blockers: lambda_code_signing_enforced, ecr_tag_immutability, glue_nonoverridable_arguments (only if all code-loading args pinned)
- S3 bucket policy/ACL write should be treated as implying s3:PutObject on that bucket for artifact entries

## Kubernetes / OpenShift / cloud pivot (catalog/k8s/*.yaml; conventions also in rbac.yaml header)
- requirement `resource_name` (rule has no resourceNames or lists it); placeholders {target.name} {target.node} {target.client_id}; named roles {admin_equivalent_clusterrole} {source_bound_clusterrole} {source_bound_role} {host_scc}
- `namespace: "{pivot.namespace}"`: one namespace P where all requirements using it hold simultaneously; pivot-referencing blockers/selectors evaluated against P
- `{target.namespace}`: grant (RoleBinding in ns or ClusterRoleBinding) must cover target ns; `namespace: "*"` cluster-wide/cluster-scoped; omitted api_group = core
- verbs: `impersonate:<mode>`, `impersonate-on:<mode>:*`, `use-managed-identity`, `use`
- top-level `source_kind` (k8s_node|k8s_service_account|cloud_identity) + optional `source_selector` (k8s_node_role: control-plane, eks_access_entry_type: EC2_LINUX); identity edges with empty requires.all_of
- selectors: k8s_sa_used_by_running_pod, k8s_sa_used_by_controller_managed_pod, k8s_sa_absent_but_bound (virtual SA node per missing binding subject), k8s_node_schedulable, k8s_node_hosting_pods_in_namespace, k8s_node_hosting_privileged_pod_in_namespace, k8s_nodes_mapped_to_cloud_identity, k8s_node_cloud_identity, k8s_sa_cloud_binding (irsa|eks_pod_identity|gke_workload_identity|azure_workload_identity|aks_identity_binding), trust_allows_k8s_sa_oidc_subject, trust_allows_oidc_subject_wildcard, gcp_workload_identity_user_granted_to_k8s_sa, azure_fic_matches_k8s_sa, kube2iam_namespace_permits_role, openshift_namespace_has_sa_with_host_scc, exclude_names
- blocker: pivot_namespace_psa_enforce_baseline_or_restricted (unlabeled ns = privileged)
- cloud_identity targets join with AWS/GCP/Azure snapshots when present; else conditional
- severity: raise pod/controller-create to critical when a reachable SA is admin-equivalent

## AWS part A (catalog/aws/iam|ec2|ecs|cognito|sso|cloudformation|...)
- target kind `aws_identity_center_user`
- placeholders: {source.arn} (user/role ARN, not session), {source.attached_policy_arn}, {target.attached_resource_arn}, {target.consumer_input_arn}, {target.saml_provider_arn}, {target.trust_anchor_arn}
- `trust_allows_service` may be a list (ALL must be trusted)
- `attached_resource_covered_by: <action>` (role is service/exec/instance role of existing resource within that action's Resource); `attached_to_service` new values: amplify, apprunner, batch, bedrock-agentcore, cloudformation, cloudformation-stackset, codepipeline, cognito-identity, ecs, imagebuilder
- `consumer_input_writable_via: <action>`; `trust_allows_federated: <principal>`; `trust_allows_saml_provider_covered_by: <action>`; `rolesanywhere_profile_includes_target`; `has_login_profile: bool`; `cognito_user_pool_covered_by`; `cognito_user_pool_group_role_covered_by`; `codedeploy_group_instance_role_covered_by`; `ecs_task_role_on_ec2_capacity`; `ecs_container_instance_role_in_cluster_covered_by`
- source selectors: `source_kind: aws_user|aws_role`, `source_attached_policy_covered_by`, `source_group_covered_by`, `via_assumable_role_covered_by` (target aws_account_admin)
- with any_of, an action named in a selector means whichever alternative matched
- aws-iam-createrole-attach-assume: intersect Resources of CreateRole/Attach|PutRolePolicy/AssumeRole on a common role ARN

## Azure RBAC final additions
- target kind `azure_dataplane_admin` (Databricks, Kusto, Grafana, Cosmos, MySQL, PostgreSQL, SQL, Synapse data-plane auth admin)
- placeholders {target.host_resource}.content_storage / .workspace, {target.id} (UAMI resource id), {target.scope}; `pivot_resource_type: A|B` means either; `scope: "*"`
- selectors: azure_site_kind, azure_deployer_of_pivot, ml_compute_assigned_to_source, any_principal_in_scope, azure_identity_assignable_in_scope; attached_to_service ARM child types (.../workspaces/computes, .../batchAccounts/pools, .../registries/tasks)
- blockers: aks_local_accounts_disabled, aks_entra_integration_enabled
- PARTIAL identity gains (Maps SAS, AI Search skillset token): do NOT propagate the identity's ARM roles on those edges

## GCP (catalog/gcp/*.yaml; conventions also in the gcp/iam.yaml header)
- placeholders (GCP meaning):
  - `{target.email}`: target SA/group email; a permission on it holds through the SA/group policy or project/folder/org inheritance
  - `{target.project}`: target SA's project (project-level permissions such as compute.projects.setCommonInstanceMetadata, osconfig.patchJobs.exec)
  - `{target.scope}`: the project/folder/org (gcp_scope_owner) or GKE cluster (k8s_cluster_admin) being taken over
  - `{target.host_resource}`: full resource name of the EXISTING resource that runs as the target SA (VM, function, Run service/job, Composer env, Deploy target, connection, WIF pool, add-on deployment, ...); every requirement using it must cover that SAME resource
  - `{target.host_resource.content_storage}`: the GCS bucket the host resource loads and executes code from (Composer DAG bucket, function source bucket, App Engine staging bucket, Dataproc init bucket)
  - `{target.artifact_arn}`: full resource name of an executable artifact (Artifact Registry repo, GCS object/bucket, source repo) later consumed by the target workload; a setIamPolicy permission on that bucket/repo implies write for these entries
  - `{pivot}` with `pivot_resource_type`: an intermediate resource that is NOT the target. Values: `gcp_dwd_service_account` (an SA holding a Workspace domain-wide delegation grant), `dns_managed_zone` (Cloud DNS zone for the Workspace primary domain), `agentidentity_auth_provider` (Agent Identity auth provider). All requirements using `{pivot}` must hold on the same pivot.
- `attached_to_service` values (target SA = run-as identity of an existing resource of that type; not collected yet unless noted): compute_instance, gke_nodepool, cloudfunctions_function, run_service, run_job, run_worker_pool, cloudbuild_trigger, cloudbuild_default_identity (project default Cloud Build identity), compute_default_service_account, cloudservices_agent (project Google APIs Service Agent), composer_environment, dataflow_job, dataproc_cluster, cloudscheduler_job, workflows_workflow, appengine_version, notebooks_instance, workstations_config, workstations_workstation, dataform_repository (reserved; dataform is in _todo.yaml), clouddeploy_target, integration_connector, sourcerepo_trigger_consumer (run-as SA of Build triggers / Deploy pipelines fed by the repo), artifact_consumer (run-as SA of any workload pulling the artifact; needs image/package consumer mapping)
- `attached_to_service` values for non-workload targets:
  - connectors_agent_impersonable: SAs on which the project's Connectors service agent has Token Creator
  - wif_pool_bound: SAs granting roles/iam.workloadIdentityUser to principal:// or principalSet:// members of the pool `{target.host_resource}`
  - vertex_custom_code_agent: service-<number>@gcp-sa-aiplatform-cc of the project
  - workspace_dwd_delegation: Workspace users reachable via the DWD scopes of `{pivot}`
  - workspace_super_admin_of_zone_domain: Workspace super admins of the domain served by the `{pivot}` zone
  - workspace_addon_user: Workspace users who installed the add-on deployment `{target.host_resource}`
  - agentidentity_authorized_user: Workspace users who authorized the `{pivot}` auth provider
- service-agent synthetic nodes: cloudservices, aiplatform-cc, connectors, dataform, DTS (BigQuery Data Transfer) and the Dataflow service agents are Google-managed. They must become SA nodes, so that their Token Creator / actAs grants on customer SAs make an edge from "can drive the service" to "customer SA".
- selector `gcp_custom_role_bound_to_source: true` (already in schema.py): the target gcp_scope_owner scope is one where the source (directly or via a group) has a binding to a custom role defined in that scope or an ancestor, and the source has iam.roles.update on that role.
- PROPOSED selector `gcp_tag_conditional_binding`: the edge exists only when some IAM binding has a `resource.matchTag(...)` condition that the source can satisfy by binding the tag value (resourcemanager.tagValueBindings.create + tagValues.use, or tagValues.setIamPolicy). This needs tag-binding facts, so those techniques are excluded for now.
- PROPOSED kind `gcp_federated_principal`: principal:// and principalSet:// members of a WIF pool as graph nodes, so that roles bound directly to them (not via SA impersonation) are reachable from the wif entries.
- cloudidentity mapping: `cloudidentity.groups.memberships.create` on `{target.email}` (gcp_group) is not a GCP IAM permission. The evaluator must derive it from the source's Cloud Identity group role (OWNER/MANAGER), a Workspace Groups Admin / Super Admin role, or a group that allows self-join. The target group then inherits all of its IAM bindings.
- blocker dict form `{id: org_policy_constraint, constraint: <name>}`: the edge is removed when that constraint is enforced on the target's project (e.g. compute.requireOsLogin, iam.disableServiceAccountKeyCreation, storage.restrictAuthTypes, iam.workloadIdentityPoolProviders). It is not evaluated yet and is reported as not evaluated.
- GKE: k8s_cluster_admin is used as a gcp target kind with `{target.scope}` = the cluster (container.clusterRoles.bind/escalate, serviceAccounts.createToken, gkehub gateway RBAC); the GKE node-pool SA is reached via `attached_to_service: gke_nodepool`.
- Workspace admin-role facts are not collected. Super admin → GCP org admin and admin password-reset paths are excluded until a `gcp_workspace_admin_role` source fact exists.

## REVIEW FOLLOW-UP (GCP / Azure wrongly-excluded escalations)
- Azure `attached_to_service: Microsoft.Authorization/policyAssignments` (used by azure-policy-definition-write-remediation-identity). The target is the system- or user-assigned managed identity of a policy assignment `{target.host_resource}` that uses a deployIfNotExists or modify effect. With `pivot_resource_type: Microsoft.Authorization/policyDefinitions|Microsoft.Authorization/policySetDefinitions`, the pivot must be the custom definition the assignment references, directly or through an initiative, or the initiative itself. The evaluator must join assignment.policyDefinitionId (and the initiative's policyDefinitions[]) to `{pivot}`. Facts needed: policy assignments with `identity` (type, principalId, userAssignedIdentities), and policy set definition membership. Until they are collected, the edge is unknown.
- Azure requirement `scope: '*'` on Microsoft.Authorization/policyDefinitions/write in azure-policy-*: this is the definition's storage location (management group or subscription). It must be the assignment/initiative scope or an ancestor of it; this is conditional (definition_visible_at_pivot / new_definition_location).
- Azure `pivot_resource_type: Microsoft.Management/managementGroups|Microsoft.Resources/subscriptions|Microsoft.Resources/resourceGroups` (azure-policy-assignment-write-user-assigned-identity). Any scope at which the source can write a policy assignment. The target UAMI is matched with `azure_identity_assignable_in_scope` and `userAssignedIdentities/assign/action` on `{target.id}`.
- Azure `attached_to_service: Microsoft.ApiManagement/service` (azure-apim-policy-write-managed-identity-token). Every identity attached to the APIM instance, system-assigned and each user-assigned. The edge is a full token for any audience, so all of the identity's roles propagate (not a PARTIAL gain).
- PROPOSED (gcp): add `gcp` to EXTRA_KIND_PROVIDERS for `k8s_service_account`, plus a selector `k8s_sa_has_token_secret: true`. The target would be KSAs referenced by a `kubernetes.io/service-account-token` Secret (annotation kubernetes.io/service-account.name) in the GKE cluster `{target.scope}` covered by container.secrets.get/list. Facts needed: K8s Secret metadata (type and SA annotation only, never data) joined to the GKE cluster. gcp-container-secrets-read-ksa-token-secret should then move from `k8s_cluster_admin` to this kind and selector. gcp-container-serviceaccounts-createtoken could do the same with a `k8s_sa_in_cluster: true` selector.
- PROPOSED (gcp) source selector `gcp_workspace_admin_role: super_admin|<admin role id>`. The source is a Workspace/Cloud Identity user holding that admin role (Admin SDK Directory users.isAdmin / roleAssignments). It is needed by the commented-out gcp-workspace-super-admin-org-admin at the end of gcp/workspace.yaml (target `gcp_scope_owner`, scope org, empty requires with `source_kind: gcp_user`). It would also cover the admin password-reset path (#access-privileged-gcp-users) when combined with a `gcp_user` target selector for users whose password that admin role may reset.
- GCP permission naming: the IAM names for Workload Identity pools and providers carry the service prefix, e.g. `iam.googleapis.com/workloadIdentityPoolProviders.create`, exactly as Google's IAM reference and role definitions list them. gcp_permissions_cat.yaml stores them mangled as `iam.googleapis.com-workloadIdentityPool...` (slash replaced by a dash), so the --permissions check flags them. The evaluator matches role permissions exactly, so the catalog uses the real names.

## REVIEW FOLLOW-UP (catalog/aws/cloudformation.yaml, aws-cloudformation-passrole-stackset)
- `pivot_resource_type: aws_stackset_administration_role`: `{pivot}` is a role that trusts cloudformation.amazonaws.com and that the source can pass (the `iam:PassRole` requirement on `{pivot}` must hold on that same role). With no pivot candidates the requirement falls back to the usual conditional "pivot not verified" result.
- selector `assumable_by_pivot_role: true` (aws_role targets, scope org): the target role can be assumed by the pivot role. This holds when the target's trust policy allows the pivot role ARN, or the pivot's account root, and the pivot role's identity policy allows sts:AssumeRole on the target. The trust check alone suffices when the trust names the pivot ARN in the same account. The pivot role itself is not a target. Targets include roles in the pivot's own account and in other accounts, because the source chooses ExecutionRoleName. Until it is registered, the validator reports "unknown selector key" and drops the entry.

## CATALOG REFRESH (hacktricks-cloud 171e422: gcp, azure, k8s)
- K8s `k8s_node_hosting_privileged_pod_in_namespace` (narrowed, implemented). A pod counts only for a privileged container (derived), or for a container that adds SYS_ADMIN/ALL (`cap_sys_admin_constrained_by_seccomp_apparmor`), SYS_MODULE (`kernel_module_loading_restricted`), DAC_READ_SEARCH (`open_by_handle_at_blocked_by_seccomp`), or SYS_PTRACE together with hostPID (`ptrace_restricted_by_apparmor_or_yama`). Those four are conditional. hostPID, hostIPC, hostNetwork and shareProcessNamespace alone no longer count. Containers, initContainers and ephemeralContainers are all inspected.
- K8s `k8s_node_hosting_host_mount_pod_in_namespace: "<ns>|{pivot.namespace}|*"` (new, implemented, dynamic). The node runs a running pod in the namespace with a sensitive hostPath. These count as derived:
  - a container runtime socket (containerd, docker, cri-o, dockershim, k3s, podman, buildkit), even when mounted readOnly
  - kubelet credentials (/var/lib/kubelet/pki, /var/lib/kubelet/kubeconfig, /var/lib/kubelet/pods, /var/lib/rancher/k3s/agent) or any ancestor of them, even readOnly
  - host root `/`
  - a writable host-executed path: cron, systemd, static manifests, sudoers, ld.so.preload, passwd/shadow, /root/.ssh, bin/lib dirs, /opt/cni/bin, /etc/cni, core_pattern, uevent_helper
  These are conditional: /etc readOnly or /etc/kubernetes or /etc/rancher/k3s (`node_credential_location_varies`), /home, /var/lib/docker, /var/lib/containerd, /sys/fs/cgroup, and any subPath mount (`hostpath_subpath_narrows_mount`). Writable /var/log does not count, because the kubelet log-symlink read depends on the kubelet version. /var/run is normalised to /run. Facts used: pod spec volumes, volumeMounts, readOnly and subPath; no new collection is needed.
- K8s `k8s_sa_name: <name>|[names]` (new, implemented): the target ServiceAccount has one of these names. It is used with `namespace` for well-known controller identities (Flux kustomize-controller and helm-controller, argocd-application-controller).
- K8s `k8s_sa_used_by_pod_consuming_configmap: true` (new, implemented, always conditional `configmap_consumer_executes_content_not_verified`): the SA runs a pod that mounts a ConfigMap or loads it through envFrom/env. Whether the workload executes that content is not derivable.
- hostNetwork semantics: hostNetwork never means node root. It only matters in `k8s-cloud-hostnetwork-pod-node-identity`, where it gives the node's cloud identity even when pod-network IMDS access is blocked (EKS hop limit 1, GKE metadata server, NetworkPolicy does not apply to host-network pods).
- NOT COLLECTED (caveats): the Flux `--default-service-account` and `--no-cross-namespace-refs` flags and the Argo CD AppProject restrictions. The GitOps controller entries are conditional on these.
- GCP `attached_to_service` new values from the G1 refresh: `saasservicemgmt_unit`, `bigquery_spark_connection`, `agentregistry_skill_consumer`, `hypercomputecluster_cluster`. They are not in SERVICE_HOSTS yet, so the edge is reported unknown (`attachment_inventory_not_collected`) until the attachment facts are collected.

## CATALOG REFRESH (catalog/aws/*, hacktricks-cloud 171e422299)
New `via_resource_type` / `attached_to_service` values. They use only registered keys. Each one resolves through the existing prefix convention (`<prefix>_<thing>` -> `<prefix>.amazonaws.com`) or a full principal name. Until the matching inventory is collected, attachment is reported as unknown for every role that trusts that principal:
- `appstream_fleet`, `appstream_image_builder`, `appstream_app_block_builder` (IamRoleArn of AppStream fleets and builders); `gameliftstreams_stream_session` (session RoleArn); `pipes_pipe`; `cloudwatch_space` (Omni dataAccessRoleArn); `importexport_job` (Snowball); `lambda_microvm`; `athena_workgroup`; `emr-serverless_session`, `emr-serverless_application`; `datazone_environment`; `kinesisanalytics_application`; `sagemaker_cluster` (HyperPod).
- `attached_to_service: credentials.deadline.amazonaws.com` (Deadline Cloud queue and fleet roles; a full principal is used because the service prefix `deadline` is not the trust principal).
- `consumer_input_writable_via` with `appstream:UpdateApplication` (application -> Elastic fleet role) and `devicefarm:UpdateUpload` (test-spec upload -> project/run execution role). These need new input-to-consumer mappings.

IMPLEMENTED (AWS follow-ups; registered in schema.py SELECTOR_KEYS / PRECONDITIONS / PLACEHOLDERS with FACTS_NEEDED, evaluated in effective_permissions/aws.py). Missing facts give unresolved placeholders (UNKNOWN), never FAIL:
- EKS clusters are `k8s_cluster_admin` targets built from `eks_cluster` (eks:ListClusters + DescribeCluster: arn, name, endpoint, accessConfig.authenticationMode), labelled "EKS cluster <name> (cluster-admin)", with `{target.scope}` = cluster ARN and `{target.name}` / `{target.account}`. Selector `eks_authentication_mode: [API, API_AND_CONFIG_MAP]`; precondition `eks_cluster_exists` (pod identity and nodegroup entries). A related K8s snapshot of the same cluster (metadata/provenance cluster_id equal to the ARN, endpoint-origin digest or unique name) is joined with a `cloud-identity-join` edge to its `k8s_cluster_admin:<cluster_id>` node.
- `trust_allows_oidc_provider_covered_by: <action>` with `{target.oidc_provider_arn}` (aws-iam-oidcprovider-add-client-id; AddClientID or Delete+Create).
- `trust_federated_provider_missing: saml|oidc` (needs iam:ListSAMLProviders / ListOpenIDConnectProviders as `iam_saml_provider` / `iam_oidc_provider` items with Arn).
- `trust_allows_principal_org: true` + precondition `source_in_org_management_account` (organizations:CreateAccount); `org_member_account: true` (AssumeRoot, StartPrimaryEmailUpdate, RegisterDelegatedAdministrator). Facts: organizations:ListAccounts (`organization_account` Id, Arn, State) and ListRoots for aws:PrincipalOrgPaths.
- `ecs_task_colocated_with_source_container_instance: "{source.arn}"` (ECScape). Proven only with ecs:ListContainerInstances + DescribeContainerInstances (containerInstanceArn, ec2InstanceId) and ecs:ListTasks + DescribeTasks (taskDefinitionArn, overrides.taskRoleArn, containerInstanceArn, launchType); clusters with 0 container instances and Fargate-only task definitions are dropped.
- `emr_runtime_role_of_cluster: true` (elasticmapreduce:ListClusters + DescribeCluster: SecurityConfiguration, Ec2InstanceAttributes.IamInstanceProfile) and `trust_allows_emr_containers_oidc: true` (trust only).
- Redshift: no new key; `trust_allows_service` takes the list [redshift.amazonaws.com, redshift-serverless.amazonaws.com].
- `instance_profile_name_prefix_or_path: [AWSPCS, /aws-pcs/]` (PCS).
- `portfolio_of_target_product_covered_by: <action>` with `{target.portfolio_arn}` (servicecatalog:ListPortfolios + ListConstraintsForPortfolio: LAUNCH constraint RoleArn / LocalRoleName, ProductId).
- Target kind `aws_directory_domain_admin` (entity, not an AWS admin kind) for PCA Connector for AD templates; connectors are not collected (pca-connector-ad:ListConnectors, ListTemplates), so the targets are per-account unresolved placeholders.
- Azure (Az1 refresh) new values:
  - `azure_host_linked_to_pivot: devtest_lab_compute_vm`: the compute VM that backs a DevTest Labs VM. Not collected, so it evaluates as unknown.
  - `attached_to_service: Microsoft.DevCenter/projects/environmentTypes | Microsoft.DigitalTwins/digitalTwinsInstances`: identities attached to those resources.
  - Real actions missing from the permission catalog: `Microsoft.DocumentDB/databaseAccounts/{cassandra,gremlin,table,mongoMI}RoleAssignments/write`.
- PROPOSED (Entra, not used by any entry yet):
  - requirement `entra_pim_eligible_group: "{target.id}"`: the source is eligible through PIM for Groups (member or owner) for the target group. Facts come from identityGovernance/privilegedAccess/group/eligibilitySchedules.
  - requirement `entra_entitlement_catalog_role` with selector `entra_resource_in_catalog_managed_by_source`: the source holds Catalog owner or Access package manager on a catalog, and the target is a group, app or role in that catalog.
  - selector `entra_access_package_auto_rule_satisfiable_by_invited_guest`.
  - selector `entra_condition_satisfiable_by_custom_attribute`.
  - target kind `entra_managed_device`: Intune device code execution, plus a device-to-signed-in-user fact.
- PROPOSED (Azure refresh A; no entry uses these yet):
  - add `azure` to the providers of target kind `k8s_service_account`, so AKS namespace RBAC Writer secret reads can reach Kubernetes service-account tokens.
  - a selector for Image Builder build-VM identities (vmProfile.userAssignedIdentities), kept separate from the template's top-level identity.
  - a two-hop check, "the template UAMI holds Managed Identity Operator on the target", for the net-new Image Builder template path.
  - `credential_stored_in_scope` with an `azure_user` kind, for user-consented API connections.
- Azure (refresh C): real actions that are absent from azure_permissions_cat.yaml and used only in conditions or notes: `Microsoft.Compute/virtualMachineScaleSets/virtualMachines/manualUpgrade/action`, `.../virtualMachineScaleSets/runCommands/write`, `.../virtualMachineScaleSets/virtualmachines/login/action`, `Microsoft.Synapse/workspaces/sparkConfigurations/write`, `Microsoft.Synapse/workspaces/libraries/write`. BloodHound AZExecuteCommand (Intune Administrator scripts on managed devices) stays unmodelled until the proposed `entra_managed_device` target kind exists.
- Azure (refresh B): `azure_host_linked_to_pivot: service_fabric_node_vmss` means the node scale sets of a Service Fabric cluster (for managed clusters they sit in the service-managed SFC_ resource group). It evaluates as unknown until the cluster-to-VMSS link is collected. Spring Apps identities sit on child resources (Microsoft.AppPlatform/Spring/apps), and the collector should list app-level identities.
- K8s: the Flux controller entries select `k8s_sa_name` in any namespace on purpose, because Flux can be installed outside flux-system. The validator's "reaches every namespace" warning for those two entries is expected. The Argo CD entry is pinned with `k8s_sa_in_namespace: argocd`.
- GCP selector `gcp_actas_granted_to_service_agent: cloudservices` (implemented and registered). The target SA is one on which <project-number>@cloudservices.gserviceaccount.com holds iam.serviceAccounts.actAs, computed from the collected allow policies (it holds roles/editor by default). The result is unknown when no binding of that agent is collected. Used by the MIG entries in gcp/compute.yaml.
- GCP selector `gcp_pam_entitlement_requester: true` (registered, not evaluated). The source is an eligible requester, directly or through a group, of a PAM entitlement on the target scope whose roles give IAM control of it. Facts needed: privilegedaccessmanager entitlements (eligibleUsers, privilegedAccess.gcpIamAccess.roleBindings, approvalWorkflow).
- GCP (G2 refresh): pivot resource type `appintegration_auth_config`, plus new `attached_to_service` values `config_connector_identity`, `datafusion_instance`, `dataform_workflow_config_end_user`, `appintegration_authconfig_identity`, `firebase_apphosting_backend`, `cloudbuild_unpinned_storage_source`, `vmmigration_target_default`, `vertex_reasoning_engine_agent` and `workforce_pool_bound`. Until SERVICE_HOSTS maps them and the attachments are collected, they evaluate as unknown.
