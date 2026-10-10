"""Privilege-escalation catalog loader and strict schema validator.

The registries in this module are the single source of truth for which target
kinds, selector keys, scopes, requirement fields and placeholders the evaluator
implements. The validator rejects anything the evaluator would not understand,
so an unknown selector key can never silently widen or narrow a target set.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

PROVIDERS = ("aws", "gcp", "azure", "k8s")
CATALOG_DIR = Path(__file__).resolve().parent / "catalog"
HACKTRICKS_CLOUD = Path("/Users/carlospolop/git/hacktricks-cloud")

# kind -> (provider, node class). "principal" kinds are real identities that can
# act as sources; "entity" kinds are collapsed control objects (account admin,
# scope owner, cluster-admin, a directory role) that are terminal privileges.
TARGET_KINDS = {
    "aws_role": ("aws", "principal"),
    "aws_user": ("aws", "principal"),
    "aws_group": ("aws", "principal"),
    "aws_identity_center_user": ("aws", "principal"),
    "aws_identity_center_permission_set": ("aws", "entity"),
    "aws_account_admin": ("aws", "entity"),
    "gcp_service_account": ("gcp", "principal"),
    "gcp_user": ("gcp", "principal"),
    "gcp_group": ("gcp", "principal"),
    "gcp_workspace_user": ("gcp", "principal"),
    "gcp_scope_owner": ("gcp", "entity"),
    "azure_managed_identity": ("azure", "principal"),
    "azure_service_principal": ("azure", "principal"),
    "azure_user": ("azure", "principal"),
    "azure_scope_owner": ("azure", "entity"),
    "azure_dataplane_admin": ("azure", "entity"),
    "entra_role": ("azure", "entity"),
    "entra_group": ("azure", "principal"),
    "k8s_service_account": ("k8s", "principal"),
    "k8s_user": ("k8s", "principal"),
    "k8s_group": ("k8s", "principal"),
    "k8s_node": ("k8s", "principal"),
    "k8s_cluster_admin": ("k8s", "entity"),
    "cloud_identity": ("k8s", "principal"),
}
# Kinds that more than one provider's catalog may target (AKS cluster-admin from Azure RBAC, ...).
EXTRA_KIND_PROVIDERS = {"k8s_cluster_admin": ("azure", "gcp", "aws"), "k8s_service_account": ("gcp",)}
ADMIN_KINDS = ("aws_account_admin", "gcp_scope_owner", "azure_scope_owner", "k8s_cluster_admin", "entra_role")


def kind_allowed(kind, provider):
    return kind in TARGET_KINDS and (TARGET_KINDS[kind][0] == provider or provider in EXTRA_KIND_PROVIDERS.get(kind, ()))


# selector key -> (providers, value kind, description). Value kinds: bool_true,
# bool, string, string_or_list, namespace, action, any.
SELECTOR_KEYS = {
    # ---- generic ---------------------------------------------------------
    "attached_to_service": (("aws", "gcp", "azure"), "string_or_list",
        "Identity is attached to a collected resource of that service (Lambda Role, EC2 instance profile, "
        "GCE/GKE service account, Azure resource identity incl. full ARM types). Uncollected attachment "
        "inventories fall back to trust/all identities with unknown confidence."),
    "same_as_source": (("aws", "gcp", "azure", "k8s"), "bool_true",
        "Target is the source itself (self-escalation); for entity kinds the source's own scope."),
    "resource_permission_covers_target": (("aws", "gcp", "azure", "k8s"), "action",
        "The source must also hold this action on the target resource ({target.arn}/{target.email}/{target.scope}/{target.namespace})."),
    "any_principal_in_scope": (("gcp", "azure", "k8s", "aws"), "bool_true",
        "Entity target covering every principal of the scope where the requirement holds (scope owner / cluster-admin / account admin)."),
    # ---- AWS -------------------------------------------------------------
    "trust_allows_service": (("aws",), "string_or_list",
        "Role trust policy has an Allow for sts:AssumeRole* whose Principal.Service includes the value."),
    "trust_allows_principal_of_source": (("aws",), "bool_true",
        "Role trust policy allows the source principal ARN, the source account (root/ID) or '*'."),
    "trust_allows_federated": (("aws",), "string_or_list",
        "Role trust policy allows Principal.Federated equal to the value (e.g. cognito-identity.amazonaws.com)."),
    "trust_allows_saml_provider_covered_by": (("aws",), "action",
        "Role trusts a SAML provider ({target.saml_provider_arn}) on which the source holds the action."),
    "has_instance_profile": (("aws",), "bool",
        "Role is in at least one instance profile (InstanceProfileList)."),
    "has_login_profile": (("aws",), "bool",
        "IAM user has (true) / lacks (false) a console password (LoginProfile detail)."),
    "name_prefix": (("aws",), "string",
        "Role name (and instance-profile name) starts with the value."),
    "source_kind": (("aws",), "string_or_list",
        "Technique only applies when the source principal is of this kind."),
    "source_group_covered_by": (("aws",), "action",
        "Source is a member of an IAM group ({source.group_arn}) on which it holds the action."),
    "source_attached_policy_covered_by": (("aws",), "action",
        "A customer-managed policy attached to the source ({source.attached_policy_arn}) is covered by the action."),
    "via_assumable_role_covered_by": (("aws",), "action",
        "The source can assume a role on which it also holds the action (two-step self-escalation)."),
    "via_resource_type": (("aws",), "string_or_list",
        "Target role is attached to an existing resource of that type ({target.resource_arn}); lambda_function and "
        "ec2_instance are collected, other types are unknown."),
    "via_artifact_type": (("aws",), "string_or_list",
        "Target role's workload consumes an artifact ({target.artifact_arn}) of that type; artifact consumers are not collected (unknown)."),
    "attached_resource_covered_by": (("aws",), "action",
        "The resource carrying the target role ({target.attached_resource_arn}) is covered by the action."),
    "consumer_input_writable_via": (("aws",), "action",
        "The source can write an input ({target.consumer_input_arn}) consumed by the target workload with the action."),
    "cognito_user_pool_covered_by": (("aws",), "action",
        "Target role is mapped by an identity pool to a user pool covered by the action (Cognito facts not collected)."),
    "cognito_user_pool_group_role_covered_by": (("aws",), "action",
        "Target role is the RoleArn of a user-pool group covered by the action (Cognito facts not collected)."),
    "codedeploy_group_instance_role_covered_by": (("aws",), "action",
        "Target role is the instance role of a CodeDeploy deployment group covered by the action (not collected)."),
    "ecs_task_role_on_ec2_capacity": (("aws",), "bool_true",
        "Target role is used by ECS tasks running on EC2 capacity (ECS facts not collected)."),
    "ecs_container_instance_role_in_cluster_covered_by": (("aws",), "action",
        "Target role is the container-instance role of an ECS cluster covered by the action (not collected)."),
    "assigned_to_identity_center_group": (("aws",), "bool_true",
        "Permission set / user is reachable through an Identity Center group assignment (not collected)."),
    "rolesanywhere_profile_includes_target": (("aws",), "bool_true",
        "Target role is listed in an IAM Roles Anywhere profile ({target.trust_anchor_arn}) (not collected)."),
    # ---- GCP -------------------------------------------------------------
    "gcp_actas_granted_on_target": (("gcp",), "bool_true",
        "Source holds iam.serviceAccounts.actAs on the target SA (SA policy or project/folder/org inheritance)."),
    "gcp_sa_in_scope_of_permission": (("gcp",), "bool_true",
        "Requirements with resource '*' must hold on the target SA's project (or the SA / an ancestor)."),
    "gcp_implicit_delegation_chain": (("gcp",), "bool_true",
        "Target SA is one a delegate chain can mint credentials for: the source holds iam.serviceAccounts.implicitDelegation "
        "on delegate D1, each Di holds implicitDelegation on Di+1 (transitively), and some Dk holds getAccessToken, signBlob "
        "or signJwt on the target. Delegates are not targets themselves (implicitDelegation does not yield their own token)."),
    "gcp_custom_role_bound_to_source": (("gcp",), "bool_true",
        "Target scope (gcp_scope_owner) is one where the source has a binding to a custom role defined in that scope "
        "or an ancestor (projects/<p>/roles/* or organizations/<o>/roles/*)."),
    # ---- Azure RBAC ------------------------------------------------------
    "azure_identity_assignable_in_scope": (("azure",), "bool_true",
        "Requirements with scope '*' must hold on a scope that contains the identity's attached resource "
        "(or the user-assigned identity resource)."),
    "managed_identity_type": (("azure",), "string",
        "Managed identity is user_assigned or system_assigned."),
    "custom_role_assigned_to_source": (("azure",), "bool_true",
        "Target scope is one where a custom role assigned to the source applies (role definition rewrite)."),
    "credential_stored_in_scope": (("azure",), "string",
        "Principals whose secrets are stored in that resource/scope (always conditional; secret contents are never read)."),
    "azure_host_linked_to_pivot": (("azure",), "string",
        "Identity of a host linked to the pivot resource (e.g. automation hybrid worker VM); not collected (unknown)."),
    "azure_deployer_of_pivot": (("azure",), "bool_true",
        "Identity that deploys the pivot resource (e.g. deployment script runner); not collected (unknown)."),
    "azure_site_kind": (("azure",), "string_or_list",
        "Microsoft.Web/sites kind contains the value (functionapp, app, ...)."),
    "ml_compute_assigned_to_source": (("azure",), "bool_true",
        "Azure ML compute instance assigned to the source (not collected, unknown)."),
    # ---- Entra ID --------------------------------------------------------
    "entra_role_assignable": (("azure",), "string_or_list",
        "Target is the named Entra directory role (display name, template ID, '*' or 'any')."),
    "entra_reset_matrix_column": (("azure",), "string",
        "Targets whose password the role column may reset per Microsoft's 'who can reset passwords' table, "
        "excluding role-assignable-group members and restricted-AU members."),
    "entra_role_assignment_scope_covers_target": (("azure",), "bool_true",
        "The directory role assignment's directoryScopeId ('/', AU or object) contains the target."),
    "entra_target_not_in_restricted_au": (("azure",), "bool_true",
        "Target is not a member of a restricted management administrative unit (AU facts needed)."),
    "entra_sp_has_tenant_application": (("azure",), "bool_true",
        "Service principal's appId belongs to an application registered in this tenant."),
    "entra_app_sign_in_audience": (("azure",), "string_or_list",
        "Application signInAudience equals the value."),
    "entra_sp_type_in": (("azure",), "string_or_list",
        "Service principal servicePrincipalType is one of the values."),
    "entra_source_is_owner_of_application": (("azure",), "bool_true", "Source owns the target's application object."),
    "entra_source_is_owner_of_service_principal": (("azure",), "bool_true", "Source owns the target service principal."),
    "entra_source_is_owner_of_group": (("azure",), "bool_true", "Source owns the target group."),
    "entra_custom_role_assigned_to_source": (("azure",), "bool_true",
        "Target is reached by editing a custom directory role already assigned to the source."),
    "entra_pim_eligible_for_source": (("azure",), "bool_true",
        "Source has a PIM eligibility schedule for the target role."),
    "entra_agent_blueprint_principal_or_child_identity": (("azure",), "bool_true",
        "Target is an agent identity blueprint principal or one of its child agent identities."),
    "entra_user_upn_on_federatable_custom_domain": (("azure",), "bool_true",
        "Target user's UPN is on a verified custom domain whose federation the source can change (domain facts needed)."),
    "entra_group_role_assignable": (("azure",), "bool",
        "Group isAssignableToRole equals the value."),
    "entra_group_membership_type": (("azure",), "string",
        "Group membership is 'assigned' or 'dynamic' (groupTypes contains DynamicMembership)."),
    "entra_group_type_covered_by_permission": (("azure",), "bool_true",
        "Group type (security / Microsoft 365) is covered by the entra_permission variant (groups.security / groups.unified)."),
    "entra_dynamic_rule_attributes_writable_by_source": (("azure",), "bool_true",
        "Dynamic membershipRule references user attributes the source can write (membershipRule needed)."),
    "entra_dynamic_rule_satisfiable_by_invited_guest": (("azure",), "bool_true",
        "Dynamic membershipRule can be satisfied by a guest the source can invite (membershipRule needed)."),
    # ---- Kubernetes ------------------------------------------------------
    "k8s_sa_in_namespace": (("k8s",), "namespace",
        "Target service account namespace: '{source.namespace}', '{target.namespace}', '*', or a literal namespace."),
    "k8s_node_hosting_pods_with_sa": (("k8s",), "bool_true",
        "Service account is mounted by a scheduled pod (k8s_service_account) or node hosts pods (k8s_node); "
        "with a k8s_node source, the SAs of pods scheduled on that node."),
    "k8s_sa_used_by_running_pod": (("k8s",), "bool_true", "Service account is used by at least one collected running pod."),
    "k8s_sa_used_by_controller_managed_pod": (("k8s",), "bool_true",
        "Service account is used by a pod owned by a controller (ownerReferences)."),
    "k8s_node_schedulable": (("k8s",), "bool_true", "Node is not cordoned (spec.unschedulable is not true)."),
    "k8s_node_hosting_pods_in_namespace": (("k8s",), "namespace", "Node hosts pods of that namespace."),
    "k8s_node_hosting_privileged_pod_in_namespace": (("k8s",), "namespace",
        "Node hosts a privileged / hostPath / hostPID pod of that namespace."),
    "exclude_names": (("k8s",), "string_or_list", "Drop targets whose name is in the list."),
    "k8s_sa_cloud_binding": (("k8s",), "string",
        "Cloud identity bound to the source SA via irsa|eks_pod_identity|gke_workload_identity|azure_workload_identity|aks_identity_binding (cloud facts needed)."),
    "trust_allows_k8s_sa_oidc_subject": (("k8s",), "bool_true", "IAM role trust allows the cluster OIDC subject of the SA (cloud facts needed)."),
    "gcp_workload_identity_user_granted_to_k8s_sa": (("k8s",), "bool_true",
        "GSA grants roles/iam.workloadIdentityUser to the KSA member (cloud facts needed)."),
    "azure_fic_matches_k8s_sa": (("k8s",), "bool_true", "Federated identity credential subject matches the SA (cloud facts needed)."),
    "k8s_node_cloud_identity": (("k8s",), "bool_true", "Cloud identity attached to the node (cloud facts needed)."),
    "k8s_nodes_mapped_to_cloud_identity": (("k8s",), "bool_true", "Nodes mapped to the source cloud identity (cloud facts needed)."),
    "k8s_sa_absent_but_bound": (("k8s",), "bool_true",
        "Service account referenced by a (Cluster)RoleBinding subject but absent from the serviceaccount inventory "
        "(virtual SA node; anyone who can create it inherits the binding)."),
    "trust_allows_oidc_subject_wildcard": (("k8s",), "string",
        "IAM role trust matches the given OIDC subject pattern (e.g. system:serviceaccount:{pivot.namespace}:*) on the cluster OIDC provider (cloud facts needed)."),
    "kube2iam_namespace_permits_role": (("k8s",), "namespace",
        "Namespace (usually {pivot.namespace}) annotation iam.amazonaws.com/permitted (kube2iam/kiam) allows the target role (annotation facts needed)."),
    "k8s_sa_has_token_secret": (("gcp",), "bool_true",
        "GKE: KSAs of cluster {target.scope} referenced by a kubernetes.io/service-account-token Secret "
        "(annotation kubernetes.io/service-account.name); joined from the related K8s snapshot, else one conditional aggregate per cluster."),
    "k8s_sa_in_cluster": (("gcp",), "bool_true",
        "GKE: every KSA of cluster {target.scope}; joined from the related K8s snapshot, else one conditional aggregate per cluster."),
    "assumable_by_pivot_role": (("aws",), "bool_true",
        "Role the pivot role ({pivot}, e.g. a StackSet administration role) can assume: its trust admits the pivot role "
        "(or its account) and the pivot's identity policy allows sts:AssumeRole on it (trust naming the pivot ARN in the same "
        "account suffices). The pivot itself is excluded; roles in other accounts are included."),
    "openshift_namespace_has_sa_with_host_scc": (("k8s",), "namespace",
        "The OpenShift namespace (usually {pivot.namespace}) contains an SA allowed to use a host-level SCC (securitycontextconstraints not collected)."),
}
# Keys allowed under the top-level `source_selector` (restricts which principals act as sources).
SOURCE_SELECTOR_KEYS = {
    "k8s_node_role": (("k8s",), "string", "Node carries node-role.kubernetes.io/<value> label."),
    "eks_access_entry_type": (("k8s",), "string", "EKS access entry type of the source cloud identity (not collected)."),
    "gcp_workspace_admin_role": (("gcp",), "string",
        "Source is a Workspace/Cloud Identity user holding that admin role: 'super_admin' (users.isAdmin or a role with "
        "isSuperAdminRole) or an admin roleId / roleName (Admin SDK roleAssignments)."),
}
# Collection types/fields a selector or requirement needs; reported in coverage when missing.
FACTS_NEEDED = {
    "via_resource_type": "AWS: per-type workload inventories carrying the role (ecs task definitions, glue jobs, sagemaker, ...)",
    "via_artifact_type": "AWS: artifact consumer mapping (S3 object / ECR repo / SSM document -> consuming role)",
    "consumer_input_writable_via": "AWS: workload input mapping (ECR repo / S3 object -> consuming role)",
    "cognito_user_pool_covered_by": "AWS: cognito identity pool roles + user pool providers",
    "cognito_user_pool_group_role_covered_by": "AWS: cognito user pool groups RoleArn",
    "codedeploy_group_instance_role_covered_by": "AWS: codedeploy deployment groups + instance roles",
    "ecs_task_role_on_ec2_capacity": "AWS: ecs clusters/tasks with launch type",
    "ecs_container_instance_role_in_cluster_covered_by": "AWS: ecs container instances",
    "assigned_to_identity_center_group": "AWS: sso-admin account assignments + identitystore groups",
    "rolesanywhere_profile_includes_target": "AWS: rolesanywhere profiles/trust anchors",
    "entra_target_not_in_restricted_au": "Azure: directory_administrative_unit {id,isMemberManagementRestricted} + members",
    "entra_reset_matrix_column": "Azure: directory_role_assignment for target users, directory_group.isAssignableToRole, AU membership",
    "entra_sp_has_tenant_application": "Azure: directory_application.appId",
    "entra_app_sign_in_audience": "Azure: directory_application.signInAudience",
    "entra_source_is_owner_of_application": "Azure: directory_owner (applications/{id}/owners)",
    "entra_source_is_owner_of_service_principal": "Azure: directory_owner (servicePrincipals/{id}/owners)",
    "entra_source_is_owner_of_group": "Azure: directory_owner (groups/{id}/owners)",
    "entra_pim_eligible_for_source": "Azure: directory_role_eligibility_schedule (roleManagement/directory/roleEligibilitySchedules)",
    "entra_agent_blueprint_principal_or_child_identity": "Azure: agent identity blueprint principals",
    "entra_user_upn_on_federatable_custom_domain": "Azure: directory_domain {id,authenticationType,isVerified} + user UPNs",
    "entra_group_role_assignable": "Azure: directory_group.isAssignableToRole",
    "entra_group_membership_type": "Azure: directory_group.groupTypes (collected)",
    "entra_dynamic_rule_attributes_writable_by_source": "Azure: directory_group.membershipRule",
    "entra_dynamic_rule_satisfiable_by_invited_guest": "Azure: directory_group.membershipRule + authorizationPolicy.allowInvitesFrom",
    "azure_host_linked_to_pivot": "Azure: automation hybrid worker groups + worker VM ids",
    "azure_deployer_of_pivot": "Azure: deployment script / pipeline runner identities",
    "ml_compute_assigned_to_source": "Azure: machine learning compute instances personal assignment",
    "credential_stored_in_scope": "Azure: secret holder mapping (never secret values)",
    "k8s_sa_cloud_binding": "Cloud: IRSA annotations + IAM trust, EKS pod identity associations, GKE WI bindings, AKS FICs",
    "trust_allows_k8s_sa_oidc_subject": "AWS: iam_role trust policies in the cluster's account",
    "gcp_workload_identity_user_granted_to_k8s_sa": "GCP: service_account iamPolicy",
    "azure_fic_matches_k8s_sa": "Azure: user-assigned identity federatedIdentityCredentials",
    "k8s_node_cloud_identity": "Cloud: node instance role / node SA",
    "k8s_nodes_mapped_to_cloud_identity": "AWS: EKS access entries / aws-auth",
    "trust_allows_oidc_subject_wildcard": "AWS: iam_role trust policies in the cluster's account (join with AWS snapshot)",
    "kube2iam_namespace_permits_role": "K8s: namespace metadata.annotations (iam.amazonaws.com/permitted)",
    "openshift_namespace_has_sa_with_host_scc": "K8s/OpenShift: securitycontextconstraints {users, groups, allowHostPID/Network/DirVolumePlugin, allowPrivilegedContainer}",
    "gcp_implicit_delegation_chain": "GCP: service_account iamPolicy + project/folder/org iam_policy (collected)",
    "ecr_tag_immutability": "AWS: ecr_repository {repositoryArn, imageTagMutability}",
    "k8s_sa_has_token_secret": "K8s: secret metadata {metadata.namespace, type, metadata.annotations[kubernetes.io/service-account.name]} "
                               "(never data) in a K8s snapshot of the GKE cluster passed as related_snapshots; GCP: gke_cluster",
    "k8s_sa_in_cluster": "K8s: serviceaccount inventory of the GKE cluster passed as related_snapshots; GCP: gke_cluster",
    "assumable_by_pivot_role": "AWS: iam_role trust policies + the pivot role's identity policies (collected)",
    "gcp_workspace_admin_role": "GCP: workspace_user {primaryEmail, isAdmin}, workspace_role {roleId, roleName, isSuperAdminRole}, "
                                "workspace_role_assignment {roleId, assignedTo} (Admin SDK Directory API)",
    "k8s_sa_absent_but_bound": "K8s: serviceaccount inventory for every namespace (collected)",
    "eks_access_entry_type": "AWS: EKS access entries",
    "graph_app_permission": "Azure: directory_app_role_assignment (servicePrincipals/{id}/appRoleAssignments) incl. resourceId+appRoleId",
    "entra_owner_of": "Azure: directory_owner {object_id, object_type, owner_ids}",
    "entra_pim_eligible_role": "Azure: directory_role_eligibility_schedule {principalId, roleDefinitionId, directoryScopeId}",
    "entra_tenant_setting": "Azure: directory_authorization_policy {allowInvitesFrom, guestUserRoleId}",
}
SCOPES = ("same_account", "same_project", "inherited_scope", "same_namespace", "cluster", "tenant", "org", "any")
CONFIDENCES = ("derived", "conditional", "unknown")
SEVERITIES = ("critical", "high", "medium", "low", "info")
REQUIREMENT_FIELDS = {
    "aws": {"action", "resource", "notes"},
    "gcp": {"action", "permission", "resource", "notes"},
    "azure": {"action", "data_action", "scope", "entra_permission", "entra_role", "directory_scope", "graph_app_permission",
              "entra_owner_of", "object_type", "entra_pim_eligible_role", "entra_tenant_setting", "notes"},
    "k8s": {"verb", "resource", "subresource", "api_group", "namespace", "resource_name", "notes"},
}
AZURE_REQUIREMENT_KINDS = ("action", "entra_permission", "entra_role", "graph_app_permission", "entra_owner_of",
                           "entra_pim_eligible_role", "entra_tenant_setting")
ENTRA_TENANT_SETTINGS = ("guest_invites_allowed_for_source",)
PLACEHOLDERS = {
    "target.arn", "target.email", "target.id", "target.scope", "target.namespace", "target.name", "target.account",
    "target.project", "target.node", "target.client_id", "target.application_id",
    "target.resource_arn", "target.attached_resource_arn", "target.artifact_arn", "target.consumer_input_arn",
    "target.saml_provider_arn", "target.trust_anchor_arn",
    "target.host_resource", "target.host_resource.content_storage", "target.host_resource.workspace",
    "source", "source.account", "source.arn", "source.id", "source.email", "source.namespace", "source.name",
    "source.scope", "source.attached_policy_arn", "source.group_arn", "source.assumable_role_arn",
    "source.controlled_user", "target.user",
    "pivot", "pivot.namespace",
    "account", "project", "scope", "namespace", "cluster",
    "admin_equivalent_clusterrole", "source_bound_clusterrole", "source_bound_role", "host_scc",
}
ENTRY_FIELDS = {"id", "provider", "service", "title", "source", "source_revision", "summary", "requires", "target",
                "conditions", "blockers", "confidence", "severity", "mitigation", "references", "notes",
                "pivot_resource_type", "source_kind", "source_selector"}
REQUIRED_FIELDS = ("id", "provider", "service", "title", "source", "summary", "requires", "target", "severity", "mitigation")
# Blockers the evaluator evaluates from snapshot facts; every other known blocker is reported
# in finding evidence as `blockers_not_evaluated` (it never silently removes or downgrades an edge).
# Blockers a provider model evaluates from optional snapshot facts (listed as not evaluated when the facts are absent).
MODEL_BLOCKERS = {"aws": {"ecr_tag_immutability"}}
# Placeholders that resolve on entity targets (account admin, scope owner, cluster-admin, ...). Any other
# {target.*} placeholder on an entity target can never resolve and would silently make every edge unknown.
ENTITY_TARGET_PLACEHOLDERS = {
    "aws_account_admin": {"target.scope", "target.account"},
    "aws_identity_center_permission_set": {"target.scope", "target.account", "target.arn", "target.id"},
    "gcp_scope_owner": {"target.scope", "target.project", "target.id", "target.name"},
    "azure_scope_owner": {"target.scope"},
    "azure_dataplane_admin": {"target.scope"},
    "k8s_cluster_admin": {"target.scope", "target.cluster"},
    "entra_role": {"target.scope", "target.id", "target.name"},
}
ENTITY_KINDS = {k for k, (_, role) in TARGET_KINDS.items() if role == "entity"}
EVALUATED_BLOCKERS = {"scp_or_boundary_deny", "scp_deny", "permission_boundary", "explicit_deny", "deny_policy",
                      "gcp_deny_policy", "azure_deny_assignment"}
KNOWN_BLOCKERS = EVALUATED_BLOCKERS | {
    "abac_condition", "restricted_management_au", "role_assignable_group_member_or_owner",
    "sp_lock_configuration_credentials", "ecr_tag_immutability", "lambda_code_signing_enforced",
    "scm_and_ftp_basic_auth_disabled", "service_principal_conditional_access_block", "glue_nonoverridable_arguments",
    "role_assignment_condition_is_allowlist", "pim_approval_required_by_other_principal",
    "target_upn_on_initial_onmicrosoft_domain", "aks_local_accounts_disabled", "aks_entra_integration_enabled",
    "pivot_namespace_psa_enforce_baseline_or_restricted", "vpc_sc_perimeter", "org_policy_constraint",
    "pod_security_admission", "admission_policy",
}
_ID = re.compile(r"^(aws|gcp|azure|k8s|entra)-[a-z0-9]+(?:-[a-z0-9]+)*$")
_PLACEHOLDER = re.compile(r"(?<!\$)\{([^{}]+)\}")
# Execution content is forbidden: entries describe preconditions, not steps.
_COMMANDS = re.compile(r"(^|\s)(aws|gcloud|az|kubectl|curl|wget|python3?|bash)\s+[a-z-]+\s+[a-z-]+", re.I)


class CatalogError(ValueError):
    pass


def _placeholders(value):
    return set(_PLACEHOLDER.findall(value)) if isinstance(value, str) else set()


def _requirements(requires):
    out = [r for r in (requires.get("all_of") or []) if isinstance(r, dict)] if isinstance(requires.get("all_of"), list) else []
    for group in requires.get("any_of") or [] if isinstance(requires.get("any_of"), list) else []:
        out.extend(r for r in (group if isinstance(group, list) else []) if isinstance(r, dict))
    return out


def _validate_requirement(item, provider, where, errors):
    if not isinstance(item, dict):
        errors.append(f"{where}: requirement must be a mapping")
        return
    allowed = REQUIREMENT_FIELDS[provider]
    unknown = set(item) - allowed
    if unknown:
        errors.append(f"{where}: unknown requirement fields {sorted(unknown)}")
    if provider == "aws":
        if not isinstance(item.get("action"), str) or ":" not in item["action"]:
            errors.append(f"{where}: aws requirement needs action 'service:Action'")
        elif any(c in item["action"] for c in "*?"):
            errors.append(f"{where}: requirement action must be concrete (no wildcards)")
    elif provider == "gcp":
        permission = item.get("permission", item.get("action"))
        if not isinstance(permission, str) or permission.count(".") < 2 or "*" in permission:
            errors.append(f"{where}: gcp requirement needs a concrete permission 'service.resource.verb'")
    elif provider == "azure":
        kinds = [k for k in AZURE_REQUIREMENT_KINDS if k in item]
        if len(kinds) != 1 or not isinstance(item[kinds[0]], str) or not item[kinds[0]]:
            errors.append(f"{where}: azure requirement needs exactly one of {'/'.join(AZURE_REQUIREMENT_KINDS)}")
        if "data_action" in item and not isinstance(item["data_action"], bool):
            errors.append(f"{where}: data_action must be a boolean")
        if "entra_owner_of" in item and item.get("object_type") not in ("application", "servicePrincipal", "group"):
            errors.append(f"{where}: entra_owner_of needs object_type application|servicePrincipal|group")
        if "object_type" in item and "entra_owner_of" not in item:
            errors.append(f"{where}: object_type is only valid with entra_owner_of")
        if "entra_tenant_setting" in item and item["entra_tenant_setting"] not in ENTRA_TENANT_SETTINGS:
            errors.append(f"{where}: unknown entra_tenant_setting {item['entra_tenant_setting']!r}")
    elif provider == "k8s":
        if not isinstance(item.get("verb"), str) or not isinstance(item.get("resource"), str):
            errors.append(f"{where}: k8s requirement needs verb and resource")
        if "/" in str(item.get("resource", "")):
            errors.append(f"{where}: use subresource instead of resource 'a/b'")
    for key, value in item.items():
        if key == "notes":
            continue
        if not isinstance(value, (str, bool)):
            errors.append(f"{where}: field {key} must be a string or boolean")
        bad = _placeholders(value) - PLACEHOLDERS
        if bad:
            errors.append(f"{where}: unknown placeholders {sorted(bad)}")


def validate_entry(entry, *, expected_provider=None, hacktricks_root=None):
    """Return (errors, warnings) for one technique."""
    errors, warnings = [], []
    if not isinstance(entry, dict):
        return ["entry must be a mapping"], warnings
    ident = entry.get("id", "<missing id>")
    where = str(ident)
    for field in REQUIRED_FIELDS:
        if field not in entry:
            errors.append(f"{where}: missing field {field}")
    unknown = set(entry) - ENTRY_FIELDS
    if unknown:
        errors.append(f"{where}: unknown fields {sorted(unknown)}")
    if not isinstance(entry.get("id"), str) or not _ID.match(entry.get("id", "")):
        errors.append(f"{where}: id must be kebab-case and provider-prefixed")
    provider = entry.get("provider")
    if provider not in PROVIDERS:
        errors.append(f"{where}: provider must be one of {PROVIDERS}")
        return errors, warnings
    prefix = str(entry.get("id", "")).split("-", 1)[0]
    if prefix != provider and not (prefix == "entra" and provider == "azure"):
        errors.append(f"{where}: id prefix must match provider {provider}")
    if expected_provider and provider != expected_provider:
        errors.append(f"{where}: provider {provider} does not match catalog directory {expected_provider}")
    for field in ("service", "title", "summary", "mitigation", "source"):
        if field in entry and (not isinstance(entry[field], str) or not entry[field].strip()):
            errors.append(f"{where}: {field} must be a non-empty string")
    for field in ("title", "summary", "mitigation", "notes"):
        if isinstance(entry.get(field), str) and _COMMANDS.search(entry[field]):
            warnings.append(f"{where}: {field} looks like it contains a command; entries must not contain how-to steps")
    source = entry.get("source")
    if isinstance(source, str):
        if not source.startswith("src/"):
            errors.append(f"{where}: source must be a hacktricks-cloud path starting with src/")
        root = Path(hacktricks_root) if hacktricks_root else HACKTRICKS_CLOUD
        if root.is_dir() and not (root / source.split("#", 1)[0]).is_file():
            errors.append(f"{where}: source file not found in hacktricks-cloud: {source.split('#', 1)[0]}")
    requires = entry.get("requires")
    groups = 0
    if not isinstance(requires, dict) or set(requires) - {"all_of", "any_of"}:
        errors.append(f"{where}: requires must be a mapping with all_of/any_of")
    else:
        all_of = requires.get("all_of") or []
        any_of = requires.get("any_of") or []
        if not isinstance(all_of, list) or not isinstance(any_of, list):
            errors.append(f"{where}: all_of and any_of must be lists")
        else:
            for i, item in enumerate(all_of):
                _validate_requirement(item, provider, f"{where}.requires.all_of[{i}]", errors)
            for i, group in enumerate(any_of):
                if not isinstance(group, list) or not group:
                    errors.append(f"{where}: any_of[{i}] must be a non-empty list of requirements")
                    continue
                for j, item in enumerate(group):
                    _validate_requirement(item, provider, f"{where}.requires.any_of[{i}][{j}]", errors)
            groups = len(all_of) + len(any_of)
        if groups == 0 and not entry.get("source_kind"):
            errors.append(f"{where}: at least one requirement is needed (or a source_kind for intrinsic techniques)")
    target = entry.get("target")
    if not isinstance(target, dict):
        errors.append(f"{where}: target must be a mapping")
    else:
        unknown = set(target) - {"kind", "selector", "scope", "aggregate_as", "include_service_managed"}
        if unknown:
            errors.append(f"{where}: unknown target fields {sorted(unknown)}")
        kind = target.get("kind")
        if kind not in TARGET_KINDS:
            errors.append(f"{where}: unknown target kind {kind!r}")
        elif not kind_allowed(kind, provider):
            errors.append(f"{where}: target kind {kind} is not a {provider} kind")
        selector = target.get("selector") or {}
        if not isinstance(selector, dict):
            errors.append(f"{where}: selector must be a mapping")
            selector = {}
        for key, value in selector.items():
            if key not in SELECTOR_KEYS:
                errors.append(f"{where}: unknown selector key {key!r}")
                continue
            providers, value_kind, _ = SELECTOR_KEYS[key]
            if provider not in providers:
                errors.append(f"{where}: selector {key} is not supported for {provider}")
            if value_kind == "bool_true" and value is not True:
                errors.append(f"{where}: selector {key} must be true")
            elif value_kind == "bool" and not isinstance(value, bool):
                errors.append(f"{where}: selector {key} must be a boolean")
            elif value_kind in ("string", "action", "namespace") and not isinstance(value, str):
                errors.append(f"{where}: selector {key} must be a string")
            elif value_kind == "string_or_list" and not (isinstance(value, str) or (
                    isinstance(value, list) and value and all(isinstance(x, str) for x in value))):
                errors.append(f"{where}: selector {key} must be a string or list of strings")
            bad = set().union(*(_placeholders(x) for x in (value if isinstance(value, list) else [value]))) - PLACEHOLDERS
            if bad:
                errors.append(f"{where}: selector {key} has unknown placeholders {sorted(bad)}")
        if target.get("scope", "any") not in SCOPES:
            errors.append(f"{where}: target scope must be one of {SCOPES}")
        if "aggregate_as" in target and not isinstance(target["aggregate_as"], str):
            errors.append(f"{where}: aggregate_as must be a string")
        if "include_service_managed" in target and not isinstance(target["include_service_managed"], bool):
            errors.append(f"{where}: include_service_managed must be a boolean")
        if kind in ENTITY_KINDS and isinstance(requires, dict):
            used = set().union(*(_placeholders(v) for r in _requirements(requires) for k, v in r.items() if k != "notes"))
            allowed = ENTITY_TARGET_PLACEHOLDERS.get(kind, {"target.scope"})
            bad = sorted(p for p in used if p.startswith("target.") and p not in allowed)
            if bad:
                errors.append(f"{where}: placeholders {bad} cannot resolve on entity target kind {kind} "
                              f"(only {sorted(allowed)}); use a source.* placeholder or a principal target kind")
        if kind == "k8s_service_account" and provider == "gcp" and not {"k8s_sa_has_token_secret", "k8s_sa_in_cluster"} & set(selector):
            errors.append(f"{where}: gcp k8s_service_account targets need selector k8s_sa_has_token_secret or k8s_sa_in_cluster")
        if kind == "k8s_service_account" and provider == "k8s" and isinstance(requires, dict):
            text = repr(requires) + repr(selector)
            if "{target.namespace}" not in text and "k8s_sa_in_namespace" not in selector and target.get("scope") != "same_namespace":
                warnings.append(f"{where}: k8s service-account target without a namespace restriction reaches every namespace")
    source_kind = entry.get("source_kind")
    if source_kind is not None:
        kinds = source_kind if isinstance(source_kind, list) else [source_kind]
        for value in kinds:
            if value not in TARGET_KINDS or TARGET_KINDS[value][1] != "principal" or not kind_allowed(value, provider):
                errors.append(f"{where}: source_kind {value!r} is not a {provider} principal kind")
    source_selector = entry.get("source_selector")
    if source_selector is not None:
        if not isinstance(source_selector, dict):
            errors.append(f"{where}: source_selector must be a mapping")
        else:
            for key in source_selector:
                if key not in SOURCE_SELECTOR_KEYS:
                    errors.append(f"{where}: unknown source_selector key {key!r}")
                elif provider not in SOURCE_SELECTOR_KEYS[key][0]:
                    errors.append(f"{where}: source_selector {key} is not supported for {provider}")
    pivot_type = entry.get("pivot_resource_type")
    uses_pivot = "{pivot}" in repr(requires) + repr((target or {}).get("selector") if isinstance(target, dict) else "")
    if pivot_type is not None and not isinstance(pivot_type, str):
        errors.append(f"{where}: pivot_resource_type must be a string")
    if uses_pivot and pivot_type is None:
        warnings.append(f"{where}: uses {{pivot}} without pivot_resource_type")
    conditions = entry.get("conditions", [])
    if not isinstance(conditions, list):
        errors.append(f"{where}: conditions must be a list")
    else:
        for i, condition in enumerate(conditions):
            if isinstance(condition, str):
                continue
            if not isinstance(condition, dict) or not isinstance(condition.get("id"), str) or set(condition) - {"id", "description"}:
                errors.append(f"{where}: conditions[{i}] must be {{id, description}}")
    blockers = entry.get("blockers", [])
    if not isinstance(blockers, list) or any(not isinstance(x, (str, dict)) for x in blockers):
        errors.append(f"{where}: blockers must be a list of strings")
    else:
        for blocker in blockers:
            name = blocker if isinstance(blocker, str) else blocker.get("id")
            if name not in KNOWN_BLOCKERS:
                warnings.append(f"{where}: unknown blocker {name!r} (reported as not evaluated)")
    for field, allowed in (("confidence", CONFIDENCES), ("severity", SEVERITIES)):
        if field in entry and entry[field] not in allowed:
            errors.append(f"{where}: {field} must be one of {allowed}")
    if "references" in entry and (not isinstance(entry["references"], list) or any(not isinstance(x, str) for x in entry["references"])):
        errors.append(f"{where}: references must be a list of URLs")
    if "notes" in entry and not isinstance(entry["notes"], str):
        errors.append(f"{where}: notes must be a string")
    return errors, warnings


def validate_excluded(items, where):
    errors = []
    if items is None:
        return errors
    if not isinstance(items, list):
        return [f"{where}: _excluded.yaml must be a list"]
    for i, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("source"), str) or not isinstance(item.get("reason"), str):
            errors.append(f"{where}[{i}]: excluded entries need source and reason strings")
    return errors


def catalog_files(catalog_dir=None):
    root = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    return sorted(p for p in root.rglob("*.y*ml") if p.is_file())


def load_catalog(catalog_dir=None, *, strict=False, hacktricks_root=None):
    """Load every technique. Returns {entries, errors, warnings, files, excluded}.

    Invalid entries are dropped (never half-evaluated) and reported; strict mode
    raises CatalogError instead.
    """
    root = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    entries, errors, warnings, files, excluded = [], [], [], [], 0
    seen = {}
    for path in catalog_files(root):
        rel = str(path.relative_to(root))
        provider = path.relative_to(root).parts[0] if len(path.relative_to(root).parts) > 1 else None
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: YAML parse error: {str(exc).splitlines()[0]}")
            files.append({"file": rel, "entries": 0, "valid": 0})
            continue
        if path.name.startswith("_excluded"):
            errors.extend(validate_excluded(data, rel))
            excluded += len(data or [])
            files.append({"file": rel, "entries": 0, "excluded": len(data or [])})
            continue
        if data is None:
            data = []
        if not isinstance(data, list):
            errors.append(f"{rel}: catalog file must be a YAML list")
            continue
        valid = 0
        for index, entry in enumerate(data):
            entry_errors, entry_warnings = validate_entry(entry, expected_provider=provider if provider in PROVIDERS else None,
                                                          hacktricks_root=hacktricks_root)
            ident = entry.get("id") if isinstance(entry, dict) else None
            if ident in seen:
                entry_errors.append(f"{ident}: duplicate id (also in {seen[ident]})")
            elif ident:
                seen[ident] = rel
            errors.extend(f"{rel}[{index}] {e}" for e in entry_errors)
            warnings.extend(f"{rel}[{index}] {w}" for w in entry_warnings)
            if not entry_errors:
                item = dict(entry)
                item["_file"] = rel
                entries.append(item)
                valid += 1
        files.append({"file": rel, "entries": len(data), "valid": valid})
    if strict and errors:
        raise CatalogError("; ".join(errors[:20]))
    return {"entries": entries, "errors": errors, "warnings": warnings, "files": files, "excluded": excluded}
