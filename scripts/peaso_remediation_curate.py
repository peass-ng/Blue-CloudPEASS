#!/usr/bin/env python3
"""Write the individually reviewed remediation examples; no evaluator changes."""
import json
from pathlib import Path
import tempfile

OUT = Path(__file__).resolve().parents[1] / "peaso/rulepacks/remediation_curated.json"


def ref(title, url):
    return {"title": title, "url": url}


def cmd(label, code):
    return {"label": label, "shell": "bash", "code": code}


def rule(summary, steps, cli, caveats, references, iac=None):
    value = {"summary": summary, "steps": steps, "cli": cli, "caveats": caveats,
             "references": references, "review_status": "approved"}
    if iac:
        value["iac"] = {"label": "Change the existing managed declaration", "language": "text", "code": iac}
    return value


AWS_SG = ref("AWS security group rules", "https://docs.aws.amazon.com/vpc/latest/userguide/working-with-security-group-rules.html")
AWS_IAM = ref("AWS customer managed policy editing", "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage-edit-cli.html")
GCP_FIREWALL = ref("Google Cloud firewall rule update", "https://cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/update")
GCP_IAM = ref("Google Cloud IAM access changes", "https://cloud.google.com/iam/docs/granting-changing-revoking-access")
AZ_APP = ref("Application Insights workspace configuration", "https://learn.microsoft.com/en-us/azure/azure-monitor/app/create-workspace-resource")
AZ_VAULT = ref("Key Vault Private Link", "https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service?tabs=portal")
AZ_BLOB = ref("Prevent anonymous blob access", "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-overview")
K8S_POD = ref("Kubernetes security context", "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/")
K8S_KUBELET = ref("Kubelet authentication and authorization", "https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/")

RULES = {
    "aws.gap.vpc.sg_world_any_common_ports": rule(
        "Narrow the matching security group ingress source for the flagged common port.",
        ["Inspect GroupId and each matching IpPermissions rule; identify its rule ID, attached workloads and required client source.",
         "Authorize the same needed port from an approved CIDR or source security group, then test the intended clients.",
         "Revoke only the independently identified broad rule and rerun this check; verify application traffic separately."],
        [cmd("Inspect ingress rule IDs", "aws ec2 describe-security-group-rules --filters Name=group-id,Values=<RESOURCE_ID> --region <REGION>"),
         cmd("Authorize approved replacement", "aws ec2 authorize-security-group-ingress --group-id <RESOURCE_ID> --protocol tcp --port <PORT> --cidr <APPROVED_CIDR> --region <REGION>"),
         cmd("Remove the identified broad rule after testing", "aws ec2 revoke-security-group-ingress --group-id <RESOURCE_ID> --security-group-rule-ids <RULE_ID> --region <REGION>")],
        ["The finding does not include a rule ID or approved CIDR. Changing ingress may interrupt clients; this declaration does not prove reachability."],
        [AWS_SG, ref("AWS revoke security group ingress", "https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html")],
        "Update the existing aws_vpc_security_group_ingress_rule or equivalent managed ingress CIDR in its owner module, then review and apply its plan."),
    "aws.iam.no_full_admin": rule(
        "Replace the unconditional Action '*' and Resource '*' Allow grant with reviewed workload permissions.",
        ["Inspect PolicyDocument or the default PolicyVersionList version and list every principal attached to the policy.",
         "Approve a replacement document limited to required actions and resource ARNs, with supported conditions where applicable.",
         "Publish the reviewed default policy version, validate it and test all attached workloads before removing old versions."],
        [cmd("Inspect attached principals", "aws iam list-entities-for-policy --policy-arn <RESOURCE_ARN>"),
         cmd("Inspect the default version", "aws iam get-policy --policy-arn <RESOURCE_ARN>"),
         cmd("Apply a separately reviewed policy file", "aws iam create-policy-version --policy-arn <RESOURCE_ARN> --policy-document file://reviewed-policy.json --set-as-default")],
        ["No replacement policy can be inferred from the finding. AWS managed policies cannot be edited in place; changing a shared customer managed policy may interrupt other principals."],
        [AWS_IAM], "Update the existing aws_iam_policy policy document or CloudFormation policy resource with the separately reviewed grant."),
    "aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation": rule(
        "Remove the unnecessary granting action combination or constrain its allowed role and launch resources.",
        ["Inspect the flagged PolicyDocument/default version and all attached principals; identify which ordinary workload uses each action.",
         "Remove an unused grant or limit iam:PassRole to reviewed role ARNs and supported conditions; review launch permissions separately.",
         "Publish the reviewed version and test legitimate launches; rerun the check and inspect its declared escalation_actions evidence."],
        [cmd("Inspect attached principals", "aws iam list-entities-for-policy --policy-arn <RESOURCE_ARN>"),
         cmd("Apply a separately reviewed policy file", "aws iam create-policy-version --policy-arn <RESOURCE_ARN> --policy-document file://reviewed-policy.json --set-as-default")],
        ["The evaluator flags declared action combinations without proving an executable escalation path. The finding does not supply a safe replacement policy."],
        [AWS_IAM, ref("AWS PassRole guidance", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html")],
        "Edit the owning customer managed IAM policy document in Terraform or CloudFormation after the role, action and condition review."),
    "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only": rule(
        "Restrict the flagged TCP ingress sourceRanges to sources approved for the actual target and port.",
        ["Inspect direction, allowed TCP ports, target tags/service accounts, source selectors and ranges_outside_cis_list on the named rule.",
         "For an IAP-only admin target, set the approved IAP source range; include health-check ranges only when that workload needs them.",
         "Test IAP access and load-balancer health, then rerun the check; review higher-priority firewall policies separately."],
        [cmd("Inspect the firewall rule", "gcloud compute firewall-rules describe <RESOURCE_NAME> --project=<PROJECT_ID>"),
         cmd("Set the approved IAP source for an IAP-only target", "gcloud compute firewall-rules update <RESOURCE_NAME> --project=<PROJECT_ID> --source-ranges=35.235.240.0/20")],
        ["This rule may have other source selectors or serve health checks. The range check does not prove effective reachability or IAP authorization."],
        [GCP_FIREWALL, ref("IAP TCP forwarding", "https://cloud.google.com/iap/docs/using-tcp-forwarding")],
        "Update source_ranges on the existing google_compute_firewall resource only after reviewing the rule target and clients."),
    "gcp.gap.iam_user_managed_sa_no_admin_roles": rule(
        "Replace the flagged service-account admin/editor/owner binding at its actual policy level with tested narrow permissions.",
        ["Inspect admin_role_bindings and locate each binding at the project, folder or organization policy that owns it.",
         "Grant a tested narrower role at the required scope, preserving reviewed conditions.",
         "Remove the broad binding at the same policy level and verify deployment operations and inherited access."],
        [cmd("Inspect project policy when the binding is project-owned", "gcloud projects get-iam-policy <PROJECT_ID_OR_NUMBER> --format=json"),
         cmd("Remove a verified project-owned broad binding after replacement", "gcloud projects remove-iam-policy-binding <PROJECT_ID> --member=<SERVICE_ACCOUNT_MEMBER> --role=<BROAD_ROLE>")],
        ["A project command cannot remove inherited folder or organization grants. The finding does not establish the replacement role or prove a binding is unconditioned."],
        [GCP_IAM], "Update the actual owning google_project_iam_* / google_folder_iam_* / google_organization_iam_* declaration after access testing."),
    "azure.claude2.application_insights_workspace_based": rule(
        "Link the Application Insights component to the approved Log Analytics WorkspaceResourceId.",
        ["Inspect properties.WorkspaceResourceId and identify a workspace with approved retention, residency and access.",
         "Update the component to reference that workspace through its configuration owner.",
         "Read WorkspaceResourceId again and verify telemetry arrives in the intended workspace."],
        [cmd("Inspect the component", "az monitor app-insights component show --resource-group <RESOURCE_GROUP> --app <RESOURCE_NAME>"),
         cmd("Link the reviewed workspace", "az monitor app-insights component update --resource-group <RESOURCE_GROUP> --app <RESOURCE_NAME> --workspace <WORKSPACE_RESOURCE_ID>")],
        ["Workspace linking can affect cost, retention and data location. The predicate sees a declaration, not telemetry delivery."],
        [AZ_APP, ref("Azure CLI Application Insights component", "https://learn.microsoft.com/en-us/cli/azure/monitor/app-insights/component?view=azure-cli-latest")],
        "Set WorkspaceResourceId on the owning Microsoft.Insights/components Bicep/ARM/Terraform resource to the reviewed workspace ID."),
    "azure.vault.approved_private_endpoint": rule(
        "Approve a tested Key Vault private endpoint and set networkAcls.defaultAction to Deny after client migration.",
        ["Inspect networkAcls.defaultAction and privateEndpointConnections status; identify dependent clients and DNS paths.",
         "Provision and approve a private endpoint through the infrastructure owner; test client DNS and vault operations.",
         "Set the vault default firewall action to Deny and verify clients and endpoint approval independently."],
        [cmd("Inspect vault networking", "az keyvault show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>"),
         cmd("Set default Deny after client migration", "az keyvault update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --default-action Deny")],
        ["An approved endpoint does not prove DNS or reachability. Setting Deny before migration can stop vault access."],
        [AZ_VAULT, ref("Azure CLI Key Vault update", "https://learn.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest")],
        "Manage the endpoint, DNS and Key Vault networkAcls in the owning Bicep/Terraform deployment; apply defaultAction Deny after client tests."),
    "azure.storage.no_blob_public_access": rule(
        "Set storage-account properties.allowBlobPublicAccess to false after migrating intentional public readers.",
        ["Inspect allowBlobPublicAccess and container consumers; identify any intentional anonymous download path.",
         "Move intended public content to an approved delivery path, then disable account-level anonymous blob access.",
         "Read the account setting again and test authorized readers and migrated public content."],
        [cmd("Inspect the account", "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>"),
         cmd("Disable anonymous blob access", "az storage account update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --allow-blob-public-access false")],
        ["This setting blocks anonymous blob reads even on public containers and may interrupt clients."],
        [AZ_BLOB, ref("Azure CLI storage account update", "https://learn.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest")],
        "Set allowBlobPublicAccess = false on the owning Microsoft.Storage/storageAccounts declaration after client migration."),
    "k8s.pod.no_privileged_containers": rule(
        "Set securityContext.privileged to false for each flagged container in its owning Pod template.",
        ["Inspect the named containers across spec.containers, initContainers and ephemeralContainers; identify the workload controller.",
         "Remove the privileged requirement or replace it with reviewed minimum capabilities in the controller Pod template.",
         "Roll out the controller and verify the new Pods, application behavior and Pod Security admission."],
        [cmd("Inspect the Pod and its ownerReferences", "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o yaml")],
        ["A live Pod edit is not a durable controller fix. Removing privilege can break workloads; the finding does not prove admission policy enforcement."],
        [K8S_POD, ref("Kubernetes owners and dependents", "https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/")],
        "Set securityContext.privileged: false in the owning Deployment/DaemonSet/StatefulSet/Job manifest or Helm values and apply its reviewed rollout."),
    "k8s.ports.pod.container_argument_anonymous_auth_disabled": rule(
        "Set kubelet anonymous authentication to false in its owning managed configuration.",
        ["Confirm _component_config identifies kubelet, flags_complete is true, and the captured version supports this flag.",
         "Use the node or managed-cluster owner's supported configuration route to set anonymous-auth=false.",
         "Verify kubelet health, authenticated clients and the captured flag after rollout; rerun this check."],
        [cmd("Inspect the projected declaration", "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o yaml")],
        ["The projected Pod metadata is not proof of live host enforcement; the durable kubelet owner and update route are not established by this finding."],
        [K8S_KUBELET], "Set anonymous-auth: false in the owning kubelet configuration or supported managed-cluster setting; do not patch the projection Pod."),
}

RULES["azure.storage.default_oauth"] = rule(
    "Set this storage account's portal defaultToOAuthAuthentication property to true.",
    ["Inspect properties.defaultToOAuthAuthentication on the named storage account and identify users who browse blob data through the Azure portal.",
     "Enable Default to Microsoft Entra authorization in the account's Configuration settings or owning ARM/Bicep declaration; verify those users have appropriate data-plane RBAC.",
     "Read the property again and test authorized portal data access before rerunning the check."],
    [cmd("Inspect the storage account property", "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --query defaultToOAuthAuthentication")],
    ["This changes the Azure portal's default authentication choice only; users may still choose account-key authorization if Shared Key remains enabled. Verify client RBAC and do not claim that this setting disables keys."],
    [ref("Microsoft Entra authorization in Azure portal", "https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal")],
    "Set properties.defaultToOAuthAuthentication = true on the owning Microsoft.Storage/storageAccounts resource.")
RULES["azure.storage.default_oauth"]["field_binding"] = {"target": "resource", "kind": "storage_account", "field": "properties.defaultToOAuthAuthentication"}

AZ_BLOB_SOFT_DELETE = ref("Azure blob soft delete configuration", "https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-enable")
AZ_CONTAINER_SOFT_DELETE = ref("Azure container soft delete configuration", "https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-enable")
AZ_BLOB_VERSIONING = ref("Azure blob versioning configuration", "https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-enable")
for check_id, policy, update_flag, days_flag, documentation in (
    ("azure.port.storage_account_soft_delete_enabled", "deleteRetentionPolicy", "--enable-delete-retention", "--delete-retention-days", AZ_BLOB_SOFT_DELETE),
    ("azure.port.storage_account_blob_soft_delete_enabled", "deleteRetentionPolicy", "--enable-delete-retention", "--delete-retention-days", AZ_BLOB_SOFT_DELETE),
    ("azure.port.storage_account_container_soft_delete_enabled", "containerDeleteRetentionPolicy", "--enable-container-delete-retention", "--container-delete-retention-days", AZ_CONTAINER_SOFT_DELETE),
):
    minimum = check_id != "azure.port.storage_account_soft_delete_enabled"
    RULES[check_id] = rule(
        f"Enable the flagged Azure Blob service {policy} with a reviewed retention period.",
        [f"Inspect blobServices/default properties.{policy}.enabled" + (f" and days (the source accepts 7–365 days)" if minimum else "") + "; identify the storage account owner and current retention or lifecycle rules.",
         f"Choose an approved retention period" + (" of at least 7 and at most 365 days" if minimum else "") + f" and enable {policy} in the owning blob service configuration.",
         f"Read properties.{policy} again, test an authorized recovery path and rerun the native check."],
        [cmd("Inspect Blob service recovery settings", "az storage account blob-service-properties show --account-name <RESOURCE_NAME> --resource-group <RESOURCE_GROUP>"),
         cmd("Enable with an owner-approved retention period", f"az storage account blob-service-properties update --account-name <RESOURCE_NAME> --resource-group <RESOURCE_GROUP> {update_flag} true {days_flag} <APPROVED_RETENTION_DAYS>")],
        ["The evaluator joins the authoritative blobServices/default child; missing or ambiguous child data is UNKNOWN. Retention can increase storage cost, and this check does not prove restore success."],
        [documentation],
        f"Set properties.{policy}.enabled = true and days = <APPROVED_RETENTION_DAYS> on the owning Microsoft.Storage/storageAccounts/blobServices/default resource.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": "storage_account",
                                         "field": f"joined blobServices/default properties.{policy}.enabled" + ("/days=7..365" if minimum else ""),
                                         "evaluator_family": "azure_ports_storage._service"}

RULES["azure.port.storage_account_blob_and_container_soft_delete_enabled"] = rule(
    "Enable both Blob and container soft delete with reviewed 7–365 day retention on the flagged account.",
    ["Inspect joined blobServices/default properties.deleteRetentionPolicy and containerDeleteRetentionPolicy, including enabled and days for each.",
     "Select approved retention for both policies and update the owning Blob service configuration while preserving existing lifecycle rules.",
     "Read both policies again, test authorized Blob and container recovery paths and rerun the check."],
    [cmd("Inspect both policies", "az storage account blob-service-properties show --account-name <RESOURCE_NAME> --resource-group <RESOURCE_GROUP>"),
     cmd("Enable both with approved retention", "az storage account blob-service-properties update --account-name <RESOURCE_NAME> --resource-group <RESOURCE_GROUP> --enable-delete-retention true --delete-retention-days <APPROVED_BLOB_DAYS> --enable-container-delete-retention true --container-delete-retention-days <APPROVED_CONTAINER_DAYS>")],
    ["The evaluator requires both policies enabled with 7–365 days, using an authoritative blobServices/default join. Retention can increase cost; declaration is not recovery proof."],
    [AZ_BLOB_SOFT_DELETE, AZ_CONTAINER_SOFT_DELETE],
    "Set properties.deleteRetentionPolicy and properties.containerDeleteRetentionPolicy enabled=true with separately approved 7–365 day retention on the owning Blob service resource.")
RULES["azure.port.storage_account_blob_and_container_soft_delete_enabled"]["field_binding"] = {
    "target": "resource", "kind": "storage_account", "field": "joined blobServices/default properties.deleteRetentionPolicy and containerDeleteRetentionPolicy enabled/days=7..365",
    "evaluator_family": "azure_ports_storage.both"}

RULES["azure.port.storage_account_blob_versioning_enabled"] = rule(
    "Enable Blob versioning on the flagged storage account after reviewing retention and lifecycle cost.",
    ["Inspect joined blobServices/default properties.isVersioningEnabled and current version lifecycle rules.",
     "Enable versioning on the owning Blob service configuration and choose a reviewed old-version retention strategy.",
     "Read isVersioningEnabled again, test version restore and rerun the native check."],
    [cmd("Inspect Blob service settings", "az storage account blob-service-properties show --account-name <RESOURCE_NAME> --resource-group <RESOURCE_GROUP>"),
     cmd("Enable versioning", "az storage account blob-service-properties update --account-name <RESOURCE_NAME> --resource-group <RESOURCE_GROUP> --enable-versioning true")],
    ["The evaluator reads the joined Blob service flag only; it does not prove that earlier object versions exist or are restorable. Version retention can increase storage cost."],
    [AZ_BLOB_VERSIONING],
    "Set properties.isVersioningEnabled = true on the owning Microsoft.Storage/storageAccounts/blobServices/default resource and review lifecycle retention.")
RULES["azure.port.storage_account_blob_versioning_enabled"]["field_binding"] = {
    "target": "resource", "kind": "storage_account", "field": "joined blobServices/default properties.isVersioningEnabled",
    "evaluator_family": "azure_ports_storage.versioning"}

RULES["azure.port.storage_account_key_rotation_reminder_enabled"] = rule(
    "Set the storage-account key expiration reminder policy to the source's exact 90-day value.",
    ["Inspect properties.keyPolicy.keyExpirationPeriodInDays and keyCreationTime for both keys on the named storage account; identify current key users and rotation process.",
     "If both key creation timestamps exist, set the expiration reminder to 90 days through the account owner; otherwise plan staged key rotation before setting the policy.",
     "Read the policy again and rerun this check; verify rotation separately using key creation metadata."],
    [cmd("Inspect key expiration reminder", "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --query keyPolicy"),
     cmd("Set 90-day reminder", "az storage account update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --key-exp-days 90")],
    ["This policy is a reminder, not key regeneration. Azure requires creation timestamps for both keys before setting it; older accounts may need staged key rotation first. Existing keys and clients are unchanged by the policy update."],
    [ref("Azure storage account key management", "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage")],
    "Set properties.keyPolicy.keyExpirationPeriodInDays = 90 on the owning storage account declaration.")
RULES["azure.port.storage_account_key_rotation_reminder_enabled"]["field_binding"] = {
    "target": "resource", "kind": "storage_account", "field": "properties.keyPolicy.keyExpirationPeriodInDays=90",
    "evaluator_family": "azure_ports_storage.reminder"}

for check_id, service_name, purpose in (
    ("gcp.ports.project_service_cloudasset_api_enabled", "cloudasset.googleapis.com", "Cloud Asset inventory"),
    ("gcp.ports.artifacts_container_analysis_enabled", "containeranalysis.googleapis.com", "Artifact Analysis"),
):
    RULES[check_id] = rule(
        f"Enable {service_name} on the exact project when {purpose} collection is required.",
        [f"Inspect the collected service_usage name and state for projects/<PROJECT_ID>/services/{service_name}; identify the owning project and its service-use policy.",
         f"After the project owner approves {purpose} use, enable {service_name} on that project and retain the service in its desired configuration.",
         "Recollect the exact service state and rerun the native check; verify dependent inventory or scanning separately."],
        [cmd("List enabled services in the project", "gcloud services list --enabled --project=<PROJECT_ID>"),
         cmd("Enable the reviewed service", f"gcloud services enable {service_name} --project=<PROJECT_ID>")],
        ["Service enablement can change billing, quotas and available APIs. The evaluator reads only a complete Service Usage state; it does not prove the dependent inventory or analysis is configured or successful."],
        [ref("Google Cloud service enablement", "https://cloud.google.com/sdk/gcloud/reference/services/enable")],
        f"Declare {service_name} enabled on the exact project through its owning service-usage configuration.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": "project",
                                         "field": f"service_usage[].name=projects/<project>/services/{service_name}; state"}

# These native predicates read explicit Cloud SQL settings.databaseFlags entries.
# A one-flag gcloud patch would replace *all* existing flags, so the copyable
# command deliberately inspects the instance and the mutation stays with the
# configuration owner after reviewing the complete flag set and restart impact.
SQL_FLAG_REVIEW = {
    "gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on": ("POSTGRES", "log_checkpoints", "on", "PostgreSQL checkpoint logging"),
    "gcp.ports.sql_instance_postgresql_log_duration_database_flag_on": ("POSTGRES", "log_duration", "on", "PostgreSQL statement duration logging"),
    "gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on": ("POSTGRES", "log_lock_waits", "on", "PostgreSQL lock-wait logging"),
    "gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off": ("POSTGRES", "log_executor_stats", "off", "PostgreSQL executor statistics logging"),
    "gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off": ("POSTGRES", "log_parser_stats", "off", "PostgreSQL parser statistics logging"),
    "gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off": ("POSTGRES", "log_planner_stats", "off", "PostgreSQL planner statistics logging"),
    "gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off": ("POSTGRES", "log_statement_stats", "off", "PostgreSQL statement statistics logging"),
    "gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter": ("POSTGRES", "log_error_verbosity", "default or verbose", "PostgreSQL error log verbosity"),
    "gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error": ("POSTGRES", "log_min_messages", "error or warning", "PostgreSQL minimum logged message severity"),
    "gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0": ("POSTGRES", "log_temp_files", "0", "PostgreSQL temporary-file logging"),
    "gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off": ("SQLSERVER", "contained database authentication", "off", "SQL Server contained database authentication"),
    "gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off": ("SQLSERVER", "cross db ownership chaining", "off", "SQL Server cross-database ownership chaining"),
    "gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off": ("SQLSERVER", "external scripts enabled", "off", "SQL Server external scripts"),
    "gcp.ports.sql_instance_sql_remote_access_database_flag_off": ("SQLSERVER", "remote access", "off", "SQL Server remote access"),
    "gcp.ports.sql_instance_sql_3625_trace_database_flag_on": ("SQLSERVER", "3625", "on", "SQL Server trace flag 3625"),
}
for check_id, (engine, flag, desired, purpose) in SQL_FLAG_REVIEW.items():
    documentation = "postgres" if engine == "POSTGRES" else "sqlserver"
    selected_value = desired.split(" or ")[0]
    RULES[check_id] = rule(
        f"Set the {flag} flag to {desired} on the flagged {engine} Cloud SQL instance after a complete flag-set review.",
        [f"Inspect databaseVersion and settings.databaseFlags on the named instance; confirm the engine is {engine} and identify the current {flag} entry.",
         f"Have the instance owner prepare a reviewed YAML flags file with a --database-flags: mapping and indented flag_name: \"string value\" entries: retain every current required flag/value and change {flag} to {desired}.",
         "Compare the complete YAML mapping with the current instance and owning IaC declaration before using the operator-gated patch command.",
         f"Plan the possible instance and replica restart, test database clients, then read the {flag} declaration again and rerun the check."],
        [cmd("Inspect the instance and all declared flags", "gcloud sql instances describe <RESOURCE_NAME> --project=<PROJECT_ID>"),
         cmd("Apply the complete reviewed flag mapping", "gcloud sql instances patch <RESOURCE_NAME> --project=<PROJECT_ID> --flags-file=<REVIEWED_FULL_FLAGS_YAML>")],
        ["A gcloud --database-flags patch replaces every existing flag; a partial command could reset unrelated flags. A flag change can restart the instance and its replicas.",
         f"This evaluator reads the explicit {flag} declaration, not runtime database behavior. Confirm version support and logging volume or application dependency before changing the flag.",
         "The reviewed file is an operator-created full replacement, not a merge; do not use a file containing only the flagged key."],
        [ref(f"Cloud SQL {documentation} supported flags and update behavior", f"https://cloud.google.com/sql/docs/{documentation}/flags"),
         ref("gcloud Cloud SQL instance patch", "https://cloud.google.com/sdk/gcloud/reference/sql/instances/patch"),
         ref("gcloud YAML flags-file format", "https://cloud.google.com/sdk/gcloud/reference/topic/flags-file")],
        f"database_flags {{\n  name = \"{flag}\"\n  value = \"{selected_value}\"\n}}")
    RULES[check_id]["iac"]["language"] = "hcl"
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": "sql_instance",
                                         "field": f"databaseVersion={engine}; settings.databaseFlags[].name={flag}; value",
                                         "evaluator_family": "gcp_ports_services.sql_flag"}

RULES["gcp.reviewed.storage.soft_delete"] = rule(
    "Set a positive, owner-approved soft-delete retention duration on the flagged Cloud Storage bucket.",
    ["Inspect softDeletePolicy.retentionDurationSeconds on the exact bucket and confirm the organization retention and cost policy.",
     "Choose a supported positive duration with the data owner, then update the bucket's soft-delete policy through its configuration owner.",
     "Reread the retention duration, test an authorized recovery path and rerun the native check."],
    [cmd("Inspect bucket protection settings", "gcloud storage buckets describe gs://<RESOURCE_NAME>"),
     cmd("Set the approved soft-delete duration", "gcloud storage buckets update gs://<RESOURCE_NAME> --soft-delete-duration=<APPROVED_DURATION>")],
    ["The evaluator rejects only an explicit zero retention duration; it does not establish recoverability. The new duration applies to future deletions and can increase storage cost; check organization constraints and permitted duration units."],
    [ref("Cloud Storage soft-delete policy", "https://cloud.google.com/storage/docs/use-soft-delete")],
    "Set soft_delete_policy.retention_duration_seconds to an approved positive duration in the owning bucket declaration.")
RULES["gcp.reviewed.storage.soft_delete"]["field_binding"] = {
    "target": "resource", "kind": "bucket", "field": "softDeletePolicy.retentionDurationSeconds > 0",
    "evaluator_family": "gcp_extended.soft_delete"}

RULES["gcp.reviewed.storage.versioning"] = rule(
    "Enable object versioning on the flagged Cloud Storage bucket with a reviewed old-version lifecycle policy.",
    ["Inspect versioning.enabled on the named bucket and identify object overwrite/delete patterns and retention costs.",
     "Enable versioning in the bucket owner configuration, retaining a reviewed lifecycle policy for noncurrent versions.",
     "Read versioning.enabled again, test an authorized version recovery and rerun the check."],
    [cmd("Inspect bucket versioning", "gcloud storage buckets describe gs://<RESOURCE_NAME>"),
     cmd("Enable object versioning", "gcloud storage buckets update gs://<RESOURCE_NAME> --versioning")],
    ["The evaluator treats an omitted setting as false and does not prove earlier versions exist or can be restored. Old versions can increase storage cost; Google recommends soft delete for accidental or malicious deletion recovery."],
    [ref("Cloud Storage object versioning", "https://cloud.google.com/storage/docs/using-object-versioning")],
    "Set versioning.enabled = true on the owning bucket declaration and review the noncurrent-version lifecycle rule.")
RULES["gcp.reviewed.storage.versioning"]["field_binding"] = {
    "target": "resource", "kind": "bucket", "field": "versioning.enabled=true (omitted=false)",
    "evaluator_family": "gcp_extended.bucket_versioning"}

RULES["gcp.reviewed.storage.access_logging"] = rule(
    "Configure the flagged bucket's usage and storage logs to an approved existing log bucket.",
    ["Inspect logging.logBucket on the named source bucket and choose an existing log bucket with approved access, retention and cost controls.",
     "Grant the documented Cloud Storage analytics writer role on that log bucket through its owner, then set the source bucket's logging.logBucket to it.",
     "Reread logging.logBucket and independently verify that log objects arrive; rerun the native check."],
    [cmd("Inspect source bucket logging", "gcloud storage buckets describe gs://<RESOURCE_NAME>"),
     cmd("Set the reviewed existing log destination", "gcloud storage buckets update gs://<RESOURCE_NAME> --log-bucket=gs://<APPROVED_LOG_BUCKET>")],
    ["The evaluator checks only that logging.logBucket is nonempty; it does not prove the destination exists, accepts writes, retains logs or receives events. The log bucket requires writer access for cloud-storage-analytics@google.com and may incur storage charges."],
    [ref("Cloud Storage usage and storage logs", "https://cloud.google.com/storage/docs/access-logs")],
    "Set logging.log_bucket to the approved existing destination on the owning source bucket declaration and grant its analytics writer through the log bucket owner.")
RULES["gcp.reviewed.storage.access_logging"]["field_binding"] = {
    "target": "resource", "kind": "bucket", "field": "logging.logBucket nonempty (omitted=None)",
    "evaluator_family": "gcp_extended.bucket_logging"}

RULES["gcp.ports.dns_managed_zone_dnssec_enabled"] = rule(
    "Enable DNSSEC signing for the flagged public Cloud DNS managed zone and complete its registrar delegation.",
    ["Inspect visibility and dnssecConfig.state on the named managed zone; confirm it is public and identify its registrar and DNS operator.",
     "Have the zone owner enable DNSSEC and publish the matching DS record at the registrar using the documented deployment sequence.",
     "Verify DNSSEC validation through independent DNS queries and read dnssecConfig.state again; rerun this check."],
    [cmd("Inspect DNSSEC state", "gcloud dns managed-zones describe <RESOURCE_NAME> --project=<PROJECT_ID>")],
    ["The evaluator treats 'transfer' as a non-off declaration; it does not prove active signing or correct DS delegation. A mismatched DS record can make the zone fail validation."],
    [ref("Cloud DNS DNSSEC configuration", "https://cloud.google.com/dns/docs/dnssec-config")],
    "Set dnssec_config.state to on on the owning public google_dns_managed_zone and coordinate its DS delegation.")
RULES["gcp.ports.dns_managed_zone_dnssec_enabled"]["field_binding"] = {
    "target": "resource", "kind": "dns_managed_zone", "field": "visibility=public; dnssecConfig.state",
    "evaluator_family": "gcp_ports_metadata.dns"}

for check_id, key_type, key_label in (
    ("gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1", "keySigning", "key-signing"),
    ("gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1", "zoneSigning", "zone-signing"),
):
    RULES[check_id] = rule(
        f"Replace the flagged RSASHA1 {key_label} algorithm with a reviewed Cloud DNS supported algorithm.",
        [f"Inspect visibility, dnssecConfig.state and defaultKeySpecs for the {key_type} entry on the named public zone.",
         "Choose a supported non-RSASHA1 KSK/ZSK algorithm and key length pair with the DNS operator; plan the documented DNSSEC disable/change/re-enable and registrar DS sequence.",
         "Validate signed answers and the registrar DS chain after rollout, then reread defaultKeySpecs and rerun the check."],
        [cmd("Inspect the DNSSEC key specifications", "gcloud dns managed-zones describe <RESOURCE_NAME> --project=<PROJECT_ID>")],
        ["Changing an already enabled zone's algorithm requires temporarily disabling DNSSEC; an incorrect DS transition can disrupt validation. This predicate checks only the declared algorithm, not cryptographic validation."],
        [ref("Cloud DNS advanced DNSSEC algorithm changes", "https://cloud.google.com/dns/docs/dnssec-advanced")],
        f"Change dnssec_config.default_key_specs for the {key_type} key in the owning zone configuration, preserving a reviewed KSK/ZSK pair and registrar transition.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": "dns_managed_zone",
                                         "field": f"visibility=public; dnssecConfig.state; defaultKeySpecs[].keyType={key_type}/algorithm=rsasha1",
                                         "evaluator_family": "gcp_ports_metadata.dns"}

# These IAM predicates inspect resource-local allow-policy declarations. They
# do not prove effective public access (condition, deny and inherited policies
# may alter it); the action names the policy owner and the exact member field.
GCP_PUBLIC_BINDINGS = {
    "gcp.ports.storage_bucket_not_publicly_accessible": (
        "bucket", "bucket", "every public bucket IAM binding", "iamPolicy.bindings[].members=allUsers|allAuthenticatedUsers",
        "gcloud storage buckets get-iam-policy gs://<RESOURCE_NAME>",
        ref("Cloud Storage bucket IAM policy and public access", "https://cloud.google.com/storage/docs/access-control/making-data-public")),
    "gcp.ports.cloudfunction_function_restrict_public_access": (
        "function", "Cloud Run function", "every public function IAM binding", "iamPolicy.bindings[].members=allUsers|allAuthenticatedUsers",
        "gcloud functions get-iam-policy <RESOURCE_NAME> --region=<LOCATION> --project=<PROJECT_ID>",
        ref("Cloud Run functions IAM access", "https://cloud.google.com/functions/docs/securing/managing-access-iam")),
    "gcp.ports.function_active_public_binding": (
        "function", "active Cloud Run function", "every public function IAM binding", "state=ACTIVE; iamPolicy.bindings[].members=allUsers|allAuthenticatedUsers",
        "gcloud functions get-iam-policy <RESOURCE_NAME> --region=<LOCATION> --project=<PROJECT_ID>",
        ref("Cloud Run functions IAM access", "https://cloud.google.com/functions/docs/securing/managing-access-iam")),
    "gcp.ports.cloudrun_service_restrict_public_access": (
        "cloudrun_service", "Cloud Run service", "the public roles/run.invoker binding", "iamPolicy.bindings[].role=roles/run.invoker/members=allUsers|allAuthenticatedUsers",
        "gcloud run services get-iam-policy <RESOURCE_NAME> --region=<LOCATION> --project=<PROJECT_ID>",
        ref("Cloud Run service IAM access", "https://cloud.google.com/run/docs/securing/managing-access")),
}
GCP_PUBLIC_REMOVAL = {
    "gcp.ports.storage_bucket_not_publicly_accessible": (
        "gcloud storage buckets remove-iam-policy-binding gs://<RESOURCE_NAME> --member=<REVIEWED_PUBLIC_MEMBER> --role=<REVIEWED_ROLE>",
        "https://cloud.google.com/sdk/gcloud/reference/storage/buckets/remove-iam-policy-binding"),
    "gcp.ports.cloudfunction_function_restrict_public_access": (
        "gcloud functions remove-iam-policy-binding <RESOURCE_NAME> --region=<LOCATION> --project=<PROJECT_ID> --member=<REVIEWED_PUBLIC_MEMBER> --role=<REVIEWED_ROLE>",
        "https://cloud.google.com/sdk/gcloud/reference/functions/remove-iam-policy-binding"),
    "gcp.ports.function_active_public_binding": (
        "gcloud functions remove-iam-policy-binding <RESOURCE_NAME> --region=<LOCATION> --project=<PROJECT_ID> --member=<REVIEWED_PUBLIC_MEMBER> --role=<REVIEWED_ROLE>",
        "https://cloud.google.com/sdk/gcloud/reference/functions/remove-iam-policy-binding"),
    "gcp.ports.cloudrun_service_restrict_public_access": (
        "gcloud run services remove-iam-policy-binding <RESOURCE_NAME> --region=<LOCATION> --project=<PROJECT_ID> --member=<REVIEWED_PUBLIC_MEMBER> --role=roles/run.invoker",
        "https://cloud.google.com/sdk/gcloud/reference/run/services/remove-iam-policy-binding"),
}
for check_id, (kind, resource, offending, field, inspect, documentation) in GCP_PUBLIC_BINDINGS.items():
    removal, remove_doc = GCP_PUBLIC_REMOVAL[check_id]
    RULES[check_id] = rule(
        f"Remove or narrow {offending} on the flagged {resource} after migrating intended callers.",
        [f"Inspect {field} on the named {resource}; identify the exact public member, role, condition and configuration owner.",
         "Replace any intentional public use with a tested authenticated path before changing the reviewed resource-local binding.",
         f"Remove or narrow only that reviewed binding in the owning policy, test callers, recollect the {resource} IAM policy and rerun the check."],
        [cmd("Inspect the resource IAM policy", inspect),
         cmd("Remove only the reviewed unconditional public binding after caller migration", removal)],
        ["This evaluator reports a resource-local public principal declaration, not effective access; conditions, deny and inherited policy are separate. Removing a public binding can interrupt callers, and the finding does not establish a safe replacement principal.",
         "The sample removal command applies to a reviewed unconditional binding; conditional bindings require the exact condition in the provider operation and should be changed through their configuration owner."],
        [documentation, ref("Resource IAM binding removal command", remove_doc)],
        f"Edit the owning {resource} IAM policy declaration to remove the reviewed public member or replace it with approved authenticated principals.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": kind, "field": field,
                                         "evaluator_family": "gcp_ports_metadata.policy_public"}

RULES["gcp.ports.bigquery_dataset_not_publicly_accessible"] = rule(
    "Remove the flagged public BigQuery dataset ACL entry after migrating intended data consumers.",
    ["Inspect access[].specialGroup=allAuthenticatedUsers and access[].iamMember=allUsers on the exact dataset; locate the owning dataset declaration.",
     "Give legitimate consumers a reviewed identity-specific grant at the appropriate dataset or table scope, then remove the identified public ACL entry.",
     "Test authorized queries and views, reread the dataset ACL and rerun the check."],
    [cmd("Inspect dataset ACL", "bq show --format=prettyjson <PROJECT_ID>:<RESOURCE_NAME>")],
    ["The evaluator reads dataset-local ACL entries only; inherited IAM and authorized views are separate. A bq update with a partial access list can overwrite unrelated ACL entries, so use the full owner-managed declaration."],
    [ref("BigQuery dataset access controls", "https://cloud.google.com/bigquery/docs/control-access-to-resources-iam")],
    "Remove only the identified public entry from the owning dataset access list while preserving every other approved ACL entry.")
RULES["gcp.ports.bigquery_dataset_not_publicly_accessible"]["field_binding"] = {
    "target": "resource", "kind": "bigquery_dataset", "field": "access[].specialGroup=allAuthenticatedUsers or access[].iamMember=allUsers",
    "evaluator_family": "gcp_ports_metadata.dataset_public"}

GCP_SQL_ADDRESS = {
    "gcp.ports.sql_instance_with_no_public_ips": ("ipAddresses[].type=PRIMARY and backendType=SECOND_GEN", "the flagged second-generation public PRIMARY address"),
    "gcp.ports.sql_instance_not_publicly_accessible": ("ipAddresses[].type=PRIVATE without PRIMARY; settings.ipConfiguration.privateNetwork", "the missing private network or present public PRIMARY address"),
    "gcp.ports.sql_no_primary_address": ("ipAddresses[].type=PRIMARY", "the public PRIMARY address declaration"),
}
# sql_private_ip_assignments also fails an OUTGOING address; this source does
# not establish that such a platform egress address is removable, so it stays
# without an approved action rather than inheriting a public-IP fix.
for check_id, (field, concern) in GCP_SQL_ADDRESS.items():
    RULES[check_id] = rule(
        f"Migrate clients to a reviewed private Cloud SQL network path before removing {concern}.",
        [f"Inspect {field} on the named instance and identify every client, replica and Cloud SQL Auth Proxy dependency.",
         "Have the instance/network owner configure private services access and settings.ipConfiguration.privateNetwork where supported; test client connections over the intended private path.",
         "Only after migration, disable the public IP declaration through the complete managed instance configuration; verify connectivity and reread ipAddresses before rerunning this check."],
        [cmd("Inspect address and network configuration", "gcloud sql instances describe <RESOURCE_NAME> --project=<PROJECT_ID>")],
        ["Adding private IP to an existing instance can restart it and can be unavailable on an existing Shared VPC instance. Private IP cannot later be disabled. Removing public IP before migration can stop clients.",
         "These predicates read address declarations, not effective reachability; OUTGOING and PRIMARY/PRIVATE types have distinct source branches, so inspect the exact failed check before rollout."],
        [ref("Cloud SQL private IP configuration", "https://cloud.google.com/sql/docs/mysql/configure-private-ip")],
        "Coordinate settings.ipConfiguration.privateNetwork and ipv4Enabled=false in the owning Cloud SQL instance declaration after the approved private-network migration.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": "sql_instance", "field": field,
                                         "evaluator_family": "gcp_ports_metadata.sql_address"}

ANALYSIS = {
    "analysis.grant_review": ("Narrow the declared high-impact grant to tested workload actions and resources at its actual policy owner.",
        "Inspect the referenced grant, principal, scope, condition and use before approving a narrower replacement.", AWS_IAM),
    "analysis.inactive_identity": ("Review the identity's observed activity window and disable unused credentials through its owner after confirming dependencies.",
        "Check the observation window and independent sign-in or workload use; document any dependency before changing credentials.", GCP_IAM),
    "analysis.principal_exposure": ("Remove or constrain the flagged public or external principal declaration at the owning policy.",
        "Identify the declared principal, policy owner, inheritance and legitimate external access before changing the grant.", GCP_IAM),
    "analysis.network_review": ("Restrict the candidate broad network rule to the tested client sources and required ports.",
        "Identify the native rule, attachments, traffic need and effective network path before selecting a narrower source.", AWS_SG),
    "analysis.coverage": ("Collect the named missing or denied inventory before deciding whether any grant or exposure needs remediation.",
        "Inspect the coverage reason and restore authorized read access or correct the collection scope, then rerun analysis.", AWS_IAM),
    "analysis.internet_exposure": ("Remove the unnecessary public path or constrain its source and target after validating the application need.",
        "Inspect the referenced route, listener, ingress rule and target together; confirm the path with independent network evidence.", AWS_SG),
    "analysis.federated_trust": ("Pin the federated trust to approved issuer, audience and workload subject conditions.",
        "Inspect the trust document and actual workload identity claims; approve exact issuer, audience and subject restrictions.", AWS_IAM),
}
for check_id, (summary, inspect, reference) in ANALYSIS.items():
    RULES[check_id] = rule(summary,
        [inspect, "Change the owning policy or network declaration through its reviewed configuration route; test legitimate use.",
         "Rerun the analysis and verify effective access or reachability separately from this projection."], [],
        ["Analysis evidence is a projection and may be MANUAL or incomplete; it does not prove effective access or reachability.",
         "The source provider and exact configuration owner must be confirmed before choosing a mutation command."],
        [reference])
    RULES[check_id]["review_status"] = "provider_reference_pending"

RULES["analysis.network_review@aws"] = rule(
    "Narrow the candidate public security group ingress rule to its tested client sources and required port.",
    ["Inspect evidence.rules[].source.path and native_rule; identify the actual security group rule ID, attachments and traffic need.",
     "Authorize the reviewed narrower source for the required port, test clients, and remove the identified broad rule through its owner.",
     "Rerun network analysis and assess effective reachability separately; this candidate alone does not prove exposure."],
    [cmd("Inspect candidate security group rule IDs", "aws ec2 describe-security-group-rules --filters Name=group-id,Values=<RESOURCE_ID>"),
     cmd("Authorize an approved source before removal", "aws ec2 authorize-security-group-ingress --group-id <RESOURCE_ID> --protocol tcp --port <PORT> --cidr <APPROVED_CIDR>"),
     cmd("Revoke the verified broad rule after testing", "aws ec2 revoke-security-group-ingress --group-id <RESOURCE_ID> --security-group-rule-ids <RULE_ID>")],
    ["This MANUAL analysis candidate records declared rules and unknown reachability. Its raw native_rule is never interpolated into a command."],
    [AWS_SG], "Change the existing managed security group ingress rule source and review the plan before applying it.")

RULES["analysis.network_review@gcp"] = rule(
    "Narrow this candidate Google Cloud firewall rule's ingress source ranges to approved clients.",
    ["Inspect direction, allowed entries, sourceRanges, source tags/service accounts and target selectors on the named firewall rule.",
     "Set sourceRanges to a tested approved CIDR in the owning rule after confirming the target and required clients.",
     "Verify intended traffic and higher-priority firewall policies; rerun the analysis without treating the declaration as proven reachability."],
    [cmd("Inspect the candidate firewall rule", "gcloud compute firewall-rules describe <RESOURCE_NAME> --project=<PROJECT_ID>"),
     cmd("Narrow to a separately approved source", "gcloud compute firewall-rules update <RESOURCE_NAME> --project=<PROJECT_ID> --source-ranges=<APPROVED_CIDR>")],
    ["An omitted sourceRanges can mean world IPv4 ingress when no source tags/accounts constrain it. Target attachment, hierarchy, priority and routing remain unresolved; replacing ranges can interrupt clients."],
    [GCP_FIREWALL], "Update source_ranges and retain reviewed target and allow selectors on the existing google_compute_firewall declaration.")

RULES["analysis.network_review@azure"] = rule(
    "Narrow the candidate Azure NSG inbound Allow rule's public source prefix.",
    ["Inspect evidence.rules[].source.path and the NSG securityRules/defaultSecurityRules; verify the exact rule name, priority, source and attached subnet or NIC.",
     "Replace a verified custom Allow rule's public source prefix with approved clients; handle built-in default rules through an owner-reviewed higher-priority policy.",
     "Test intended clients and effective NSG rules, then rerun the analysis; routes and public addressing require separate assessment."],
    [cmd("Inspect NSG rules and priority", "az network nsg rule list --resource-group <RESOURCE_GROUP> --nsg-name <RESOURCE_NAME>"),
     cmd("Narrow a verified custom Allow rule", "az network nsg rule update --resource-group <RESOURCE_GROUP> --nsg-name <RESOURCE_NAME> --name <RULE_NAME> --source-address-prefixes <APPROVED_CIDR>")],
    ["The candidate can be a built-in defaultSecurityRule, which cannot be updated with the custom-rule command. Rule identity and approved CIDR are placeholders; NSG policy intersection and reachability are unknown."],
    [ref("Azure CLI NSG rule operations", "https://learn.microsoft.com/en-us/cli/azure/network/nsg/rule?view=azure-cli-latest")],
    "Update only the verified custom securityRules sourceAddressPrefixes in the owning NSG declaration, or add a reviewed higher-priority rule for built-in defaults.")

RULES["analysis.network_review@k8s"] = rule(
    "Restrict this NetworkPolicy's candidate ingress peer or port allowance to required traffic.",
    ["Inspect spec.ingress and evidence.rules[].source.path for an empty from selector, empty peer or world ipBlock; identify selected Pods and intended clients.",
     "Replace the candidate with tested namespace/pod selectors or a bounded ipBlock and necessary ports in the owning NetworkPolicy.",
     "Roll out through the policy owner, verify CNI enforcement and the additive policy union, then rerun the analysis."],
    [cmd("Inspect the candidate NetworkPolicy", "kubectl get networkpolicy <RESOURCE_NAME> -n <NAMESPACE> -o yaml")],
    ["An empty ingress list denies, while an empty ingress rule allows all at this policy layer. ipBlock exceptions, other policies, CNI enforcement and external routing remain unresolved."],
    [ref("Kubernetes NetworkPolicy behavior", "https://kubernetes.io/docs/concepts/services-networking/network-policies/")],
    "Replace the exact spec.ingress peer and port selectors in the owning NetworkPolicy manifest and test required traffic.")

# The federation evaluator handles only these three provider/resource pairs.
# Guidance deliberately leaves tenant, subject, audience and replacement policy
# values for the owner; it never copies token claims or raw trust evidence into CLI.
RULES["analysis.federated_trust@aws"] = rule(
    "Pin the flagged IAM role's web-identity trust to approved issuer claims and workload subjects.",
    ["Inspect each flagged AssumeRolePolicyDocument.Statement and identify its Federated principal, Action, Condition and attached role permissions.",
     "For a failing OIDC statement, approve positive issuer-qualified sub conditions that identify the intended workload; add the required aud condition for a multi-tenant issuer or Cognito identity pool.",
     "Update the owning role trust document with those reviewed values, test intended token exchange and confirm other identities cannot assume the role."],
    [cmd("Inspect the role trust policy", "aws iam get-role --role-name <RESOURCE_NAME>")],
    ["The evaluator checks declared trust conditions and does not model provider-side claim customization or session policies. Narrowing a trust statement can interrupt federated workloads; a PASS or MANUAL finding still needs owner review before any change."],
    [ref("AWS OIDC trust conditions", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html"),
     ref("AWS IAM get-role", "https://docs.aws.amazon.com/cli/latest/reference/iam/get-role.html")],
    "Change only the flagged AssumeRolePolicyDocument statements in the owning role declaration, preserving unrelated principals and testing intended federation.")

RULES["analysis.federated_trust@gcp"] = rule(
    "Constrain the flagged Workload Identity Federation provider to an approved external tenant and subject mapping.",
    ["Inspect the provider's oidc.issuerUri, attributeMapping and attributeCondition and identify every service-account binding that accepts this pool.",
     "For a failing or review finding with no condition, define a tested attributeCondition that restricts trusted tenant or organization claims and map a stable workload subject.",
     "Update the owning provider declaration, test intended token exchange and service-account impersonation, and reject a token from an unrelated tenant."],
    [cmd("Inspect the workload identity provider", "gcloud iam workload-identity-pools providers describe <PROVIDER_ID> --workload-identity-pool=<POOL_ID> --location=global --project=<PROJECT_ID>")],
    ["A present attributeCondition receives PASS without validation of its CEL logic; inspect it independently. Changing attribute mapping or conditions may remove legitimate access or broaden which identities match existing bindings."],
    [ref("Google Cloud federation best practices", "https://cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation"),
     ref("Google Cloud provider inspection", "https://cloud.google.com/sdk/gcloud/reference/iam/workload-identity-pools/providers/describe")],
    "Set the reviewed attributeCondition and stable attributeMapping on the existing WorkloadIdentityPoolProvider declaration; assess dependent IAM bindings first.")

RULES["analysis.federated_trust@azure"] = rule(
    "Restrict the flagged federated identity credential to its intended issuer, audience and exact workload subject.",
    ["Identify whether the source is a managed identity or application credential; inspect properties.issuer, subject, audiences and any claimsMatchingExpression.",
     "For a failing wildcard expression, replace the broad match with the approved exact subject or a narrowly scoped supported expression.",
     "Update the credential through its actual owner, test intended workload sign-in and confirm unrelated subjects are rejected."],
    [cmd("Inspect a managed-identity credential", "az identity federated-credential show --identity-name <MANAGED_IDENTITY_NAME> --name <CREDENTIAL_NAME> --resource-group <RESOURCE_GROUP>"),
     cmd("Inspect an application credential", "az ad app federated-credential show --id <APP_ID> --federated-credential-id <CREDENTIAL_NAME>")],
    ["Use only the inspection command matching the resource kind. A missing subject yields UNKNOWN; a nonwildcard expression can receive PASS without proving its external issuer or token behavior. Tightening claims can interrupt workload sign-in."],
    [ref("Microsoft Entra federated identity credentials", "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust"),
     ref("Azure managed identity credential CLI", "https://learn.microsoft.com/en-us/cli/azure/identity/federated-credential?view=azure-cli-latest"),
     ref("Azure application credential CLI", "https://learn.microsoft.com/en-us/cli/azure/ad/app/federated-credential?view=azure-cli-latest")],
    "Update only the flagged federated credential in its managed identity or application declaration after approving issuer, audience and subject.")

RULES["analysis.coverage@aws"] = rule(
    "Restore the specific missing or denied AWS inventory before judging the affected grant or exposure.",
    ["Read evidence.gaps and evidence.reason for the exact account, Region, resource kind and collection status; distinguish denied access, collection failure and malformed native facts.",
     "For a denied API, have the scan owner grant only the named read action at the required scope after checking boundaries, SCPs and explicit denies; for malformed facts, correct the collector input or mapping.",
     "Rerun only the authorized inventory and confirm that its collection status is complete before interpreting dependent findings."],
    [cmd("Confirm the scan principal", "aws sts get-caller-identity")],
    ["The finding does not identify a safe permission grant or a resource configuration fix. Identity confirmation alone does not resolve the missing inventory, and an empty complete collection differs from a denied one."],
    [ref("AWS access-denied troubleshooting", "https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html")])

RULES["analysis.coverage@gcp"] = rule(
    "Repair the exact Google Cloud inventory gap, then reevaluate the related risk finding.",
    ["Read evidence.gaps or evidence.reason for the project, collection kind and status; separate permission denial from unavailable or malformed data.",
     "For a denied read, have the project owner diagnose the principal, resource and required permission, then approve the narrowest collector access; correct malformed source facts at their collector.",
     "Repeat the authorized collection and verify a complete or explicitly empty status before drawing access or exposure conclusions."],
    [cmd("Identify the active gcloud account", "gcloud auth list --filter=status:ACTIVE")],
    ["This is an UNKNOWN analysis result, not evidence that a grant or public path is safe. The finding cannot infer a role to add or a target policy to mutate."],
    [ref("Google Cloud IAM access troubleshooting", "https://cloud.google.com/policy-intelligence/docs/troubleshoot-access")])

RULES["analysis.coverage@azure"] = rule(
    "Resolve the named Azure inventory or role-definition gap before changing an assignment.",
    ["Inspect evidence.gaps, evidence.reason and any roleDefinitionId source for the exact subscription, resource type and failed collection status.",
     "Have the tenant or subscription owner diagnose the denied read at its actual scope, or repair malformed assignment/definition facts; retain the least privilege needed by the collector.",
     "Recollect the missing assignment and matching definition, then rerun the analysis and confirm the UNKNOWN reason has cleared."],
    [cmd("Identify the current Azure account and subscription", "az account show")],
    ["A role definition absent from the collected snapshot cannot be treated as a harmless grant. This finding does not justify creating or removing a role assignment."],
    [ref("Azure RBAC access troubleshooting", "https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting")])

RULES["analysis.coverage@k8s"] = rule(
    "Complete the named Kubernetes resource inventory before evaluating its RBAC or network declaration.",
    ["Read evidence.gaps or evidence.reason for the namespace, resource kind and collection status; separate forbidden list/watch from an empty complete result or malformed object.",
     "Check the scanner ServiceAccount's authorization for that exact resource and namespace; have the RBAC owner add only the approved list/get/watch verbs if collection was denied.",
     "Recollect that resource kind, verify completion and rerun analysis before treating missing relationships as safe."],
    [cmd("Inspect authorization for the missing resource kind", "kubectl auth can-i list <RESOURCE_KIND> -n <NAMESPACE> --as=system:serviceaccount:<SCAN_NAMESPACE>:<SCAN_SERVICE_ACCOUNT>")],
    ["The placeholder kind, namespace and ServiceAccount must come from the authorized scan configuration, not arbitrary evidence interpolation. The --as check requires permission to impersonate the scanner identity; a forbidden or malformed collection cannot prove absence."],
    [ref("Kubernetes authorization", "https://kubernetes.io/docs/reference/access-authn-authz/authorization/"),
     ref("kubectl auth can-i", "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/")])

RULES["analysis.grant_review@aws"] = rule(
    "Narrow the flagged high-impact AWS Allow action at the policy document that actually grants it.",
    ["Use evidence.grants[].path and native_grant to locate the exact Allow statement and attached principals; inspect conditions, permission boundaries and usage for that principal.",
     "Remove an unused action or replace a wildcard with the tested minimum actions and resource ARNs; add a supported condition only where it still allows required workload calls.",
     "Publish the reviewed policy through its owner, test affected principals and compare the flagged statement after re-collection."], [],
    ["The projection classifies individual declared grants and does not prove effective access or a privilege-escalation chain. A single IAM CLI command cannot inspect or edit every resource policy, identity policy and role type covered by this check; no replacement document is inferred."],
    [ref("AWS IAM policy management", "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html")])

RULES["analysis.grant_review@gcp"] = rule(
    "Reduce the flagged Google Cloud role binding or permission to its approved principal, scope and workload need.",
    ["Locate each evidence.grants[].path in the actual IAM policy or role definition; inspect the member, role, condition and inherited parent scope.",
     "Replace an unnecessary basic or broad role with a reviewed smaller role at the narrowest appropriate resource, preserving a required IAM condition.",
     "Test the workload with the replacement binding and verify the source policy and inherited grants after re-collection."], [],
    ["The evaluator sees declared grants and cannot prove effective access through deny policies or Principal Access Boundaries. It may cover project, folder, organization or resource policies; a project-only mutation command would be unsafe without the actual policy owner."],
    [ref("Google Cloud IAM role changes", "https://cloud.google.com/iam/docs/granting-changing-revoking-access")])

RULES["analysis.grant_review@azure"] = rule(
    "Reduce the specific Azure role assignment's high-impact actions at its actual scope.",
    ["Use evidence.assignment.roleDefinitionId and scope to resolve the role definition and flagged evidence.grants[].path; inspect assignment condition, deny assignments and PIM state.",
     "If the workload does not need the grant, replace that assignment with a tested narrower role or scope; for a custom role, edit only the reviewed actions and dataActions.",
     "Validate intended operations and re-collect the assignment and matching definition before closing the finding."], [],
    ["A role definition can be shared by many assignments, so changing it can affect other principals. The projection does not model deny assignments, conditions or active PIM elevation; no blanket assignment removal is recommended."],
    [ref("Azure role assignments", "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments")])

RULES["analysis.grant_review@k8s"] = rule(
    "Limit the flagged Kubernetes Role or ClusterRole rule to approved verbs and resources.",
    ["Trace evidence.grants[].path to rules[].verbs/resources/apiGroups and inspect each RoleBinding or ClusterRoleBinding subject that receives the rule.",
     "Remove unneeded wildcard verbs or resources, or create a tested narrower Role and binding for the workload's namespace; retain only approved resourceNames restrictions where supported.",
     "Test intended API requests for each bound ServiceAccount and rerun the RBAC projection after the owner applies the manifest."], [],
    ["A ClusterRole may be shared across namespaces and aggregated into another role; editing it can interrupt many controllers. This is declared RBAC only, not a proof of actual API access or escalation."],
    [ref("Kubernetes RBAC good practices", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")])

RULES["analysis.principal_exposure@aws"] = rule(
    "Replace the flagged public or external AWS Principal declaration with approved principals and source conditions.",
    ["Locate evidence.principals[].source.path in its actual Allow statement; inspect Principal, Action, Resource, Condition and any known external account or service principal.",
     "If public or unwanted, narrow Principal to approved account, role or service identities and add a supported source or organization condition where applicable; remove an unnecessary external grant.",
     "Test intended callers and independently assess SCPs, explicit denies and Block Public Access before rerunning the projection."], [],
    ["A declared Principal is not effective-access proof; the source may be a resource policy, role trust or service policy with different update APIs. An external account ID in evidence is not automatically unauthorized."],
    [ref("AWS resource-based policies", "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html")])

RULES["analysis.principal_exposure@gcp"] = rule(
    "Limit the flagged Google Cloud IAM binding member to approved identities at the right scope.",
    ["Find evidence.principals[].source.path in bindings[].members and inspect the binding role, condition, parent scope and any public allUsers/allAuthenticatedUsers member.",
     "Replace an unwanted public member with approved identities, or move an external principal to a narrower conditional binding where its business need is established.",
     "Validate intended access and inherited policy behavior, then rerun the declaration review."], [],
    ["A condition can make a public binding conditional and the evaluator marks it for manual review; its logic needs separate validation. The source may be a project, folder, organization or resource policy, so no single mutation command is safe."],
    [ref("Google Cloud IAM public access", "https://cloud.google.com/iam/docs/principals-overview"), GCP_IAM])

RULES["analysis.principal_exposure@azure"] = rule(
    "Review and narrow the flagged Azure external principal assignment at its actual scope.",
    ["Trace evidence.principals[].source.path to properties.principalId or the collected policy member and resolve its tenant and role assignment scope.",
     "If the principal is not approved, replace the assignment with the intended principal or a narrower scope; review assignment conditions and cross-tenant access before removing any existing access.",
     "Confirm affected users and workloads can still operate, then recollect assignment and tenant context."], [],
    ["An Azure object ID does not establish its tenant; UNKNOWN externality must be resolved before a change. The finding does not include a safe replacement principal or prove effective access."],
    [ref("Azure role assignments", "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments")])

RULES["analysis.principal_exposure@k8s"] = rule(
    "Restrict the flagged Kubernetes RoleBinding subject to approved namespace identities.",
    ["Locate evidence.principals[].source.path in subjects[] and inspect the referenced Role or ClusterRole, namespace and any system:unauthenticated or external subject.",
     "Replace an unintended broad Group or cross-namespace ServiceAccount subject with the approved workload ServiceAccount; use a namespaced RoleBinding where cluster scope is unnecessary.",
     "Test intended API access for bound subjects and rerun the RBAC projection after the owner updates the manifest."], [],
    ["The finding classifies a declared subject and does not prove a usable API path. Changing a shared ClusterRoleBinding can break controllers across namespaces; verify all consumers first."],
    [ref("Kubernetes RBAC good practices", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")])

RULES["analysis.inactive_identity@aws"] = rule(
    "Validate the AWS identity's apparent inactivity before reducing its credentials or grants.",
    ["Read evidence.usage.window, completeness and observations; compare the named IAM identity with last-accessed reports, role sessions and application ownership.",
     "If the owner confirms no dependency, stage a reversible credential deactivation or narrower policy for the exact user or role; retain an approved recovery route.",
     "Observe the agreed business cycle for failures, then remove only confirmed unused access through the identity owner."], [],
    ["The evaluator sets safe_to_remove=false: zero observed activity can omit data events, federation, Regions or earlier periods. IAM users, roles, groups and policies need different changes, so no universal disable command is given."],
    [ref("AWS IAM last-accessed limitations", "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html")])

RULES["analysis.inactive_identity@gcp"] = rule(
    "Confirm the Google Cloud identity's use and then retire only its verified unused access path.",
    ["Inspect evidence.usage.window, completeness and observations for the named service account or IAM principal; trace workload bindings, key use and impersonation separately.",
     "For an owner-confirmed unused service-account key, disable that exact key with a rollback window; for an unused binding, narrow or remove only the verified member-role pair at its actual policy scope.",
     "Monitor dependent workloads and re-collect activity over the approved window before permanently removing access."], [],
    ["No observed activity does not prove a service account, role or policy is unused; token exchange and telemetry gaps can hide use. The evidence does not identify a safe key ID or policy owner for an automatic command."],
    [ref("Google Cloud service-account key disable and restore", "https://cloud.google.com/iam/docs/keys-disable-enable"), GCP_IAM])

RULES["analysis.inactive_identity@azure"] = rule(
    "Verify the Azure or Entra identity's activity coverage before disabling any account or assignment.",
    ["Review evidence.usage.window, completeness and observations against Entra sign-in activity, service-principal use, PIM and the identity's assigned roles.",
     "After the owner confirms a specific unused user or service principal, stage a reversible account or credential disable; narrow a role assignment only at its verified scope.",
     "Watch intended sign-ins and workloads through the agreed window, then finalize removal if no dependency remains."], [],
    ["A zero-count Usage declaration is not proof of inactivity, especially for service principals and workloads absent from user sign-in reports. No object ID, tenant or safe disable target is inferred."],
    [ref("Microsoft Entra inactive-account review", "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts"),
     ref("Azure role assignments", "https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments")])

RULES["analysis.inactive_identity@k8s"] = rule(
    "Confirm the Kubernetes ServiceAccount or RBAC subject has no workload use before reducing its access.",
    ["Read evidence.usage.window and completeness, then inspect namespace workloads, Pod serviceAccountName declarations and RoleBinding subjects for the named identity.",
     "If the owner confirms no API use, remove an unused binding or disable token automount in its actual workload template; preserve a tested controller rollout and rollback.",
     "Verify workloads and API authorization after the change and repeat the observed window before any permanent identity removal."], [],
    ["A Usage activity_count of zero is only supplied observation, not a Kubernetes API audit guarantee. Removing a ServiceAccount or shared ClusterRoleBinding can break controllers; no deletion command is generated."],
    [ref("Kubernetes ServiceAccounts", "https://kubernetes.io/docs/concepts/security/service-accounts/"),
     ref("Kubernetes ServiceAccount token automount", "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/")])

RULES["analysis.internet_exposure@aws"] = rule(
    "Constrain the modeled AWS public network path or external share at its actual granting declaration.",
    ["Read evidence.exposure_kind, exposed_ports, path[].layer and unresolved for the named asset; identify the network listener/rule owner, bucket policy owner or RDS snapshot restore-attribute owner.",
     "For a failing network path, narrow only the unnecessary listener or ingress source/port; for an external snapshot share, restrict restore attributes to approved accounts; for a public bucket, narrow its policy or ACL after migrating intended readers.",
     "Re-collect each changed layer and independently verify intended access; resolve collector_facts_needed before acting on an UNKNOWN path."], [],
    ["This is a declared-configuration path model from public origins; no packets were sent and unresolved layers may change the verdict. A bucket external share and a VPC listener need different owners, so no universal mutation command or deletion is supplied."],
    [AWS_SG, ref("AWS internet gateway routing", "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html"),
     ref("Amazon S3 Block Public Access", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"),
     ref("Amazon RDS snapshot sharing", "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html")])

RULES["analysis.internet_exposure@gcp"] = rule(
    "Narrow the flagged Google Cloud public endpoint or storage share at its granting control.",
    ["Trace evidence.exposure_kind, public_addresses, exposed_ports and path[].layer to the forwarding rule/firewall target, serverless invoker setting, SQL authorized network or bucket IAM policy.",
     "For a failing path, move the service to an approved private access design or restrict the exact ingress selector, invoker member, authorized network or bucket public member after testing intended clients.",
     "Validate required traffic and hierarchy precedence, then rerun collection; complete missing collector_facts_needed for UNKNOWN findings."], [],
    ["The model does not send traffic and cannot prove that DNS, application auth or higher-priority policy permits a connection. Disabling a forwarding rule or external IP without client migration can interrupt service; no automatic deletion is proposed."],
    [GCP_FIREWALL, ref("Google Cloud external load balancers", "https://cloud.google.com/load-balancing/docs/load-balancing-overview"),
     ref("Google Cloud Storage public access", "https://cloud.google.com/storage/docs/access-control/making-data-public")])

RULES["analysis.internet_exposure@azure"] = rule(
    "Reduce the Azure asset's modeled public path at its actual listener, network rule or service access setting.",
    ["Trace evidence.exposure_kind, public_addresses, exposed_ports, path[].layer and unresolved to the public IP/listener, subnet and NIC NSGs, storage networkAcls, SQL firewall rule or App Service access restriction.",
     "For a failing path, migrate unnecessary public access to a tested private route or narrow the verified custom Allow rule, service allow-list or listener to approved clients.",
     "Test legitimate access, inspect effective policy intersection and recollect the path; resolve missing layer facts for UNKNOWN findings."], [],
    ["The projection models declared layers and sends no traffic. Azure default NSG rules cannot be edited directly, and a public IP or listener may serve multiple clients; no blanket removal is safe."],
    [ref("Azure NSG effective rules", "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"),
     ref("Azure public IP addresses", "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"),
     ref("Azure Storage network security", "https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security")])

RULES["analysis.internet_exposure@k8s"] = rule(
    "Restrict the flagged Kubernetes Service or Ingress public entry point to intended clients and backend ports.",
    ["Read evidence.exposure_kind, public_addresses, exposed_ports and path[].layer; identify the exact Service, Ingress, controller, NetworkPolicy and external load-balancer owner.",
     "For a failing path, change an unneeded public Service to a reviewed internal access design or narrow the controller's source policy and Pod ingress peers after testing required clients.",
     "Verify CNI enforcement and cloud load-balancer settings, then rerun the projection; resolve unresolved layers before acting on UNKNOWN findings."], [],
    ["NetworkPolicies are additive and require CNI enforcement; an Ingress annotation alone may not constrain the external load balancer. The model sends no traffic and does not prove reachable application content."],
    [ref("Kubernetes Services", "https://kubernetes.io/docs/concepts/services-networking/service/"),
     ref("Kubernetes NetworkPolicies", "https://kubernetes.io/docs/concepts/services-networking/network-policies/")])

# Hand-reviewed core Kubernetes checks from peaso.checks.k8s. These read the
# native Pod/Namespace fields directly; commands print only the relevant paths.
K8S_CORE = {
    "k8s.pod.non_root": ("spec.securityContext.runAsNonRoot/runAsUser and containers[].securityContext.runAsNonRoot/runAsUser",
        "Declare a tested non-root identity for every flagged Linux container, using the Pod default or container override.",
        "Set runAsNonRoot=true or a positive runAsUser on the owning Pod template; test image ownership and volume access before rollout.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.securityContext} {.spec.containers[*].securityContext} {.spec.initContainers[*].securityContext} {.spec.ephemeralContainers[*].securityContext}'", K8S_POD),
    "k8s.pod.drop_capabilities": ("spec.containers/initContainers/ephemeralContainers[].securityContext.capabilities.drop",
        "Require capabilities.drop to include ALL on each flagged Linux container.",
        "Add ALL to capabilities.drop in the owning Pod template and test required system calls before restoring only separately approved minimum capabilities.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext.capabilities} {.spec.initContainers[*].securityContext.capabilities} {.spec.ephemeralContainers[*].securityContext.capabilities}'", K8S_POD),
    "k8s.pod.restrict_added_capabilities": ("spec.containers/initContainers/ephemeralContainers[].securityContext.capabilities.add",
        "Remove added Linux capabilities other than the check's allowed NET_BIND_SERVICE exception.",
        "Remove every flagged add entry except an owner-approved NET_BIND_SERVICE requirement in the Pod template; test application network binding.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext.capabilities.add} {.spec.initContainers[*].securityContext.capabilities.add} {.spec.ephemeralContainers[*].securityContext.capabilities.add}'", K8S_POD),
    "k8s.pod.seccomp": ("spec.securityContext.seccompProfile and containers[].securityContext.seccompProfile",
        "Choose a restrictive RuntimeDefault or reviewed Localhost seccomp profile for each flagged Linux container.",
        "Set RuntimeDefault at Pod or container level, or a tested Localhost profile with its installed localhostProfile path; verify container overrides.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.securityContext.seccompProfile} {.spec.containers[*].securityContext.seccompProfile} {.spec.initContainers[*].securityContext.seccompProfile} {.spec.ephemeralContainers[*].securityContext.seccompProfile}'", ref("Kubernetes seccomp profiles", "https://kubernetes.io/docs/tutorials/security/seccomp/")),
    "k8s.pod.no_hostpath": ("spec.volumes[].hostPath",
        "Replace each flagged hostPath volume with owner-approved storage that does not mount a node filesystem path.",
        "Migrate the application's required files to a reviewed volume type, then remove the exact hostPath volume from the owning Pod template and test data access.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.volumes[*].hostPath}'", ref("Kubernetes volumes", "https://kubernetes.io/docs/concepts/storage/volumes/")),
    "k8s.pod.no_default_serviceaccount": ("spec.serviceAccountName",
        "Assign this Pod an explicitly reviewed ServiceAccount instead of the namespace default.",
        "Create or select the workload's approved ServiceAccount, review its bindings, and set spec.serviceAccountName in the owning Pod template.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.serviceAccountName}'", ref("Kubernetes ServiceAccounts", "https://kubernetes.io/docs/concepts/security/service-accounts/")),
    "k8s.pod.restrict_token_automount": ("spec.automountServiceAccountToken",
        "Disable automatic API token mounting for the flagged Pod after confirming it does not call the Kubernetes API.",
        "Set spec.automountServiceAccountToken=false in the owning Pod template after testing any in-cluster client or projected-token dependency.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.automountServiceAccountToken}'", ref("Kubernetes ServiceAccount token automount", "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/")),
    "k8s.pod.default_proc_mount": ("spec.containers/initContainers/ephemeralContainers[].securityContext.procMount",
        "Restore the default procMount mask for each flagged Linux container.",
        "Remove an Unmasked procMount override or set procMount=Default in the owning Pod template after testing applications that read /proc.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.containers[*].securityContext.procMount} {.spec.initContainers[*].securityContext.procMount} {.spec.ephemeralContainers[*].securityContext.procMount}'", ref("Kubernetes Pod Security Standards", "https://kubernetes.io/docs/concepts/security/pod-security-standards/")),
    "k8s.pod.restrict_selinux_identity": ("spec.securityContext.seLinuxOptions.user/role and containers[].securityContext.seLinuxOptions.user/role",
        "Remove custom SELinux user and role overrides from the flagged Pod or Linux containers.",
        "Unset only seLinuxOptions.user and seLinuxOptions.role in the Pod and flagged containers; retain separately approved SELinux type and level settings.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.securityContext.seLinuxOptions} {.spec.containers[*].securityContext.seLinuxOptions} {.spec.initContainers[*].securityContext.seLinuxOptions} {.spec.ephemeralContainers[*].securityContext.seLinuxOptions}'", ref("Kubernetes Pod Security Standards", "https://kubernetes.io/docs/concepts/security/pod-security-standards/")),
    "k8s.namespace.restricted_admission": ("metadata.labels['pod-security.kubernetes.io/enforce']",
        "Enforce the restricted Pod Security level on this namespace after reviewing existing workloads and exemptions.",
        "Set pod-security.kubernetes.io/enforce=restricted and a reviewed enforce-version label on the namespace declaration after testing workload admission.",
        "kubectl get namespace <RESOURCE_NAME> -o jsonpath='{.metadata.labels}'", ref("Kubernetes Pod Security Admission", "https://kubernetes.io/docs/concepts/security/pod-security-admission/")),
}
for check_id, (field, summary, action, inspect, reference) in K8S_CORE.items():
    kind = "namespace" if check_id.startswith("k8s.namespace.") else "pod"
    RULES[check_id] = rule(summary,
        [f"Inspect {field} on the named {kind} and identify its durable manifest or controller owner.",
         action, "Apply the reviewed owner change, test dependent workloads and rerun the native declaration check."],
        [cmd("Inspect only the evaluated declaration", inspect)],
        ["The evaluator reads declared configuration, not admission or runtime enforcement. Pod security, storage and identity changes can interrupt workloads; stage a tested rollback."],
        [reference], f"Change {field} in the owning {kind} manifest or Helm values, not only the live object.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": kind, "field": field,
                                         "evaluator_family": "peaso.checks.k8s_extended" if check_id in ("k8s.pod.default_proc_mount", "k8s.pod.restrict_selinux_identity") else "peaso.checks.k8s"}

K8S_REGISTRY = {
    "k8s.rbac.no_wildcards": ("clusterrole", "rules[].verbs/resources/apiGroups/nonResourceURLs",
        "Replace wildcard entries in this ClusterRole with tested API groups, resources and verbs.",
        "List each wildcard rule's bound subjects and observed operations, then specify only the required verbs and resource names in the owning ClusterRole manifest.",
        "kubectl get clusterrole <RESOURCE_NAME> -o yaml", "rbac"),
    "k8s.rbac.role_no_wildcards": ("role", "rules[].verbs/resources/apiGroups/nonResourceURLs",
        "Replace wildcard entries in this namespaced Role with the workload's required verbs and resources.",
        "Identify bound ServiceAccounts and their API requests, then narrow the exact wildcard rule in the owning Role manifest.",
        "kubectl get role <RESOURCE_NAME> -n <NAMESPACE> -o yaml", "rbac"),
    "k8s.rbac.review_broad_subjects": ("clusterrolebinding", "subjects[].kind/name and roleRef",
        "Replace this ClusterRoleBinding's broad authenticated Group with approved identities.",
        "Trace the referenced ClusterRole and consumers, then replace the flagged system:authenticated, system:unauthenticated or system:serviceaccounts subject with tested named subjects.",
        "kubectl get clusterrolebinding <RESOURCE_NAME> -o yaml", "rbac"),
    "k8s.rbac.review_namespaced_subjects": ("rolebinding", "subjects[].kind/name and roleRef",
        "Replace this RoleBinding's broad Group subject with intended namespace users or ServiceAccounts.",
        "Trace the referenced Role and workload consumers, then replace the flagged broad Group with tested named subjects in the owning RoleBinding.",
        "kubectl get rolebinding <RESOURCE_NAME> -n <NAMESPACE> -o yaml", "rbac"),
    "k8s.pod.no_host_namespaces": ("pod", "spec.hostNetwork/hostPID/hostIPC",
        "Disable only the flagged hostNetwork, hostPID or hostIPC declaration in this Pod's owner template.",
        "Replace approved host namespace dependencies with a reviewed Service or node-agent design, then set the flagged host* fields to false.",
        "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.hostNetwork} {.spec.hostPID} {.spec.hostIPC}'", "standards"),
    "k8s.service.review_public_type": ("service", "spec.type/externalIPs/loadBalancerSourceRanges and metadata.annotations",
        "Review this Service's public type, externalIPs and source ranges against its required clients.",
        "For unneeded publication, migrate clients to an internal Service; otherwise restrict the actual LoadBalancer source ranges or external ingress control to approved sources.",
        "kubectl get service <RESOURCE_NAME> -n <NAMESPACE> -o yaml", "service"),
    "k8s.network.namespace_policy_inventory": ("namespace", "complete networkpolicy collection for namespace",
        "Define a tested ingress and egress NetworkPolicy baseline for this namespace after confirming complete inventory.",
        "When no policies are observed in a complete namespace inventory, add owner-reviewed default-deny policies and explicit allowed peers/ports for required traffic.",
        "kubectl get networkpolicy -n <RESOURCE_NAME> -o yaml", "networkpolicy"),
}
for check_id, (kind, field, summary, action, inspect, reference) in K8S_REGISTRY.items():
    RULES[check_id] = rule(summary,
        [f"Inspect {field} on the named {kind} and identify the actual manifest owner and dependent subjects or clients.",
         action, "Apply the reviewed manifest, test intended access and rerun the declaration check."],
        [cmd("Inspect the evaluated declaration", inspect)],
        ["This check reads declarations, not effective authorization or internet reachability. RBAC, namespace policy and Service publication changes can interrupt dependent workloads; test a rollback."],
        [ref("Kubernetes RBAC", "https://kubernetes.io/docs/reference/access-authn-authz/rbac/") if reference == "rbac" else
         ref("Kubernetes Pod Security Standards", "https://kubernetes.io/docs/concepts/security/pod-security-standards/") if reference == "standards" else
         ref("Kubernetes Services", "https://kubernetes.io/docs/concepts/services-networking/service/") if reference == "service" else
         ref("Kubernetes NetworkPolicies", "https://kubernetes.io/docs/concepts/services-networking/network-policies/")],
        f"Change {field} in the owning {kind} manifest after testing dependent workloads and access.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": kind, "field": field, "evaluator_family": "peaso.checks.__init__"}

K8S_HTBP_RBAC = {
    "no_impersonation": ("rules[].apiGroups=authentication.k8s.io|core, resources=users|serviceaccounts, verbs=impersonate",
        "Remove an unneeded impersonate grant on users or ServiceAccounts from this {label}.",
        "Remove the flagged impersonate verb or constrain it to separately approved named identities where the RBAC operation supports resourceNames."),
    "no_pod_interactive_access": ("rules[].resources=pods/exec|pods/attach|pods/portforward|pods/ephemeralcontainers; verbs=create|patch|update",
        "Restrict this {label}'s Pod exec, attach, port-forward or ephemeral-container grant.",
        "Remove the flagged interactive Pod subresource grant from ordinary workload subjects; provide a tested break-glass operator role only where required."),
    "no_workload_controller_write": ("rules[].resources=deployments|daemonsets|statefulsets|replicasets|jobs|cronjobs|replicationcontrollers; verbs=create|update|patch",
        "Limit this {label}'s workload-controller write grant to approved deployment operators.",
        "Remove unnecessary create/update/patch verbs on flagged controllers or move the required grant into a narrower namespaced deployment role."),
    "no_service_status_write": ("rules[].apiGroups=core, resources=services/status, verbs=update|patch",
        "Remove services/status write access from this {label} unless its subject is an approved service controller.",
        "Remove update/patch on services/status from noncontroller subjects, and preserve only the reviewed cloud/load-balancer controller's needed grant."),
}
for kind, label in (("role", "Role"), ("clusterrole", "ClusterRole")):
    for slug, (field, summary, action) in K8S_HTBP_RBAC.items():
        check_id = f"k8s.htbp.{kind}.{slug}"
        scope_arg = " -n <NAMESPACE>" if kind == "role" else ""
        RULES[check_id] = rule(summary.format(label=label),
            [f"Inspect the exact matching {field} rule and every binding that gives it to a subject.",
             action, "Apply the reviewed role manifest, test legitimate API operations and rerun the declared-grant check."],
            [cmd("Inspect the native RBAC rules", f"kubectl get {kind} <RESOURCE_NAME>{scope_arg} -o yaml")],
            ["The evaluator reports declared rules only; aggregation, bindings and admission can change effective access. Shared roles may serve controllers, and resourceNames does not make every create/list/watch grant safe; test each consumer before narrowing."],
            [ref("Kubernetes RBAC authorization", "https://kubernetes.io/docs/reference/access-authn-authz/rbac/")],
            f"Update only the flagged {field} entries in the owning {label} manifest after reviewing bound subjects.")
        RULES[check_id]["field_binding"] = {"target": "resource", "kind": kind, "field": field, "evaluator_family": "hacktricks_bp_k8s.matching_rules"}

RULES["k8s.htbp.service.no_external_ips"] = rule(
    "Remove this Service's spec.externalIPs after migrating approved clients to a controlled ingress path.",
    ["Inspect spec.externalIPs and identify the address owner, routed traffic and clients for the named Service.",
     "Move needed access to a reviewed LoadBalancer or ingress configuration, then remove only the unused externalIPs declaration from the owning Service manifest.",
     "Test clients and verify Service routing after rollout; rerun the declaration check."],
    [cmd("Inspect only the Service external IPs", "kubectl get service <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.spec.externalIPs}'")],
    ["Kube-proxy can capture traffic for an externalIP even when the address is not owned by the cluster. Removing an active address can interrupt clients; this finding does not prove external reachability."],
    [ref("Kubernetes Service externalIPs", "https://kubernetes.io/docs/concepts/services-networking/service/")],
    "Remove only spec.externalIPs in the owned Service manifest after client migration and review admission policy for future declarations.")
RULES["k8s.htbp.service.no_external_ips"]["field_binding"] = {"target": "resource", "kind": "service", "field": "spec.externalIPs", "evaluator_family": "hacktricks_bp_k8s.service_external_ips"}

RULES["k8s.htbp.secret.no_legacy_service_account_token"] = rule(
    "Replace the flagged long-lived ServiceAccount token Secret with reviewed short-lived projected credentials.",
    ["Inspect only the Secret type and ServiceAccount annotation; identify every workload or external client that uses this exact token without reading its value.",
     "Migrate those clients to bound projected tokens or TokenRequest credentials and test authentication and authorization.",
     "After the owner confirms the replacement, revoke the exact legacy token Secret through its managed declaration and verify dependent access."],
    [cmd("Inspect only Secret metadata", r"kubectl get secret <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.type} {.metadata.annotations.kubernetes\.io/service-account\.name}'")],
    ["Deleting the Secret invalidates a token still used by clients. The check reads metadata type only and does not expose, copy or rotate the token value; no deletion command is supplied."],
    [ref("Kubernetes ServiceAccount token administration", "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/")],
    "Migrate token consumers first, then remove the exact managed kubernetes.io/service-account-token Secret from its owner deployment.")
RULES["k8s.htbp.secret.no_legacy_service_account_token"]["field_binding"] = {"target": "resource", "kind": "secret_metadata", "field": "type=kubernetes.io/service-account-token; metadata.annotations['kubernetes.io/service-account.name']", "evaluator_family": "hacktricks_bp_k8s.legacy_sa_token"}

for kind, label in (("rolebinding", "RoleBinding"), ("clusterrolebinding", "ClusterRoleBinding")):
    check_id = f"k8s.htbp.{kind}.no_anonymous_user"
    scope_arg = " -n <NAMESPACE>" if kind == "rolebinding" else ""
    RULES[check_id] = rule(
        f"Remove an unapproved system:anonymous User subject from this {label}.",
        ["Inspect subjects[].kind/name and roleRef on the exact binding; identify any intended unauthenticated bootstrap or health dependency.",
         "Replace an unnecessary system:anonymous subject with the approved authenticated identity and narrow the referenced Role if needed.",
         "Apply the owner manifest, verify intended bootstrap and API access, and rerun the declared-binding check."],
        [cmd("Inspect binding subjects and roleRef", f"kubectl get {kind} <RESOURCE_NAME>{scope_arg} -o jsonpath='{{.subjects}} {{.roleRef}}'")],
        ["The evaluator excludes the kubeadm cluster-info discovery RoleBinding in kube-public; do not remove that exception without a separate bootstrap design. Removing a shared binding subject can break clients; no automatic mutation command is supplied."],
        [ref("Kubernetes RBAC good practices", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")],
        f"Replace only the flagged subjects[] entry in the owning {label} manifest after testing authenticated replacement access.")
    RULES[check_id]["field_binding"] = {"target": "resource", "kind": kind, "field": "subjects[].kind=User/name=system:anonymous; roleRef", "evaluator_family": "hacktricks_bp_k8s.anonymous_binding"}

# Every curated entry is tied to the native field or analysis source consumed by
# its evaluator. These bindings are documentation/validation metadata, not code
# paths that read evidence or construct a mutation command.
FIELD_BINDINGS = {
    "aws.gap.vpc.sg_world_any_common_ports": ("resource", "security_group", "IpPermissions[].IpRanges/Ipv6Ranges, FromPort/ToPort"),
    "aws.iam.no_full_admin": ("resource", "iam_policy", "PolicyDocument/PolicyVersionList[].Document Statement[].Action/Resource"),
    "aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation": ("resource", "iam_policy", "PolicyDocument/PolicyVersionList[].Document Statement[].Action/Resource"),
    "gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only": ("resource", "firewall", "direction, sourceRanges, allowed[].IPProtocol/ports"),
    "gcp.gap.iam_user_managed_sa_no_admin_roles": ("resource", "service_account", "admin_role_bindings"),
    "azure.claude2.application_insights_workspace_based": ("resource", "application_insights", "properties.WorkspaceResourceId"),
    "azure.vault.approved_private_endpoint": ("resource", "vault", "properties.networkAcls.defaultAction, privateEndpointConnections"),
    "azure.storage.no_blob_public_access": ("resource", "storage_account", "properties.allowBlobPublicAccess"),
    "k8s.pod.no_privileged_containers": ("resource", "pod", "spec.containers/initContainers/ephemeralContainers[].securityContext.privileged"),
    "k8s.ports.pod.container_argument_anonymous_auth_disabled": ("resource", "pod", "_component_config.flags.anonymous-auth"),
    "analysis.network_review@aws": ("projection", "security_group", "evidence.rules[].source.path -> IpPermissions[]"),
    "analysis.network_review@gcp": ("projection", "firewall", "evidence.rules[].source.path -> allowed/sourceRanges"),
    "analysis.network_review@azure": ("projection", "nsg", "evidence.rules[].source.path -> properties.securityRules[]"),
    "analysis.network_review@k8s": ("projection", "networkpolicy", "evidence.rules[].source.path -> spec.ingress[]"),
    "analysis.federated_trust@aws": ("projection", "iam_role", "AssumeRolePolicyDocument.Statement[].Principal.Federated/Condition"),
    "analysis.federated_trust@gcp": ("projection", "workload_identity_provider", "oidc.issuerUri/attributeMapping/attributeCondition"),
    "analysis.federated_trust@azure": ("projection", "managed_identity_federated_credential|directory_application_federated_credential", "properties.issuer/subject/audiences/claimsMatchingExpression"),
    "analysis.coverage@aws": ("projection", "inventory", "evidence.gaps[].type/status, reason, source.collection_status"),
    "analysis.coverage@gcp": ("projection", "inventory", "evidence.gaps[].type/status, reason, source.collection_status"),
    "analysis.coverage@azure": ("projection", "inventory|role_assignment", "evidence.gaps[].type/status, reason, source.path"),
    "analysis.coverage@k8s": ("projection", "inventory", "evidence.gaps[].type/status, reason, source.collection_status"),
    "analysis.grant_review@aws": ("projection", "iam_policy|iam_role|iam_user|resource_policy", "evidence.grants[].path/native_grant -> PolicyDocument.Statement[]"),
    "analysis.grant_review@gcp": ("projection", "iam_policy|iam_role|iam_binding", "evidence.grants[].path/native_grant -> bindings[]/includedPermissions"),
    "analysis.grant_review@azure": ("projection", "role_assignment", "evidence.assignment.roleDefinitionId/scope, grants[].path -> properties.permissions[]"),
    "analysis.grant_review@k8s": ("projection", "role|clusterrole", "evidence.grants[].path/native_grant -> rules[].verbs/resources/apiGroups"),
    "analysis.principal_exposure@aws": ("projection", "iam_role|resource_policy", "evidence.principals[].source.path -> Statement[].Principal/Condition"),
    "analysis.principal_exposure@gcp": ("projection", "iam_policy", "evidence.principals[].source.path -> bindings[].members/condition"),
    "analysis.principal_exposure@azure": ("projection", "role_assignment|policy", "evidence.principals[].source.path -> properties.principalId"),
    "analysis.principal_exposure@k8s": ("projection", "rolebinding|clusterrolebinding", "evidence.principals[].source.path -> subjects[]"),
    "analysis.inactive_identity@aws": ("projection", "iam_identity", "evidence.usage.window/completeness/observations/inactive_observation"),
    "analysis.inactive_identity@gcp": ("projection", "iam_identity", "evidence.usage.window/completeness/observations/inactive_observation"),
    "analysis.inactive_identity@azure": ("projection", "iam_identity", "evidence.usage.window/completeness/observations/inactive_observation"),
    "analysis.inactive_identity@k8s": ("projection", "serviceaccount|rbac_subject", "evidence.usage.window/completeness/observations/inactive_observation"),
    "analysis.internet_exposure@aws": ("projection", "internet_path", "evidence.exposure_kind/exposed_ports/path[].layer/unresolved/collector_facts_needed"),
    "analysis.internet_exposure@gcp": ("projection", "internet_path", "evidence.public_addresses/exposed_ports/path[].layer/unresolved"),
    "analysis.internet_exposure@azure": ("projection", "internet_path", "evidence.public_addresses/exposed_ports/path[].layer/unresolved"),
    "analysis.internet_exposure@k8s": ("projection", "internet_path", "evidence.exposure_kind/exposed_ports/path[].layer/unresolved"),
}
for check_id, (target, kind, field) in FIELD_BINDINGS.items():
    RULES[check_id]["field_binding"] = {"target": target, "kind": kind, "field": field}


if __name__ == "__main__":
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=OUT.parent,
                                     prefix=".remediation_curated-", suffix=".tmp",
                                     delete=False) as published:
        published.write(json.dumps(RULES, indent=2, sort_keys=True) + "\n")
        staged = Path(published.name)
    staged.replace(OUT)
    print(f"Wrote {len(RULES)} reviewed entries to {OUT}")
