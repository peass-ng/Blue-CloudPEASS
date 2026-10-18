#!/usr/bin/env python3
"""Generate reviewed-field remediation drafts for registered native checks.

The output is a proposal ledger. Only entries with review_status=approved are
eligible for product rendering; the other entries remain visible for human review.
No check evaluator, selector, or source catalog is changed here.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from peaso.checks import CHECKS
from peaso.checks import k8s_ports_components as components
from peaso.checks.facts import FIELD_SPECS
from peaso.checks import claude_aws_a_network as aws_network
from peaso.checks import claude_gcp_k8s_compute as gcp_network
from peaso.checks import claude_azure_network as azure_network
from peaso.checks import k8s_ports_workloads as workloads
from peaso.checks import k8s_ports_cluster as cluster
from peaso.checks import k8s_extended

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "peaso/rulepacks/remediation_details.json"

COMPONENT_REFS = {
    "kubelet": "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/",
    "kube-apiserver": "https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/",
    "kube-scheduler": "https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/",
    "kube-controller-manager": "https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/",
    "etcd": "https://etcd.io/docs/v3.5/op-guide/configuration/",
}
NETWORK_REFS = {
    "aws": {"title": "AWS security group rules", "url": "https://docs.aws.amazon.com/vpc/latest/userguide/working-with-security-group-rules.html"},
    "gcp": {"title": "Google Cloud firewall rule updates", "url": "https://cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/update"},
    "azure": {"title": "Azure CLI NSG rule updates", "url": "https://learn.microsoft.com/en-us/cli/azure/network/nsg/rule?view=azure-cli-latest"},
}
K8S_REFS = {
    "security": {"title": "Kubernetes container security context", "url": "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"},
    "standards": {"title": "Kubernetes Pod Security Standards", "url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
    "seccomp": {"title": "Kubernetes seccomp profiles", "url": "https://kubernetes.io/docs/tutorials/security/seccomp/"},
    "service_account": {"title": "Kubernetes ServiceAccounts", "url": "https://kubernetes.io/docs/concepts/security/service-accounts/"},
    "resources": {"title": "Kubernetes container resource requests and limits", "url": "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"},
    "probes": {"title": "Kubernetes liveness and readiness probes", "url": "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/"},
    "images": {"title": "Kubernetes image names and pull policy", "url": "https://kubernetes.io/docs/concepts/containers/images/"},
    "rbac": {"title": "Kubernetes RBAC authorization", "url": "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"},
    "quota": {"title": "Kubernetes ResourceQuota", "url": "https://kubernetes.io/docs/concepts/policy/resource-quotas/"},
    "limits": {"title": "Kubernetes LimitRange", "url": "https://kubernetes.io/docs/concepts/policy/limit-range/"},
    "networkpolicy": {"title": "Kubernetes NetworkPolicy", "url": "https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
    "service": {"title": "Kubernetes Service types", "url": "https://kubernetes.io/docs/concepts/services-networking/service/"},
    "secrets": {"title": "Kubernetes Secrets in Pods", "url": "https://kubernetes.io/docs/concepts/configuration/secret/"},
}

# Explicit branches in k8s_ports_workloads.evaluate_predicate, reviewed against
# the exact PodSpec path for each kind. Quantity values, probe targets and image
# digests are owner-supplied rather than copied from synthetic fixtures.
WORKLOAD_GUIDANCE = {
    "privileged": ("containers[*].securityContext.privileged=false", "Set privileged=false on each flagged regular, init or ephemeral container.", "security"),
    "privilege_escalation": ("containers[*].securityContext.allowPrivilegeEscalation=false", "Set allowPrivilegeEscalation=false after removing incompatible privileged or SYS_ADMIN requirements.", "security"),
    "readonly_root": ("containers[*].securityContext.readOnlyRootFilesystem=true", "Set readOnlyRootFilesystem=true and move required writes to reviewed writable volumes.", "security"),
    "declared_nonroot": ("containers[*].securityContext.runAsNonRoot=true", "Set runAsNonRoot=true in each flagged container context and verify its image user and file permissions.", "security"),
    "context_present": ("containers[*].securityContext", "Declare an explicit securityContext with the workload's reviewed controls for each flagged container.", "security"),
    "no_added_capabilities": ("containers[*].securityContext.capabilities.add=[]", "Remove unneeded entries from capabilities.add; retain only a separately approved minimum when this check is excepted.", "security"),
    "drop_all": ("containers[*].securityContext.capabilities.drop includes ALL", "Add ALL to capabilities.drop and test the container's required operations.", "standards"),
    "drop_net_raw": ("containers[*].securityContext.capabilities.drop includes NET_RAW or ALL", "Add NET_RAW or ALL to capabilities.drop and test network behavior.", "standards"),
    "no_sys_admin": ("containers[*].securityContext.capabilities.add excludes SYS_ADMIN", "Remove CAP_SYS_ADMIN or SYS_ADMIN from capabilities.add and replace its use with a reviewed design.", "security"),
    "host_namespaces": ("hostPID=false and hostIPC=false", "Set hostPID=false and hostIPC=false in the owning PodSpec after reviewing host-namespace dependencies.", "standards"),
    "host_network": ("hostNetwork=false", "Set hostNetwork=false in the owning PodSpec and update service/discovery paths required by the workload.", "standards"),
    "pod_runtime_default_seccomp": ("securityContext.seccompProfile.type=RuntimeDefault", "Declare Pod-level seccompProfile.type=RuntimeDefault and separately inspect container overrides.", "seccomp"),
    "container_runtime_default_seccomp": ("containers[*].securityContext.seccompProfile.type=RuntimeDefault", "Declare seccompProfile.type=RuntimeDefault on each flagged container.", "seccomp"),
    "explicit_serviceaccount": ("serviceAccountName=<APPROVED_SERVICE_ACCOUNT>", "Set an explicitly approved namespace ServiceAccount name in the owning PodSpec after reviewing its RBAC grants.", "service_account"),
    "cpu_limit": ("containers[*].resources.limits.cpu=<REVIEWED_CPU_LIMIT>", "Set a valid CPU limit for each flagged container based on observed demand and rollout policy.", "resources"),
    "cpu_request": ("containers[*].resources.requests.cpu=<REVIEWED_CPU_REQUEST>", "Set a valid CPU request for each flagged container based on observed demand and scheduling capacity.", "resources"),
    "memory_limit": ("containers[*].resources.limits.memory=<REVIEWED_MEMORY_LIMIT>", "Set a valid memory limit for each flagged container after testing peak memory use and termination behavior.", "resources"),
    "memory_request": ("containers[*].resources.requests.memory=<REVIEWED_MEMORY_REQUEST>", "Set a valid memory request for each flagged container using observed demand and scheduler capacity.", "resources"),
    "readiness_probe": ("containers[*].readinessProbe=<REVIEWED_PROBE>", "Add a readinessProbe that checks the application's actual ability to accept traffic, with reviewed startup timing.", "probes"),
    "liveness_probe": ("containers[*].livenessProbe=<REVIEWED_PROBE>", "Add a livenessProbe that detects a recoverable deadlock without restarting a healthy but slow-starting process.", "probes"),
    "no_host_ports": ("containers[*].ports[*].hostPort absent", "Remove each explicit hostPort declaration and route required access through a reviewed Service or ingress path.", "standards"),
    "pinned_image": ("containers[*].image uses a non-latest tag or digest", "Replace an untagged or latest image reference with a reviewed version tag or immutable digest.", "images"),
    "always_pull": ("containers[*].imagePullPolicy=Always or immutable SHA256 digest", "Set imagePullPolicy=Always for mutable image references, or use an immutable SHA256 digest with an allowed pull policy.", "images"),
    "content_digest_or_always_pull": ("containers[*].image uses SHA256 digest or imagePullPolicy=Always", "Pin the image by a valid SHA256 digest, or set imagePullPolicy=Always when the tag must remain mutable.", "images"),
}

# Direct FIELD_SPECS path/value pairs with independently checked provider
# inspect and update operations. Other scalar specs remain drafts.
SCALAR_APPROVALS = {
    "aws.cloudtrail.logging": (
        "aws cloudtrail get-trail-status --name <RESOURCE_ARN> --region <REGION>",
        "aws cloudtrail start-logging --name <RESOURCE_ARN> --region <REGION>",
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-additional-cli-commands.html",
        "Confirm the trail's S3 delivery destination and permissions first; starting logging does not prove delivery or event-selector completeness.",
        "Set enable_logging = true on the owning CloudTrail declaration and verify delivered log objects."),
    "aws.rds.deletion_protection": (
        "aws rds describe-db-instances --db-instance-identifier <RESOURCE_NAME> --region <REGION>",
        "aws rds modify-db-instance --db-instance-identifier <RESOURCE_NAME> --deletion-protection --region <REGION>",
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ModifyInstance.Settings.html",
        "Deletion protection prevents accidental deletion but is not a backup; confirm the instance identifier and maintenance plan.",
        "Set deletion_protection = true on the owning aws_db_instance declaration."),
    "aws.rds.cluster_deletion_protection": (
        "aws rds describe-db-clusters --db-cluster-identifier <RESOURCE_NAME> --region <REGION>",
        "aws rds modify-db-cluster --db-cluster-identifier <RESOURCE_NAME> --deletion-protection --region <REGION>",
        "https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-cluster.html",
        "Deletion protection prevents accidental cluster deletion but is not a backup; review the cluster owner and engine applicability.",
        "Set deletion_protection = true on the owning aws_rds_cluster declaration."),
    "aws.rds.auto_minor_upgrade": (
        "aws rds describe-db-instances --db-instance-identifier <RESOURCE_NAME> --region <REGION>",
        "aws rds modify-db-instance --db-instance-identifier <RESOURCE_NAME> --auto-minor-version-upgrade --region <REGION>",
        "https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html",
        "RDS Custom instances do not support this setting. An eligible minor upgrade can cause an outage during a maintenance window; review engine compatibility, window and rollback before enabling it.",
        "Set auto_minor_version_upgrade = true on the owning aws_db_instance declaration only for a supported engine."),
    "aws.ecr.immutable_tags": (
        "aws ecr describe-repositories --repository-names <REPOSITORY_NAME> --region <REGION>",
        "aws ecr put-image-tag-mutability --repository-name <REPOSITORY_NAME> --image-tag-mutability IMMUTABLE --region <REGION>",
        "https://docs.aws.amazon.com/cli/latest/reference/ecr/put-image-tag-mutability.html",
        "Immutable tags prevent overwrite and may require a new image version in existing release automation.",
        "Set image_tag_mutability = IMMUTABLE on the owning ECR repository declaration."),
    "aws.cloudtrail.log_validation": (
        "aws cloudtrail describe-trails --trail-name-list <RESOURCE_ARN> --region <REGION>",
        "aws cloudtrail update-trail --name <RESOURCE_ARN> --enable-log-file-validation --region <REGION>",
        "https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html",
        "Update the trail in its home Region; digest files are not retroactive for logs delivered while validation was disabled.",
        "Set enable_log_file_validation = true on the owning CloudTrail declaration."),
    "aws.cloudtrail.multi_region": (
        "aws cloudtrail describe-trails --trail-name-list <RESOURCE_ARN> --region <REGION>",
        "aws cloudtrail update-trail --name <RESOURCE_ARN> --is-multi-region-trail --region <REGION>",
        "https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html",
        "Update in the trail's home Region; enabling multi-Region coverage creates shadow trails and may change log volume and cost.",
        "Set is_multi_region_trail = true on the owning CloudTrail declaration and review destination capacity."),
    "gcp.compute.shielded_vtpm": (
        "gcloud compute instances describe <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION>",
        "gcloud compute instances update <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION> --shielded-vtpm",
        "https://cloud.google.com/sdk/gcloud/reference/compute/instances/update",
        "The Shielded VM setting takes effect after a stop/start; review disk-encryption and measured-boot dependencies before changing vTPM.",
        "Set shielded_instance_config.enable_vtpm = true on the owning Compute Engine instance declaration."),
    "gcp.compute.integrity_monitoring": (
        "gcloud compute instances describe <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION>",
        "gcloud compute instances update <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION> --shielded-integrity-monitoring",
        "https://cloud.google.com/sdk/gcloud/reference/compute/instances/update",
        "The setting takes effect after a stop/start; evaluate alerts and the measured-boot baseline separately.",
        "Set shielded_instance_config.enable_integrity_monitoring = true on the owning instance declaration."),
    "gcp.compute.secure_boot": (
        "gcloud compute instances describe <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION>",
        "gcloud compute instances update <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION> --shielded-secure-boot",
        "https://cloud.google.com/sdk/gcloud/reference/compute/instances/update",
        "Secure Boot takes effect after a stop/start and may block unsigned kernels or drivers; test recovery before rollout.",
        "Set shielded_instance_config.enable_secure_boot = true on the owning instance declaration."),
    "gcp.reviewed.compute.deletion_protection": (
        "gcloud compute instances describe <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION>",
        "gcloud compute instances update <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION> --deletion-protection",
        "https://cloud.google.com/compute/docs/instances/preventing-accidental-vm-deletion",
        "Deletion protection does not prevent instance modification or replace backup and recovery controls.",
        "Set deletion_protection = true on the owning google_compute_instance declaration."),
    "gcp.reviewed.compute.automatic_restart": (
        "gcloud compute instances describe <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION>",
        "gcloud compute instances set-scheduling <RESOURCE_NAME> --project=<PROJECT_ID> --zone=<LOCATION> --restart-on-failure",
        "https://cloud.google.com/sdk/gcloud/reference/compute/instances/set-scheduling",
        "Automatic restart applies to eligible standard VMs after a Compute Engine termination, not user-initiated stops; preemptible and Spot instances do not support the same availability guarantee. Review scheduling and application recovery before changing it.",
        "Set scheduling.automatic_restart = true only on an eligible owning Compute Engine instance declaration."),
    "gcp.sql.no_public_ip": (
        "gcloud sql instances describe <RESOURCE_NAME> --project=<PROJECT_ID>",
        "gcloud sql instances patch <RESOURCE_NAME> --project=<PROJECT_ID> --no-assign-ip",
        "https://cloud.google.com/sdk/gcloud/reference/sql/instances/patch",
        "First provision and test private IP connectivity, DNS and all clients. Disabling public IP can disconnect applications; this setting alone does not establish private-path access or authorized networks.",
        "Set settings.ipConfiguration.ipv4Enabled = false on the owning Cloud SQL declaration after its private IP path is tested."),
    "gcp.sql.backups": (
        "gcloud sql instances describe <RESOURCE_NAME> --project=<PROJECT_ID>",
        "gcloud sql instances patch <RESOURCE_NAME> --project=<PROJECT_ID> --backup-start-time=<REVIEWED_UTC_HH_MM>",
        "https://cloud.google.com/sdk/gcloud/reference/sql/instances/patch",
        "Choose a reviewed four-hour UTC backup window, retention and storage location for the engine and edition. Scheduled backup configuration does not prove successful backups or restore readiness; verify a completed backup and test recovery separately.",
        "Set settings.backupConfiguration.enabled = true with a reviewed startTime and retention policy on the owning Cloud SQL instance declaration."),
    "gcp.network.custom_subnets": (
        "gcloud compute networks describe <RESOURCE_NAME> --project=<PROJECT_ID>",
        "gcloud compute networks update <RESOURCE_NAME> --project=<PROJECT_ID> --switch-to-custom-subnet-mode",
        "https://cloud.google.com/sdk/gcloud/reference/compute/networks/update",
        "Auto-to-custom subnet conversion is irreversible. Existing subnets remain, but API calls and automation that relied on implicit auto subnets may need explicit subnet selection; inventory and test them first.",
        "Set auto_create_subnetworks = false on the owning network declaration only after a reviewed one-way conversion plan."),
    "azure.storage.no_shared_key": (
        "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az storage account update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --allow-shared-key-access false",
        "https://learn.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest",
        "Disabling Shared Key can break key-signed requests and affected SAS flows; migrate clients to Microsoft Entra authorization first.",
        "Set allowSharedKeyAccess = false on the owning Microsoft.Storage/storageAccounts declaration."),
    "azure.storage.no_public_network": (
        "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az storage account update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --public-network-access Disabled",
        "https://learn.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest",
        "Disable public networking only after the private endpoint, DNS and dependent clients are verified; otherwise access can stop.",
        "Set publicNetworkAccess = Disabled in the owning storage account declaration after private access is tested."),
    "azure.sql.minimum_tls": (
        "az sql server show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az sql server update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --minimal-tls-version 1.2",
        "https://learn.microsoft.com/en-us/cli/azure/sql/server?view=azure-cli-latest",
        "Clients restricted to older TLS versions can lose connectivity; inventory and test them before raising the minimum.",
        "Set minimalTlsVersion = 1.2 on the owning Microsoft.Sql/servers declaration."),
    "azure.storage.cross_tenant_replication": (
        "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az storage account update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --allow-cross-tenant-replication false",
        "https://learn.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest",
        "Existing cross-tenant object replication workflows may fail; inventory source and destination policies first.",
        "Set allowCrossTenantReplication = false on the owning storage account declaration."),
    "azure.storage.default_deny": (
        "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az storage account update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --default-action Deny",
        "https://learn.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest",
        "Default Deny can block clients without an approved network exception or private path; test those paths first.",
        "Set networkAcls.defaultAction = Deny on the owning storage account declaration."),
    "azure.vault.default_deny": (
        "az keyvault show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az keyvault update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --default-action Deny",
        "https://learn.microsoft.com/en-us/cli/azure/keyvault?view=azure-cli-latest",
        "Default Deny may block dependent applications until private endpoints or approved network rules and DNS are tested.",
        "Set networkAcls.defaultAction = Deny on the owning Key Vault declaration."),
    "azure.vault.no_public_network": (
        "az keyvault show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az keyvault update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --public-network-access Disabled",
        "https://learn.microsoft.com/en-us/azure/key-vault/general/network-security",
        "Private endpoint, DNS and all dependent clients must be tested before public access is disabled; trusted service behavior needs separate review.",
        "Set publicNetworkAccess = Disabled on the owning Key Vault declaration after private access is verified."),
    "azure.vault.purge_protection": (
        "az keyvault show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az keyvault update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --enable-purge-protection true",
        "https://learn.microsoft.com/en-us/azure/key-vault/general/key-vault-recovery",
        "Enabling purge protection is irreversible for the vault's retention period and prevents immediate permanent deletion. Confirm soft delete, recovery policy and lifecycle ownership first.",
        "Set enablePurgeProtection = true on the owning Key Vault declaration after retention and recovery review."),
    "azure.vault.rbac": (
        "az keyvault show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az keyvault update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --enable-rbac-authorization true",
        "https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration",
        "RBAC mode ignores existing vault access policies; create and test required role assignments before switching or clients may lose access.",
        "Set enableRbacAuthorization = true on the owning vault declaration only after the role assignment migration."),
    "azure.aks.no_local_accounts": (
        "az aks show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az aks update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --disable-local-accounts",
        "https://learn.microsoft.com/en-us/azure/aks/entra-id-control-plane-authentication",
        "Verify Microsoft Entra sign-in and recovery access before disabling static cluster credentials.",
        "Set disableLocalAccounts = true on the owning Microsoft.ContainerService/managedClusters declaration."),
    "azure.aks.azure_rbac": (
        "az aks show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az aks update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --enable-azure-rbac",
        "https://learn.microsoft.com/en-us/azure/aks/manage-azure-rbac?tabs=azure-cli",
        "Managed Microsoft Entra integration and tested Azure RBAC assignments are prerequisites; an authorization-model change can lock out operators.",
        "Set aadProfile.enableAzureRBAC = true on the owning AKS declaration after validating administrator role assignments."),
    "azure.app.https_only": (
        "az webapp show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az webapp update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --https-only true",
        "https://learn.microsoft.com/en-us/cli/azure/webapp?view=azure-cli-latest",
        "HTTP clients may be redirected or fail; test custom domains, certificates and application callbacks before enforcing HTTPS.",
        "Set httpsOnly = true on the owning Microsoft.Web/sites declaration."),
    "azure.app.http2": (
        "az webapp config show --resource-group <RESOURCE_GROUP> --name <WEBAPP_NAME>",
        "az webapp config set --resource-group <RESOURCE_GROUP> --name <WEBAPP_NAME> --http20-enabled true",
        "https://learn.microsoft.com/en-us/cli/azure/webapp/config?view=azure-cli-latest",
        "HTTP/2 changes client and proxy protocol behavior; validate custom front ends and application traffic. The finding targets a site config object, so verify its owning web app name rather than using the config leaf as an app name.",
        "Set http20Enabled = true on the owning Microsoft.Web/sites/config web declaration."),
    "azure.app.remote_debugging_off": (
        "az webapp config show --resource-group <RESOURCE_GROUP> --name <WEBAPP_NAME>",
        "az webapp config set --resource-group <RESOURCE_GROUP> --name <WEBAPP_NAME> --remote-debugging-enabled false",
        "https://learn.microsoft.com/en-us/cli/azure/webapp/config?view=azure-cli-latest",
        "Remote debugging sessions will disconnect; coordinate with active troubleshooters. The finding targets a site config object, so verify its owning web app name rather than using the config leaf as an app name.",
        "Set remoteDebuggingEnabled = false on the owning Microsoft.Web/sites/config web declaration."),
    "azure.app.request_logging": (
        "az webapp log show --resource-group <RESOURCE_GROUP> --name <WEBAPP_NAME>",
        "az webapp log config --resource-group <RESOURCE_GROUP> --name <WEBAPP_NAME> --web-server-logging filesystem",
        "https://learn.microsoft.com/en-us/cli/azure/webapp/log?view=azure-cli-latest",
        "Filesystem web-server logs have retention and storage limits and can contain request metadata; define retention, access and budget before enabling. Verify the owning web app name because this finding targets its config object.",
        "Set httpLoggingEnabled = true on the owning Microsoft.Web/sites/config web declaration and configure approved retention."),
    "azure.vm.encryption_at_host": (
        "az vm show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --query securityProfile.encryptionAtHost",
        "az vm update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --encryption-at-host true",
        "https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-enable-host-based-encryption-cli",
        "Confirm the VM size, disk and encryption combination supports encryption at host; coordinate any required stop/start and workload downtime. Verify disk and temporary-storage behavior independently after update.",
        "Set securityProfile.encryptionAtHost = true on the owning Microsoft.Compute/virtualMachines declaration after compatibility review."),
    "azure.sql.no_public_network": (
        "az sql server show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az sql server update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --set publicNetworkAccess=Disabled",
        "https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql-db",
        "Public clients will lose access; verify private endpoint, DNS and application connectivity first.",
        "Set publicNetworkAccess = Disabled on the owning Microsoft.Sql/servers declaration."),
    "azure.network.nic_no_ip_forwarding": (
        "az network nic show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "az network nic update --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME> --ip-forwarding false",
        "https://learn.microsoft.com/en-us/cli/azure/network/nic?view=azure-cli-latest",
        "Disabling IP forwarding can break intentionally deployed network virtual appliances or routing; verify NIC role first.",
        "Set enableIPForwarding = false on the owning Microsoft.Network/networkInterfaces declaration."),
}
for _suffix, _field in (
    ("uppercase", "RequireUppercaseCharacters"), ("lowercase", "RequireLowercaseCharacters"),
    ("numbers", "RequireNumbers"), ("symbols", "RequireSymbols"),
):
    SCALAR_APPROVALS[f"aws.iam.password_{_suffix}"] = (
        "aws iam get-account-password-policy",
        "aws iam update-account-password-policy --cli-input-json file://reviewed-password-policy.json",
        "https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html",
        f"The update API resets every omitted password-policy option to its default. The reviewed input file must preserve every other approved setting while enabling {_field}; this affects native IAM user passwords, not federated sign-in.",
        f"Set {_field} = true in the complete, owning account password policy declaration without dropping other settings.",
    )

IMMUTABLE_SCALAR_APPROVALS = {
    "azure.storage.infrastructure_encryption": {
        "inspect": "az storage account show --resource-group <RESOURCE_GROUP> --name <RESOURCE_NAME>",
        "summary": "Migrate this storage account to a reviewed replacement created with infrastructure encryption enabled.",
        "steps": ["Inspect properties.encryption.requireInfrastructureEncryption and identify account type, data, applications, endpoints and replication dependencies.",
                  "Create a compatible replacement account with infrastructure encryption enabled at creation through the infrastructure owner; migrate data and test every client path.",
                  "Cut over only after verification, then read the replacement setting and rerun the check against the new account."],
        "reference": "https://learn.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable",
        "caveat": "Infrastructure encryption cannot be enabled or disabled on an existing account. Replacement and data migration can change endpoints, cost, availability and application behavior; no deletion is implied by this guidance.",
        "iac": "Set requireInfrastructureEncryption = true when creating the replacement Microsoft.Storage/storageAccounts resource; use a separately reviewed migration and cutover plan.",
    },
}

# Each tuple below was matched to evaluate_component's (component, flags,
# comparison, expected) predicate and the cited current component reference.
# The same predicate is registered against nine explicit PodSpec kinds; no
# unrelated suffix or version-gated legacy control inherits approval.
REVIEWED_COMPONENTS = {
    ("kubelet", ("anonymous-auth",), "equal", "false"),
    ("kube-apiserver", ("anonymous-auth",), "equal", "false"),
    ("kubelet", ("rotate-certificates",), "equal", "true"),
    ("kubelet", ("read-only-port",), "equal", "0"),
    ("kubelet", ("protect-kernel-defaults",), "equal", "true"),
    ("kubelet", ("make-iptables-util-chains",), "equal", "true"),
    ("kubelet", ("terminated-pod-gc-threshold",), "gt", 0),
    ("kubelet", ("tls-cert-file", "tls-private-key-file"), "present", None),
    ("kubelet", ("client-ca-file",), "present", None),
    ("kubelet", ("streaming-connection-idle-timeout",), "nonzero_duration", None),
    ("kube-apiserver", ("service-account-lookup",), "equal", "true"),
    ("kube-apiserver", ("audit-log-path",), "present", None),
    ("kube-apiserver", ("encryption-provider-config",), "present", None),
    ("kube-apiserver", ("etcd-cafile",), "present", None),
    ("kube-apiserver", ("etcd-certfile", "etcd-keyfile"), "present", None),
    ("kube-apiserver", ("kubelet-client-certificate", "kubelet-client-key"), "present", None),
    ("kube-apiserver", ("tls-cert-file", "tls-private-key-file"), "present", None),
    ("kube-apiserver", ("client-ca-file",), "present", None),
    ("kube-apiserver", ("kubelet-certificate-authority",), "present", None),
    ("kube-apiserver", ("service-account-key-file",), "present", None),
    ("kube-apiserver", ("secure-port",), "gt", 0),
    ("kube-apiserver", ("audit-log-maxage",), "ge", 30),
    ("kube-apiserver", ("audit-log-maxbackup",), "ge", 10),
    ("kube-apiserver", ("audit-log-maxsize",), "ge", 100),
    ("kube-apiserver", ("authorization-mode",), "contains", "Node"),
    ("kube-apiserver", ("authorization-mode",), "contains", "RBAC"),
    ("kube-apiserver", ("authorization-mode",), "excludes", "AlwaysAllow"),
    ("kube-apiserver", ("profiling",), "equal", "false"),
    ("kube-scheduler", ("profiling",), "equal", "false"),
    ("kube-scheduler", ("bind-address",), "equal", "127.0.0.1"),
    ("kube-controller-manager", ("profiling",), "equal", "false"),
    ("kube-controller-manager", ("bind-address",), "equal", "127.0.0.1"),
    ("kube-controller-manager", ("use-service-account-credentials",), "equal", "true"),
    ("etcd", ("auto-tls",), "equal", "false"),
    ("etcd", ("client-cert-auth",), "equal", "true"),
    ("etcd", ("peer-client-cert-auth",), "equal", "true"),
    ("etcd", ("peer-auto-tls",), "equal", "false"),
    ("etcd", ("cert-file", "key-file"), "present", None),
    ("etcd", ("peer-cert-file", "peer-key-file"), "present", None),
}
COMPONENT_PREREQUISITES = {
    ("etcd", "auto-tls"): "Install and test reviewed CA-signed client/server certificates and keys before disabling generated TLS certificates.",
    ("etcd", "client-cert-auth"): "Install a reviewed trusted CA and verify all etcd clients present valid certificates before requiring client certificate authentication.",
    ("etcd", "peer-client-cert-auth"): "Install a reviewed peer trusted CA and verify every etcd peer certificate before requiring peer certificate authentication.",
    ("etcd", "peer-auto-tls"): "Install and test reviewed peer certificates and keys on every member before disabling generated peer TLS certificates.",
    ("etcd", "cert-file"): "Provide a valid client-serving certificate and matching protected private key, with SANs matching advertised client endpoints; test every etcd client first.",
    ("etcd", "peer-cert-file"): "Provide a valid peer certificate and matching protected private key on every member, with SANs matching peer endpoints; test cluster quorum and rollback first.",
    ("kube-apiserver", "audit-log-path"): "Choose an existing writable destination and audit policy; log-path alone does not prove audit coverage, log delivery or retention.",
    ("kube-apiserver", "encryption-provider-config"): "Use a reviewed EncryptionConfiguration with a non-identity first provider and protected key material on every API server; coordinate a staged rollout and rewrite existing objects to complete migration. Flag presence alone does not prove encryption.",
    ("kube-apiserver", "etcd-cafile"): "Install the reviewed etcd CA bundle and validate endpoint certificate SANs before changing API-server trust, or storage access can fail.",
    ("kube-apiserver", "etcd-certfile"): "Install a valid client certificate and matching protected private key accepted by etcd on every API server; test quorum and rollback before rollout.",
    ("kube-apiserver", "kubelet-client-certificate"): "Install a reviewed client certificate and matching protected key accepted by kubelets; test logs, exec and port-forward functionality first.",
    ("kube-apiserver", "tls-cert-file"): "Install a valid serving certificate and matching protected private key for every advertised API-server name; test client trust and rollback before rollout.",
    ("kube-apiserver", "client-ca-file"): "Use only the reviewed client CA for authenticated client certificates; a wrong trust bundle can deny clients or admit unintended identities.",
    ("kube-apiserver", "kubelet-certificate-authority"): "Use the reviewed CA that signs kubelet serving certificates; verify kubelet SANs and API-server-to-kubelet paths first.",
    ("kube-apiserver", "service-account-key-file"): "Provide the reviewed ServiceAccount token verification public key material and coordinate signing-key rotation across API servers; wrong keys can invalidate workload tokens.",
    ("kube-apiserver", "secure-port"): "Choose a supported nonzero secure port and verify load balancer, health probes and every API client before changing the control-plane listener.",
    ("kubelet", "tls-cert-file"): "Install a valid kubelet serving certificate and matching protected key through the node owner; current kubelet configuration should use supported config-file fields rather than deprecated flags.",
    ("kubelet", "client-ca-file"): "Use only the reviewed CA for kubelet client authentication; verify API-server and operator clients before applying through the supported kubelet config file.",
    ("kubelet", "streaming-connection-idle-timeout"): "Choose a nonzero duration that permits legitimate streaming operations while limiting abandoned sessions; apply through the supported kubelet config file and test exec/log clients.",
    ("kube-apiserver", "authorization-mode"): "Review the existing authorizer chain and all required node and user permissions before changing its ordered modes; an incorrect chain can deny cluster operations.",
    ("kubelet", "terminated-pod-gc-threshold"): "Choose a positive threshold sized for node capacity; pod garbage collection changes retention of terminated Pod objects.",
    ("kube-controller-manager", "use-service-account-credentials"): "Verify the required per-controller ServiceAccounts and RBAC grants before changing controller credentials.",
    ("kubelet", "protect-kernel-defaults"): "Confirm node kernel tunables match kubelet defaults, or the kubelet can fail to start.",
    ("kube-scheduler", "bind-address"): "Check scheduler health probes and local access paths before binding only to loopback.",
    ("kube-controller-manager", "bind-address"): "Check controller-manager health probes and local access paths before binding only to loopback.",
}


def _setting(fields, operation, expected):
    label = ", ".join("--" + field for field in fields)
    if operation == "equal":
        return f"Set {label} to {expected} in the managed component configuration."
    if operation == "present":
        return f"Configure {label} with the owner-approved nonempty value."
    if operation == "absent":
        return f"Remove {label} from the managed configuration if the component version and workload permit it."
    if operation in ("ge", "gt", "le"):
        relation = {"ge": "at least", "gt": "greater than", "le": "at most"}[operation]
        return f"Set {label} to a value {relation} {expected} in the managed component configuration."
    if operation == "contains":
        return f"Include {expected} in the declared {label} list without removing required entries."
    if operation == "contains_any":
        return f"Include one approved value from {', '.join(expected)} in the declared {label} list."
    if operation == "excludes":
        return f"Remove {expected} from the declared {label} list while keeping the required alternatives."
    if operation == "subset":
        return f"Limit {label} to the approved cipher set documented for this component version."
    if operation == "nonzero_duration":
        return f"Set {label} to an approved nonzero duration."
    raise ValueError(f"Unsupported component operation: {operation}")


def _component(check, specification):
    kind, component, fields, operation, expected = specification
    names = [component] if isinstance(component, str) else list(component)
    name = "/".join(names)
    field = ", ".join("--" + item for item in fields)
    summary = f"Set the {kind} {name} {field} declaration to the reviewed value."
    if operation == "absent":
        summary = f"Remove the {kind} {name} {field} declaration when applicable."
    elif operation == "equal":
        summary = f"Set the {kind} {name} {field} declaration to {expected}."
    elif operation in ("contains", "excludes"):
        summary = f"Update the {kind} {name} {field} declaration to {'include' if operation == 'contains' else 'exclude'} {expected}."
    if expected in ("PodSecurityPolicy", ("PodSecurityPolicy", "SecurityContextDeny")):
        action = "For legacy versions where this predicate applies, review admission controls; use Pod Security Admission on supported modern clusters instead of enabling removed plugins."
    else:
        action = _setting(fields, operation, expected)
    reviewed = (component, tuple(fields), operation, expected) in REVIEWED_COMPONENTS
    prerequisite = COMPONENT_PREREQUISITES.get((component, fields[0])) if isinstance(component, str) else None
    steps = [f"Inspect the {kind} PodSpec and confirm the captured _component_config identifies {name}, has complete flags, and names its version."]
    if prerequisite:
        steps.append(prerequisite)
    steps.extend([action, "Apply the change through the owning node or control-plane configuration and verify component health and the declared flag independently."])
    return {
        "summary": summary,
        "steps": steps,
        "cli": [{"label": "Inspect the declared object", "shell": "bash", "code": f"kubectl get {kind} <RESOURCE_NAME> -n <NAMESPACE> -o yaml"}],
        "caveats": ["The evaluator reads a projected declaration, not live host enforcement. The component owner and supported update route are not proven by this finding; no generic fix command is safe.",
                    "Changing component arguments can interrupt cluster operation; review version applicability and test rollback first." + (" " + prerequisite if prerequisite else "")],
        "references": ([{"title": f"{name} configuration", "url": COMPONENT_REFS[names[0]]}] +
                       ([{"title": "Kubernetes API data encryption at rest", "url": "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"}]
                        if component == "kube-apiserver" and fields == ("encryption-provider-config",) else [])),
        **({"iac": {"label": "Update the owning component configuration", "language": "text",
                    "code": f"{action} Use the node or control-plane configuration owned by the cluster operator and the provider-supported route for managed components."}}
           if reviewed else {}),
        "review_status": "approved" if reviewed else "field_derived_reference_pending",
        "field_binding": {"target": check.target, "kind": kind, "component": names, "fields": fields, "operation": operation},
    }


def _scalar(check, spec):
    path, good = spec["path"], spec["good"]
    if isinstance(good, tuple):
        action = f"Set {path} to one of the documented acceptable values: {', '.join(map(str, good))}."
    elif isinstance(good, bool) or isinstance(good, (int, float)) or isinstance(good, str) and good in {"Enabled", "Disabled", "ENABLED", "DISABLED", "Active", "PassThrough", "TLS1_2", "TLS1_3"}:
        action = f"Set {path} to {good} through the owning provider configuration."
    else:
        action = f"Set {path} to the owner-approved value that meets this check's documented requirement."
    value = {
        "summary": f"Set {check.kind} {path} to satisfy {check.title.lower()}.",
        "steps": [f"Inspect {path} on the exact {check.kind} resource and identify its configuration owner.", action,
                  f"Read {path} again and rerun {check.id} after testing dependent workloads."],
        "cli": [],
        "caveats": ["No provider-specific mutation command is emitted until the resource's configuration owner and supported API operation are reviewed."],
        "references": [],
        "review_status": "field_draft_reference_pending",
        "field_binding": {"target": check.target, "kind": check.kind, "path": path},
    }
    if check.id in SCALAR_APPROVALS:
        assert check.target == "resource"
        inspect, fix, reference, caveat, iac = SCALAR_APPROVALS[check.id]
        value.update({"summary": f"Set {check.kind} {path} to {good} on the reviewed resource.",
            "steps": [f"Inspect {path} on the exact {check.kind} resource and identify its configuration owner.",
                      f"Use the supported provider update to set {path} to {good} after checking dependent clients and rollout impact.",
                      f"Read {path} again and rerun {check.id}; verify dependent workloads separately."],
            "cli": [{"label": "Inspect the setting", "shell": "bash", "code": inspect},
                    {"label": "Apply the reviewed field change", "shell": "bash", "code": fix}],
            "iac": {"label": "Update the owning declaration", "language": "text", "code": iac},
            "caveats": [caveat, "The check reads declared configuration; runtime behavior and collection completeness require independent verification."],
            "references": [{"title": "Official provider update reference", "url": reference}],
            "review_status": "approved"})
    elif check.id in IMMUTABLE_SCALAR_APPROVALS:
        reviewed = IMMUTABLE_SCALAR_APPROVALS[check.id]
        value.update({"summary": reviewed["summary"], "steps": reviewed["steps"],
            "cli": [{"label": "Inspect the existing immutable setting", "shell": "bash", "code": reviewed["inspect"]}],
            "iac": {"label": "Define the replacement through its owner", "language": "text", "code": reviewed["iac"]},
            "caveats": [reviewed["caveat"], "Verify collection completeness and application behavior independently after cutover."],
            "references": [{"title": "Official immutable-setting and migration reference", "url": reviewed["reference"]}],
            "review_status": "approved"})
    return value


def _network(check, label, provider):
    assert check.target == "resource", (check.id, check.target)
    if provider == "aws":
        summary = f"Narrow world-open {label} ingress on this security group to approved clients."
        steps = [
            f"Inspect GroupId and the matching {label} ingress declaration; identify the exact rule ID, protocol, port range and attached workloads.",
            "Add a reviewed narrower source or remove an unused allowance in the owning configuration; test legitimate clients before revoking the broad rule.",
            "Revoke only the independently identified broad rule, then verify the declaration and application traffic.",
        ]
        cli = [
            {"label": "Inspect exact rule IDs", "shell": "bash", "code": "aws ec2 describe-security-group-rules --filters Name=group-id,Values=<RESOURCE_ID> --region <REGION>"},
            {"label": "Revoke the reviewed broad rule after replacement", "shell": "bash", "code": "aws ec2 revoke-security-group-ingress --group-id <RESOURCE_ID> --security-group-rule-ids <RULE_ID> --region <REGION>"},
        ]
        iac = "Narrow or remove the matching aws_vpc_security_group_ingress_rule in its owning Terraform/CloudFormation module; review the plan and test clients."
        caveats = ["The evaluator reports a matching-rule count, not its rule ID. A declared world CIDR does not prove route reachability; a rule change can interrupt clients."]
    elif provider == "gcp":
        summary = f"Restrict public {label} ingress in this firewall rule to approved sources and necessary targets."
        steps = [
            f"Inspect direction, sourceRanges, allowed protocol and port entries, and target tags/service accounts for the {label} rule.",
            "Replace world-open source ranges with tested approved CIDRs or narrow the target and allowed ports in the owning rule.",
            "Test intended connections, reread the firewall rule and rerun this check; review higher-priority policies separately.",
        ]
        cli = [
            {"label": "Inspect the firewall rule", "shell": "bash", "code": "gcloud compute firewall-rules describe <RESOURCE_NAME> --project=<PROJECT_ID>"},
            {"label": "Set a reviewed source range", "shell": "bash", "code": "gcloud compute firewall-rules update <RESOURCE_NAME> --project=<PROJECT_ID> --source-ranges=<APPROVED_CIDR>"},
        ]
        iac = "Change source_ranges and, if needed, target_tags/target_service_accounts and allow entries on the existing google_compute_firewall resource."
        caveats = ["The check examines a declared allow rule, not effective reachability, priority, target attachment or hierarchical firewall policy. Source selectors and other ports may still allow exposure."]
    else:
        summary = f"Narrow the exposed {label} Allow rule in this NSG to approved client prefixes."
        steps = [
            f"Inspect exposed_rules and identify the exact {label} Allow rule, priority, source prefixes, destination and NSG attachments.",
            "Review application need and higher-priority Deny rules; replace the broad source prefix with tested approved prefixes in the owning rule.",
            "Verify effective NSG rules and intended traffic, then rerun this check.",
        ]
        cli = [
            {"label": "Inspect NSG rule names and priorities", "shell": "bash", "code": "az network nsg rule list --resource-group <RESOURCE_GROUP> --nsg-name <RESOURCE_NAME>"},
            {"label": "Narrow the verified Allow rule", "shell": "bash", "code": "az network nsg rule update --resource-group <RESOURCE_GROUP> --nsg-name <RESOURCE_NAME> --name <RULE_NAME> --source-address-prefixes <APPROVED_CIDR>"},
        ]
        iac = "Update the exact securityRules sourceAddressPrefixes on the owning Microsoft.Network/networkSecurityGroups Bicep/ARM/Terraform declaration."
        caveats = ["The predicate accounts for rule priority but does not establish effective routes or client need. Replacing source prefixes may interrupt traffic; the finding does not authorize a CIDR."]
    return {"summary": summary, "steps": steps, "cli": cli,
            "iac": {"label": "Change the existing managed rule", "code": iac, "language": "text"},
            "caveats": caveats, "references": [NETWORK_REFS[provider]],
            "review_status": "approved", "field_binding": {"target": check.target, "kind": check.kind, "label": label,
            "evaluator_family": {"aws": "claude_aws_a_network._turbot_check",
                                 "gcp": "claude_gcp_k8s_compute.firewall_port",
                                 "azure": "claude_azure_network.nsg_check"}[provider]}}


def _network_rules(index):
    out = {}
    for suffix, _rows, _title, options, _fixture, _severity in aws_network.TURBOT_SG:
        cid = "aws.claude_a.vpc." + suffix
        ports = ",".join(map(str, options.get("ports", [])))
        label = ("TCP/UDP or all-protocol" if options.get("protocols") else "port " + ports) + (" IPv6" if options.get("v4") is False else " IPv4/IPv6" if options.get("v6") else " IPv4")
        out[cid] = _network(index[cid], label, "aws")
    for suffix, (ports, protocols) in gcp_network.FIREWALL_PORTS.items():
        cid = gcp_network.FIREWALL_PORT_IDS[suffix]
        label = "/".join(protocols).upper() + " port " + ",".join(map(str, ports))
        out[cid] = _network(index[cid], label, "gcp")
    for port in azure_network.TCP_PORTS:
        cid = f"azure.claude.nsg_internet_tcp_{port}"
        out[cid] = _network(index[cid], f"TCP port {port}", "azure")
    for port in azure_network.UDP_PORTS:
        cid = f"azure.claude.nsg_internet_udp_{port}"
        out[cid] = _network(index[cid], f"UDP port {port}", "azure")
    extras = {
        "rdp": "TCP port 3389", "ssh": "TCP port 22", "remote_access": "TCP ports 22/3389",
        "icmp": "ICMP", "udp_services": "UDP ports 53/123/161/389/1900", "udp_any": "UDP on any port",
        "all_ports_tcp_udp": "all TCP/UDP ports", "common_ports": "common administrative/data ports",
    }
    for suffix, label in extras.items():
        cid = "azure.claude.nsg_internet_" + suffix
        out[cid] = _network(index[cid], label, "azure")
    return out


def _workload_rules(index):
    out = {}
    for kind, pod_path in workloads.KIND_PATHS.items():
        for predicate, (field, action, reference) in WORKLOAD_GUIDANCE.items():
            cid = workloads.native_id(kind, predicate)
            if cid in k8s_extended.EXTENDED_IDS:
                # These IDs resolve to k8s_extended._evaluate_pod, whose Pod
                # inheritance and explicit UID checks differ from the ported
                # workload family. The exact extended evaluator owns them below.
                continue
            check = index.get(cid)
            if check is None or check.target != "resource" or check.kind != kind:
                continue
            summary = f"Set {kind} {field} in the owning PodSpec."
            steps = [
                f"Inspect {pod_path} on the named {kind}; locate each flagged container or Pod-level {field} declaration and identify the owning manifest/controller.",
                action,
                "Roll out the reviewed owner manifest, test workload behavior and admission, then rerun the check against the new declaration.",
            ]
            cli = [{"label": "Inspect the exact workload declaration", "shell": "bash", "code": f"kubectl get {kind} <RESOURCE_NAME> -n <NAMESPACE> -o yaml"}]
            if kind != "pod":
                cli.append({"label": "Apply the separately reviewed owner manifest", "shell": "bash", "code": "kubectl apply -f <REVIEWED_MANIFEST>"})
            impacts = {
                "resources": "A limit can throttle CPU or terminate a container for memory exhaustion; an oversized request can prevent scheduling. Synthetic fixture quantities are not recommended values.",
                "probes": "A poorly chosen readiness target removes healthy Pods from service, and a liveness target can restart them repeatedly; test timing and startup behavior.",
                "images": "A version tag is still mutable unless the registry enforces immutability; changing image or pull policy can alter rollout and registry behavior.",
                "standards": "Removing hostPort or host namespace access can interrupt inbound traffic or host-integrated workloads; validate the replacement path.",
            }
            out[cid] = {"summary": summary, "steps": steps, "cli": cli,
                "iac": {"label": "Update the owning manifest or Helm values", "language": "text", "code": f"Set {field} under {pod_path} in the reviewed {kind} declaration and roll out through its owner."},
                "caveats": ["This predicate reads declared PodSpec fields across regular, init and ephemeral containers; it does not prove runtime isolation or admission enforcement.",
                            impacts.get(reference, "Changing security context or ServiceAccount identity can interrupt the workload; confirm the actual owner and test the rollout.")],
                "references": [K8S_REFS[reference]], "review_status": "approved",
                "field_binding": {"target": check.target, "kind": kind, "pod_spec_path": pod_path, "predicate": predicate, "field": field,
                                  "evaluator_family": "k8s_ports_workloads.evaluate_predicate"}}
    return out


def _cluster_rules(index):
    """Exact k8s_ports_cluster predicates; legacy PSP and namespace moves stay pending."""
    out = {}

    def add(cid, *, kind, summary, field, steps, caveat, reference, inspect):
        check = index[cid]
        assert check.provider == "k8s" and check.target == "resource" and check.kind == kind
        out[cid] = {
            "summary": summary, "steps": steps,
            "cli": [{"label": "Inspect the exact declaration", "shell": "bash", "code": inspect}],
            "iac": {"label": "Update the owning manifest", "language": "text",
                    "code": f"Change {field} in the reviewed owning manifest or Helm values, then roll out through its owner."},
            "caveats": [caveat, "The evaluator reads declarations; admission and effective runtime behavior require separate verification."],
            "references": [K8S_REFS[reference]], "review_status": "approved",
            "field_binding": {"target": check.target, "kind": kind, "field": field,
                              "evaluator_family": "k8s_ports_cluster"},
        }

    for resource in ("cpu", "memory"):
        for measure in ("limit", "request"):
            query = f"namespace_resource_quota_{resource}_{measure}"
            field = f"spec.hard.{('limits' if measure == 'limit' else 'requests')}.{resource}"
            add(f"k8s.ports.namespace.{query}", kind="namespace",
                summary=f"Declare a reviewed namespace ResourceQuota {field} quantity.", field=field,
                steps=[f"Inspect ResourceQuota objects in the named namespace and confirm no quota declares {field} (or the supported alias for requests).",
                       f"Choose a {resource} {measure} quota from observed workload demand and capacity; add {field} to a reviewed ResourceQuota manifest.",
                       "Apply through the namespace owner, verify admissions and quota status, then rerun the check."],
                caveat="A quota can reject new or updated Pods when requests/limits or capacity do not fit; scope selectors and admission enforcement are separate.",
                reference="quota", inspect="kubectl get resourcequota -n <NAMESPACE> -o yaml")
            query = f"namespace_limit_range_default_{resource}_{measure}"
            field = f"spec.limits[*].{('default' if measure == 'limit' else 'defaultRequest')}.{resource}"
            add(f"k8s.ports.namespace.{query}", kind="namespace",
                summary=f"Declare a reviewed namespace LimitRange {field} value.", field=field,
                steps=[f"Inspect LimitRange objects and each Container entry in the named namespace for {field}.",
                       f"Select a {resource} default {measure} from observed workload demand and add it under a reviewed Container LimitRange entry.",
                       "Apply through the namespace owner, verify newly admitted Pods and effective defaults, then rerun the check."],
                caveat="Default requests or limits can change scheduling, CPU throttling or memory termination; the check only observes declaration presence.",
                reference="limits", inspect="kubectl get limitrange -n <NAMESPACE> -o yaml")

    for direction in ("ingress", "egress"):
        title = direction.capitalize()
        add(f"k8s.ports.namespace.network_policy_default_deny_{direction}", kind="namespace",
            summary=f"Declare a reviewed namespace-wide default-deny {direction} NetworkPolicy.",
            field=f"spec.podSelector={{}}, policyTypes includes {title}, spec.{direction}=[]",
            steps=[f"Inspect all NetworkPolicies in the namespace and determine whether one selects all Pods for {title} with no {direction} rules.",
                   f"Stage a default-deny {direction} policy and the explicitly required allow policies; test DNS and application flows before enforcement.",
                   "Apply the reviewed manifests, verify intended traffic and CNI enforcement, then rerun the check."],
            caveat="NetworkPolicies are additive, so another policy can still allow traffic; default deny may interrupt workloads or DNS when prerequisites are missing.",
            reference="networkpolicy", inspect="kubectl get networkpolicy -n <NAMESPACE> -o yaml")
        add(f"k8s.ports.networkpolicy.network_policy_default_dont_allow_{direction}", kind="networkpolicy",
            summary=f"Remove the unrestricted spec.{direction} empty rule from this NetworkPolicy.",
            field=f"spec.{direction}[*]={{}}",
            steps=[f"Inspect spec.{direction}, podSelector and policyTypes on the named NetworkPolicy; identify every empty rule that allows all peers and ports.",
                   f"Replace each unrestricted {direction} rule with tested peer and port selectors required by selected Pods.",
                   "Apply through the policy owner, test required traffic and inspect the policy union before rerunning the check."],
            caveat="An empty rule permits all traffic for its direction on selected Pods; replacing it can interrupt connections, while other policies may still allow them.",
            reference="networkpolicy", inspect="kubectl get networkpolicy <RESOURCE_NAME> -n <NAMESPACE> -o yaml")

    add("k8s.ports.service.service_type_forbidden", kind="service",
        summary="Replace this Service's NodePort or LoadBalancer publication with a reviewed internal access path.",
        field="spec.type=ClusterIP", steps=[
            "Inspect spec.type, ports, ingress consumers and allocated load balancer or NodePort on the named Service.",
            "Move required external clients to a separately approved ingress or gateway path, then set the Service type to ClusterIP in its owner manifest.",
            "Roll out and test both internal and intended external clients; verify cloud load balancer cleanup before rerunning the check."],
        caveat="Changing Service type can remove an external load balancer or node port and interrupt clients; the finding does not prove current internet reachability.",
        reference="service", inspect="kubectl get service <RESOURCE_NAME> -n <NAMESPACE> -o yaml")

    for kind in ("role", "clusterrole"):
        cid = f"k8s.ports.{kind}.role_with_rbac_escalate_permissions"
        suffix = " -n <NAMESPACE>" if kind == "role" else ""
        add(cid, kind=kind,
            summary=f"Remove or narrow unnecessary rbac.authorization.k8s.io escalate grants in this {kind.title()}.",
            field="rules[*].apiGroups/resources/verbs for escalate",
            steps=["Inspect declared_sensitive_rules and all bindings to this role; identify the exact escalate rule and legitimate owner workflow.",
                   "Remove the unused escalate verb or split the reviewed grant into a narrower role for its authorized operator.",
                   "Apply the reviewed RBAC manifest and test authorized role maintenance, then rerun the declaration check."],
            caveat="The evaluator flags declared RBAC capability, not effective authorization; removing a needed grant can stop role administration. No escalation path is inferred.",
            reference="rbac", inspect=f"kubectl get {kind} <RESOURCE_NAME>{suffix} -o yaml")
    add("k8s.ports.clusterrole.role_with_wildcards_used", kind="clusterrole",
        summary="Replace wildcard ClusterRole apiGroups, resources or verbs with reviewed explicit RBAC symbols.",
        field="rules[*].apiGroups/resources/verbs", steps=[
            "Inspect declared_wildcards and bindings; list the precise resources and verbs each bound workload needs.",
            "Replace wildcard symbols with those reviewed explicit symbols in the owning ClusterRole declaration.",
            "Test bound clients and admission before rollout, then rerun the check."],
        caveat="RBAC wildcard grants can include future resources; narrowing them may interrupt controllers. This declaration alone does not prove effective access.",
        reference="rbac", inspect="kubectl get clusterrole <RESOURCE_NAME> -o yaml")
    return out


def _extended_rules(index):
    """Exact k8s_extended Pod-template, ServiceAccount and quota predicates."""
    out = {}
    controls = {
        "no_privileged": ("containers[*].securityContext.privileged=false",
                          "Set privileged=false on each flagged regular, init or ephemeral container after removing its need for host privilege.", "standards"),
        "non_root": ("securityContext.runAsNonRoot=true and runAsUser!=0",
                     "Set runAsNonRoot=true at Pod or flagged container level and ensure no flagged container declares runAsUser=0; verify image users and file permissions.", "security"),
        "no_host_network": ("hostNetwork=false",
                            "Set hostNetwork=false in the owning Pod template and provide a reviewed Service or ingress path for required connections.", "standards"),
        "no_host_ports": ("containers[*].ports[*].hostPort=0 or absent",
                          "Remove nonzero hostPort declarations in each flagged container and use a reviewed Service or ingress path.", "standards"),
    }
    for kind in k8s_extended.CONTROLLERS + ("pod",):
        path = "spec.jobTemplate.spec.template.spec" if kind == "cronjob" else "spec" if kind == "pod" else "spec.template.spec"
        for predicate, (field, action, reference) in controls.items():
            if kind == "pod" and predicate != "no_host_ports":
                continue
            cid = f"k8s.{kind}.{predicate}"
            check = index[cid]
            assert check.kind == kind and check.target == "resource"
            out[cid] = {"summary": f"Set {kind} {path}.{field} in the owning Pod declaration.",
                "steps": [f"Inspect {path} on the named {kind}, including init and ephemeral containers, and identify the durable owner.",
                          action, "Roll out the reviewed owner manifest, test application behavior and admission, then rerun the check."],
                "cli": [{"label": "Inspect the exact object", "shell": "bash", "code": f"kubectl get {kind} <RESOURCE_NAME> -n <NAMESPACE> -o yaml"}],
                "iac": {"label": "Update the Pod template owner", "language": "text", "code": f"Set {field} under {path} in the reviewed {kind} manifest or Helm values."},
                "caveats": ["The evaluator reads the Pod or controller template declaration, not future admission or runtime isolation.",
                            "Removing privilege, root identity or host networking/ports may interrupt workloads; test the replacement path and rollback before rollout."],
                "references": [K8S_REFS[reference]], "review_status": "approved",
                "field_binding": {"target": check.target, "kind": kind, "field": f"{path}.{field}", "predicate": predicate,
                                  "evaluator_family": "k8s_extended._evaluate_pod"}}
    for key in ("limits.cpu", "requests.cpu", "limits.memory", "requests.memory"):
        cid = "k8s.namespace.quota_" + key.replace(".", "_")
        check = index[cid]
        assert check.kind == "namespace" and check.target == "resource"
        field = "spec.hard." + key
        out[cid] = {"summary": f"Declare an unscoped namespace-wide ResourceQuota {key} quantity.",
            "steps": [f"Inspect ResourceQuota objects for {key} and their scopes/scopeSelector in the named namespace.",
                      f"Choose an approved {key} quantity from observed demand and capacity; declare it on a namespace-wide ResourceQuota without a limiting selector.",
                      "Apply through the namespace owner, verify new Pod admissions and quota status, then rerun the check."],
            "cli": [{"label": "Inspect namespace quotas", "shell": "bash", "code": "kubectl get resourcequota -n <NAMESPACE> -o yaml"}],
            "iac": {"label": "Update the namespace ResourceQuota", "language": "text", "code": f"Set {field} to a reviewed quantity in an unscoped ResourceQuota for this namespace."},
            "caveats": ["Scoped quotas are a MANUAL result here and do not prove namespace-wide coverage.",
                        "A new quota can reject workloads whose requests or limits are missing or exceed the reviewed capacity; test admission and scheduling."],
            "references": [K8S_REFS["quota"]], "review_status": "approved",
            "field_binding": {"target": check.target, "kind": check.kind, "field": field,
                              "evaluator_family": "k8s_extended._quota_check"}}
    cid = "k8s.serviceaccount.disable_automount"
    check = index[cid]
    assert check.kind == "serviceaccount" and check.target == "resource"
    out[cid] = {"summary": "Disable default API token automount on this ServiceAccount when its workloads do not need Kubernetes API access.",
        "steps": ["Inspect automountServiceAccountToken on the ServiceAccount and every Pod that uses it; identify workloads that call the Kubernetes API.",
                  "Set automountServiceAccountToken=false on the owning ServiceAccount and remove any unneeded Pod override after testing dependent clients.",
                  "Roll out through the ServiceAccount/workload owner, verify Pods and intended API calls, then rerun the check."],
        "cli": [{"label": "Inspect the ServiceAccount", "shell": "bash", "code": "kubectl get serviceaccount <RESOURCE_NAME> -n <NAMESPACE> -o yaml"}],
        "iac": {"label": "Update the ServiceAccount declaration", "language": "text", "code": "Set automountServiceAccountToken: false on the owning ServiceAccount manifest after dependency review."},
        "caveats": ["Pod-level automountServiceAccountToken overrides the ServiceAccount default; this check does not verify each Pod.",
                    "Disabling token mount can break workloads that use the Kubernetes API or projected credentials."],
        "references": [K8S_REFS["service_account"]], "review_status": "approved",
        "field_binding": {"target": check.target, "kind": check.kind, "field": "automountServiceAccountToken",
                          "evaluator_family": "k8s_extended.serviceaccount_automount"}}
    return out


def _claude_k8s_rules(index):
    """Individual regular-container and PodSpec predicates in claude_gcp_k8s_k8s."""
    out = {}
    guidance = {
        "cpu_limits_set": ("spec.containers[*].resources.limits.cpu", "Set a reviewed CPU limit on each flagged regular container using observed demand.", "resources"),
        "cpu_requests_set": ("spec.containers[*].resources.requests.cpu", "Set a reviewed CPU request on each flagged regular container using observed demand and scheduler capacity.", "resources"),
        "memory_limits_set": ("spec.containers[*].resources.limits.memory", "Set a reviewed memory limit on each flagged regular container after testing peak use.", "resources"),
        "memory_requests_set": ("spec.containers[*].resources.requests.memory", "Set a reviewed memory request on each flagged regular container using observed demand and scheduler capacity.", "resources"),
        "liveness_probe_configured": ("spec.containers[*].livenessProbe", "Add a liveness probe that detects a recoverable deadlock without restarting a slow but healthy container.", "probes"),
        "readiness_probe_configured": ("spec.containers[*].readinessProbe", "Add a readiness probe that checks the application's actual ability to accept traffic.", "probes"),
        "no_host_ports": ("spec.containers[*].ports[*].hostPort", "Remove hostPort declarations from flagged regular containers and provide a tested Service or ingress path.", "standards"),
        "no_windows_host_process": ("spec.securityContext.windowsOptions.hostProcess / spec.containers[*].securityContext.windowsOptions.hostProcess", "Set hostProcess=false at Pod and flagged container levels after replacing any approved node-management need.", "standards"),
        "no_added_capabilities": ("spec.containers[*].securityContext.capabilities.add", "Remove unneeded entries from capabilities.add on each flagged regular container.", "security"),
        "capabilities_dropped": ("spec.containers[*].securityContext.capabilities.add/drop", "Remove added capabilities and declare the required drop set, normally ALL, on each flagged regular container.", "standards"),
        "no_net_raw_capability": ("spec.containers[*].securityContext.capabilities.add", "Remove NET_RAW, CAP_NET_RAW or ALL from capabilities.add on each flagged regular container.", "security"),
        "no_root_user": ("spec.securityContext.runAsUser / spec.containers[*].securityContext.runAsUser", "Set an approved positive runAsUser for each flagged regular container and test image filesystem permissions.", "security"),
        "no_secret_env": ("spec.containers[*].env[].valueFrom.secretKeyRef", "Move flagged Secret references from environment variables to a read-only Secret volume or reviewed CSI mount; update the application to read files.", "secrets"),
        "no_host_ipc": ("spec.hostIPC", "Set hostIPC=false in the owning PodSpec and replace any host IPC dependency.", "standards"),
        "no_host_pid": ("spec.hostPID", "Set hostPID=false in the owning PodSpec and replace any host process namespace dependency.", "standards"),
        "runtime_default_seccomp": ("spec.securityContext.seccompProfile.type / spec.containers[*].securityContext.seccompProfile.type", "Set Pod-level RuntimeDefault seccomp, or set it on every regular container, and verify container overrides.", "seccomp"),
    }
    for slug, (field, action, reference) in guidance.items():
        cid = "k8s.claude.pod." + slug
        check = index[cid]
        assert check.kind == "pod" and check.target == "resource"
        inspect_code = ("kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.metadata.ownerReferences}'"
                        if slug == "no_secret_env" else "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o yaml")
        inspect_step = ("Use the finding's flagged variable names to locate the owning Pod template; inspect only Pod ownerReferences and do not print environment values."
                        if slug == "no_secret_env" else f"Inspect {field} on the named Pod and identify its owning controller or manifest.")
        out[cid] = {"summary": f"Update {field} on this Pod's owning template.",
            "steps": [inspect_step,
                      action, "Roll out the reviewed owner template, test affected workloads and admission, then rerun the declaration check."],
            "cli": [{"label": "Inspect this Pod and owner references", "shell": "bash", "code": inspect_code}],
            "iac": {"label": "Update the durable Pod template", "language": "text", "code": f"Set {field} in the owning controller/Pod manifest or Helm values after review."},
            "caveats": ["The evaluator reads regular Pod containers and declared fields, not init/ephemeral container runtime state or admission enforcement.",
                        "Changing resource limits, probes, credentials or security context can restart or interrupt the workload; test the exact dependency first."],
            "references": [K8S_REFS[reference]], "review_status": "approved",
            "field_binding": {"target": check.target, "kind": check.kind, "field": field,
                              "evaluator_family": "claude_gcp_k8s_k8s.pod_rule"}}
    cid = "k8s.claude.pod.no_literal_secret_env"
    check = index[cid]
    assert check.kind == "pod" and check.target == "resource"
    out[cid] = {"summary": "Move the flagged literal credential-like environment value into a managed Secret and rotate the credential.",
        "steps": ["Inspect only the flagged environment variable names and owning Pod template; do not expose or copy their values from running containers.",
                  "Create an owner-approved Secret or external secret mount, change the application to read the mounted file and remove each literal value from the template.",
                  "Rotate the old credential through its actual issuer, roll out the new Pod and verify dependent access before rerunning the check."],
        "cli": [{"label": "Inspect only the Pod owner reference", "shell": "bash", "code": "kubectl get pod <RESOURCE_NAME> -n <NAMESPACE> -o jsonpath='{.metadata.ownerReferences}'"}],
        "iac": {"label": "Update the owning workload and secret delivery", "language": "text", "code": "Remove the flagged literal env value from regular/init containers; reference a reviewed Secret volume or CSI mount and rotate the source credential."},
        "caveats": ["The collector retains only variable names and value lengths; this guidance never displays or interpolates secret contents.",
                    "Credential rotation and app configuration changes can interrupt service; a name heuristic does not prove the literal is a secret."],
        "references": [K8S_REFS["secrets"]], "review_status": "approved",
        "field_binding": {"target": check.target, "kind": check.kind, "field": "spec.containers/initContainers[].env[].value/value_length",
                          "evaluator_family": "claude_gcp_k8s_k8s.literal_secret_env"}}
    return out


def build():
    reverse = {cid: spec for spec, cid in components.CANONICAL_SPECS.items()}
    rules = {}
    for check in CHECKS:
        if check.id in reverse:
            rules[check.id] = _component(check, reverse[check.id])
        elif check.id in FIELD_SPECS:
            rules[check.id] = _scalar(check, FIELD_SPECS[check.id])
    index = {check.id: check for check in CHECKS}
    for family in (_network_rules, _workload_rules, _cluster_rules, _extended_rules, _claude_k8s_rules):
        next_rules = family(index)
        overlap = sorted(set(rules).intersection(next_rules))
        if overlap:
            raise ValueError(f"Remediation families overlap at {family.__name__}: {overlap[:10]}")
        rules.update(next_rules)
    return rules


if __name__ == "__main__":
    rules = build()
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=OUTPUT.parent,
                                     prefix=".remediation_details-", suffix=".tmp",
                                     delete=False) as published:
        published.write(json.dumps(rules, indent=2, sort_keys=True) + "\n")
        staged = Path(published.name)
    staged.replace(OUTPUT)
    print(f"Generated {len(rules)} field-derived remediation drafts in {OUTPUT}")
