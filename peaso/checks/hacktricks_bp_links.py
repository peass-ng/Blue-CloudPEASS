"""HackTricks Cloud Best Practices: existing Prowler/Powerpipe-derived checks that
already implement a HackTricks Cloud technique.

They are linked to the specific HackTricks page (framework reference only) instead of
being re-implemented in a hacktricks_bp_* module. Every id must exist in CHECKS
(enforced by tests/test_peaso_checks_hacktricks_bp.py).
"""
from __future__ import annotations

from .hacktricks_bp_common import link

AWS = "pentesting-cloud/aws-security/"
GCP = "pentesting-cloud/gcp-security/"
AZ = "pentesting-cloud/azure-security/"
K8S = "pentesting-cloud/kubernetes-security/"

LINKS = {
    # AWS
    "aws.b.cognito.no_guest_identities": (AWS + "aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum/README.md",
                                          AWS + "aws-services/aws-cognito-enum/cognito-identity-pools.md"),
    "aws.b.codebuild.nonprivileged": (AWS + "aws-privilege-escalation/aws-codebuild-privesc/README.md",),
    "aws.c2b.lambda.no_cross_account_layers": (AWS + "aws-persistence/aws-lambda-persistence/aws-lambda-layers-persistence.md",),
    "aws.lambda.function_url_authentication": (AWS + "aws-post-exploitation/aws-lambda-post-exploitation/aws-lambda-function-url-public-exposure.md",
                                               AWS + "aws-unauthenticated-enum-access/aws-lambda-unauthenticated-access/README.md"),
    "aws.c2b.lambda.policy_not_public": (AWS + "aws-unauthenticated-enum-access/aws-lambda-unauthenticated-access/README.md",),
    "aws.claude_a.ebs.snapshot_not_public": (AWS + "aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ebs-snapshot-dump.md",),
    "aws.claude_a.ec2.ami_not_public": (AWS + "aws-unauthenticated-enum-access/aws-ec2-unauthenticated-enum/README.md",),
    "aws.cb.rds.instance_snapshot_not_public_prowler": (AWS + "aws-unauthenticated-enum-access/aws-rds-unauthenticated-enum/README.md",),
    "aws.cb.rds.cluster_snapshot_not_public_prowler": (AWS + "aws-unauthenticated-enum-access/aws-rds-unauthenticated-enum/README.md",),
    "aws.cb.sns.topic_not_publicly_accessible_prowler": (AWS + "aws-unauthenticated-enum-access/aws-sns-unauthenticated-enum/README.md",),
    "aws.cb.sqs.queue_not_public_prowler": (AWS + "aws-unauthenticated-enum-access/aws-sqs-unauthenticated-enum/README.md",),
    "aws.cb.secretsmanager.policy_not_public": (AWS + "aws-post-exploitation/aws-secrets-manager-post-exploitation/README.md",),
    "aws.claude_a.s3.prowler_public_access": (AWS + "aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum/README.md",),
    # Azure
    "azure.claude.acr_admin_user_disabled": (AZ + "az-privilege-escalation/az-container-registry-privesc.md",),
    "azure.storage.no_blob_public_access": (AZ + "az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md",),
    # GCP
    "gcp.claude.workload_identity_provider.multi_tenant_condition": (GCP + "gcp-privilege-escalation/gcp-workload-identity-federation-privesc.md",),
    "gcp.claude.secret.not_public": (GCP + "gcp-unauthenticated-enum-and-access/gcp-secret-manager-unauthenticated-enum.md",),
    "gcp.claude.instance.sa_no_service_account_impersonate_permission": (GCP + "gcp-privilege-escalation/gcp-iam-privesc.md",),
    # Native-only checks (ledgers/checks-native-only.md) whose attack a HackTricks page documents.
    "gcp.gke.node_pools_gke_metadata": (GCP + "gcp-privilege-escalation/gcp-container-privesc.md",
                                        K8S + "kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md"),
    "gcp.gke.workload_identity": (K8S + "kubernetes-post-exploitation/kubernetes-pivoting-to-clouds.md",
                                  GCP + "gcp-privilege-escalation/gcp-container-privesc.md"),
    "gcp.ports.storage_bucket_not_publicly_accessible": (GCP + "gcp-unauthenticated-enum-and-access/gcp-storage-unauthenticated-enum/README.md",),
    "gcp.storage.public_access_prevention": (GCP + "gcp-unauthenticated-enum-and-access/gcp-storage-unauthenticated-enum/README.md",),
    "k8s.pod.no_host_namespaces": (K8S + "kubernetes-privilege-escalation/workload-and-pod-access.md",
                                   K8S + "kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md"),
    "k8s.ports.podtemplate.host_namespaces": (K8S + "kubernetes-privilege-escalation/workload-and-pod-access.md",),
    "k8s.ports.podtemplate.host_network": (K8S + "kubernetes-privilege-escalation/workload-and-pod-access.md",),
    "k8s.pod.restrict_added_capabilities": (K8S + "kubernetes-post-exploitation/attacking-kubernetes-from-inside-a-pod.md",),
    **{f"k8s.ports.{kind}.container_argument_api_server_anonymous_auth_disabled": (K8S + "kubernetes-unauthenticated-access/README.md",)
       for kind in ("cronjob", "daemonset", "deployment", "job", "replicaset", "replicationcontroller", "statefulset")},
}

for _check_id, _pages in LINKS.items():
    link(_check_id, *_pages)
