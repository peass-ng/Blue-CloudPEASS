"""Reviewed, resource-scoped GCP permission grants to the acting principal.

IAM policy writes and policy-grant DDL are both supported when the catalog
declares their complete requirements. Mutation authority alone does not
identify a new permission. The optional
collection attests the exact resource, grantee, granted permissions, and before/
after authorization result. Incomplete or conflicting records create no target.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timezone

from . import Grant, Node, inventory_status, items

COLLECTION = "gcp_resource_self_grant_evidence"
SECRET_TECHNIQUE = "gcp-secretmanager-secrets-setiampolicy-secret-self-grant"
TOPIC_TECHNIQUE = "gcp-pubsub-topics-setiampolicy-topic-self-grant"
SUBSCRIPTION_TECHNIQUE = "gcp-pubsub-subscriptions-setiampolicy-subscription-self-grant"
KMS_TECHNIQUE = "gcp-cloudkms-cryptokeys-setiampolicy-crypto-key-self-grant"
ARTIFACT_TECHNIQUE = "gcp-artifactregistry-repositories-setiampolicy-repository-self-grant"
CONTAINERANALYSIS_NOTE_TECHNIQUE = "gcp-containeranalysis-notes-setiampolicy-note-self-grant"
DATACATALOG_TAG_TECHNIQUE = "gcp-datacatalog-categories-setiampolicy-policy-tag-self-grant"
DATACATALOG_TAXONOMY_TECHNIQUE = "gcp-datacatalog-taxonomies-setiampolicy-taxonomy-self-grant"
METASTORE_SERVICE_TECHNIQUE = "gcp-metastore-services-setiampolicy-metastore-service-self-grant"
ANALYTICSHUB_EXCHANGE_TECHNIQUE = "gcp-analyticshub-dataexchanges-setiampolicy-data-exchange-self-grant"
ANALYTICSHUB_LISTING_TECHNIQUE = "gcp-analyticshub-listings-setiampolicy-listing-self-grant"
BIGLAKE_CATALOG_TECHNIQUE = "gcp-biglake-catalogs-setiampolicy-catalog-self-grant"
BIGLAKE_NAMESPACE_TECHNIQUE = "gcp-biglake-namespaces-setiampolicy-namespace-self-grant"
BIGLAKE_TABLE_TECHNIQUE = "gcp-biglake-tables-setiampolicy-table-self-grant"
BIGQUERY_DATASET_TECHNIQUE = "gcp-bigquery-datasets-setiampolicy-dataset-iam-self-grant"
BIGQUERY_DATASET_UPDATE_TECHNIQUE = "gcp-bigquery-datasets-update-dataset-acl-self-grant"
BIGQUERY_ROW_POLICY_TECHNIQUE = "gcp-bigquery-row-policy-create-self-grant"
BIGQUERY_TABLE_TECHNIQUE = "gcp-bigquery-tables-setiampolicy-table-self-grant"
BIGQUERY_CONNECTION_TECHNIQUE = "gcp-bigquery-connections-setiampolicy-connection-self-grant"
CONNECTOR_CONNECTION_TECHNIQUE = "gcp-connectors-connections-setiampolicy-connection-self-grant"
CONTACT_CENTER_VIEW_TECHNIQUE = "gcp-contactcenterinsights-authorizedviews-setiampolicy-self-grant"
DISCOVERYENGINE_COLLECTION_TECHNIQUE = "gcp-discoveryengine-collections-setiampolicy-collection-self-grant"
DISCOVERYENGINE_DATA_STORE_TECHNIQUE = "gcp-discoveryengine-datastores-setiampolicy-data-store-self-grant"
DISCOVERYENGINE_ENGINE_TECHNIQUE = "gcp-discoveryengine-engines-setiampolicy-engine-self-grant"
FLEET_MEMBERSHIP_TECHNIQUE = "gcp-gkehub-memberships-setiampolicy-membership-self-grant"
HEALTHCARE_CONSENT_TECHNIQUE = "gcp-healthcare-consentstores-setiampolicy-consent-store-self-grant"
HEALTHCARE_DATASET_TECHNIQUE = "gcp-healthcare-datasets-setiampolicy-dataset-self-grant"
HEALTHCARE_DICOM_TECHNIQUE = "gcp-healthcare-dicomstores-setiampolicy-dicom-store-self-grant"
HEALTHCARE_FHIR_TECHNIQUE = "gcp-healthcare-fhirstores-setiampolicy-fhir-store-self-grant"
HEALTHCARE_HL7V2_TECHNIQUE = "gcp-healthcare-hl7v2stores-setiampolicy-hl7v2-store-self-grant"
IAP_INSTANCE_TECHNIQUE = "gcp-iap-tunnelinstances-setiampolicy-instance-self-grant"
IAP_ZONE_TECHNIQUE = "gcp-iap-tunnelzones-setiampolicy-zone-self-grant"
IDENTITYPLATFORM_TENANT_TECHNIQUE = "gcp-identitytoolkit-tenants-setiampolicy-tenant-self-grant"
KRM_API_HOST_TECHNIQUE = "gcp-krmapihosting-krmapihosts-setiampolicy-krm-api-host-self-grant"
LOGGING_VIEW_TECHNIQUE = "gcp-logging-views-setiampolicy-self-grant"
FOLDER_TECHNIQUE = "gcp-resourcemanager-folders-setiampolicy"
ORGANIZATION_TECHNIQUE = "gcp-resourcemanager-organizations-setiampolicy"
ORGANIZATION_DENY_TECHNIQUE = "gcp-resourcemanager-organizations-setiampolicy-deny-admin"
ORGANIZATION_ROLE_TECHNIQUE = "gcp-resourcemanager-organizations-setiampolicy-role-admin"
PROJECT_TECHNIQUE = "gcp-resourcemanager-projects-setiampolicy"
PROJECT_DELETER_TECHNIQUE = "gcp-resourcemanager-projects-setiampolicy-project-delete"
NCC_GROUP_TECHNIQUE = "gcp-networkconnectivity-groups-setiampolicy-group-self-grant"
NCC_HUB_GROUP_USE_TECHNIQUE = "gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant"
NETWORKSECURITY_ADDRESS_GROUP_TECHNIQUE = "gcp-networksecurity-addressgroups-setiampolicy-address-group-self-grant"
NETWORKSECURITY_AUTHORIZATION_POLICY_TECHNIQUE = "gcp-networksecurity-authorizationpolicies-setiampolicy-authorization-policy-self-grant"
NETWORKSECURITY_AUTHZ_POLICY_TECHNIQUE = "gcp-networksecurity-authzpolicies-setiampolicy-authz-policy-self-grant"
NETWORKSECURITY_CLIENT_TLS_POLICY_TECHNIQUE = "gcp-networksecurity-clienttlspolicies-setiampolicy-client-tls-policy-self-grant"
NETWORKSECURITY_SERVER_TLS_POLICY_TECHNIQUE = "gcp-networksecurity-servertlspolicies-setiampolicy-server-tls-policy-self-grant"
BIGTABLE_AUTHORIZED_VIEW_TECHNIQUE = "gcp-bigtable-authorizedviews-setiampolicy-authorized-view-self-grant"
BIGTABLE_MATERIALIZED_VIEW_TECHNIQUE = "gcp-bigtable-materializedviews-setiampolicy-materialized-view-self-grant"
BIGTABLE_TABLE_TECHNIQUE = "gcp-bigtable-tables-setiampolicy-table-self-grant"
BIGTABLE_BACKUP_TECHNIQUE = "gcp-bigtable-backups-setiampolicy-backup-self-grant"
BIGTABLE_INSTANCE_TECHNIQUE = "gcp-bigtable-instances-setiampolicy-instance-self-grant"
BIGTABLE_INSTANCE_ADMIN_TECHNIQUE = "gcp-bigtable-instances-setiampolicy-instance-admin-self-grant"
DISK_TECHNIQUE = "gcp-compute-disks-setiampolicy-disk-self-grant"
IMAGE_TECHNIQUE = "gcp-compute-images-setiampolicy-image-self-grant"
INSTANCE_TECHNIQUE = "gcp-compute-instances-setiampolicy"
MACHINE_IMAGE_TECHNIQUE = "gcp-compute-machineimages-setiampolicy-machine-image-self-grant"
RECOVERABLE_SNAPSHOT_TECHNIQUE = "gcp-compute-recoverablesnapshots-setiampolicy-recoverable-snapshot-self-grant"
SNAPSHOT_TECHNIQUE = "gcp-compute-snapshots-setiampolicy-snapshot-self-grant"
PRIVATECA_POOL_TECHNIQUE = "gcp-privateca-capools-setiampolicy-ca-pool-self-grant"
DOMAINS_REGISTRATION_TECHNIQUE = "gcp-domains-registrations-setiampolicy-self-grant"
PROSPECTIVE_RULES = {
    IAP_INSTANCE_TECHNIQUE: ("iap_tunnel_policy", "iap.tunnelInstances.setIamPolicy",
                             "iap.tunnelInstances.accessViaIAP"),
    IAP_ZONE_TECHNIQUE: ("iap_tunnel_policy", "iap.tunnelZones.setIamPolicy",
                         "iap.tunnelInstances.accessViaIAP"),
    IDENTITYPLATFORM_TENANT_TECHNIQUE: ("identityplatform_tenant",
        "identitytoolkit.tenants.setIamPolicy", "firebaseauth.users.update"),
    KRM_API_HOST_TECHNIQUE: ("krm_api_host",
        "krmapihosting.krmApiHosts.setIamPolicy", "krmapihosting.krmApiHosts.update"),
    LOGGING_VIEW_TECHNIQUE: ("logging_view", "logging.views.setIamPolicy", "logging.views.access"),
    FOLDER_TECHNIQUE: ("folder", "resourcemanager.folders.setIamPolicy", "resourcemanager.folders.update"),
    ORGANIZATION_TECHNIQUE: ("organization", "resourcemanager.organizations.setIamPolicy",
                             "orgpolicy.policy.set"),
    ORGANIZATION_DENY_TECHNIQUE: ("organization", "resourcemanager.organizations.setIamPolicy",
                                  "iam.denypolicies.create"),
    ORGANIZATION_ROLE_TECHNIQUE: ("organization", "resourcemanager.organizations.setIamPolicy",
                                  "iam.roles.create"),
    PROJECT_TECHNIQUE: ("project", "resourcemanager.projects.setIamPolicy",
                        "compute.instances.create"),
    PROJECT_DELETER_TECHNIQUE: ("project", "resourcemanager.projects.setIamPolicy",
                                "resourcemanager.projects.delete"),
    DOMAINS_REGISTRATION_TECHNIQUE: ("domains_registration", "domains.registrations.setIamPolicy",
                                      "domains.registrations.configureDns"),
    PRIVATECA_POOL_TECHNIQUE: ("ca_pool", "privateca.caPools.setIamPolicy", "privateca.certificates.create"),
    INSTANCE_TECHNIQUE: ("instance", "compute.instances.setIamPolicy", "compute.instances.osAdminLogin"),
    MACHINE_IMAGE_TECHNIQUE: ("machine_image", "compute.machineImages.setIamPolicy", "compute.machineImages.useReadOnly"),
    RECOVERABLE_SNAPSHOT_TECHNIQUE: ("recoverable_snapshot", "compute.recoverableSnapshots.setIamPolicy",
                                     "compute.recoverableSnapshots.recover"),
    SNAPSHOT_TECHNIQUE: ("snapshot", "compute.snapshots.setIamPolicy", "compute.snapshots.useReadOnly"),
    DISK_TECHNIQUE: ("disk", "compute.disks.setIamPolicy", "compute.disks.useReadOnly"),
    IMAGE_TECHNIQUE: ("image", "compute.images.setIamPolicy", "compute.images.useReadOnly"),
    BIGTABLE_INSTANCE_ADMIN_TECHNIQUE: ("bigtable_instance", "bigtable.instances.setIamPolicy",
                                        "bigtable.instances.update"),
    BIGTABLE_INSTANCE_TECHNIQUE: ("bigtable_instance", "bigtable.instances.setIamPolicy",
                                  "bigtable.tables.readRows"),
    BIGTABLE_BACKUP_TECHNIQUE: ("bigtable_backup", "bigtable.backups.setIamPolicy",
                                "bigtable.backups.restore"),
    BIGTABLE_AUTHORIZED_VIEW_TECHNIQUE: ("bigtable_authorized_view",
        "bigtable.authorizedViews.setIamPolicy", "bigtable.authorizedViews.readRows"),
    BIGTABLE_MATERIALIZED_VIEW_TECHNIQUE: ("bigtable_materialized_view",
        "bigtable.materializedViews.setIamPolicy", "bigtable.materializedViews.readRows"),
    BIGTABLE_TABLE_TECHNIQUE: ("bigtable_table", "bigtable.tables.setIamPolicy",
                               "bigtable.tables.readRows"),
    SECRET_TECHNIQUE: ("secret", "secretmanager.secrets.setIamPolicy", "secretmanager.versions.access"),
    TOPIC_TECHNIQUE: ("pubsub_topic", "pubsub.topics.setIamPolicy", "pubsub.topics.publish"),
    SUBSCRIPTION_TECHNIQUE: ("pubsub_subscription", "pubsub.subscriptions.setIamPolicy",
                             "pubsub.subscriptions.consume"),
    KMS_TECHNIQUE: ("kms_key", "cloudkms.cryptoKeys.setIamPolicy",
                    "cloudkms.cryptoKeyVersions.useToDecrypt"),
    ARTIFACT_TECHNIQUE: ("artifact_repository", "artifactregistry.repositories.setIamPolicy",
                         "artifactregistry.repositories.uploadArtifacts"),
    CONTAINERANALYSIS_NOTE_TECHNIQUE: ("containeranalysis_note", "containeranalysis.notes.setIamPolicy",
                                       "containeranalysis.notes.attachOccurrence"),
    DATACATALOG_TAG_TECHNIQUE: ("datacatalog_policy_tag", "datacatalog.categories.setIamPolicy",
                                "datacatalog.categories.fineGrainedGet"),
    DATACATALOG_TAXONOMY_TECHNIQUE: ("datacatalog_taxonomy", "datacatalog.taxonomies.setIamPolicy",
                                     "datacatalog.categories.fineGrainedGet"),
    METASTORE_SERVICE_TECHNIQUE: ("metastore_service", "metastore.services.setIamPolicy",
                                  "metastore.services.use"),
    ANALYTICSHUB_EXCHANGE_TECHNIQUE: ("analyticshub_data_exchange",
                                     "analyticshub.dataExchanges.setIamPolicy",
                                     "analyticshub.dataExchanges.subscribe"),
    ANALYTICSHUB_LISTING_TECHNIQUE: ("analyticshub_listing",
                                    "analyticshub.listings.setIamPolicy",
                                    "analyticshub.listings.subscribe"),
    BIGLAKE_CATALOG_TECHNIQUE: ("biglake_catalog", "biglake.catalogs.setIamPolicy",
                                 "biglake.catalogs.get"),
    BIGLAKE_NAMESPACE_TECHNIQUE: ("biglake_namespace", "biglake.namespaces.setIamPolicy",
                                   "biglake.namespaces.get"),
    BIGLAKE_TABLE_TECHNIQUE: ("biglake_table", "biglake.tables.setIamPolicy",
                               "biglake.tables.get"),
    BIGQUERY_DATASET_TECHNIQUE: ("bigquery_dataset", "bigquery.datasets.setIamPolicy",
                                  "bigquery.tables.getData"),
    BIGQUERY_DATASET_UPDATE_TECHNIQUE: ("bigquery_dataset", "bigquery.datasets.update",
                                         "bigquery.tables.getData"),
    BIGQUERY_ROW_POLICY_TECHNIQUE: ("bigquery_row_policy_inventory", "bigquery.rowAccessPolicies.create",
                                    "bigquery.rowAccessPolicies.getFilteredData"),
    BIGQUERY_TABLE_TECHNIQUE: ("bigquery_table", "bigquery.tables.setIamPolicy",
                               "bigquery.tables.getData"),
    BIGQUERY_CONNECTION_TECHNIQUE: ("bigquery_connection", "bigquery.connections.setIamPolicy",
                                    "bigquery.connections.use"),
    CONNECTOR_CONNECTION_TECHNIQUE: ("integration_connection", "connectors.connections.setIamPolicy",
                                     "connectors.connections.executeSqlQuery"),
    CONTACT_CENTER_VIEW_TECHNIQUE: ("contact_center_authorized_view", "contactcenterinsights.authorizedViews.setIamPolicy",
                                    "contactcenterinsights.authorizedViews.get"),
    DISCOVERYENGINE_COLLECTION_TECHNIQUE: ("discoveryengine_collection", "discoveryengine.collections.setIamPolicy",
                                           "discoveryengine.collections.get"),
    DISCOVERYENGINE_DATA_STORE_TECHNIQUE: ("discoveryengine_data_store", "discoveryengine.dataStores.setIamPolicy",
                                           "discoveryengine.dataStores.update"),
    DISCOVERYENGINE_ENGINE_TECHNIQUE: ("discoveryengine_engine", "discoveryengine.engines.setIamPolicy",
                                       "discoveryengine.engines.update"),
    FLEET_MEMBERSHIP_TECHNIQUE: ("fleet_membership", "gkehub.memberships.setIamPolicy",
                                 "gkehub.gateway.generateCredentials"),
    HEALTHCARE_CONSENT_TECHNIQUE: ("healthcare_consent_store", "healthcare.consentStores.setIamPolicy",
                                   "healthcare.consents.get"),
    HEALTHCARE_DATASET_TECHNIQUE: ("healthcare_dataset", "healthcare.datasets.setIamPolicy",
                                   "healthcare.fhirStores.searchResources"),
    HEALTHCARE_DICOM_TECHNIQUE: ("healthcare_dicom_store", "healthcare.dicomStores.setIamPolicy",
                                 "healthcare.dicomStores.dicomWebRead"),
    HEALTHCARE_FHIR_TECHNIQUE: ("healthcare_fhir_store", "healthcare.fhirStores.setIamPolicy",
                                "healthcare.fhirResources.get"),
    HEALTHCARE_HL7V2_TECHNIQUE: ("healthcare_hl7v2_store", "healthcare.hl7V2Stores.setIamPolicy",
                                 "healthcare.hl7V2Messages.list"),
    NCC_GROUP_TECHNIQUE: ("network_connectivity_hub_group", "networkconnectivity.groups.setIamPolicy",
                           "networkconnectivity.groups.use"),
    NCC_HUB_GROUP_USE_TECHNIQUE: ("network_connectivity_hub", "networkconnectivity.hubs.setIamPolicy",
                                   "networkconnectivity.groups.use"),
    NETWORKSECURITY_ADDRESS_GROUP_TECHNIQUE: (
        "network_security_address_group", "networksecurity.addressGroups.setIamPolicy",
        "networksecurity.addressGroups.update"),
    NETWORKSECURITY_AUTHORIZATION_POLICY_TECHNIQUE: (
        "network_security_authorization_policy", "networksecurity.authorizationPolicies.setIamPolicy",
        "networksecurity.authorizationPolicies.update"),
    NETWORKSECURITY_AUTHZ_POLICY_TECHNIQUE: (
        "ngfw_authz_policy", "networksecurity.authzPolicies.setIamPolicy",
        "networksecurity.authzPolicies.update"),
    NETWORKSECURITY_CLIENT_TLS_POLICY_TECHNIQUE: (
        "network_security_client_tls_policy", "networksecurity.clientTlsPolicies.setIamPolicy",
        "networksecurity.clientTlsPolicies.update"),
    NETWORKSECURITY_SERVER_TLS_POLICY_TECHNIQUE: (
        "network_security_server_tls_policy", "networksecurity.serverTlsPolicies.setIamPolicy",
        "networksecurity.serverTlsPolicies.update"),
}


def folder_candidates(model):
    """Active, uniquely identified folders collected at their own scope."""
    nodes = {}
    rows = list(items(model.snapshot, "folder"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        resource = model._norm_scope(item.get("name"))
        if (not isinstance(resource, str) or not re.fullmatch(r"folders/[1-9][0-9]*", resource)
                or model._norm_scope(scope) != resource or counts[item["name"]] != 1
                or item.get("state") != "ACTIVE"
                or not re.fullmatch(r"(?:folders|organizations)/[1-9][0-9]*",
                                    str(item.get("parent") or ""))):
            continue
        ident = "gcp_verified_authority:possible-folder-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", resource,
                            f"Possible Folder Admin self-grant on {resource}",
                            attrs={"scope": resource, "resource": resource,
                                   "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": FOLDER_TECHNIQUE}, entity=True)
    return nodes


def organization_candidates(model, *, deny_admin=False, role_admin=False):
    """Active, uniquely identified organizations collected at their own scope."""
    nodes = {}
    rows = list(items(model.snapshot, "organization"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        resource = model._norm_scope(item.get("name"))
        if (not isinstance(resource, str) or not re.fullmatch(r"organizations/[1-9][0-9]*", resource)
                or model._norm_scope(scope) != resource or counts[item["name"]] != 1
                or item.get("state") != "ACTIVE"):
            continue
        technique = (ORGANIZATION_DENY_TECHNIQUE if deny_admin else
                     ORGANIZATION_ROLE_TECHNIQUE if role_admin else ORGANIZATION_TECHNIQUE)
        role_name = ("Deny Admin" if deny_admin else
                     "Organization Role Administrator" if role_admin else "Organization Policy Admin")
        slug = "org-deny-admin" if deny_admin else "org-role-admin" if role_admin else "org-policy"
        ident = f"gcp_verified_authority:possible-{slug}-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", resource,
                            f"Possible {role_name} self-grant on {resource}",
                            attrs={"scope": resource, "resource": resource,
                                   "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": technique}, entity=True)
    return nodes


def project_candidates(model, *, deleter=False):
    """Active projects identified by one collected Resource Manager record."""
    nodes = {}
    rows = list(items(model.snapshot, "project"))
    counts = Counter((scope, item.get("projectId")) for scope, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        project_id = item.get("projectId")
        if (not isinstance(project_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id)
                or project != f"projects/{project_id}"
                or counts[(scope, project_id)] != 1 or item.get("state") != "ACTIVE"):
            continue
        technique = PROJECT_DELETER_TECHNIQUE if deleter else PROJECT_TECHNIQUE
        role_name = "Project Deleter" if deleter else "Editor"
        slug = "project-delete" if deleter else "project-editor"
        ident = f"gcp_verified_authority:possible-{slug}-self-grant:" + project
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible {role_name} self-grant on {project}",
                            attrs={"scope": project, "resource": project,
                                   "policy_resource": project,
                                   "prospective_self_grant": True,
                                   "prospective_technique": technique}, entity=True)
    return nodes


def machine_image_candidates(model):
    """Ready machine images with a unique global identity."""
    nodes = {}
    rows = list(items(model.snapshot, "machine_image"))
    counts = Counter(item.get("selfLink") for _, item in rows if isinstance(item.get("selfLink"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        link = item.get("selfLink")
        if not isinstance(link, str) or counts[link] != 1:
            continue
        match = re.fullmatch(
            r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/global/machineImages/[^/]+)",
            link)
        if not match:
            continue
        resource = model._norm_scope(match.group(1))
        if (not resource.startswith(project + "/") or item.get("name") != resource.rsplit("/", 1)[-1]):
            continue
        ident = "gcp_verified_authority:possible-machine-image-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible machine image read-only use on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "image_status": item.get("status"),
                                   "prospective_self_grant": True,
                                   "prospective_technique": MACHINE_IMAGE_TECHNIQUE}, entity=True)
    return nodes


def recoverable_snapshot_candidates(model):
    """Ready recoverable snapshots with a unique generated global identity."""
    nodes = {}
    rows = list(items(model.snapshot, "recoverable_snapshot"))
    counts = Counter(item.get("selfLink") for _, item in rows if isinstance(item.get("selfLink"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        link = item.get("selfLink")
        if not isinstance(link, str) or counts[link] != 1:
            continue
        match = re.fullmatch(
            r"https://(?:www|compute)\.googleapis\.com/compute/beta/(projects/[^/]+/global/recoverableSnapshots/[^/]+)",
            link)
        if not match:
            continue
        resource = model._norm_scope(match.group(1))
        if not resource.startswith(project + "/") or item.get("name") != resource.rsplit("/", 1)[-1]:
            continue
        ident = "gcp_verified_authority:possible-recoverable-snapshot-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible recoverable snapshot recovery on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "snapshot_status": item.get("status"),
                                   "prospective_self_grant": True,
                                   "prospective_technique": RECOVERABLE_SNAPSHOT_TECHNIQUE}, entity=True)
    return nodes


def snapshot_candidates(model):
    """Ready global or regional snapshots with unique exact identities."""
    nodes = {}
    rows = list(items(model.snapshot, "snapshot"))
    counts = Counter(item.get("selfLink") for _, item in rows if isinstance(item.get("selfLink"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        link = item.get("selfLink")
        if not isinstance(link, str) or counts[link] != 1:
            continue
        match = re.fullmatch(
            r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/(?:global|regions/[^/]+)/snapshots/[^/]+)",
            link)
        if not match:
            continue
        resource = model._norm_scope(match.group(1))
        region = resource.split("/regions/", 1)[1].split("/", 1)[0] if "/regions/" in resource else None
        if (not resource.startswith(project + "/") or item.get("name") != resource.rsplit("/", 1)[-1]
                or (region and str(item.get("region") or "").rsplit("/", 1)[-1] != region)):
            continue
        ident = "gcp_verified_authority:possible-snapshot-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible snapshot read-only use on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "snapshot_status": item.get("status"),
                                   "prospective_self_grant": True,
                                   "prospective_technique": SNAPSHOT_TECHNIQUE}, entity=True)
    return nodes


def instance_candidates(model):
    """Exact Compute instances where an instance-level OS Admin role is grantable."""
    nodes = {}
    rows = list(items(model.snapshot, "instance"))
    counts = Counter(item.get("selfLink") for _, item in rows if isinstance(item.get("selfLink"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        link = item.get("selfLink")
        if not isinstance(link, str) or counts[link] != 1:
            continue
        match = re.fullmatch(
            r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/zones/[^/]+/instances/[^/]+)",
            link)
        if not match:
            continue
        resource = model._norm_scope(match.group(1))
        if (not resource.startswith(project + "/") or item.get("name") != resource.rsplit("/", 1)[-1]
                or str(item.get("zone") or "").rsplit("/", 1)[-1] != resource.split("/zones/", 1)[1].split("/", 1)[0]):
            continue
        ident = "gcp_verified_authority:possible-instance-osadmin-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible OS administrator login permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": INSTANCE_TECHNIQUE}, entity=True)
    return nodes


def disk_candidates(model):
    """Zonal and regional disks with a complete resource identity and IAM policy."""
    nodes = {}
    rows = list(items(model.snapshot, "disk"))
    counts = Counter(item.get("selfLink") for _, item in rows if isinstance(item.get("selfLink"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        link = item.get("selfLink")
        if not isinstance(link, str) or counts[link] != 1:
            continue
        match = re.fullmatch(
            r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/(?:zones|regions)/[^/]+/disks/[^/]+)",
            link)
        if not match:
            continue
        resource = model._norm_scope(match.group(1))
        location_kind = "zones" if "/zones/" in resource else "regions"
        if (not resource.startswith(project + "/")
                or resource not in model.disks
                or item.get("name") != resource.rsplit("/", 1)[-1]
                or str(item.get("zone" if location_kind == "zones" else "region") or "").rsplit("/", 1)[-1] !=
                resource.split("/" + location_kind + "/", 1)[-1].split("/", 1)[0]):
            continue
        ident = "gcp_verified_authority:possible-disk-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible disk read-only use on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": DISK_TECHNIQUE}, entity=True)
    return nodes


def image_candidates(model):
    """Ready images with a complete global identity and an IAM policy."""
    nodes = {}
    rows = list(items(model.snapshot, "image"))
    counts = Counter(item.get("selfLink") for _, item in rows if isinstance(item.get("selfLink"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        link = item.get("selfLink")
        if not isinstance(link, str) or counts[link] != 1:
            continue
        match = re.fullmatch(
            r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/global/images/[^/]+)",
            link)
        if not match:
            continue
        resource = model._norm_scope(match.group(1))
        if (not resource.startswith(project + "/") or resource not in model.images
                or item.get("name") != resource.rsplit("/", 1)[-1]):
            continue
        ident = "gcp_verified_authority:possible-image-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible image read-only use on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "image_status": item.get("status"),
                                   "prospective_self_grant": True,
                                   "prospective_technique": IMAGE_TECHNIQUE}, entity=True)
    return nodes


def bigtable_instance_admin_candidates(model):
    """The instance itself can gain a new administrative permission."""
    nodes = {}
    rows = list(items(model.snapshot, "bigtable_instance"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        instance = item.get("name")
        if (not isinstance(instance, str) or counts[instance] != 1
                or not re.fullmatch(re.escape(project) + r"/instances/[^/]+", instance)):
            continue
        ident = "gcp_verified_authority:possible-bigtable-instance-admin-self-grant:" + instance
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Bigtable instance administration on {instance}",
                            attrs={"scope": project, "project": project,
                                   "resource": instance, "policy_resource": instance,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGTABLE_INSTANCE_ADMIN_TECHNIQUE}, entity=True)
    return nodes


def bigtable_instance_candidates(model):
    """Exact tables newly readable through one instance policy change."""
    nodes = {}
    rows = list(items(model.snapshot, "bigtable_table"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        table = item.get("name")
        if (not isinstance(table, str) or counts[table] != 1
                or not re.fullmatch(re.escape(project) + r"/instances/[^/]+/tables/[^/]+", table)):
            continue
        instance = table.rsplit("/tables/", 1)[0]
        ident = "gcp_verified_authority:possible-bigtable-instance-self-grant:" + table
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Bigtable table read through {instance} IAM on {table}",
                            attrs={"scope": project, "project": project,
                                   "resource": table, "gain_resource": table,
                                   "policy_resource": instance,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGTABLE_INSTANCE_TECHNIQUE}, entity=True)
    return nodes


def bigtable_backup_candidates(model):
    """Existing backups whose exact policy could grant restore access."""
    nodes = {}
    rows = list(items(model.snapshot, "bigtable_backup"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        name = item.get("name")
        if (not isinstance(name, str) or counts[name] != 1
                or not re.fullmatch(re.escape(project)
                    + r"/instances/[^/]+/clusters/[^/]+/backups/[^/]+", name)):
            continue
        ident = "gcp_verified_authority:possible-bigtable-backup-self-grant:" + name
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Bigtable backup restore permission on {name}",
                            attrs={"scope": project, "project": project,
                                   "resource": name, "policy_resource": name,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGTABLE_BACKUP_TECHNIQUE}, entity=True)
    return nodes


def bigtable_authorized_view_candidates(model):
    """Existing views with an exact policy and bounded view-read permission."""
    nodes = {}
    rows = list(items(model.snapshot, "bigtable_authorized_view"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        name = item.get("name")
        if (not isinstance(name, str) or counts[name] != 1
                or not re.fullmatch(re.escape(project)
                    + r"/instances/[^/]+/tables/[^/]+/authorizedViews/[^/]+", name)):
            continue
        ident = "gcp_verified_authority:possible-bigtable-authorized-view-self-grant:" + name
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Bigtable authorized-view read permission on {name}",
                            attrs={"scope": project, "project": project,
                                   "resource": name, "policy_resource": name,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGTABLE_AUTHORIZED_VIEW_TECHNIQUE}, entity=True)
    return nodes


def bigtable_materialized_view_candidates(model):
    """Existing continuous materialized views with their own exact IAM policy."""
    nodes = {}
    rows = list(items(model.snapshot, "bigtable_materialized_view"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        name = item.get("name")
        if (not isinstance(name, str) or counts[name] != 1
                or not re.fullmatch(re.escape(project)
                    + r"/instances/[^/]+/materializedViews/[^/]+", name)):
            continue
        ident = "gcp_verified_authority:possible-bigtable-materialized-view-self-grant:" + name
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Bigtable materialized-view read permission on {name}",
                            attrs={"scope": project, "project": project,
                                   "resource": name, "policy_resource": name,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGTABLE_MATERIALIZED_VIEW_TECHNIQUE}, entity=True)
    return nodes


def bigtable_table_candidates(model):
    """Exact Bigtable tables whose own policy can add row-read access."""
    nodes = {}
    rows = list(items(model.snapshot, "bigtable_table"))
    counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        name = item.get("name")
        if (not isinstance(name, str) or counts[name] != 1
                or not re.fullmatch(re.escape(project)
                    + r"/instances/[^/]+/tables/[^/]+", name)):
            continue
        ident = "gcp_verified_authority:possible-bigtable-table-self-grant:" + name
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Bigtable table read permission on {name}",
                            attrs={"scope": project, "project": project,
                                   "resource": name, "policy_resource": name,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGTABLE_TABLE_TECHNIQUE}, entity=True)
    return nodes


def contact_center_authorized_view_candidates(model):
    """Exact authorized views with a collected resource-level policy."""
    nodes = {}
    rows = list(items(model.snapshot, "contact_center_authorized_view"))
    names = Counter(model._norm_scope(item.get("name")) for _, item in rows
                    if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/authorizedViewSets/[^/]+/authorizedViews/[^/]+", resource)
                or not resource.startswith(project + "/") or names[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-contact-center-view-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Contact Center authorized-view read permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "view_details_collected": ((item.get("_coverage") or {}).get("network_detail") or {}).get("status") == "collected",
                                   "prospective_self_grant": True,
                                   "prospective_technique": CONTACT_CENTER_VIEW_TECHNIQUE}, entity=True)
    return nodes


def discoveryengine_collection_candidates(model):
    """Exact listed collections whose own IAM policy can add collection access."""
    nodes = {}
    rows = list(items(model.snapshot, "discoveryengine_collection"))
    names = Counter(model._norm_scope(item.get("name")) for _, item in rows
                    if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+", resource)
                or not resource.startswith(project + "/") or names[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-discoveryengine-collection-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Discovery Engine collection access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": DISCOVERYENGINE_COLLECTION_TECHNIQUE}, entity=True)
    return nodes


def discoveryengine_data_store_candidates(model):
    """Exact standalone and collection-child stores with their own IAM policies."""
    nodes = {}
    rows = list(items(model.snapshot, "discoveryengine_data_store"))
    names = Counter(model._norm_scope(item.get("name")) for _, item in rows
                    if isinstance(item.get("name"), str))
    pattern = r"projects/[^/]+/locations/(?:global|us|eu)/(?:collections/[^/]+/)?dataStores/[^/]+"
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(pattern, resource) or
                not resource.startswith(project + "/") or names[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-discoveryengine-data-store-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Discovery Engine data store update on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": DISCOVERYENGINE_DATA_STORE_TECHNIQUE}, entity=True)
    return nodes


def discoveryengine_engine_candidates(model):
    """Exact collection-child engines with their own IAM policies."""
    nodes = {}
    rows = list(items(model.snapshot, "discoveryengine_engine"))
    names = Counter(model._norm_scope(item.get("name")) for _, item in rows
                    if isinstance(item.get("name"), str))
    pattern = r"projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+/engines/[^/]+"
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(pattern, resource) or
                not resource.startswith(project + "/") or names[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-discoveryengine-engine-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Discovery Engine engine update on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": DISCOVERYENGINE_ENGINE_TECHNIQUE}, entity=True)
    return nodes


def integration_connection_candidates(model):
    """Exact inventoried Connector connections that could accept a self grant."""
    nodes = {}
    rows = list(items(model.snapshot, "integration_connection"))
    names = Counter(model._norm_scope(item.get("name")) for _, item in rows
                    if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/connections/[^/]+", resource)
                or not resource.startswith(project + "/") or names[resource] != 1):
            continue
        status = item.get("status")
        state = status.get("state") if isinstance(status, dict) else None
        ident = "gcp_verified_authority:possible-connector-connection-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Connector SQL query permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "connection_state": state,
                                   "connection_suspended": item.get("suspended"),
                                   "connection_details_collected": ((item.get("_coverage") or {}).get("network_detail") or {}).get("status") == "collected",
                                   "prospective_self_grant": True,
                                   "prospective_technique": CONNECTOR_CONNECTION_TECHNIQUE}, entity=True)
    return nodes


def bigquery_connection_candidates(model):
    """Inventoried connections with a resource policy that could grant use."""
    nodes = {}
    rows = list(items(model.snapshot, "bigquery_connection"))
    names = Counter(model._norm_scope(item.get("name")) for _, item in rows
                    if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/[A-Za-z0-9-]+/connections/[A-Za-z0-9_-]+", resource)
                or not resource.startswith(project + "/") or names[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-bigquery-connection-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible BigQuery connection use on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGQUERY_CONNECTION_TECHNIQUE,
                                   "connection_details_collected": ((item.get("_coverage") or {}).get("connectionDetails") or {}).get("status") == "collected",
                                   "connection_type": next((key for key in ("cloudSql", "cloudResource", "aws", "azure", "spark")
                                                            if isinstance(item.get(key), dict)), None)}, entity=True)
    return nodes


def bigquery_table_candidates(model):
    """Existing exact tables that can receive a table-level Data Viewer binding."""
    nodes = {}
    for scope, item in items(model.snapshot, "bigquery_table"):
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/datasets/[^/]+/tables/[^/]+", resource)
                or not resource.startswith(project + "/") or item.get("type") != "TABLE"):
            continue
        ident = "gcp_verified_authority:possible-bigquery-table-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible new BigQuery table read permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "gain_resource": resource, "prospective_self_grant": True,
                                   "prospective_technique": BIGQUERY_TABLE_TECHNIQUE}, entity=True)
    return nodes


def bigquery_row_policy_candidates(model):
    """Exact data tables with existing row policies that a new policy can bypass."""
    nodes = {}
    for scope, item in items(model.snapshot, "bigquery_table"):
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/datasets/[^/]+/tables/[^/]+", resource)
                or not resource.startswith(project + "/") or item.get("type") != "TABLE"):
            continue
        ident = "gcp_verified_authority:possible-bigquery-row-policy-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible new filtered row access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "gain_resource": resource, "prospective_self_grant": True,
                                   "prospective_technique": BIGQUERY_ROW_POLICY_TECHNIQUE}, entity=True)
    return nodes


def bigquery_dataset_candidates(model, technique=BIGQUERY_DATASET_TECHNIQUE):
    """Exact data tables that a dataset ACL grant could newly expose."""
    nodes = {}
    datasets = {}
    for scope, item in items(model.snapshot, "bigquery_dataset"):
        project = model._norm_scope(scope)
        name = model._norm_scope(item.get("name")) if isinstance(item.get("name"), str) else ""
        if re.fullmatch(r"projects/[^/]+/datasets/[^/]+", name) and name.startswith(project + "/"):
            datasets[name] = item
    for scope, item in items(model.snapshot, "bigquery_table"):
        project = model._norm_scope(scope)
        name = model._norm_scope(item.get("name")) if isinstance(item.get("name"), str) else ""
        if (not re.fullmatch(r"projects/[^/]+/datasets/[^/]+/tables/[^/]+", name)
                or not name.startswith(project + "/") or item.get("type") != "TABLE"):
            continue
        dataset = name.rsplit("/tables/", 1)[0]
        if dataset not in datasets:
            continue
        ident = "gcp_verified_authority:possible-bigquery-dataset-self-grant:" + (
            name if technique == BIGQUERY_DATASET_TECHNIQUE else "update:" + name)
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible BigQuery table data access on {name}",
                            attrs={"scope": project, "project": project,
                                   "resource": name, "policy_resource": dataset,
                                   "gain_resource": name,
                                   "prospective_self_grant": True,
                                   "prospective_technique": technique}, entity=True)
    return nodes


def biglake_table_candidates(model):
    """Exact Iceberg tables whose policy could grant new metadata access."""
    nodes = {}
    for scope, item in items(model.snapshot, "biglake_table"):
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str)
                or not re.fullmatch(r"projects/[^/]+/catalogs/[^/]+/namespaces/[^/]+/tables/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-biglake-table-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible BigLake table access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGLAKE_TABLE_TECHNIQUE}, entity=True)
    return nodes


def biglake_namespace_candidates(model):
    """Exact one-level Iceberg namespaces with resource IAM policies."""
    nodes = {}
    for scope, item in items(model.snapshot, "biglake_namespace"):
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str)
                or not re.fullmatch(r"projects/[^/]+/catalogs/[^/]+/namespaces/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-biglake-namespace-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible BigLake namespace access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGLAKE_NAMESPACE_TECHNIQUE}, entity=True)
    return nodes


def biglake_catalog_candidates(model):
    """Exact collected Iceberg catalogs whose policy could grant new access."""
    nodes = {}
    for scope, item in items(model.snapshot, "biglake_catalog"):
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str)
                or not re.fullmatch(r"projects/[^/]+/catalogs/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-biglake-catalog-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible BigLake catalog access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": BIGLAKE_CATALOG_TECHNIQUE}, entity=True)
    return nodes


def analyticshub_listing_candidates(model):
    """Exact collected listings whose IAM policy can grant a new subscription right."""
    nodes = {}
    for scope, item in items(model.snapshot, "analyticshub_listing"):
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str)
                or not re.fullmatch(r"projects/[^/]+/locations/[^/]+/dataExchanges/[^/]+/listings/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-listing-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Analytics Hub listing subscribe access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": ANALYTICSHUB_LISTING_TECHNIQUE}, entity=True)
    return nodes


def analyticshub_exchange_candidates(model):
    """Exact collected exchanges whose IAM policy can grant a new subscription right."""
    nodes = {}
    for scope, item in items(model.snapshot, "analyticshub_data_exchange"):
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str)
                or not re.fullmatch(r"projects/[^/]+/locations/[^/]+/dataExchanges/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-exchange-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Analytics Hub subscribe access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": ANALYTICSHUB_EXCHANGE_TECHNIQUE}, entity=True)
    return nodes


def artifact_repository_candidates(model):
    """Standard repositories where a policy grant could add upload authority."""
    nodes = {}
    for scope, item in items(model.snapshot, "artifact_repository"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/repositories/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        if item.get("mode") in ("REMOTE_REPOSITORY", "VIRTUAL_REPOSITORY"):
            continue
        ident = "gcp_verified_authority:possible-artifact-upload-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Artifact Registry upload access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": ARTIFACT_TECHNIQUE,
                                   "repository_mode": item.get("mode")}, entity=True)
    return nodes


def containeranalysis_note_candidates(model):
    """Exact global or regional notes whose policy could grant attach access."""
    nodes = {}
    for scope, item in items(model.snapshot, "containeranalysis_note"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/(?:locations/[^/]+/)?notes/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-containeranalysis-note-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Container Analysis note attachment access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": CONTAINERANALYSIS_NOTE_TECHNIQUE}, entity=True)
    return nodes


def datacatalog_policy_tag_candidates(model):
    """Exact policy tags where a grant could add fine-grained reader access."""
    nodes = {}
    for scope, item in items(model.snapshot, "datacatalog_policy_tag"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/taxonomies/[^/]+/policyTags/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-datacatalog-tag-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible policy-tag fine-grained reader access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": DATACATALOG_TAG_TECHNIQUE}, entity=True)
    return nodes


def datacatalog_taxonomy_candidates(model):
    """Taxonomy policy grants that would reach a specific descendant tag."""
    nodes = {}
    taxonomies = model.datacatalog_taxonomies
    for scope, item in items(model.snapshot, "datacatalog_policy_tag"):
        project = model._norm_scope(scope)
        raw_tag = item.get("name")
        tag = model._norm_scope(raw_tag) if isinstance(raw_tag, str) else None
        if (not isinstance(tag, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/taxonomies/[^/]+/policyTags/[^/]+", tag)
                or not tag.startswith(project + "/")):
            continue
        taxonomy = tag.rsplit("/policyTags/", 1)[0]
        if taxonomy not in taxonomies:
            continue
        ident = "gcp_verified_authority:possible-datacatalog-taxonomy-self-grant:" + tag
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible taxonomy reader access on {tag}",
                            attrs={"scope": project, "project": project,
                                   "resource": tag, "gain_resource": tag,
                                   "policy_resource": taxonomy,
                                   "prospective_self_grant": True,
                                   "prospective_technique": DATACATALOG_TAXONOMY_TECHNIQUE}, entity=True)
    return nodes


def metastore_service_candidates(model):
    """Exact services where a metadata-viewer binding could add gRPC use."""
    nodes = {}
    for scope, item in items(model.snapshot, "metastore_service"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/services/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        config = item.get("hiveMetastoreConfig")
        protocol = config.get("endpointProtocol") if isinstance(config, dict) else None
        if protocol in ("THRIFT", "ENDPOINT_PROTOCOL_UNSPECIFIED"):
            continue
        if item.get("state") in ("SUSPENDED", "DELETING", "ERROR"):
            continue
        ident = "gcp_verified_authority:possible-metastore-service-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Metastore metadata access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": METASTORE_SERVICE_TECHNIQUE,
                                   "service_state": item.get("state"),
                                   "endpoint_protocol": protocol,
                                   "service_details_collected": ((item.get("_coverage") or {}).get(
                                       "network_detail") or {}).get("status") == "collected"}, entity=True)
    return nodes


def secret_candidates(model):
    """Inventoried secrets whose policy could grant the caller version access."""
    nodes = {}
    for scope, item in items(model.snapshot, "secret"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/(?:locations/[^/]+/)?secrets/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-secret-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Secret Manager access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": SECRET_TECHNIQUE}, entity=True)
    return nodes


def fleet_membership_candidates(model):
    """Registered fleet members with an exact IAM policy resource identity."""
    nodes = {}
    rows = list(items(model.snapshot, "fleet_membership"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/memberships/[^/]+", resource)
                or not resource.startswith(project + "/") or counts[resource] != 1 or
                (item.get("state") or {}).get("code") == "DELETING"):
            continue
        ident = "gcp_verified_authority:possible-fleet-membership-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Connect Gateway credential permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "membership_state": (item.get("state") or {}).get("code"),
                                   "prospective_self_grant": True,
                                   "prospective_technique": FLEET_MEMBERSHIP_TECHNIQUE}, entity=True)
    return nodes


def healthcare_consent_store_candidates(model):
    """Named consent stores with a separately readable dataset policy."""
    nodes = {}
    rows = list(items(model.snapshot, "healthcare_consent_store"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/consentStores/[^/]+", resource)
                or not resource.startswith(project + "/") or counts[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-healthcare-consent-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible consent read permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": HEALTHCARE_CONSENT_TECHNIQUE}, entity=True)
    return nodes


def healthcare_dataset_fhir_candidates(model):
    """Existing FHIR stores whose parent dataset policy can add store search."""
    nodes = {}
    rows = list(items(model.snapshot, "healthcare_fhir_store"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows
                     if isinstance(item, dict) and isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name") if isinstance(item, dict) else None
        store = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/fhirStores/[^/]+", store)
                or not store.startswith(project + "/") or counts[store] != 1):
            continue
        dataset = store.rsplit("/fhirStores/", 1)[0]
        if dataset not in model.resource_policy_status.get("healthcare_dataset", {}):
            continue
        ident = "gcp_verified_authority:possible-healthcare-dataset-self-grant:" + store
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible FHIR store search permission on {store}",
                            attrs={"scope": project, "project": project,
                                   "resource": store, "policy_resource": dataset,
                                   "gain_resource": store,
                                   "prospective_self_grant": True,
                                   "prospective_technique": HEALTHCARE_DATASET_TECHNIQUE}, entity=True)
    return nodes


def healthcare_dicom_store_candidates(model):
    """Exact inventoried DICOM stores with separately collected store policies."""
    nodes = {}
    rows = list(items(model.snapshot, "healthcare_dicom_store"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows
                     if isinstance(item, dict) and isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name") if isinstance(item, dict) else None
        store = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/dicomStores/[^/]+", store)
                or not store.startswith(project + "/") or counts[store] != 1):
            continue
        dataset = store.rsplit("/dicomStores/", 1)[0]
        if dataset not in model.resource_policy_status.get("healthcare_dataset", {}):
            continue
        ident = "gcp_verified_authority:possible-healthcare-dicom-self-grant:" + store
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible DICOMweb read permission on {store}",
                            attrs={"scope": project, "project": project,
                                   "resource": store, "policy_resource": store,
                                   "prospective_self_grant": True,
                                   "prospective_technique": HEALTHCARE_DICOM_TECHNIQUE}, entity=True)
    return nodes


def healthcare_fhir_store_candidates(model):
    """Exact inventoried FHIR stores with separately collected store policies."""
    nodes = {}
    rows = list(items(model.snapshot, "healthcare_fhir_store"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows
                     if isinstance(item, dict) and isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name") if isinstance(item, dict) else None
        store = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/fhirStores/[^/]+", store)
                or not store.startswith(project + "/") or counts[store] != 1):
            continue
        dataset = store.rsplit("/fhirStores/", 1)[0]
        if dataset not in model.resource_policy_status.get("healthcare_dataset", {}):
            continue
        ident = "gcp_verified_authority:possible-healthcare-fhir-self-grant:" + store
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible FHIR resource read permission on {store}",
                            attrs={"scope": project, "project": project,
                                   "resource": store, "policy_resource": store,
                                   "prospective_self_grant": True,
                                   "prospective_technique": HEALTHCARE_FHIR_TECHNIQUE}, entity=True)
    return nodes


def healthcare_hl7v2_store_candidates(model):
    """Exact inventoried HL7v2 stores with separately collected store policies."""
    nodes = {}
    rows = list(items(model.snapshot, "healthcare_hl7v2_store"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows
                     if isinstance(item, dict) and isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name") if isinstance(item, dict) else None
        store = model._norm_scope(raw) if isinstance(raw, str) else ""
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/hl7V2Stores/[^/]+", store)
                or not store.startswith(project + "/") or counts[store] != 1):
            continue
        dataset = store.rsplit("/hl7V2Stores/", 1)[0]
        if dataset not in model.resource_policy_status.get("healthcare_dataset", {}):
            continue
        ident = "gcp_verified_authority:possible-healthcare-hl7v2-self-grant:" + store
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible HL7v2 message list permission on {store}",
                            attrs={"scope": project, "project": project,
                                   "resource": store, "policy_resource": store,
                                   "prospective_self_grant": True,
                                   "prospective_technique": HEALTHCARE_HL7V2_TECHNIQUE}, entity=True)
    return nodes


def iap_tunnel_instance_candidates(model, *, zone_policy=False):
    """IAP instance resources joined to unique existing Compute VMs."""
    nodes = {}
    rows = list(items(model.snapshot, "instance"))
    links = Counter(item.get("selfLink") for _, item in rows
                    if isinstance(item.get("selfLink"), str))
    policies = model.resource_policy_status.get("iap_tunnel_policy", {})
    for scope, item in rows:
        project = model._norm_scope(scope)
        link = item.get("selfLink")
        match = re.fullmatch(
            r"https://(?:www|compute)\.googleapis\.com/compute/v1/"
            + re.escape(project) + r"/zones/([a-z][a-z0-9-]*[0-9]-[a-z])/instances/([A-Za-z0-9_-]+)",
            link) if isinstance(link, str) else None
        if (not match or links[link] != 1 or item.get("name") != match.group(2)):
            continue
        zone, name = match.groups()
        root = project + "/iap_tunnel"
        zone_resource = root + "/zones/" + zone
        resource = zone_resource + "/instances/" + name
        if any(path not in policies for path in (root, zone_resource, resource)):
            continue
        technique = IAP_ZONE_TECHNIQUE if zone_policy else IAP_INSTANCE_TECHNIQUE
        policy_resource = zone_resource if zone_policy else resource
        ident = "gcp_verified_authority:possible-iap-" + (
            "zone" if zone_policy else "instance") + "-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible IAP tunnel access to {name} in {zone}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": policy_resource,
                                   "gain_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": technique}, entity=True)
    return nodes


def identityplatform_tenant_candidates(model):
    """Exact listed tenants with a unique policy boundary."""
    nodes = {}
    rows = list(items(model.snapshot, "identityplatform_tenant"))
    counts = Counter(item.get("name") for _, item in rows
                     if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        resource = item.get("name")
        if (not isinstance(resource, str) or counts[resource] != 1
                or not re.fullmatch(re.escape(project) + r"/tenants/[A-Za-z0-9_-]+", resource)):
            continue
        ident = "gcp_verified_authority:possible-identityplatform-tenant-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible user update access to Identity Platform tenant {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": IDENTITYPLATFORM_TENANT_TECHNIQUE}, entity=True)
    return nodes


def krm_api_host_candidates(model):
    """Unique listed Config Controller hosts at the exact IAM policy boundary."""
    nodes = {}
    rows = list(items(model.snapshot, "krm_api_host"))
    counts = Counter(item.get("name") for _, item in rows
                     if isinstance(item.get("name"), str))
    for scope, item in rows:
        project = model._norm_scope(scope)
        resource = item.get("name")
        if (not isinstance(resource, str) or counts[resource] != 1
                or not re.fullmatch(re.escape(project) +
                                    r"/locations/[a-z][a-z0-9-]*/krmApiHosts/[A-Za-z0-9_-]+", resource)
                or item.get("state") == "DELETING"):
            continue
        ident = "gcp_verified_authority:possible-krm-api-host-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Config Controller host update on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "host_state": item.get("state"),
                                   "prospective_self_grant": True,
                                   "prospective_technique": KRM_API_HOST_TECHNIQUE}, entity=True)
    return nodes


def logging_view_candidates(model):
    """Unique listed views with an exact bucket and view IAM boundary."""
    nodes = {}
    rows = list(items(model.snapshot, "logging_view"))
    counts = Counter(item.get("name") for _, item in rows
                     if isinstance(item.get("name"), str))
    for scope, item in rows:
        parent_scope = model._norm_scope(scope)
        resource = item.get("name")
        if (not isinstance(resource, str) or counts[resource] != 1
                or not re.fullmatch(re.escape(parent_scope) +
                                    r"/locations/[a-z0-9-]+/buckets/[A-Za-z0-9_.-]+/views/[A-Za-z0-9_-]+",
                                    resource)):
            continue
        ident = "gcp_verified_authority:possible-logging-view-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", parent_scope,
                            f"Possible log view access on {resource}",
                            attrs={"scope": parent_scope, "resource": resource,
                                   "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": LOGGING_VIEW_TECHNIQUE}, entity=True)
    return nodes


def ncc_group_candidates(model, *, hub_policy=False):
    """Exact hub groups with their own IAM boundary and an inventoried parent hub."""
    nodes = {}
    rows = list(items(model.snapshot, "network_connectivity_hub_group"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    hubs = Counter(model._norm_scope(item.get("name")) for _, item in
                   items(model.snapshot, "network_connectivity_hub"))
    technique = NCC_HUB_GROUP_USE_TECHNIQUE if hub_policy else NCC_GROUP_TECHNIQUE
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        group = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(group, str) or not re.fullmatch(
                r"projects/[^/]+/locations/global/hubs/[^/]+/groups/[^/]+", group)
                or not group.startswith(project + "/") or counts[group] != 1):
            continue
        hub = group.rsplit("/groups/", 1)[0]
        if hub_policy and hubs[hub] != 1:
            continue
        policy = hub if hub_policy else group
        ident = "gcp_verified_authority:possible-ncc-group-self-grant:" + technique + ":" + group
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Network Connectivity group use on {group}",
                            attrs={"scope": project, "project": project,
                                   "resource": group, "gain_resource": group,
                                   "policy_resource": policy,
                                   "prospective_self_grant": True,
                                   "prospective_technique": technique}, entity=True)
    return nodes


def networksecurity_address_group_candidates(model):
    """Existing project-scoped address groups with exact resource identities."""
    nodes = {}
    rows = list(items(model.snapshot, "network_security_address_group"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/addressGroups/[^/]+", resource)
                or not resource.startswith(project + "/") or counts[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-address-group-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible address group update permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": NETWORKSECURITY_ADDRESS_GROUP_TECHNIQUE}, entity=True)
    return nodes


def networksecurity_authorization_policy_candidates(model):
    """Existing project authorization policies with exact resource identities."""
    nodes = {}
    rows = list(items(model.snapshot, "network_security_authorization_policy"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/authorizationPolicies/[^/]+", resource)
                or not resource.startswith(project + "/") or counts[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-authorization-policy-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible authorization policy update permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": NETWORKSECURITY_AUTHORIZATION_POLICY_TECHNIQUE}, entity=True)
    return nodes


def networksecurity_authz_policy_candidates(model):
    """Existing project authz policies with exact resource identities."""
    nodes = {}
    rows = list(items(model.snapshot, "ngfw_authz_policy"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/authzPolicies/[^/]+", resource)
                or not resource.startswith(project + "/") or counts[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-authz-policy-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible authz policy update permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": NETWORKSECURITY_AUTHZ_POLICY_TECHNIQUE}, entity=True)
    return nodes


def networksecurity_client_tls_policy_candidates(model):
    """Existing project client TLS policies with exact resource identities."""
    nodes = {}
    rows = list(items(model.snapshot, "network_security_client_tls_policy"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/clientTlsPolicies/[^/]+", resource)
                or not resource.startswith(project + "/") or counts[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-client-tls-policy-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible client TLS policy update permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": NETWORKSECURITY_CLIENT_TLS_POLICY_TECHNIQUE}, entity=True)
    return nodes


def networksecurity_server_tls_policy_candidates(model):
    """Existing project server TLS policies with exact resource identities."""
    nodes = {}
    rows = list(items(model.snapshot, "network_security_server_tls_policy"))
    counts = Counter(model._norm_scope(item.get("name")) for _, item in rows)
    for scope, item in rows:
        project = model._norm_scope(scope)
        raw = item.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/serverTlsPolicies/[^/]+", resource)
                or not resource.startswith(project + "/") or counts[resource] != 1):
            continue
        ident = "gcp_verified_authority:possible-server-tls-policy-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible server TLS policy update permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": NETWORKSECURITY_SERVER_TLS_POLICY_TECHNIQUE}, entity=True)
    return nodes


def domains_registration_candidates(model):
    """Only active, uniquely named registrations can receive a new DNS grant."""
    nodes = {}
    rows = list(items(model.snapshot, "domains_registration"))
    counts = Counter(model._norm_scope(row.get("name")) for _, row in rows)
    for scope, row in rows:
        project = model._norm_scope(scope)
        raw = row.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        domain = row.get("domainName")
        if (not isinstance(resource, str) or not isinstance(domain, str)
                or not re.fullmatch(re.escape(project) + r"/locations/global/registrations/[^/]+", resource)
                or resource.rsplit("/registrations/", 1)[-1].lower() != domain.lower().rstrip(".")
                or counts[resource] != 1 or row.get("state") != "ACTIVE"):
            continue
        ident = "gcp_verified_authority:possible-domain-registration-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible DNS setting permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": DOMAINS_REGISTRATION_TECHNIQUE}, entity=True)
    return nodes


def privateca_pool_candidates(model):
    """Exact CA pools whose policy can grant certificate issuance."""
    nodes = {}
    rows = list(items(model.snapshot, "ca_pool"))
    counts = Counter(model._norm_scope(row.get("name")) for _, row in rows)
    for scope, row in rows:
        project = model._norm_scope(scope)
        raw = row.get("name")
        resource = model._norm_scope(raw) if isinstance(raw, str) else None
        if (not isinstance(resource, str) or counts[resource] != 1
                or not re.fullmatch(re.escape(project) + r"/locations/[^/]+/caPools/[^/]+", resource)):
            continue
        ident = "gcp_verified_authority:possible-ca-pool-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible certificate issuance permission on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": PRIVATECA_POOL_TECHNIQUE}, entity=True)
    return nodes


def topic_candidates(model):
    """Inventoried topics whose IAM policy could grant publish access."""
    nodes = {}
    for scope, item in items(model.snapshot, "pubsub_topic"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(r"projects/[^/]+/topics/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        ident = "gcp_verified_authority:possible-topic-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Pub/Sub publish access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": TOPIC_TECHNIQUE}, entity=True)
    return nodes


def subscription_candidates(model):
    """Inventoried subscriptions with a new per-resource consume grant."""
    nodes = {}
    for scope, item in items(model.snapshot, "pubsub_subscription"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/(?:locations/[^/]+/)?subscriptions/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        push = item.get("pushConfig")
        mode = ("export" if "bigqueryConfig" in item or "cloudStorageConfig" in item else
                "pull" if push in (None, {}) else
                "push" if isinstance(push, dict) and push.get("pushEndpoint") else "unknown")
        ident = "gcp_verified_authority:possible-subscription-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible Pub/Sub consume access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": SUBSCRIPTION_TECHNIQUE,
                                   "delivery_mode": mode}, entity=True)
    return nodes


def kms_key_candidates(model):
    """Inventoried decrypt-capable keys with a possibly usable version."""
    nodes = {}
    versions = {}
    for _, item in items(model.snapshot, "kms_key_version"):
        raw_name = item.get("name")
        name = model._norm_scope(raw_name) if isinstance(raw_name, str) else ""
        if "/cryptoKeyVersions/" in name:
            versions.setdefault(name.rsplit("/cryptoKeyVersions/", 1)[0], []).append(item.get("state"))
    version_status = {model._norm_scope(scope): status
                      for scope, status in inventory_status(model.snapshot, "kms_key_version").items()}
    for scope, item in items(model.snapshot, "kms_key"):
        project = model._norm_scope(scope)
        raw_resource = item.get("name")
        resource = model._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
        if (not isinstance(resource, str) or not re.fullmatch(
                r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+", resource)
                or not resource.startswith(project + "/")):
            continue
        purpose = item.get("purpose")
        if purpose in ("ASYMMETRIC_SIGN", "MAC"):
            continue
        states = versions.get(resource, [])
        primary = item.get("primary") or {}
        primary_enabled = isinstance(primary, dict) and primary.get("state") == "ENABLED"
        enabled = (True if "ENABLED" in states or primary_enabled else
                   False if version_status.get(project) in ("collected", "empty") else None)
        ident = "gcp_verified_authority:possible-kms-self-grant:" + resource
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", project,
                            f"Possible KMS decrypt access on {resource}",
                            attrs={"scope": project, "project": project,
                                   "resource": resource, "policy_resource": resource,
                                   "prospective_self_grant": True,
                                   "prospective_technique": KMS_TECHNIQUE,
                                   "key_purpose": purpose, "enabled_version": enabled}, entity=True)
    return nodes


def _name(value):
    return isinstance(value, str) and bool(value.strip()) and "*" not in value


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp")
    return parsed


def _valid_analyticshub_review(record, scope, snapshot, *, listing):
    resource = record["TargetResource"]
    action = "analyticshub.listings.subscribe" if listing else "analyticshub.dataExchanges.subscribe"
    mutation = "analyticshub.listings.setIamPolicy" if listing else "analyticshub.dataExchanges.setIamPolicy"
    suffix = r"/locations/[^/]+/dataExchanges/[^/]+/listings/[^/]+" if listing else r"/locations/[^/]+/dataExchanges/[^/]+"
    if (not re.fullmatch(re.escape(scope) + suffix, resource)
            or record["GrantedResource"] != resource
            or record["AccessPermission"] != mutation
            or record["GrantedPermissions"] != [action]
            or record.get("PriorTestedPermission") != action
            or record.get("AfterTestedPermission") != action
            or record.get("PriorTestedResource") != resource
            or record.get("AfterTestedResource") != resource
            or record.get("AcceptedBindingMember") != record["SourceId"]
            or not _name(record.get("AcceptedBindingRole"))
            or record.get("BindingPresentAtSnapshot") is not True):
        return False
    # A collected native policy must agree with the externally reviewed
    # binding; otherwise the recorded mutation has been superseded or was
    # attached to another resource.
    kind = "analyticshub_listing" if listing else "analyticshub_data_exchange"
    for collected_scope, item in items(snapshot, kind):
        if collected_scope != scope or item.get("name") != resource:
            continue
        if ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status") == "collected":
            bindings = (item.get("iamPolicy") or {}).get("bindings", [])
            if not isinstance(bindings, list) or not any(
                    isinstance(binding, dict)
                    and binding.get("role") == record["AcceptedBindingRole"]
                    and record["SourceId"] in (binding.get("members") or [])
                    for binding in bindings):
                return False
            break
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("PolicyMutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        binding = _instant(record.get("BindingCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < mutation < after <= binding <= observed <= captured
                and (captured - binding).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def _valid_containeranalysis_note_review(record, scope, snapshot):
    resource = record["TargetResource"]
    action = "containeranalysis.notes.attachOccurrence"
    if (not re.fullmatch(re.escape(scope) + r"/(?:locations/[^/]+/)?notes/[^/]+", resource)
            or record["GrantedResource"] != resource
            or record["AccessPermission"] != "containeranalysis.notes.setIamPolicy"
            or record["GrantedPermissions"] != [action]
            or record.get("PriorTestedPermission") != action
            or record.get("AfterTestedPermission") != action
            or record.get("PriorTestedResource") != resource
            or record.get("AfterTestedResource") != resource
            or record.get("AcceptedBindingMember") != record["SourceId"]
            or not _name(record.get("AcceptedBindingRole"))
            or record.get("BindingPresentAtSnapshot") is not True):
        return False
    for collected_scope, item in items(snapshot, "containeranalysis_note"):
        if collected_scope != scope or item.get("name") != resource:
            continue
        if ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status") == "collected":
            bindings = (item.get("iamPolicy") or {}).get("bindings", [])
            if not isinstance(bindings, list) or not any(
                    isinstance(binding, dict)
                    and binding.get("role") == record["AcceptedBindingRole"]
                    and record["SourceId"] in (binding.get("members") or [])
                    and not binding.get("condition")
                    for binding in bindings):
                return False
            break
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("PolicyMutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        binding = _instant(record.get("BindingCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < mutation < after <= binding <= observed <= captured
                and (captured - binding).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def _valid_datacatalog_tag_review(record, scope, snapshot):
    resource = record["TargetResource"]
    action = "datacatalog.categories.fineGrainedGet"
    if (not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/taxonomies/[^/]+/policyTags/[^/]+",
                         resource)
            or record["GrantedResource"] != resource
            or record["AccessPermission"] != "datacatalog.categories.setIamPolicy"
            or record["GrantedPermissions"] != [action]
            or record.get("PriorTestedPermission") != action
            or record.get("AfterTestedPermission") != action
            or record.get("PriorTestedResource") != resource
            or record.get("AfterTestedResource") != resource
            or record.get("AcceptedBindingMember") != record["SourceId"]
            or not _name(record.get("AcceptedBindingRole"))
            or record.get("BindingPresentAtSnapshot") is not True):
        return False
    for collected_scope, item in items(snapshot, "datacatalog_policy_tag"):
        if collected_scope != scope or item.get("name") != resource:
            continue
        if ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status") == "collected":
            bindings = (item.get("iamPolicy") or {}).get("bindings", [])
            if not isinstance(bindings, list) or not any(
                    isinstance(binding, dict)
                    and binding.get("role") == record["AcceptedBindingRole"]
                    and record["SourceId"] in (binding.get("members") or [])
                    and not binding.get("condition")
                    for binding in bindings):
                return False
            break
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("PolicyMutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        binding = _instant(record.get("BindingCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < mutation < after <= binding <= observed <= captured
                and (captured - binding).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def _valid_datacatalog_taxonomy_review(record, scope, snapshot):
    taxonomy = record["TargetResource"]
    tag = record["GrantedResource"]
    action = "datacatalog.categories.fineGrainedGet"
    if (not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/taxonomies/[^/]+", taxonomy)
            or not re.fullmatch(re.escape(taxonomy) + r"/policyTags/[^/]+", tag)
            or record["AccessPermission"] != "datacatalog.taxonomies.setIamPolicy"
            or record["GrantedPermissions"] != [action]
            or record.get("PriorTestedPermission") != action
            or record.get("AfterTestedPermission") != action
            or record.get("PriorTestedResource") != tag
            or record.get("AfterTestedResource") != tag
            or record.get("AcceptedBindingMember") != record["SourceId"]
            or record.get("AcceptedBindingRole") != "roles/datacatalog.categoryFineGrainedReader"
            or record.get("BindingPresentAtSnapshot") is not True):
        return False
    taxonomy_found = False
    for collected_scope, item in items(snapshot, "datacatalog_taxonomy"):
        if collected_scope != scope or item.get("name") != taxonomy:
            continue
        taxonomy_found = True
        if "FINE_GRAINED_ACCESS_CONTROL" not in (item.get("activatedPolicyTypes") or []):
            return False
        if ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status") == "collected":
            bindings = (item.get("iamPolicy") or {}).get("bindings", [])
            if not isinstance(bindings, list) or not any(
                    isinstance(binding, dict)
                    and binding.get("role") == record["AcceptedBindingRole"]
                    and record["SourceId"] in (binding.get("members") or [])
                    and not binding.get("condition")
                    for binding in bindings):
                return False
        break
    if not taxonomy_found or not any(s == scope and item.get("name") == tag
                                      for s, item in items(snapshot, "datacatalog_policy_tag")):
        return False
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("PolicyMutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        binding = _instant(record.get("BindingCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < mutation < after <= binding <= observed <= captured
                and (captured - binding).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def _valid_metastore_service_review(record, scope, snapshot):
    resource = record["TargetResource"]
    action = "metastore.services.use"
    if (not re.fullmatch(re.escape(scope) + r"/locations/[^/]+/services/[^/]+", resource)
            or record["GrantedResource"] != resource
            or record["AccessPermission"] != "metastore.services.setIamPolicy"
            or record["GrantedPermissions"] != [action]
            or record.get("PriorTestedPermission") != action
            or record.get("AfterTestedPermission") != action
            or record.get("PriorTestedResource") != resource
            or record.get("AfterTestedResource") != resource
            or record.get("AcceptedBindingMember") != record["SourceId"]
            or record.get("AcceptedBindingRole") != "roles/metastore.metadataViewer"
            or record.get("BindingPresentAtSnapshot") is not True):
        return False
    service_found = False
    for collected_scope, item in items(snapshot, "metastore_service"):
        if collected_scope != scope or item.get("name") != resource:
            continue
        service_found = True
        config = item.get("hiveMetastoreConfig")
        if (item.get("state") != "ACTIVE" or not isinstance(config, dict)
                or config.get("endpointProtocol") != "GRPC"
                or ((snapshot.get("metadata") or {}).get("collector") == "native-gcp"
                    and ((item.get("_coverage") or {}).get("network_detail") or {}).get("status")
                    != "collected")):
            return False
        if ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status") == "collected":
            bindings = (item.get("iamPolicy") or {}).get("bindings", [])
            if not isinstance(bindings, list) or not any(
                    isinstance(binding, dict)
                    and binding.get("role") == record["AcceptedBindingRole"]
                    and record["SourceId"] in (binding.get("members") or [])
                    and not binding.get("condition")
                    for binding in bindings):
                return False
            break
    if not service_found:
        return False
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("PolicyMutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        binding = _instant(record.get("BindingCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < mutation < after <= binding <= observed <= captured
                and (captured - binding).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def _valid_bigquery_connection_review(record, scope, snapshot):
    resource = record["TargetResource"]
    if (not re.fullmatch(re.escape(scope) + r"/locations/[A-Za-z0-9-]+/connections/[A-Za-z0-9_-]+", resource)
            or record["GrantedResource"] != resource
            or record["AccessPermission"] != "bigquery.connections.setIamPolicy"
            or record["GrantedPermissions"] != ["bigquery.connections.use"]
            or record.get("PriorTestedPermission") != "bigquery.connections.use"
            or record.get("AfterTestedPermission") != "bigquery.connections.use"
            or record.get("PriorTestedResource") != resource
            or record.get("AfterTestedResource") != resource
            or record.get("AcceptedBindingMember") != record["SourceId"]
            or record.get("AcceptedBindingRole") != "roles/bigquery.connectionUser"
            or record.get("BindingPresentAtSnapshot") is not True):
        return False
    matching = [item for collected_scope, item in items(snapshot, "bigquery_connection")
                if collected_scope == scope and item.get("name") == resource]
    if len(matching) != 1:
        return False
    connection = matching[0]
    if ((connection.get("_coverage") or {}).get("connectionDetails") or {}).get("status") != "collected":
        return False
    policy_status = ((connection.get("_coverage") or {}).get("iamPolicy") or {}).get("status")
    if policy_status == "collected":
        bindings = (connection.get("iamPolicy") or {}).get("bindings", [])
        if not isinstance(bindings, list) or not any(
                isinstance(binding, dict)
                and binding.get("role") == "roles/bigquery.connectionUser"
                and record["SourceId"] in (binding.get("members") or [])
                for binding in bindings):
            return False
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("PolicyMutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        binding = _instant(record.get("BindingCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < mutation < after <= binding <= observed <= captured
                and (captured - binding).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def _valid_domains_registration_review(record, scope, snapshot):
    resource = record["TargetResource"]
    access = "domains.registrations.configureDns"
    if (not re.fullmatch(re.escape(scope) + r"/locations/global/registrations/[^/]+", resource)
            or record["GrantedResource"] != resource
            or record["AccessPermission"] != "domains.registrations.setIamPolicy"
            or record["GrantedPermissions"] != [access]
            or record.get("PriorTestedPermission") != access
            or record.get("AfterTestedPermission") != access
            or record.get("PriorTestedResource") != resource
            or record.get("AfterTestedResource") != resource
            or record.get("AcceptedBindingMember") != record["SourceId"]
            or not _name(record.get("AcceptedBindingRole"))
            or record.get("BindingPresentAtSnapshot") is not True):
        return False
    matching = [item for collected_scope, item in items(snapshot, "domains_registration")
                if collected_scope == scope and item.get("name") == resource]
    if (len(matching) != 1 or matching[0].get("state") != "ACTIVE"
            or not isinstance(matching[0].get("domainName"), str)
            or matching[0]["domainName"].lower().rstrip(".") != resource.rsplit("/registrations/", 1)[-1].lower()):
        return False
    policy = matching[0].get("iamPolicy") or {}
    if ((matching[0].get("_coverage") or {}).get("iamPolicy") or {}).get("status") != "collected":
        return False
    bindings = policy.get("bindings")
    if not isinstance(bindings, list) or not any(
            isinstance(binding, dict)
            and binding.get("role") == record["AcceptedBindingRole"]
            and record["SourceId"] in (binding.get("members") or [])
            and not binding.get("condition") for binding in bindings):
        return False
    try:
        prior = _instant(record.get("PriorAccessCheckedAt"))
        mutation = _instant(record.get("PolicyMutationObservedAt"))
        after = _instant(record.get("AfterAccessCheckedAt"))
        binding = _instant(record.get("BindingCheckedAt"))
        observed = _instant(record.get("EvidenceObservedAt"))
        captured = _instant(snapshot.get("created_at"))
        return (prior < mutation < after <= binding <= observed <= captured
                and (captured - binding).total_seconds() <= 900)
    except (TypeError, ValueError, OverflowError):
        return False


def _valid(record, scope, snapshot):
    if not isinstance(record, dict) or not scope.startswith("projects/"):
        return False
    for key in ("TechniqueId", "SourceId", "TargetResource", "GrantedResource",
                "AccessPermission", "EvidenceRef"):
        if not _name(record.get(key)):
            return False
    if record.get("TargetScope") != scope or record.get("GrantedPrincipalId") != record.get("SourceId"):
        return False
    resource = record["TargetResource"]
    if resource != scope and not resource.startswith(scope + "/"):
        return False
    for technique, pattern in (
            (DISCOVERYENGINE_COLLECTION_TECHNIQUE,
             r"projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+"),
            (DISCOVERYENGINE_DATA_STORE_TECHNIQUE,
             r"projects/[^/]+/locations/(?:global|us|eu)/(?:collections/[^/]+/)?dataStores/[^/]+"),
            (DISCOVERYENGINE_ENGINE_TECHNIQUE,
             r"projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+/engines/[^/]+"),
            (KRM_API_HOST_TECHNIQUE,
             r"projects/[^/]+/locations/[a-z][a-z0-9-]*/krmApiHosts/[A-Za-z0-9_-]+"),
            (LOGGING_VIEW_TECHNIQUE,
             r"projects/[^/]+/locations/[a-z0-9-]+/buckets/[A-Za-z0-9_.-]+/views/[A-Za-z0-9_-]+"),
            (NETWORKSECURITY_ADDRESS_GROUP_TECHNIQUE,
             r"projects/[^/]+/locations/[^/]+/addressGroups/[^/]+"),
            (NETWORKSECURITY_AUTHORIZATION_POLICY_TECHNIQUE,
             r"projects/[^/]+/locations/[^/]+/authorizationPolicies/[^/]+"),
            (NETWORKSECURITY_AUTHZ_POLICY_TECHNIQUE,
             r"projects/[^/]+/locations/[^/]+/authzPolicies/[^/]+"),
            (NETWORKSECURITY_CLIENT_TLS_POLICY_TECHNIQUE,
             r"projects/[^/]+/locations/[^/]+/clientTlsPolicies/[^/]+"),
            (NETWORKSECURITY_SERVER_TLS_POLICY_TECHNIQUE,
             r"projects/[^/]+/locations/[^/]+/serverTlsPolicies/[^/]+")):
        if (record.get("TechniqueId") == technique
                and (not re.fullmatch(pattern, resource)
                     or record.get("GrantedResource") != resource)):
            return False
    # A policy grant can be effective on the resource or a child governed by
    # it. The reviewed allow result must identify
    # the exact resource where the newly granted permission was tested.
    granted_resource = record["GrantedResource"]
    if granted_resource != resource and not granted_resource.startswith(resource + "/"):
        return False
    if record.get("TechniqueId") == HEALTHCARE_DATASET_TECHNIQUE:
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+", resource)
                or not re.fullmatch(re.escape(resource) + r"/fhirStores/[^/]+", granted_resource)):
            return False
    if record.get("TechniqueId") == HEALTHCARE_DICOM_TECHNIQUE:
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/dicomStores/[^/]+", resource)
                or granted_resource != resource):
            return False
    if record.get("TechniqueId") == HEALTHCARE_FHIR_TECHNIQUE:
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/fhirStores/[^/]+", resource)
                or granted_resource != resource):
            return False
    if record.get("TechniqueId") == HEALTHCARE_HL7V2_TECHNIQUE:
        if (not re.fullmatch(r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/hl7V2Stores/[^/]+", resource)
                or granted_resource != resource):
            return False
    permissions = record.get("GrantedPermissions")
    if (not isinstance(permissions, list) or not permissions
            or any(not _name(permission) for permission in permissions)
            or len(permissions) != len(set(permissions))):
        return False
    if (record.get("TechniqueId") in (ANALYTICSHUB_EXCHANGE_TECHNIQUE, ANALYTICSHUB_LISTING_TECHNIQUE)
            and not _valid_analyticshub_review(record, scope, snapshot,
                listing=record["TechniqueId"] == ANALYTICSHUB_LISTING_TECHNIQUE)):
        return False
    if (record.get("TechniqueId") == CONTAINERANALYSIS_NOTE_TECHNIQUE
            and not _valid_containeranalysis_note_review(record, scope, snapshot)):
        return False
    if (record.get("TechniqueId") == DATACATALOG_TAG_TECHNIQUE
            and not _valid_datacatalog_tag_review(record, scope, snapshot)):
        return False
    if (record.get("TechniqueId") == DATACATALOG_TAXONOMY_TECHNIQUE
            and not _valid_datacatalog_taxonomy_review(record, scope, snapshot)):
        return False
    if (record.get("TechniqueId") == METASTORE_SERVICE_TECHNIQUE
            and not _valid_metastore_service_review(record, scope, snapshot)):
        return False
    if (record.get("TechniqueId") == BIGQUERY_CONNECTION_TECHNIQUE
            and not _valid_bigquery_connection_review(record, scope, snapshot)):
        return False
    if (record.get("TechniqueId") == DOMAINS_REGISTRATION_TECHNIQUE
            and not _valid_domains_registration_review(record, scope, snapshot)):
        return False
    return (record.get("Status") == "verified"
            and all(record.get(key) is True for key in (
                "PriorPermissionAbsent", "PolicyMutationAuthorized", "PolicyMutationAccepted", "AfterPermissionAllowed")))


def _node_id(technique, source, resource, granted_resource):
    digest = hashlib.sha256(f"{technique}\x00{source}\x00{resource}\x00{granted_resource}".encode()).hexdigest()[:20]
    return f"gcp_verified_authority:self-grant:{technique}:{digest}"


def load(model):
    """Return only unique records from complete project collections."""
    status = inventory_status(model.snapshot, COLLECTION)
    grouped = {}
    for collection_scope, record in items(model.snapshot, COLLECTION):
        scope = model._norm_scope(collection_scope)
        if not isinstance(record, dict) or not all(_name(record.get(key)) for key in (
                "TechniqueId", "SourceId", "TargetResource", "GrantedResource")):
            continue
        key = (record["TechniqueId"], record["SourceId"], scope,
               record["TargetResource"], record["GrantedResource"])
        grouped.setdefault(key, []).append((collection_scope, record))
    nodes, records = {}, {}
    for (technique, source, scope, resource, granted_resource), matches in grouped.items():
        if len(matches) != 1 or status.get(matches[0][0]) not in ("collected", "empty"):
            continue
        record = matches[0][1]
        if not _valid(record, scope, model.snapshot):
            continue
        ident = _node_id(technique, source, resource, granted_resource)
        # The reviewed resource-to-project join lets the ordinary GCP IAM
        # evaluator test the declared mutation permission on this exact target.
        if resource != scope:
            model.parents.setdefault(resource, scope)
        if granted_resource != resource:
            model.parents.setdefault(granted_resource, resource)
        nodes[ident] = Node(ident, "gcp_verified_authority", "gcp", scope,
                            f"{source} gains {', '.join(record['GrantedPermissions'])} on {granted_resource}",
                            attrs={"scope": scope, "resource": granted_resource,
                                   "policy_resource": resource, "source_id": source,
                                   "technique_id": technique}, entity=True)
        records[ident] = record
    return nodes, records


def select(model, candidates, source):
    """Join the reviewed new grant to the YAML action and its exact source."""
    entry = model.current_entry or {}
    if source is None or entry.get("target", {}).get("outcome") != "permission_grant":
        return {}
    technique = entry.get("id")
    grants = (entry.get("target") or {}).get("grants")
    if not isinstance(grants, list) or not grants:
        return {}
    def actions(value):
        if isinstance(value, dict):
            if isinstance(value.get("action"), str):
                yield value["action"].lower()
            for nested in value.values():
                yield from actions(nested)
        elif isinstance(value, list):
            for nested in value:
                yield from actions(nested)
    required_actions = set(actions(entry.get("requires") or {}))
    out = {}
    for target_id, node in candidates.items():
        if node.attrs.get("prospective_self_grant"):
            rule = PROSPECTIVE_RULES.get(technique)
            if (rule is None or node.attrs.get("prospective_technique") != technique
                    or source.kind not in ("gcp_user", "gcp_service_account")):
                continue
            kind, mutation, access = rule
            resource = node.attrs["policy_resource"]
            gain_resource = node.attrs.get("gain_resource", resource)
            if technique == FOLDER_TECHNIQUE:
                admin = model.roles.get("roles/resourcemanager.folderAdmin")
                if admin is None:
                    out[target_id] = ("unknown", "folder_admin_role_not_collected")
                    continue
                probes = [(permission, resource) for permission in (
                    "resourcemanager.folders.create", "resourcemanager.folders.delete",
                    "resourcemanager.folders.move", "resourcemanager.folders.update",
                    "resourcemanager.folders.undelete")]
                probes.extend(("resourcemanager.projects.setIamPolicy", project)
                              for project in sorted(model.scopes)
                              if project.startswith("projects/") and project.count("/") == 1
                              and resource in model.ancestors(project))
                missing = [(permission, target) for permission, target in probes
                           if admin.has(permission.lower())
                           and model.check(source, {"action": permission}, target) is None
                           and model._deny(source, permission, target, Grant()) is not None]
                if not missing:
                    if any(admin.has(permission.lower())
                           and (prior := model.check(source, {"action": permission}, target)) is not None
                           and prior.confidence != "derived" for permission, target in probes):
                        out[target_id] = ("unknown", "folder_admin_prior_permission_unresolved")
                    continue
                access, gain_resource = missing[0]
            if technique == PROJECT_TECHNIQUE:
                editor = model.roles.get("roles/editor")
                if editor is None:
                    out[target_id] = ("unknown", "project_editor_role_not_collected")
                    continue
                # A project-wide Editor binding is a new authorization only if
                # at least one included permission is absent at this project.
                # Keep the first definite new permission as the proof; a
                # conditional current grant cannot prove its absence.
                permissions = sorted(permission for permission in editor.native_permissions
                                     if permission and "*" not in permission)
                if not permissions:
                    out[target_id] = ("unknown", "project_editor_permissions_not_collected")
                    continue
                missing, unresolved = None, False
                for permission in permissions:
                    prior = model.check(source, {"action": permission}, resource)
                    if prior is not None:
                        unresolved |= prior.confidence != "derived"
                        continue
                    deny = model._deny(source, permission, resource, Grant())
                    if deny is None:
                        continue
                    if deny.confidence != "derived":
                        unresolved = True
                        continue
                    missing = permission
                    break
                if missing is None:
                    if unresolved:
                        out[target_id] = ("unknown", "project_editor_prior_permission_unresolved")
                    continue
                access = missing
            if (technique in (DATACATALOG_TAXONOMY_TECHNIQUE, IAP_ZONE_TECHNIQUE)
                    and (technique, source.id, resource, gain_resource)
                    in model.resource_self_grant_granted_record_keys):
                continue
            if (technique not in (DATACATALOG_TAXONOMY_TECHNIQUE, IAP_ZONE_TECHNIQUE)
                    and (technique, source.id, resource) in model.resource_self_grant_record_keys):
                continue
            authority = model.check(source, {"action": mutation}, resource)
            if authority is None:
                continue
            # A principal already holding the permission gains nothing from
            # another binding on the same resource.
            prior = model.check(source, {"action": access}, gain_resource)
            if prior is not None:
                if (technique in (DISK_TECHNIQUE, IMAGE_TECHNIQUE, SNAPSHOT_TECHNIQUE, RECOVERABLE_SNAPSHOT_TECHNIQUE,
                                  BIGQUERY_CONNECTION_TECHNIQUE, CONTAINERANALYSIS_NOTE_TECHNIQUE,
                                  DATACATALOG_TAG_TECHNIQUE,
                                  DATACATALOG_TAXONOMY_TECHNIQUE,
                                  METASTORE_SERVICE_TECHNIQUE,
                                  BIGTABLE_INSTANCE_TECHNIQUE,
                                  CONNECTOR_CONNECTION_TECHNIQUE,
                                  CONTACT_CENTER_VIEW_TECHNIQUE,
                                  DISCOVERYENGINE_COLLECTION_TECHNIQUE,
                                  DISCOVERYENGINE_DATA_STORE_TECHNIQUE,
                                  DISCOVERYENGINE_ENGINE_TECHNIQUE,
                                  DOMAINS_REGISTRATION_TECHNIQUE,
                                  BIGTABLE_INSTANCE_ADMIN_TECHNIQUE,
                                  BIGTABLE_AUTHORIZED_VIEW_TECHNIQUE,
                                  BIGTABLE_MATERIALIZED_VIEW_TECHNIQUE,
                                  BIGTABLE_TABLE_TECHNIQUE,
                                  BIGTABLE_BACKUP_TECHNIQUE, FLEET_MEMBERSHIP_TECHNIQUE,
                                  HEALTHCARE_CONSENT_TECHNIQUE, HEALTHCARE_DATASET_TECHNIQUE,
                                  HEALTHCARE_DICOM_TECHNIQUE, HEALTHCARE_FHIR_TECHNIQUE,
                                  HEALTHCARE_HL7V2_TECHNIQUE,
                                  IAP_INSTANCE_TECHNIQUE, IAP_ZONE_TECHNIQUE,
                                  FOLDER_TECHNIQUE, ORGANIZATION_TECHNIQUE,
                                  ORGANIZATION_DENY_TECHNIQUE, ORGANIZATION_ROLE_TECHNIQUE,
                                  PROJECT_TECHNIQUE, PROJECT_DELETER_TECHNIQUE,
                                  IDENTITYPLATFORM_TENANT_TECHNIQUE,
                                  KRM_API_HOST_TECHNIQUE,
                                  LOGGING_VIEW_TECHNIQUE,
                                  NCC_GROUP_TECHNIQUE,
                                  NCC_HUB_GROUP_USE_TECHNIQUE,
                                  NETWORKSECURITY_ADDRESS_GROUP_TECHNIQUE,
                                  NETWORKSECURITY_AUTHORIZATION_POLICY_TECHNIQUE,
                                  NETWORKSECURITY_AUTHZ_POLICY_TECHNIQUE,
                                  NETWORKSECURITY_CLIENT_TLS_POLICY_TECHNIQUE,
                                  NETWORKSECURITY_SERVER_TLS_POLICY_TECHNIQUE)
                        and prior.confidence != "derived"):
                    out[target_id] = ("unknown", "self_grant_prior_permission_unresolved")
                continue
            access_deny = model._deny(source, access, gain_resource, Grant())
            if access_deny is None:
                continue
            project = node.scope
            policy_status = model.resource_policy_status.get(kind, {}).get(resource)
            inventory = model.resource_inventory_status.get(kind, {})
            uncertain = (authority.confidence == "unknown"
                         or access_deny.confidence != "derived"
                         or policy_status != "collected"
                         or inventory.get(project) not in ("collected", "empty")
                         or inventory_status(model.snapshot, "org_policy_effective").get(project)
                         not in ("collected", "empty")
                         or model.deny_status.get(project) not in ("collected", "empty")
                         or any(role not in model.roles for _, role, _, _ in source.attrs.get("grants", ())))
            if technique == PRIVATECA_POOL_TECHNIQUE:
                requester = model.roles.get("roles/privateca.certificateRequester")
                if (authority.confidence != "derived" or requester is None
                        or requester.confidence != "derived" or not requester.has(access.lower())):
                    uncertain = True
            if technique in (IAP_INSTANCE_TECHNIQUE, IAP_ZONE_TECHNIQUE):
                zone = gain_resource.rsplit("/instances/", 1)[0]
                root = zone.rsplit("/zones/", 1)[0]
                accessor = model.roles.get("roles/iap.tunnelResourceAccessor")
                ancestors = [scope for scope in model.ancestors(gain_resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or accessor is None or accessor.confidence != "derived"
                        or not accessor.has(access.lower())
                        or any(model.resource_policy_status.get("iap_tunnel_policy", {}).get(path)
                               != "collected" for path in (root, zone, gain_resource))
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == IDENTITYPLATFORM_TENANT_TECHNIQUE:
                admin = model.roles.get("roles/identityplatform.admin")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or admin is None or admin.confidence != "derived"
                        or not admin.has(access.lower())
                        or model.resource_policy_status.get(kind, {}).get(resource) != "collected"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == KRM_API_HOST_TECHNIQUE:
                admin = model.roles.get("roles/krmapihosting.admin")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or node.attrs.get("host_state") != "RUNNING"
                        or admin is None or admin.confidence != "derived"
                        or not admin.has(access.lower())
                        or model.resource_policy_status.get(kind, {}).get(resource) != "collected"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == LOGGING_VIEW_TECHNIQUE:
                accessor = model.roles.get("roles/logging.viewAccessor")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or accessor is None or accessor.confidence != "derived"
                        or not accessor.has(access.lower())
                        or model.resource_policy_status.get(kind, {}).get(resource) != "collected"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == FOLDER_TECHNIQUE:
                folder_rows = [row for scope, row in items(model.snapshot, "folder")
                               if model._norm_scope(scope) == resource and row.get("name") == resource]
                root_policies = [row for scope, row in items(model.snapshot, "iam_policy")
                                 if model._norm_scope(scope) == resource and row.get("name") == resource]
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("folders/", "organizations/")) and scope.count("/") == 1]
                policy_scopes = (resource, *ancestors, *((gain_resource,)
                                 if gain_resource != resource else ()))
                pab_scopes = set(policy_scopes)
                if source.kind == "gcp_service_account":
                    home = source.attrs.get("project") or source.scope
                    if isinstance(home, str) and home.startswith("projects/"):
                        pab_scopes.add(home)
                        pab_scopes.update(scope for scope in model.ancestors(home)
                                          if scope.startswith(("folders/", "organizations/")))
                inherited_policies = [row for scope, row in items(model.snapshot, "iam_policy")
                                      if model._norm_scope(scope) in policy_scopes
                                      and row.get("name") == model._norm_scope(scope)]
                group_bindings = any(
                    isinstance(member, str) and member.startswith("group:")
                    for policy in inherited_policies
                    for binding in (policy.get("bindings") if isinstance(policy.get("bindings"), list) else [])
                    if isinstance(binding, dict)
                    for member in (binding.get("members") if isinstance(binding.get("members"), list) else []))
                group_scopes = [scope for scope in (resource, *ancestors)
                                if scope.startswith("organizations/")]
                pab_orgs = [scope for scope in pab_scopes if scope.startswith("organizations/")]
                pab_bindings = [row for scope, row in items(model.snapshot, "policy_binding")
                                if model._norm_scope(scope) in pab_scopes
                                and row.get("policyKind") == "PRINCIPAL_ACCESS_BOUNDARY"]
                grant_constraints = [row for scope, row in items(model.snapshot, "folder_policy_grant_constraints")
                                     if model._norm_scope(scope) == resource]
                restrictive_or_unknown_constraint = any(
                    not isinstance(row.get("spec"), dict)
                    or not isinstance(row["spec"].get("rules", []), list)
                    or any(not isinstance(rule, dict) or rule.get("allowAll") is not True
                           for rule in row["spec"].get("rules", []))
                    for row in grant_constraints)
                uncertain = (authority.confidence != "derived" or access_deny.confidence != "derived"
                             or len(folder_rows) != 1 or folder_rows[0].get("state") != "ACTIVE"
                             or inventory_status(model.snapshot, "folder").get(resource) != "collected"
                             or len(root_policies) != 1
                             or root_policies[0].get("_representation") != "full"
                             or not isinstance(root_policies[0].get("bindings"), list)
                             or model.iam_policy_inventory_status.get(resource) != "collected"
                             or admin.confidence != "derived"
                             or not admin.has(access.lower())
                             or inventory_status(model.snapshot, "folder_policy_grant_constraints").get(resource)
                             not in ("collected", "empty")
                             or restrictive_or_unknown_constraint
                             or bool(pab_bindings)
                             or any(inventory_status(model.snapshot, "policy_binding").get(scope)
                                    not in ("collected", "empty") for scope in pab_scopes)
                             or any(inventory_status(model.snapshot, "principal_access_boundary_policy").get(scope)
                                    not in ("collected", "empty") for scope in pab_orgs)
                             or (group_bindings and (
                                 not group_scopes or any(
                                     model.group_membership_status.get(scope) not in ("collected", "empty")
                                     or inventory_status(model.snapshot, "group").get(scope)
                                     not in ("collected", "empty") for scope in group_scopes)))
                             or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                                    or (scope != resource and model.iam_role_inventory_status.get(scope)
                                        not in ("collected", "empty"))
                                    or model.deny_status.get(scope) not in ("collected", "empty")
                                    for scope in policy_scopes))
            if technique in (ORGANIZATION_TECHNIQUE, ORGANIZATION_DENY_TECHNIQUE,
                             ORGANIZATION_ROLE_TECHNIQUE):
                role_name = ("roles/iam.denyAdmin" if technique == ORGANIZATION_DENY_TECHNIQUE else
                             "roles/iam.organizationRoleAdmin" if technique == ORGANIZATION_ROLE_TECHNIQUE
                             else "roles/orgpolicy.policyAdmin")
                admin = model.roles.get(role_name)
                role_rows = [row for scope, row in items(model.snapshot, "iam_role_builtin")
                             if model._norm_scope(scope) == resource and row.get("name") == role_name]
                org_rows = [row for scope, row in items(model.snapshot, "organization")
                            if model._norm_scope(scope) == resource and row.get("name") == resource]
                root_policies = [row for scope, row in items(model.snapshot, "iam_policy")
                                 if model._norm_scope(scope) == resource and row.get("name") == resource]
                constraints = [row for scope, row in items(model.snapshot, "organization_policy_grant_constraints")
                               if model._norm_scope(scope) == resource]
                pab_scopes = {resource}
                if source.kind == "gcp_service_account":
                    home = source.attrs.get("project") or source.scope
                    if isinstance(home, str) and home.startswith("projects/"):
                        pab_scopes.add(home)
                        pab_scopes.update(scope for scope in model.ancestors(home)
                                          if scope.startswith(("folders/", "organizations/")))
                restrictive_or_unknown = any(
                    not isinstance(row.get("spec"), dict)
                    or not isinstance(row["spec"].get("rules", []), list)
                    or any(not isinstance(rule, dict) or rule.get("allowAll") is not True
                           for rule in row["spec"].get("rules", [])) for row in constraints)
                pab = any(row.get("policyKind") == "PRINCIPAL_ACCESS_BOUNDARY"
                          for scope, row in items(model.snapshot, "policy_binding")
                          if model._norm_scope(scope) in pab_scopes)
                group_binding = any(
                    isinstance(member, str) and member.startswith("group:")
                    for policy in root_policies
                    for binding in (policy.get("bindings") if isinstance(policy.get("bindings"), list) else [])
                    if isinstance(binding, dict)
                    for member in (binding.get("members") if isinstance(binding.get("members"), list) else []))
                uncertain = (authority.confidence != "derived" or access_deny.confidence != "derived"
                             or len(org_rows) != 1 or org_rows[0].get("state") != "ACTIVE"
                             or inventory_status(model.snapshot, "organization").get(resource) != "collected"
                             or len(root_policies) != 1 or root_policies[0].get("_representation") != "full"
                             or not isinstance(root_policies[0].get("bindings"), list)
                             or model.iam_policy_inventory_status.get(resource) != "collected"
                             or model.iam_role_inventory_status.get(resource) not in ("collected", "empty")
                             or model.deny_status.get(resource) not in ("collected", "empty")
                             or inventory_status(model.snapshot, "iam_role_builtin").get(resource) != "collected"
                             or len(role_rows) != 1 or not isinstance(role_rows[0].get("includedPermissions"), list)
                             or access.lower() not in {str(permission).lower()
                                                       for permission in role_rows[0].get("includedPermissions", [])}
                             or admin is None or admin.confidence != "derived" or not admin.has(access.lower())
                             or inventory_status(model.snapshot, "organization_policy_grant_constraints").get(resource)
                             not in ("collected", "empty") or restrictive_or_unknown
                             or pab
                             or any(inventory_status(model.snapshot, "policy_binding").get(scope)
                                    not in ("collected", "empty") for scope in pab_scopes)
                             or any(inventory_status(model.snapshot, "principal_access_boundary_policy").get(scope)
                                    not in ("collected", "empty") for scope in pab_scopes
                                    if scope.startswith("organizations/"))
                             or (group_binding and (
                                 model.group_membership_status.get(resource) not in ("collected", "empty")
                                 or inventory_status(model.snapshot, "group").get(resource)
                                 not in ("collected", "empty"))))
            if technique in (PROJECT_TECHNIQUE, PROJECT_DELETER_TECHNIQUE):
                role_name = ("roles/editor" if technique == PROJECT_TECHNIQUE
                             else "roles/resourcemanager.projectDeleter")
                project_role = model.roles.get(role_name)
                role_rows = [row for scope, row in items(model.snapshot, "iam_role_builtin")
                             if model._norm_scope(scope) == resource and row.get("name") == role_name]
                project_rows = [row for scope, row in items(model.snapshot, "project")
                                if model._norm_scope(scope) == resource
                                and row.get("projectId") == resource.split("/", 1)[1]]
                root_policies = [row for scope, row in items(model.snapshot, "iam_policy")
                                 if model._norm_scope(scope) == resource
                                 and model._norm_scope(row.get("name")) == resource]
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("folders/", "organizations/")) and scope.count("/") == 1]
                policy_scopes = (resource, *ancestors)
                pab_scopes = set(policy_scopes)
                if source.kind == "gcp_service_account":
                    home = source.attrs.get("project") or source.scope
                    if isinstance(home, str) and home.startswith("projects/"):
                        pab_scopes.add(home)
                        pab_scopes.update(scope for scope in model.ancestors(home)
                                          if scope.startswith(("folders/", "organizations/")))
                member_constraints = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}
                constraints = [row for scope, row in items(model.snapshot, "org_policy_effective")
                               if model._norm_scope(scope) == resource
                               and row.get("constraint") in member_constraints]
                restrictive_or_unknown = any(
                    not isinstance(row.get("spec"), dict)
                    or not isinstance(row["spec"].get("rules", []), list)
                    or any(not isinstance(rule, dict) or rule.get("allowAll") is not True
                           for rule in row["spec"].get("rules", [])) for row in constraints)
                pab = any(row.get("policyKind") == "PRINCIPAL_ACCESS_BOUNDARY"
                          for scope, row in items(model.snapshot, "policy_binding")
                          if model._norm_scope(scope) in pab_scopes)
                inherited_policies = [row for scope, row in items(model.snapshot, "iam_policy")
                                      if model._norm_scope(scope) in policy_scopes]
                group_binding = any(
                    isinstance(member, str) and member.startswith("group:")
                    for policy in inherited_policies
                    for binding in (policy.get("bindings") if isinstance(policy.get("bindings"), list) else [])
                    if isinstance(binding, dict)
                    for member in (binding.get("members") if isinstance(binding.get("members"), list) else []))
                group_scopes = [scope for scope in policy_scopes if scope.startswith("organizations/")]
                email = source.attrs.get("email", "") if source.kind == "gcp_service_account" else ""
                default_sa = bool(re.fullmatch(
                    r"(?:[a-z][a-z0-9-]{4,28}[a-z0-9]@appspot\.gserviceaccount\.com|"
                    r"[0-9]+-compute@developer\.gserviceaccount\.com)", email))
                basic_role_constraint = "iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts"
                basic_role_rows = [row for scope, row in items(model.snapshot, "org_policy_effective")
                                   if model._norm_scope(scope) == resource
                                   and row.get("constraint") == basic_role_constraint]
                basic_role_enforced = (model._effective_boolean_policy(resource, basic_role_constraint)
                                       if technique == PROJECT_TECHNIQUE and default_sa and basic_role_rows
                                       else False)
                if basic_role_enforced is True:
                    continue
                uncertain = (authority.confidence != "derived" or access_deny.confidence != "derived"
                             or len(project_rows) != 1 or project_rows[0].get("state") != "ACTIVE"
                             or inventory_status(model.snapshot, "project").get(resource) != "collected"
                             or len(root_policies) != 1 or root_policies[0].get("_representation") != "full"
                             or not isinstance(root_policies[0].get("bindings"), list)
                             or inventory_status(model.snapshot, "iam_role_builtin").get(resource) != "collected"
                             or len(role_rows) != 1 or not isinstance(role_rows[0].get("includedPermissions"), list)
                             or access.lower() not in {str(permission).lower()
                                                       for permission in role_rows[0].get("includedPermissions", [])}
                             or project_role is None or project_role.confidence != "derived"
                             or not project_role.has(access.lower())
                             or basic_role_enforced is None
                             or inventory_status(model.snapshot, "org_policy_effective").get(resource)
                             not in ("collected", "empty") or restrictive_or_unknown or pab
                             or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                                    or (scope.startswith(("projects/", "organizations/"))
                                        and model.iam_role_inventory_status.get(scope)
                                        not in ("collected", "empty"))
                                    or model.deny_status.get(scope) not in ("collected", "empty")
                                    or inventory_status(model.snapshot, "policy_binding").get(scope)
                                    not in ("collected", "empty") for scope in policy_scopes)
                             or any(inventory_status(model.snapshot, "principal_access_boundary_policy").get(scope)
                                    not in ("collected", "empty") for scope in pab_scopes
                                    if scope.startswith("organizations/"))
                             or (group_binding and (not group_scopes or any(
                                 model.group_membership_status.get(scope) not in ("collected", "empty")
                                 or inventory_status(model.snapshot, "group").get(scope)
                                 not in ("collected", "empty") for scope in group_scopes))))
            if technique == DISCOVERYENGINE_COLLECTION_TECHNIQUE:
                viewer = model.roles.get("roles/discoveryengine.agentspaceViewer")
                if (authority.confidence != "derived" or viewer is None
                        or viewer.confidence != "derived" or not viewer.has(access.lower())):
                    uncertain = True
            if technique == DOMAINS_REGISTRATION_TECHNIQUE:
                editor = model.roles.get("roles/domains.editor")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or editor is None
                        or editor.confidence != "derived" or not editor.has(access.lower())
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique in (DISCOVERYENGINE_DATA_STORE_TECHNIQUE,
                             DISCOVERYENGINE_ENGINE_TECHNIQUE):
                admin = model.roles.get("roles/discoveryengine.agentspaceAdmin")
                if (authority.confidence != "derived" or admin is None
                        or admin.confidence != "derived" or not admin.has(access.lower())):
                    uncertain = True
            if technique == SUBSCRIPTION_TECHNIQUE and node.attrs.get("delivery_mode") != "pull":
                uncertain = True
            if technique == KMS_TECHNIQUE and (node.attrs.get("key_purpose") not in (
                    "ENCRYPT_DECRYPT", "ASYMMETRIC_DECRYPT", "RAW_ENCRYPT_DECRYPT")
                    or node.attrs.get("enabled_version") is not True):
                uncertain = True
            if technique == KMS_TECHNIQUE and model.kms_ring_policy_status.get(
                    resource.rsplit("/cryptoKeys/", 1)[0]) != "collected":
                uncertain = True
            if technique == ARTIFACT_TECHNIQUE and node.attrs.get("repository_mode") != "STANDARD_REPOSITORY":
                uncertain = True
            if technique == CONTAINERANALYSIS_NOTE_TECHNIQUE:
                attacher = model.roles.get("roles/containeranalysis.notes.attacher")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or attacher is None
                        or attacher.confidence != "derived" or not attacher.has(access.lower())
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == DATACATALOG_TAG_TECHNIQUE:
                reader = model.roles.get("roles/datacatalog.categoryFineGrainedReader")
                taxonomy = resource.rsplit("/policyTags/", 1)[0]
                chain = model.ancestors(resource)
                tag_ancestors = [name for name in chain
                                 if name.startswith(taxonomy + "/policyTags/")]
                ancestors = [scope for scope in chain
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or reader is None
                        or reader.confidence != "derived" or not reader.has(access.lower())
                        or "FINE_GRAINED_ACCESS_CONTROL" not in (
                            model.datacatalog_taxonomies.get(taxonomy, {}).get("activatedPolicyTypes") or [])
                        or taxonomy not in chain or len(tag_ancestors) > 5
                        or model.resource_policy_status.get("datacatalog_taxonomy", {}).get(taxonomy) != "collected"
                        or any(model.resource_policy_status.get("datacatalog_policy_tag", {}).get(name)
                               != "collected" for name in tag_ancestors)
                        or inventory_status(model.snapshot, "datacatalog_taxonomy").get(project)
                           not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == DATACATALOG_TAXONOMY_TECHNIQUE:
                taxonomy = resource
                tag = gain_resource
                reader = model.roles.get("roles/datacatalog.categoryFineGrainedReader")
                chain = model.ancestors(tag)
                tag_ancestors = [name for name in chain
                                 if name.startswith(taxonomy + "/policyTags/")]
                ancestors = [scope for scope in chain
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or reader is None
                        or reader.confidence != "derived" or not reader.has(access.lower())
                        or "FINE_GRAINED_ACCESS_CONTROL" not in (
                            model.datacatalog_taxonomies.get(taxonomy, {}).get("activatedPolicyTypes") or [])
                        or taxonomy not in chain or len(tag_ancestors) > 5
                        or model.resource_policy_status.get("datacatalog_taxonomy", {}).get(taxonomy) != "collected"
                        or any(model.resource_policy_status.get("datacatalog_policy_tag", {}).get(name)
                               != "collected" for name in tag_ancestors)
                        or inventory_status(model.snapshot, "datacatalog_policy_tag").get(project)
                           not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == METASTORE_SERVICE_TECHNIQUE:
                viewer = model.roles.get("roles/metastore.metadataViewer")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or viewer is None
                        or viewer.confidence != "derived" or not viewer.has(access.lower())
                        or node.attrs.get("service_state") != "ACTIVE"
                        or node.attrs.get("endpoint_protocol") != "GRPC"
                        or ((model.snapshot.get("metadata") or {}).get("collector") == "native-gcp"
                            and node.attrs.get("service_details_collected") is not True)
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == ANALYTICSHUB_LISTING_TECHNIQUE:
                parent = resource.rsplit("/listings/", 1)[0]
                if model.resource_policy_status.get("analyticshub_data_exchange", {}).get(parent) != "collected":
                    uncertain = True
            if technique == BIGLAKE_NAMESPACE_TECHNIQUE:
                parent = resource.rsplit("/namespaces/", 1)[0]
                if model.resource_policy_status.get("biglake_catalog", {}).get(parent) != "collected":
                    uncertain = True
            if technique == BIGLAKE_TABLE_TECHNIQUE:
                namespace = resource.rsplit("/tables/", 1)[0]
                catalog = namespace.rsplit("/namespaces/", 1)[0]
                if (model.resource_policy_status.get("biglake_namespace", {}).get(namespace) != "collected"
                        or model.resource_policy_status.get("biglake_catalog", {}).get(catalog) != "collected"):
                    uncertain = True
            if technique in (BIGQUERY_DATASET_TECHNIQUE, BIGQUERY_DATASET_UPDATE_TECHNIQUE):
                if (inventory_status(model.snapshot, "bigquery_table").get(project) not in ("collected", "empty")
                        or model.resource_policy_status.get("bigquery_table", {}).get(gain_resource) != "collected"):
                    uncertain = True
                dataset_item = model.bigquery_datasets.get(resource, {})
                if model.bigquery_dataset_access_uncertain(source, dataset_item, project):
                    uncertain = True
                if technique == BIGQUERY_DATASET_UPDATE_TECHNIQUE:
                    # datasets.update alone changes ACLs only while fine-grained
                    # dataset ACL enforcement is disabled for this project/region.
                    mode = model.bigquery_acl_mode.get((project, dataset_item.get("location")))
                    if mode is True:
                        continue
                    if mode is not False:
                        uncertain = True
            if technique == BIGQUERY_TABLE_TECHNIQUE:
                dataset = resource.rsplit("/tables/", 1)[0]
                dataset_item = model.bigquery_datasets.get(dataset)
                if (inventory_status(model.snapshot, "bigquery_table").get(project) not in ("collected", "empty")
                        or model.resource_policy_status.get("bigquery_table", {}).get(resource) != "collected"
                        or model.resource_policy_status.get("bigquery_dataset", {}).get(dataset) != "collected"
                        or not isinstance(dataset_item, dict)):
                    uncertain = True
                elif model.bigquery_dataset_access_uncertain(source, dataset_item, project):
                    uncertain = True
            if technique == BIGQUERY_CONNECTION_TECHNIQUE:
                ancestor_scopes = [scope for scope in model.ancestors(resource)
                                   if scope.startswith(("projects/", "folders/", "organizations/"))
                                   and scope.count("/") == 1]
                if (node.attrs.get("connection_details_collected") is not True
                        or node.attrs.get("connection_type") is None
                        or "roles/bigquery.connectionUser" not in model.roles
                        or authority.confidence != "derived"
                        or any(inventory_status(model.snapshot, "iam_policy").get(scope)
                               not in ("collected", "empty") for scope in ancestor_scopes)
                        or any(inventory_status(model.snapshot, "iam_role").get(scope)
                               not in ("collected", "empty") for scope in ancestor_scopes)
                        or any(model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestor_scopes)):
                    uncertain = True
            if technique == CONNECTOR_CONNECTION_TECHNIQUE:
                ancestor_scopes = [scope for scope in model.ancestors(resource)
                                   if scope.startswith(("projects/", "folders/", "organizations/"))
                                   and scope.count("/") == 1]
                invoker = model.roles.get("roles/connectors.invoker")
                if (node.attrs.get("connection_details_collected") is not True
                        or node.attrs.get("connection_state") != "ACTIVE"
                        or node.attrs.get("connection_suspended") not in (False, None)
                        or invoker is None or not invoker.has(access.lower())
                        or authority.confidence != "derived"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestor_scopes)):
                    uncertain = True
            if technique == CONTACT_CENTER_VIEW_TECHNIQUE:
                ancestor_scopes = [scope for scope in model.ancestors(resource)
                                   if scope.startswith(("projects/", "folders/", "organizations/"))
                                   and scope.count("/") == 1]
                viewer = model.roles.get("roles/contactcenterinsights.authorizedViewer")
                if (node.attrs.get("view_details_collected") is not True
                        or viewer is None or not viewer.has(access.lower())
                        or authority.confidence != "derived"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestor_scopes)):
                    uncertain = True
            if technique == BIGTABLE_AUTHORIZED_VIEW_TECHNIQUE:
                table = resource.rsplit("/authorizedViews/", 1)[0]
                instance = table.rsplit("/tables/", 1)[0]
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or model.resource_policy_status.get("bigtable_table", {}).get(table) != "collected"
                        or model.resource_policy_status.get("bigtable_instance", {}).get(instance) != "collected"
                        or inventory_status(model.snapshot, "bigtable_table").get(project) not in ("collected", "empty")
                        or inventory_status(model.snapshot, "bigtable_instance").get(project) not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
                base_read = model.check(source, {"action": "bigtable.tables.readRows"}, table)
                if base_read is not None:
                    if base_read.confidence == "derived":
                        continue
                    uncertain = True
            if technique == BIGTABLE_MATERIALIZED_VIEW_TECHNIQUE:
                instance = resource.rsplit("/materializedViews/", 1)[0]
                view = model.bigtable_materialized_views.get(resource) or {}
                states = view.get("clusterStates")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or model.resource_policy_status.get("bigtable_instance", {}).get(instance) != "collected"
                        or inventory_status(model.snapshot, "bigtable_instance").get(project) not in ("collected", "empty")
                        or ((view.get("_coverage") or {}).get("details") or {}).get("status") != "collected"
                        or not isinstance(view.get("query"), str) or not view["query"].strip()
                        or not isinstance(states, dict) or not states
                        or not any(isinstance(state, dict) and state.get("replicationState") == "READY"
                                   for state in states.values())
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == BIGTABLE_TABLE_TECHNIQUE:
                instance = resource.rsplit("/tables/", 1)[0]
                table = model.bigtable_tables.get(resource) or {}
                states = table.get("clusterStates")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or model.resource_policy_status.get("bigtable_instance", {}).get(instance) != "collected"
                        or model.bigtable_instances.get(instance, {}).get("state") != "READY"
                        or inventory_status(model.snapshot, "bigtable_instance").get(project) not in ("collected", "empty")
                        or ((table.get("_coverage") or {}).get("details") or {}).get("status") != "collected"
                        or not isinstance(states, dict) or not states
                        or not any(isinstance(state, dict) and state.get("replicationState") in ("READY", "READY_OPTIMIZING")
                                   for state in states.values())
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == BIGTABLE_BACKUP_TECHNIQUE:
                instance = resource.rsplit("/clusters/", 1)[0]
                backup = model.bigtable_backups.get(resource) or {}
                source_table = backup.get("sourceTable")
                encryption = backup.get("encryptionInfo")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or model.resource_policy_status.get("bigtable_instance", {}).get(instance) != "collected"
                        or inventory_status(model.snapshot, "bigtable_instance").get(project) not in ("collected", "empty")
                        or not isinstance(source_table, str)
                        or not re.fullmatch(re.escape(instance) + r"/tables/[^/]+", source_table)
                        or backup.get("state") != "READY"
                        or not isinstance(encryption, dict)
                        or encryption.get("encryptionType") != "GOOGLE_DEFAULT_ENCRYPTION"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
                try:
                    if _instant(backup.get("expireTime")) <= datetime.now(timezone.utc):
                        continue
                except (TypeError, ValueError, OverflowError):
                    uncertain = True
            if technique in (BIGTABLE_INSTANCE_TECHNIQUE, BIGTABLE_INSTANCE_ADMIN_TECHNIQUE):
                instance = resource
                table = gain_resource
                ancestors = [scope for scope in model.ancestors(instance)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived"
                        or model.bigtable_instances.get(instance, {}).get("state") != "READY"
                        or (technique == BIGTABLE_INSTANCE_TECHNIQUE
                            and model.resource_policy_status.get("bigtable_table", {}).get(table) != "collected")
                        or (technique == BIGTABLE_INSTANCE_TECHNIQUE
                            and inventory_status(model.snapshot, "bigtable_table").get(project) not in ("collected", "empty"))
                        or inventory_status(model.snapshot, "bigtable_instance").get(project) not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == BIGQUERY_ROW_POLICY_TECHNIQUE:
                row_status = model.bigquery_row_policy_status.get(resource)
                policies = model.bigquery_row_policies.get(resource, ())
                if row_status != "collected":
                    uncertain = True
                elif not policies or len(policies) >= 400:
                    continue
                prior, prior_uncertain = model.bigquery_row_policy_prior_access(source, resource)
                if prior:
                    continue
                if prior_uncertain:
                    uncertain = True
                if (inventory_status(model.snapshot, "bigquery_table").get(project) not in ("collected", "empty")
                        or model.resource_policy_status.get("bigquery_table", {}).get(resource) != "collected"):
                    uncertain = True
            if technique == DISK_TECHNIQUE:
                role = model.roles.get("roles/compute.storageAdmin")
                if (authority.confidence != "derived" or role is None
                        or role.confidence != "derived" or not role.has(access.lower())
                        or node.attrs.get("policy_resource") not in model.disks):
                    uncertain = True
            if technique == IMAGE_TECHNIQUE:
                role = model.roles.get("roles/compute.imageUser")
                if (authority.confidence != "derived" or role is None
                        or role.confidence != "derived" or not role.has(access.lower())
                        or node.attrs.get("policy_resource") not in model.images
                        or node.attrs.get("image_status") != "READY"):
                    uncertain = True
            if technique == INSTANCE_TECHNIQUE:
                role = model.roles.get("roles/compute.osAdminLogin")
                policy_read = model.check(source, {"action": "compute.instances.getIamPolicy"}, resource)
                if (authority.confidence != "derived" or role is None
                        or role.confidence != "derived" or not role.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or node.attrs.get("policy_resource") not in model.resource_policy_status["instance"]):
                    uncertain = True
            if technique == FLEET_MEMBERSHIP_TECHNIQUE:
                reader = model.roles.get("roles/gkehub.gatewayReader")
                policy_read = model.check(source, {"action": "gkehub.memberships.getIamPolicy"}, resource)
                ancestor_scopes = [scope for scope in model.ancestors(resource)
                                   if scope.startswith(("projects/", "folders/", "organizations/"))
                                   and scope.count("/") == 1]
                if (authority.confidence != "derived" or reader is None
                        or reader.confidence != "derived" or not reader.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or node.attrs.get("membership_state") != "READY"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestor_scopes)):
                    uncertain = True
            if technique == HEALTHCARE_CONSENT_TECHNIQUE:
                reader = model.roles.get("roles/healthcare.consentReader")
                dataset = resource.rsplit("/consentStores/", 1)[0]
                policy_read = model.check(source, {
                    "action": "healthcare.consentStores.getIamPolicy"}, resource)
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or reader is None
                        or reader.confidence != "derived" or not reader.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or model.resource_policy_status.get("healthcare_dataset", {}).get(dataset) != "collected"
                        or model.resource_inventory_status.get("healthcare_dataset", {}).get(project)
                        not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == HEALTHCARE_DATASET_TECHNIQUE:
                reader = model.roles.get("roles/healthcare.fhirResourceReader")
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or reader is None
                        or reader.confidence != "derived" or not reader.has(access.lower())
                        or model.resource_policy_status.get("healthcare_fhir_store", {}).get(gain_resource) != "collected"
                        or model.resource_inventory_status.get("healthcare_fhir_store", {}).get(project)
                        not in ("collected", "empty")
                        or model.resource_inventory_status.get("healthcare_dataset", {}).get(project)
                        not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == HEALTHCARE_DICOM_TECHNIQUE:
                viewer = model.roles.get("roles/healthcare.dicomViewer")
                dataset = resource.rsplit("/dicomStores/", 1)[0]
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or viewer is None
                        or viewer.confidence != "derived" or not viewer.has(access.lower())
                        or model.resource_policy_status.get("healthcare_dataset", {}).get(dataset) != "collected"
                        or model.resource_inventory_status.get("healthcare_dataset", {}).get(project)
                        not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == HEALTHCARE_FHIR_TECHNIQUE:
                reader = model.roles.get("roles/healthcare.fhirResourceReader")
                dataset = resource.rsplit("/fhirStores/", 1)[0]
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or reader is None
                        or reader.confidence != "derived" or not reader.has(access.lower())
                        or model.resource_policy_status.get("healthcare_dataset", {}).get(dataset) != "collected"
                        or model.resource_inventory_status.get("healthcare_dataset", {}).get(project)
                        not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == HEALTHCARE_HL7V2_TECHNIQUE:
                consumer = model.roles.get("roles/healthcare.hl7V2Consumer")
                dataset = resource.rsplit("/hl7V2Stores/", 1)[0]
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or consumer is None
                        or consumer.confidence != "derived" or not consumer.has(access.lower())
                        or model.resource_policy_status.get("healthcare_dataset", {}).get(dataset) != "collected"
                        or model.resource_inventory_status.get("healthcare_dataset", {}).get(project)
                        not in ("collected", "empty")
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique in (NCC_GROUP_TECHNIQUE, NCC_HUB_GROUP_USE_TECHNIQUE):
                group = gain_resource
                hub = group.rsplit("/groups/", 1)[0]
                reader = model.roles.get("roles/networkconnectivity.groupUser")
                read_action = ("networkconnectivity.hubs.getIamPolicy" if
                               technique == NCC_HUB_GROUP_USE_TECHNIQUE else
                               "networkconnectivity.groups.getIamPolicy")
                policy_read = model.check(source, {"action": read_action}, resource)
                ancestors = [scope for scope in model.ancestors(group)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or reader is None
                        or reader.confidence != "derived" or not reader.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or model.resource_policy_status.get("network_connectivity_hub", {}).get(hub) != "collected"
                        or model.resource_policy_status.get("network_connectivity_hub_group", {}).get(group) != "collected"
                        or any(model.resource_inventory_status.get(kind, {}).get(project)
                               not in ("collected", "empty") for kind in (
                                   "network_connectivity_hub", "network_connectivity_hub_group"))
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique in (NETWORKSECURITY_ADDRESS_GROUP_TECHNIQUE,
                             NETWORKSECURITY_AUTHORIZATION_POLICY_TECHNIQUE,
                             NETWORKSECURITY_AUTHZ_POLICY_TECHNIQUE,
                             NETWORKSECURITY_CLIENT_TLS_POLICY_TECHNIQUE,
                             NETWORKSECURITY_SERVER_TLS_POLICY_TECHNIQUE):
                editor = model.roles.get("roles/networksecurity.editor")
                policy_read = model.check(source, {
                    "action": ("networksecurity.addressGroups.getIamPolicy" if
                               technique == NETWORKSECURITY_ADDRESS_GROUP_TECHNIQUE else
                               "networksecurity.authorizationPolicies.getIamPolicy" if
                               technique == NETWORKSECURITY_AUTHORIZATION_POLICY_TECHNIQUE else
                               "networksecurity.authzPolicies.getIamPolicy" if
                               technique == NETWORKSECURITY_AUTHZ_POLICY_TECHNIQUE else
                               "networksecurity.clientTlsPolicies.getIamPolicy" if
                               technique == NETWORKSECURITY_CLIENT_TLS_POLICY_TECHNIQUE else
                               "networksecurity.serverTlsPolicies.getIamPolicy")}, resource)
                ancestors = [scope for scope in model.ancestors(resource)
                             if scope.startswith(("projects/", "folders/", "organizations/"))
                             and scope.count("/") == 1]
                if (authority.confidence != "derived" or editor is None
                        or editor.confidence != "derived" or not editor.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or any(model.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                               or model.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                               or model.deny_status.get(scope) not in ("collected", "empty")
                               for scope in ancestors)):
                    uncertain = True
            if technique == MACHINE_IMAGE_TECHNIQUE:
                role = model.roles.get("roles/compute.admin")
                policy_read = model.check(source, {"action": "compute.machineImages.getIamPolicy"}, resource)
                if (authority.confidence != "derived" or role is None
                        or role.confidence != "derived" or not role.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or node.attrs.get("image_status") != "READY"
                        or node.attrs.get("policy_resource") not in model.resource_policy_status["machine_image"]):
                    uncertain = True
            if technique == RECOVERABLE_SNAPSHOT_TECHNIQUE:
                role = model.roles.get("roles/compute.storageAdmin")
                policy_read = model.check(source, {"action": "compute.recoverableSnapshots.getIamPolicy"}, resource)
                if (authority.confidence != "derived" or role is None
                        or role.confidence != "derived" or not role.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or node.attrs.get("snapshot_status") != "READY"
                        or resource not in model.resource_policy_status["recoverable_snapshot"]):
                    uncertain = True
            if technique == SNAPSHOT_TECHNIQUE:
                role = model.roles.get("roles/compute.storageAdmin")
                policy_read = model.check(source, {"action": "compute.snapshots.getIamPolicy"}, resource)
                if (authority.confidence != "derived" or role is None
                        or role.confidence != "derived" or not role.has(access.lower())
                        or policy_read is None or policy_read.confidence != "derived"
                        or node.attrs.get("snapshot_status") != "READY"
                        or resource not in model.resource_policy_status["snapshot"]):
                    uncertain = True
            constraints = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}
            if any(model._norm_scope(scope) == project and item.get("constraint") in constraints
                   for scope, item in items(model.snapshot, "org_policy_effective")):
                uncertain = True
            if (technique not in (FOLDER_TECHNIQUE, ORGANIZATION_TECHNIQUE,
                                  ORGANIZATION_DENY_TECHNIQUE, ORGANIZATION_ROLE_TECHNIQUE,
                                  PROJECT_TECHNIQUE, PROJECT_DELETER_TECHNIQUE)
                    and (model.group_membership_status.get(project) not in ("collected", "empty")
                         or inventory_status(model.snapshot, "group").get(project) not in ("collected", "empty"))):
                uncertain = True
            group_already_access = False
            for group_resource, members in model.group_members.items():
                if source.attrs.get("email", "").lower() not in members:
                    continue
                group_record = model.group_by_resource.get(group_resource)
                group_node = model.principals.get("group:" + group_record[0]) if group_record else None
                if group_node and model.check(group_node, {"action": access}, gain_resource) is not None:
                    group_already_access = True
                    break
            if group_already_access:
                continue
            if source.kind == "gcp_user":
                domain = source.attrs.get("email", "").lower().partition("@")[2]
                domain_node = model.principals.get("domain:" + domain)
                if domain_node and model.check(domain_node, {"action": access}, gain_resource) is not None:
                    continue
            out[target_id] = (("unknown", "self_grant_policy_or_prior_access_unresolved") if uncertain else
                              ("conditional", "exact_resource_policy_write_can_add_role_binding"))
            continue
        record = model.resource_self_grant_records.get(target_id)
        if (record is None or record["TechniqueId"] != technique
                or record["SourceId"] != source.id
                or record["GrantedPermissions"] != grants
                or node.attrs.get("policy_resource") != record["TargetResource"]
                or node.attrs.get("resource") != record["GrantedResource"]):
            continue
        permission = record["AccessPermission"]
        if permission.lower() not in required_actions:
            continue
        authority = model.check(source, {"action": permission}, record["TargetResource"])
        if authority is not None and authority.confidence != "unknown":
            out[target_id] = ("conditional", "reviewed_resource_self_grant")
    return out
