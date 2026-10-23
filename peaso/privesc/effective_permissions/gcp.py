"""GCP effective permissions: allow bindings with org/folder/project/resource inheritance.

  * principals are binding members (user:, serviceAccount:, group:, domain:) plus
    every collected service account; allUsers / allAuthenticatedUsers bindings
    apply to every principal,
  * role permissions come from collected iam_role items (custom + predefined
    fetched by name); a small builtin table covers the basic and key IAM roles
    when they were not collected; any other uncollected role is reported in
    coverage and contributes nothing,
  * IAM conditions on bindings: the decidable CEL subset (gcp_conditions: resource.name ==/startsWith,
    resource.type, resource.service, request.time) is evaluated per target resource; an expired
    binding is inactive; anything undecidable makes the edge conditional with the expression attached,
  * deny policies (iam_deny_policy) remove permissions for denied principals
    (unless excepted; denialCondition -> conditional). When deny policies were not
    collected for a scope, edges are conditional,
  * implicitDelegation chains (gcp_implicit_delegation_chain),
  * GKE clusters as k8s_cluster_admin entities and as the scope of KSA targets joined
    from related K8s snapshots (k8s_sa_has_token_secret / k8s_sa_in_cluster),
  * Workspace admin roles as a source selector (gcp_workspace_admin_role).
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter

from ..schema import FACTS_NEEDED
from . import gcp_conditions as cel
from . import (ANY, AllTargets, Grant, Model, Node, as_list, best, combine, downgrade, glob_match, inventory_status, items,
               unavailable)

_OWNER_EXCLUDED = ()
_BUILTIN = {
    # role -> (permissions pattern list, confidence)
    "roles/owner": (["*"], "derived"),
    "roles/editor": (["*.create", "*.update", "*.delete", "*.get", "*.list", "iam.serviceAccounts.actAs",
                      "iam.serviceAccountKeys.*", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob",
                      "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation", "*.run", "*.deploy",
                      "*.setMetadata", "*.setServiceAccount", "*.call", "*.invoke", "*.execute", "*.patch", "*.use",
                      "*.start", "*.upload", "*.uploadArtifacts", "*.sourceCodeSet", "*.setLabels",
                      "gkehub.gateway.generateCredentials"], "conditional"),
    "roles/iam.serviceAccountUser": (["iam.serviceAccounts.actAs", "iam.serviceAccounts.get", "iam.serviceAccounts.list"], "derived"),
    "roles/iam.serviceAccountTokenCreator": (["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken",
                                              "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.signBlob",
                                              "iam.serviceAccounts.signJwt", "iam.serviceAccounts.get", "iam.serviceAccounts.list"], "derived"),
    "roles/iam.serviceAccountKeyAdmin": (["iam.serviceAccountKeys.*", "iam.serviceAccounts.get", "iam.serviceAccounts.list"], "derived"),
    "roles/iam.serviceAccountAdmin": (["iam.serviceAccounts.*"], "conditional"),
    "roles/iam.securityAdmin": (["*.setIamPolicy", "*.getIamPolicy", "iam.roles.*", "iam.serviceAccountKeys.*"], "conditional"),
    "roles/resourcemanager.projectIamAdmin": (["resourcemanager.projects.setIamPolicy", "resourcemanager.projects.getIamPolicy"], "derived"),
    "roles/resourcemanager.folderIamAdmin": (["resourcemanager.folders.setIamPolicy", "resourcemanager.folders.getIamPolicy"], "derived"),
    "roles/resourcemanager.organizationAdmin": (["resourcemanager.*", "*.setIamPolicy", "*.getIamPolicy"], "conditional"),
    "roles/iam.roleAdmin": (["iam.roles.*"], "derived"),
    "roles/iam.organizationRoleAdmin": (["iam.roles.*"], "derived"),
    "roles/iam.workloadIdentityUser": (["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken"], "derived"),
    "roles/gkehub.gatewayReader": (["gkehub.gateway.generateCredentials", "gkehub.gateway.get",
                                    "gkehub.memberships.get"], "derived"),
    "roles/gkehub.gatewayAdmin": (["gkehub.gateway.*", "gkehub.memberships.get"], "derived"),
    "roles/iap.tunnelResourceAccessor": (["iap.tunnelInstances.accessViaIAP",
                                           "iap.tunnelDestGroups.accessViaIAP"], "derived"),
    "roles/identityplatform.admin": (["firebaseauth.users.update",
                                       "identitytoolkit.tenants.get"], "derived"),
    "roles/healthcare.consentReader": (["healthcare.consents.get", "healthcare.consents.list",
                                         "healthcare.consentStores.get"], "derived"),
    "roles/healthcare.fhirResourceReader": (["healthcare.fhirResources.get",
                                               "healthcare.fhirStores.searchResources"], "derived"),
    "roles/healthcare.dicomViewer": (["healthcare.dicomStores.dicomWebRead"], "derived"),
    "roles/healthcare.hl7V2Consumer": (["healthcare.hl7V2Messages.get",
                                         "healthcare.hl7V2Messages.list"], "derived"),
    "roles/networkconnectivity.groupUser": (["networkconnectivity.groups.use"], "derived"),
    "roles/networksecurity.editor": (["networksecurity.addressGroups.update", "networksecurity.authorizationPolicies.update", "networksecurity.authzPolicies.update", "networksecurity.clientTlsPolicies.update", "networksecurity.serverTlsPolicies.update"], "derived"),
    "roles/networksecurity.admin": (["networksecurity.*"], "derived"),
    "roles/privateca.certificateRequester": (["privateca.certificates.create"], "derived"),
    "roles/dataform.admin": (["dataform.*"], "derived"),
    "roles/bigquery.connectionUser": (["bigquery.connections.get", "bigquery.connections.getIamPolicy",
                                       "bigquery.connections.list", "bigquery.connections.use"], "derived"),
    "roles/containeranalysis.notes.attacher": (["containeranalysis.notes.attachOccurrence",
                                                 "containeranalysis.notes.get"], "derived"),
    "roles/datacatalog.categoryFineGrainedReader": (["datacatalog.categories.fineGrainedGet"], "derived"),
    "roles/metastore.metadataViewer": (["metastore.services.use"], "derived"),
    "roles/compute.storageAdmin": (["compute.disks.useReadOnly"], "derived"),
    "roles/compute.imageUser": (["compute.images.useReadOnly"], "derived"),
}
ADMIN_PERMS = {"projects": "resourcemanager.projects.setiampolicy", "folders": "resourcemanager.folders.setiampolicy",
               "organizations": "resourcemanager.organizations.setiampolicy"}
PUBLIC = ("allUsers", "allAuthenticatedUsers")
DELEGATE_PERM = "iam.serviceaccounts.implicitdelegation"
MINT_PERMS = ("iam.serviceaccounts.getaccesstoken", "iam.serviceaccounts.signblob", "iam.serviceaccounts.signjwt")
MAX_DELEGATION_DEPTH = 10
SERVICE_HOSTS = {"compute": "instance", "gce": "instance", "compute_instance": "instance",
                 "appengine_version": "app_engine_instance",
                 "run_service": "cloudrun_service", "run_job": "cloudrun_job",
                 "run_instance": "cloudrun_instance",
                 "run_worker_pool": "cloudrun_worker_pool",
                 "hypercomputecluster_cluster": "hypercomputecluster_cluster",
                 "inframanager_location": "inframanager_location",
                 "firebase_apphosting_backend": "firebase_apphosting_backend",
                 "cloudfunctions_function": "function",
                 "wif_active_pool_wide_binding": "wif_active_pool_wide_binding",
                 "wif_active_provider_pool_wide_binding": "wif_active_provider_pool_wide_binding",
                 "dataproc_cluster": "dataproc_cluster", "gke_nodepool": "gke_nodepool",
                 "composer_environment": "composer_environment",
                 "cloudbuild_unpinned_storage_source": "cloudbuild_build",
                 "cloudbuild_default_identity": "cloudbuild_default_sa",
                 "workflows_workflow": "workflows_workflow",
                 "workstations_config": "workstations_config",
                 "workstations_workstation": "workstations_workstation",
                 "notebooks_instance": "notebooks_instance",
                 "vmmigration_target_default": "vm_migration_vm"}
VERTEX_DEFAULT_AGENTS = {
    "vertex_custom_code_agent": ("gcp-sa-aiplatform-cc", "roles/aiplatform.customCodeServiceAgent"),
    "vertex_reasoning_engine_agent": ("gcp-sa-aiplatform-re", "roles/aiplatform.reasoningEngineServiceAgent"),
}
# attached_to_service values whose attachment inventory is not collected (yet): every candidate SA is reported as one
# unresolved placeholder per scope with a coverage note naming the value. A value in neither map is a catalog typo.
UNCOLLECTED_ATTACHMENTS = frozenset({
    "agentidentity_authorized_user", "agentregistry_skill_consumer",
    "appintegration_authconfig_identity", "artifact_consumer",
    "clouddeploy_target",
    "cloudservices_agent", "config_connector_identity", "dataflow_job",
    "dataform_workflow_config_end_user", "datafusion_instance",
    "integration_connector",
    "saasservicemgmt_unit", "wif_pool_bound",
    "workforce_pool_bound", "workspace_addon_user", "workspace_dwd_delegation",
    "workspace_super_admin_of_zone_domain",
})
REQUIRED_COLLECTIONS = ("agentidentity_auth_provider", "agentidentity_authorization")

# Only a verified reusable service-account private key reaches the full SA
# principal. OAuth/application tokens may be audience- or scope-bound and stay
# outside this typed-principal tranche.
_EXACT_TABLE_KEY_PERMISSIONS = {
    "gcp-bigquery-table-row-credential": ("bigquery.tables.getdata", "datasets"),
    "gcp-bigtable-row-credential": ("bigtable.tables.readrows", "instances"),
}
_EXACT_RUNNING_POD_UPDATE = "gcp-container-pods-update-running-ksa"


class Role:
    __slots__ = ("name", "patterns", "exact", "confidence", "universal", "native_permissions")

    def __init__(self, name, permissions, confidence="derived"):
        self.name = name
        self.native_permissions = tuple(str(p) for p in permissions)
        perms = [p.lower() for p in self.native_permissions]
        self.exact = {p for p in perms if "*" not in p}
        self.patterns = [p for p in perms if "*" in p]
        self.universal = "*" in perms
        self.confidence = confidence

    def has(self, perm):
        return perm in self.exact or any(glob_match(p, perm) for p in self.patterns)


class GcpModel(Model):
    provider = "gcp"

    def __init__(self, snapshot, catalog_keys=()):
        super().__init__(snapshot, catalog_keys)
        self.roles, self.parents, self.project_alias = {}, {}, {}
        self.grants = {}          # member -> list[(node name, role name, conditional, ref)]
        self.public = []          # grants that apply to every principal
        self.sas, self.scopes = {}, set()
        self.sa_by_resource = {}
        self.deny = []            # (attachment node, rule)
        self.deny_status = {}
        self.hosts = {}           # sa email -> {host kind: [resource]}
        self.host_status = {}
        self.vertex_agent_status = {}
        self.vertex_agents = {}
        self._holders = {}
        self._resdep = {}         # holders key -> {node: (unconditional best, [(expression, grant if true, grant if undecided)])}
        self.inactive_bindings = 0
        self.missing_roles = set()
        self._load()
        from .gcp_resource_self_grant import load as load_resource_self_grants
        self.resource_self_grant_targets, self.resource_self_grant_records = load_resource_self_grants(self)
        self.resource_self_grant_record_keys = {
            (row["TechniqueId"], row["SourceId"], row["TargetResource"])
            for row in self.resource_self_grant_records.values()}
        self.resource_self_grant_granted_record_keys = {
            (row["TechniqueId"], row["SourceId"], row["TargetResource"], row["GrantedResource"])
            for row in self.resource_self_grant_records.values()}
        from .gcp_resource_self_grant import (secret_candidates, topic_candidates,
                                               subscription_candidates, kms_key_candidates,
                                               artifact_repository_candidates,
                                               containeranalysis_note_candidates,
                                               datacatalog_policy_tag_candidates,
                                               datacatalog_taxonomy_candidates,
                                               metastore_service_candidates,
                                               analyticshub_exchange_candidates,
                                               analyticshub_listing_candidates,
                                               biglake_catalog_candidates,
                                               biglake_namespace_candidates,
                                               biglake_table_candidates,
                                               bigquery_dataset_candidates,
                                               bigquery_row_policy_candidates,
                                               bigquery_table_candidates,
                                               bigquery_connection_candidates,
                                               bigtable_authorized_view_candidates,
                                               bigtable_materialized_view_candidates,
                                               bigtable_table_candidates,
                                               bigtable_backup_candidates,
                                               bigtable_instance_candidates,
                                               bigtable_instance_admin_candidates,
                                               disk_candidates,
                                               image_candidates)
        self.secret_self_grant_targets = secret_candidates(self)
        self.topic_self_grant_targets = topic_candidates(self)
        self.subscription_self_grant_targets = subscription_candidates(self)
        self.kms_self_grant_targets = kms_key_candidates(self)
        self.artifact_self_grant_targets = artifact_repository_candidates(self)
        self.containeranalysis_note_self_grant_targets = containeranalysis_note_candidates(self)
        self.datacatalog_policy_tag_self_grant_targets = datacatalog_policy_tag_candidates(self)
        self.datacatalog_taxonomy_self_grant_targets = datacatalog_taxonomy_candidates(self)
        self.metastore_service_self_grant_targets = metastore_service_candidates(self)
        self.analyticshub_exchange_self_grant_targets = analyticshub_exchange_candidates(self)
        self.analyticshub_listing_self_grant_targets = analyticshub_listing_candidates(self)
        self.biglake_catalog_self_grant_targets = biglake_catalog_candidates(self)
        self.biglake_namespace_self_grant_targets = biglake_namespace_candidates(self)
        self.biglake_table_self_grant_targets = biglake_table_candidates(self)
        self.bigquery_dataset_self_grant_targets = bigquery_dataset_candidates(self)
        from .gcp_resource_self_grant import BIGQUERY_DATASET_UPDATE_TECHNIQUE
        self.bigquery_dataset_update_self_grant_targets = bigquery_dataset_candidates(
            self, BIGQUERY_DATASET_UPDATE_TECHNIQUE)
        self.bigquery_row_policy_self_grant_targets = bigquery_row_policy_candidates(self)
        self.bigquery_table_self_grant_targets = bigquery_table_candidates(self)
        self.bigquery_connection_self_grant_targets = bigquery_connection_candidates(self)
        self.bigtable_authorized_view_self_grant_targets = bigtable_authorized_view_candidates(self)
        self.bigtable_materialized_view_self_grant_targets = bigtable_materialized_view_candidates(self)
        self.bigtable_table_self_grant_targets = bigtable_table_candidates(self)
        self.bigtable_backup_self_grant_targets = bigtable_backup_candidates(self)
        self.bigtable_instance_self_grant_targets = bigtable_instance_candidates(self)
        self.bigtable_instance_admin_self_grant_targets = bigtable_instance_admin_candidates(self)
        self.disk_self_grant_targets = disk_candidates(self)
        self.image_self_grant_targets = image_candidates(self)
        from .gcp_agentidentity import targets as agentidentity_targets
        self.agentidentity_authorization_targets = agentidentity_targets(self)
        from .gcp_external_principal import load as load_external_principals
        self.external_principal_targets, self.external_principal_records = load_external_principals(self)
        from .gcp_agentregistry_skill import load as load_agentregistry_skill
        self.agentregistry_skill_targets, self.agentregistry_skill_records = load_agentregistry_skill(self)
        # Evidence is optional and deliberately absent from ordinary cloud snapshots. An
        # importer must review the complete exploit prerequisites before marking it verified.
        self.challenge_evidence = {}
        self.challenge_status = inventory_status(snapshot, "gcp_privesc_challenge_evidence")
        for collection_scope, item in items(snapshot, "gcp_privesc_challenge_evidence"):
            if not isinstance(item, dict):
                continue
            tid, source, kind, target, scope = (item.get(k) for k in
                ("TechniqueId", "SourceId", "TargetKind", "TargetId", "TargetScope"))
            if not all(isinstance(v, str) and v and "*" not in v for v in (tid, source, kind, target, scope)):
                continue
            if kind not in ("gcp_verified_authority", "gcp_service_account", "gcp_user",
                            "gcp_workspace_user", "gcp_group", "k8s_service_account"):
                continue
            if scope != self._norm_scope(collection_scope) or not scope.startswith("projects/"):
                continue
            self.challenge_evidence.setdefault((tid, source, kind, target, scope), []).append(item)
            if source.startswith("user:") and source not in self.principals:
                self.principals[source] = Node(source, "gcp_user", "gcp", scope, source.removeprefix("user:"),
                    attrs={"email": source.removeprefix("user:"), "grants": []}, perm_key=source)
        for scope in sorted(s for s in self.scopes if s.startswith("projects/")):
            for foothold in ("host", "directory", "external", "application", "user_interaction"):
                ident = f"gcp_challenge_foothold:{scope}:{foothold}"
                self.principals[ident] = Node(ident, "gcp_challenge_foothold", "gcp", scope,
                    f"Unverified {foothold} foothold in {scope}", attrs={"grants": []}, perm_key=ident)
        # The hierarchy is complete once loaded; ancestors() is memoized from here on (see ancestors).
        self._ancestor_memo = {}
        for (tid, _, kind, target, scope), records in self.challenge_evidence.items():
            if tid not in _EXACT_TABLE_KEY_PERMISSIONS or kind != "gcp_service_account":
                continue
            for fact in records:
                if self._table_key_fact_bound(tid, target, scope, fact):
                    table = fact["CredentialResource"]
                    parent = table.rsplit("/tables/", 1)[0]
                    self.parents.setdefault(table, parent)
                    self.parents.setdefault(parent, scope)
        from .bounded_evidence import CONTRACT as bounded_contract, valid as bounded_valid
        for (tid, source, kind, target, scope), records in self.challenge_evidence.items():
            if (tid in bounded_contract and len(records) == 1 and kind == "gcp_verified_authority"
                    and bounded_valid(tid, records[0], source, target, scope)):
                self.parents.setdefault(target, scope)
        self.require_collections(("iam_policy", "iam_role", "service_account"), {
            "iam_policy": "Allow bindings are unknown for this scope", "iam_role": "Role permissions are unknown",
            "service_account": "Service-account targets are unknown"})
        for scope in sorted(self.scopes):
            if not scope.startswith(("projects/", "folders/", "organizations/")):
                continue
            status = self.deny_status.get(scope, "not_collected")
            if status not in ("collected", "empty"):
                self.add_coverage("guardrail", scope, status, "iam_deny_policy not evaluated",
                                  "Edges are conditional: IAM deny policies may block them")
        if self.inactive_bindings:
            self.add_coverage("conditions", "*", "collected", f"{self.inactive_bindings} binding member(s) with an expired IAM condition",
                              "Expired bindings (request.time past) grant nothing and are skipped")
        if self.missing_roles:
            self.add_coverage("roles", "*", "partial", "role permissions not collected: " + ", ".join(sorted(self.missing_roles)[:30]),
                              "Bindings of these roles are not evaluated (collect iam_role for predefined roles)")

    # ---------------------------------------------------------------- load
    def _norm_scope(self, name):
        name = str(name or "")
        if name.startswith("//"):
            return name
        if name.startswith("projects/"):
            parts = name.split("/")
            parts[1] = self.project_alias.get(parts[1], parts[1])
            return "/".join(parts)
        return name

    def _load(self):
        snap = self.snapshot
        for scope, item in items(snap, "project"):
            pid = item.get("projectId") or scope.split("/", 1)[-1]
            number = str(item.get("name", "")).split("/")[-1]
            if number:
                self.project_alias[number] = pid
        for scope, item in items(snap, "project"):
            pid = item.get("projectId") or scope.split("/", 1)[-1]
            chain = [f"projects/{pid}"]
            for ancestor in as_list(item.get("_ancestry")):
                res = (ancestor or {}).get("resourceId") or {}
                if res.get("type") in ("folder", "organization"):
                    chain.append(f"{res['type']}s/{res['id']}")
            if len(chain) == 1 and item.get("parent"):
                chain.append(str(item["parent"]))
            for child, parent in zip(chain, chain[1:]):
                self.parents.setdefault(child, parent)
        for scope, item in items(snap, "folder"):
            if item.get("name") and item.get("parent"):
                self.parents.setdefault(item["name"], item["parent"])
        for scope, _ in items(snap, "project"):
            project = self._norm_scope(scope)
            if project.startswith("projects/") and project.count("/") == 1:
                self.parents.setdefault(project + "/locations/global", project)
        # GKE Hub IAM is evaluated on the exact Feature or MembershipFeature
        # named by its API, with inherited project and location bindings.
        for kind in ("fleet_feature", "fleet_membership", "fleet_membership_feature",
                     "fleet_scope", "fleet_member_rbac_binding", "fleet_scope_rbac_binding"):
            for collection_scope, item in items(snap, kind):
                name = self._norm_scope(item.get("name"))
                project = self._norm_scope(collection_scope)
                if not (project.startswith("projects/") and project.count("/") == 1 and
                        name.startswith(project + "/locations/")):
                    continue
                parts = name.split("/")
                if len(parts) < 6 or parts[2] != "locations":
                    continue
                location = "/".join(parts[:4])
                self.parents.setdefault(location, project)
                if kind == "fleet_membership_feature":
                    if len(parts) != 8 or parts[4] != "memberships" or parts[6] != "features":
                        continue
                    membership = "/".join(parts[:6])
                    self.parents.setdefault(membership, location)
                    self.parents.setdefault(name, membership)
                elif kind in ("fleet_member_rbac_binding", "fleet_scope_rbac_binding"):
                    expected = "memberships" if kind == "fleet_member_rbac_binding" else "scopes"
                    if len(parts) != 8 or parts[4] != expected or parts[6] != "rbacrolebindings":
                        continue
                    parent = "/".join(parts[:6])
                    self.parents.setdefault(parent, location)
                    self.parents.setdefault(name, parent)
                elif len(parts) == 6 and parts[4] in ("features", "memberships", "scopes"):
                    self.parents.setdefault(name, location)
        for name, (perms, conf) in _BUILTIN.items():
            self.roles[name] = Role(name, perms, conf)
        for role in ("roles/bigquery.dataViewer", "roles/bigquery.dataEditor", "roles/bigquery.dataOwner"):
            self.roles[role] = Role(role, ["bigquery.tables.getData"], "derived")
        builtin = set(self.roles)
        self.collected_role_rows = {}
        for scope, item in (*items(snap, "iam_role"), *items(snap, "iam_role_builtin")):
            if item.get("name") and not item.get("deleted"):
                self.collected_role_rows[item["name"]] = item
                if item.get("stage") != "DISABLED":
                    self.roles[item["name"]] = Role(item["name"], item.get("includedPermissions") or [])
                if item["name"].startswith(("projects/", "organizations/")) and "/roles/" in item["name"]:
                    parent = self._norm_scope(item["name"].split("/roles/", 1)[0])
                    self.parents.setdefault(item["name"], parent)
        self._collected_roles = set(self.collected_role_rows) - builtin
        for collection_scope, policy in items(snap, "iam_policy"):
            node = self._norm_scope(policy.get("name") or collection_scope)
            self.scopes.add(self._norm_scope(collection_scope))
            if node.startswith("//"):
                project = self._norm_scope(policy.get("project")) if policy.get("project") else self._norm_scope(collection_scope)
                self.parents.setdefault(node, project)
                sa = _sa_from_cai(node)
                if sa:
                    node = f"projects/{self._norm_scope('projects/' + sa[0]).split('/')[1]}/serviceAccounts/{sa[1]}"
                    self.parents.setdefault(node, project)
            self._bindings(node, policy)
        # Data Fusion can grant access directly on an instance or, with RBAC,
        # on a namespace. These policies are collected with the instance so
        # namespace-only grants are evaluated on their actual resource.
        self.datafusion_instances = {}
        for collection_scope, instance in items(snap, "datafusion_privesc_instance"):
            project = self._norm_scope(collection_scope)
            name = self._norm_scope(instance.get("name"))
            if (not re.fullmatch(r"projects/[^/]+/locations/[a-z0-9-]+/instances/[A-Za-z0-9_-]+", name)
                    or not name.startswith(project + "/locations/")):
                continue
            self.datafusion_instances[name] = instance
            location = name.rsplit("/instances/", 1)[0]
            self.parents.setdefault(location, project)
            self.parents.setdefault(name, location)
            policy = instance.get("iamPolicy")
            if isinstance(policy, dict) and isinstance(policy.get("bindings"), list):
                self._bindings(name, policy)
            else:
                self.add_coverage("datafusion_instance_iam", name, "not_collected",
                                  "instance IAM policy was not collected",
                                  "Direct Data Fusion instance grants may be missed")
            for namespace in as_list(instance.get("namespaces")):
                if not isinstance(namespace, dict):
                    continue
                ns = namespace.get("name")
                if not isinstance(ns, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", ns):
                    continue
                resource = name + "/namespaces/" + ns
                self.parents.setdefault(resource, name)
                ns_policy = namespace.get("iamPolicy")
                if isinstance(ns_policy, dict) and isinstance(ns_policy.get("bindings"), list):
                    self._bindings(resource, ns_policy)
                elif instance.get("enableRbac") is True:
                    self.add_coverage("datafusion_namespace_iam", resource, "not_collected",
                                      "namespace IAM policy was not collected",
                                      "Direct Data Fusion namespace grants may be missed")
        self.dataplex_lakes = {}
        for collection_scope, lake in items(snap, "dataplex_privesc_lake"):
            project = self._norm_scope(collection_scope)
            name = self._norm_scope(lake.get("name"))
            if (not re.fullmatch(r"projects/[^/]+/locations/[a-z0-9-]+/lakes/[a-z][a-z0-9-]*", name)
                    or not name.startswith(project + "/locations/")):
                continue
            self.dataplex_lakes[name] = lake
            location = name.rsplit("/lakes/", 1)[0]
            self.parents.setdefault(location, project)
            self.parents.setdefault(name, location)
            policy = lake.get("iamPolicy")
            if isinstance(policy, dict) and isinstance(policy.get("bindings"), list):
                self._bindings(name, policy)
            else:
                self.add_coverage("dataplex_lake_iam", name, "not_collected",
                                  "lake IAM policy was not collected",
                                  "Direct Dataplex lake grants may be missed")
        self.service_catalog_versions = {}
        catalog_rows = list(items(snap, "service_catalog_version"))
        catalog_counts = {}
        catalog_signatures = {}
        catalog_conflicts = set()
        for _, row in catalog_rows:
            name = row.get("name")
            if isinstance(name, str):
                catalog_counts[name] = catalog_counts.get(name, 0) + 1
            catalog = row.get("catalog")
            if isinstance(catalog, str):
                signature = (row.get("catalogParent"), row.get("catalogIamPolicy"),
                             row.get("consumerTargets"))
                if catalog in catalog_signatures and catalog_signatures[catalog] != signature:
                    catalog_conflicts.add(catalog)
                catalog_signatures.setdefault(catalog, signature)
        bound_catalogs = set()
        for scope, row in catalog_rows:
            org = self._norm_scope(scope)
            name = row.get("name")
            catalog = row.get("catalog")
            product = row.get("product")
            parent = row.get("catalogParent")
            targets = row.get("consumerTargets")
            policy = row.get("catalogIamPolicy")
            if (inventory_status(snap, "service_catalog_version").get(scope) != "collected"
                    or not isinstance(name, str) or catalog_counts.get(name) != 1
                    or not re.fullmatch(r"catalogs/[^/]+/products/[^/]+/versions/[^/]+", name)
                    or product != name.rsplit("/versions/", 1)[0]
                    or catalog != product.split("/products/", 1)[0]
                    or catalog in catalog_conflicts
                    or parent != "//cloudresourcemanager.googleapis.com/" + org
                    or not isinstance(targets, list) or not all(
                        isinstance(value, str) and re.fullmatch(
                            r"//cloudresourcemanager.googleapis.com/(?:projects|folders|organizations)/[^/]+", value)
                        for value in targets)
                    or not isinstance(policy, dict) or not isinstance(policy.get("bindings", []), list)
                    or any(not isinstance(binding, dict)
                           or not isinstance(binding.get("role"), str)
                           or not isinstance(binding.get("members"), list)
                           for binding in policy.get("bindings", []))):
                continue
            self.service_catalog_versions[name] = row
            self.parents.setdefault(catalog, org)
            self.parents.setdefault(product, catalog)
            self.parents.setdefault(name, product)
            if catalog not in bound_catalogs:
                self._bindings(catalog, policy)
                bound_catalogs.add(catalog)
        self.dataform_locations = {}
        self.dataform_repositories = {}
        dataform_rows = list(items(snap, "dataform_privesc_location"))
        location_counts = {}
        for _, row in dataform_rows:
            name = row.get("name")
            if isinstance(name, str):
                location_counts[name] = location_counts.get(name, 0) + 1
        for scope, row in dataform_rows:
            project = self._norm_scope(scope)
            raw_name = row.get("name")
            name = self._norm_scope(raw_name) if isinstance(raw_name, str) else None
            creator = row.get("creatorRoleConfig")
            repositories = row.get("repositories")
            if (inventory_status(snap, "dataform_privesc_location").get(scope) != "collected"
                    or not isinstance(name, str) or location_counts.get(raw_name) != 1
                    or not re.fullmatch(re.escape(project) + r"/locations/[a-z0-9-]+", name)
                    or not isinstance(creator, dict) or not isinstance(repositories, list)):
                continue
            parsed = {}
            for repo in repositories:
                if not isinstance(repo, dict):
                    parsed = None
                    break
                repo_name = self._norm_scope(repo.get("name"))
                policy = repo.get("iamPolicy")
                if (not re.fullmatch(re.escape(name) + r"/repositories/[A-Za-z0-9_-]+", repo_name)
                        or repo_name in parsed or not isinstance(policy, dict)
                        or not isinstance(policy.get("bindings", []), list)
                        or any(not isinstance(binding, dict)
                               or not isinstance(binding.get("role"), str)
                               or not isinstance(binding.get("members"), list)
                               for binding in policy.get("bindings", []))):
                    parsed = None
                    break
                parsed[repo_name] = repo
            if parsed is None:
                continue
            self.dataform_locations[name] = row
            self.parents.setdefault(name, project)
            for repo_name, repo in parsed.items():
                self.dataform_repositories[repo_name] = repo
                self.parents.setdefault(repo_name, name)
                self._bindings(repo_name, repo["iamPolicy"])
        self.resource_policy_status = {}
        self.resource_inventory_status = {}
        self.datacatalog_taxonomies = {}
        self.bigquery_datasets = {}
        self.bigquery_tables = {}
        self.bigtable_instances = {}
        self.bigtable_backups = {}
        self.bigtable_materialized_views = {}
        self.bigtable_tables = {}
        self.disks = {}
        self.images = {}
        self.bigquery_acl_mode = {}
        mode_status = inventory_status(snap, "bigquery_acl_mode")
        mode_conflicts = set()
        for scope, item in items(snap, "bigquery_acl_mode"):
            project = self._norm_scope(scope)
            if mode_status.get(scope) != "collected":
                continue
            location = item.get("location")
            expected = f"{project}/locations/{location}/bigqueryAclMode"
            if (isinstance(location, str) and re.fullmatch(r"[A-Za-z0-9-]+", location)
                    and item.get("name") == expected and type(item.get("enabled")) is bool):
                key = (project, location)
                if key in mode_conflicts:
                    continue
                if key in self.bigquery_acl_mode and self.bigquery_acl_mode[key] != item["enabled"]:
                    mode_conflicts.add(key)
                    self.bigquery_acl_mode.pop(key, None)
                else:
                    self.bigquery_acl_mode[key] = item["enabled"]
        self.kms_ring_policy_status = {}
        for scope, item in items(snap, "kms_key_ring"):
            raw_resource = item.get("name")
            resource = self._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
            project = self._norm_scope(scope)
            if (not isinstance(resource, str) or not re.fullmatch(
                    r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+", resource)
                    or not resource.startswith(project + "/")):
                continue
            self.parents.setdefault(resource, project)
            status = ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status")
            self.kms_ring_policy_status[resource] = status
            if status == "collected" and isinstance(item.get("iamPolicy"), dict):
                self._bindings(resource, item["iamPolicy"])
        for kind, pattern in (("secret", r"projects/[^/]+/(?:locations/[^/]+/)?secrets/[^/]+"),
                              ("instance", r"projects/[^/]+/zones/[^/]+/instances/[^/]+"),
                              ("disk", r"projects/[^/]+/(?:zones|regions)/[^/]+/disks/[^/]+"),
                              ("image", r"projects/[^/]+/global/images/[^/]+"),
                              ("machine_image", r"projects/[^/]+/global/machineImages/[^/]+"),
                              ("recoverable_snapshot", r"projects/[^/]+/global/recoverableSnapshots/[^/]+"),
                              ("snapshot", r"projects/[^/]+/(?:global|regions/[^/]+)/snapshots/[^/]+"),
                              ("bigquery_dataset", r"projects/[^/]+/datasets/[^/]+"),
                              ("bigquery_table", r"projects/[^/]+/datasets/[^/]+/tables/[^/]+"),
                              ("bigquery_connection", r"projects/[^/]+/locations/[^/]+/connections/[^/]+"),
                              ("integration_connection", r"projects/[^/]+/locations/[^/]+/connections/[^/]+"),
                              ("discoveryengine_collection", r"projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+"),
                              ("discoveryengine_data_store", r"projects/[^/]+/locations/(?:global|us|eu)/(?:collections/[^/]+/)?dataStores/[^/]+"),
                              ("discoveryengine_engine", r"projects/[^/]+/locations/(?:global|us|eu)/collections/[^/]+/engines/[^/]+"),
                              ("contact_center_authorized_view", r"projects/[^/]+/locations/[^/]+/authorizedViewSets/[^/]+/authorizedViews/[^/]+"),
                              ("healthcare_dataset", r"projects/[^/]+/locations/[^/]+/datasets/[^/]+"),
                              ("healthcare_fhir_store", r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/fhirStores/[^/]+"),
                              ("healthcare_dicom_store", r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/dicomStores/[^/]+"),
                              ("healthcare_hl7v2_store", r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/hl7V2Stores/[^/]+"),
                              ("healthcare_consent_store", r"projects/[^/]+/locations/[^/]+/datasets/[^/]+/consentStores/[^/]+"),
                              ("identityplatform_tenant", r"projects/[^/]+/tenants/[A-Za-z0-9_-]+"),
                              ("krm_api_host", r"projects/[^/]+/locations/[a-z][a-z0-9-]*/krmApiHosts/[A-Za-z0-9_-]+"),
                              ("logging_view", r"(?:projects|folders|organizations|billingAccounts)/[^/]+/locations/[a-z0-9-]+/buckets/[A-Za-z0-9_.-]+/views/[A-Za-z0-9_-]+"),
                              ("network_connectivity_hub", r"projects/[^/]+/locations/global/hubs/[^/]+"),
                              ("network_connectivity_hub_group", r"projects/[^/]+/locations/global/hubs/[^/]+/groups/[^/]+"),
                              ("network_security_address_group", r"projects/[^/]+/locations/[^/]+/addressGroups/[^/]+"),
                              ("network_security_authorization_policy", r"projects/[^/]+/locations/[^/]+/authorizationPolicies/[^/]+"),
                              ("ngfw_authz_policy", r"projects/[^/]+/locations/[^/]+/authzPolicies/[^/]+"),
                              ("network_security_client_tls_policy", r"projects/[^/]+/locations/[^/]+/clientTlsPolicies/[^/]+"),
                              ("network_security_server_tls_policy", r"projects/[^/]+/locations/[^/]+/serverTlsPolicies/[^/]+"),
                              ("bigtable_instance", r"projects/[^/]+/instances/[^/]+"),
                              ("bigtable_table", r"projects/[^/]+/instances/[^/]+/tables/[^/]+"),
                              ("bigtable_authorized_view", r"projects/[^/]+/instances/[^/]+/tables/[^/]+/authorizedViews/[^/]+"),
                              ("bigtable_materialized_view", r"projects/[^/]+/instances/[^/]+/materializedViews/[^/]+"),
                              ("bigtable_backup", r"projects/[^/]+/instances/[^/]+/clusters/[^/]+/backups/[^/]+"),
                              ("cloudbuild_connection", r"projects/[^/]+/locations/[^/]+/connections/[^/]+"),
                              ("eventarc_message_bus", r"projects/[^/]+/locations/[^/]+/messageBuses/[^/]+"),
                              ("eventarc_enrollment", r"projects/[^/]+/locations/[^/]+/enrollments/[^/]+"),
                              ("domains_registration", r"projects/[^/]+/locations/global/registrations/[^/]+"),
                              ("clouddeploy_delivery_pipeline", r"projects/[^/]+/locations/[^/]+/deliveryPipelines/[^/]+"),
                              ("biglake_catalog", r"projects/[^/]+/catalogs/[^/]+"),
                              ("biglake_namespace", r"projects/[^/]+/catalogs/[^/]+/namespaces/[^/]+"),
                              ("biglake_table", r"projects/[^/]+/catalogs/[^/]+/namespaces/[^/]+/tables/[^/]+"),
                              ("analyticshub_data_exchange", r"projects/[^/]+/locations/[^/]+/dataExchanges/[^/]+"),
                              ("analyticshub_listing", r"projects/[^/]+/locations/[^/]+/dataExchanges/[^/]+/listings/[^/]+"),
                              ("agentidentity_auth_provider", r"projects/[^/]+/locations/[^/]+/authProviders/[^/]+"),
                              ("artifact_repository", r"projects/[^/]+/locations/[^/]+/repositories/[^/]+"),
                              ("fleet_membership", r"projects/[^/]+/locations/[^/]+/memberships/[^/]+"),
                              ("containeranalysis_note", r"projects/[^/]+/(?:locations/[^/]+/)?notes/[^/]+"),
                              ("datacatalog_taxonomy", r"projects/[^/]+/locations/[^/]+/taxonomies/[^/]+"),
                              ("datacatalog_policy_tag", r"projects/[^/]+/locations/[^/]+/taxonomies/[^/]+/policyTags/[^/]+"),
                              ("metastore_service", r"projects/[^/]+/locations/[^/]+/services/[^/]+"),
                              ("ca_pool", r"projects/[^/]+/locations/[^/]+/caPools/[^/]+"),
                              ("pubsub_topic", r"projects/[^/]+/topics/[^/]+"),
                              ("pubsub_subscription", r"projects/[^/]+/(?:locations/[^/]+/)?subscriptions/[^/]+"),
                              ("kms_key", r"projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+")):
            self.resource_policy_status[kind] = {}
            self.resource_inventory_status[kind] = {
                self._norm_scope(scope): status for scope, status in inventory_status(snap, kind).items()}
            for scope, item in items(snap, kind):
                raw_resource = item.get("name")
                if kind in ("disk", "instance"):
                    link = item.get("selfLink")
                    match = re.fullmatch(
                        r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/(?:zones|regions)/[^/]+/"
                        + (r"disks/[^/]+" if kind == "disk" else r"instances/[^/]+") + r")",
                        link) if isinstance(link, str) else None
                    raw_resource = match.group(1) if match else None
                if kind == "image":
                    link = item.get("selfLink")
                    match = re.fullmatch(
                        r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/global/images/[^/]+)",
                        link) if isinstance(link, str) else None
                    raw_resource = match.group(1) if match else None
                if kind == "snapshot":
                    link = item.get("selfLink")
                    match = re.fullmatch(
                        r"https://(?:www|compute)\.googleapis\.com/compute/v1/(projects/[^/]+/(?:global|regions/[^/]+)/snapshots/[^/]+)",
                        link) if isinstance(link, str) else None
                    raw_resource = match.group(1) if match else None
                if kind in ("machine_image", "recoverable_snapshot"):
                    link = item.get("selfLink")
                    segment = "machineImages" if kind == "machine_image" else "recoverableSnapshots"
                    match = re.fullmatch(
                        rf"https://(?:www|compute)\.googleapis\.com/compute/(?:v1|beta)/(projects/[^/]+/global/{segment}/[^/]+)",
                        link) if isinstance(link, str) else None
                    raw_resource = match.group(1) if match else None
                resource = self._norm_scope(raw_resource) if isinstance(raw_resource, str) else None
                project = self._norm_scope(scope)
                if (not isinstance(resource, str) or not re.fullmatch(pattern, resource)
                        or not resource.startswith(project + "/")):
                    continue
                parent = (resource.rsplit("/authorizedViews/", 1)[0] if kind == "bigtable_authorized_view" else
                          resource.rsplit("/materializedViews/", 1)[0] if kind == "bigtable_materialized_view" else
                          resource.rsplit("/clusters/", 1)[0] if kind == "bigtable_backup" else
                          resource.rsplit("/tables/", 1)[0] if kind == "bigtable_table" else
                          resource.rsplit("/tables/", 1)[0] if kind in ("biglake_table", "bigquery_table") else
                          resource.rsplit("/namespaces/", 1)[0] if kind == "biglake_namespace" else
                          resource.rsplit("/cryptoKeys/", 1)[0] if kind == "kms_key" else
                          resource.rsplit("/consentStores/", 1)[0] if kind == "healthcare_consent_store" else
                          resource.rsplit("/fhirStores/", 1)[0] if kind == "healthcare_fhir_store" else
                          resource.rsplit("/dicomStores/", 1)[0] if kind == "healthcare_dicom_store" else
                          resource.rsplit("/hl7V2Stores/", 1)[0] if kind == "healthcare_hl7v2_store" else
                          resource.rsplit("/datasets/", 1)[0] if kind == "healthcare_dataset" else
                          resource.rsplit("/groups/", 1)[0] if kind == "network_connectivity_hub_group" else
                          resource.rsplit("/hubs/", 1)[0] if kind == "network_connectivity_hub" else
                          resource.rsplit("/addressGroups/", 1)[0] if kind == "network_security_address_group" else
                          resource.rsplit("/authorizationPolicies/", 1)[0] if kind == "network_security_authorization_policy" else
                          resource.rsplit("/authzPolicies/", 1)[0] if kind == "ngfw_authz_policy" else
                          resource.rsplit("/clientTlsPolicies/", 1)[0] if kind == "network_security_client_tls_policy" else
                          resource.rsplit("/serverTlsPolicies/", 1)[0] if kind == "network_security_server_tls_policy" else
                          resource.rsplit("/listings/", 1)[0] if kind == "analyticshub_listing" else project)
                if kind == "discoveryengine_data_store" and "/collections/" in resource:
                    parent = resource.rsplit("/dataStores/", 1)[0]
                    self.parents.setdefault(parent, project)
                if kind == "discoveryengine_engine":
                    parent = resource.rsplit("/engines/", 1)[0]
                    self.parents.setdefault(parent, project)
                if kind in ("healthcare_dataset", "healthcare_consent_store", "healthcare_fhir_store",
                            "healthcare_dicom_store", "healthcare_hl7v2_store"):
                    location = resource.split("/datasets/", 1)[0]
                    self.parents.setdefault(location, project)
                    if kind in ("healthcare_consent_store", "healthcare_fhir_store", "healthcare_dicom_store",
                                "healthcare_hl7v2_store"):
                        self.parents.setdefault(parent, location)
                if kind in ("network_connectivity_hub", "network_connectivity_hub_group"):
                    location = resource.split("/hubs/", 1)[0]
                    self.parents.setdefault(location, project)
                    if kind == "network_connectivity_hub_group":
                        self.parents.setdefault(parent, location)
                if kind in ("network_security_address_group", "network_security_authorization_policy", "ngfw_authz_policy", "network_security_client_tls_policy", "network_security_server_tls_policy"):
                    self.parents.setdefault(parent, project)
                if kind == "datacatalog_taxonomy":
                    parent = project
                    self.datacatalog_taxonomies[resource] = item
                if kind == "datacatalog_policy_tag":
                    taxonomy = resource.rsplit("/policyTags/", 1)[0]
                    raw_parent = item.get("parentPolicyTag")
                    tag_parent = self._norm_scope(raw_parent) if raw_parent else taxonomy
                    if (not isinstance(raw_parent, str) and raw_parent not in (None, "")
                            or not re.fullmatch(re.escape(taxonomy) + r"/policyTags/[^/]+", tag_parent)
                            and tag_parent != taxonomy
                            or tag_parent == resource):
                        continue
                    parent = tag_parent
                    self.parents.setdefault(taxonomy, project)
                self.parents.setdefault(resource, parent)
                if kind == "bigtable_authorized_view":
                    instance = parent.rsplit("/tables/", 1)[0]
                    self.parents.setdefault(parent, instance)
                    self.parents.setdefault(instance, project)
                if kind == "bigtable_backup":
                    self.parents.setdefault(parent, project)
                    self.bigtable_backups[resource] = item
                if kind == "bigtable_materialized_view":
                    self.parents.setdefault(parent, project)
                    self.bigtable_materialized_views[resource] = item
                if kind == "bigtable_table":
                    self.parents.setdefault(parent, project)
                    self.bigtable_tables[resource] = item
                if kind == "bigtable_instance":
                    self.bigtable_instances[resource] = item
                if kind == "disk":
                    self.disks[resource] = item
                if kind == "image":
                    self.images[resource] = item
                status = (((item.get("_coverage") or {}).get("datasetDetails") or {}).get("status")
                          if kind == "bigquery_dataset" else
                          ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status"))
                if kind == "bigquery_dataset":
                    self.bigquery_datasets[resource] = item
                    if status == "collected" and isinstance(item.get("access"), list):
                        bindings = []
                        roles = {"READER": "roles/bigquery.dataViewer",
                                 "WRITER": "roles/bigquery.dataEditor", "OWNER": "roles/bigquery.dataOwner"}
                        for acl in item["access"]:
                            if not isinstance(acl, dict):
                                continue
                            role = roles.get(acl.get("role"), acl.get("role"))
                            if not isinstance(role, str):
                                continue
                            member = ("user:" + acl["userByEmail"] if isinstance(acl.get("userByEmail"), str) else
                                      "group:" + acl["groupByEmail"] if isinstance(acl.get("groupByEmail"), str) else
                                      "domain:" + acl["domain"] if isinstance(acl.get("domain"), str) else
                                      acl.get("iamMember"))
                            if isinstance(member, str) and member:
                                if member.startswith("user:") and member.endswith(".iam.gserviceaccount.com"):
                                    member = "serviceAccount:" + member.removeprefix("user:")
                                bindings.append({"role": role, "members": [member],
                                                 **({"condition": acl["condition"]} if "condition" in acl else {})})
                        self._bindings(resource, {"bindings": bindings})
                    else:
                        status = "partial" if status == "collected" else status
                elif kind == "bigquery_table":
                    self.bigquery_tables[resource] = item
                if kind in ("bigquery_table", "integration_connection", "discoveryengine_collection", "discoveryengine_data_store", "discoveryengine_engine", "contact_center_authorized_view", "domains_registration", "eventarc_message_bus", "eventarc_enrollment", "identityplatform_tenant", "krm_api_host", "logging_view",
                            "ca_pool",
                            "healthcare_dataset", "healthcare_consent_store", "healthcare_fhir_store",
                            "healthcare_dicom_store",
                            "healthcare_hl7v2_store",
                            "network_connectivity_hub", "network_connectivity_hub_group",
                            "network_security_address_group",
                            "network_security_authorization_policy",
                            "ngfw_authz_policy",
                            "network_security_client_tls_policy",
                            "network_security_server_tls_policy",
                            "fleet_membership",
                            "containeranalysis_note", "datacatalog_taxonomy", "datacatalog_policy_tag",
                            "metastore_service") and status == "collected":
                    policy = item.get("iamPolicy")
                    bindings = policy.get("bindings", []) if isinstance(policy, dict) else None
                    if (not isinstance(bindings, list) or any(
                            not isinstance(binding, dict)
                            or not isinstance(binding.get("role"), str)
                            or not isinstance(binding.get("members"), list)
                            for binding in bindings)):
                        status = "malformed"
                if kind == "logging_view" and status == "collected" and any(
                        any(not isinstance(member, str) or not member for member in binding.get("members", []))
                        or ("condition" in binding and (
                            not isinstance(binding["condition"], dict)
                            or not isinstance(binding["condition"].get("expression"), str)))
                        for binding in item["iamPolicy"].get("bindings", [])):
                    status = "malformed"
                self.resource_policy_status[kind][resource] = status
                if kind != "bigquery_dataset" and status == "collected" and isinstance(item.get("iamPolicy"), dict):
                    self._bindings(resource, item["iamPolicy"])
        self.resource_policy_status["iap_tunnel_policy"] = {}
        self.resource_inventory_status["iap_tunnel_policy"] = {
            self._norm_scope(scope): status for scope, status in
            inventory_status(snap, "iap_tunnel_policy").items()}
        iap_rows = list(items(snap, "iap_tunnel_policy"))
        iap_counts = Counter(item.get("name") for _, item in iap_rows
                             if isinstance(item.get("name"), str))
        for scope, item in iap_rows:
            project = self._norm_scope(scope)
            resource = item.get("name")
            if (not isinstance(resource, str) or iap_counts[resource] != 1
                    or not re.fullmatch(re.escape(project) +
                        r"/iap_tunnel(?:/zones/[a-z][a-z0-9-]*[0-9]-[a-z]"
                        r"(?:/instances/[A-Za-z0-9_-]+)?)?", resource)):
                continue
            coverage = ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status")
            policy = item.get("iamPolicy")
            bindings = policy.get("bindings", []) if isinstance(policy, dict) else None
            if coverage == "collected" and (not isinstance(bindings, list) or any(
                    not isinstance(binding, dict) or not isinstance(binding.get("role"), str)
                    or not isinstance(binding.get("members"), list) for binding in bindings)):
                coverage = "malformed"
            self.resource_policy_status["iap_tunnel_policy"][resource] = coverage
            parent = (resource.rsplit("/instances/", 1)[0] if "/instances/" in resource else
                      resource.rsplit("/zones/", 1)[0] if "/zones/" in resource else project)
            self.parents.setdefault(resource, parent)
            if coverage == "collected":
                self._bindings(resource, policy)
        self.bigquery_row_policy_status = {}
        self.bigquery_row_policies = {}
        self.resource_policy_status["bigquery_row_policy_inventory"] = self.bigquery_row_policy_status
        self.resource_inventory_status["bigquery_row_policy_inventory"] = {
            self._norm_scope(scope): status for scope, status in
            inventory_status(snap, "bigquery_row_policy_inventory").items()}
        for scope, item in items(snap, "bigquery_row_policy_inventory"):
            project = self._norm_scope(scope)
            table = item.get("table")
            if (not isinstance(table, str) or not re.fullmatch(
                    r"projects/[^/]+/datasets/[^/]+/tables/[^/]+", table)
                    or not table.startswith(project + "/")
                    or item.get("name") != table + "/rowAccessPolicyInventory"):
                continue
            status = item.get("status")
            policies = item.get("policies")
            if table in self.bigquery_row_policy_status:
                self.bigquery_row_policy_status[table] = "malformed"
                self.bigquery_row_policies.pop(table, None)
                continue
            if status != "collected" or not isinstance(policies, list):
                self.bigquery_row_policy_status[table] = status or "malformed"
                continue
            parsed = []
            seen = set()
            for policy in policies:
                name = policy.get("name") if isinstance(policy, dict) else None
                iam = policy.get("iamPolicy") if isinstance(policy, dict) else None
                if (not isinstance(name, str) or not re.fullmatch(
                        re.escape(table) + r"/rowAccessPolicies/[A-Za-z0-9_]{1,256}", name)
                        or name in seen or not isinstance(iam, dict)
                        or ((policy.get("_coverage") or {}).get("iamPolicy") or {}).get("status") != "collected"
                        or ("bindings" in iam and not isinstance(iam["bindings"], list))):
                    status = "malformed"
                    break
                seen.add(name)
                parsed.append(policy)
            self.bigquery_row_policy_status[table] = status
            if status == "collected":
                self.bigquery_row_policies[table] = parsed
        for scope, item in items(snap, "apigee_organization"):
            project = self._norm_scope(scope)
            org = item.get("name")
            if not isinstance(org, str) or not re.fullmatch(r"organizations/[^/]+", org):
                continue
            self.parents.setdefault(org, project)
            for environment in item.get("_apigee_environments") or ():
                env = environment.get("name") if isinstance(environment, dict) else None
                if not isinstance(env, str) or not env.startswith(org + "/environments/"):
                    continue
                self.parents.setdefault(env, org)
                policy_status = ((environment.get("_coverage") or {}).get("iamPolicy") or {}).get("status")
                if policy_status == "collected" and isinstance(environment.get("iamPolicy"), dict):
                    self._bindings(env, environment["iamPolicy"])
                else:
                    self.add_coverage("apigee_environment_iam", env, policy_status or "not_collected",
                                      "environment IAM policy was not collected",
                                      "Direct Apigee environment grants may be missed")
                deployment_status = ((environment.get("_coverage") or {}).get("proxyDeployments") or {}).get("status")
                if deployment_status != "collected":
                    self.add_coverage("apigee_proxy_deployments", env, deployment_status or "not_collected",
                                      "proxy deployments were not collected",
                                      "Shared-flow hook execution remains unresolved")
        for scope, item in items(snap, "service_account"):
            email = item.get("email")
            if not email:
                continue
            project = f"projects/{item.get('projectId') or scope.split('/', 1)[-1]}"
            resource = f"{project}/serviceAccounts/{email}"
            self.parents[resource] = project
            node = self._principal(f"serviceAccount:{email}", project)
            node.attrs.update(resource=resource, project=project, disabled=bool(item.get("disabled")),
                              unique_id=item.get("uniqueId"))
            self.sas[node.id] = node
            self.sa_by_resource[resource] = node
            self._bindings(resource, item.get("iamPolicy") or {})
        self.deployment_manager_deployments = {}
        for scope, item in items(snap, "deployment_manager_deployment"):
            project = self._norm_scope(scope)
            name = item.get("name")
            if (not isinstance(name, str) or not re.fullmatch(r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?", name)):
                continue
            resource = f"{project}/global/deployments/{name}"
            self.parents[resource] = project
            self.deployment_manager_deployments[resource] = item
            policy_status = ((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status")
            if policy_status == "collected" and isinstance(item.get("iamPolicy"), dict):
                self._bindings(resource, item["iamPolicy"])
            else:
                self.add_coverage("deployment_manager_iam", resource,
                                  policy_status or "not_collected",
                                  "Deployment IAM policy was not collected",
                                  "Direct deployment policy grants may be missed")
        # Google-managed agents do not appear in IAM serviceAccounts.list. A project
        # number identifies the exact principal, while its expected project role
        # binding is evidence that the agent is provisioned and usable. Keep an
        # unbound/missing-policy agent unresolved rather than inventing its access.
        for number, pid in self.project_alias.items():
            if not number.isdecimal() or not pid:
                continue
            project = f"projects/{pid}"
            cloudservices_email = f"{number}@cloudservices.gserviceaccount.com"
            cloudservices = self._principal("serviceAccount:" + cloudservices_email, project)
            cloudservices_resource = f"{project}/serviceAccounts/{cloudservices_email}"
            cloudservices.scope = project
            cloudservices.attrs.update(resource=cloudservices_resource, project=project,
                                       service_agent="cloudservices_agent")
            self.parents.setdefault(cloudservices_resource, project)
            self.sas[cloudservices.id] = cloudservices
            for service, (domain, role) in VERTEX_DEFAULT_AGENTS.items():
                email = f"service-{number}@{domain}.iam.gserviceaccount.com"
                member = f"serviceAccount:{email}"
                node = self._principal(member, project)
                resource = f"{project}/serviceAccounts/{email}"
                node.scope = project
                node.attrs.update(resource=resource, project=project, service_agent=service)
                self.parents.setdefault(resource, project)
                self.vertex_agents[node.id] = node
                bindings = [grant for grant in self.grants.get(member, ())
                            if grant[0] == project and grant[1] == role]
                self.vertex_agent_status[(member, service)] = (
                    "yes" if any(not grant[2] for grant in bindings) else "unknown")
        self.managed_folders = {}
        self.managed_folder_policy_status = {}
        self.bucket_projects = {}
        self.bucket_ubla = {}
        self.composer_custom_buckets = {}
        for scope, item in items(snap, "bucket"):
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            project = self._norm_scope(scope)
            bucket_resource = f"//storage.googleapis.com/projects/_/buckets/{name}"
            self.bucket_projects[name] = project
            self.bucket_ubla[name] = ((item.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {}).get("enabled") is True
            self.composer_custom_buckets.setdefault(project, []).append((bucket_resource, item))
            self.parents.setdefault(bucket_resource, project)
            if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                self._bindings(bucket_resource, item.get("iamPolicy") or {})
        for scope, item in items(snap, "managed_folder"):
            bucket, name = item.get("bucket"), item.get("name")
            if not isinstance(bucket, str) or not isinstance(name, str) or not bucket or not name:
                continue
            resource = item.get("resource") or f"//storage.googleapis.com/projects/_/buckets/{bucket}/managedFolders/{name}"
            bucket_resource = f"//storage.googleapis.com/projects/_/buckets/{bucket}"
            self.parents.setdefault(resource, bucket_resource)
            self.parents.setdefault(bucket_resource, self._norm_scope(item.get("project") or scope))
            self.managed_folders.setdefault(bucket, []).append((name, resource))
            policy_status = (item.get("_coverage") or {}).get("iamPolicy", {}).get("status")
            self.managed_folder_policy_status[resource] = policy_status
            if policy_status == "collected":
                self._bindings(resource, item.get("iamPolicy") or {})
            else:
                self.add_coverage("managed_folder_iam", resource, "not_collected",
                                  "managed folder IAM policy was not collected",
                                  "A direct folder grant may be missed")
        for bucket, folders in self.managed_folders.items():
            for name, resource in folders:
                parents = [(len(outer_name), outer_resource) for outer_name, outer_resource in folders
                           if len(outer_name) < len(name) and name.startswith(outer_name)]
                if parents:
                    self.parents[resource] = max(parents)[1]
        for scope, status in inventory_status(snap, "iam_deny_policy").items():
            self.deny_status[self._norm_scope(scope)] = status
        for scope, item in items(snap, "iam_deny_policy"):
            for rule in as_list(item.get("rules")):
                rule = (rule or {}).get("denyRule") or {}
                if rule:
                    self.deny.append((self._norm_scope(scope), rule, item.get("name")))
        for scope, item in items(snap, "instance"):
            resource = _instance_resource(item, scope)
            if resource:
                self.parents.setdefault(resource, resource.split("/zones/", 1)[0])
            for sa in as_list(item.get("serviceAccounts")):
                email = (sa or {}).get("email")
                if email:
                    self.hosts.setdefault(email, {}).setdefault("instance", []).append(resource or item.get("selfLink") or item.get("name"))
        for scope, item in items(snap, "osconfig_guest_policy"):
            project = self._norm_scope(scope)
            name = self._norm_scope(item.get("name"))
            if re.fullmatch(re.escape(project) + r"/guestPolicies/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", name):
                self.parents.setdefault(name, project)
        for scope, item in items(snap, "instance"):
            project = self._norm_scope(scope)
            resource = _instance_resource(item, scope)
            if resource and "/zones/" in resource:
                zone = resource.split("/zones/", 1)[1].split("/", 1)[0]
                self.parents.setdefault(project + "/locations/" + zone, project)
        for scope, item in items(snap, "osconfig_os_policy_assignment"):
            project = self._norm_scope(scope)
            name = self._norm_scope(item.get("name"))
            match = re.fullmatch(re.escape(project) + r"/locations/([^/]+)/osPolicyAssignments/([^/]+)", name)
            if match:
                self.parents.setdefault(name, project + "/locations/" + match[1])
        for scope, item in items(snap, "os_patch_deployment"):
            project = self._norm_scope(scope)
            name = self._norm_scope(item.get("name"))
            if re.fullmatch(re.escape(project) + r"/patchDeployments/[^/]+", name):
                self.parents.setdefault(name, project)
        for scope, item in items(snap, "osconfig_policy_orchestrator"):
            parent = self._norm_scope(scope)
            location = parent + "/locations/global"
            name = self._norm_scope(item.get("name"))
            self.parents.setdefault(location, parent)
            if re.fullmatch(re.escape(location) + r"/policyOrchestrators/[^/]+", name):
                self.parents.setdefault(name, location)
        for kind in ("folder", "organization"):
            for _, item in items(snap, kind):
                name = item.get("name")
                if isinstance(name, str) and re.fullmatch(r"(?:folders|organizations)/[1-9][0-9]*", name):
                    self.parents.setdefault(name + "/locations/global", name)
        for scope, status in inventory_status(snap, "instance").items():
            self.host_status[(self._norm_scope(scope), "instance")] = status
        self._load_workload_hosts(snap)
        self._load_bigquery_transfer_configs(snap)
        self._load_bigquery_continuous_assignments(snap)
        from .gcp_appengine_debug import load as load_appengine_debug
        self.appengine_debug_instances = load_appengine_debug(self)
        self.scheduler_job_status = {self._norm_scope(scope): status
                                     for scope, status in inventory_status(snap, "scheduler_job").items()}
        self.scheduler_jobs_by_project = {}
        for scope, item in items(snap, "scheduler_job"):
            project = "/".join(self._norm_scope(scope).split("/")[:2])
            resource = self._norm_scope(item.get("name") or "")
            if not resource.startswith(project + "/locations/") or "/jobs/" not in resource:
                self.scheduler_job_status[project] = "partial"
                continue
            self.parents.setdefault(resource, project)
            self.scheduler_jobs_by_project.setdefault(project, []).append((resource, item.get("state"), item))
        self.cloudtasks_queue_status = {self._norm_scope(scope): status
                                        for scope, status in inventory_status(snap, "cloudtasks_queue").items()}
        self.composer_image_status = {self._norm_scope(scope): status
                                      for scope, status in inventory_status(snap, "composer_image_version").items()}
        self.composer_supported_regions = {}
        for scope, item in items(snap, "composer_image_version"):
            project = self._norm_scope(scope)
            location = item.get("location")
            version = item.get("imageVersionId")
            match = re.match(r"^composer-(\d+)(?:\.(\d+))?(?:\.|-|$)", version or "") if isinstance(version, str) else None
            if (not isinstance(location, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", location)
                    or not match):
                self.composer_image_status[project] = "partial"
                continue
            if ((int(match[1]), int(match[2] or 0)) >= (2, 5)
                    and item.get("creationDisabled") is not True):
                self.composer_supported_regions.setdefault(project, set()).add(location)
        self.cloudtasks_queues_by_project = {}
        for scope, item in items(snap, "cloudtasks_queue"):
            project = "/".join(self._norm_scope(scope).split("/")[:2])
            resource = self._norm_scope(item.get("name") or "")
            if not resource.startswith(project + "/locations/") or "/queues/" not in resource:
                self.cloudtasks_queue_status[project] = "partial"
                continue
            self.parents.setdefault(resource, project)
            policy_status = (item.get("_coverage") or {}).get("iamPolicy", {}).get("status")
            self.cloudtasks_queues_by_project.setdefault(project, []).append(
                (resource, item.get("state"), item.get("hasTargetOverride"), policy_status))
            if policy_status == "collected":
                self._bindings(resource, item.get("iamPolicy") or {})
            else:
                self.add_coverage("cloudtasks_queue_iam", resource, "not_collected",
                                  "queue IAM policy was not collected", "Direct queue grants may be missed")
        self._load_cloudbuild_default_identity(snap)
        self.function_location_status = {self._norm_scope(scope): status
                                         for scope, status in inventory_status(snap, "cloudfunctions_location").items()}
        self.function_locations_by_project = {}
        for scope, item in items(snap, "cloudfunctions_location"):
            project = self._norm_scope(scope)
            name = self._norm_scope(item.get("name"))
            match = re.fullmatch(re.escape(project) + r"/locations/([a-z][a-z0-9-]*)", name)
            if not match or item.get("locationId") not in (None, match[1]):
                self.function_location_status[project] = "partial"
                continue
            self.function_locations_by_project.setdefault(project, set()).add(match[1])
        self.function_inventory_status = {self._norm_scope(scope): status
                                          for scope, status in inventory_status(snap, "function").items()}
        self.functions_by_project = {}
        for scope, item in items(snap, "function"):
            project = "/".join(self._norm_scope(scope).split("/")[:2])
            resource = self._norm_scope(item.get("name") or "")
            if not resource.startswith(project + "/locations/") or "/functions/" not in resource:
                self.function_inventory_status[project] = "partial"
                continue
            location_resource = resource.rsplit("/functions/", 1)[0]
            self.parents.setdefault(location_resource, project)
            self.parents[resource] = location_resource
            self.functions_by_project.setdefault(project, []).append((resource, item))
        self.workbench_inventory_status = {self._norm_scope(scope): status
                                           for scope, status in inventory_status(snap, "workbench_instance").items()}
        self.workbench_by_project = {}
        for scope, item in items(snap, "workbench_instance"):
            project = "/".join(self._norm_scope(scope).split("/")[:2])
            resource = self._norm_scope(item.get("name") or "")
            if not resource.startswith(project + "/locations/") or "/instances/" not in resource:
                self.workbench_inventory_status[project] = "partial"
                continue
            location_resource = resource.rsplit("/instances/", 1)[0]
            self.parents.setdefault(location_resource, project)
            self.parents[resource] = location_resource
            self.workbench_by_project.setdefault(project, []).append((resource, item))
            policy_status = (item.get("_coverage") or {}).get("iamPolicy", {}).get("status")
            if policy_status == "collected":
                self._bindings(resource, item.get("iamPolicy") or {})
            else:
                self.add_coverage("workbench_instance_iam", resource, "not_collected",
                                  "instance IAM policy was not collected", "Direct instance grants may be missed")
        self._load_cloudbuild_writable_triggers(snap)
        self._load_sourcerepo_triggers(snap)
        # GKE clusters: k8s_cluster_admin / k8s_service_account targets live under the project.
        self.gke = {}
        for scope, item in items(snap, "gke_cluster"):
            resource = _gke_resource(item, self._norm_scope(scope))
            if resource:
                resource = self._norm_scope(resource)
                self.gke[resource] = item
                self.parents.setdefault(resource, resource.split("/locations/", 1)[0])
        self.gke_status = {self._norm_scope(s): st for s, st in inventory_status(snap, "gke_cluster").items()}
        # Workspace / Cloud Identity admin roles (Admin SDK Directory API), optional.
        self.ws_status = inventory_status(snap, "workspace_user")
        self.ws_admin = {}
        self.ws_customer_of_email = {}
        self.ws_customer_status = inventory_status(snap, "workspace_customer")
        self.ws_customer_domains = {}
        for _, item in items(snap, "workspace_customer"):
            customer = str(item.get("id") or "")
            domain = str(item.get("customerDomain") or "").lower().rstrip(".")
            if customer and domain:
                self.ws_customer_domains[customer] = domain
        role_names, super_roles = {}, set()
        for _, item in items(snap, "workspace_role"):
            rid = str(item.get("roleId") or "")
            role_names[rid] = str(item.get("roleName") or rid)
            if item.get("isSuperAdminRole"):
                super_roles.add(rid)
        user_by_id = {}
        workspace_users = {}
        for user_scope, item in items(snap, "workspace_user"):
            email = str(item.get("primaryEmail") or "").lower()
            if not email:
                continue
            workspace_users[email] = user_scope
            if item.get("customerId"):
                self.ws_customer_of_email[email] = str(item["customerId"])
            user_by_id[str(item.get("id") or email)] = email
            roles = self.ws_admin.setdefault(email, set())
            if item.get("isAdmin"):
                roles.add("super_admin")
        for _, item in items(snap, "workspace_role_assignment"):
            email = user_by_id.get(str(item.get("assignedTo") or ""))
            rid = str(item.get("roleId") or "")
            if email and rid:
                roles = self.ws_admin.setdefault(email, set())
                roles.update({rid, role_names.get(rid, rid)})
                if rid in super_roles:
                    roles.add("super_admin")
        for email, roles in self.ws_admin.items():
            if roles:
                self._principal(f"user:{email}", "*")
        self._load_ext_facts(snap)
        bound_groups = {member[6:].lower() for member in self.grants if member.startswith("group:")}
        unresolved_groups = bound_groups - set(self.group_by_email)
        if unresolved_groups:
            self.add_coverage("group_iam", "*", "not_collected",
                              "IAM-bound Google groups not resolved: " + ", ".join(sorted(unresolved_groups)[:12]),
                              "Members of these groups may have inherited IAM grants that cannot be attributed")
        if bound_groups and not any(status in ("collected", "empty")
                                    for status in self.group_membership_status.values()):
            self.add_coverage("group_membership", "*", "not_collected",
                              "Google group membership was not collected",
                              "Inherited IAM grants for group members cannot be evaluated")
        self._load_wif_hosts(snap)
        self._load_workforce_paths(snap)
        self.related_k8s = None
        for member, grants in self.grants.items():
            if member.split(":", 1)[0] in ("user", "serviceAccount", "group", "domain", "principal", "principalSet"):
                self._principal(member, grants[0][0] if grants else "*")
        bound_domains = {member[7:].lower() for member in self.grants if member.startswith("domain:")}
        for email, user_scope in workspace_users.items():
            if email.rpartition("@")[2] in bound_domains:
                self._principal("user:" + email, user_scope)
        inherited_groups = {}
        for group_resource, members in self.group_members.items():
            record = self.group_by_resource.get(group_resource)
            if record is None:
                continue
            group_email = record[0]
            group_grants = self.grants.get("group:" + group_email, ())
            if not group_grants:
                continue
            for member_email in members:
                if ("@" not in member_email or member_email in self.group_by_email
                        or not re.fullmatch(r"[^@\s/]+@[^@\s/]+", member_email)):
                    continue
                prefix = ("serviceAccount" if member_email.endswith(".iam.gserviceaccount.com") else "user")
                member_id = prefix + ":" + member_email
                self._principal(member_id, record[2])
                inherited = inherited_groups.setdefault(member_id, [])
                for grant_scope, role, condition, frozen_ref in group_grants:
                    ref = dict(frozen_ref)
                    ref.update(group_membership=group_resource, group_member=member_email)
                    inherited.append((grant_scope, role, condition, _freeze(ref)))
        inherited_domains = {}
        for node in self.principals.values():
            if not node.id.startswith("user:"):
                continue
            domain = node.id.rpartition("@")[2].lower()
            for grant_scope, role, condition, frozen_ref in self.grants.get("domain:" + domain, ()):
                # The user's email domain can be a secondary Workspace domain.
                # Without the customer's primary-domain mapping, this grant is
                # possible but cannot be reported as a definite permission.
                ref = dict(frozen_ref)
                ref.update(domain_member=node.id, domain_membership="primary_domain_unverified")
                inherited_domains.setdefault(node.id, []).append(
                    (grant_scope, role, condition or "?", _freeze(ref)))
        if bound_domains:
            self.add_coverage("domain_iam", "*", "partial",
                              "IAM domain bindings found; Workspace primary-domain membership was not verified",
                              "Matching user permissions are conditional and other domain users may be missing")
        for email, group in self.group_by_email.items():
            node = self.principals.get("group:" + email)
            if node is not None:
                node.attrs["resource"] = group["name"]
        for node in self.principals.values():
            mine = tuple(sorted(set((*self.grants.get(node.id, []), *inherited_groups.get(node.id, []),
                                     *inherited_domains.get(node.id, []))), key=repr))
            node.attrs["grants"] = mine + tuple(self.public)
            node.perm_key = node.attrs["grants"]
        self._load_inframanager_hosts(snap)

    def _load_inframanager_hosts(self, snap):
        """Bind deployment locations to SAs with complete same/cross-project prerequisites."""
        host = "inframanager_location"
        statuses = {self._norm_scope(scope): status for scope, status in
                    inventory_status(snap, host).items()}
        rows = list(items(snap, host))
        names = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
        locations = {}
        for scope, item in rows:
            project = self._norm_scope(scope)
            name = self._norm_scope(item.get("name"))
            if (not re.fullmatch(re.escape(project) + r"/locations/[a-z][a-z0-9-]*", name)
                    or names.get(item.get("name")) != 1):
                self.host_status[(project, host)] = "partial"
                continue
            self.parents.setdefault(name, project)
            locations.setdefault(project, []).append(name)
        for project, status in statuses.items():
            self.host_status.setdefault((project, host), status)
            if self.iam_policy_inventory_status.get(project) not in ("collected", "empty"):
                self.host_status[(project, host)] = "partial"
        numbers = {f"projects/{project_id}": number
                   for number, project_id in self.project_alias.items()}
        for sa in self.sas.values():
            sa_project = sa.attrs.get("project")
            if (sa.attrs.get("disabled") or _google_managed(sa.attrs.get("email"))
                    or not isinstance(sa_project, str)):
                continue
            for project, project_locations in locations.items():
                ancestors = set(self.ancestors(project))
                bindings = [(node, condition) for node, role, condition, _ in
                            sa.attrs.get("grants", ()) if role == "roles/config.agent"
                            and node in ancestors]
                if not any(not condition for _, condition in bindings):
                    if bindings:
                        self.host_status[(sa_project, host)] = "partial"
                    continue
                if sa_project != project:
                    policy = self._effective_boolean_policy(
                        sa_project, "iam.disableCrossProjectServiceAccountUsage")
                    if policy is True:
                        continue
                    number = numbers.get(project)
                    agent = (self.principals.get("serviceAccount:service-" + number +
                              "@gcp-sa-config.iam.gserviceaccount.com") if number else None)
                    builder = (self.principals.get("serviceAccount:service-" + number +
                                "@gcp-sa-cloudbuild.iam.gserviceaccount.com") if number else None)
                    resource = sa.attrs.get("resource")
                    act_as = self.check(agent, {"action": "iam.serviceAccounts.actAs"}, resource) if agent else None
                    token = self.check(builder, {"action": "iam.serviceAccounts.getAccessToken"}, resource) if builder else None
                    if (policy is not False or act_as is None or token is None
                            or act_as.confidence != "derived" or token.confidence != "derived"
                            or self.iam_policy_inventory_status.get(sa_project) not in ("collected", "empty")):
                        self.host_status[(sa_project, host)] = "partial"
                        continue
                email = sa.attrs["email"]
                self.host_projects.setdefault((email, host), set()).add(project)
                for location in project_locations:
                    self.hosts.setdefault(email, {}).setdefault(host, []).append(location)

    def _load_wif_hosts(self, snap):
        """Join active workload pools and providers to pool-wide SA token grants."""
        create_host = "wif_active_pool_wide_binding"
        update_host = "wif_active_provider_pool_wide_binding"
        pool_sas = {}
        pool_rows = {}
        providers_by_pool = {}
        self.wif_create_paths = {}
        self.wif_update_paths = {}
        self.wif_restore_paths = {}
        provider_statuses = {self._norm_scope(scope): status for scope, status in
                             inventory_status(snap, "workload_identity_provider").items()}
        for scope, status in inventory_status(snap, "workload_identity_pool").items():
            project = self._norm_scope(scope)
            if project.startswith("projects/"):
                self.host_status[(project, create_host)] = status
                self.host_status[(project, update_host)] = (
                    provider_statuses.get(project, "not_collected") if status in ("collected", "empty") else status)
        for scope, pool in items(snap, "workload_identity_pool"):
            project = self._norm_scope(scope)
            raw_name = pool.get("name")
            if not isinstance(raw_name, str) or not re.fullmatch(
                    r"projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[A-Za-z0-9_-]+", raw_name):
                self.host_status[(project, create_host)] = "partial"
                self.host_status[(project, update_host)] = "partial"
                continue
            if self._norm_scope(raw_name).split("/locations/", 1)[0] != project:
                self.host_status[(project, create_host)] = "partial"
                self.host_status[(project, update_host)] = "partial"
                continue
            if pool.get("state") not in ("ACTIVE", "DELETED") or type(pool.get("disabled", False)) is not bool:
                self.host_status[(project, create_host)] = "partial"
                self.host_status[(project, update_host)] = "partial"
                continue
            resource = self._norm_scope(raw_name)
            self.parents.setdefault(resource, project)
            pool_rows[resource] = pool
            member = "principalSet://iam.googleapis.com/" + raw_name + "/*"
            for sa in self.sas.values():
                if sa.attrs.get("disabled"):
                    continue
                chain = set(self.ancestors(sa.attrs["resource"]))
                matching_bindings = [condition for node, role, condition, _ in self.grants.get(member, ())
                                     if node in chain and self.roles.get(role) is not None
                                     and self.roles[role].has("iam.serviceaccounts.getaccesstoken")]
                if matching_bindings:
                    binding_uncertain = all(bool(condition) for condition in matching_bindings)
                    pool_sas.setdefault(resource, []).append((sa, binding_uncertain))
                    if pool["state"] != "ACTIVE" or pool.get("disabled") is True:
                        continue
                    self.wif_create_paths.setdefault(sa.id, []).append((
                        "iam.googleapis.com/workloadIdentityPoolProviders.create", resource, binding_uncertain))
                    self.host_projects.setdefault((sa.attrs["email"], create_host), set()).add(project)
                    listed = self.hosts.setdefault(sa.attrs["email"], {}).setdefault(create_host, [])
                    if resource not in listed:
                        listed.append(resource)
        for scope, provider in items(snap, "workload_identity_provider"):
            project = self._norm_scope(scope)
            raw_name = provider.get("name")
            if not isinstance(raw_name, str) or not re.fullmatch(
                    r"projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[A-Za-z0-9_-]+/providers/[A-Za-z0-9_-]+",
                    raw_name):
                self.host_status[(project, update_host)] = "partial"
                continue
            resource = self._norm_scope(raw_name)
            pool_resource = resource.rsplit("/providers/", 1)[0]
            if pool_resource.split("/locations/", 1)[0] != project:
                self.host_status[(project, update_host)] = "partial"
                continue
            if provider.get("state") not in ("ACTIVE", "DELETED") or type(provider.get("disabled", False)) is not bool:
                self.host_status[(project, update_host)] = "partial"
                continue
            providers_by_pool.setdefault(pool_resource, []).append((resource, provider))
            if provider["state"] != "ACTIVE" or pool_resource not in pool_sas:
                continue
            self.parents.setdefault(resource, pool_resource)
            if pool_rows[pool_resource]["state"] != "ACTIVE" or pool_rows[pool_resource].get("disabled") is True:
                continue
            for sa, binding_uncertain in pool_sas[pool_resource]:
                self.wif_update_paths.setdefault(sa.id, []).append((
                    "iam.googleapis.com/workloadIdentityPoolProviders.update", resource, binding_uncertain))
                self.host_projects.setdefault((sa.attrs["email"], update_host), set()).add(project)
                listed = self.hosts.setdefault(sa.attrs["email"], {}).setdefault(update_host, [])
                if resource not in listed:
                    listed.append(resource)
        for pool_resource, sas in pool_sas.items():
            pool = pool_rows[pool_resource]
            providers = providers_by_pool.get(pool_resource, ())
            for provider_resource, provider in providers:
                if provider.get("disabled") is True:
                    continue
                if pool["state"] == "ACTIVE" and pool.get("disabled") is True and provider["state"] == "ACTIVE":
                    action, resource = "iam.googleapis.com/workloadIdentityPools.update", pool_resource
                elif pool["state"] == "DELETED" and provider["state"] in ("ACTIVE", "DELETED"):
                    action, resource = "iam.googleapis.com/workloadIdentityPools.undelete", pool_resource
                elif pool["state"] == "ACTIVE" and pool.get("disabled") is not True and provider["state"] == "DELETED":
                    action, resource = "iam.googleapis.com/workloadIdentityPoolProviders.undelete", provider_resource
                else:
                    continue
                self.parents.setdefault(provider_resource, pool_resource)
                for sa, binding_uncertain in sas:
                    self.wif_restore_paths.setdefault(sa.id, []).append((action, resource, binding_uncertain))

    def _load_workforce_paths(self, snap):
        """Join workforce pool control to exact organization-local SA token grants."""
        self.workforce_control_paths = {}
        pools = {}
        providers = {}
        for scope, pool in items(snap, "workforce_pool"):
            organization = self._norm_scope(scope)
            name = pool.get("name")
            if (not organization.startswith("organizations/") or not isinstance(name, str)
                    or not re.fullmatch(r"locations/global/workforcePools/[A-Za-z0-9_-]+", name)
                    or pool.get("state") not in ("ACTIVE", "DELETED")
                    or type(pool.get("disabled", False)) is not bool):
                continue
            pools[name] = (organization, pool)
            self.parents.setdefault(name, organization)
        for scope, provider in items(snap, "workforce_provider"):
            organization = self._norm_scope(scope)
            name = provider.get("name")
            if (not isinstance(name, str) or not re.fullmatch(
                    r"locations/global/workforcePools/[A-Za-z0-9_-]+/providers/[A-Za-z0-9_-]+", name)
                    or provider.get("state") not in ("ACTIVE", "DELETED")
                    or type(provider.get("disabled", False)) is not bool):
                continue
            pool_name = name.rsplit("/providers/", 1)[0]
            if pool_name not in pools or pools[pool_name][0] != organization:
                continue
            providers.setdefault(pool_name, []).append((name, provider))
            self.parents.setdefault(name, pool_name)
        for name, (organization, pool) in pools.items():
            member = "principalSet://iam.googleapis.com/" + name + "/*"
            for sa in self.sas.values():
                if sa.attrs.get("disabled") or organization not in self.ancestors(sa.attrs["resource"]):
                    continue
                chain = set(self.ancestors(sa.attrs["resource"]))
                matching_bindings = [condition for node, role, condition, _ in self.grants.get(member, ())
                                     if node in chain and self.roles.get(role) is not None
                                     and self.roles[role].has("iam.serviceaccounts.getaccesstoken")]
                if not matching_bindings:
                    continue
                binding_uncertain = all(bool(condition) for condition in matching_bindings)
                paths = self.workforce_control_paths.setdefault(sa.id, [])
                if pool["state"] == "ACTIVE" and pool.get("disabled") is not True:
                    paths.append(("iam.googleapis.com/workforcePoolProviders.create", name, binding_uncertain))
                for provider_name, provider in providers.get(name, ()):
                    if pool["state"] == "ACTIVE" and pool.get("disabled") is not True:
                        if provider["state"] == "ACTIVE":
                            paths.append(("iam.googleapis.com/workforcePoolProviders.update", provider_name, binding_uncertain))
                        elif provider.get("disabled") is not True:
                            paths.append(("iam.googleapis.com/workforcePoolProviders.undelete", provider_name, binding_uncertain))
                    elif pool["state"] == "ACTIVE" and provider["state"] == "ACTIVE" and provider.get("disabled") is not True:
                        paths.append(("iam.googleapis.com/workforcePools.update", name, binding_uncertain))
                    elif pool["state"] == "DELETED" and provider.get("disabled") is not True:
                        paths.append(("iam.googleapis.com/workforcePools.undelete", name, binding_uncertain))

    def _load_ext_facts(self, snap):
        """Groups Settings (whoCanJoin), Cloud Domains registrations and instance-template image families."""
        self.group_by_email = {}
        self.group_by_resource = {}
        self.group_settings = {}  # group email -> (whoCanJoin, allowExternalMembers or None)
        for scope, item in items(snap, "group"):
            email = str(((item.get("groupKey") or {}).get("id")) or item.get("email") or "").lower()
            name = item.get("name")
            if email and isinstance(name, str) and re.fullmatch(r"groups/[A-Za-z0-9_-]+", name):
                self.group_by_email[email] = item
                self.group_by_resource[name] = (email, item, scope)
            settings = item.get("groupSettings") or item.get("settings") or item
            who = settings.get("whoCanJoin") if isinstance(settings, dict) else None
            if email and who:
                ext = settings.get("allowExternalMembers")
                ext = None if ext is None else str(ext).lower() == "true"
                self.group_settings[email] = (str(who).upper(), ext)
        self.group_membership_status = inventory_status(snap, "group_membership")
        self.group_members = {}
        for _, item in items(snap, "group_membership"):
            group = item.get("group")
            member = (item.get("preferredMemberKey") or {}).get("id")
            if isinstance(group, str) and isinstance(member, str):
                self.group_members.setdefault(group, set()).add(member.lower())
        self.registrations_status = inventory_status(snap, "domains_registration")
        self.registrations = {}  # domain -> [(registration resource, state)]
        for scope, item in items(snap, "domains_registration"):
            domain = str(item.get("domainName") or "").lower().rstrip(".")
            if domain and item.get("name"):
                resource = self._norm_scope(item["name"])
                self.registrations.setdefault(domain, []).append((resource, str(item.get("state") or "")))
                self.parents.setdefault(resource, "/".join(resource.split("/")[:2]))
        self.template_status = {self._norm_scope(s): st for s, st in inventory_status(snap, "instance_template").items()}
        self.image_families = {}  # sa email -> sorted family projects
        for scope, item in items(snap, "instance_template"):
            props = item.get("properties") or {}
            projects = set()
            for disk in as_list(props.get("disks")):
                image = str(((disk or {}).get("initializeParams") or {}).get("sourceImage") or "")
                path = image.split("/compute/v1/", 1)[-1].split("/compute/beta/", 1)[-1]
                parts = path.split("/")
                if len(parts) >= 5 and parts[0] == "projects" and parts[2:4] == ["global", "images"] and parts[4] == "family":
                    projects.add("projects/" + parts[1])
            for sa in as_list(props.get("serviceAccounts")):
                email = str((sa or {}).get("email") or "")
                if email and projects:
                    self.image_families.setdefault(email, set()).update(projects)

    def bigquery_dataset_access_uncertain(self, source, dataset, project):
        """Avoid claiming new data access when legacy ACL membership is unresolved."""
        access = dataset.get("access") if isinstance(dataset, dict) else None
        if not isinstance(access, list):
            return True
        basic = {"projectReaders": {"roles/viewer", "roles/reader", "roles/editor", "roles/writer", "roles/owner"},
                 "projectWriters": {"roles/editor", "roles/writer", "roles/owner"},
                 "projectOwners": {"roles/owner"}}
        held = {role for node, role, _, _ in source.attrs.get("grants", ())
                if node in self.ancestors(project)}
        for acl in access:
            if not isinstance(acl, dict):
                return True
            role = acl.get("role")
            if role and role not in {"READER", "WRITER", "OWNER"} and role not in self.roles:
                return True
            special = acl.get("specialGroup")
            if special is not None:
                if special not in basic or held & basic[special]:
                    return True
            if acl.get("iamMember") and not str(acl["iamMember"]).startswith(
                    ("user:", "serviceAccount:", "group:", "domain:", *PUBLIC)):
                return True
        return False

    def bigquery_row_policy_prior_access(self, source, table):
        """Whether an existing row policy already grants filtered table access."""
        email = source.attrs.get("email", "").lower()
        direct = {source.id.lower(), "user:" + email, "serviceaccount:" + email}
        domain = email.partition("@")[2]
        uncertain = False
        for policy in self.bigquery_row_policies.get(table, ()):
            for binding in policy["iamPolicy"].get("bindings", ()):
                if not isinstance(binding, dict):
                    uncertain = True
                    continue
                if binding.get("role") != "roles/bigquery.filteredDataViewer":
                    continue
                members = binding.get("members")
                if not isinstance(members, list):
                    uncertain = True
                    continue
                for member in members:
                    if not isinstance(member, str):
                        uncertain = True
                        continue
                    normalized = member.lower()
                    matches = (normalized in direct or member in PUBLIC
                               or (source.kind == "gcp_user" and bool(domain)
                                   and normalized == "domain:" + domain))
                    if normalized.startswith("group:"):
                        group = self.group_by_email.get(normalized.removeprefix("group:"))
                        name = group.get("name") if isinstance(group, dict) else None
                        matches = isinstance(name, str) and email in self.group_members.get(name, ())
                        if (not matches and (name is None or self.group_membership_status.get(
                                             table.split("/datasets/", 1)[0])
                                             not in ("collected", "empty"))):
                            uncertain = True
                    elif not matches and not normalized.startswith(("user:", "serviceaccount:", "domain:")):
                        uncertain = True
                    if matches:
                        if binding.get("condition"):
                            uncertain = True
                        else:
                            return True, uncertain
        return False, uncertain

    def _bindings(self, node, policy):
        for index, binding in enumerate(as_list(policy.get("bindings"))):
            if not isinstance(binding, dict):
                continue
            role = binding.get("role")
            if role not in self.roles and role:
                self.missing_roles.add(role)
            condition = binding.get("condition") or {}
            ref = {"policy": node, "role": role, "binding": index, "condition": condition.get("title")}
            conditional = ""
            if condition:
                expression = str(condition.get("expression") or "") if isinstance(condition, dict) else ""
                ref["expression"] = expression
                now = cel.evaluate(expression, cel.now_context())
                if now is False and not cel.uses_resource(expression):
                    self.inactive_bindings += 1  # e.g. request.time < timestamp(<past>): the binding is inactive
                    continue
                # Resource-independent and true now (future expiry): unconditional; otherwise keep the expression.
                conditional = "" if now is True and not cel.uses_resource(expression) else (expression or "?")
            for member in as_list(binding.get("members")):
                member = str(member)
                if member.startswith("deleted:"):
                    continue
                grant = (node, role, conditional, _freeze(ref))
                if member in PUBLIC:
                    self.public.append(grant)
                else:
                    self.grants.setdefault(member, []).append(grant)

    def _principal(self, member, scope):
        if member in self.principals:
            return self.principals[member]
        prefix, _, value = member.partition(":")
        kind = {"serviceAccount": "gcp_service_account", "user": "gcp_user", "group": "gcp_group"}.get(prefix, "gcp_user")
        project = scope if str(scope).startswith("projects/") else "*"
        if prefix == "serviceAccount" and "@" in value:
            domain = value.split("@", 1)[1]
            if domain.endswith(".iam.gserviceaccount.com"):
                project = "projects/" + domain.split(".", 1)[0]
        node = Node(member, kind, "gcp", project, value, attrs={"email": value, "member": member})
        self.principals[member] = node
        return node

    def _load_workload_hosts(self, snap):
        """Cloud Run services, Cloud Functions, Dataproc clusters and GKE node pools with the SA they run as. A
        project whose collection is complete (collected / empty) is authoritative: an SA not listed there runs no
        such workload. An item whose SA cannot be determined makes that project's inventory partial."""
        number = {pid: num for num, pid in self.project_alias.items()}

        def default_compute(project):
            num = number.get(project.split("/", 1)[-1])
            return f"{num}-compute@developer.gserviceaccount.com" if num else None

        def merge(key, status):
            previous = self.host_status.get(key)
            if previous in (None, "collected", "empty"):
                self.host_status[key] = status

        self.composer_dag_buckets = {}
        self.composer_dag_folders = {}
        self.composer_dag_paths = {}
        self.composer_host_projects = {}
        self.composer_dag_incomplete = set()
        self.composer_unknown_bucket_projects = set()
        self.dataproc_init_buckets = {}
        self.dataproc_init_folders = {}
        self.dataproc_init_objects = {}
        self.dataproc_clusters_by_resource = {}
        self.dataproc_cluster_service_accounts = {}
        self.dataproc_init_by_cluster = {}
        self.cloudbuild_source_buckets = {}
        self.cloudbuild_source_objects = {}
        self.host_projects = {}
        self.workflows_by_project = {}
        self.workstation_configs = {}
        self.workstation_rows = {}
        self.workstation_clusters_by_project = {}
        for scope, item in items(snap, "workstations_cluster"):
            project = "/".join(self._norm_scope(scope).split("/")[:2])
            resource = self._norm_scope(item.get("name") or "")
            if (resource.startswith(project + "/locations/") and
                    "/workstationClusters/" in resource and not item.get("deleteTime")):
                self.workstation_clusters_by_project.setdefault(project, set()).add(resource)
                self.parents.setdefault(resource, project)
        self.run_jobs_by_project = {}
        self.run_services_by_project = {}
        self.run_instances_by_project = {}
        self.run_worker_pools_by_project = {}
        migration_targets = {}
        migration_target_status = {
            self._norm_scope(scope): status
            for scope, status in inventory_status(snap, "vm_migration_target_project").items()}
        for _, target_project in items(snap, "vm_migration_target_project"):
            name = self._norm_scope(target_project.get("name") or "")
            project_ref = target_project.get("project")
            if not isinstance(project_ref, str) or not project_ref:
                continue
            resolved_project = self._norm_scope(
                project_ref if project_ref.startswith("projects/") else "projects/" + project_ref)
            migration_targets[name] = resolved_project
        for kind, host in (("cloudrun_service", "cloudrun_service"), ("function", "function"),
                           ("cloudrun_job", "cloudrun_job"),
                           ("cloudrun_instance", "cloudrun_instance"),
                           ("cloudrun_worker_pool", "cloudrun_worker_pool"),
                           ("dataproc_cluster", "dataproc_cluster"), ("gke_cluster", "gke_nodepool"),
                           ("composer_environment", "composer_environment"),
                           ("cloudbuild_build", "cloudbuild_build"),
                           ("firebase_apphosting_backend", "firebase_apphosting_backend"),
                           ("workflows_workflow", "workflows_workflow"),
                           ("workstations_config", "workstations_config"),
                           ("workstations_workstation", "workstations_workstation"),
                           ("workbench_instance", "notebooks_instance"),
                           ("vm_migration_vm", "vm_migration_vm")):
            from collections import Counter
            apphosting_names = (Counter(item.get("name") for _, item in items(snap, kind)
                                        if isinstance(item, dict) and isinstance(item.get("name"), str))
                                if kind == "firebase_apphosting_backend" else {})
            for scope, status in inventory_status(snap, kind).items():
                project = "/".join(self._norm_scope(scope).split("/")[:2])
                if project.startswith("projects/"):
                    # Historical builds establish exact consumers, but a complete
                    # build list cannot rule out an uncollected future trigger.
                    merge((project, host), "partial" if kind == "cloudbuild_build"
                          and status in ("collected", "empty") else status)
            for scope, item in items(snap, kind):
                project = "/".join(self._norm_scope(item.get("projectId") and f"projects/{item['projectId']}" or scope).split("/")[:2])
                if not project.startswith("projects/"):
                    continue
                found = []  # (email or None, resource)
                if kind == "cloudrun_service":
                    resource = self._norm_scope(item.get("name") or "")
                    if not resource.startswith(project + "/locations/") or "/services/" not in resource:
                        merge((project, host), "partial")
                        continue
                    template = item.get("template")
                    if not isinstance(template, dict):
                        merge((project, host), "partial")
                        continue
                    sa = template.get("serviceAccount") or default_compute(project)
                    found.append((sa, resource))
                    self.run_services_by_project.setdefault(project, []).append((resource, sa, item))
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                        self._bindings(resource, item.get("iamPolicy") or {})
                    else:
                        self.add_coverage("cloudrun_service_iam", resource, "not_collected",
                                          "service IAM policy was not collected", "Direct service grants may be missed")
                elif kind == "firebase_apphosting_backend":
                    resource = self._norm_scope(item.get("name") or "")
                    if (not re.fullmatch(re.escape(project) + r"/locations/[a-z0-9-]+/backends/[^/]+", resource)
                            or apphosting_names.get(item.get("name")) != 1):
                        merge((project, host), "partial")
                        continue
                    if item.get("deleteTime"):
                        continue
                    if item.get("reconciling") is True:
                        merge((project, host), "partial")
                        continue
                    raw_sa = item.get("serviceAccount")
                    if not isinstance(raw_sa, str):
                        merge((project, host), "partial")
                        continue
                    owner = None
                    if "/serviceAccounts/" in raw_sa:
                        match = re.fullmatch(r"projects/([^/]+)/serviceAccounts/([^/]+)", raw_sa)
                        if not match:
                            merge((project, host), "partial")
                            continue
                        owner, sa = match.groups()
                    else:
                        sa = raw_sa
                    account = self.sas.get("serviceAccount:" + sa)
                    if (not re.fullmatch(r"[^/@\s]+@[^/@\s]+\.gserviceaccount\.com", sa)
                            or account is None or account.attrs.get("disabled")
                            or (owner not in (None, "-") and
                                self._norm_scope("projects/" + owner) != account.scope)):
                        merge((project, host), "partial")
                        continue
                    found.append((sa, resource))
                elif kind == "cloudrun_job":
                    resource = self._norm_scope(item.get("name") or "")
                    if not resource.startswith(project + "/locations/") or "/jobs/" not in resource:
                        merge((project, host), "partial")
                        continue
                    template = (item.get("template") or {}).get("template")
                    if not isinstance(template, dict):
                        merge((project, host), "partial")
                        continue
                    sa = template.get("serviceAccount") or default_compute(project)
                    found.append((sa, resource))
                    self.run_jobs_by_project.setdefault(project, []).append((resource, sa, item))
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                        self._bindings(resource, item.get("iamPolicy") or {})
                    else:
                        self.add_coverage("cloudrun_job_iam", resource, "not_collected",
                                          "job IAM policy was not collected", "Direct job grants may be missed")
                elif kind == "cloudrun_instance":
                    resource = self._norm_scope(item.get("name") or "")
                    if not resource.startswith(project + "/locations/") or "/instances/" not in resource:
                        merge((project, host), "partial")
                        continue
                    raw_sa = item.get("serviceAccount")
                    sa = default_compute(project) if raw_sa in (None, "") else raw_sa
                    if isinstance(sa, str) and "/serviceAccounts/" in sa:
                        sa = sa.rsplit("/serviceAccounts/", 1)[-1]
                    found.append((sa, resource))
                    self.run_instances_by_project.setdefault(project, []).append((resource, sa, item))
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                        self._bindings(resource, item.get("iamPolicy") or {})
                    else:
                        self.add_coverage("cloudrun_instance_iam", resource, "not_collected",
                                          "instance IAM policy was not collected", "Direct instance grants may be missed")
                elif kind == "cloudrun_worker_pool":
                    resource = self._norm_scope(item.get("name") or "")
                    if not resource.startswith(project + "/locations/") or "/workerPools/" not in resource:
                        merge((project, host), "partial")
                        continue
                    template = item.get("template")
                    if not isinstance(template, dict):
                        merge((project, host), "partial")
                        continue
                    sa = template.get("serviceAccount") or default_compute(project)
                    found.append((sa, resource))
                    self.run_worker_pools_by_project.setdefault(project, []).append((resource, sa, item))
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                        self._bindings(resource, item.get("iamPolicy") or {})
                    else:
                        self.add_coverage("cloudrun_worker_pool_iam", resource, "not_collected",
                                          "worker pool IAM policy was not collected", "Direct pool grants may be missed")
                elif kind == "function":
                    sa = (item.get("serviceConfig") or {}).get("serviceAccountEmail") or item.get("serviceAccountEmail")
                    if not sa:
                        sa = default_compute(project) if "serviceConfig" in item or "buildConfig" in item else (
                            f"{project.split('/', 1)[1]}@appspot.gserviceaccount.com" if "runtime" in item else None)
                    found.append((sa, self._norm_scope(item.get("name") or "")))
                elif kind == "dataproc_cluster":
                    sa = ((item.get("config") or {}).get("gceClusterConfig") or {}).get("serviceAccount") or default_compute(project)
                    region = item.get("_region") or (item.get("labels") or {}).get("goog-dataproc-location")
                    cluster_name = item.get("clusterName")
                    if (not isinstance(region, str) or not re.fullmatch(r"[a-z0-9-]+", region)
                            or not isinstance(cluster_name, str)
                            or not re.fullmatch(r"[a-z][a-z0-9-]*", cluster_name)):
                        merge((project, host), "partial")
                        continue
                    cluster_resource = f"{project}/regions/{region}/clusters/{cluster_name}"
                    found.append((sa, cluster_resource))
                    self.dataproc_clusters_by_resource[cluster_resource] = item
                    self.dataproc_cluster_service_accounts[cluster_resource] = sa
                    self.dataproc_init_by_cluster[cluster_resource] = {}
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                        self._bindings(cluster_resource, item.get("iamPolicy") or {})
                    else:
                        self.add_coverage("dataproc_cluster_iam", cluster_resource, "not_collected",
                                          "cluster IAM policy was not collected", "Direct cluster grants may be missed")
                    for action in as_list((item.get("config") or {}).get("initializationActions")):
                        uri = str((action or {}).get("executableFile") or "") if isinstance(action, dict) else ""
                        if not sa or not uri.startswith("gs://"):
                            continue
                        bucket, _, object_path = uri[5:].partition("/")
                        if (not bucket or not object_path or object_path.endswith("/") or
                                "//" in object_path or "#" in object_path or "?" in object_path):
                            continue
                        bucket_resource = f"//storage.googleapis.com/projects/_/buckets/{bucket}"
                        object_resource = bucket_resource + "/objects/" + object_path
                        self.dataproc_init_by_cluster[cluster_resource][object_resource] = (
                            (item.get("_initObjectMetadata") or {}).get("objects", {}).get(uri))
                        self.dataproc_init_buckets.setdefault(sa, set()).add(bucket_resource)
                        self.dataproc_init_objects.setdefault(sa, set()).add(object_resource)
                        folder_parents = [(len(folder_name), folder_resource)
                                          for folder_name, folder_resource in self.managed_folders.get(bucket, ())
                                          if self.bucket_ubla.get(bucket) and object_path.startswith(folder_name)]
                        self.parents.setdefault(object_resource, max(folder_parents)[1] if folder_parents
                                                else bucket_resource)
                        for folder_name, folder_resource in self.managed_folders.get(bucket, ()):
                            if self.bucket_ubla.get(bucket) and object_path.startswith(folder_name):
                                self.dataproc_init_folders.setdefault(sa, set()).add(folder_resource)
                elif kind == "cloudbuild_build":
                    storage = item.get("sourceStorage") or {}
                    if not storage or item.get("buildTriggerId") or "generation" in storage:
                        continue
                    raw_sa = item.get("serviceAccount")
                    sa = raw_sa.rsplit("/serviceAccounts/", 1)[-1] if isinstance(raw_sa, str) and "/serviceAccounts/" in raw_sa else None
                    bucket, object_name = storage.get("bucket"), storage.get("object")
                    if (not sa or not isinstance(bucket, str) or not bucket or
                            not isinstance(object_name, str) or
                            not object_name.endswith((".zip", ".tar.gz"))):
                        merge((project, host), "partial")
                        continue
                    resource = self._norm_scope(item.get("name") or "") or None
                    found.append((sa, resource))
                    bucket_resource = f"//storage.googleapis.com/projects/_/buckets/{bucket}"
                    object_resource = bucket_resource + "/objects/" + object_name
                    self.cloudbuild_source_buckets.setdefault(sa, set()).add(bucket_resource)
                    self.cloudbuild_source_objects.setdefault(sa, set()).add(object_resource)
                    folder_parents = [(len(folder_name), folder_resource)
                                      for folder_name, folder_resource in self.managed_folders.get(bucket, ())
                                      if self.bucket_ubla.get(bucket) and object_name.startswith(folder_name)]
                    self.parents.setdefault(object_resource, max(folder_parents)[1] if folder_parents
                                            else bucket_resource)
                elif kind == "workflows_workflow":
                    resource = self._norm_scope(item.get("name") or "") or None
                    if not resource or not resource.startswith(project + "/locations/") or "/workflows/" not in resource:
                        merge((project, host), "partial")
                        continue
                    state = item.get("state")
                    if state != "ACTIVE":
                        if state not in ("UNAVAILABLE",):
                            merge((project, host), "partial")
                        continue
                    self.workflows_by_project.setdefault(project, set()).add(resource)
                    raw_sa = item.get("serviceAccount")
                    if raw_sa in (None, ""):
                        sa = default_compute(project)
                    elif isinstance(raw_sa, str):
                        sa = raw_sa.rsplit("/serviceAccounts/", 1)[-1] if "/serviceAccounts/" in raw_sa else raw_sa
                        if "@" not in sa:
                            sa = None
                    else:
                        sa = None
                    found.append((sa, resource))
                elif kind == "workstations_config":
                    resource = self._norm_scope(item.get("name") or "")
                    if (not resource.startswith(project + "/locations/") or
                            "/workstationClusters/" not in resource or
                            "/workstationConfigs/" not in resource):
                        merge((project, host), "partial")
                        continue
                    if item.get("deleteTime"):
                        continue
                    gce = item.get("host", {}).get("gceInstance", {}) if isinstance(item.get("host"), dict) else {}
                    sa = gce.get("serviceAccount") if isinstance(gce, dict) else None
                    if sa in (None, ""):
                        continue  # The service-managed identity is not an inventoried user SA.
                    if not isinstance(sa, str) or "@" not in sa:
                        merge((project, host), "partial")
                        continue
                    self.workstation_configs[resource] = {"sa": sa, "scopes": gce.get("serviceAccountScopes") or (),
                                                          "project": project, "item": item}
                    self.parents[resource] = resource.rsplit("/workstationConfigs/", 1)[0]
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                        self._bindings(resource, item.get("iamPolicy") or {})
                    else:
                        self.add_coverage("workstations_config_iam", resource, "not_collected",
                                          "config IAM policy was not collected", "Direct config grants may be missed")
                    found.append((sa, resource))
                elif kind == "workstations_workstation":
                    resource = self._norm_scope(item.get("name") or "")
                    if (not resource.startswith(project + "/locations/") or
                            "/workstationClusters/" not in resource or
                            "/workstationConfigs/" not in resource or
                            "/workstations/" not in resource):
                        merge((project, host), "partial")
                        continue
                    if item.get("deleteTime"):
                        continue
                    config = self.workstation_configs.get(resource.rsplit("/workstations/", 1)[0])
                    if config is None:
                        if self.host_status.get((project, "workstations_config")) not in ("collected", "empty"):
                            merge((project, host), "partial")
                        continue
                    self.parents[resource] = resource.rsplit("/workstations/", 1)[0]
                    self.workstation_rows[resource] = item
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") == "collected":
                        self._bindings(resource, item.get("iamPolicy") or {})
                    else:
                        self.add_coverage("workstations_workstation_iam", resource, "not_collected",
                                          "workstation IAM policy was not collected", "Direct workstation grants may be missed")
                    found.append((config["sa"], resource))
                elif kind == "workbench_instance":
                    resource = self._norm_scope(item.get("name") or "") or None
                    if not resource or not resource.startswith(project + "/locations/") or "/instances/" not in resource:
                        merge((project, host), "partial")
                        continue
                    if item.get("state") == "DELETED" or item.get("enableManagedEuc") is True:
                        continue
                    accounts = (item.get("gceSetup") or {}).get("serviceAccounts")
                    if accounts is None or accounts == []:
                        sa = default_compute(project)
                    elif isinstance(accounts, list) and len(accounts) == 1 and isinstance(accounts[0], dict):
                        sa = accounts[0].get("email") or default_compute(project)
                    else:
                        sa = None
                    found.append((sa, resource))
                elif kind == "vm_migration_vm":
                    resource = self._norm_scope(item.get("name") or "") or None
                    if (not resource or not re.fullmatch(
                            re.escape(project) + r"/locations/[^/]+/sources/[^/]+/migratingVms/[^/]+", resource)):
                        merge((project, host), "partial")
                        continue
                    defaults = item.get("computeEngineTargetDefaults")
                    if not isinstance(defaults, dict):
                        merge((project, host), "partial")
                        continue
                    target_project_name = self._norm_scope(defaults.get("targetProject") or "")
                    target_project = migration_targets.get(target_project_name)
                    if not target_project:
                        if migration_target_status.get(project) not in ("collected", "empty"):
                            merge((project, host), "partial")
                        continue
                    sa = defaults.get("serviceAccount")
                    if sa in (None, ""):
                        continue  # target VMs have no service account by default
                    if not isinstance(sa, str):
                        merge((project, host), "partial")
                        continue
                    if "/serviceAccounts/" in sa:
                        sa = sa.rsplit("/serviceAccounts/", 1)[-1]
                    if not re.fullmatch(r"[^/@\s]+@[^/@\s]+\.gserviceaccount\.com", sa):
                        merge((project, host), "partial")
                        continue
                    account = self.sas.get("serviceAccount:" + sa)
                    if account is None or account.scope != target_project or account.attrs.get("disabled"):
                        continue
                    found.append((sa, resource))
                elif kind == "gke_cluster":
                    resource = self._norm_scope(_gke_resource(item, project) or "") or None
                    pools = item.get("nodePools")
                    if not isinstance(pools, list) or not pools:
                        found.append((None, resource))  # Autopilot / pools not listed: node SA unknown
                    for pool in pools if isinstance(pools, list) else ():
                        sa = ((pool or {}).get("config") or {}).get("serviceAccount")
                        found.append((default_compute(project) if sa in (None, "", "default") else sa, resource))
                else:
                    config = item.get("config") or {}
                    sa = (config.get("nodeConfig") or {}).get("serviceAccount") or default_compute(project)
                    resource = self._norm_scope(item.get("name") or "") or None
                    found.append((sa, resource))
                    prefix = str(config.get("dagGcsPrefix") or "")
                    if sa and prefix.startswith("gs://"):
                        bucket, _, dag_path = prefix[5:].partition("/")
                        if bucket and dag_path:
                            dag_path = dag_path.rstrip("/") + "/"
                            bucket_resource = f"//storage.googleapis.com/projects/_/buckets/{bucket}"
                            self.composer_dag_buckets.setdefault(sa, set()).add(bucket_resource)
                            self.composer_dag_paths.setdefault(sa, []).append(
                                (resource, bucket_resource, dag_path, item.get("state")))
                            for folder_name, folder_resource in self.managed_folders.get(bucket, ()):
                                if self.bucket_ubla.get(bucket) and (dag_path.startswith(folder_name) or folder_name.startswith(dag_path)):
                                    self.composer_dag_folders.setdefault(sa, set()).add(folder_resource)
                        else:
                            self.composer_dag_incomplete.add(sa)
                            self.composer_unknown_bucket_projects.add(project)
                    elif sa:
                        self.composer_dag_incomplete.add(sa)
                        self.composer_unknown_bucket_projects.add(project)
                for sa, resource in found:
                    if not sa or not resource:
                        merge((project, host), "partial")
                        continue
                    if host == "composer_environment":
                        self.composer_host_projects.setdefault(sa, set()).add(project)
                    self.host_projects.setdefault((sa, host), set()).add(project)
                    if resource not in self.parents:
                        self.parents[resource] = project
                    listed = self.hosts.setdefault(sa, {}).setdefault(host, [])
                    if resource not in listed:
                        listed.append(resource)
        self._load_clouddeploy_render_paths(snap, default_compute)
        self._load_bigquery_spark_connections(snap)
        self._load_hypercompute_login_hosts(snap)

    def _load_hypercompute_login_hosts(self, snap):
        """Join Cluster Director login VM references to their exact Compute identities."""
        from collections import Counter

        host = "hypercomputecluster_cluster"
        cluster_status = inventory_status(snap, "hypercompute_cluster")
        vm_status = inventory_status(snap, "instance")
        vm_rows = list(items(snap, "instance"))
        vm_names = Counter(_instance_resource(item, scope) for scope, item in vm_rows
                           if isinstance(item, dict))
        vms = {name: (scope, item) for scope, item in vm_rows
               if isinstance(item, dict) and (name := _instance_resource(item, scope))
               and vm_names[name] == 1}
        cluster_rows = list(items(snap, "hypercompute_cluster"))
        cluster_names = Counter(item.get("name") for _, item in cluster_rows
                                if isinstance(item, dict) and isinstance(item.get("name"), str))

        def partial(project):
            self.host_status[(project, host)] = "partial"

        projects = {self._norm_scope(scope) for scope in cluster_status}
        for project in projects:
            self.host_status[(project, host)] = (
                "empty" if cluster_status.get(project) == "empty" else
                "collected" if cluster_status.get(project) == "collected"
                and vm_status.get(project) in ("collected", "empty") else "partial")
        for scope, item in cluster_rows:
            project = self._norm_scope(scope)
            raw = item.get("name") if isinstance(item, dict) else None
            cluster = self._norm_scope(raw) if isinstance(raw, str) else ""
            match = re.fullmatch(re.escape(project) + r"/locations/([a-z0-9-]+)/clusters/[^/]+", cluster)
            if not match or cluster_names.get(raw) != 1 or item.get("reconciling") is True:
                partial(project)
                continue
            region = match.group(1)
            login = ((item.get("orchestrator") or {}).get("slurm") or {}).get("loginNodes")
            if not isinstance(login, dict):
                # Other orchestrators and clusters without login nodes have no path.
                continue
            try:
                count = int(login.get("count"))
            except (TypeError, ValueError):
                count = 0
            refs = login.get("instances")
            zone = login.get("zone")
            if count == 0 and login.get("count") in (0, "0"):
                continue
            if (count < 1 or not isinstance(zone, str) or not zone.startswith(region + "-")
                    or not isinstance(refs, list) or not refs):
                partial(project)
                continue
            seen = set()
            for entry in refs:
                vm_name = entry.get("instance") if isinstance(entry, dict) else None
                if (not isinstance(vm_name, str)
                        or not re.fullmatch(re.escape(project) + r"/zones/" + re.escape(zone)
                                            + r"/instances/[^/]+", vm_name)
                        or vm_name in seen or vm_names.get(vm_name) != 1):
                    partial(project)
                    continue
                seen.add(vm_name)
                vm_row = vms.get(vm_name)
                if vm_row is None or self._norm_scope(vm_row[0]) != project:
                    partial(project)
                    continue
                vm = vm_row[1]
                accounts = vm.get("serviceAccounts")
                if vm.get("status") != "RUNNING" or not isinstance(accounts, list) or len(accounts) != 1:
                    partial(project)
                    continue
                account = accounts[0]
                email = account.get("email") if isinstance(account, dict) else None
                scopes = account.get("scopes") if isinstance(account, dict) else None
                target = self.sas.get("serviceAccount:" + email) if isinstance(email, str) else None
                if (target is None or target.attrs.get("disabled")
                        or not isinstance(scopes, list)
                        or "https://www.googleapis.com/auth/cloud-platform" not in scopes):
                    partial(project)
                    continue
                self.parents.setdefault(cluster, project)
                self.host_projects.setdefault((email, host), set()).add(project)
                listed = self.hosts.setdefault(email, {}).setdefault(host, [])
                if cluster not in listed:
                    listed.append(cluster)

    def _load_bigquery_spark_connections(self, snap):
        """Keep exact Spark connection identities and policy coverage for the procedure path."""
        self.spark_connections = {}
        self.spark_routines = {}
        routine_inventory = {self._norm_scope(scope): status for scope, status in
                             inventory_status(snap, "bigquery_routine_metadata").items()}
        self.spark_routine_status = dict(routine_inventory)
        from collections import Counter
        routine_rows = list(items(snap, "bigquery_routine_metadata"))
        routine_counts = Counter(item.get("name") for _, item in routine_rows
                                 if isinstance(item.get("name"), str))
        for scope, item in routine_rows:
            project = self._norm_scope(scope)
            if routine_inventory.get(project) != "collected":
                if routine_inventory.get(project) == "empty":
                    self.spark_routine_status[project] = "partial"
                continue
            name = item.get("name")
            if item.get("routineType") != "PROCEDURE" or item.get("language") not in (
                    "PYTHON", "JAVA", "SCALA"):
                continue
            if (not isinstance(name, str) or not re.fullmatch(
                    re.escape(project) + r"/datasets/[A-Za-z0-9_]+/routines/[A-Za-z0-9_]{1,256}", name)
                    or routine_counts[name] != 1):
                self.spark_routine_status[project] = "partial"
                continue
            dataset = name.rsplit("/routines/", 1)[0]
            metadata = self.bigquery_datasets.get(dataset)
            if (not isinstance(metadata, dict) or not isinstance(metadata.get("location"), str)
                    or metadata["location"].lower() != str(item.get("datasetLocation", "")).lower()):
                self.spark_routine_status[project] = "partial"
                continue
            self.parents.setdefault(name, dataset)
            self.spark_routines[name] = {"dataset": dataset, "location": metadata["location"]}
        rows = list(items(snap, "bigquery_connection"))
        counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
        repeated = {name for name, count in counts.items() if count > 1}
        connection_inventory = {self._norm_scope(scope): status for scope, status in
                                inventory_status(snap, "bigquery_connection").items()}
        for project, status in connection_inventory.items():
            if project.startswith("projects/"):
                self.host_status[(project, "bigquery_spark_connection")] = status
        for scope, item in rows:
            project = self._norm_scope(scope)
            if connection_inventory.get(project) != "collected":
                if connection_inventory.get(project) == "empty":
                    self.host_status[(project, "bigquery_spark_connection")] = "partial"
                continue
            name = item.get("name")
            coverage = item.get("_coverage")
            if (not isinstance(name, str) or name in repeated or not project.startswith("projects/")
                    or not re.fullmatch(
                    re.escape(project) + r"/locations/[A-Za-z0-9-]+/connections/[A-Za-z0-9_-]+", name)
                    or not isinstance(coverage, dict)
                    or not isinstance(coverage.get("connectionDetails"), dict)
                    or coverage["connectionDetails"].get("status") != "collected"):
                self.host_status[(project, "bigquery_spark_connection")] = "partial"
                continue
            spark = item.get("spark")
            if spark is None:
                continue
            email = spark.get("serviceAccountId") if isinstance(spark, dict) else None
            if (not isinstance(email, str) or not re.fullmatch(
                    r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com", email)):
                self.host_status[(project, "bigquery_spark_connection")] = "partial"
                continue
            self.parents.setdefault(name, project)
            node = self._principal("serviceAccount:" + email, project)
            node.scope = project
            node.attrs.update(project=project, resource=f"{project}/serviceAccounts/{email}")
            self.sas[node.id] = node
            self.host_projects.setdefault((email, "bigquery_spark_connection"), set()).add(project)
            self.hosts.setdefault(email, {}).setdefault("bigquery_spark_connection", []).append(name)
            policy_coverage = coverage.get("iamPolicy")
            policy_status = policy_coverage.get("status") if isinstance(policy_coverage, dict) else None
            policy = item.get("iamPolicy")
            if policy_status == "collected" and not isinstance(policy, dict):
                policy_status = "malformed"
            self.spark_connections[name] = {
                "identity": node, "project": project,
                "location": name.split("/locations/", 1)[1].split("/", 1)[0],
                "policy_status": policy_status if policy_status else "not_collected",
            }

    def _load_bigquery_transfer_configs(self, snap):
        """Bind scheduled-query metadata without importing SQL parameters."""
        from collections import Counter
        self.transfer_configs = {}
        self.iam_policy_inventory_status = {
            self._norm_scope(scope): status for scope, status in inventory_status(snap, "iam_policy").items()}
        self.iam_role_inventory_status = {
            self._norm_scope(scope): status for scope, status in inventory_status(snap, "iam_role").items()}
        self.transfer_service_state = {}
        usage_status = {self._norm_scope(scope): status for scope, status in
                        inventory_status(snap, "service_usage").items()}
        for project, status in usage_status.items():
            self.transfer_service_state[project] = "unknown" if status not in ("collected", "empty") else "disabled"
        observed_services = set()
        for scope, item in items(snap, "service_usage"):
            project = self._norm_scope(scope)
            name = item.get("name")
            if isinstance(name, str) and self._norm_scope(name) == f"{project}/services/bigquerydatatransfer.googleapis.com":
                if project in observed_services:
                    self.transfer_service_state[project] = "unknown"
                    continue
                observed_services.add(project)
                self.transfer_service_state[project] = (
                    "enabled" if item.get("state") == "ENABLED" else
                    "disabled" if item.get("state") == "DISABLED" else "unknown")
        inventory = {self._norm_scope(scope): status for scope, status in
                     inventory_status(snap, "bigquery_transfer_config").items()}
        self.transfer_config_status = dict(inventory)
        rows = list(items(snap, "bigquery_transfer_config"))
        counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
        for scope, item in rows:
            project = self._norm_scope(scope)
            if inventory.get(project) != "collected":
                if inventory.get(project) == "empty":
                    self.transfer_config_status[project] = "partial"
                continue
            name = item.get("name")
            schedule_options = item.get("scheduleOptions")
            if (not isinstance(name, str) or counts[name] != 1 or not re.fullmatch(
                    re.escape(project) + r"/(?:locations/[A-Za-z0-9-]+/)?transferConfigs/[A-Za-z0-9_-]+", name)
                    or item.get("dataSourceId") != "scheduled_query"
                    or not isinstance(item.get("destinationDatasetId"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_]+", item["destinationDatasetId"])
                    or type(item.get("disabled")) is not bool
                    or (schedule_options is not None and not isinstance(schedule_options, dict))):
                self.transfer_config_status[project] = "partial"
                continue
            dataset = project + "/datasets/" + item["destinationDatasetId"]
            metadata = self.bigquery_datasets.get(dataset)
            if (not isinstance(metadata, dict) or not isinstance(metadata.get("location"), str)
                    or metadata["location"].lower() != str(item.get("location", "")).lower()):
                self.transfer_config_status[project] = "partial"
                continue
            self.parents.setdefault(name, project)
            self.transfer_configs[name] = {"project": project, "dataset": dataset,
                                           "location": metadata["location"],
                                           "disabled": item["disabled"],
                                           "auto_disabled": (schedule_options or {}).get(
                                               "disableAutoScheduling") is True}

    def _load_bigquery_continuous_assignments(self, snap):
        """Keep only exact, effective CONTINUOUS reservation assignments."""
        from collections import Counter

        self.continuous_assignment_status = {
            self._norm_scope(scope): status for scope, status in
            inventory_status(snap, "bigquery_continuous_assignment").items()}
        self.continuous_assignments = {}
        rows = list(items(snap, "bigquery_continuous_assignment"))
        counts = Counter(item.get("name") for _, item in rows if isinstance(item.get("name"), str))
        for scope, item in rows:
            project = self._norm_scope(scope)
            name = item.get("name")
            location = item.get("sourceLocation")
            coverage = (item.get("_coverage") or {}).get("reservationDetails") or {}
            if (self.continuous_assignment_status.get(project) != "collected"
                    or not isinstance(name, str) or counts[name] != 1
                    or not isinstance(location, str)
                    or not re.fullmatch(r"[A-Za-z0-9-]+", location)
                    or not re.fullmatch(r"projects/[^/]+/locations/" + re.escape(location)
                                        + r"/reservations/[A-Za-z0-9_-]+/assignments/[A-Za-z0-9_-]+", name)
                    or self._norm_scope(item.get("assignee") or "") not in self.ancestors(project)
                    or item.get("jobType") != "CONTINUOUS"
                    or item.get("state") not in ("ACTIVE", "PENDING")
                    or not isinstance(coverage, dict)):
                self.continuous_assignment_status[project] = "partial"
                continue
            principal = item.get("principal")
            if principal is not None and (not isinstance(principal, str) or not principal):
                self.continuous_assignment_status[project] = "partial"
                continue
            self.continuous_assignments.setdefault((project, location.lower()), []).append({
                "name": name,
                "reservation": name.rsplit("/assignments/", 1)[0],
                "state": item["state"],
                "principal": principal,
                "edition": item.get("reservationEdition") if coverage.get("status") == "collected" else None,
                "reservation_status": coverage.get("status") or "not_collected",
            })

    def _load_clouddeploy_render_paths(self, snap, default_compute):
        """Join a pipeline stage to its custom target type and RENDER identity."""
        self.clouddeploy_render_paths = {}
        self.clouddeploy_existing_render_paths = {}
        self.clouddeploy_existing_render_uncertain_paths = {}
        self.clouddeploy_render_types_by_project = {}
        self.clouddeploy_render_targets_by_project = {}
        self.clouddeploy_render_pipeline_targets_by_project = {}
        self.clouddeploy_pipelines_by_project = {}
        statuses = [inventory_status(snap, kind) for kind in
                    ("clouddeploy_delivery_pipeline", "clouddeploy_target", "clouddeploy_custom_target_type")]
        self.clouddeploy_render_incomplete = any(
            not state or any(status not in ("collected", "empty") for status in state.values())
            for state in statuses)
        targets = {item.get("name"): item for _, item in items(snap, "clouddeploy_target")
                   if isinstance(item.get("name"), str)}
        types = {item.get("name"): item for _, item in items(snap, "clouddeploy_custom_target_type")
                 if isinstance(item.get("name"), str)}
        for custom, item in types.items():
            actions = item.get("customActions") or {}
            if (isinstance(actions.get("renderAction"), str) and actions["renderAction"]
                    and not actions.get("includeSkaffoldModules")):
                self.clouddeploy_render_types_by_project.setdefault("/".join(custom.split("/")[:2]), set()).add(custom)
        for target_name, target in targets.items():
            custom = (target.get("customTarget") or {}).get("customTargetType")
            project = "/".join(target_name.split("/")[:2])
            same_location = (isinstance(custom, str) and "/targets/" in target_name
                             and "/customTargetTypes/" in custom
                             and target_name.split("/targets/", 1)[0] == custom.split("/customTargetTypes/", 1)[0])
            if same_location and custom in self.clouddeploy_render_types_by_project.get(project, ()):
                self.parents.setdefault(target_name, project)
                self.clouddeploy_render_targets_by_project.setdefault(project, []).append(target_name)
        for scope, pipeline in items(snap, "clouddeploy_delivery_pipeline"):
            project = self._norm_scope(scope)
            name = pipeline.get("name")
            if (not isinstance(name, str) or not name.startswith(project + "/locations/")
                    or "/deliveryPipelines/" not in name or pipeline.get("suspended") is True):
                continue
            location = name.split("/deliveryPipelines/", 1)[0]
            self.parents.setdefault(name, project)
            self.clouddeploy_pipelines_by_project.setdefault(project, []).append(name)
            for stage in as_list((pipeline.get("serialPipeline") or {}).get("stages")):
                target_id = stage.get("targetId") if isinstance(stage, dict) else None
                if not isinstance(target_id, str) or not target_id or "/" in target_id:
                    continue
                target = targets.get(location + "/targets/" + target_id)
                if not isinstance(target, dict):
                    if statuses[1].get(project) not in ("collected", "empty"):
                        self.clouddeploy_render_incomplete = True
                    continue
                children = as_list((target.get("multiTarget") or {}).get("targetIds"))
                render_targets = []
                if children:
                    for child_id in children:
                        if not isinstance(child_id, str) or not child_id or "/" in child_id:
                            self.clouddeploy_render_incomplete = True
                            continue
                        child = targets.get(location + "/targets/" + child_id)
                        if not isinstance(child, dict):
                            self.clouddeploy_render_incomplete = True
                            continue
                        render_targets.append((child, target))
                else:
                    render_targets.append((target, None))
                for render_target, parent_target in render_targets:
                    custom = (render_target.get("customTarget") or {}).get("customTargetType")
                    if not isinstance(custom, str) or not custom.startswith(location + "/customTargetTypes/"):
                        continue
                    if custom not in types:
                        if statuses[2].get(project) not in ("collected", "empty"):
                            self.clouddeploy_render_incomplete = True
                        continue
                    configs = as_list(render_target.get("executionConfigs"))
                    renders = [config for config in configs if isinstance(config, dict)
                               and "RENDER" in as_list(config.get("usages"))]
                    if parent_target is not None and not renders and not configs:
                        configs = as_list(parent_target.get("executionConfigs"))
                        renders = [config for config in configs if isinstance(config, dict)
                                   and "RENDER" in as_list(config.get("usages"))]
                    if len(renders) > 1 or (configs and not renders):
                        self.clouddeploy_render_incomplete = True
                        continue
                    config = renders[0] if renders else {}
                    configured_accounts = [account for account in (
                        config.get("serviceAccount"),
                        (config.get("defaultPool") or {}).get("serviceAccount"),
                        (config.get("privatePool") or {}).get("serviceAccount")) if account]
                    if len(set(configured_accounts)) > 1:
                        self.clouddeploy_render_incomplete = True
                        continue
                    email = configured_accounts[0] if configured_accounts else default_compute(project)
                    if isinstance(email, str) and "/serviceAccounts/" in email:
                        email = email.rsplit("/serviceAccounts/", 1)[-1]
                    if not isinstance(email, str) or "@" not in email:
                        self.clouddeploy_render_incomplete = True
                        continue
                    self.parents.setdefault(custom, project)
                    self.clouddeploy_render_paths.setdefault(email, []).append((name, custom))
                    actions = types[custom].get("customActions") or {}
                    if isinstance(actions.get("renderAction"), str) and actions["renderAction"]:
                        if actions.get("includeSkaffoldModules") or not actions.get("deployAction"):
                            self.clouddeploy_existing_render_uncertain_paths.setdefault(email, []).append(name)
                        else:
                            self.clouddeploy_existing_render_paths.setdefault(email, []).append(name)
                            self.clouddeploy_render_pipeline_targets_by_project.setdefault(project, []).append(
                                (name, render_target["name"]))

    def _load_cloudbuild_writable_triggers(self, snap):
        """Join writable connected repositories to push triggers and explicit build identities."""
        self.cloudbuild_writable_trigger_paths = {}
        status = inventory_status(snap, "cloudbuild_trigger")
        self.cloudbuild_trigger_incomplete = not status or any(
            value not in ("collected", "empty") for value in status.values())
        connection_status = {self._norm_scope(scope): state for scope, state in
                             inventory_status(snap, "cloudbuild_connection").items()}
        repository_status = {self._norm_scope(scope): state for scope, state in
                             inventory_status(snap, "cloudbuild_repository").items()}
        connections = {}
        for scope, item in items(snap, "cloudbuild_connection"):
            name = self._norm_scope(item.get("name"))
            if name.startswith(self._norm_scope(scope) + "/locations/"):
                connections.setdefault(name, []).append(item)
        repositories = {}
        for scope, item in items(snap, "cloudbuild_repository"):
            name = self._norm_scope(item.get("name"))
            if name.startswith(self._norm_scope(scope) + "/locations/"):
                repositories.setdefault(name, []).append(item)
        for scope, trigger in items(snap, "cloudbuild_trigger"):
            if trigger.get("disabled") is True:
                continue
            project = self._norm_scope(scope)
            if trigger.get("eventType") == "MANUAL":
                continue
            trigger_name = trigger.get("resourceName")
            trigger_identity_uncertain = not (isinstance(trigger_name, str) and
                re.fullmatch(re.escape(project) + r"/locations/[^/]+/triggers/[^/]+",
                             self._norm_scope(trigger_name)))
            event_type_uncertain = trigger.get("eventType") not in (None, "REPO")
            event = trigger.get("repositoryEventConfig") or {}
            repo = event.get("repository")
            push = event.get("push")
            if (not isinstance(repo, str) or not isinstance(push, dict)
                    or not (push.get("branch") or push.get("tag"))):
                continue
            parts = repo.split("/")
            if (len(parts) != 8 or parts[0] != "projects" or parts[2] != "locations"
                    or parts[4] != "connections" or parts[6] != "repositories"
                    or any(not part for part in parts)):
                continue
            sa = trigger.get("serviceAccount")
            if not sa:
                resource_name = trigger.get("resourceName")
                match = re.fullmatch(re.escape(project) + r"/locations/([^/]+)/triggers/[^/]+",
                                     self._norm_scope(resource_name)) if isinstance(resource_name, str) else None
                if match:
                    sa = self.cloudbuild_legacy_default_by_location.get((project, match[1]))
            if not isinstance(sa, str) or "/serviceAccounts/" not in sa:
                self.cloudbuild_trigger_incomplete = True
                continue
            email = sa.rsplit("/serviceAccounts/", 1)[-1]
            if "@" not in email:
                self.cloudbuild_trigger_incomplete = True
                continue
            sa_identity_uncertain = self._norm_scope(sa) != f"{project}/serviceAccounts/{email}"
            connection = "/".join(parts[:-2])
            repo_project = "/".join(parts[:2])
            self.parents.setdefault(connection, repo_project)
            self.parents.setdefault(repo, connection)
            if (connection_status.get(repo_project) in ("collected", "empty")
                    and repository_status.get(repo_project) in ("collected", "empty")
                    and not connections.get(connection) and not repositories.get(repo)):
                continue
            inventory_uncertain = (connection_status.get(repo_project) not in ("collected", "empty")
                                   or repository_status.get(repo_project) not in ("collected", "empty")
                                   or len(connections.get(connection, ())) != 1
                                   or len(repositories.get(repo, ())) != 1)
            connection_item = (connections.get(connection) or [{}])[0]
            repository_item = (repositories.get(repo) or [{}])[0]
            stage = connection_item.get("installationStage")
            if stage not in (None, "COMPLETE"):
                inventory_uncertain = True
            remote_uri = repository_item.get("remoteUri")
            if not isinstance(remote_uri, str) or not remote_uri.startswith("https://"):
                inventory_uncertain = True
            git_file = trigger.get("gitFileSource")
            same_repo_file = (isinstance(git_file, dict)
                              and isinstance(git_file.get("path"), str) and bool(git_file["path"])
                              and not git_file.get("uri")
                              and git_file.get("repository") in (None, repo)
                              and not git_file.get("revision"))
            source_config = (isinstance(trigger.get("filename"), str) and bool(trigger["filename"])) or same_repo_file
            approval = (trigger.get("approvalConfig") or {}).get("approvalRequired") is True
            filtered = bool(trigger.get("filter"))
            cross_repository = repo_project != project
            self.cloudbuild_writable_trigger_paths.setdefault(email, []).append(
                (repo, connection, project, approval or filtered or not source_config or cross_repository
                 or inventory_uncertain or trigger_identity_uncertain or event_type_uncertain
                 or sa_identity_uncertain))

    def _load_sourcerepo_triggers(self, snap):
        """Associate a Cloud Source repo's exact push trigger with its build SA."""
        self.sourcerepo_trigger_paths = {}
        self.sourcerepo_trigger_incomplete = any(
            not status or any(value not in ("collected", "empty") for value in status.values())
            for status in (inventory_status(snap, "source_repository"),
                           inventory_status(snap, "cloudbuild_trigger")))
        trigger_status = {self._norm_scope(scope): state for scope, state in
                          inventory_status(snap, "cloudbuild_trigger").items()}
        repository_status = {self._norm_scope(scope): state for scope, state in
                             inventory_status(snap, "source_repository").items()}
        repositories = {}
        for scope, item in items(snap, "source_repository"):
            project = self._norm_scope(scope)
            name = self._norm_scope(item.get("name") or "")
            if not re.fullmatch(re.escape(project) + r"/repos/[A-Za-z0-9._-]+", name):
                self.sourcerepo_trigger_incomplete = True
                continue
            repositories.setdefault(name, []).append(item)
            self.parents.setdefault(name, project)
            policy_status = (item.get("_coverage") or {}).get("iamPolicy", {}).get("status")
            if policy_status == "collected" and isinstance(item.get("iamPolicy"), dict):
                self._bindings(name, item["iamPolicy"])
            else:
                self.add_coverage("source_repository_iam", name, "not_collected",
                                  "repository IAM policy was not collected", "Repository-level push grants may be missed")
        for scope, trigger in items(snap, "cloudbuild_trigger"):
            if trigger.get("disabled") is True:
                continue
            project = self._norm_scope(scope)
            template = trigger.get("triggerTemplate")
            if not isinstance(template, dict):
                continue
            repo_name = template.get("repoName")
            repo_project = template.get("projectId") or project.partition("/")[2]
            if (not isinstance(repo_name, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", repo_name)
                    or not isinstance(repo_project, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", repo_project)):
                self.sourcerepo_trigger_incomplete = True
                continue
            repo = f"projects/{repo_project}/repos/{repo_name}"
            if len(repositories.get(repo, ())) != 1:
                if repositories.get(repo) or self.sourcerepo_trigger_incomplete:
                    self.sourcerepo_trigger_incomplete = True
                continue
            if not any(isinstance(template.get(field), str) and template[field]
                       for field in ("branchName", "tagName")):
                continue
            sa = trigger.get("serviceAccount")
            if not sa:
                name = self._norm_scope(trigger.get("resourceName") or "")
                match = re.fullmatch(re.escape(project) + r"/locations/([^/]+)/triggers/[^/]+", name)
                if match:
                    sa = self.cloudbuild_legacy_default_by_location.get((project, match[1]))
            if not isinstance(sa, str) or "/serviceAccounts/" not in sa:
                self.sourcerepo_trigger_incomplete = True
                continue
            email = sa.rsplit("/serviceAccounts/", 1)[-1]
            if "@" not in email:
                self.sourcerepo_trigger_incomplete = True
                continue
            git_file = trigger.get("gitFileSource")
            source_config = (isinstance(trigger.get("filename"), str) and bool(trigger["filename"])) or (
                isinstance(git_file, dict) and isinstance(git_file.get("path"), str)
                and bool(git_file["path"]) and not git_file.get("uri")
                and git_file.get("repository") in (None, repo) and not git_file.get("revision"))
            review = (trigger_status.get(project) != "collected"
                      or repository_status.get(f"projects/{repo_project}") != "collected" or not source_config
                      or (trigger.get("approvalConfig") or {}).get("approvalRequired") is True
                      or bool(trigger.get("filter")) or trigger.get("eventType") not in (None, "REPO")
                      or self._norm_scope(sa) != f"{project}/serviceAccounts/{email}")
            self.sourcerepo_trigger_paths.setdefault(email, []).append((repo, review))

    def _load_cloudbuild_default_identity(self, snap):
        """Synthesize a legacy Google-owned build identity only when the API reports it as default."""
        self.cloudbuild_legacy_default_by_location = {}
        self.cloudbuild_default_by_location = {}
        for scope, status in inventory_status(snap, "cloudbuild_default_sa").items():
            project = self._norm_scope(scope)
            self.host_status[(project, "cloudbuild_default_sa")] = status
        for scope, item in items(snap, "cloudbuild_default_sa"):
            project = self._norm_scope(scope)
            name = self._norm_scope(item.get("name") or "")
            account = item.get("serviceAccountEmail")
            if (not name.startswith(project + "/locations/")
                    or not name.endswith("/defaultServiceAccount")
                    or not isinstance(account, str)):
                self.host_status[(project, "cloudbuild_default_sa")] = "partial"
                continue
            email = account.rsplit("/serviceAccounts/", 1)[-1]
            if "@" not in email:
                self.host_status[(project, "cloudbuild_default_sa")] = "partial"
                continue
            location = name.split("/locations/", 1)[-1].split("/", 1)[0]
            self.cloudbuild_default_by_location[(project, location)] = email
            self.parents.setdefault(f"{project}/locations/{location}", project)
            if not re.fullmatch(r"[0-9]+@cloudbuild\.gserviceaccount\.com", email):
                continue
            self.cloudbuild_legacy_default_by_location[(project, location)] = account
            resource = f"{project}/serviceAccounts/{email}"
            node = self._principal(f"serviceAccount:{email}", project)
            node.attrs.update(resource=resource, project=project, disabled=False)
            self.sas[node.id] = node
            self.sa_by_resource[resource] = node
            self.parents.setdefault(resource, project)
            self.parents.setdefault(name, project)
            self.hosts.setdefault(email, {}).setdefault("cloudbuild_default_sa", []).append(name)

    # ------------------------------------------------------------ hierarchy
    def ancestors(self, ref):
        """Chain from ref up to the root. Memoized after _load (callers never mutate the returned list)."""
        memo = self.__dict__.get("_ancestor_memo")
        if memo is not None:
            try:
                return memo[ref]
            except KeyError:
                chain = memo[ref] = self._ancestors(ref)
                return chain
            except TypeError:
                pass
        return self._ancestors(ref)

    def _ancestors(self, ref):
        chain, seen = [], set()
        while ref and ref not in seen:
            chain.append(ref)
            seen.add(ref)
            ref = self.parents.get(ref)
        return chain

    # ------------------------------------------------------------ interface
    def requirement_key(self, req):
        return str(req.get("permission") or req.get("action") or "").lower()

    def requirement_template(self, req):
        value = req.get("resource")
        return None if value in (None, "*") else value

    def localizable(self, req):
        return self.requirement_template(req) is None

    def possible(self, principal):
        indexes, signature = self.prefilter_indexes()
        key = ("possible", signature, principal.kind, principal.perm_key)
        if key not in self._check_cache:
            keys, universal = set(), False
            role_keys = indexes.setdefault("gcp_role_keys", {})
            for _, role_name, _, _ in principal.attrs["grants"]:
                role = self.roles.get(role_name)
                if role is None:
                    continue
                if role.universal:
                    universal = True
                    continue
                keys.update(role.exact)
                if role.patterns:
                    if role_name not in role_keys:
                        role_keys[role_name] = frozenset(k for k in self.catalog_keys if role.has(k))
                    keys.update(role_keys[role_name])
            if principal.kind == "gcp_user" and self.group_by_resource:
                keys.add("cloudidentity.groups.memberships.create")
            self._check_cache[key] = (frozenset(keys), universal)
        return self._check_cache[key]

    def cached_check(self, principal, req, ref):
        if self.requirement_key(req) == "cloudidentity.groups.memberships.create":
            key = ("group_membership_gain", principal.id, ref)
            if key not in self._check_cache:
                self._check_cache[key] = self._group_membership_gain(principal, ref)
            return self._check_cache[key]
        return super().cached_check(principal, req, ref)

    def holders(self, principal, perm):
        """[(node, Grant)] where the principal holds perm (allow side only)."""
        key = (principal.perm_key, perm)
        if key not in self._holders:
            out, plain, listed = {}, {}, {}
            for node, role_name, conditional, ref in principal.attrs["grants"]:
                role = self.roles.get(role_name)
                if role is None or not role.has(perm):
                    continue
                approx = ["builtin_role_permissions_approximated"] if role.confidence != "derived" else []
                conf = "conditional" if conditional or role.confidence != "derived" else "derived"
                grant = Grant(conf, [dict(ref)], (["binding_condition"] if conditional else []) + approx)
                if conditional and cel.compile_condition(conditional) is not None and cel.uses_resource(conditional):
                    # Decided per resource in check(): derived (role confidence) when true, dropped when false.
                    listed.setdefault(node, []).append(
                        (conditional, Grant(role.confidence, [dict(ref)], ["binding_condition_satisfied"] + approx), grant))
                else:
                    plain[node] = best(plain.get(node), grant)
                previous = out.get(node)
                out[node] = grant if previous is None or (previous.confidence != "derived" and conf == "derived") else previous
            # Nodes where an unconditional binding already gives a derived grant need no per-resource evaluation.
            self._resdep[key] = {n: (plain.get(n), v) for n, v in listed.items() if out[n].confidence != "derived"}
            self._holders[key] = out
        return self._holders[key]

    def _deny(self, principal, perm, ref, grant):
        chain = self.ancestors(ref) if ref is not ANY else []
        project = chain[-1] if chain else None
        for attachment, rule, name in self.deny:
            if ref is not ANY and attachment not in chain:
                continue
            if not any(_deny_perm_match(p, perm) for p in as_list(rule.get("deniedPermissions"))):
                continue
            if any(_deny_perm_match(p, perm) for p in as_list(rule.get("exceptionPermissions"))):
                continue
            if not _deny_member(principal, rule.get("deniedPrincipals")) or _deny_member(principal, rule.get("exceptionPrincipals")):
                continue
            if rule.get("denialCondition") or ref is ANY:
                grant = downgrade(Grant(grant.confidence, grant.refs + ({"deny_policy": name},), grant.conditions),
                                  "conditional", "deny_policy_may_apply")
                continue
            return None
        if ref is not ANY:
            roots = [n for n in chain if n.startswith(("projects/", "folders/", "organizations/")) and n.count("/") == 1]
            if any(self.deny_status.get(n, "not_collected") not in ("collected", "empty") for n in roots):
                grant = downgrade(grant, "conditional", "deny_policies_not_evaluated")
        elif any(s not in ("collected", "empty") for s in self.deny_status.values()) or not self.deny_status:
            grant = downgrade(grant, "conditional", "deny_policies_not_evaluated")
        del project
        return grant

    def check(self, principal, req, ref):
        perm = self.requirement_key(req)
        if perm == "cloudidentity.groups.memberships.create":
            return self._group_membership_gain(principal, ref)
        held = self.holders(principal, perm)
        if not held:
            return None
        if ref is ANY:
            best_grant = None
            for grant in held.values():
                best_grant = grant if best_grant is None or grant.confidence == "derived" else best_grant
            return self._deny(principal, perm, ANY, best_grant)
        found = None
        resdep = self._resdep.get((principal.perm_key, perm))
        for node in self.ancestors(ref):
            if node in held:
                got = self._conditioned(resdep[node], ref) if resdep and node in resdep else held[node]
                if got is None:
                    continue
                found = got
                if found.confidence == "derived":
                    break
        return self._deny(principal, perm, ref, found) if found else None

    def _group_membership_gain(self, principal, ref):
        """Synthetic Cloud Identity membership action, scoped to a privileged exact group."""
        if principal.kind != "gcp_user":
            return None
        if ref is ANY:
            grant = None
            for name in self.group_by_resource:
                grant = best(grant, self._group_membership_gain(principal, name))
            return grant
        group_record = self.group_by_resource.get(ref)
        if group_record is None:
            return None
        email, group, scope = group_record
        labels = group.get("labels") or {}
        if (not isinstance(labels, dict) or group.get("dynamicGroupMetadata")
                or "cloudidentity.googleapis.com/groups.dynamic" in labels):
            return None
        grants = self.grants.get("group:" + email, ())
        if not grants:
            return None
        actor = str(principal.attrs.get("email") or "").lower()
        if not actor or actor in self.group_members.get(ref, set()):
            return None
        membership_known = self.group_membership_status.get(scope) in ("collected", "empty")
        admin_roles = {str(role).lower().replace("_", " ") for role in self.ws_admin.get(actor, ())}
        can_manage = "super admin" in admin_roles or "groups admin" in admin_roles
        locked = "cloudidentity.googleapis.com/groups.locked" in labels
        if locked and not can_manage:
            return None
        settings = self.group_settings.get(email)
        can_join = False
        join_unknown = False
        external_membership_unknown = False
        if settings:
            who, external = settings
            same_domain = _email_domain(actor) == _email_domain(email)
            # The group's email domain is only a hint about Workspace domain
            # ownership. A different email domain may be another verified
            # domain of the same customer, so keep the outcome unresolved.
            external_membership_unknown = not same_domain and external is not True
            if who == "ANYONE_CAN_JOIN":
                can_join = same_domain or external is True
                join_unknown = not can_join and external is None
            elif who == "ALL_IN_DOMAIN_CAN_JOIN":
                can_join = same_domain
                join_unknown = not same_domain
        else:
            join_unknown = True
        if can_manage and external_membership_unknown:
            join_unknown = True
        if not can_manage and not can_join and not join_unknown:
            return None
        gain = False
        uncertain_gain = False
        for node, role_name, condition, _ in grants:
            role = self.roles.get(role_name)
            if role is None:
                uncertain_gain = True
                continue
            perms = set(role.exact)
            if role.universal:
                representative = ("iam.serviceaccounts.getaccesstoken" if "/serviceAccounts/" in node else
                                  "storage.objects.get" if node.startswith("//storage.googleapis.com/") else
                                  ADMIN_PERMS.get(node.split("/", 1)[0]))
                if representative:
                    perms.add(representative)
                else:
                    uncertain_gain = True
            # Catalog keys can contain only this technique when the evaluator is
            # scoped to one rule. Probe known real permissions as well, so a
            # wildcard IAM role still has a concrete gain to compare.
            probes = set(self.catalog_keys) | set(ADMIN_PERMS.values()) | {
                "iam.roles.update", "iam.serviceaccounts.getaccesstoken",
                "storage.objects.get",
            }
            perms.update(perm for perm in probes if role.has(perm))
            if role.patterns and not any(role.has(perm) for perm in probes):
                uncertain_gain = True
            for permission in perms:
                if permission == "cloudidentity.groups.memberships.create":
                    continue
                if self.check(principal, {"action": permission}, node) is None:
                    if condition:
                        uncertain_gain = True
                    else:
                        gain = True
                    break
        if not gain and not uncertain_gain:
            return None
        uncertain = (not membership_known or external_membership_unknown or locked
                     or not (can_manage or can_join) or not gain)
        refs = [{"group": ref, "group_email": email, "whoCanJoin": settings[0] if settings else None}]
        refs.extend(dict(grant_ref) for _, _, _, grant_ref in grants[:2])
        return Grant("unknown" if uncertain else "conditional", refs,
                     ("group_membership_or_permission_gain_unresolved",) if uncertain else
                     ("group_membership_would_add_iam_permission",))

    def blocker_verdict(self, blocker, source, compiled, pivots=None, reached=None, cset=None):
        if blocker == "disabled_service_account":
            if cset is None:
                return None
            verdicts = {}
            for tid in (reached if isinstance(reached, dict) else cset.members):
                node = cset.members.get(tid)
                if node is None or node.kind != "gcp_service_account":
                    continue
                if not node.attrs.get("disabled"):
                    verdicts[tid] = "clear"
                    continue
                can_enable = self.check(source, {"action": "iam.serviceAccounts.enable"},
                                        node.attrs.get("resource") or node.id)
                verdicts[tid] = (("possibly_blocked", "service account is disabled; source may be able to enable it")
                                 if can_enable else ("blocked", "service account is disabled"))
            return verdicts
        if blocker == "vpc_sc_perimeter":
            return self._perimeter_verdict(source, reached, cset)
        if blocker != "org_policy_constraint":
            return super().blocker_verdict(blocker, source, compiled, pivots=pivots, reached=reached, cset=cset)
        if compiled["entry"].get("id") == "gcp-apikeys-authorization-key-bound-sa" and cset is not None:
            target_ids = reached if isinstance(reached, dict) else cset.members
            verdicts = {}
            for tid in target_ids:
                node = cset.members.get(tid)
                if node is None or node.kind != "gcp_verified_authority":
                    continue
                project = node.attrs.get("project") or node.scope
                verdicts[tid] = self._authorization_key_policy(project, source)
            return verdicts
        if compiled["entry"].get("id") == "gcp-iam-serviceaccounts-setiampolicy" and cset is not None:
            target_ids = reached if isinstance(reached, dict) else cset.members
            verdicts = {}
            statuses = inventory_status(self.snapshot, "org_policy_effective")
            constraints = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}
            for tid in target_ids:
                node = cset.members.get(tid)
                if node is None or node.kind != "gcp_service_account":
                    continue
                project = node.attrs.get("project") or node.scope
                if statuses.get(project) not in ("collected", "empty"):
                    verdicts[tid] = ("possibly_blocked", "effective IAM member policy was not collected")
                    continue
                rows = [row for scope, row in items(self.snapshot, "org_policy_effective")
                        if self._norm_scope(scope) == project and row.get("constraint") in constraints]
                verdicts[tid] = (("possibly_blocked", "effective IAM member policy may restrict the new binding")
                                 if rows else "clear")
            return verdicts
        # Only the external SA key technique has boolean policy semantics.
        # Other org-policy constraints need their own semantics.
        if compiled["entry"].get("id") != "gcp-iam-serviceaccountkeys-create" or cset is None:
            return None
        target_ids = reached if isinstance(reached, dict) else cset.members
        verdicts = {}
        for tid in target_ids:
            node = cset.members.get(tid)
            if node is None or node.kind != "gcp_service_account":
                continue
            project = node.attrs.get("project") or node.scope
            creation = self._sa_key_policy(project, "iam.managed.disableServiceAccountKeyCreation",
                                           "iam.disableServiceAccountKeyCreation")
            upload = self._sa_key_policy(project, "iam.managed.disableServiceAccountKeyUpload",
                                         "iam.disableServiceAccountKeyUpload")
            if creation is False or upload is False:
                verdicts[tid] = "clear"
            elif creation is True and upload is True:
                # A principal able to edit the project policy might lift the
                # restriction. Keep that path visible, but do not claim it works now.
                can_edit = self.check(source, {"action": "orgpolicy.policy.set"}, project)
                verdicts[tid] = (("possibly_blocked", "both service-account key policies are enforced; "
                                  "source may be able to change the project policy") if can_edit else
                                 ("blocked", "both service-account key creation and upload are disabled"))
            else:
                verdicts[tid] = ("possibly_blocked", "effective service-account key policy is incomplete or conditional")
        return verdicts

    def _authorization_key_policy(self, project, source):
        """Block only a policy that explicitly allows no authorization-key API."""
        status = inventory_status(self.snapshot, "org_policy_effective").get(project)
        if status not in ("collected", "empty"):
            return ("possibly_blocked", "effective authorization-key policy was not collected")
        rows = [row for scope, row in items(self.snapshot, "org_policy_effective")
                if self._norm_scope(scope) == project
                and row.get("constraint") == "iam.managed.disableServiceAccountApiKeyCreation"]
        if not rows:
            # Google's managed default permits Gemini-only authorization keys.
            return "clear"
        if len(rows) != 1:
            return ("possibly_blocked", "effective authorization-key policy is ambiguous")
        spec = rows[0].get("spec")
        rules = spec.get("rules") if isinstance(spec, dict) else None
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            return ("possibly_blocked", "effective authorization-key policy is conditional or incomplete")
        rule = rules[0]
        if "condition" in rule or type(rule.get("enforce")) is not bool:
            return ("possibly_blocked", "effective authorization-key policy is conditional or incomplete")
        if rule["enforce"] is False:
            return "clear"
        parameters = rule.get("parameters")
        allowed = parameters.get("allowedServices") if isinstance(parameters, dict) else None
        if allowed == []:
            can_edit = self.check(source, {"action": "orgpolicy.policy.set"}, project)
            return (("possibly_blocked", "authorization-key services are blocked, but the source may change policy")
                    if can_edit else ("blocked", "authorization-key policy allows no API service"))
        if isinstance(allowed, list) and any(service in allowed for service in
                                             ("generativelanguage.googleapis.com", "aiplatform.googleapis.com")):
            return "clear"
        return ("possibly_blocked", "authorization-key policy does not confirm a supported API service")

    def _perimeter_verdict(self, source, reached, cset):
        """Preserve possible paths when the request's VPC SC context is unknown."""
        if cset is None:
            return ("possibly_blocked", "VPC Service Controls context is unavailable")
        target_ids = reached if isinstance(reached, dict) else cset.members
        verdicts = {}
        statuses = inventory_status(self.snapshot, "service_perimeter")
        rows_by_scope = {}
        for row_scope, row in items(self.snapshot, "service_perimeter"):
            rows_by_scope.setdefault(self._norm_scope(row_scope), []).append(row)
        for tid in target_ids:
            node = cset.members.get(tid)
            if node is None:
                continue
            project = node.attrs.get("project") or node.scope
            if not str(project).startswith("projects/"):
                project = source.scope
            unknown, active = False, False
            # A technique may call an API in the source's project while using a
            # service account in another project. Each collection lists every
            # perimeter in its organization; inspect both organizations.
            for scope in {project, source.scope}:
                if not str(scope).startswith("projects/"):
                    unknown = True
                    continue
                status = statuses.get(scope)
                if status not in ("collected", "empty"):
                    unknown = True
                    continue
                if status == "empty":
                    continue
                for row in rows_by_scope.get(scope, ()):
                    enforced = row.get("status")
                    if not isinstance(enforced, dict):
                        unknown = True
                        continue
                    resources = enforced.get("resources")
                    restricted = enforced.get("restrictedServices")
                    if not isinstance(resources, list) or not isinstance(restricted, list):
                        unknown = True
                        continue
                    if resources and restricted:
                        active = True
            verdicts[tid] = (("possibly_blocked", "an enforced VPC Service Controls perimeter exists; "
                              "the API request context is not known") if active else
                             ("possibly_blocked", "VPC Service Controls configuration is incomplete") if unknown else
                             "clear")
        return verdicts

    def _sa_key_policy(self, project, managed, legacy):
        """True/False for a definite effective boolean rule, None if unknown."""
        status = inventory_status(self.snapshot, "org_policy_effective").get(project)
        if status not in ("collected", "empty"):
            return None
        rows = [item for scope, item in items(self.snapshot, "org_policy_effective")
                if self._norm_scope(scope) == project and item.get("constraint") in (managed, legacy)]
        for name in (managed, legacy):
            matching = [row for row in rows if row.get("constraint") == name]
            if len(matching) > 1:
                return None
            if not matching:
                continue
            spec = matching[0].get("spec")
            if not isinstance(spec, dict) or not isinstance(spec.get("rules"), list):
                return None
            rules = spec["rules"]
            if not rules:
                continue
            if len(rules) != 1 or not isinstance(rules[0], dict) or "condition" in rules[0] or \
                    type(rules[0].get("enforce")) is not bool or set(rules[0]) - {"enforce"}:
                return None
            return rules[0]["enforce"]
        return None

    def _effective_boolean_policy(self, project, constraint):
        if inventory_status(self.snapshot, "org_policy_effective").get(project) not in ("collected", "empty"):
            return None
        rows = [row for scope, row in items(self.snapshot, "org_policy_effective")
                if self._norm_scope(scope) == project and row.get("constraint") == constraint]
        if len(rows) != 1:
            return None
        spec = rows[0].get("spec")
        rules = spec.get("rules") if isinstance(spec, dict) else None
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            return None
        rule = rules[0]
        if "condition" in rule or type(rule.get("enforce")) is not bool or set(rule) - {"enforce"}:
            return None
        return rule["enforce"]

    def _run_job_create_execute_access(self, source, project):
        """A new job inherits both grants only when they cover the same project."""
        ancestors = set(self.ancestors(project))
        grants = []
        for action in ("run.jobs.create", "run.jobs.run"):
            holders = self.holders(source, action.lower())
            if not ancestors.intersection(holders):
                return None
            grants.append(self.check(source, {"action": action}, project))
        if any(grant is None or grant.confidence == "unknown" for grant in grants):
            return "unknown", "job_grant_condition_on_future_resource_unresolved"
        status = {self._norm_scope(scope): state for scope, state in
                  inventory_status(self.snapshot, "service_usage").items()}
        if status.get(project) not in ("collected", "empty"):
            return "unknown", "cloud_run_api_state_unresolved"
        states = [item.get("state") for scope, item in items(self.snapshot, "service_usage")
                  if self._norm_scope(scope) == project and
                  self._norm_scope(item.get("name")) == f"{project}/services/run.googleapis.com"]
        if len(states) > 1 or len(states) == 1 and states[0] not in ("ENABLED", "DISABLED"):
            return "unknown", "cloud_run_api_state_unresolved"
        if not states or states[0] == "DISABLED":
            if self.check(source, {"action": "serviceusage.services.enable"}, project):
                return "unknown", "cloud_run_api_must_be_enabled"
            return None
        if any(grant.confidence != "derived" for grant in grants):
            return "conditional", "job_grants_conditional"
        return "derived", "same_project_job_create_and_execute"

    def _run_service_create_access(self, source, project):
        """A new service needs a project create grant and an enabled Run API."""
        if not set(self.ancestors(project)).intersection(self.holders(source, "run.services.create")):
            return None
        create = self.check(source, {"action": "run.services.create"}, project)
        if create is None or create.confidence == "unknown":
            return "unknown", "service_create_grant_on_future_resource_unresolved"
        status = {self._norm_scope(scope): state for scope, state in
                  inventory_status(self.snapshot, "service_usage").items()}
        if status.get(project) not in ("collected", "empty"):
            return "unknown", "cloud_run_api_state_unresolved"
        states = [item.get("state") for scope, item in items(self.snapshot, "service_usage")
                  if self._norm_scope(scope) == project and
                  self._norm_scope(item.get("name")) == f"{project}/services/run.googleapis.com"]
        if len(states) > 1 or len(states) == 1 and states[0] not in ("ENABLED", "DISABLED"):
            return "unknown", "cloud_run_api_state_unresolved"
        if not states or states[0] == "DISABLED":
            if self.check(source, {"action": "serviceusage.services.enable"}, project):
                return "unknown", "cloud_run_api_must_be_enabled"
            return None
        return (("derived", "same_project_service_create") if create.confidence == "derived"
                else ("conditional", "service_create_grant_conditional"))

    @staticmethod
    def _run_job_override_accepts_code(item):
        """Only recorded interpreter commands whose args can become source code."""
        task = ((item.get("template") or {}).get("template") or {})
        containers = task.get("containers")
        if not isinstance(containers, list):
            return False
        interpreters = {"sh", "bash", "dash", "ash", "zsh", "ksh",
                        "python", "python3", "pypy", "pypy3", "node", "nodejs",
                        "ruby", "perl", "php"}
        flags = {"sh": {"-c", "-lc"}, "bash": {"-c", "-lc"},
                 "dash": {"-c"}, "ash": {"-c"}, "zsh": {"-c", "-lc"},
                 "ksh": {"-c", "-lc"}, "python": {"-c"}, "python3": {"-c"},
                 "pypy": {"-c"}, "pypy3": {"-c"}, "node": {"-e", "--eval"},
                 "nodejs": {"-e", "--eval"}, "ruby": {"-e"},
                 "perl": {"-e"}, "php": {"-r"}}
        for container in containers:
            if not isinstance(container, dict):
                continue
            command = container.get("command")
            if not isinstance(command, list) or not command or not all(
                    isinstance(part, str) and part for part in command):
                continue
            parts = list(command)
            if parts[0].rsplit("/", 1)[-1] == "env" and len(parts) == 2:
                parts = parts[1:]
            name = parts[0].rsplit("/", 1)[-1]
            if name not in interpreters:
                continue
            if len(parts) == 1 or len(parts) == 2 and parts[1] in flags[name]:
                return True
        return False

    def _run_job_policy_grant_path(self, source, target, resource, item, authority):
        """A job policy self-grant must add an executable path on that job."""
        project = resource.split("/locations/", 1)[0]
        if target.attrs.get("disabled"):
            return None
        if authority.confidence != "derived":
            return "unknown", "cloud_run_job_policy_write_unresolved"
        policy = item.get("iamPolicy")
        if (((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status") != "collected"
                or not isinstance(policy, dict) or not isinstance(policy.get("bindings"), list)
                or any(not isinstance(binding, dict)
                       or not isinstance(binding.get("role"), str)
                       or not isinstance(binding.get("members"), list)
                       for binding in policy["bindings"])):
            return "unknown", "cloud_run_job_policy_unresolved"
        if ((item.get("terminalCondition") or {}).get("state") != "CONDITION_SUCCEEDED"
                or item.get("reconciling") is not False
                or (item.get("generation") and item.get("observedGeneration")
                    and item["generation"] != item["observedGeneration"])):
            return "unknown", "cloud_run_job_readiness_unresolved"
        member_constraints = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}
        org_status = inventory_status(self.snapshot, "org_policy_effective").get(project)
        constrained = any(self._norm_scope(scope) == project and row.get("constraint") in member_constraints
                          for scope, row in items(self.snapshot, "org_policy_effective"))
        if org_status not in ("collected", "empty") or constrained:
            return "unknown", "cloud_run_job_member_policy_unresolved"
        ancestors = [scope for scope in self.ancestors(resource)
                     if scope.startswith(("projects/", "folders/", "organizations/"))
                     and scope.count("/") == 1]
        boundary_scopes = set(ancestors)
        if source.kind == "gcp_service_account":
            home = source.attrs.get("project") or source.scope
            if isinstance(home, str) and home.startswith("projects/"):
                boundary_scopes.update(scope for scope in self.ancestors(home)
                                       if scope.startswith(("projects/", "folders/", "organizations/"))
                                       and scope.count("/") == 1)
        if (any(self.deny_status.get(scope) not in ("collected", "empty") for scope in ancestors)
                or any(self.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                       or self.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                       for scope in ancestors)
                or any(inventory_status(self.snapshot, "policy_binding").get(scope)
                       not in ("collected", "empty") for scope in boundary_scopes)
                or any(row.get("policyKind") == "PRINCIPAL_ACCESS_BOUNDARY"
                       for scope, row in items(self.snapshot, "policy_binding")
                       if self._norm_scope(scope) in boundary_scopes)):
            return "unknown", "cloud_run_job_policy_boundary_unresolved"

        paths = []
        if self._run_job_override_accepts_code(item):
            paths.append(("roles/run.jobsExecutorWithOverrides",
                          ("run.jobs.run", "run.jobs.runWithOverrides"),
                          "self_granted_cloud_run_job_override"))
        service_account = target.attrs.get("resource") or target.id
        act_as = self.check(source, {"action": "iam.serviceAccounts.actAs"}, service_account)
        if act_as is not None and act_as.confidence == "derived":
            paths.append(("roles/run.developer", ("run.jobs.update", "run.jobs.run"),
                          "self_granted_cloud_run_job_update_and_run"))
        uncertain = (not self._run_job_override_accepts_code(item)
                     or act_as is not None and act_as.confidence != "derived")
        for role_name, actions, reason in paths:
            role = self.roles.get(role_name)
            rows = [row for scope, row in items(self.snapshot, "iam_role_builtin")
                    if self._norm_scope(scope) == project and row.get("name") == role_name]
            if (inventory_status(self.snapshot, "iam_role_builtin").get(project) != "collected"
                    or len(rows) != 1 or role is None or role.confidence != "derived"
                    or not all(role.has(action.lower()) for action in actions)):
                uncertain = True
                continue
            prior = [self.check(source, {"action": action}, resource) for action in actions]
            if all(grant is not None and grant.confidence == "derived" for grant in prior):
                continue
            if any(grant is not None and grant.confidence != "derived" for grant in prior):
                uncertain = True
                continue
            missing = [action for action, grant in zip(actions, prior) if grant is None]
            denied = [self._deny(source, action, resource, Grant()) for action in missing]
            if any(grant is None for grant in denied):
                continue
            if any(grant.confidence != "derived" for grant in denied):
                uncertain = True
                continue
            return "conditional", reason
        if uncertain:
            return "unknown", "cloud_run_job_self_grant_path_unresolved"
        return None

    def _run_service_policy_update_path(self, source, target, resource, item, authority,
                                        update_action="run.services.update"):
        """Cloud Run policy control is useful only when it adds update authority."""
        if target.attrs.get("disabled"):
            return None
        if authority.confidence != "derived":
            return "unknown", "cloud_run_service_policy_write_unresolved"
        policy = item.get("iamPolicy")
        if (((item.get("_coverage") or {}).get("iamPolicy") or {}).get("status") != "collected"
                or not isinstance(policy, dict) or not isinstance(policy.get("bindings"), list)
                or any(not isinstance(binding, dict)
                       or not isinstance(binding.get("role"), str)
                       or not isinstance(binding.get("members"), list)
                       for binding in policy["bindings"])):
            return "unknown", "cloud_run_service_policy_unresolved"
        if ((item.get("terminalCondition") or {}).get("state") != "CONDITION_SUCCEEDED"
                or item.get("reconciling") is not False
                or (item.get("latestReadyRevision") and item.get("latestCreatedRevision")
                    and item["latestReadyRevision"] != item["latestCreatedRevision"])):
            return "unknown", "cloud_run_service_readiness_unresolved"
        project = resource.split("/locations/", 1)[0]
        member_constraints = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}
        org_status = inventory_status(self.snapshot, "org_policy_effective").get(project)
        constrained = any(self._norm_scope(scope) == project and row.get("constraint") in member_constraints
                          for scope, row in items(self.snapshot, "org_policy_effective"))
        ancestors = [scope for scope in self.ancestors(resource)
                     if scope.startswith(("projects/", "folders/", "organizations/"))
                     and scope.count("/") == 1]
        boundaries = set(ancestors)
        if source.kind == "gcp_service_account":
            home = source.attrs.get("project") or source.scope
            if isinstance(home, str) and home.startswith("projects/"):
                boundaries.update(scope for scope in self.ancestors(home)
                                  if scope.startswith(("projects/", "folders/", "organizations/"))
                                  and scope.count("/") == 1)
        if (org_status not in ("collected", "empty") or constrained
                or any(self.iam_policy_inventory_status.get(scope) not in ("collected", "empty")
                       or self.iam_role_inventory_status.get(scope) not in ("collected", "empty")
                       or self.deny_status.get(scope) not in ("collected", "empty")
                       for scope in ancestors)
                or any(inventory_status(self.snapshot, "policy_binding").get(scope)
                       not in ("collected", "empty") for scope in boundaries)
                or any(row.get("policyKind") == "PRINCIPAL_ACCESS_BOUNDARY"
                       for scope, row in items(self.snapshot, "policy_binding")
                       if self._norm_scope(scope) in boundaries)):
            return "unknown", "cloud_run_service_self_grant_guardrail_unresolved"
        role_name = "roles/run.developer"
        rows = [row for scope, row in items(self.snapshot, "iam_role_builtin")
                if self._norm_scope(scope) == project and row.get("name") == role_name]
        role = self.roles.get(role_name)
        if (inventory_status(self.snapshot, "iam_role_builtin").get(project) != "collected"
                or len(rows) != 1 or role is None or role.confidence != "derived"
                or not role.has(update_action)):
            return "unknown", "cloud_run_developer_role_unresolved"
        prior = self.check(source, {"action": update_action}, resource)
        if prior is not None:
            return ("unknown", "cloud_run_service_prior_update_unresolved") if prior.confidence != "derived" else None
        denied = self._deny(source, update_action, resource, Grant())
        if denied is None:
            return None
        if denied.confidence != "derived":
            return "unknown", "cloud_run_service_update_deny_unresolved"
        return "conditional", "self_granted_cloud_run_service_update"

    def _run_instance_deploy_access(self, source, project):
        """Return the strongest supported create or exact-instance update path."""
        create = self.check(source, {"action": "run.instances.create"}, project)
        if create and create.confidence == "derived":
            return "derived", "instance_create_with_target_identity"
        unresolved = bool(create) or self.host_status.get((project, "cloudrun_instance")) not in (
            "collected", "empty")
        conditional = create is not None and create.confidence == "conditional"
        for resource, _, item in self.run_instances_by_project.get(project, ()):
            if item.get("deleteTime"):
                continue
            update = self.check(source, {"action": "run.instances.update"}, resource)
            if update is None:
                continue
            if update.confidence == "unknown":
                unresolved = True
                continue
            condition = item.get("terminalCondition") or {}
            ready = (condition.get("state") == "CONDITION_SUCCEEDED" and
                     item.get("reconciling") is False)
            if ready:
                if update.confidence == "derived":
                    return "derived", "ready_instance_update_with_target_identity"
                conditional = True
                continue
            start = self.check(source, {"action": "run.instances.start"}, resource)
            if start and start.confidence in ("derived", "conditional"):
                if start.confidence == update.confidence == "derived":
                    return "derived", "instance_update_and_start_with_target_identity"
                conditional = True
            else:
                unresolved = True
        if conditional:
            return "conditional", "instance_deploy_grant_conditional"
        if unresolved:
            return "unknown", "instance_inventory_state_or_grant_unresolved"
        return None

    def _cross_project_sa_attachment(self, candidates, source, permissions, agent_domain, mechanism):
        projects = sorted({self._norm_scope(item.get("projectId") and f"projects/{item['projectId']}" or scope)
                           for scope, item in items(self.snapshot, "project")})
        numbers = {f"projects/{project_id}": number for number, project_id in self.project_alias.items()}
        hosts = []
        for project in projects:
            if mechanism in ("run_instance", "run_job", "run_service"):
                access = (self._run_instance_deploy_access(source, project)
                          if mechanism == "run_instance" else
                          self._run_job_create_execute_access(source, project)
                          if mechanism == "run_job" else
                          self._run_service_create_access(source, project))
                if access is not None:
                    hosts.append((project, access[0] == "derived"))
            else:
                grants = [self.check(source, {"action": action}, project) for action in permissions]
                if all(grant is not None for grant in grants):
                    hosts.append((project, all(grant.confidence == "derived" for grant in grants)))
        usage_status = {self._norm_scope(scope): state for scope, state in
                        inventory_status(self.snapshot, "service_usage").items()}
        cloudbuild_service = {}
        if mechanism == "cloudbuild":
            for scope, item in items(self.snapshot, "service_usage"):
                project = self._norm_scope(scope)
                name = item.get("name")
                if isinstance(name, str) and self._norm_scope(name) == f"{project}/services/cloudbuild.googleapis.com":
                    cloudbuild_service.setdefault(project, []).append(item.get("state"))
        out = {}
        for tid, target in candidates.items():
            target_project = target.attrs.get("project") or target.scope
            if not str(target_project).startswith("projects/"):
                continue
            if target.attrs.get("disabled"):
                # A disabled SA cannot authenticate. Re-enabling it is a
                # separate action, so keep only an unresolved path if the
                # source can perform that action.
                if any(host != target_project for host, _ in hosts) and self.check(
                        source, {"action": "iam.serviceAccounts.enable"}, target.attrs.get("resource")):
                    out[tid] = ("unknown", "target_service_account_must_be_enabled")
                continue
            policy = self._effective_boolean_policy(target_project, "iam.disableCrossProjectServiceAccountUsage")
            unknown = False
            for host_project, host_grants_derived in hosts:
                if host_project == target_project:
                    continue
                if mechanism == "cloudbuild":
                    states = cloudbuild_service.get(host_project, [])
                    if usage_status.get(host_project) not in ("collected", "empty") or len(states) != 1:
                        unknown = True
                        continue
                    if states[0] == "DISABLED":
                        if self.check(source, {"action": "serviceusage.services.enable"}, host_project):
                            unknown = True
                        continue
                    if states[0] != "ENABLED":
                        unknown = True
                        continue
                if policy is True:
                    if self.check(source, {"action": "orgpolicy.policy.set"}, target_project):
                        unknown = True
                    continue
                if policy is None:
                    unknown = True
                    continue
                number = numbers.get(host_project)
                if not number:
                    unknown = True
                    continue
                email = f"service-{number}@{agent_domain}"
                agent = self.principals.get("serviceAccount:" + email)
                if agent is None:
                    unknown = True
                    continue
                token = self.check(agent, {"action": "iam.serviceAccounts.getAccessToken"},
                                   target.attrs.get("resource") or f"{target_project}/serviceAccounts/{target.attrs.get('email')}")
                if token is None:
                    unknown = True
                    continue
                if not host_grants_derived or token.confidence != "derived":
                    unknown = True
                    continue
                out[tid] = ("conditional", f"cross_project_{mechanism}_service_agent_token_access")
                break
            else:
                if unknown and any(host != target_project for host, _ in hosts):
                    out[tid] = ("unknown", f"cross_project_{mechanism}_attachment_guardrails_unresolved")
        return out

    def _conditioned(self, entry, ref):
        """Grant at one node for a resource, evaluating resource-dependent binding conditions against it."""
        found, listed = entry
        sa = self.sa_by_resource.get(ref)
        aliases = []
        if sa is not None and sa.attrs.get("unique_id"):
            aliases.append(ref.split("/serviceAccounts/", 1)[0] + "/serviceAccounts/" + str(sa.attrs["unique_id"]))
        if str(ref).startswith("projects/"):
            pid = str(ref).split("/")[1]
            aliases += [ref.replace(f"projects/{pid}", f"projects/{n}", 1) for n, p in self.project_alias.items() if p == pid]
        datafusion = any(ref == name or ref.startswith(name + "/namespaces/")
                         for name in self.datafusion_instances)
        ctx = cel.resource_context(ref, aliases, attributes_available=not datafusion)
        for expression, if_true, undecided in listed:
            verdict = cel.evaluate(expression, ctx)
            if verdict is False:
                continue
            found = best(found, if_true if verdict else undecided)
        return found

    def check_targets(self, principal, req, template, candidates, localized=False):
        perm = self.requirement_key(req)
        if perm == "cloudidentity.groups.memberships.create":
            return super().check_targets(principal, req, template, candidates, localized)
        held = self.holders(principal, perm)
        if not held:
            return {}
        # When the permission is not granted on individual resources, a target's own-resource requirement
        # depends only on its parent scope: evaluate once per scope (not when a binding condition names resources).
        own = not self._resdep.get((principal.perm_key, perm)) and (localized or template in ("{target.email}", "{target.id}", "{target.resource}"))
        resource_grants = {n for n in held if "/serviceAccounts/" in n or n.startswith("//")} if own else None
        # These templates name only the target. Reuse their resolution across
        # sources, and reject a pair only when no grant node is an ancestor of
        # any resolved resource. Exact checks still handle conditions and deny
        # policies for every pair that could match. Missing placeholders (ANY)
        # must stay in the ordinary evaluation path.
        target_only = localized or template in ("{target.email}", "{target.id}", "{target.resource}")
        resolved = self.__dict__.setdefault("_target_resolution_cache", {}) if target_only else None
        result, memo, single, total = {}, {}, None, 0
        for target in candidates:
            total += 1
            key = None
            if own and target.attrs.get("resource") not in resource_grants:
                key = target.scope
                if key in memo:
                    if memo[key] is not None:
                        result[target.id] = memo[key]
                    continue
            if target_only:
                signature = (localized, template, target.id, target.kind, target.scope, target.entity,
                             target.attrs.get("resource"), target.attrs.get("email"))
                cached = resolved.get(signature)
                if cached is None:
                    refs, floor = self.resolve(template, principal, target) if not localized else ([self.localize(req, target)], None)
                    ancestors = None if ANY in refs else frozenset(node for ref in refs for node in self.ancestors(ref))
                    cached = resolved[signature] = (refs, floor, ancestors)
                refs, floor, ancestors = cached
                if ancestors is not None and ancestors.isdisjoint(held):
                    if key is not None:
                        memo[key] = None
                    continue
            else:
                refs, floor = self.resolve(template, principal, target)
            if refs == [ANY]:
                key = ("any", floor)  # resolution did not depend on this target
                if key in memo:
                    if memo[key] is not None:
                        result[target.id] = memo[key]
                    continue
            grant = None
            for ref in refs:
                got = self.cached_check(principal, req, ref)
                if got is not None and (grant is None or got.confidence == "derived"):
                    grant = got
            if grant is not None:
                grant = downgrade(grant, floor[0], floor[1]) if floor else grant
                result[target.id] = grant
            if key is not None:
                memo[key] = grant
        grants = {id(g) for g in result.values()}
        if result and len(result) == total and len(grants) == 1:
            return AllTargets(next(iter(result.values())))
        return result

    def localize(self, req, target):
        return target.attrs.get("resource") or target.scope

    def placeholder_values(self, name, source, target, pivot=None):
        owner, _, attr = name.partition(".")
        if not attr:
            owner, attr = "source", owner
        node = target if owner == "target" else source
        if node is None:
            return None
        if name == "target.workstation_config":
            email = node.attrs.get("email")
            workstations = self.hosts.get(email, {}).get("workstations_workstation", ())
            configs = sorted({resource.rsplit("/workstations/", 1)[0] for resource in workstations})
            if configs:
                return configs
            return (None if self.host_status.get((node.scope, "workstations_workstation")) not in
                    ("collected", "empty") else [])
        if name == "target.host_resource" and node.attrs.get("host_resource"):
            return [node.attrs["host_resource"]]
        if attr in ("host_resource", "host_resource.content_storage") and owner == "target":
            services = [str(v).lower() for v in as_list((self.current_selector or {}).get("attached_to_service"))]
            hosts = [SERVICE_HOSTS.get(v) for v in services]
            if not hosts or None in hosts:
                return None  # host type not modelled for GCP: unknown
            out = []
            incomplete = False
            for host in hosts:
                email = node.attrs.get("email")
                if host == "instance" and attr == "host_resource":
                    out.extend(self.hosts.get(email, {}).get(host, []))
                    continue
                host_scopes = self.host_projects.get((email, host), ())
                if not host_scopes:
                    if self.host_status.get((node.scope, host)) not in ("collected", "empty"):
                        incomplete = True
                    continue
                if any(self.host_status.get((scope, host)) not in ("collected", "empty")
                       for scope in host_scopes):
                    incomplete = True
                if attr == "host_resource.content_storage":
                    if host == "composer_environment":
                        buckets = self.composer_dag_buckets.get(email, ())
                        if email in self.composer_dag_incomplete and not buckets:
                            return None
                    elif host == "dataproc_cluster":
                        buckets = self.dataproc_init_buckets.get(email, ())
                    elif host == "cloudbuild_build":
                        buckets = self.cloudbuild_source_buckets.get(email, ())
                    else:
                        incomplete = True
                        continue
                    if any(bucket.split("/buckets/", 1)[-1] not in self.bucket_projects for bucket in buckets):
                        incomplete = True
                        continue
                    out.extend(sorted(buckets))
                else:
                    out.extend(self.hosts.get(email, {}).get(host, []))
            return out if out else None if incomplete else []
        if name == "target.cloudbuild_source_object":
            email = node.attrs.get("email")
            objects = self.cloudbuild_source_objects.get(email, ())
            if any(obj.split("/buckets/", 1)[-1].split("/objects/", 1)[0] not in self.bucket_projects
                   for obj in objects):
                return None
            return sorted(objects) if objects else None
        if name == "target.dataproc_init_object":
            email = node.attrs.get("email")
            objects = self.dataproc_init_objects.get(email, ())
            if any(obj.split("/buckets/", 1)[-1].split("/objects/", 1)[0] not in self.bucket_projects
                   for obj in objects):
                return None
            return sorted(objects) if objects else None
        if name == "target.composer_dag_managed_folder":
            email = node.attrs.get("email")
            host_scopes = self.composer_host_projects.get(email, ())
            if not host_scopes or any(self.host_status.get((scope, "composer_environment")) not in ("collected", "empty")
                                      for scope in host_scopes):
                return None
            if email in self.composer_dag_incomplete and not self.composer_dag_buckets.get(email):
                return None
            folder_status = inventory_status(self.snapshot, "managed_folder")
            if any(folder_status.get(self.bucket_projects.get(bucket.split("/buckets/", 1)[-1], ""))
                   not in ("collected", "empty") for bucket in self.composer_dag_buckets.get(email, ())):
                return None
            return sorted(self.composer_dag_folders.get(email, ()))
        if name == "target.osconfig_guest_policy":
            from .gcp_osconfig_guest_policy import policy_resources
            return policy_resources(self, node.scope)
        if name in ("target.osconfig_zone", "target.osconfig_assignment"):
            from .gcp_osconfig_os_policy_assignment import resources
            return resources(self, node, assignments=name.endswith("assignment"))
        if name == "target.osconfig_unknown_assignment":
            return None
        if name == "target.osconfig_patch_deployment":
            from .gcp_osconfig_patch_job import deployment_resources
            return deployment_resources(self, node.scope)
        if name == "target.osconfig_unknown_patch_deployment":
            return None
        if name in ("target.osconfig_orchestrator_parent", "target.osconfig_orchestrator"):
            from .gcp_osconfig_policy_orchestrator import resources
            return resources(self, node.scope, orchestrators=name.endswith("orchestrator"))
        if name == "target.osconfig_unknown_orchestrator":
            return None
        if name == "target.dataproc_init_managed_folder":
            email = node.attrs.get("email")
            host_scopes = self.host_projects.get((email, "dataproc_cluster"), ())
            if not host_scopes or any(self.host_status.get((scope, "dataproc_cluster")) not in ("collected", "empty")
                                      for scope in host_scopes):
                return None
            folder_status = inventory_status(self.snapshot, "managed_folder")
            if any(folder_status.get(self.bucket_projects.get(bucket.split("/buckets/", 1)[-1], ""))
                   not in ("collected", "empty") for bucket in self.dataproc_init_buckets.get(email, ())):
                return None
            return sorted(self.dataproc_init_folders.get(email, ()))
        if attr == "domain_registration" and owner == "target":
            if not any(st in ("collected", "empty") for st in self.registrations_status.values()):
                return None
            customer = self.ws_customer_of_email.get(str(node.attrs.get("email") or "").lower())
            domain = self.ws_customer_domains.get(customer)
            if not domain:
                return None
            return [resource for resource, state in self.registrations.get(domain, ()) if state == "ACTIVE"] or None
        if attr == "image_family_project" and owner == "target":
            return sorted(self.image_families.get(node.attrs.get("email"), ())) or None
        if attr == "policy_resource" and owner == "target" and node.kind == "gcp_verified_authority":
            return [node.attrs["policy_resource"]] if node.attrs.get("policy_resource") else None
        if attr == "quota_project" and owner == "target" and node.kind in ("gcp_external_principal", "gcp_verified_authority"):
            return [node.attrs["quota_project"]] if node.attrs.get("quota_project") else None
        if attr == "artifact_arn" and owner == "target" and node.kind == "gcp_service_account" and (
                "gcp_sourcerepo_trigger_path" in (self.current_selector or {})):
            return sorted({repo for repo, _review in self.sourcerepo_trigger_paths.get(node.attrs.get("email"), ())}) or None
        if attr == "artifact_arn" and owner == "target" and node.kind == "gcp_verified_authority":
            return [node.attrs["artifact_arn"]] if node.attrs.get("artifact_arn") else None
        if attr == "email":
            return [node.attrs["resource"]] if node.attrs.get("resource") else (
                [f"projects/-/serviceAccounts/{node.attrs.get('email')}"] if node.kind == "gcp_service_account" else None)
        if attr in ("scope", "id", "name", "cluster") and node.entity:
            return [node.scope]
        if attr == "cluster" and node.attrs.get("gke_cluster"):
            return [node.attrs["gke_cluster"]]
        if attr in ("namespace", "name") and node.kind == "k8s_service_account" and not node.attrs.get("aggregate"):
            return [node.attrs[attr]]
        if attr in ("project", "scope"):
            return [node.scope]
        if attr in ("arn", "id", "resource"):
            return [node.attrs.get("resource") or node.id]
        return None

    def resolve(self, template, source, target, pivot=None):
        import re as _re
        if template is None:
            return [ANY], None
        names = _re.findall(r"(?<!\$)\{([^{}]+)\}", template)
        if not names:
            return [template], None
        refs = [template]
        for name in names:
            if name.startswith("pivot"):
                return [ANY], ("conditional", "pivot_resource_not_verified")
            got = self.placeholder_values(name, source, target)
            if got is None:
                return [ANY], ("unknown", f"placeholder_{name}_not_in_snapshot")
            refs = [r.replace("{" + name + "}", v) for r in refs for v in got]
        # A full template like "{target.email}" resolves to the SA resource itself.
        return [self._norm_scope(r) for r in refs], None

    # ------------------------------------------------------------- sources
    def source_matches(self, source, kinds, selector):
        if not super().source_matches(source, kinds, selector):
            return False
        if source.kind == "gcp_service_account" and source.attrs.get("disabled"):
            return False
        wanted = (selector or {}).get("gcp_workspace_admin_role")
        if wanted is None:
            return True
        if not any(st in ("collected", "empty") for st in self.ws_status.values()):
            if not self.__dict__.get("_ws_noted"):
                self._ws_noted = True
                self.add_coverage("source_selector", "*", "not_collected", "gcp_workspace_admin_role not evaluated",
                                  "Workspace admin techniques (super admin -> organization admin) are not evaluated; needs "
                                  + FACTS_NEEDED["gcp_workspace_admin_role"])
            return False
        roles = self.ws_admin.get(str(source.attrs.get("email") or "").lower(), set())
        return str(wanted) in roles or str(wanted).lower() in {r.lower() for r in roles}

    def allowed_scopes(self, rule, source):
        if rule == "org" and ((self.current_entry or {}).get("target") or {}).get("kind") == "gcp_scope_owner":
            return {n.scope for n in self.targets("gcp_scope_owner") if n.scope.startswith("organizations/")}
        return None

    # ----------------------------------------------------- related snapshots
    def set_related(self, snapshots):
        """Join K8s snapshots of GKE clusters (KSA targets of container.* techniques)."""
        self.related_k8s = {}
        self._ambiguous_k8s = set()
        for snapshot in snapshots or ():
            if (snapshot or {}).get("provider") != "k8s":
                continue
            clusters = {}
            smeta = snapshot.get("metadata") or {}
            for key in ("cluster_id", "context"):  # snapshot-level ids (items do not always carry one)
                if smeta.get(key):
                    clusters.setdefault(str(smeta[key]), None)
            for kind in ("serviceaccount", "secret_metadata", "secret", "namespace", "pod", "rolebinding", "clusterrolebinding"):
                for _, item in items(snapshot, kind):
                    prov = item.get("provenance") or {}
                    meta = item.get("metadata") or {}
                    cid = str(prov.get("cluster_id") or meta.get("cluster_id") or "")
                    if cid:
                        clusters.setdefault(cid, None)
            for cid in clusters:
                resource = self._match_gke(cid)
                if resource:
                    if resource in self.related_k8s:
                        self.__dict__.setdefault("_ambiguous_k8s", set()).add(resource)
                    else:
                        self.related_k8s[resource] = (cid, snapshot)
        self.__dict__.pop("_ksa_target_cache", None)

    def _gke_origin_digests(self):
        """`k8s-cluster:<sha256(origin)>` ids the K8s collector derives from the API server URL, per GKE cluster
        endpoint (public IP, private endpoint, DNS endpoint)."""
        out = {}
        for resource, item in self.gke.items():
            private = item.get("privateClusterConfig") if isinstance(item.get("privateClusterConfig"), dict) else {}
            dns = ((item.get("controlPlaneEndpointsConfig") or {}).get("dnsEndpointConfig") or {}) \
                if isinstance(item.get("controlPlaneEndpointsConfig"), dict) else {}
            for endpoint in (item.get("endpoint"), private.get("privateEndpoint"), dns.get("endpoint") if isinstance(dns, dict) else None):
                if isinstance(endpoint, str) and endpoint:
                    origin = endpoint.lower().rstrip("/")
                    origin = origin if origin.startswith("https://") else "https://" + origin
                    out.setdefault("k8s-cluster:" + hashlib.sha256(origin.encode()).hexdigest(), set()).add(resource)
        return out

    def _match_gke(self, cluster_id):
        cid = str(cluster_id)
        if cid.startswith("k8s-cluster:"):
            matched = self._gke_origin_digests().get(cid, set())
            return next(iter(matched)) if len(matched) == 1 else None
        if cid.startswith("//container.googleapis.com/"):
            cid = cid[len("//container.googleapis.com/"):]
        if cid.startswith("gke_") and cid.count("_") >= 3:
            _, project, location, name = cid.split("_", 3)
            cid = f"projects/{project}/locations/{location}/clusters/{name}"
        if "/clusters/" in cid:
            cid = self._norm_scope(cid.replace("/zones/", "/locations/"))
            return cid if cid in self.gke else None
        named = [r for r in self.gke if r.rsplit("/", 1)[-1] == cid]
        return named[0] if len(named) == 1 else None

    def _ksa_targets(self, variant):
        cache = self.__dict__.setdefault("_ksa_target_cache", {})
        if variant in cache:
            return cache[variant]
        out = []
        for resource in sorted(self.gke):
            joined = (self.related_k8s or {}).get(resource)
            if variant == "running_pod" and resource in self.__dict__.get("_ambiguous_k8s", ()):
                joined = None
            name = resource.rsplit("/", 1)[-1]
            if joined is None:
                # Every cluster has KSAs (default SAs), but token Secrets are only proven by Secret metadata:
                # the token_secret variant becomes an unresolved placeholder.
                why = ("unknown" if variant in ("token_secret", "running_pod") else "conditional", "k8s_snapshot_not_joined")
                label = (f"KSAs with token Secrets in GKE cluster {name}" if variant == "token_secret"
                         else f"KSAs of GKE cluster {name}")
                out.append(self._ksa_aggregate(variant, resource, label, why))
                continue
            cid, snapshot = joined
            def same_cluster(it):
                return str((it.get("provenance") or {}).get("cluster_id") or
                           (it.get("metadata") or {}).get("cluster_id") or
                           (snapshot.get("metadata") or {}).get("cluster_id") or cid) == cid
            sas = [(it.get("metadata") or {}) for _, it in items(snapshot, "serviceaccount")
                   if same_cluster(it)]
            if variant == "in_cluster":
                sa_status = inventory_status(snapshot, "serviceaccount")
                if not sa_status or unavailable(sa_status):
                    out.append(self._ksa_aggregate(variant, resource, f"KSAs in GKE cluster {name}",
                                                   ("unknown", "k8s_serviceaccount_not_collected")))
                    continue
            if variant == "running_pod":
                statuses = inventory_status(snapshot, "pod")
                sa_status = inventory_status(snapshot, "serviceaccount")
                if not statuses or unavailable(statuses) or not sa_status or unavailable(sa_status):
                    out.append(self._ksa_aggregate(variant, resource, f"Running-pod KSAs in GKE cluster {name}",
                                                   ("unknown", "k8s_pod_or_serviceaccount_not_collected")))
                    continue
                by_sa = {(m.get("namespace"), m.get("name")): it for _, it in items(snapshot, "serviceaccount")
                         for m in [it.get("metadata") or {}] if same_cluster(it) and m.get("namespace") and m.get("name")}
                pairs, unresolved = set(), False
                for _, pod in items(snapshot, "pod"):
                    if not same_cluster(pod):
                        continue
                    phase = (pod.get("status") or {}).get("phase")
                    if phase is None:
                        unresolved = True
                        continue
                    if phase != "Running":
                        continue
                    meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
                    pair = (meta.get("namespace"), spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
                    sa = by_sa.get(pair)
                    if sa is None:
                        unresolved = True
                        continue
                    mounted = spec.get("automountServiceAccountToken")
                    if mounted is None:
                        mounted = sa.get("automountServiceAccountToken")
                    if mounted is not None and not isinstance(mounted, bool):
                        unresolved = True
                        continue
                    if mounted is False:
                        projected = {v.get("name") for v in (spec.get("volumes") or ()) if isinstance(v, dict)
                                     and any(isinstance(src.get("serviceAccountToken"), dict)
                                             and src["serviceAccountToken"].get("path") for src in
                                             ((v.get("projected") or {}).get("sources") or ()) if isinstance(src, dict))}
                        containers = list(spec.get("containers") or ())
                        if not any(m.get("name") in projected and m.get("mountPath")
                                   for c in containers if isinstance(c, dict)
                                   for m in (c.get("volumeMounts") or ()) if isinstance(m, dict)):
                            continue
                    pairs.add(pair)
                if unresolved:
                    out.append(self._ksa_aggregate(variant, resource, f"Running-pod KSAs in GKE cluster {name}",
                                                   ("unknown", "running_pod_serviceaccount_unresolved")))
                pairs = sorted(pairs)
            elif variant == "token_secret":
                # The K8s collector emits Secret metadata only, as `secret_metadata` (`secret` kept for older snapshots).
                secret_kind = "secret_metadata" if inventory_status(snapshot, "secret_metadata") else "secret"
                statuses = inventory_status(snapshot, secret_kind)
                if not statuses or unavailable(statuses):
                    out.append(self._ksa_aggregate(variant, resource, f"KSAs with token Secrets in GKE cluster {name}",
                                                   ("unknown", "k8s_secret_metadata_not_collected")))
                    continue
                refs = set()
                for _, it in items(snapshot, secret_kind):
                    meta = it.get("metadata") or {}
                    if it.get("type") != "kubernetes.io/service-account-token":
                        continue
                    sa_name = (meta.get("annotations") or {}).get("kubernetes.io/service-account.name")
                    if sa_name and meta.get("namespace"):
                        refs.add((meta["namespace"], sa_name))
                pairs = sorted(refs)
            else:
                pairs = sorted({(m.get("namespace"), m.get("name")) for m in sas if m.get("namespace") and m.get("name")})
            for ns, sa_name in pairs:
                out.append(Node(f"k8s:{cid}:sa:{ns}:{sa_name}", "k8s_service_account", "k8s", resource, f"{ns}/{sa_name}",
                                attrs={"cluster": cid, "gke_cluster": resource, "namespace": ns, "name": sa_name,
                                       "resource": resource, "floor": None, "related_snapshot": True}))
        cache[variant] = out
        return out

    def _ksa_aggregate(self, variant, resource, label, why):
        return Node(f"gke-ksa:{variant}:{resource}", "k8s_service_account", "k8s", resource, label,
                    attrs={"gke_cluster": resource, "resource": resource, "aggregate": True, "floor": why})

    def target_variant(self, kind, selector):
        if kind == "k8s_service_account":
            if (selector or {}).get("k8s_sa_has_token_secret"):
                return "token_secret"
            if (selector or {}).get("k8s_sa_in_cluster"):
                return "in_cluster"
            if (selector or {}).get("k8s_sa_used_by_running_pod"):
                return "running_pod"
        return None

    def _table_key_fact_bound(self, technique, target, scope, fact):
        """Require one exact table and one inventoried SA key subject, never token-shaped text."""
        permission, parent_kind = _EXACT_TABLE_KEY_PERMISSIONS[technique]
        resource = fact.get("CredentialResource")
        return (fact.get("TargetKind") == "gcp_service_account"
                and fact.get("TargetId") == target
                and fact.get("TargetScope") == scope
                and fact.get("CredentialSubjectId") == target
                and fact.get("CredentialKind") == "gcp_service_account_private_key"
                and isinstance(resource, str)
                and bool(re.fullmatch(rf"{re.escape(scope)}/{parent_kind}/[^/]+/tables/[^/]+", resource))
                and str(fact.get("AccessPermission", "")).lower() == permission)

    def targets_for(self, kind, selector):
        if (selector or {}).get("gcp_privatecatalog_dm_iam_path"):
            if kind != "gcp_verified_authority":
                return []
            from .gcp_privatecatalog_dm import candidates
            return list(candidates(self).values())
        if (selector or {}).get("gcp_kcc_project_policy_grant"):
            if kind != "gcp_verified_authority":
                return []
            from .gcp_config_connector import candidates
            return list(candidates(self).values())
        if (selector or {}).get("gcp_bigquery_spark_connection_path"):
            return (list({row["identity"].id: row["identity"] for row in
                          self.spark_connections.values()}.values())
                    if kind == "gcp_service_account" else [])
        if ((selector or {}).get("gcp_agentidentity_retrieve_path")
                or (selector or {}).get("gcp_agentidentity_update_path")):
            return (list(self.agentidentity_authorization_targets.values())
                    if kind == "gcp_verified_authority" else [])
        workspace_mechanism = (selector or {}).get("gcp_bounded_workspace_oauth")
        if workspace_mechanism:
            if kind != "gcp_verified_authority":
                return []
            return [Node(f"gcp_verified_authority:workspace_oauth:{workspace_mechanism}:{user.id}",
                         kind, "gcp", user.scope,
                         f"{workspace_mechanism} OAuth access as {user.attrs['email']}",
                         attrs={"resource": user.id, "scope": user.scope, "email": user.attrs["email"]},
                         entity=True)
                    for user in self.principals.values() if user.kind == "gcp_user"]
        mechanism = (selector or {}).get("gcp_bounded_service_execution")
        if mechanism:
            if kind != "gcp_verified_authority":
                return []
            return [Node(f"gcp_verified_authority:{mechanism}:{sa.id}", kind, "gcp", sa.scope,
                         f"{mechanism.replace('_', ' ')} access as {sa.attrs['email']}",
                         attrs={"resource": sa.attrs["resource"], "scope": sa.scope,
                                "project": sa.attrs.get("project"), "email": sa.attrs["email"]},
                         entity=True)
                    for sa in self.sas.values() if not sa.attrs.get("disabled")]
        if (selector or {}).get("gcp_hmac_storage_identity"):
            if kind != "gcp_verified_authority":
                return []
            return [Node(f"gcp_verified_authority:hmac:{sa.id}", kind, "gcp", sa.scope,
                         f"Cloud Storage HMAC access as {sa.attrs['email']}",
                         attrs={"resource": sa.attrs["resource"], "scope": sa.scope,
                                "project": sa.attrs.get("project"), "email": sa.attrs["email"]},
                         entity=True)
                    for sa in self.sas.values() if not sa.attrs.get("disabled")]
        if (selector or {}).get("gcp_external_principal_evidence"):
            return list(self.external_principal_targets.values()) if kind == "gcp_external_principal" else []
        if (selector or {}).get("gcp_agentregistry_skill_evidence"):
            return list(self.agentregistry_skill_targets.values()) if kind == "gcp_verified_authority" else []
        if (selector or {}).get("gcp_resource_self_grant"):
            if kind != "gcp_verified_authority":
                return []
            targets = list(self.resource_self_grant_targets.values())
            if (self.current_entry or {}).get("id") == "gcp-secretmanager-secrets-setiampolicy-secret-self-grant":
                targets.extend(self.secret_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-domains-registrations-setiampolicy-self-grant":
                from .gcp_resource_self_grant import domains_registration_candidates
                targets.extend(domains_registration_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-gkehub-memberships-setiampolicy-membership-self-grant":
                from .gcp_resource_self_grant import fleet_membership_candidates
                targets.extend(fleet_membership_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-healthcare-consentstores-setiampolicy-consent-store-self-grant":
                from .gcp_resource_self_grant import healthcare_consent_store_candidates
                targets.extend(healthcare_consent_store_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-healthcare-datasets-setiampolicy-dataset-self-grant":
                from .gcp_resource_self_grant import healthcare_dataset_fhir_candidates
                targets.extend(healthcare_dataset_fhir_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-healthcare-dicomstores-setiampolicy-dicom-store-self-grant":
                from .gcp_resource_self_grant import healthcare_dicom_store_candidates
                targets.extend(healthcare_dicom_store_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-healthcare-fhirstores-setiampolicy-fhir-store-self-grant":
                from .gcp_resource_self_grant import healthcare_fhir_store_candidates
                targets.extend(healthcare_fhir_store_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-healthcare-hl7v2stores-setiampolicy-hl7v2-store-self-grant":
                from .gcp_resource_self_grant import healthcare_hl7v2_store_candidates
                targets.extend(healthcare_hl7v2_store_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-iap-tunnelinstances-setiampolicy-instance-self-grant":
                from .gcp_resource_self_grant import iap_tunnel_instance_candidates
                targets.extend(iap_tunnel_instance_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-iap-tunnelzones-setiampolicy-zone-self-grant":
                from .gcp_resource_self_grant import iap_tunnel_instance_candidates
                targets.extend(iap_tunnel_instance_candidates(self, zone_policy=True).values())
            elif (self.current_entry or {}).get("id") == "gcp-identitytoolkit-tenants-setiampolicy-tenant-self-grant":
                from .gcp_resource_self_grant import identityplatform_tenant_candidates
                targets.extend(identityplatform_tenant_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-krmapihosting-krmapihosts-setiampolicy-krm-api-host-self-grant":
                from .gcp_resource_self_grant import krm_api_host_candidates
                targets.extend(krm_api_host_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-logging-views-setiampolicy-self-grant":
                from .gcp_resource_self_grant import logging_view_candidates
                targets.extend(logging_view_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-resourcemanager-folders-setiampolicy":
                from .gcp_resource_self_grant import folder_candidates
                targets.extend(folder_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-resourcemanager-organizations-setiampolicy":
                from .gcp_resource_self_grant import organization_candidates
                targets.extend(organization_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-resourcemanager-organizations-setiampolicy-deny-admin":
                from .gcp_resource_self_grant import organization_candidates
                targets.extend(organization_candidates(self, deny_admin=True).values())
            elif (self.current_entry or {}).get("id") == "gcp-resourcemanager-organizations-setiampolicy-role-admin":
                from .gcp_resource_self_grant import organization_candidates
                targets.extend(organization_candidates(self, role_admin=True).values())
            elif (self.current_entry or {}).get("id") == "gcp-resourcemanager-projects-setiampolicy":
                from .gcp_resource_self_grant import project_candidates
                targets.extend(project_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-resourcemanager-projects-setiampolicy-project-delete":
                from .gcp_resource_self_grant import project_candidates
                targets.extend(project_candidates(self, deleter=True).values())
            elif (self.current_entry or {}).get("id") in (
                    "gcp-networkconnectivity-groups-setiampolicy-group-self-grant",
                    "gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant"):
                from .gcp_resource_self_grant import ncc_group_candidates
                targets.extend(ncc_group_candidates(self, hub_policy=(self.current_entry or {}).get("id") ==
                                                 "gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant").values())
            elif (self.current_entry or {}).get("id") == "gcp-networksecurity-addressgroups-setiampolicy-address-group-self-grant":
                from .gcp_resource_self_grant import networksecurity_address_group_candidates
                targets.extend(networksecurity_address_group_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-networksecurity-authorizationpolicies-setiampolicy-authorization-policy-self-grant":
                from .gcp_resource_self_grant import networksecurity_authorization_policy_candidates
                targets.extend(networksecurity_authorization_policy_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-networksecurity-authzpolicies-setiampolicy-authz-policy-self-grant":
                from .gcp_resource_self_grant import networksecurity_authz_policy_candidates
                targets.extend(networksecurity_authz_policy_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-networksecurity-clienttlspolicies-setiampolicy-client-tls-policy-self-grant":
                from .gcp_resource_self_grant import networksecurity_client_tls_policy_candidates
                targets.extend(networksecurity_client_tls_policy_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-networksecurity-servertlspolicies-setiampolicy-server-tls-policy-self-grant":
                from .gcp_resource_self_grant import networksecurity_server_tls_policy_candidates
                targets.extend(networksecurity_server_tls_policy_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-privateca-capools-setiampolicy-ca-pool-self-grant":
                from .gcp_resource_self_grant import privateca_pool_candidates
                targets.extend(privateca_pool_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-compute-instances-setiampolicy":
                from .gcp_resource_self_grant import instance_candidates
                targets.extend(instance_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-compute-machineimages-setiampolicy-machine-image-self-grant":
                from .gcp_resource_self_grant import machine_image_candidates
                targets.extend(machine_image_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-compute-recoverablesnapshots-setiampolicy-recoverable-snapshot-self-grant":
                from .gcp_resource_self_grant import recoverable_snapshot_candidates
                targets.extend(recoverable_snapshot_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-compute-snapshots-setiampolicy-snapshot-self-grant":
                from .gcp_resource_self_grant import snapshot_candidates
                targets.extend(snapshot_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-pubsub-topics-setiampolicy-topic-self-grant":
                targets.extend(self.topic_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-pubsub-subscriptions-setiampolicy-subscription-self-grant":
                targets.extend(self.subscription_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-cloudkms-cryptokeys-setiampolicy-crypto-key-self-grant":
                targets.extend(self.kms_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-artifactregistry-repositories-setiampolicy-repository-self-grant":
                targets.extend(self.artifact_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-containeranalysis-notes-setiampolicy-note-self-grant":
                targets.extend(self.containeranalysis_note_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-datacatalog-categories-setiampolicy-policy-tag-self-grant":
                targets.extend(self.datacatalog_policy_tag_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-datacatalog-taxonomies-setiampolicy-taxonomy-self-grant":
                targets.extend(self.datacatalog_taxonomy_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-metastore-services-setiampolicy-metastore-service-self-grant":
                targets.extend(self.metastore_service_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-analyticshub-dataexchanges-setiampolicy-data-exchange-self-grant":
                targets.extend(self.analyticshub_exchange_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-analyticshub-listings-setiampolicy-listing-self-grant":
                targets.extend(self.analyticshub_listing_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-biglake-catalogs-setiampolicy-catalog-self-grant":
                targets.extend(self.biglake_catalog_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-biglake-namespaces-setiampolicy-namespace-self-grant":
                targets.extend(self.biglake_namespace_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-biglake-tables-setiampolicy-table-self-grant":
                targets.extend(self.biglake_table_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigquery-datasets-setiampolicy-dataset-iam-self-grant":
                targets.extend(self.bigquery_dataset_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigquery-datasets-update-dataset-acl-self-grant":
                targets.extend(self.bigquery_dataset_update_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigquery-row-policy-create-self-grant":
                targets.extend(self.bigquery_row_policy_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigquery-tables-setiampolicy-table-self-grant":
                targets.extend(self.bigquery_table_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigquery-connections-setiampolicy-connection-self-grant":
                targets.extend(self.bigquery_connection_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-connectors-connections-setiampolicy-connection-self-grant":
                from .gcp_resource_self_grant import integration_connection_candidates
                targets.extend(integration_connection_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-contactcenterinsights-authorizedviews-setiampolicy-self-grant":
                from .gcp_resource_self_grant import contact_center_authorized_view_candidates
                targets.extend(contact_center_authorized_view_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-discoveryengine-collections-setiampolicy-collection-self-grant":
                from .gcp_resource_self_grant import discoveryengine_collection_candidates
                targets.extend(discoveryengine_collection_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-discoveryengine-datastores-setiampolicy-data-store-self-grant":
                from .gcp_resource_self_grant import discoveryengine_data_store_candidates
                targets.extend(discoveryengine_data_store_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-discoveryengine-engines-setiampolicy-engine-self-grant":
                from .gcp_resource_self_grant import discoveryengine_engine_candidates
                targets.extend(discoveryengine_engine_candidates(self).values())
            elif (self.current_entry or {}).get("id") == "gcp-bigtable-authorizedviews-setiampolicy-authorized-view-self-grant":
                targets.extend(self.bigtable_authorized_view_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigtable-materializedviews-setiampolicy-materialized-view-self-grant":
                targets.extend(self.bigtable_materialized_view_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigtable-tables-setiampolicy-table-self-grant":
                targets.extend(self.bigtable_table_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigtable-backups-setiampolicy-backup-self-grant":
                targets.extend(self.bigtable_backup_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigtable-instances-setiampolicy-instance-self-grant":
                targets.extend(self.bigtable_instance_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-bigtable-instances-setiampolicy-instance-admin-self-grant":
                targets.extend(self.bigtable_instance_admin_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-compute-disks-setiampolicy-disk-self-grant":
                targets.extend(self.disk_self_grant_targets.values())
            elif (self.current_entry or {}).get("id") == "gcp-compute-images-setiampolicy-image-self-grant":
                targets.extend(self.image_self_grant_targets.values())
            return targets
        if (selector or {}).get("gcp_challenge_fact"):
            tid = selector["gcp_challenge_fact"]
            from .principal_evidence import CONTRACT as principal_contract
            if tid in principal_contract:
                if kind != "gcp_service_account": return []
                return [self.principals[target] for (fact_tid, _, fact_kind, target, scope), records in self.challenge_evidence.items()
                        if fact_tid == tid and fact_kind == kind and target in self.principals
                        and self.principals[target].kind == kind and self.principals[target].scope == scope
                        and not self.principals[target].attrs.get("disabled")]
            if tid == _EXACT_RUNNING_POD_UPDATE:
                return self._ksa_targets("running_pod") if kind == "k8s_service_account" else []
            if tid in _EXACT_TABLE_KEY_PERMISSIONS:
                if kind != "gcp_service_account":
                    return []
                return [self.sas[target] for (fact_tid, _, fact_kind, target, scope), records
                        in self.challenge_evidence.items()
                        if fact_tid == tid and fact_kind == kind and target in self.sas
                        and not self.sas[target].attrs.get("disabled")
                        and any(self._table_key_fact_bound(tid, target, scope, fact)
                                for fact in records)]
            out = {}
            for (fact_tid, _, fact_kind, resource, scope), records in self.challenge_evidence.items():
                if fact_tid != tid or fact_kind != kind or all(r.get("Status") == "disproven" for r in records):
                    continue
                ident = f"gcp_verified_authority:{tid}:{scope}:{resource}" if kind == "gcp_verified_authority" else resource
                out[ident] = Node(ident, kind, "gcp", scope,
                    f"{kind} reached through {tid} ({resource})",
                    attrs={"resource": resource, "scope": scope, "email": resource.partition(":")[2]},
                    entity=kind == "gcp_verified_authority")
            return list(out.values())
        variant = self.target_variant(kind, selector)
        if variant is not None:
            return self._ksa_targets(variant)
        if kind == "gcp_service_account" and any(
                str(service).lower() in VERTEX_DEFAULT_AGENTS
                for service in as_list((selector or {}).get("attached_to_service"))):
            return [*self.sas.values(), *self.vertex_agents.values()]
        return self.targets(kind)

    # -------------------------------------------------------------- targets
    def service_managed(self, node):
        """Google-managed service agents (service-<n>@gcp-sa-*/...-robot, <n>@cloudservices, legacy
        <n>@cloudbuild ...) belong to Google; only techniques that select them through attached_to_service
        (e.g. cloudservices_agent, vertex_custom_code_agent) or include_service_managed target them.
        Default compute/App Engine SAs are customer-usable and stay."""
        if node.kind != "gcp_service_account":
            return False
        return _google_managed(node.attrs.get("email"))

    def include_service_managed(self, compiled):
        selector = compiled.get("selector") or {}
        return (super().include_service_managed(compiled) or "attached_to_service" in selector
                or "gcp_sourcerepo_trigger_path" in selector
                or "gcp_deploymentmanager_create_path" in selector
                or "gcp_deploymentmanager_update_path" in selector
                or "gcp_deploymentmanager_selfgrant_path" in selector
                or "gcp_bigquery_spark_connection_path" in selector
                or "gcp_cloudfunctions_source_deploy_build_path" in selector)

    def targets(self, kind):
        if kind == "k8s_cluster_admin":
            return [self.cluster_entity(r) for r in sorted(self.gke)]
        if kind == "gcp_service_account":
            return list(self.sas.values())
        if kind in ("gcp_user", "gcp_workspace_user"):
            return [n for n in self.principals.values() if n.kind == "gcp_user"]
        if kind == "gcp_group":
            return [n for n in self.principals.values() if n.kind == "gcp_group"]
        if kind == "gcp_scope_owner":
            nodes = {n for n in self.parents} | set(self.parents.values()) | self.scopes
            return [self.entity(n) for n in sorted(nodes) if n.startswith(("projects/", "folders/", "organizations/")) and "/serviceAccounts/" not in n]
        return []

    def entity(self, scope):
        cache = self.__dict__.setdefault("_entities", {})
        if scope not in cache:
            cache[scope] = Node(f"gcp_scope_owner:{scope}", "gcp_scope_owner", "gcp", scope, f"IAM control of {scope}",
                                attrs={"scope": scope, "resource": scope}, entity=True)
        return cache[scope]

    def cluster_entity(self, resource):
        cache = self.__dict__.setdefault("_entities", {})
        key = ("k8s_cluster_admin", resource)
        if key not in cache:
            cache[key] = Node(f"k8s_cluster_admin:{resource}", "k8s_cluster_admin", "gcp", resource,
                              f"cluster-admin of GKE cluster {resource.rsplit('/', 1)[-1]}",
                              attrs={"scope": resource, "resource": resource, "cluster": resource}, entity=True)
        return cache[key]

    def unknown_target_scopes(self, kind):
        if (self.current_selector or {}).get("gcp_dataplex_task_path"):
            statuses = inventory_status(self.snapshot, "dataplex_privesc_lake")
            projects = {scope for scope in self.scopes if scope.startswith("projects/")
                        and scope.count("/") == 1}
            return {scope: statuses.get(scope, "not_collected") for scope in projects
                    if statuses.get(scope) not in ("collected", "empty")}
        if ((self.current_selector or {}).get("gcp_datafusion_artifact_poison_path")
                or (self.current_selector or {}).get("gcp_datafusion_pipeline_path")
                or (self.current_selector or {}).get("gcp_datafusion_selfgrant_path")):
            statuses = inventory_status(self.snapshot, "datafusion_privesc_instance")
            projects = {scope for scope in self.scopes if scope.startswith("projects/") and scope.count("/") == 1}
            return {scope: statuses.get(scope, "not_collected") for scope in projects
                    if statuses.get(scope) not in ("collected", "empty")}
        if (self.current_selector or {}).get("gcp_privatecatalog_dm_iam_path"):
            statuses = inventory_status(self.snapshot, "service_catalog_version")
            orgs = {scope for scope in self.scopes if scope.startswith("organizations/")}
            return {scope: statuses.get(scope, "not_collected") for scope in orgs
                    if statuses.get(scope) not in ("collected", "empty")}
        if (self.current_selector or {}).get("gcp_kcc_project_policy_grant"):
            from .gcp_config_connector import unresolved_scopes
            return unresolved_scopes(self)
        if (self.current_selector or {}).get("gcp_kcc_generated_key_secret"):
            from .gcp_config_connector_key import unknown_scopes
            return unknown_scopes(self)
        if (self.current_selector or {}).get("gcp_configdelivery_fleet_target"):
            from .gcp_config_delivery import unknown_scopes
            return unknown_scopes(self)
        if (self.current_selector or {}).get("gcp_fleet_config_management_target"):
            from .gcp_fleet_config_management import unknown_scopes
            return unknown_scopes(self)
        if (self.current_selector or {}).get("gcp_fleet_rbac_admin_target"):
            from .gcp_fleet_rbac import unknown_scopes
            return unknown_scopes(self)
        if (self.current_selector or {}).get("gcp_bigquery_spark_connection_path"):
            statuses = inventory_status(self.snapshot, "bigquery_connection")
            projects = {scope for scope in self.scopes if scope.startswith("projects/") and scope.count("/") == 1}
            return {scope: self.host_status.get((scope, "bigquery_spark_connection"),
                                                 statuses.get(scope, "not_collected"))
                    for scope in projects if self.host_status.get((scope, "bigquery_spark_connection"),
                                                                    statuses.get(scope)) not in ("collected", "empty")}
        if (self.current_selector or {}).get("gcp_bounded_service_execution"):
            scopes = {self._norm_scope(s): st for s, st in unavailable(inventory_status(self.snapshot, "service_account")).items()}
            return {s: st for s, st in scopes.items() if s.startswith("projects/")}
        if (self.current_selector or {}).get("gcp_hmac_storage_identity"):
            scopes = {self._norm_scope(s): st for s, st in unavailable(inventory_status(self.snapshot, "service_account")).items()}
            return {s: st for s, st in scopes.items() if s.startswith("projects/")}
        if (self.current_selector or {}).get("gcp_external_principal_evidence"):
            return {}
        if (self.current_selector or {}).get("gcp_firebase_apphosting_retarget"):
            status = inventory_status(self.snapshot, "firebase_apphosting_backend")
            projects = {scope for scope in self.scopes if scope.startswith("projects/")
                        and scope.count("/") == 1}
            return {project: status.get(project, "not_collected") for project in projects
                    if status.get(project) not in ("collected", "empty")}
        if (self.current_selector or {}).get("gcp_agentregistry_skill_evidence"):
            return {}
        if (self.current_selector or {}).get("gcp_resource_self_grant"):
            prospective_kind = {
                "gcp-secretmanager-secrets-setiampolicy-secret-self-grant": "secret",
                "gcp-gkehub-memberships-setiampolicy-membership-self-grant": "fleet_membership",
                "gcp-healthcare-consentstores-setiampolicy-consent-store-self-grant": "healthcare_consent_store",
                "gcp-healthcare-datasets-setiampolicy-dataset-self-grant": "healthcare_fhir_store",
                "gcp-healthcare-dicomstores-setiampolicy-dicom-store-self-grant": "healthcare_dicom_store",
                "gcp-healthcare-fhirstores-setiampolicy-fhir-store-self-grant": "healthcare_fhir_store",
                "gcp-healthcare-hl7v2stores-setiampolicy-hl7v2-store-self-grant": "healthcare_hl7v2_store",
                "gcp-iap-tunnelinstances-setiampolicy-instance-self-grant": "iap_tunnel_policy",
                "gcp-iap-tunnelzones-setiampolicy-zone-self-grant": "iap_tunnel_policy",
                "gcp-identitytoolkit-tenants-setiampolicy-tenant-self-grant": "identityplatform_tenant",
                "gcp-krmapihosting-krmapihosts-setiampolicy-krm-api-host-self-grant": "krm_api_host",
                "gcp-logging-views-setiampolicy-self-grant": "logging_view",
                "gcp-resourcemanager-folders-setiampolicy": "folder",
                "gcp-resourcemanager-organizations-setiampolicy": "organization",
                "gcp-resourcemanager-organizations-setiampolicy-deny-admin": "organization",
                "gcp-resourcemanager-organizations-setiampolicy-role-admin": "organization",
                "gcp-resourcemanager-projects-setiampolicy": "project",
                "gcp-resourcemanager-projects-setiampolicy-project-delete": "project",
                "gcp-networkconnectivity-groups-setiampolicy-group-self-grant": "network_connectivity_hub_group",
                "gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant": "network_connectivity_hub_group",
                "gcp-networksecurity-addressgroups-setiampolicy-address-group-self-grant": "network_security_address_group",
                "gcp-networksecurity-authorizationpolicies-setiampolicy-authorization-policy-self-grant": "network_security_authorization_policy",
                "gcp-networksecurity-authzpolicies-setiampolicy-authz-policy-self-grant": "ngfw_authz_policy",
                "gcp-networksecurity-clienttlspolicies-setiampolicy-client-tls-policy-self-grant": "network_security_client_tls_policy",
                "gcp-networksecurity-servertlspolicies-setiampolicy-server-tls-policy-self-grant": "network_security_server_tls_policy",
                "gcp-privateca-capools-setiampolicy-ca-pool-self-grant": "ca_pool",
                "gcp-containeranalysis-notes-setiampolicy-note-self-grant": "containeranalysis_note",
                "gcp-datacatalog-categories-setiampolicy-policy-tag-self-grant": "datacatalog_policy_tag",
                "gcp-datacatalog-taxonomies-setiampolicy-taxonomy-self-grant": "datacatalog_policy_tag",
                "gcp-metastore-services-setiampolicy-metastore-service-self-grant": "metastore_service",
                "gcp-pubsub-topics-setiampolicy-topic-self-grant": "pubsub_topic",
                "gcp-pubsub-subscriptions-setiampolicy-subscription-self-grant": "pubsub_subscription",
                "gcp-cloudkms-cryptokeys-setiampolicy-crypto-key-self-grant": "kms_key",
                "gcp-analyticshub-dataexchanges-setiampolicy-data-exchange-self-grant": "analyticshub_data_exchange",
                "gcp-analyticshub-listings-setiampolicy-listing-self-grant": "analyticshub_listing",
                "gcp-biglake-catalogs-setiampolicy-catalog-self-grant": "biglake_catalog",
                "gcp-biglake-namespaces-setiampolicy-namespace-self-grant": "biglake_namespace",
                "gcp-biglake-tables-setiampolicy-table-self-grant": "biglake_table",
                "gcp-bigquery-datasets-setiampolicy-dataset-iam-self-grant": "bigquery_dataset",
                "gcp-bigquery-datasets-update-dataset-acl-self-grant": "bigquery_dataset",
                "gcp-bigquery-row-policy-create-self-grant": "bigquery_row_policy_inventory",
                "gcp-bigquery-tables-setiampolicy-table-self-grant": "bigquery_table",
                "gcp-bigquery-connections-setiampolicy-connection-self-grant": "bigquery_connection",
                "gcp-connectors-connections-setiampolicy-connection-self-grant": "integration_connection",
                "gcp-contactcenterinsights-authorizedviews-setiampolicy-self-grant": "contact_center_authorized_view",
                "gcp-discoveryengine-collections-setiampolicy-collection-self-grant": "discoveryengine_collection",
                "gcp-discoveryengine-datastores-setiampolicy-data-store-self-grant": "discoveryengine_data_store",
                "gcp-discoveryengine-engines-setiampolicy-engine-self-grant": "discoveryengine_engine",
                "gcp-domains-registrations-setiampolicy-self-grant": "domains_registration",
                "gcp-bigtable-authorizedviews-setiampolicy-authorized-view-self-grant": "bigtable_authorized_view",
                "gcp-bigtable-materializedviews-setiampolicy-materialized-view-self-grant": "bigtable_materialized_view",
                "gcp-bigtable-tables-setiampolicy-table-self-grant": "bigtable_table",
                "gcp-bigtable-backups-setiampolicy-backup-self-grant": "bigtable_backup",
                "gcp-bigtable-instances-setiampolicy-instance-self-grant": "bigtable_table",
                "gcp-bigtable-instances-setiampolicy-instance-admin-self-grant": "bigtable_instance",
                "gcp-compute-disks-setiampolicy-disk-self-grant": "disk",
                "gcp-compute-instances-setiampolicy": "instance",
                "gcp-compute-machineimages-setiampolicy-machine-image-self-grant": "machine_image",
                "gcp-compute-recoverablesnapshots-setiampolicy-recoverable-snapshot-self-grant": "recoverable_snapshot",
                "gcp-compute-snapshots-setiampolicy-snapshot-self-grant": "snapshot",
                "gcp-compute-images-setiampolicy-image-self-grant": "image",
            }.get((self.current_entry or {}).get("id"))
            if prospective_kind:
                inventory = (self.resource_inventory_status.get(prospective_kind)
                             if prospective_kind not in ("folder", "organization", "project") else {
                                 self._norm_scope(scope): status for scope, status in
                                 inventory_status(self.snapshot, prospective_kind).items()})
                projects = {scope for scope in self.scopes if scope.startswith("projects/") and scope.count("/") == 1}
                projects.update(scope for scope in inventory
                                if scope.startswith("projects/") and scope.count("/") == 1)
                if prospective_kind == "logging_view":
                    parents = ("folders/", "organizations/", "billingAccounts/")
                    projects.update(scope for scope in self.scopes if scope.startswith(parents)
                                    and scope.count("/") == 1)
                    projects.update(scope for scope in inventory if scope.startswith(parents)
                                    and scope.count("/") == 1)
                if prospective_kind == "folder":
                    projects = {scope for scope in self.scopes if scope.startswith("folders/")
                                and scope.count("/") == 1}
                    projects.update(scope for scope in inventory if scope.startswith("folders/")
                                    and scope.count("/") == 1)
                if prospective_kind == "organization":
                    projects = {scope for scope in self.scopes if scope.startswith("organizations/")
                                and scope.count("/") == 1}
                    projects.update(scope for scope in inventory if scope.startswith("organizations/")
                                    and scope.count("/") == 1)
                gaps = {scope: inventory.get(scope, "not_collected")
                        for scope in projects if inventory.get(scope) not in ("collected", "empty")}
                if (self.current_entry or {}).get("id") == "gcp-datacatalog-taxonomies-setiampolicy-taxonomy-self-grant":
                    taxonomy_inventory = self.resource_inventory_status.get("datacatalog_taxonomy", {})
                    for scope in projects:
                        if taxonomy_inventory.get(scope) not in ("collected", "empty"):
                            gaps.setdefault(scope, "taxonomy_inventory_" + taxonomy_inventory.get(scope, "not_collected"))
                if (self.current_entry or {}).get("id") == "gcp-healthcare-consentstores-setiampolicy-consent-store-self-grant":
                    dataset_inventory = self.resource_inventory_status.get("healthcare_dataset", {})
                    for scope in projects:
                        if dataset_inventory.get(scope) not in ("collected", "empty"):
                            gaps.setdefault(scope, "dataset_inventory_" + dataset_inventory.get(scope, "not_collected"))
                if (self.current_entry or {}).get("id") == "gcp-healthcare-datasets-setiampolicy-dataset-self-grant":
                    dataset_inventory = self.resource_inventory_status.get("healthcare_dataset", {})
                    for scope in projects:
                        if dataset_inventory.get(scope) not in ("collected", "empty"):
                            gaps.setdefault(scope, "dataset_inventory_" + dataset_inventory.get(scope, "not_collected"))
                if (self.current_entry or {}).get("id") == "gcp-healthcare-dicomstores-setiampolicy-dicom-store-self-grant":
                    dataset_inventory = self.resource_inventory_status.get("healthcare_dataset", {})
                    for scope in projects:
                        if dataset_inventory.get(scope) not in ("collected", "empty"):
                            gaps.setdefault(scope, "dataset_inventory_" + dataset_inventory.get(scope, "not_collected"))
                if (self.current_entry or {}).get("id") == "gcp-healthcare-fhirstores-setiampolicy-fhir-store-self-grant":
                    dataset_inventory = self.resource_inventory_status.get("healthcare_dataset", {})
                    for scope in projects:
                        if dataset_inventory.get(scope) not in ("collected", "empty"):
                            gaps.setdefault(scope, "dataset_inventory_" + dataset_inventory.get(scope, "not_collected"))
                if (self.current_entry or {}).get("id") == "gcp-healthcare-hl7v2stores-setiampolicy-hl7v2-store-self-grant":
                    dataset_inventory = self.resource_inventory_status.get("healthcare_dataset", {})
                    for scope in projects:
                        if dataset_inventory.get(scope) not in ("collected", "empty"):
                            gaps.setdefault(scope, "dataset_inventory_" + dataset_inventory.get(scope, "not_collected"))
                if (self.current_entry or {}).get("id") in (
                        "gcp-networkconnectivity-groups-setiampolicy-group-self-grant",
                        "gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant"):
                    hub_inventory = self.resource_inventory_status.get("network_connectivity_hub", {})
                    for scope in projects:
                        if hub_inventory.get(scope) not in ("collected", "empty"):
                            gaps.setdefault(scope, "hub_inventory_" + hub_inventory.get(scope, "not_collected"))
                if (prospective_kind == "bigquery_connection"
                        and (self.snapshot.get("metadata") or {}).get("collector") == "native-gcp"
                        and (self.snapshot.get("metadata") or {}).get(
                            "bigquery_connection_location_mode") == "dataset_and_selected"):
                    for scope in projects:
                        gaps.setdefault(scope, "unsearched_connection_locations")
                if (prospective_kind in ("integration_connection", "contact_center_authorized_view")
                        and (self.snapshot.get("metadata") or {}).get("collector") == "native-gcp"
                        and (self.snapshot.get("metadata") or {}).get(
                            prospective_kind + "_location_mode") == "selected"):
                    for scope in projects:
                        gaps.setdefault(scope, "unsearched_resource_locations")
                return gaps if projects else {"*": "resource_inventory_not_collected"}
            # Ordinary inventories do not include an attempted IAM mutation.
            # Keep a single unresolved outcome for principals that hold the
            # policy-write action, even if no reviewed mutation was supplied.
            return {"*": "self_grant_outcome_not_collected"}
        if (self.current_selector or {}).get("gcp_challenge_fact"):
            scopes = {s for s in self.scopes if s.startswith("projects/")}
            out = {}
            for scope in scopes:
                states = [st for s, st in self.challenge_status.items() if self._norm_scope(s) == scope]
                if not states or any(st not in ("collected", "empty") for st in states):
                    out[scope] = next((st for st in states if st not in ("collected", "empty")), "not_collected")
            return out
        if kind in ("k8s_cluster_admin", "k8s_service_account"):
            # GKE clusters live only in projects.
            return {s: st for s, st in unavailable(self.gke_status).items() if not str(s).startswith(("folders/", "organizations/"))}
        if kind == "gcp_service_account":
            # Service accounts live only in projects: a folder/organization "service_account" collection is not a gap.
            scopes = {self._norm_scope(s): st for s, st in unavailable(inventory_status(self.snapshot, "service_account")).items()}
            return {s: st for s, st in scopes.items() if not s.startswith(("folders/", "organizations/"))}
        return {}

    def _vertex_prediction_delegated(self, target):
        project = target.scope
        numbers = [number for number, pid in self.project_alias.items()
                   if "projects/" + pid == project]
        if len(numbers) != 1:
            return False
        agent = "serviceAccount:service-" + numbers[0] + "@gcp-sa-aiplatform.iam.gserviceaccount.com"
        target_resource = target.attrs.get("resource") or f"{project}/serviceAccounts/{target.attrs.get('email')}"
        chain = set(self.ancestors(target_resource))
        return any(node in chain and role == "roles/iam.serviceAccountAdmin" and not condition
                   for node, role, condition, _ in self.grants.get(agent, ()))

    def selector(self, key, value, candidates, source, pivot=None):
        if key == "gcp_developerconnect_pipeline_path":
            from .gcp_developerconnect_pipeline import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_deploymentmanager_update_path":
            from .gcp_deploymentmanager_update import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_deploymentmanager_selfgrant_path":
            from .gcp_deploymentmanager_selfgrant import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_deploymentmanager_create_path":
            from .gcp_deploymentmanager_create import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataproc_workflow_path":
            from .gcp_dataproc_workflow import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataproc_init_replace_path":
            from .gcp_dataproc_init_replace import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataproc_job_path":
            from .gcp_dataproc_job import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataproc_gateway_path":
            from .gcp_dataproc_gateway import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataproc_cluster_selfgrant_path":
            from .gcp_dataproc_cluster_selfgrant import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataproc_session_path":
            from .gcp_dataproc_session import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataproc_create_path":
            from .gcp_dataproc_create import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataplex_task_path":
            from .gcp_dataplex_task import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_datafusion_selfgrant_path":
            from .gcp_datafusion_selfgrant import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_datafusion_pipeline_path":
            from .gcp_datafusion_pipeline import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_datafusion_artifact_poison_path":
            from .gcp_datafusion_artifact import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataflow_artifact_overwrite_path":
            from .gcp_dataflow_artifact import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_dataflow_flex_launch_path":
            from .gcp_dataflow import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_datapipelines_scheduled_template_path":
            from .gcp_datapipelines import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_cloudbuild_api_enabled":
            if value is not True or source is None:
                return {}
            status = {self._norm_scope(scope): state for scope, state in
                      inventory_status(self.snapshot, "service_usage").items()}
            states = {}
            for scope, item in items(self.snapshot, "service_usage"):
                project = self._norm_scope(scope)
                name = item.get("name")
                if isinstance(name, str) and self._norm_scope(name) == f"{project}/services/cloudbuild.googleapis.com":
                    states.setdefault(project, []).append(item.get("state"))
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                matches = states.get(project, [])
                if status.get(project) not in ("collected", "empty") or len(matches) != 1:
                    out[tid] = ("unknown", "cloudbuild_service_state_unresolved")
                elif matches[0] == "ENABLED":
                    out[tid] = None
                elif matches[0] == "DISABLED":
                    if self.check(source, {"action": "serviceusage.services.enable"}, project):
                        out[tid] = ("unknown", "cloudbuild_api_must_be_enabled")
                else:
                    out[tid] = ("unknown", "cloudbuild_service_state_unresolved")
            return out
        if key == "gcp_bigquery_spark_connection_path":
            from .gcp_bigquery_spark import selector as spark_selector
            return spark_selector(self, value, candidates, source)
        if key == "gcp_mig_existing_template_path":
            from .gcp_mig_template import selector as mig_selector
            return mig_selector(self, value, candidates, source)
        if key == "gcp_vm_create_path":
            from .gcp_vm_create import selector as vm_create_selector
            return vm_create_selector(self, value, candidates, source)
        if key == "gcp_osadminlogin_vm_path":
            from .gcp_oslogin import selector as oslogin_selector
            return oslogin_selector(self, value, candidates, source)
        if key == "gcp_osconfig_guest_policy_path":
            from .gcp_osconfig_guest_policy import selector as guest_policy_selector
            return guest_policy_selector(self, value, candidates, source)
        if key == "gcp_osconfig_os_policy_assignment_path":
            from .gcp_osconfig_os_policy_assignment import selector as os_policy_selector
            return os_policy_selector(self, value, candidates, source)
        if key == "gcp_osconfig_patch_job_path":
            from .gcp_osconfig_patch_job import selector as patch_job_selector
            return patch_job_selector(self, value, candidates, source)
        if key == "gcp_osconfig_policy_orchestrator_path":
            from .gcp_osconfig_policy_orchestrator import selector as orchestrator_selector
            return orchestrator_selector(self, value, candidates, source)
        if key == "gcp_oslogin_vm_path":
            from .gcp_oslogin import selector as oslogin_selector
            return oslogin_selector(self, value, candidates, source, require_admin=False)
        if key == "gcp_metadata_vm_path":
            from .gcp_metadata_vm import selector as metadata_vm_selector
            return metadata_vm_selector(self, value, candidates, source)
        if key == "gcp_project_metadata_vm_path":
            from .gcp_project_metadata import selector as project_metadata_selector
            return project_metadata_selector(self, value, candidates, source)
        if key == "gcp_sa_swap_vm_path":
            from .gcp_sa_swap import selector as sa_swap_selector
            return sa_swap_selector(self, value, candidates, source)
        if key == "gcp_mig_create_path":
            from .gcp_mig_create import selector as mig_create_selector
            return mig_create_selector(self, value, candidates, source)
        if key == "gcp_apigee_proxy_deploy_path":
            from .gcp_apigee import proxy_deploy_selector
            return proxy_deploy_selector(self, value, candidates, source)
        if key == "gcp_apigee_sharedflow_hook_path":
            from .gcp_apigee import sharedflow_hook_selector
            return sharedflow_hook_selector(self, value, candidates, source)
        if key == "gcp_agentidentity_retrieve_path":
            from .gcp_agentidentity import select
            return select(self, candidates) if value is True else {}
        if key == "gcp_agentidentity_update_path":
            from .gcp_agentidentity import select
            return select(self, candidates, mode="update") if value is True else {}
        if key == "gcp_appengine_instance_ssh_path":
            from .gcp_appengine_debug import selector as appengine_debug_selector
            return appengine_debug_selector(self, value, candidates, source)
        if key == "gcp_appengine_deploy_path":
            from .gcp_appengine_deploy import selector as appengine_deploy_selector
            return appengine_deploy_selector(self, value, candidates, source)
        if key == "gcp_appengine_legacy_actas_unenforced":
            from .gcp_appengine_deploy import legacy_selector
            return legacy_selector(self, value, candidates, source)
        if key == "gcp_appintegration_run_as_path":
            from .gcp_appintegration import selector as appintegration_selector
            return appintegration_selector(self, value, candidates, source)
        if key == "gcp_gcr_namespace_path":
            from .gcp_gcr_namespace import selector as gcr_namespace_selector
            return gcr_namespace_selector(self, value, candidates, source)
        if key == "gcp_artifact_policy_consumer_path":
            from .gcp_artifact_policy_consumer import selector as artifact_policy_consumer_selector
            return artifact_policy_consumer_selector(self, value, candidates, source)
        if key == "gcp_artifact_upload_consumer_path":
            from .gcp_artifact_upload_consumer import selector as artifact_upload_consumer_selector
            return artifact_upload_consumer_selector(self, value, candidates, source)
        if key == "gcp_wif_active_path":
            if value not in ("create", "update") or source is None:
                return {}
            path_map = self.wif_create_paths if value == "create" else self.wif_update_paths
            out = {}
            for tid in candidates:
                paths = [(action, resource, uncertain) for action, resource, uncertain in path_map.get(tid, ())
                         if self.check(source, {"action": action}, resource) is not None]
                if paths:
                    out[tid] = (("conditional", "wif_provider_must_admit_source_controlled_credentials")
                                if any(not uncertain for _, _, uncertain in paths)
                                else ("unknown", "wif_service_account_binding_condition_unresolved"))
            return out
        if key == "gcp_workforce_control_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid in candidates:
                paths = [(action, resource, uncertain)
                         for action, resource, uncertain in self.workforce_control_paths.get(tid, ())
                         if self.check(source, {"action": action}, resource) is not None]
                if paths:
                    out[tid] = (("conditional", "workforce_provider_must_admit_source_controlled_credentials")
                                if any(not uncertain for _, _, uncertain in paths)
                                else ("unknown", "workforce_service_account_binding_condition_unresolved"))
            return out
        if key == "gcp_wif_restorable_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid in candidates:
                paths = [(action, resource, uncertain)
                         for action, resource, uncertain in self.wif_restore_paths.get(tid, ())
                         if self.check(source, {"action": action}, resource) is not None]
                if paths:
                    out[tid] = (("conditional", "restored_provider_must_accept_source_controlled_credentials")
                                if any(not uncertain for _, _, uncertain in paths)
                                else ("unknown", "wif_service_account_binding_condition_unresolved"))
            return out
        if key == "gcp_batch_agent_reporter_on_target":
            if value is not True:
                return {}
            out = {}
            for tid, target in candidates.items():
                if tid not in self.sas or target.kind != "gcp_service_account":
                    continue
                grant = self.check(target, {"action": "batch.states.report"}, target.scope)
                if grant and grant.confidence != "unknown":
                    out[tid] = None if grant.confidence == "derived" else ("conditional", "batch_reporter_grant_conditional")
                else:
                    out[tid] = ("unknown", "batch_reporter_grant_unresolved")
            return out
        if key == "gcp_run_service_ssh_path":
            if value is not True or source is None:
                return {}
            if not self.holders(source, "run.services.sshroot"):
                return {}
            out = {}
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                unresolved = False
                for services in self.run_services_by_project.values():
                    for resource, sa, item in services:
                        if sa != email:
                            continue
                        grant = self.check(source, {"action": "run.services.sshRoot"}, resource)
                        if not grant:
                            continue
                        if item.get("sshEnabled") is False or item.get("deleteTime"):
                            continue
                        template = item.get("template") or {}
                        environment = template.get("executionEnvironment")
                        if environment == "EXECUTION_ENVIRONMENT_GEN1":
                            continue
                        if (item.get("sshEnabled") is not True or
                                environment != "EXECUTION_ENVIRONMENT_GEN2" or
                                (item.get("terminalCondition") or {}).get("state") != "CONDITION_SUCCEEDED" or
                                item.get("reconciling") is True or
                                (item.get("latestReadyRevision") and item.get("latestCreatedRevision") and
                                 item["latestReadyRevision"] != item["latestCreatedRevision"])):
                            unresolved = True
                            continue
                        if grant.confidence == "unknown":
                            unresolved = True
                            continue
                        out[tid] = ("conditional", "ready_gen2_service_ssh_enabled")
                        break
                    if tid in out:
                        break
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "service_ssh_setting_or_state_unresolved")
            return out
        if key in ("gcp_run_job_create_execute_path", "gcp_run_service_create_path"):
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                if target.attrs.get("disabled"):
                    continue
                access = (self._run_job_create_execute_access(source, target.scope)
                          if key == "gcp_run_job_create_execute_path" else
                          self._run_service_create_access(source, target.scope))
                if access is not None:
                    confidence, reason = access
                    out[tid] = None if confidence == "derived" else (confidence, reason)
            return out
        if key == "gcp_run_instance_ssh_path":
            if value is not True or source is None:
                return {}
            if not (self.holders(source, "run.instances.sshroot") or
                    self.holders(source, "run.instances.sshread")):
                return {}
            out = {}
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                unresolved = False
                for instances in self.run_instances_by_project.values():
                    for resource, sa, item in instances:
                        if sa != email:
                            continue
                        root = self.check(source, {"action": "run.instances.sshRoot"}, resource)
                        read = self.check(source, {"action": "run.instances.sshRead"}, resource)
                        if not root and not read:
                            continue
                        if item.get("deleteTime"):
                            continue
                        if (item.get("annotations") or {}).get("run.googleapis.com/ssh-enabled") == "false":
                            continue
                        condition = item.get("terminalCondition") or {}
                        if condition.get("instanceReason") in ("INSTANCE_STOPPED", "INSTANCE_STOPPING"):
                            start = self.check(source, {"action": "run.instances.start"}, resource)
                            if not start:
                                continue
                            if start.confidence == "unknown":
                                unresolved = True
                                continue
                        elif condition.get("state") != "CONDITION_SUCCEEDED" or item.get("reconciling") is not False:
                            unresolved = True
                            continue
                        if not root or root.confidence == "unknown":
                            unresolved = True
                            continue
                        out[tid] = ("conditional", "running_or_startable_instance_ssh")
                        break
                    if tid in out:
                        break
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "instance_ssh_state_or_grant_unresolved")
            return out
        if key == "gcp_run_instance_create_or_update_path":
            if value is not True or source is None:
                return {}
            if not (self.holders(source, "run.instances.create") or
                    self.holders(source, "run.instances.update")):
                return {}
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                access = self._run_instance_deploy_access(source, project)
                if access is not None:
                    confidence, reason = access
                    out[tid] = ("unknown" if confidence == "unknown" else "conditional", reason)
            return out
        if key == "gcp_run_worker_pool_create_or_update_path":
            if value is not True or source is None:
                return {}
            if not (self.holders(source, "run.workerpools.create") or
                    self.holders(source, "run.workerpools.update")):
                return {}
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                create = self.check(source, {"action": "run.workerpools.create"}, project)
                unresolved = bool(create) and create.confidence == "unknown"
                if create and create.confidence != "unknown":
                    status = {self._norm_scope(scope): state for scope, state in
                              inventory_status(self.snapshot, "service_usage").items()}
                    states = [item.get("state") for scope, item in items(self.snapshot, "service_usage")
                              if self._norm_scope(scope) == project and
                              self._norm_scope(item.get("name")) == f"{project}/services/run.googleapis.com"]
                    if status.get(project) not in ("collected", "empty") or len(states) != 1 or states[0] not in ("ENABLED", "DISABLED"):
                        unresolved = True
                    elif states[0] == "ENABLED":
                        out[tid] = ("conditional", "worker_pool_create_with_target_identity")
                        continue
                    elif self.check(source, {"action": "serviceusage.services.enable"}, project):
                        unresolved = True
                unresolved = unresolved or self.host_status.get((project, "cloudrun_worker_pool")) not in ("collected", "empty")
                for resource, _, item in self.run_worker_pools_by_project.get(project, ()):
                    if item.get("deleteTime"):
                        continue
                    update = self.check(source, {"action": "run.workerpools.update"}, resource)
                    if not update:
                        continue
                    if (item.get("terminalCondition") or {}).get("state") != "CONDITION_SUCCEEDED" or item.get("reconciling") is not False or (item.get("generation") and item.get("observedGeneration") and item["generation"] != item["observedGeneration"]):
                        unresolved = True
                        continue
                    if update.confidence != "unknown":
                        out[tid] = ("conditional", "existing_worker_pool_update_with_target_identity")
                        break
                    unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "worker_pool_inventory_or_grant_unresolved")
            return out
        if key in ("gcp_run_service_update_path", "gcp_run_job_update_execute_path"):
            if value is not True or source is None:
                return {}
            is_job = key == "gcp_run_job_update_execute_path"
            update = "run.jobs.update" if is_job else "run.services.update"
            if not self.holders(source, update.lower()):
                return {}
            host = "cloudrun_job" if is_job else "cloudrun_service"
            inventory = self.run_jobs_by_project if is_job else self.run_services_by_project
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                unresolved = self.host_status.get((project, host)) not in ("collected", "empty")
                for resource, _, item in inventory.get(project, ()):
                    if is_job:
                        if item.get("deleteTime"):
                            continue
                        if ((item.get("terminalCondition") or {}).get("state") != "CONDITION_SUCCEEDED"
                                or item.get("reconciling") is not False
                                or (item.get("generation") and item.get("observedGeneration")
                                    and item["generation"] != item["observedGeneration"])):
                            unresolved = True
                            continue
                    else:
                        if item.get("deleteTime"):
                            continue
                        if ((item.get("terminalCondition") or {}).get("state") != "CONDITION_SUCCEEDED"
                                or item.get("reconciling") is not False
                                or (item.get("latestReadyRevision") and item.get("latestCreatedRevision")
                                    and item["latestReadyRevision"] != item["latestCreatedRevision"])):
                            unresolved = True
                            continue
                    grants = [self.check(source, {"action": update}, resource)]
                    if is_job:
                        grants.append(self.check(source, {"action": "run.jobs.run"}, resource))
                    if all(grants):
                        if any(grant.confidence == "unknown" for grant in grants):
                            unresolved = True
                            continue
                        out[tid] = ("conditional", "exact_existing_cloud_run_workload_update_and_execute")
                        break
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "cloud_run_workload_inventory_or_grant_unresolved")
            return out
        if key in ("gcp_run_service_policy_update_path", "gcp_run_worker_pool_policy_update_path"):
            worker = key == "gcp_run_worker_pool_policy_update_path"
            action = "run.workerpools" if worker else "run.services"
            host = "cloudrun_worker_pool" if worker else "cloudrun_service"
            pools = self.run_worker_pools_by_project if worker else self.run_services_by_project
            if value is not True or source is None or not self.holders(source, action + ".setiampolicy"):
                return {}
            services = {resource: item for rows in pools.values()
                        for resource, _, item in rows}
            out = {}
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                projects = self.host_projects.get((email, host), ())
                unresolved = any(self.host_status.get((project, host))
                                 not in ("collected", "empty") for project in projects)
                for resource in self.hosts.get(email, {}).get(host, ()):
                    item = services.get(resource)
                    if item is None:
                        unresolved = True
                        continue
                    if item.get("deleteTime"):
                        continue
                    authority = self.check(source, {"action": action + ".setIamPolicy"}, resource)
                    if authority is None:
                        continue
                    verdict = self._run_service_policy_update_path(source, target, resource, item,
                                                                   authority, action + ".update")
                    if verdict is None:
                        continue
                    if verdict[0] == "unknown":
                        unresolved = True
                        continue
                    out[tid] = verdict
                    break
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "cloud_run_service_policy_or_grant_unresolved")
            return out
        if key in ("gcp_run_job_override_path", "gcp_run_job_policy_override_path"):
            if value is not True or source is None:
                return {}
            if not self.holders(source, "run.jobs.setiampolicy" if key == "gcp_run_job_policy_override_path"
                                else "run.jobs.runwithoverrides"):
                return {}
            out = {}
            job_items = {resource: item for jobs in self.run_jobs_by_project.values()
                         for resource, _, item in jobs}
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                projects = self.host_projects.get((email, "cloudrun_job"), ())
                unresolved = any(self.host_status.get((project, "cloudrun_job")) not in ("collected", "empty")
                                 for project in projects)
                for resource in self.hosts.get(email, {}).get("cloudrun_job", ()):
                    item = job_items.get(resource)
                    if item is None:
                        unresolved = True
                        continue
                    if item.get("deleteTime"):
                        continue
                    if key == "gcp_run_job_policy_override_path":
                        grants = [self.check(source, {"action": "run.jobs.setIamPolicy"}, resource)]
                    else:
                        grants = [self.check(source, {"action": action}, resource) for action in
                                  ("run.jobs.run", "run.jobs.runWithOverrides")]
                    if all(grants):
                        if any(grant.confidence == "unknown" for grant in grants):
                            unresolved = True
                            continue
                        if key == "gcp_run_job_policy_override_path":
                            path = self._run_job_policy_grant_path(source, target, resource, item, grants[0])
                            if path is None:
                                continue
                            if path[0] == "unknown":
                                unresolved = True
                                continue
                            out[tid] = path
                            break
                        else:
                            if ((item.get("terminalCondition") or {}).get("state") != "CONDITION_SUCCEEDED"
                                    or item.get("reconciling") is not False
                                    or (item.get("generation") and item.get("observedGeneration") and
                                        item["generation"] != item["observedGeneration"])):
                                unresolved = True
                                continue
                            if not self._run_job_override_accepts_code(item):
                                unresolved = True
                                continue
                        out[tid] = ("conditional", "same_cloud_run_job_override_or_policy_grant")
                        break
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "cloud_run_job_inventory_or_grant_unresolved")
            return out
        if key == "gcp_workbench_existing_takeover_path":
            if value is not True or source is None:
                return {}
            if not (self.holders(source, "notebooks.instances.update") or
                    self.holders(source, "notebooks.instances.setiampolicy")):
                return {}
            out = {}
            for tid, target in candidates.items():
                project, email = target.scope, target.attrs.get("email")
                unresolved = self.workbench_inventory_status.get(project) not in ("collected", "empty")
                attached = set(self.hosts.get(email, {}).get("notebooks_instance", ()))
                for resource, item in self.workbench_by_project.get(project, ()):
                    if resource not in attached:
                        continue
                    state = item.get("state")
                    if state not in ("ACTIVE", "STOPPED"):
                        unresolved = True
                        continue
                    policy = self.check(source, {"action": "notebooks.instances.setIamPolicy"}, resource)
                    update = self.check(source, {"action": "notebooks.instances.update"}, resource)
                    reset = self.check(source, {"action": "notebooks.instances.reset"}, resource)
                    start = self.check(source, {"action": "notebooks.instances.start"}, resource)
                    if (update and (reset if state == "ACTIVE" else start)) or policy:
                        out[tid] = ("conditional", "exact_workbench_metadata_boot_or_policy_self_grant")
                        break
                    if (item.get("_coverage") or {}).get("iamPolicy", {}).get("status") != "collected":
                        unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "workbench_state_or_instance_policy_unresolved")
            return out
        if key == "gcp_vmmigration_metadata_clone_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                if not email:
                    continue
                for resource in self.hosts.get(email, {}).get("vm_migration_vm", ()):
                    if (self.check(source, {"action": "vmmigration.migratingVms.update"}, resource) and
                            self.check(source, {"action": "vmmigration.cloneJobs.create"}, resource)):
                        out[tid] = ("conditional", "same_migrating_vm_metadata_clone")
                        break
                if tid not in out and any(
                        self.host_status.get((project, "vm_migration_vm")) not in ("collected", "empty")
                        for project in self.scopes if str(project).startswith("projects/")):
                    out[tid] = ("unknown", "migrating_vm_attachment_inventory_incomplete")
            return out
        if key == "gcp_vertex_batch_prediction_path":
            if value is not True or source is None:
                return {}
            if not self.holders(source, "aiplatform.batchpredictionjobs.create"):
                return {}
            out = {}
            for tid, target in candidates.items():
                if self.check(source, {"action": "aiplatform.batchPredictionJobs.create"}, target.scope) is None:
                    out[tid] = ("unknown", "batch_prediction_location_permission_unresolved")
                elif self._vertex_prediction_delegated(target):
                    out[tid] = ("conditional", "batch_prediction_container_with_vertex_delegation")
                else:
                    out[tid] = ("unknown", "vertex_prediction_service_agent_delegation_unresolved")
            return out
        if key == "gcp_vertex_new_model_endpoint_path":
            if value is not True or source is None:
                return {}
            if not self.holders(source, "aiplatform.endpoints.deploy"):
                return {}
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                if self.check(source, {"action": "aiplatform.endpoints.deploy"}, project) is None:
                    out[tid] = ("unknown", "existing_endpoint_or_scoped_deploy_unresolved")
                    continue
                if (self.check(source, {"action": "aiplatform.models.upload"}, project) is None or
                        self.check(source, {"action": "aiplatform.endpoints.create"}, project) is None):
                    out[tid] = ("unknown", "controlled_model_or_endpoint_unresolved")
                    continue
                out[tid] = (("conditional", "new_model_endpoint_with_vertex_delegation") if self._vertex_prediction_delegated(target) else
                            ("unknown", "vertex_prediction_service_agent_delegation_unresolved"))
            return out
        if key == "gcp_composer_storage_policy_path":
            if value not in ("bucket", "managed_folder") or source is None:
                return {}
            action = ("storage.buckets.setIamPolicy" if value == "bucket" else
                      "storage.managedFolders.setIamPolicy")
            out = {}
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                unresolved = False
                for _, bucket_resource, dag_prefix, state in self.composer_dag_paths.get(email, ()):
                    bucket = bucket_resource.rsplit("/buckets/", 1)[-1]
                    resources = ([bucket_resource] if value == "bucket" else
                                 [folder_resource for folder_name, folder_resource
                                  in self.managed_folders.get(bucket, ())
                                  if self.bucket_ubla.get(bucket) and
                                  (dag_prefix.startswith(folder_name) or folder_name.startswith(dag_prefix))])
                    for resource in resources:
                        if self.check(source, {"action": action}, resource) is None:
                            continue
                        if state in ("RUNNING", "UPDATING"):
                            out[tid] = ("conditional", "usable_composer_dag_policy_self_grant")
                            break
                        if state not in ("ERROR", "DELETING"):
                            unresolved = True
                    if tid in out:
                        break
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "composer_environment_state_not_usable_or_missing")
            return out
        if key == "gcp_composer_pypi_update_path":
            if value is not True or source is None:
                return {}
            environments = {self._norm_scope(item.get("name")): item
                            for _, item in items(self.snapshot, "composer_environment")
                            if isinstance(item.get("name"), str)}
            usage_status = {self._norm_scope(scope): status
                            for scope, status in inventory_status(self.snapshot, "service_usage").items()}
            enabled = {self._norm_scope(scope) for scope, item in items(self.snapshot, "service_usage")
                       if self._norm_scope(item.get("name")) ==
                       f"{self._norm_scope(scope)}/services/composer.googleapis.com" and
                       item.get("state") == "ENABLED"}
            out = {}
            for tid, target in candidates.items():
                if target.attrs.get("disabled"):
                    continue
                email = target.attrs.get("email")
                paths = self.hosts.get(email, {}).get("composer_environment", ())
                projects = self.composer_host_projects.get(email, ())
                unresolved = (not paths or not projects or
                              any(self.host_status.get((project, "composer_environment"))
                                  not in ("collected", "empty") for project in projects))
                for path in paths:
                    environment = environments.get(path)
                    if environment is None:
                        unresolved = True
                        continue
                    project = path.split("/locations/", 1)[0]
                    if usage_status.get(project) not in ("collected", "empty"):
                        unresolved = True
                        continue
                    if project not in enabled:
                        continue
                    if environment.get("state") != "RUNNING":
                        if environment.get("state") not in ("DELETING", "DELETED"):
                            unresolved = True
                        continue
                    grant = self.check(source, {"action": "composer.environments.update"}, path)
                    if grant is not None and grant.confidence == "derived":
                        out[tid] = ("conditional", "running_composer_environment_pypi_update")
                        break
                    if grant is not None:
                        unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "composer_update_environment_or_api_unresolved")
            return out
        if key == "gcp_composer_create_with_dag_path":
            if value is not True or source is None:
                return {}
            out = {}
            usage = {self._norm_scope(scope): status
                     for scope, status in inventory_status(self.snapshot, "service_usage").items()}
            enabled = {self._norm_scope(scope) for scope, item in items(self.snapshot, "service_usage")
                       if self._norm_scope(item.get("name")) ==
                       f"{self._norm_scope(scope)}/services/composer.googleapis.com" and
                       item.get("state") == "ENABLED"}
            environment_status = {self._norm_scope(scope): status
                                  for scope, status in inventory_status(self.snapshot, "composer_environment").items()}
            bucket_status = {self._norm_scope(scope): status
                             for scope, status in inventory_status(self.snapshot, "bucket").items()}
            for tid, target in candidates.items():
                project = target.scope
                if target.attrs.get("disabled"):
                    continue
                create = self.check(source, {"action": "composer.environments.create"}, project)
                actas = self.check(source, {"action": "iam.serviceAccounts.actAs"},
                                   target.attrs.get("resource") or
                                   f"{project}/serviceAccounts/{target.attrs.get('email')}")
                if create is None or actas is None:
                    continue
                unresolved = (create.confidence != "derived" or actas.confidence != "derived" or
                              usage.get(project) not in ("collected", "empty") or project not in enabled or
                              environment_status.get(project) not in ("collected", "empty") or
                              bucket_status.get(project) not in ("collected", "empty") or
                              self.composer_image_status.get(project) != "collected")
                if project not in enabled:
                    out[tid] = ("unknown", "composer_api_or_creation_unresolved")
                    continue
                if (environment_status.get(project) not in ("collected", "empty") or
                        project in self.composer_unknown_bucket_projects):
                    out[tid] = ("unknown", "composer_existing_bucket_usage_unresolved")
                    continue
                used = {bucket for paths in self.composer_dag_paths.values()
                        for _, bucket, _, _ in paths}
                for bucket_resource, bucket in self.composer_custom_buckets.get(project, ()):
                    name = bucket_resource.rsplit("/buckets/", 1)[-1]
                    location = str(bucket.get("location") or "").lower()
                    if bucket.get("_representation") != "full":
                        unresolved = True
                        continue
                    if (not location or str(bucket.get("locationType") or "").lower() != "region" or
                            str(bucket.get("storageClass") or "").upper() != "STANDARD" or
                            bucket.get("retentionPolicy") or
                            (bucket.get("hierarchicalNamespace") or {}).get("enabled") is True or
                            bucket_resource in used):
                        continue
                    if location not in self.composer_supported_regions.get(project, ()):
                        unresolved = True
                        continue
                    worker = any(role == "roles/composer.worker" and not condition and
                                 node in self.ancestors(project)
                                 for node, role, condition, _ in target.attrs.get("grants", ()))
                    if not worker:
                        unresolved = True
                        continue
                    prefixes = {"dags/"}
                    if self.bucket_ubla.get(name):
                        prefixes.update(folder_name for folder_name, _ in self.managed_folders.get(name, ())
                                        if folder_name.startswith("dags/"))
                    for prefix in sorted(prefixes):
                        object_resource = bucket_resource + "/objects/" + prefix + "__peaso_new_dag_9a1f.py"
                        folders = [(len(folder_name), folder_resource)
                                   for folder_name, folder_resource in self.managed_folders.get(name, ())
                                   if self.bucket_ubla.get(name) and prefix.startswith(folder_name)]
                        self.parents.setdefault(object_resource, max(folders)[1] if folders else bucket_resource)
                        worker_read = self.check(target, {"action": "storage.objects.get"}, object_resource)
                        worker_list = self.check(target, {"action": "storage.objects.list"}, bucket_resource)
                        if any(grant is None or grant.confidence != "derived"
                               for grant in (worker_read, worker_list)):
                            unresolved = True
                            continue
                        write = self.check(source, {"action": "storage.objects.create"}, object_resource)
                        if write is not None and write.confidence == "derived":
                            parent = f"{project}/locations/{location}"
                            self.parents.setdefault(parent, project)
                            regional_create = self.check(source, {"action": "composer.environments.create"}, parent)
                            if regional_create is not None and regional_create.confidence == "derived":
                                out[tid] = ("conditional", "eligible_composer_custom_bucket_preloaded_dag")
                                break
                            unresolved = True
                        elif write is not None:
                            unresolved = True
                    if tid in out:
                        break
                if tid not in out and not unresolved:
                    alternate = (
                        self.check(source, {"action": "storage.objects.create"}, project),
                        self.check(source, {"action": "storage.buckets.create"}, project),
                        self.check(source, {"action": "composer.environments.update"}, project),
                    )
                    unresolved = any(grant is not None for grant in alternate)
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "composer_custom_bucket_or_worker_unresolved")
            return out
        if key == "gcp_composer_dag_upload_path":
            if value is not True or source is None:
                return {}
            out = {}
            folder_status = {self._norm_scope(scope): status
                             for scope, status in inventory_status(self.snapshot, "managed_folder").items()}
            for tid, target in candidates.items():
                if target.attrs.get("disabled"):
                    continue
                email = target.attrs.get("email")
                paths = self.composer_dag_paths.get(email, ())
                scopes = self.composer_host_projects.get(email, ())
                unresolved = (email in self.composer_dag_incomplete or
                              not scopes or any(self.host_status.get((scope, "composer_environment"))
                                                not in ("collected", "empty") for scope in scopes))
                for environment, bucket_resource, dag_path, state in paths:
                    if not environment or state not in ("RUNNING", "UPDATING"):
                        unresolved = True
                        continue
                    bucket = bucket_resource.split("/buckets/", 1)[-1]
                    if bucket not in self.bucket_projects:
                        unresolved = True
                        continue
                    if folder_status.get(self.bucket_projects[bucket]) not in ("collected", "empty"):
                        unresolved = True
                    prefixes = {dag_path}
                    if self.bucket_ubla.get(bucket):
                        prefixes.update(folder_name for folder_name, _ in self.managed_folders.get(bucket, ())
                                        if folder_name.startswith(dag_path))
                        if any(self.managed_folder_policy_status.get(folder_resource) != "collected"
                               for folder_name, folder_resource in self.managed_folders.get(bucket, ())
                               if dag_path.startswith(folder_name) or folder_name.startswith(dag_path)):
                            unresolved = True
                    for prefix in sorted(prefixes):
                        object_resource = bucket_resource + "/objects/" + prefix + "__peaso_new_dag_9a1f.py"
                        folders = [(len(name), folder_resource)
                                   for name, folder_resource in self.managed_folders.get(bucket, ())
                                   if self.bucket_ubla.get(bucket) and prefix.startswith(name)]
                        self.parents.setdefault(object_resource, max(folders)[1] if folders else bucket_resource)
                        grant = self.check(source, {"action": "storage.objects.create"}, object_resource)
                        if grant is not None and grant.confidence == "derived":
                            out[tid] = ("conditional", "running_composer_dag_prefix_object_create")
                            break
                        if grant is not None:
                            unresolved = True
                    if tid in out:
                        break
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "composer_dag_prefix_or_write_unresolved")
            return out
        if key == "gcp_cloudfunctions_env_startup_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                project, email = target.scope, target.attrs.get("email")
                unresolved = self.function_inventory_status.get(project) not in ("collected", "empty")
                if target.attrs.get("disabled"):
                    continue
                attached = set(self.hosts.get(email, {}).get("function", ()))
                for function, item in self.functions_by_project.get(project, ()):
                    if function not in attached:
                        continue
                    update = self.check(source, {"action": "cloudfunctions.functions.update"}, function)
                    if update is None:
                        continue
                    if update.confidence != "derived":
                        unresolved = True
                        continue
                    if item.get("state") != "ACTIVE":
                        unresolved = True
                        continue
                    runtime = (item.get("buildConfig") or {}).get("runtime") or item.get("runtime")
                    if runtime not in ("nodejs20", "nodejs22", "nodejs24", "nodejs26"):
                        unresolved = True
                        continue
                    build = (item.get("buildConfig") or {}).get("serviceAccount") or item.get("buildServiceAccount")
                    if not build:
                        location = function.split("/locations/", 1)[-1].split("/", 1)[0]
                        build = (self.cloudbuild_default_by_location.get((project, location)) or
                                 self.cloudbuild_default_by_location.get((project, "global")))
                    if not isinstance(build, str) or "@" not in build:
                        unresolved = True
                        continue
                    build_email = build.rsplit("/serviceAccounts/", 1)[-1]
                    if "/serviceAccounts/" in build and not build.startswith(project + "/serviceAccounts/"):
                        unresolved = True
                        continue
                    if not re.fullmatch(r"[0-9]+@cloudbuild\.gserviceaccount\.com", build_email):
                        build_node = self.sas.get("serviceAccount:" + build_email)
                        if build_node is not None and build_node.attrs.get("disabled"):
                            unresolved = True
                            continue
                        build_resource = (build_node.attrs.get("resource") if build_node else
                                          build if "/serviceAccounts/" in build else f"{project}/serviceAccounts/{build_email}")
                        build_grant = self.check(source, {"action": "iam.serviceAccounts.actAs"}, build_resource)
                        if build_grant is None or build_grant.confidence != "derived":
                            unresolved = True
                            continue
                    trigger = bool(item.get("eventTrigger"))
                    if not trigger:
                        run_service = (item.get("serviceConfig") or {}).get("service")
                        invoke = self.check(source, {"action": "cloudfunctions.functions.invoke"}, function)
                        run_invoke = (self.check(source, {"action": "run.routes.invoke"}, run_service)
                                      if run_service else None)
                        trigger = any(grant is not None and grant.confidence == "derived"
                                      for grant in (invoke, run_invoke))
                    if trigger:
                        out[tid] = ("conditional", "active_node_function_env_startup_build_and_trigger")
                        break
                    unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "function_runtime_build_or_trigger_unresolved")
            return out
        if key == "gcp_cloudfunctions_source_deploy_build_path":
            if value is not True or source is None:
                return {}
            out = {}
            def granted(action, resource):
                grant = self.check(source, {"action": action}, resource)
                return grant is not None and grant.confidence == "derived"

            for tid, target in candidates.items():
                project = target.scope
                email = target.attrs.get("email")
                if not isinstance(email, str) or "@" not in email:
                    continue
                legacy = bool(re.fullmatch(r"[0-9]+@cloudbuild\.gserviceaccount\.com", email))
                if target.attrs.get("disabled"):
                    continue
                unresolved = (self.function_inventory_status.get(project) not in ("collected", "empty") or
                              self.host_status.get((project, "cloudbuild_default_sa")) not in ("collected", "empty"))
                build_resource = target.attrs.get("resource") or f"{project}/serviceAccounts/{email}"
                build_actas = legacy or granted("iam.serviceAccounts.actAs", build_resource)
                if not build_actas and self.check(source, {"action": "iam.serviceAccounts.actAs"}, build_resource):
                    unresolved = True
                for (candidate_project, location), default_email in self.cloudbuild_default_by_location.items():
                    if candidate_project != project or default_email != email:
                        continue
                    if location == "global":
                        unresolved = True
                        continue
                    parent = f"{project}/locations/{location}"
                    supported = (self.function_location_status.get(project) == "collected" and
                                 location in self.function_locations_by_project.get(project, set()))
                    if (supported and legacy and
                            granted("cloudfunctions.functions.create", parent) and
                            granted("cloudfunctions.functions.sourceCodeSet", parent)):
                        runtime_accounts = [node for node in self.sas.values()
                                            if node.scope == project and not node.attrs.get("disabled")
                                            and not re.fullmatch(r"[0-9]+@cloudbuild\.gserviceaccount\.com",
                                                                 node.attrs.get("email") or "")]
                        if any(granted("iam.serviceAccounts.actAs",
                                       node.attrs.get("resource") or f"{project}/serviceAccounts/{node.attrs.get('email')}")
                               for node in runtime_accounts):
                            out[tid] = ("conditional", "observed_builder_function_create_with_runtime_actas")
                            break
                        unresolved = True
                    elif self.check(source, {"action": "cloudfunctions.functions.create"}, parent):
                        unresolved = True
                if tid in out:
                    continue
                for function, item in self.functions_by_project.get(project, ()):
                    location_resource = function.rsplit("/functions/", 1)[0]
                    location = location_resource.rsplit("/locations/", 1)[-1]
                    configured = (item.get("buildConfig") or {}).get("serviceAccount") or item.get("buildServiceAccount")
                    selected = (configured.rsplit("/serviceAccounts/", 1)[-1] if isinstance(configured, str) and configured
                                else self.cloudbuild_default_by_location.get((project, location)) or
                                self.cloudbuild_default_by_location.get((project, "global")))
                    if selected != email:
                        continue
                    if (isinstance(configured, str) and "/serviceAccounts/" in configured and
                            not configured.startswith(project + "/serviceAccounts/")):
                        unresolved = True
                        continue
                    update = self.check(source, {"action": "cloudfunctions.functions.update"}, function)
                    if update is None:
                        continue
                    if update.confidence != "derived":
                        unresolved = True
                        continue
                    if (item.get("state") != "ACTIVE" or not build_actas or
                            not granted("cloudfunctions.functions.sourceCodeSet", location_resource)):
                        unresolved = True
                        continue
                    runtime = (item.get("serviceConfig") or {}).get("serviceAccountEmail") or item.get("serviceAccountEmail")
                    if not isinstance(runtime, str) or "@" not in runtime:
                        unresolved = True
                        continue
                    if "/serviceAccounts/" in runtime and not runtime.startswith(project + "/serviceAccounts/"):
                        unresolved = True
                        continue
                    runtime_email = runtime.rsplit("/serviceAccounts/", 1)[-1]
                    runtime_node = self.sas.get("serviceAccount:" + runtime_email)
                    if runtime_node is not None and runtime_node.attrs.get("disabled"):
                        unresolved = True
                        continue
                    runtime_resource = (runtime_node.attrs.get("resource") if runtime_node else
                                        f"{project}/serviceAccounts/{runtime_email}")
                    if granted("iam.serviceAccounts.actAs", runtime_resource):
                        out[tid] = ("conditional", "selected_builder_existing_function_source_update")
                        break
                    unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "function_build_identity_or_source_deploy_unresolved")
            return out
        if key == "gcp_cloudfunctions_create_path":
            if value is not True or source is None:
                return {}
            if not self.holders(source, "cloudfunctions.functions.create"):
                return {}
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                unresolved = self.function_location_status.get(project) not in ("collected", "empty")
                if unresolved:
                    out[tid] = ("unknown", "function_location_inventory_incomplete")
                    continue
                supported = self.function_locations_by_project.get(project, set())
                locations = sorted(location for candidate_project, location in self.cloudbuild_default_by_location
                                   if candidate_project == project and location in supported and location != "global")
                if not locations:
                    if unresolved or supported:
                        out[tid] = ("unknown", "function_location_or_default_build_account_unresolved")
                    continue
                for location in locations:
                    parent = f"{project}/locations/{location}"
                    create = self.check(source, {"action": "cloudfunctions.functions.create"}, parent)
                    if create is None:
                        continue
                    if create.confidence != "derived":
                        unresolved = True
                        continue
                    upload = self.check(source, {"action": "cloudfunctions.functions.sourceCodeSet"}, parent)
                    if upload is None or upload.confidence != "derived":
                        unresolved = True
                        continue
                    build_email = (self.cloudbuild_default_by_location.get((project, location)) or
                                   self.cloudbuild_default_by_location.get((project, "global")))
                    if not build_email:
                        unresolved = True
                        continue
                    if not re.fullmatch(r"[0-9]+@cloudbuild\.gserviceaccount\.com", build_email):
                        build_node = self.sas.get("serviceAccount:" + build_email)
                        if build_node is not None and build_node.attrs.get("disabled"):
                            unresolved = True
                            continue
                        build_resource = (build_node.attrs.get("resource") if build_node else
                                          f"{project}/serviceAccounts/{build_email}")
                        build_actas = self.check(source, {"action": "iam.serviceAccounts.actAs"}, build_resource)
                        if build_actas is None or build_actas.confidence != "derived":
                            unresolved = True
                            continue
                    invoke = (self.check(source, {"action": "cloudfunctions.functions.invoke"}, project),
                              self.check(source, {"action": "run.routes.invoke"}, project))
                    if any(grant is not None and grant.confidence == "derived" for grant in invoke):
                        out[tid] = ("conditional", "function_creation_source_build_and_invoke")
                        break
                    unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "function_build_or_trigger_unresolved")
            return out
        if key == "gcp_cloudfunctions_existing_source_update_path":
            if value is not True or source is None:
                return {}
            if not self.holders(source, "cloudfunctions.functions.update"):
                return {}
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                unresolved = self.function_inventory_status.get(project) not in ("collected", "empty")
                if target.attrs.get("disabled"):
                    continue
                for function, item in self.functions_by_project.get(project, ()):
                    update = self.check(source, {"action": "cloudfunctions.functions.update"}, function)
                    if update is None:
                        continue
                    if update.confidence != "derived":
                        unresolved = True
                        continue
                    if item.get("state") != "ACTIVE":
                        unresolved = True
                        continue
                    location_resource = function.rsplit("/functions/", 1)[0]
                    build = (item.get("buildConfig") or {}).get("serviceAccount") or item.get("buildServiceAccount")
                    if not build:
                        location = function.split("/locations/", 1)[-1].split("/", 1)[0]
                        build = (self.cloudbuild_default_by_location.get((project, location)) or
                                 self.cloudbuild_default_by_location.get((project, "global")))
                    if not isinstance(build, str) or "@" not in build:
                        unresolved = True
                        continue
                    if "/serviceAccounts/" in build and not build.startswith(project + "/serviceAccounts/"):
                        unresolved = True
                        continue
                    build_email = build.rsplit("/serviceAccounts/", 1)[-1]
                    if not re.fullmatch(r"[0-9]+@cloudbuild\.gserviceaccount\.com", build_email):
                        build_node = self.sas.get("serviceAccount:" + build_email)
                        if build_node is not None and build_node.attrs.get("disabled"):
                            unresolved = True
                            continue
                        build_resource = (build_node.attrs.get("resource") if build_node else
                                          build if "/serviceAccounts/" in build else f"{project}/serviceAccounts/{build_email}")
                        build_grant = self.check(source, {"action": "iam.serviceAccounts.actAs"}, build_resource)
                        if build_grant is None or build_grant.confidence != "derived":
                            unresolved = True
                            continue
                    upload = self.check(source, {"action": "cloudfunctions.functions.sourceCodeSet"}, location_resource)
                    if upload is None or upload.confidence != "derived":
                        unresolved = True
                        continue
                    trigger = bool(item.get("eventTrigger"))
                    if not trigger:
                        run_service = (item.get("serviceConfig") or {}).get("service")
                        invoke = self.check(source, {"action": "cloudfunctions.functions.invoke"}, function)
                        run_invoke = (self.check(source, {"action": "run.routes.invoke"}, run_service)
                                      if run_service else None)
                        trigger = any(grant is not None and grant.confidence == "derived"
                                      for grant in (invoke, run_invoke))
                    if trigger:
                        out[tid] = ("conditional", "exact_active_function_source_build_and_trigger")
                        break
                    unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "function_build_source_or_trigger_unresolved")
            return out
        if key in ("gcp_cloudtasks_enqueue_path", "gcp_cloudtasks_queue_policy_path"):
            if value is not True or source is None:
                return {}
            if key == "gcp_cloudtasks_queue_policy_path" and not source.id.startswith(
                    ("user:", "serviceAccount:")):
                return {}
            out = {}
            org_status = inventory_status(self.snapshot, "org_policy_effective")
            group_status = inventory_status(self.snapshot, "group")
            for tid, target in candidates.items():
                project = target.scope
                unresolved = self.cloudtasks_queue_status.get(project) not in ("collected", "empty")
                if key == "gcp_cloudtasks_enqueue_path" and (
                        self.check(source, {"action": "cloudtasks.queues.create"}, project) and
                        self.check(source, {"action": "cloudtasks.tasks.create"}, project)):
                    out[tid] = ("conditional", "new_queue_and_task_creation")
                    continue
                permission = ("cloudtasks.tasks.create" if key == "gcp_cloudtasks_enqueue_path"
                              else "cloudtasks.queues.setIamPolicy")
                for queue, state, override, policy_status in self.cloudtasks_queues_by_project.get(project, ()):
                    authority = self.check(source, {"action": permission}, queue)
                    if authority is None:
                        if policy_status != "collected":
                            unresolved = True
                        continue
                    uncertain = authority.confidence == "unknown"
                    if key == "gcp_cloudtasks_queue_policy_path":
                        if policy_status != "collected":
                            unresolved = True
                            continue
                        prior = self.check(source, {"action": "cloudtasks.tasks.create"}, queue)
                        if prior and prior.confidence == "derived":
                            continue
                        uncertain = uncertain or prior is not None
                        if self._deny(source, "cloudtasks.tasks.create", queue, Grant()) is None:
                            continue
                        constraints = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}
                        if (org_status.get(project) not in ("collected", "empty")
                                or self.deny_status.get(project) not in ("collected", "empty")
                                or any(self._norm_scope(scope) == project and row.get("constraint") in constraints
                                       for scope, row in items(self.snapshot, "org_policy_effective"))):
                            uncertain = True
                        group_grant = any(
                            self.check(group, {"action": "cloudtasks.tasks.create"}, queue) is not None
                            for group in self.principals.values() if group.kind == "gcp_group")
                        if group_grant and (group_status.get(project) not in ("collected", "empty")
                                            or self.group_membership_status.get(project) not in ("collected", "empty")):
                            uncertain = True
                        if source.id.startswith("user:"):
                            domain = source.id.rpartition("@")[2].lower()
                            domain_source = self.principals.get("domain:" + domain)
                            if domain_source and self.check(domain_source, {"action": "cloudtasks.tasks.create"}, queue):
                                uncertain = True
                    clear_override = (self.check(source, {"action": "cloudtasks.queues.update"}, queue)
                                      if key == "gcp_cloudtasks_queue_policy_path" and override is True else None)
                    usable_target = override is False or (clear_override is not None and
                                                           clear_override.confidence != "unknown")
                    if state == "RUNNING" and usable_target:
                        if not uncertain:
                            out[tid] = ("conditional", "new_task_creation_access_on_running_queue"
                                        if key == "gcp_cloudtasks_queue_policy_path" else "existing_running_queue")
                            break
                        unresolved = True
                        continue
                    resume = (self.check(source, {"action": "cloudtasks.queues.resume"}, queue)
                              if state == "PAUSED" and usable_target else None)
                    if resume:
                        if not uncertain and resume.confidence != "unknown":
                            out[tid] = ("conditional", "new_task_creation_access_on_resumable_queue"
                                        if key == "gcp_cloudtasks_queue_policy_path" else "paused_queue_can_be_resumed")
                            break
                        unresolved = True
                        continue
                    unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "queue_state_or_override_unresolved")
            return out
        if key == "gcp_cloudtasks_authenticated_delivery":
            if value is not True:
                return {}
            out = {}
            project_numbers = {"projects/" + pid: number for number, pid in self.project_alias.items()}
            for tid, target in candidates.items():
                project = target.scope
                number = project_numbers.get(project)
                if not number:
                    out[tid] = ("unknown", "tasks_service_agent_project_number_unresolved")
                    continue
                agent_id = f"serviceAccount:service-{number}@gcp-sa-cloudtasks.iam.gserviceaccount.com"
                has_role = any(scope in self.ancestors(project) and role == "roles/cloudtasks.serviceAgent"
                               for scope, role, _, _ in self.grants.get(agent_id, ()))
                if not has_role:
                    out[tid] = ("unknown", "tasks_service_agent_role_not_recorded")
                    continue
                agent = self.principals.get(agent_id)
                access = (self.check(agent, {"action": "iam.serviceAccounts.actAs"}, target.attrs.get("resource"))
                          if agent is not None else None)
                out[tid] = (("conditional", "tasks_service_agent_target_access_recorded") if access and
                            access.confidence != "unknown" else
                            ("unknown", "tasks_service_agent_target_access_unresolved"))
            return out
        if key == "gcp_cloudscheduler_update_job_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                unresolved = self.scheduler_job_status.get(project) not in ("collected", "empty")
                for job, state, _ in self.scheduler_jobs_by_project.get(project, ()):
                    update = self.check(source, {"action": "cloudscheduler.jobs.update"}, job)
                    if update is None:
                        continue
                    if state == "ENABLED":
                        out[tid] = ("conditional", "existing_enabled_scheduler_job")
                        break
                    if state == "UPDATE_FAILED":
                        out[tid] = ("conditional", "failed_scheduler_job_can_be_recovered_by_update")
                        break
                    if state == "PAUSED" and self.check(source, {"action": "cloudscheduler.jobs.enable"}, job):
                        out[tid] = ("conditional", "paused_scheduler_job_can_be_resumed")
                        break
                    unresolved = True
                if tid not in out and unresolved:
                    out[tid] = ("unknown", "scheduler_job_or_state_unresolved")
            return out
        if key == "gcp_cloudscheduler_authenticated_delivery":
            if value is not True:
                return {}
            out = {}
            project_numbers = {"projects/" + pid: number for number, pid in self.project_alias.items()}
            for tid, target in candidates.items():
                project = target.scope
                number = project_numbers.get(project)
                if not number:
                    out[tid] = ("unknown", "scheduler_service_agent_project_number_unresolved")
                    continue
                agent = f"serviceAccount:service-{number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
                if any(scope in self.ancestors(project) and role == "roles/cloudscheduler.serviceAgent"
                       for scope, role, _, _ in self.grants.get(agent, ())):
                    out[tid] = ("conditional", "scheduler_service_agent_role_recorded")
                else:
                    out[tid] = ("unknown", "scheduler_service_agent_role_not_recorded")
            return out
        if key == "gcp_workflows_observed_external_execution":
            if value is not True or source is None:
                return {}
            out = {}
            project_numbers = {"projects/" + pid: number for number, pid in self.project_alias.items()}
            for tid, target in candidates.items():
                can_update = False
                scheduler_agent_unresolved = False
                for workflow in self.hosts.get(target.attrs.get("email"), {}).get("workflows_workflow", ()):
                    if self.check(source, {"action": "workflows.workflows.update"}, workflow) is None:
                        continue
                    can_update = True
                    endpoint = f"https://workflowexecutions.googleapis.com/v1/{workflow}/executions"
                    for job_project, jobs in self.scheduler_jobs_by_project.items():
                        for _, state, job in jobs:
                            http = job.get("httpTarget") or {}
                            token = http.get("oauthToken") or {}
                            email = token.get("serviceAccountEmail")
                            if (state != "ENABLED" or http.get("uri") != endpoint or
                                    http.get("httpMethod") != "POST" or
                                    token.get("scope") not in (None, "", "https://www.googleapis.com/auth/cloud-platform") or
                                    not isinstance(email, str) or "@" not in email):
                                continue
                            invoker = self.sas.get("serviceAccount:" + email)
                            if (invoker is not None and invoker.scope == job_project and
                                    self.check(invoker, {"action": "workflows.executions.create"}, workflow)):
                                number = project_numbers.get(job_project)
                                agent = (f"serviceAccount:service-{number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
                                         if number else None)
                                if not agent or not any(
                                        scope in self.ancestors(job_project) and role == "roles/cloudscheduler.serviceAgent"
                                        for scope, role, _, _ in self.grants.get(agent, ())):
                                    scheduler_agent_unresolved = True
                                    continue
                                out[tid] = ("conditional", "observed_scheduler_execution_of_updated_workflow")
                                break
                        if tid in out:
                            break
                    if tid in out:
                        break
                if can_update and tid not in out:
                    out[tid] = ("unknown", "scheduler_service_agent_role_not_recorded" if
                                scheduler_agent_unresolved else "external_execution_not_observed")
                if tid not in out and any(
                        self.host_status.get((project, "workflows_workflow")) not in ("collected", "empty")
                        for project in (self.scopes | {scope for scope, host in self.host_status
                                                       if host == "workflows_workflow"})
                        if str(project).startswith("projects/")):
                    out[tid] = ("unknown", "workflows_inventory_incomplete")
            return out
        if key == "gcp_workflows_update_attach_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                project = target.scope
                for workflow in self.workflows_by_project.get(project, ()):
                    update = self.check(source, {"action": "workflows.workflows.update"}, workflow)
                    execute = self.check(source, {"action": "workflows.executions.create"}, workflow)
                    if update is not None and execute is not None:
                        out[tid] = ("conditional", "exact_existing_workflow_replacement")
                        break
                if tid not in out and self.host_status.get((project, "workflows_workflow")) not in ("collected", "empty"):
                    out[tid] = ("unknown", "workflows_inventory_incomplete")
            return out
        if key == "gcp_workflows_update_execute_same_workflow":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                for workflow in self.hosts.get(email, {}).get("workflows_workflow", ()):
                    update = self.check(source, {"action": "workflows.workflows.update"}, workflow)
                    execute = self.check(source, {"action": "workflows.executions.create"}, workflow)
                    if update is not None and execute is not None:
                        out[tid] = ("conditional", "exact_workflow_update_and_execution")
                        break
                if tid not in out and any(
                        self.host_status.get((project, "workflows_workflow")) not in ("collected", "empty")
                        for project in (self.scopes | {scope for scope, host in self.host_status
                                                       if host == "workflows_workflow"})
                        if str(project).startswith("projects/")):
                    out[tid] = ("unknown", "workflows_inventory_incomplete")
            return out
        if key == "gcp_workstations_create_config_path":
            if value is not True or source is None:
                return {}
            out = {}
            cluster_status = {self._norm_scope(scope): state for scope, state in
                              inventory_status(self.snapshot, "workstations_cluster").items()}
            for tid, target in candidates.items():
                project = target.scope
                for cluster in self.workstation_clusters_by_project.get(project, ()):
                    if (self.check(source, {"action": "workstations.workstationConfigs.create"}, cluster) and
                            self.check(source, {"action": "workstations.workstations.create"}, cluster)):
                        out[tid] = ("conditional", "existing_workstation_cluster_create_path")
                        break
                if tid not in out and all(self.check(source, {"action": action}, project)
                                          for action in ("workstations.workstationClusters.create",
                                                         "workstations.workstationConfigs.create",
                                                         "workstations.workstations.create")):
                    out[tid] = ("conditional", "new_workstation_cluster_create_path")
                if tid not in out and cluster_status.get(project) not in ("collected", "empty"):
                    out[tid] = ("unknown", "workstation_cluster_inventory_incomplete")
            return out
        if key in ("gcp_workstations_use_existing_path", "gcp_workstations_create_from_config_path"):
            if value is not True or source is None:
                return {}
            out = {}
            host = ("workstations_workstation" if key == "gcp_workstations_use_existing_path"
                    else "workstations_config")
            for tid, target in candidates.items():
                email = target.attrs.get("email")
                for resource in self.hosts.get(email, {}).get(host, ()):
                    config_name = (resource.rsplit("/workstations/", 1)[0]
                                   if host == "workstations_workstation" else resource)
                    config = self.workstation_configs.get(config_name)
                    if config is None:
                        continue
                    if config["scopes"] and not self.check(source, {"action": "iam.serviceAccounts.actAs"},
                                                            target.attrs.get("resource")):
                        continue
                    if key == "gcp_workstations_create_from_config_path":
                        if self.check(source, {"action": "workstations.workstations.create"}, resource):
                            out[tid] = ("conditional", "new_workstation_creator_receives_user_role")
                            break
                        continue
                    state = self.workstation_rows.get(resource, {}).get("state")
                    use = self.check(source, {"action": "workstations.workstations.use"}, resource)
                    start = self.check(source, {"action": "workstations.workstations.start"}, resource)
                    policy = self.check(source, {"action": "workstations.workstations.setIamPolicy"}, resource)
                    config_policy = self.check(source, {"action": "workstations.workstationConfigs.setIamPolicy"},
                                               config_name)
                    if policy or config_policy or (use and (state == "STATE_RUNNING" or start)):
                        out[tid] = ("conditional", "exact_workstation_session_or_policy_path")
                        break
                if tid not in out and self.host_status.get((target.scope, host)) not in ("collected", "empty"):
                    out[tid] = ("unknown", "workstations_inventory_incomplete")
            return out
        if key == "gcp_bounded_workspace_oauth":
            return {tid: None for tid in candidates
                    if tid.startswith(f"gcp_verified_authority:workspace_oauth:{value}:")}
        if key == "gcp_bounded_service_execution":
            if value == "bigquery_scheduled_query":
                from .gcp_bigquery_scheduled_query import select
                return select(self, candidates, source)
            if value == "bigquery_continuous_query":
                from .gcp_bigquery_continuous_query import select
                return select(self, candidates, source)
            if value == "dataform_workflow":
                from .gcp_dataform_workflow import select
                return select(self, candidates, source)
            return {tid: None for tid, node in candidates.items()
                    if tid.startswith(f"gcp_verified_authority:{value}:")}
        if key == "gcp_hmac_storage_identity":
            if value is not True:
                return {}
            out = {}
            for tid, target in candidates.items():
                if target.kind != "gcp_verified_authority":
                    continue
                sa = self.sas.get("serviceAccount:" + str(target.attrs.get("email") or ""))
                if (sa is not None and tid == f"gcp_verified_authority:hmac:{sa.id}"
                        and not sa.attrs.get("disabled") and not self.service_managed(sa)):
                    out[tid] = None
            return out
        if key == "gcp_cross_project_run_job":
            return (self._cross_project_sa_attachment(candidates, source, ("run.jobs.create", "run.jobs.run"),
                                                      "serverless-robot-prod.iam.gserviceaccount.com", "run_job")
                    if value is True and source is not None else {})
        if key == "gcp_cross_project_run_service":
            return (self._cross_project_sa_attachment(candidates, source, ("run.services.create",),
                                                      "serverless-robot-prod.iam.gserviceaccount.com", "run_service")
                    if value is True and source is not None else {})
        if key == "gcp_cross_project_run_instance":
            return (self._cross_project_sa_attachment(candidates, source, (),
                                                      "serverless-robot-prod.iam.gserviceaccount.com", "run_instance")
                    if value is True and source is not None else {})
        if key == "gcp_cross_project_cloudbuild":
            return (self._cross_project_sa_attachment(candidates, source, ("cloudbuild.builds.create",),
                                                      "gcp-sa-cloudbuild.iam.gserviceaccount.com", "cloudbuild")
                    if value is True and source is not None else {})
        if key == "gcp_cross_project_workflows":
            return (self._cross_project_sa_attachment(candidates, source,
                                                      ("workflows.workflows.create", "workflows.executions.create"),
                                                      "gcp-sa-workflows.iam.gserviceaccount.com", "workflows")
                    if value is True and source is not None else {})
        if key == "gcp_clouddeploy_custom_render_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                if target.attrs.get("disabled"):
                    continue
                paths = self.clouddeploy_render_paths.get(target.attrs.get("email"), ())
                for pipeline, custom_type in paths:
                    update = self.check(source, {"action": "clouddeploy.customTargetTypes.update"}, custom_type)
                    release = self.check(source, {"action": "clouddeploy.releases.create"}, pipeline)
                    if update is not None and release is not None:
                        pipeline_project = "/".join(pipeline.split("/")[:2])
                        if (pipeline_project == target.scope and update.confidence == "derived"
                                and release.confidence == "derived"):
                            out[tid] = ("conditional", "custom_target_render_requires_valid_source_and_runtime")
                            break
                        out[tid] = ("unknown", "cross_project_or_conditioned_clouddeploy_authority_unresolved")
                if tid not in out and self.clouddeploy_render_incomplete:
                    out[tid] = ("unknown", "clouddeploy_pipeline_target_or_type_inventory_incomplete")
            return out
        if key == "gcp_clouddeploy_existing_custom_render_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                if target.attrs.get("disabled"):
                    continue
                email = target.attrs.get("email")
                paths = ([(pipeline, False) for pipeline in self.clouddeploy_existing_render_paths.get(email, ())]
                         + [(pipeline, True) for pipeline in
                            self.clouddeploy_existing_render_uncertain_paths.get(email, ())])
                for pipeline, source_uncertain in paths:
                    release = self.check(source, {"action": "clouddeploy.releases.create"}, pipeline)
                    if release is not None:
                        pipeline_project = "/".join(pipeline.split("/")[:2])
                        if (pipeline_project == target.scope and release.confidence == "derived"
                                and not source_uncertain):
                            out[tid] = ("conditional", "custom_render_requires_attacker_controlled_source_and_runner_access")
                            break
                        out[tid] = ("unknown", "custom_render_source_or_release_authority_unresolved")
                if tid not in out and self.clouddeploy_render_incomplete:
                    out[tid] = ("unknown", "clouddeploy_pipeline_target_or_type_inventory_incomplete")
            return out
        if key == "gcp_clouddeploy_pipeline_policy_custom_render_path":
            if value is not True or source is None:
                return {}
            out = {}
            for tid, target in candidates.items():
                if target.attrs.get("disabled"):
                    continue
                email = target.attrs.get("email")
                paths = ([(pipeline, False) for pipeline in self.clouddeploy_existing_render_paths.get(email, ())]
                         + [(pipeline, True) for pipeline in
                            self.clouddeploy_existing_render_uncertain_paths.get(email, ())])
                for pipeline, source_uncertain in paths:
                    authority = self.check(source, {"action": "clouddeploy.deliveryPipelines.setIamPolicy"}, pipeline)
                    if authority is None:
                        continue
                    pipeline_project = "/".join(pipeline.split("/")[:2])
                    prior = self.check(source, {"action": "clouddeploy.releases.create"}, pipeline)
                    if prior is not None and prior.confidence == "derived":
                        continue
                    org_status = inventory_status(self.snapshot, "org_policy_effective").get(pipeline_project)
                    constrained = any(
                        self._norm_scope(scope) == pipeline_project and item.get("constraint") in
                        ("iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers")
                        for scope, item in items(self.snapshot, "org_policy_effective"))
                    if (pipeline_project == target.scope and not source_uncertain
                            and authority.confidence == "derived" and prior is None
                            and self.resource_policy_status.get("clouddeploy_delivery_pipeline", {}).get(pipeline)
                            == "collected" and org_status in ("collected", "empty") and not constrained):
                        out[tid] = ("conditional", "self_granted_release_requires_accepted_binding_and_valid_source")
                        break
                    out[tid] = ("unknown", "pipeline_policy_or_binding_or_render_source_unresolved")
                if tid not in out and self.clouddeploy_render_incomplete:
                    out[tid] = ("unknown", "clouddeploy_pipeline_target_or_type_inventory_incomplete")
            return out
        if key == "gcp_clouddeploy_configurable_custom_render_path":
            if value is not True or source is None:
                return {}
            out = {}
            inventory = {kind: {self._norm_scope(scope): state for scope, state in
                        inventory_status(self.snapshot, kind).items()}
                        for kind in ("clouddeploy_delivery_pipeline", "clouddeploy_target",
                                     "clouddeploy_custom_target_type")}
            def authority(action, ref):
                grant = self.check(source, {"action": action}, ref)
                return 2 if grant is not None and grant.confidence == "derived" else 1 if grant else 0
            def new_resource(kind, project):
                # PATCH with allowMissing can create a resource using update permission.
                return max(authority(f"clouddeploy.{kind}.create", project),
                           authority(f"clouddeploy.{kind}.update", project))
            def viable_project(project):
                new_type = new_resource("customTargetTypes", project)
                existing_type = 2 if self.clouddeploy_render_types_by_project.get(project) else 0
                new_target = new_resource("targets", project)
                new_pipeline = new_resource("deliveryPipelines", project)
                new_release = authority("clouddeploy.releases.create", project)
                viable = min(max(existing_type, new_type), new_target, new_pipeline, new_release)
                for pipeline in self.clouddeploy_pipelines_by_project.get(project, ()):
                    location = pipeline.split("/deliveryPipelines/", 1)[0]
                    same_location_type = 2 if any(
                        custom.startswith(location + "/customTargetTypes/")
                        for custom in self.clouddeploy_render_types_by_project.get(project, ())) else 0
                    viable = max(viable, min(
                        max(new_type, same_location_type), new_target,
                        authority("clouddeploy.deliveryPipelines.update", pipeline),
                        authority("clouddeploy.releases.create", pipeline)))
                for pipeline, target_name in self.clouddeploy_render_pipeline_targets_by_project.get(project, ()):
                    viable = max(viable, min(
                        authority("clouddeploy.targets.update", target_name),
                        authority("clouddeploy.releases.create", pipeline)))
                for target_name in self.clouddeploy_render_targets_by_project.get(project, ()):
                    viable = max(viable, min(
                        new_pipeline, new_release,
                        authority("clouddeploy.targets.update", target_name)))
                if viable == 2 and any(
                        state.get(project) not in ("collected", "empty") for state in inventory.values()):
                    return 1
                return viable
            viable_projects = {project: score for project in self.scopes
                               if project.startswith("projects/")
                               if (score := viable_project(project))}
            for tid, target in candidates.items():
                if target.attrs.get("disabled") or not target.scope.startswith("projects/"):
                    continue
                if viable_projects.get(target.scope) == 2:
                    out[tid] = ("conditional", "clouddeploy_configuration_and_source_must_be_accepted")
                elif viable_projects:
                    out[tid] = ("unknown", "cross_project_or_conditioned_clouddeploy_authority_unresolved")
                elif self.clouddeploy_render_incomplete:
                    out[tid] = ("unknown", "clouddeploy_pipeline_target_or_type_inventory_incomplete")
            return out
        if key in ("gcp_cloudbuild_writable_trigger_token_path",
                   "gcp_cloudbuild_writable_trigger_policy_path"):
            if value is not True or source is None:
                return {}
            action = ("cloudbuild.repositories.accessReadWriteToken"
                      if key == "gcp_cloudbuild_writable_trigger_token_path"
                      else "cloudbuild.connections.setIamPolicy")
            out = {}
            for tid, target in candidates.items():
                if target.attrs.get("disabled"):
                    continue
                for repo, connection, project, needs_review in self.cloudbuild_writable_trigger_paths.get(
                        target.attrs.get("email"), ()):
                    resource = repo if key == "gcp_cloudbuild_writable_trigger_token_path" else connection
                    authority = self.check(source, {"action": action}, resource)
                    if authority is None:
                        continue
                    if project != target.scope:
                        out[tid] = ("unknown", "cross_project_cloudbuild_trigger_identity_unresolved")
                    elif needs_review or authority.confidence != "derived":
                        out[tid] = ("unknown", "cloudbuild_trigger_filter_or_approval_requires_review")
                    elif key == "gcp_cloudbuild_writable_trigger_policy_path":
                        repo_project = repo.split("/locations/", 1)[0]
                        prior = self.check(source, {"action": "cloudbuild.repositories.accessReadWriteToken"}, repo)
                        constrained = any(
                            self._norm_scope(scope) == repo_project and item.get("constraint") in
                            ("iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers")
                            for scope, item in items(self.snapshot, "org_policy_effective"))
                        if prior is not None and prior.confidence == "derived":
                            continue
                        if (self.resource_policy_status.get("cloudbuild_connection", {}).get(connection) != "collected"
                                or prior is not None
                                or inventory_status(self.snapshot, "org_policy_effective").get(repo_project)
                                not in ("collected", "empty")
                                or constrained):
                            out[tid] = ("unknown", "connection_policy_or_prior_token_access_unresolved")
                        else:
                            out[tid] = ("conditional", "exact_connection_policy_self_grant_and_trigger")
                    else:
                        out[tid] = ("conditional", "scm_ref_write_and_build_source_must_be_usable")
                    if out[tid][0] == "conditional":
                        break
                if tid not in out and self.cloudbuild_trigger_incomplete:
                    out[tid] = ("unknown", "cloudbuild_trigger_or_identity_inventory_incomplete")
            return out
        if key == "gcp_external_plane":
            return {ident: ("conditional", "reviewed_external_plane") for ident, node in candidates.items()
                    if node.attrs.get("external_plane") == value}
        if key == "gcp_external_principal_evidence":
            from .gcp_external_principal import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_firebase_apphosting_retarget":
            from .gcp_firebase_apphosting_retarget import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_agentregistry_skill_evidence":
            from .gcp_agentregistry_skill import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_resource_self_grant":
            from .gcp_resource_self_grant import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_project_iam_sa_token_grant":
            from .gcp_project_iam_sa_token import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_eventarc_oauth_pipeline_path":
            from .gcp_eventarc_oauth import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_privatecatalog_dm_iam_path":
            from .gcp_privatecatalog_dm import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_kcc_project_policy_grant":
            from .gcp_config_connector import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_kcc_generated_key_secret":
            from .gcp_config_connector_key import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_configdelivery_fleet_target":
            from .gcp_config_delivery import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_fleet_config_management_target":
            from .gcp_fleet_config_management import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_fleet_rbac_admin_target":
            from .gcp_fleet_rbac import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_challenge_fact":
            if source is None:
                return None
            if value == _EXACT_RUNNING_POD_UPDATE:
                return self._running_pod_update_evidence(candidates, source)
            if value in _EXACT_TABLE_KEY_PERMISSIONS:
                out = {}
                permission = _EXACT_TABLE_KEY_PERMISSIONS[value][0]
                for candidate_id, node in candidates.items():
                    if candidate_id == source.id or node.kind != "gcp_service_account" or node.attrs.get("disabled"):
                        continue
                    records = self.challenge_evidence.get((value, source.id, node.kind,
                                                           candidate_id, node.scope), ())
                    if len(records) != 1:
                        continue
                    fact = records[0]
                    if not self._table_key_fact_bound(value, candidate_id, node.scope, fact):
                        continue
                    if fact.get("Status") == "disproven":
                        continue
                    if (fact.get("Status") != "verified" or fact.get("VerifiedPreconditions") is not True
                            or fact.get("CredentialUsable") is not True
                            or not isinstance(fact.get("EvidenceRef"), str) or not fact["EvidenceRef"]):
                        out[candidate_id] = ("unknown", "table_key_subject_or_usability_unverified")
                        continue
                    grant = self.check(source, {"action": permission}, fact["CredentialResource"])
                    if grant is not None:
                        out[candidate_id] = (("unknown", "table_resource_permission_incomplete")
                                             if grant.confidence == "unknown" else
                                             ("conditional", "exact_table_key_subject_and_resource"))
                return out
            out = {}
            for candidate_id, node in candidates.items():
                target = node.attrs.get("resource") if node.kind == "gcp_verified_authority" else node.id
                records = self.challenge_evidence.get((value, source.id, node.kind, target, node.scope), ())
                if not records:
                    continue
                states = [st for s, st in self.challenge_status.items() if self._norm_scope(s) == node.scope]
                if not states or any(st not in ("collected", "empty") for st in states):
                    out[candidate_id] = ("unknown", "challenge_evidence_collection_incomplete")
                    continue
                # Conflicting records cannot establish a path. A complete, sole verified
                # record is still conditional because later execution may be required.
                from .principal_evidence import CONTRACT as principal_contract, valid as principal_valid, check_bindings
                if value in principal_contract:
                    if (len(records) == 1 and not node.incomplete
                            and principal_valid(self.snapshot, value, records[0], source.id, node.id, node.scope)
                            and check_bindings(self, value, records[0], source)):
                        out[candidate_id] = ("conditional", "exact_full_principal_authority_verified")
                    elif any(r.get("Status") != "disproven" for r in records):
                        out[candidate_id] = ("unknown", "full_principal_authority_or_resource_binding_unverified")
                    continue
                from .bounded_evidence import CONTRACT as bounded_contract, valid as bounded_valid
                if value in bounded_contract and (len(records) != 1 or not bounded_valid(value, records[0], source.id, target, node.scope)):
                    if any(r.get("Status") != "disproven" for r in records): out[candidate_id] = ("unknown", "bounded_effect_evidence_incomplete")
                    continue
                if len(records) == 1 and records[0].get("Status") == "verified" and records[0].get("VerifiedPreconditions") is True:
                    out[candidate_id] = ("conditional", "exact_challenge_evidence")
                elif any(r.get("Status") != "disproven" for r in records):
                    out[candidate_id] = ("unknown", "challenge_preconditions_incomplete")
            return out
        if key in ("k8s_sa_has_token_secret", "k8s_sa_in_cluster", "k8s_sa_used_by_running_pod"):
            return {tid: n.attrs.get("floor") for tid, n in candidates.items() if n.kind == "k8s_service_account"}
        if key == "attached_to_service":
            out = {}
            for tid, node in candidates.items():
                verdict = None
                for service in as_list(value):
                    service = str(service).lower()
                    if service in VERTEX_DEFAULT_AGENTS:
                        status = self.vertex_agent_status.get((node.id, service))
                        if status == "yes":
                            verdict = "yes"
                            break
                        if status == "unknown":
                            verdict = verdict or "unknown"
                        continue
                    host = SERVICE_HOSTS.get(service)
                    email = node.attrs.get("email")
                    if host and self.hosts.get(email, {}).get(host):
                        if service == "firebase_apphosting_backend":
                            usable = any(
                                role == "roles/firebaseapphosting.computeRunner"
                                and bound_scope in self.ancestors(backend.rsplit("/locations/", 1)[0])
                                and not condition
                                for backend in self.hosts[email][host]
                                for bound_scope, role, condition, _ in node.attrs.get("grants", ()))
                            if not usable:
                                verdict = verdict or "unknown"
                                continue
                        verdict = "yes"
                        break
                    if host in ("workflows_workflow", "cloudrun_job") and any(
                            self.host_status.get((project, host)) not in ("collected", "empty")
                            for project in (self.scopes | {scope for scope, name in self.host_status
                                                           if name == host})
                            if str(project).startswith("projects/")):
                        verdict = verdict or "unknown"
                    if not host or self.host_status.get((node.scope, host)) not in ("collected", "empty"):
                        verdict = verdict or "unknown"
                        if not host:
                            self._note_uncollected_attachment(str(service).lower())
                if verdict == "yes":
                    out[tid] = None
                elif verdict == "unknown":
                    out[tid] = ("unknown", "attachment_inventory_not_collected")
            return out
        if key == "gcp_sourcerepo_trigger_path":
            if source is None or value not in ("push", "selfgrant"):
                return {}
            from .gcp_bigquery_spark import _new_permission
            action = "source.repos.update" if value == "push" else "source.repos.setIamPolicy"
            out = {}
            for tid, target in candidates.items():
                if target.kind != "gcp_service_account" or target.id == source.id or target.attrs.get("disabled"):
                    continue
                gain = _new_permission(self, source, target)
                if gain == "no":
                    continue
                paths = self.sourcerepo_trigger_paths.get(target.attrs.get("email"), ())
                for repo, review in paths:
                    grant = self.check(source, {"action": action}, repo)
                    if grant is None:
                        continue
                    if value == "selfgrant":
                        prior = self.check(source, {"action": "source.repos.update"}, repo)
                        if prior is not None and prior.confidence == "derived":
                            continue
                    if grant.confidence != "derived" or review or gain != "yes":
                        out[tid] = ("unknown", "sourcerepo_trigger_or_source_authority_requires_review")
                    else:
                        out[tid] = ("conditional", "push_ref_and_repository_content_must_trigger_build")
                        break
            return out
        if key == "same_as_source":
            if candidates and next(iter(candidates.values())).entity:
                return {tid: None for tid in candidates}
            return {source.id: None} if source.id in candidates else {}
        if key == "gcp_gke_clusterrole_bind":
            if value is not True:
                return {}
            from .gcp_gke_clusterrole_bind import select
            return select(self, candidates, source)
        if key == "gcp_gke_clusterrole_escalate":
            if value is not True:
                return {}
            from .gcp_gke_clusterrole_escalate import select
            return select(self, candidates, source)
        if key == "gcp_gke_system_impersonation":
            if value is not True:
                return {}
            from .gcp_gke_system_impersonation import select
            return select(self, candidates, source)
        if key == "gcp_gke_node_sa_actas":
            if value is not True:
                return {}
            from .gcp_gke_node_sa_actas import select
            return select(self, candidates, source)
        if key == "gcp_gke_webhook_ksa_path":
            if value is not True:
                return {}
            from .gcp_gke_webhook_ksa_path import select
            return select(self, candidates, source)
        if key == "gcp_gke_namespaced_rbac_ksa_path":
            if value is not True:
                return {}
            from .gcp_gke_namespaced_rbac_ksa_path import select
            return select(self, candidates, source)
        if key == "gcp_gke_node_proxy_sa":
            if value is not True:
                return {}
            from .gcp_gke_node_proxy_sa import select
            return select(self, candidates, source)
        if key == "gcp_gke_node_proxy_ksa":
            if value is not True:
                return {}
            from .gcp_gke_node_proxy_ksa import select
            return select(self, candidates, source)
        if key == "gcp_gke_pod_template_ksa":
            if value is not True:
                return {}
            from .gcp_gke_pod_template_ksa import select
            return select(self, candidates, source)
        if key == "gcp_gke_pod_template_node_sa":
            if value is not True:
                return {}
            from .gcp_gke_pod_template_node_sa import select
            return select(self, candidates, source)
        if key == "gcp_gke_pod_exec_node_sa":
            if value is not True:
                return {}
            from .gcp_gke_pod_exec_node_sa import select
            return select(self, candidates, source)
        if key == "gcp_gke_pod_exec_ksa":
            if value is not True:
                return {}
            from .gcp_gke_pod_exec_ksa import select
            return select(self, candidates, source)
        if key == "gcp_gke_pod_update_ksa":
            if value is not True:
                return {}
            from .gcp_gke_pod_update_ksa import select
            return select(self, candidates, source)
        if key == "gcp_gke_secret_ksa":
            if value is not True:
                return {}
            from .gcp_gke_secret_ksa import select
            return select(self, candidates, source)
        if key == "gcp_gke_token_request_ksa":
            if value is not True:
                return {}
            from .gcp_gke_token_request_ksa import select
            return select(self, candidates, source)
        if key == "gcp_gke_nodepool_metadata_downgrade":
            if value is not True:
                return {}
            from .gcp_gke_nodepool_metadata_downgrade import select
            return select(self, candidates, source)
        if key == "any_principal_in_scope":
            return dict.fromkeys(candidates)
        if key == "gcp_implicit_delegation_chain":
            if source is None:
                return None
            reach = self._delegation_targets(source)
            def why(grant):
                return next((c for c in grant.conditions if not c.startswith("delegate:")), "implicit_delegation_chain")
            return {tid: None if g.confidence == "derived" else (g.confidence, why(g)) for tid, g in reach.items() if tid in candidates}
        if key == "gcp_actas_granted_to_service_agent":
            domains = {"cloudservices": "@cloudservices.gserviceaccount.com"}
            suffix = domains.get(str(value).lower())
            agents = [n for m, n in self.principals.items() if suffix and m.lower().endswith(suffix)]
            if not agents:
                return {tid: ("unknown", "service_agent_bindings_not_collected") for tid in candidates}
            out = {}
            for agent in agents:
                for tid, grant in self._sas_with(agent, "iam.serviceaccounts.actas").items():
                    if tid in candidates and out.get(tid, 0) is not None:
                        why = (grant.conditions or ["service_agent_actas_" + grant.confidence])[0]
                        out[tid] = None if grant.confidence == "derived" else (grant.confidence, why)
            return out
        if key == "gcp_pam_entitlement_requester":
            return None
        if key == "gcp_group_join_open_to_source":
            return self._open_groups(candidates, source)
        if key == "gcp_workspace_super_admin_with_registered_domain":
            if not any(st in ("collected", "empty") for st in self.registrations_status.values()):
                return None
            ws_known = any(st in ("collected", "empty") for st in self.ws_status.values())
            out = {}
            for tid, node in candidates.items():
                email = str(node.attrs.get("email") or "").lower()
                if "super_admin" not in self.ws_admin.get(email, set()):
                    if not ws_known:
                        out[tid] = ("unknown", "workspace_admin_roles_not_collected")
                    continue
                customer = self.ws_customer_of_email.get(email)
                domain = self.ws_customer_domains.get(customer)
                if not domain:
                    out[tid] = ("unknown", "workspace_customer_primary_domain_not_collected")
                    continue
                registrations = self.registrations.get(domain, ())
                if any(state == "ACTIVE" for _, state in registrations):
                    out[tid] = None
                elif any(not state for _, state in registrations):
                    out[tid] = ("unknown", "domain_registration_state_not_collected")
            return out
        if key == "gcp_image_family_consumer":
            out = {}
            for tid, node in candidates.items():
                if self.image_families.get(node.attrs.get("email")):
                    out[tid] = None
                elif self.template_status.get(node.scope) not in ("collected", "empty"):
                    out[tid] = ("unknown", "instance_template_inventory_not_collected")
            return out
        if key == "gcp_custom_role_bound_to_source":
            if source is None or value is not True:
                return {}
            bound = {}
            for node, role_name, conditional, _ref in source.attrs.get("grants", ()):
                if (not str(role_name).startswith(("projects/", "organizations/"))
                        or "/roles/" not in role_name or role_name not in self._collected_roles):
                    continue
                parent = self._norm_scope(role_name.split("/roles/", 1)[0])
                if parent not in self.ancestors(node):
                    continue
                edit = self.check(source, {"action": "iam.roles.update"}, role_name)
                if edit is None:
                    continue
                verdict = (("unknown", "custom_role_binding_condition_unresolved") if conditional else
                           ("conditional", "custom_role_permission_addition_required"))
                bound[node] = verdict if node not in bound or bound[node][0] == "unknown" else bound[node]
            return {tid: bound[n.scope] for tid, n in candidates.items() if n.scope in bound}
        return None

    def _running_pod_update_evidence(self, candidates, source):
        """Bind a reviewed image-patch outcome to one inventoried running pod and its KSA."""
        out = {}
        for candidate_id, node in candidates.items():
            if (node.kind != "k8s_service_account" or node.attrs.get("aggregate")
                    or not node.attrs.get("related_snapshot")):
                continue
            cluster = node.attrs.get("gke_cluster")
            if not isinstance(cluster, str) or "/locations/" not in cluster:
                continue
            project = cluster.split("/locations/", 1)[0]
            records = self.challenge_evidence.get((
                _EXACT_RUNNING_POD_UPDATE, source.id, "k8s_service_account", candidate_id, project), ())
            if len(records) != 1:
                continue  # conflicting attestations cannot identify one execution
            states = [st for scope, st in self.challenge_status.items()
                      if self._norm_scope(scope) == project]
            if not states or any(st not in ("collected", "empty") for st in states):
                continue
            fact = records[0]
            if (fact.get("Status") != "verified" or fact.get("VerifiedPreconditions") is not True
                    or fact.get("AffectedCluster") != cluster
                    or fact.get("PodPatchAccepted") is not True
                    or fact.get("AdmissionAccepted") is not True
                    or fact.get("ImageExecuted") is not True
                    or fact.get("CredentialSubjectId") != candidate_id
                    or fact.get("CredentialKind") != "k8s_service_account_token"
                    or fact.get("CredentialAudience") != "kubernetes_api"
                    or fact.get("CredentialUsable") is not True
                    or not isinstance(fact.get("EvidenceRef"), str) or not fact["EvidenceRef"]):
                continue
            joined = (self.related_k8s or {}).get(cluster)
            if joined is None or cluster in self.__dict__.get("_ambiguous_k8s", ()):
                continue
            cid, snapshot = joined
            if node.attrs.get("cluster") != cid or unavailable(inventory_status(snapshot, "pod")):
                continue
            for _, pod in items(snapshot, "pod"):
                meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
                if (str((pod.get("provenance") or {}).get("cluster_id") or
                        meta.get("cluster_id") or (snapshot.get("metadata") or {}).get("cluster_id") or cid) != cid
                        or (pod.get("status") or {}).get("phase") != "Running"
                        or meta.get("namespace") != node.attrs.get("namespace")
                        or (spec.get("serviceAccountName") or spec.get("serviceAccount") or "default") != node.attrs.get("name")
                        or meta.get("namespace") != fact.get("AffectedPodNamespace")
                        or meta.get("name") != fact.get("AffectedPodName")
                        or not isinstance(meta.get("uid"), str) or not meta["uid"]
                        or meta["uid"] != fact.get("AffectedPodUid")):
                    continue
                grant = self.check(source, {"action": "container.pods.update"}, cluster)
                if grant is not None and grant.confidence != "unknown":
                    out[candidate_id] = ("conditional", "exact_running_pod_patch_and_ksa")
                break
        return out

    def _note_uncollected_attachment(self, service):
        noted = self.__dict__.setdefault("_attachment_noted", set())
        if service in noted:
            return
        noted.add(service)
        known = service in UNCOLLECTED_ATTACHMENTS
        self.add_coverage("selector", "*", "not_collected" if known else "unsupported",
                          f"attached_to_service {service} " + ("attachment inventory not collected" if known else "is not a known value"),
                          "Matching service accounts are reported as one unresolved placeholder per scope")

    def _open_groups(self, candidates, source):
        """Groups whose Groups Settings let the source join without approval. Settings are not collected by
        default: with none collected the technique is reported in coverage and yields no edges (an unresolved
        placeholder for every user x group would drown the graph)."""
        if not self.group_settings:
            if not self.__dict__.get("_group_settings_noted"):
                self._group_settings_noted = True
                self.add_coverage("selector", "*", "not_collected", "gcp_group_join_open_to_source not evaluated",
                                  "Self-join of open Google Groups is not evaluated; needs "
                                  + FACTS_NEEDED["gcp_group_join_open_to_source"])
            return {}
        if source is None:
            return None
        mine = _email_domain(source.attrs.get("email"))
        out = {}
        for tid, node in candidates.items():
            settings = self.group_settings.get(str(node.attrs.get("email") or "").lower())
            if settings is None:
                out[tid] = ("unknown", "group_settings_not_collected")
                continue
            who, external = settings
            same = bool(mine) and mine == _email_domain(node.attrs.get("email"))
            if who == "ANYONE_CAN_JOIN" and (same or external):
                out[tid] = None
            elif who == "ANYONE_CAN_JOIN" and external is None:
                out[tid] = ("conditional", "allow_external_members_not_collected")
            elif who == "ALL_IN_DOMAIN_CAN_JOIN" and same:
                out[tid] = ("conditional", "same_email_domain_assumed_same_customer")
        return out

    def _sas_with(self, principal, perm):
        """{SA principal id: Grant} for every collected SA on which the principal holds perm (allow + deny)."""
        key = ("sas_with", principal.perm_key, perm)
        if key not in self._check_cache:
            under = self.__dict__.get("_sas_under")
            if under is None:
                under = self._sas_under = {}
                for sa in self.sas.values():
                    for node in self.ancestors(sa.attrs["resource"]):
                        under.setdefault(node, []).append(sa)
            out = {}
            for node in self.holders(principal, perm):
                for sa in under.get(node, ()):
                    if sa.id in out and out[sa.id].confidence == "derived":
                        continue
                    grant = self.check(principal, {"permission": perm}, sa.attrs["resource"])
                    if grant is not None:
                        out[sa.id] = grant
            self._check_cache[key] = out
        return self._check_cache[key]

    def _delegation_targets(self, source):
        """SAs reachable through an implicitDelegation chain starting at the source (delegates excluded)."""
        key = ("delegation", source.perm_key, source.id)
        if key in self._check_cache:
            return self._check_cache[key]
        reach, visited = {}, set()
        frontier = {d: Grant(g.confidence, g.refs, g.conditions + (f"delegate:{self.sas[d].attrs['email']}",))
                    for d, g in self._sas_with(source, DELEGATE_PERM).items() if d != source.id}
        depth = 0
        while frontier and depth < MAX_DELEGATION_DEPTH:
            depth += 1
            following = {}
            for delegate_id, chain in frontier.items():
                if delegate_id in visited:
                    continue
                visited.add(delegate_id)
                delegate = self.sas[delegate_id]
                if delegate.attrs.get("disabled"):
                    can_enable = self.check(source, {"action": "iam.serviceAccounts.enable"},
                                            delegate.attrs["resource"])
                    if can_enable is None:
                        continue
                    chain = downgrade(combine(chain, can_enable), "conditional", "delegate_service_account_disabled")
                for perm in MINT_PERMS:
                    for target_id, grant in self._sas_with(delegate, perm).items():
                        if target_id == source.id:
                            continue
                        reach[target_id] = best(reach.get(target_id), combine(chain, grant))
                for next_id, grant in self._sas_with(delegate, DELEGATE_PERM).items():
                    if next_id not in visited and next_id != source.id:
                        step = combine(chain, grant)
                        following[next_id] = best(following.get(next_id), Grant(
                            step.confidence, step.refs, step.conditions + (f"delegate:{self.sas[next_id].attrs['email']}",)))
            frontier = following
        self._check_cache[key] = reach
        return reach

    def admin_targets(self, principal):
        found = {}
        for node, role_name, conditional, ref in principal.attrs["grants"]:
            kind = node.split("/", 1)[0]
            perm = ADMIN_PERMS.get(kind)
            role = self.roles.get(role_name)
            if not perm or role is None or "/serviceAccounts/" in node or node.startswith("//") or not role.has(perm):
                continue
            grant = self.check(principal, {"permission": perm}, node)
            if grant is not None:
                found[node] = Grant(grant.confidence, grant.refs, grant.conditions,
                    [{"permission": perm.replace(".setiampolicy", ".setIamPolicy"), "grant": ref} for ref in grant.refs if "role" in ref])
        # Keep only the top-most scopes.
        top = {n: g for n, g in found.items() if not any(a in found for a in self.ancestors(n)[1:])}
        return [(self.entity(n), g) for n, g in sorted(top.items())]

    def scope_within(self, inner, outer):
        return outer in self.ancestors(inner)

    def scope_containers(self, inner):
        """{outer : scope_within(inner, outer)}, i.e. the ancestor chain (lets the evaluator test containment from
        the inner side instead of pairing every placeholder scope with every dominating scope)."""
        return frozenset(self.ancestors(inner))


def _gke_resource(item, scope):
    """projects/<project>/locations/<location>/clusters/<name> for a container.googleapis.com cluster item."""
    link = str(item.get("selfLink") or "")
    if "/projects/" in link and "/clusters/" in link:
        path = "projects/" + link.split("/projects/", 1)[1]
        return path.replace("/zones/", "/locations/")
    name, location = item.get("name"), item.get("location") or item.get("zone")
    project = str(scope or "")
    if not (name and location and project.startswith("projects/")):
        return None
    return f"{project}/locations/{location}/clusters/{name}"


_CUSTOMER_SA_DOMAINS = ("developer.gserviceaccount.com", "appspot.gserviceaccount.com")


def _email_domain(email):
    email = str(email or "").lower()
    return email.rsplit("@", 1)[1] if "@" in email else ""


def _google_managed(email):
    email = str(email or "").lower()
    local, _, domain = email.partition("@")
    if not domain.endswith("gserviceaccount.com"):
        return False
    if re.fullmatch(r"service-\d+", local) or domain.startswith("gcp-sa-"):
        return True
    if domain.endswith(".iam.gserviceaccount.com"):
        return False  # user-managed: <name>@<project>.iam.gserviceaccount.com
    return domain not in _CUSTOMER_SA_DOMAINS  # cloudservices, cloudbuild, container-engine-robot, ...


def _instance_resource(item, scope):
    """projects/<p>/zones/<z>/instances/<name> for a compute instance item."""
    link = str(item.get("selfLink") or "")
    if "/projects/" in link and "/instances/" in link:
        return "projects/" + link.split("/projects/", 1)[1]
    zone = str(item.get("zone") or "").rstrip("/").rsplit("/", 1)[-1]
    project = scope.split("/", 1)[-1] if str(scope).startswith("projects/") else None
    if project and zone and item.get("name"):
        return f"projects/{project}/zones/{zone}/instances/{item['name']}"
    return None


def _freeze(ref):
    return tuple(sorted(ref.items()))


def _sa_from_cai(name):
    # //iam.googleapis.com/projects/<p>/serviceAccounts/<email|id>
    parts = name.split("/")
    if len(parts) >= 7 and parts[2] == "iam.googleapis.com" and parts[3] == "projects" and parts[5] == "serviceAccounts":
        return parts[4], parts[6]
    return None


def _deny_perm_match(pattern, perm):
    # deny policies use "iam.googleapis.com/serviceAccounts.actAs" style names.
    pattern = str(pattern)
    if "/" in pattern:
        service, _, rest = pattern.partition("/")
        pattern = service.split(".", 1)[0] + "." + rest
    return glob_match(pattern.lower(), perm)


def _deny_member(principal, members):
    for member in as_list(members):
        member = str(member)
        if member in ("principalSet://goog/public:all",):
            return True
        if member.endswith("/" + principal.attrs.get("email", "\0")) or member == principal.id:
            return True
        if principal.kind == "gcp_service_account" and member.startswith("principalSet://goog/subject/") is False and \
                member.endswith(principal.attrs.get("email", "\0")):
            return True
    return False
