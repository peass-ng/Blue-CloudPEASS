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
                      "*.start", "*.upload", "*.uploadArtifacts", "*.sourceCodeSet", "*.setLabels"], "conditional"),
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
}
ADMIN_PERMS = {"projects": "resourcemanager.projects.setiampolicy", "folders": "resourcemanager.folders.setiampolicy",
               "organizations": "resourcemanager.organizations.setiampolicy"}
PUBLIC = ("allUsers", "allAuthenticatedUsers")
DELEGATE_PERM = "iam.serviceaccounts.implicitdelegation"
MINT_PERMS = ("iam.serviceaccounts.getaccesstoken", "iam.serviceaccounts.signblob", "iam.serviceaccounts.signjwt")
MAX_DELEGATION_DEPTH = 10
SERVICE_HOSTS = {"compute": "instance", "gce": "instance", "compute_instance": "instance",
                 "run_service": "cloudrun_service", "cloudfunctions_function": "function",
                 "dataproc_cluster": "dataproc_cluster", "gke_nodepool": "gke_nodepool"}
# attached_to_service values whose attachment inventory is not collected (yet): every candidate SA is reported as one
# unresolved placeholder per scope with a coverage note naming the value. A value in neither map is a catalog typo.
UNCOLLECTED_ATTACHMENTS = frozenset({
    "agentidentity_authorized_user", "agentregistry_skill_consumer", "appengine_version",
    "appintegration_authconfig_identity", "artifact_consumer", "bigquery_spark_connection",
    "cloudbuild_default_identity", "cloudbuild_trigger", "cloudbuild_unpinned_storage_source", "clouddeploy_target",
    "cloudservices_agent", "composer_environment", "config_connector_identity", "dataflow_job",
    "dataform_workflow_config_end_user", "datafusion_instance", "firebase_apphosting_backend",
    "hypercomputecluster_cluster", "integration_connector", "notebooks_instance", "run_instance", "run_job", "run_worker_pool",
    "saasservicemgmt_unit", "sourcerepo_trigger_consumer", "vertex_custom_code_agent",
    "vertex_reasoning_engine_agent", "vmmigration_target_default", "wif_pool_bound", "workflows_workflow",
    "workforce_pool_bound", "workspace_addon_user", "workspace_dwd_delegation",
    "workspace_super_admin_of_zone_domain", "workstations_config", "workstations_workstation",
})

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
        self._holders = {}
        self._resdep = {}         # holders key -> {node: (unconditional best, [(expression, grant if true, grant if undecided)])}
        self.inactive_bindings = 0
        self.missing_roles = set()
        self._load()
        from .gcp_resource_self_grant import load as load_resource_self_grants
        self.resource_self_grant_targets, self.resource_self_grant_records = load_resource_self_grants(self)
        from .gcp_external_principal import load as load_external_principals
        self.external_principal_targets, self.external_principal_records = load_external_principals(self)
        from .gcp_bounded_access_gain import load as load_bounded_access
        self.bounded_access_targets, self.bounded_access_records = load_bounded_access(self)
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
        for name, (perms, conf) in _BUILTIN.items():
            self.roles[name] = Role(name, perms, conf)
        builtin = set(self.roles)
        for scope, item in items(snap, "iam_role"):
            if item.get("name") and not item.get("deleted"):
                self.roles[item["name"]] = Role(item["name"], item.get("includedPermissions") or [])
        self._collected_roles = {n for n in self.roles if n not in builtin} | set()
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
        for scope, status in inventory_status(snap, "instance").items():
            self.host_status[(self._norm_scope(scope), "instance")] = status
        self._load_workload_hosts(snap)
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
        role_names, super_roles = {}, set()
        for _, item in items(snap, "workspace_role"):
            rid = str(item.get("roleId") or "")
            role_names[rid] = str(item.get("roleName") or rid)
            if item.get("isSuperAdminRole"):
                super_roles.add(rid)
        user_by_id = {}
        for _, item in items(snap, "workspace_user"):
            email = str(item.get("primaryEmail") or "").lower()
            if not email:
                continue
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
        self.related_k8s = None
        for member, grants in self.grants.items():
            if member.split(":", 1)[0] in ("user", "serviceAccount", "group", "domain", "principal", "principalSet"):
                self._principal(member, grants[0][0] if grants else "*")
        for node in self.principals.values():
            mine = tuple(sorted(set(self.grants.get(node.id, [])), key=repr))
            node.attrs["grants"] = mine + tuple(self.public)
            node.perm_key = node.attrs["grants"]

    def _load_ext_facts(self, snap):
        """Groups Settings (whoCanJoin), Cloud Domains registrations and instance-template image families."""
        self.group_settings = {}  # group email -> (whoCanJoin, allowExternalMembers or None)
        for _, item in items(snap, "group"):
            email = str(((item.get("groupKey") or {}).get("id")) or item.get("email") or "").lower()
            settings = item.get("groupSettings") or item.get("settings") or item
            who = settings.get("whoCanJoin") if isinstance(settings, dict) else None
            if email and who:
                ext = settings.get("allowExternalMembers")
                ext = None if ext is None else str(ext).lower() == "true"
                self.group_settings[email] = (str(who).upper(), ext)
        self.registrations_status = inventory_status(snap, "domains_registration")
        self.registrations = {}  # domain -> [registration resource]
        for scope, item in items(snap, "domains_registration"):
            domain = str(item.get("domainName") or "").lower().rstrip(".")
            if domain and item.get("name"):
                resource = self._norm_scope(item["name"])
                self.registrations.setdefault(domain, []).append(resource)
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

        for kind, host in (("cloudrun_service", "cloudrun_service"), ("function", "function"),
                           ("dataproc_cluster", "dataproc_cluster"), ("gke_cluster", "gke_nodepool")):
            for scope, status in inventory_status(snap, kind).items():
                project = "/".join(self._norm_scope(scope).split("/")[:2])
                if project.startswith("projects/"):
                    merge((project, host), status)
            for scope, item in items(snap, kind):
                project = "/".join(self._norm_scope(item.get("projectId") and f"projects/{item['projectId']}" or scope).split("/")[:2])
                if not project.startswith("projects/"):
                    continue
                found = []  # (email or None, resource)
                if kind == "cloudrun_service":
                    sa = (item.get("template") or {}).get("serviceAccount") or default_compute(project)
                    found.append((sa, self._norm_scope(item.get("name") or "")))
                elif kind == "function":
                    sa = (item.get("serviceConfig") or {}).get("serviceAccountEmail") or item.get("serviceAccountEmail")
                    if not sa:
                        sa = default_compute(project) if "serviceConfig" in item or "buildConfig" in item else (
                            f"{project.split('/', 1)[1]}@appspot.gserviceaccount.com" if "runtime" in item else None)
                    found.append((sa, self._norm_scope(item.get("name") or "")))
                elif kind == "dataproc_cluster":
                    sa = ((item.get("config") or {}).get("gceClusterConfig") or {}).get("serviceAccount") or default_compute(project)
                    region = (item.get("labels") or {}).get("goog-dataproc-location") or "-"
                    found.append((sa, f"{project}/regions/{region}/clusters/{item.get('clusterName')}"))
                else:
                    resource = self._norm_scope(_gke_resource(item, project) or "") or None
                    pools = item.get("nodePools")
                    if not isinstance(pools, list) or not pools:
                        found.append((None, resource))  # Autopilot / pools not listed: node SA unknown
                    for pool in pools if isinstance(pools, list) else ():
                        sa = ((pool or {}).get("config") or {}).get("serviceAccount")
                        found.append((default_compute(project) if sa in (None, "", "default") else sa, resource))
                for sa, resource in found:
                    if not sa or not resource:
                        merge((project, host), "partial")
                        continue
                    if resource not in self.parents:
                        self.parents[resource] = project
                    listed = self.hosts.setdefault(sa, {}).setdefault(host, [])
                    if resource not in listed:
                        listed.append(resource)

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
        key = ("possible", principal.perm_key)
        if key not in self._check_cache:
            keys, universal = set(), False
            for _, role_name, _, _ in principal.attrs["grants"]:
                role = self.roles.get(role_name)
                if role is None:
                    continue
                if role.universal:
                    universal = True
                    continue
                keys |= role.exact
                if role.patterns:
                    keys |= {k for k in self.catalog_keys if role.has(k)}
            self._check_cache[key] = (frozenset(keys), universal)
        return self._check_cache[key]

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
        ctx = cel.resource_context(ref, aliases)
        for expression, if_true, undecided in listed:
            verdict = cel.evaluate(expression, ctx)
            if verdict is False:
                continue
            found = best(found, if_true if verdict else undecided)
        return found

    def check_targets(self, principal, req, template, candidates, localized=False):
        perm = self.requirement_key(req)
        held = self.holders(principal, perm)
        if not held:
            return {}
        # When the permission is not granted on individual resources, a target's own-resource requirement
        # depends only on its parent scope: evaluate once per scope (not when a binding condition names resources).
        own = not self._resdep.get((principal.perm_key, perm)) and (localized or template in ("{target.email}", "{target.id}", "{target.resource}"))
        resource_grants = {n for n in held if "/serviceAccounts/" in n or n.startswith("//")} if own else None
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
            refs, floor = self.resolve(template, principal, target) if not localized else ([self.localize(req, target)], None)
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
        if attr == "host_resource" and owner == "target":
            services = [str(v).lower() for v in as_list((self.current_selector or {}).get("attached_to_service"))]
            hosts = [SERVICE_HOSTS.get(v) for v in services]
            if not hosts or None in hosts:
                return None  # host type not modelled for GCP: unknown
            out = []
            for host in hosts:
                if self.host_status.get((node.scope, host)) not in ("collected", "empty"):
                    return None
                out.extend(self.hosts.get(node.attrs.get("email"), {}).get(host, []))
            return out
        if attr == "domain_registration" and owner == "target":
            if not any(st in ("collected", "empty") for st in self.registrations_status.values()):
                return None
            return list(self.registrations.get(_email_domain(node.attrs.get("email")), []))
        if attr == "image_family_project" and owner == "target":
            return sorted(self.image_families.get(node.attrs.get("email"), ())) or None
        if attr == "policy_resource" and owner == "target" and node.kind == "gcp_verified_authority":
            return [node.attrs["policy_resource"]] if node.attrs.get("policy_resource") else None
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
        if (selector or {}).get("gcp_bounded_access_gain"):
            return list(self.bounded_access_targets.values()) if kind == "gcp_verified_authority" else []
        if (selector or {}).get("gcp_external_principal_evidence"):
            return list(self.external_principal_targets.values()) if kind == "gcp_external_principal" else []
        if (selector or {}).get("gcp_resource_self_grant"):
            return list(self.resource_self_grant_targets.values()) if kind == "gcp_verified_authority" else []
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
        return super().include_service_managed(compiled) or "attached_to_service" in selector

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
        if (self.current_selector or {}).get("gcp_bounded_access_gain"):
            return {}
        if (self.current_selector or {}).get("gcp_external_principal_evidence"):
            return {}
        if (self.current_selector or {}).get("gcp_resource_self_grant"):
            return {}
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

    def selector(self, key, value, candidates, source, pivot=None):
        if key == "gcp_bounded_mechanism":
            return {ident: ("conditional", "reviewed_bounded_mechanism") for ident, node in candidates.items()
                    if node.attrs.get("mechanism") == value}
        if key == "gcp_bounded_access_gain":
            from .gcp_bounded_access_gain import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_external_plane":
            return {ident: ("conditional", "reviewed_external_plane") for ident, node in candidates.items()
                    if node.attrs.get("external_plane") == value}
        if key == "gcp_external_principal_evidence":
            from .gcp_external_principal import select
            return select(self, candidates, source) if value is True else {}
        if key == "gcp_resource_self_grant":
            from .gcp_resource_self_grant import select
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
                    host = SERVICE_HOSTS.get(str(service).lower())
                    email = node.attrs.get("email")
                    if host and self.hosts.get(email, {}).get(host):
                        verdict = "yes"
                        break
                    if not host or self.host_status.get((node.scope, host)) not in ("collected", "empty"):
                        verdict = verdict or "unknown"
                        if not host:
                            self._note_uncollected_attachment(str(service).lower())
                if verdict == "yes":
                    out[tid] = None
                elif verdict == "unknown":
                    out[tid] = ("unknown", "attachment_inventory_not_collected")
            return out
        if key == "same_as_source":
            if candidates and next(iter(candidates.values())).entity:
                return {tid: None for tid in candidates}
            return {source.id: None} if source.id in candidates else {}
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
                if not self.registrations.get(_email_domain(email)):
                    continue
                if "super_admin" in self.ws_admin.get(email, set()):
                    out[tid] = None
                elif not ws_known:
                    out[tid] = ("unknown", "workspace_admin_roles_not_collected")
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
            # Scopes where the source has a binding to a custom role whose parent is that scope or an ancestor
            # of it (editing the role changes the source's own permissions there).
            bound = set()
            for node, role_name, _conditional, _ref in (source.attrs.get("grants", ()) if source else ()):
                if not str(role_name).startswith(("projects/", "organizations/")):
                    continue
                parent = self._norm_scope(str(role_name).split("/roles/", 1)[0])
                if parent in self.ancestors(node):
                    bound.add(parent)
            return {tid: None for tid, n in candidates.items() if n.scope in bound}
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
