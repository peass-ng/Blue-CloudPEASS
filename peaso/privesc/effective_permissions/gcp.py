"""GCP effective permissions: allow bindings with org/folder/project/resource inheritance.

  * principals are binding members (user:, serviceAccount:, group:, domain:) plus
    every collected service account; allUsers / allAuthenticatedUsers bindings
    apply to every principal,
  * role permissions come from collected iam_role items (custom + predefined
    fetched by name); a small builtin table covers the basic and key IAM roles
    when they were not collected; any other uncollected role is reported in
    coverage and contributes nothing,
  * IAM conditions on bindings make edges conditional,
  * deny policies (iam_deny_policy) remove permissions for denied principals
    (unless excepted; denialCondition -> conditional). When deny policies were not
    collected for a scope, edges are conditional,
  * implicitDelegation chains (gcp_implicit_delegation_chain),
  * GKE clusters as k8s_cluster_admin entities and as the scope of KSA targets joined
    from related K8s snapshots (k8s_sa_has_token_secret / k8s_sa_in_cluster),
  * Workspace admin roles as a source selector (gcp_workspace_admin_role).
"""
from __future__ import annotations

import re

from ..schema import FACTS_NEEDED
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
SERVICE_HOSTS = {"compute": "instance", "gce": "instance", "compute_instance": "instance"}


class Role:
    __slots__ = ("name", "patterns", "exact", "confidence", "universal")

    def __init__(self, name, permissions, confidence="derived"):
        self.name = name
        perms = [str(p).lower() for p in permissions]
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
        self.missing_roles = set()
        self._load()
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
        self.related_k8s = None
        for member, grants in self.grants.items():
            if member.split(":", 1)[0] in ("user", "serviceAccount", "group", "domain", "principal", "principalSet"):
                self._principal(member, grants[0][0] if grants else "*")
        for node in self.principals.values():
            mine = tuple(sorted(set(self.grants.get(node.id, [])), key=repr))
            node.attrs["grants"] = mine + tuple(self.public)
            node.perm_key = node.attrs["grants"]

    def _bindings(self, node, policy):
        for index, binding in enumerate(as_list(policy.get("bindings"))):
            if not isinstance(binding, dict):
                continue
            role = binding.get("role")
            if role not in self.roles and role:
                self.missing_roles.add(role)
            conditional = bool(binding.get("condition"))
            ref = {"policy": node, "role": role, "binding": index, "condition": (binding.get("condition") or {}).get("title")}
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

    # ------------------------------------------------------------ hierarchy
    def ancestors(self, ref):
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
            out = {}
            for node, role_name, conditional, ref in principal.attrs["grants"]:
                role = self.roles.get(role_name)
                if role is None or not role.has(perm):
                    continue
                conf = "conditional" if conditional or role.confidence != "derived" else "derived"
                conditions = (["binding_condition"] if conditional else []) + (
                    ["builtin_role_permissions_approximated"] if role.confidence != "derived" else [])
                grant = Grant(conf, [dict(ref)], conditions)
                previous = out.get(node)
                out[node] = grant if previous is None or (previous.confidence != "derived" and conf == "derived") else previous
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
        for node in self.ancestors(ref):
            if node in held:
                found = held[node]
                if found.confidence == "derived":
                    break
        return self._deny(principal, perm, ref, found) if found else None

    def check_targets(self, principal, req, template, candidates, localized=False):
        perm = self.requirement_key(req)
        held = self.holders(principal, perm)
        if not held:
            return {}
        # When the permission is not granted on individual resources, a target's own-resource requirement
        # depends only on its parent scope: evaluate once per scope.
        own = localized or template in ("{target.email}", "{target.id}", "{target.resource}")
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
        for snapshot in snapshots or ():
            if (snapshot or {}).get("provider") != "k8s":
                continue
            clusters = {}
            for kind in ("serviceaccount", "secret", "namespace", "pod", "rolebinding", "clusterrolebinding"):
                for _, item in items(snapshot, kind):
                    prov = item.get("provenance") or {}
                    meta = item.get("metadata") or {}
                    cid = str(prov.get("cluster_id") or meta.get("cluster_id") or "")
                    if cid:
                        clusters.setdefault(cid, None)
            for cid in clusters:
                resource = self._match_gke(cid)
                if resource:
                    self.related_k8s[resource] = (cid, snapshot)
        self.__dict__.pop("_ksa_target_cache", None)

    def _match_gke(self, cluster_id):
        cid = str(cluster_id)
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
            name = resource.rsplit("/", 1)[-1]
            if joined is None:
                # Every cluster has KSAs (default SAs), but token Secrets are only proven by Secret metadata:
                # the token_secret variant becomes an unresolved placeholder.
                why = ("unknown" if variant == "token_secret" else "conditional", "k8s_snapshot_not_joined")
                label = (f"KSAs with token Secrets in GKE cluster {name}" if variant == "token_secret"
                         else f"KSAs of GKE cluster {name}")
                out.append(self._ksa_aggregate(variant, resource, label, why))
                continue
            cid, snapshot = joined
            sas = [(it.get("metadata") or {}) for _, it in items(snapshot, "serviceaccount")
                   if str((it.get("provenance") or {}).get("cluster_id") or (it.get("metadata") or {}).get("cluster_id")) == cid]
            if variant == "token_secret":
                statuses = inventory_status(snapshot, "secret")
                if not statuses or unavailable(statuses):
                    out.append(self._ksa_aggregate(variant, resource, f"KSAs with token Secrets in GKE cluster {name}",
                                                   ("unknown", "k8s_secret_metadata_not_collected")))
                    continue
                refs = set()
                for _, it in items(snapshot, "secret"):
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
        return None

    def targets_for(self, kind, selector):
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
        if kind in ("k8s_cluster_admin", "k8s_service_account"):
            return {s: st for s, st in unavailable(self.gke_status).items()}
        if kind == "gcp_service_account":
            return {self._norm_scope(s): st for s, st in unavailable(inventory_status(self.snapshot, "service_account")).items()}
        return {}

    def selector(self, key, value, candidates, source, pivot=None):
        if key in ("k8s_sa_has_token_secret", "k8s_sa_in_cluster"):
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
                found[node] = grant
        # Keep only the top-most scopes.
        top = {n: g for n, g in found.items() if not any(a in found for a in self.ancestors(n)[1:])}
        return [(self.entity(n), g) for n, g in sorted(top.items())]

    def scope_within(self, inner, outer):
        return outer in self.ancestors(inner)


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
