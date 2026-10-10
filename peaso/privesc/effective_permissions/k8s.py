"""Kubernetes RBAC effective permissions.

  * Role/ClusterRole rules bound by RoleBinding (namespace-limited) and
    ClusterRoleBinding (cluster-wide, incl. cluster-scoped resources),
  * ClusterRole aggregation (aggregationRule.clusterRoleSelectors.matchLabels),
  * resource matching per the apiserver: '*' covers subresources, 'res/sub' and
    '*/sub' forms; resourceNames restrict (create/list/watch/deletecollection never
    match a rule restricted by resourceNames),
  * service accounts implicitly belong to system:serviceaccounts,
    system:serviceaccounts:<ns> and system:authenticated,
  * cloud identities from SA annotations (IRSA, GKE Workload Identity, Azure
    Workload Identity) and kiam/kube2iam namespace annotations; with related cloud
    snapshots (analyze(..., related_snapshots=[...])) the cloud side is verified
    (IAM role trust / workloadIdentityUser bindings / kube2iam role regexes) and each
    cloud identity is joined to its IAM principal by a cross-snapshot edge.
"""
from __future__ import annotations

import fnmatch
import json
import re

from . import ANY, Grant, Model, Node, as_list, downgrade, glob_match, inventory_status, items, unavailable

CLUSTER_SCOPED = {
    "nodes", "namespaces", "clusterroles", "clusterrolebindings", "certificatesigningrequests", "persistentvolumes",
    "mutatingwebhookconfigurations", "validatingwebhookconfigurations", "customresourcedefinitions", "storageclasses",
    "priorityclasses", "apiservices", "tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews", "users", "groups",
    "userextras", "uids", "signers", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings",
    "validatingadmissionpolicies", "validatingadmissionpolicybindings", "runtimeclasses", "csidrivers", "volumeattachments",
    "ingressclasses", "securitycontextconstraints", "clusterissuers",
}
NO_NAME_VERBS = {"create", "list", "watch", "deletecollection"}
SEP = "\x1f"


def _cluster(item, scope=None):
    prov = item.get("provenance") or {}
    meta = item.get("metadata") or {}
    return str(prov.get("cluster_id") or meta.get("cluster_id") or "cluster")


_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")


BINDING_PROVIDER = {"irsa": "aws", "kube2iam": "aws", "eks_pod_identity": "aws", "gke_workload_identity": "gcp",
                    "azure_workload_identity": "azure", "aks_identity_binding": "azure"}
JOIN_TECHNIQUE = "cloud-identity-join"


class RelatedClouds:
    """Lightweight indexes over related cloud snapshots used to verify / join K8s cloud identities."""

    def __init__(self, snapshots):
        from .aws import AwsModel
        from .azure import AzureModel
        from .gcp import GcpModel
        classes = {"aws": AwsModel, "gcp": GcpModel, "azure": AzureModel}
        self.models = {"aws": [], "gcp": [], "azure": []}
        for snapshot in snapshots or ():
            cls = classes.get((snapshot or {}).get("provider"))
            if cls is not None:
                self.models[snapshot["provider"]].append(cls(snapshot))
        self.aws_roles, self.aws_roles_by_name, self.aws_accounts = {}, {}, set()
        for model in self.models["aws"]:
            self.aws_accounts |= model.accounts
            for node in model.principals.values():
                if node.kind == "aws_role":
                    self.aws_roles[node.id] = (model, node)
                    self.aws_roles_by_name.setdefault(node.label, []).append(node.id)
        self._wi = None

    def has(self, provider):
        return bool(self.models.get(provider))

    def aws_role(self, ref):
        """(model, node) for a role ARN or name; None when unknown."""
        ref = str(ref)
        if ref in self.aws_roles:
            return self.aws_roles[ref]
        name = ref.rsplit("/", 1)[-1]
        for arn in self.aws_roles_by_name.get(name, ()):
            if ref == name or arn.endswith("/" + name):
                return self.aws_roles[arn]
        return None

    def aws_account_covered(self, ref):
        match = re.match(r"arn:[^:]+:iam::(\d{12}):", str(ref))
        return bool(match and match.group(1) in self.aws_accounts)

    def oidc_subjects(self, role_model, role):
        """[subject patterns] admitted by OIDC-provider web-identity trust statements ('*' when no sub condition)."""
        out = []
        for st in role_model.trust.get(role.id, []):
            if st.effect != "allow" or not st.action_matches("sts:AssumeRoleWithWebIdentity"):
                continue
            principal = st.principals if isinstance(st.principals, dict) else {}
            if not any("oidc-provider/" in str(f) for f in as_list(principal.get("Federated"))):
                continue
            raw = _trust_raw(role_model, role, st)
            subjects = []
            for op, block in ((raw.get("Condition") or {}).items()):
                if not str(op).startswith(("StringEquals", "StringLike", "ForAnyValue:String")):
                    continue
                for key, value in (block or {}).items():
                    if str(key).endswith(":sub"):
                        subjects.extend(str(v) for v in as_list(value))
            out.extend(subjects or ["*"])
        return out

    def gcp_sa(self, email):
        for model in self.models["gcp"]:
            node = model.principals.get(f"serviceAccount:{email}")
            if node is not None and node.attrs.get("resource"):
                return model, node
        return None

    def gcp_project_covered(self, email):
        domain = str(email).split("@", 1)[-1]
        project = "projects/" + domain.split(".", 1)[0]
        return any(project in m.scopes or any(n.scope == project for n in m.sas.values()) for m in self.models["gcp"])

    def gcp_wi_grant(self, email, namespace, name):
        found = self.gcp_sa(email)
        if found is None:
            return None
        model, sa = found
        suffix = f".svc.id.goog[{namespace}/{name}]"
        chain = set(model.ancestors(sa.attrs["resource"]))
        for member, grants in model.grants.items():
            if not (member.startswith("serviceAccount:") and member.endswith(suffix)):
                continue
            for node, role_name, conditional, ref in grants:
                role = model.roles.get(role_name)
                if node in chain and role is not None and role.has("iam.serviceaccounts.getaccesstoken"):
                    return Grant("conditional" if conditional else "derived", [dict(ref)], ["binding_condition"] if conditional else [])
        return False

    def azure_principal(self, client_id):
        low = str(client_id).lower()
        for model in self.models["azure"]:
            for node in model.principals.values():
                if str(node.attrs.get("client_id") or node.attrs.get("app_id") or "").lower() == low:
                    return model, node
        return None


def _trust_raw(model, role, statement):
    """The raw trust statement (Condition blocks are not kept on Statement)."""
    cache = model.__dict__.get("_raw_trust")
    if cache is None:
        from .aws import _doc
        cache = model._raw_trust = {}
        for scope, item in items(model.snapshot, "iam_role"):
            doc = _doc(item.get("AssumeRolePolicyDocument")) or {}
            cache[item.get("Arn")] = [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]
    raws = cache.get(role.id, [])
    index = statement.ref.get("statement", 0)
    return raws[index] if index < len(raws) else {}


def _subject_matches(pattern, namespace, name=None):
    """OIDC sub pattern admits system:serviceaccount:<namespace>:<name> (any name when name is None)."""
    if pattern == "*":
        return True
    parts = pattern.split(":")
    if len(parts) != 4 or not glob_match(parts[0], "system", False) or not glob_match(parts[1], "serviceaccount", False):
        return glob_match(pattern, f"system:serviceaccount:{namespace}:{name or 'x'}", False)
    if not glob_match(parts[2], namespace, False):
        return False
    return True if name is None else glob_match(parts[3], name, False)


class K8sModel(Model):
    provider = "k8s"

    def __init__(self, snapshot, catalog_keys=()):
        super().__init__(snapshot, catalog_keys)
        self.roles = {}            # (cluster, ns or None, name) -> {"rules": [...], "labels": {}, "aggregation": [...]}
        self.bindings = {}         # (cluster, subject key) -> [(ns or None, role key, binding ref)]
        self.sas, self.nodes = {}, {}
        self.namespaces = {}       # cluster -> set
        self.pods = []             # (cluster, ns, sa, node, privileged, owned, running)
        self.clusters = set()
        self.cluster_scopes = {}
        self.cloud = {}
        self.related = RelatedClouds(())
        self.pod_roles = {}        # cluster -> set of iam.amazonaws.com/role pod annotations
        self._load()
        self.require_collections(("role", "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount"), {
            "role": "Namespaced RBAC grants are unknown", "clusterrole": "Cluster role rules are unknown",
            "rolebinding": "Namespaced bindings are unknown", "clusterrolebinding": "Cluster-wide bindings are unknown",
            "serviceaccount": "Service-account targets are unknown"})
        for kind in ("pod", "node"):
            if not inventory_status(snapshot, kind):
                self.add_coverage("collection", "*", "not_collected", f"{kind} not in snapshot",
                                  "Pod/node placement selectors are unknown")

    # ------------------------------------------------------------------ load
    def _load(self):
        snap = self.snapshot
        for kind in ("role", "clusterrole"):
            for scope, item in items(snap, kind):
                meta = item.get("metadata") or {}
                cluster = _cluster(item)
                self.clusters.add(cluster)
                ns = meta.get("namespace") if kind == "role" else None
                self.roles[(cluster, ns, meta.get("name"))] = {
                    "rules": [r for r in as_list(item.get("rules")) if isinstance(r, dict)],
                    "labels": meta.get("labels") or {},
                    "aggregation": [((s or {}).get("matchLabels") or {}) for s in
                                    as_list((item.get("aggregationRule") or {}).get("clusterRoleSelectors"))],
                    "name": meta.get("name"), "namespace": ns, "kind": "ClusterRole" if ns is None else "Role"}
        for key, role in list(self.roles.items()):
            if role["aggregation"]:
                extra = []
                for other_key, other in self.roles.items():
                    if other_key[0] == key[0] and other_key[1] is None and other_key != key and any(
                            sel and all(other["labels"].get(k) == v for k, v in sel.items()) for sel in role["aggregation"]):
                        extra.extend(other["rules"])
                role["rules"] = role["rules"] + [r for r in extra if r not in role["rules"]]
        self.ns_annotations = {}
        for scope, item in items(snap, "namespace"):
            meta = item.get("metadata") or {}
            self.namespaces.setdefault(_cluster(item), set()).add(meta.get("name"))
            annotations = meta.get("annotations") or {}
            rules = {}
            if annotations.get("iam.amazonaws.com/permitted"):
                rules["permitted"] = str(annotations["iam.amazonaws.com/permitted"])  # kiam: regex
            if annotations.get("iam.amazonaws.com/allowed-roles"):
                try:
                    allowed = json.loads(annotations["iam.amazonaws.com/allowed-roles"])  # kube2iam: JSON list of globs
                except (TypeError, ValueError):
                    allowed = [annotations["iam.amazonaws.com/allowed-roles"]]
                rules["allowed_roles"] = [str(a) for a in as_list(allowed)]
            if rules:
                self.ns_annotations.setdefault(_cluster(item), {})[meta.get("name")] = rules
        for scope, item in items(snap, "serviceaccount"):
            meta = item.get("metadata") or {}
            cluster, ns, name = _cluster(item), meta.get("namespace"), meta.get("name")
            node = self._sa(cluster, ns, name)
            node.attrs["annotations"] = meta.get("annotations") or {}
            node.attrs["inventoried"] = True
        for scope, item in items(snap, "node"):
            meta = item.get("metadata") or {}
            cluster, name = _cluster(item), meta.get("name")
            node = Node(f"k8s:{cluster}:node:{name}", "k8s_node", "k8s", cluster, name,
                        attrs={"cluster": cluster, "name": name, "labels": meta.get("labels") or {},
                               "unschedulable": bool((item.get("spec") or {}).get("unschedulable")),
                               "groups": ["system:nodes", "system:authenticated"], "user": f"system:node:{name}"})
            self.nodes[node.id] = node
            self.principals[node.id] = node
            self.clusters.add(cluster)
        for scope, item in items(snap, "pod"):
            meta, spec = item.get("metadata") or {}, item.get("spec") or {}
            cluster, ns = _cluster(item), meta.get("namespace")
            sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
            privileged = bool(spec.get("hostPID") or spec.get("hostNetwork") or spec.get("hostIPC") or any(
                (v or {}).get("hostPath") for v in as_list(spec.get("volumes"))) or any(
                ((c or {}).get("securityContext") or {}).get("privileged") for c in as_list(spec.get("containers"))))
            phase = (item.get("status") or {}).get("phase")
            pod_role = (meta.get("annotations") or {}).get("iam.amazonaws.com/role")
            if pod_role:
                self.pod_roles.setdefault(cluster, set()).add(str(pod_role))
            self.pods.append({"cluster": cluster, "ns": ns, "sa": sa, "node": spec.get("nodeName"), "privileged": privileged,
                              "owned": bool(meta.get("ownerReferences")), "running": phase in (None, "Running", "Pending")})
            self.namespaces.setdefault(cluster, set()).add(ns)
        for kind in ("rolebinding", "clusterrolebinding"):
            for scope, item in items(snap, kind):
                meta = item.get("metadata") or {}
                cluster = _cluster(item)
                self.clusters.add(cluster)
                ns = meta.get("namespace") if kind == "rolebinding" else None
                ref = item.get("roleRef") or {}
                role_ns = ns if ref.get("kind") == "Role" else None
                role_key = (cluster, role_ns, ref.get("name"))
                evidence = {"binding": f"{kind}/{(ns + '/') if ns else ''}{meta.get('name')}",
                            "role": f"{ref.get('kind')}/{ref.get('name')}"}
                for subject in as_list(item.get("subjects")):
                    if not isinstance(subject, dict):
                        continue
                    skind, sname = subject.get("kind"), subject.get("name")
                    if skind == "ServiceAccount":
                        sns = subject.get("namespace") or ns
                        key = f"sa:{sns}:{sname}"
                        self._sa(cluster, sns, sname)
                    elif skind == "Group":
                        key = f"group:{sname}"
                        self._subject(cluster, "k8s_group", sname)
                    else:
                        key = f"user:{sname}"
                        if not str(sname).startswith("system:node:"):
                            self._subject(cluster, "k8s_user", sname)
                    self.bindings.setdefault((cluster, key), []).append((ns, role_key, evidence))
        for cluster in self.clusters:
            self.namespaces.setdefault(cluster, set())
        for node in self.principals.values():
            cluster = node.attrs["cluster"]
            keys = self._subject_keys(node)
            bound = []
            for key in keys:
                bound.extend((ns, role, tuple(sorted(ev.items()))) for ns, role, ev in self.bindings.get((cluster, key), []))
            node.attrs["bound"] = tuple(sorted(set(bound), key=repr))
            node.perm_key = (cluster, tuple((ns, role) for ns, role, _ in node.attrs["bound"]))
            self.cluster_scopes.setdefault(cluster, set()).add(node.scope)

    def _sa(self, cluster, ns, name):
        nid = f"k8s:{cluster}:sa:{ns}:{name}"
        if nid not in self.principals:
            node = Node(nid, "k8s_service_account", "k8s", f"{cluster}/{ns}", f"{ns}/{name}",
                        attrs={"cluster": cluster, "namespace": ns, "name": name, "inventoried": False,
                               "groups": ["system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated"],
                               "user": f"system:serviceaccount:{ns}:{name}"})
            self.principals[nid] = node
            self.sas[nid] = node
            self.namespaces.setdefault(cluster, set()).add(ns)
        return self.principals[nid]

    def _subject(self, cluster, kind, name):
        nid = f"k8s:{cluster}:{'group' if kind == 'k8s_group' else 'user'}:{name}"
        if nid not in self.principals:
            groups = [] if kind == "k8s_group" else ["system:authenticated"]
            self.principals[nid] = Node(nid, kind, "k8s", cluster, name,
                                        attrs={"cluster": cluster, "name": name, "groups": groups, "user": name})
        return self.principals[nid]

    def _subject_keys(self, node):
        if node.kind == "k8s_service_account":
            keys = [f"sa:{node.attrs['namespace']}:{node.attrs['name']}", f"user:{node.attrs['user']}"]
        elif node.kind == "k8s_group":
            keys = [f"group:{node.attrs['name']}"]
        else:
            keys = [f"user:{node.attrs['user']}"]
        return keys + [f"group:{g}" for g in node.attrs.get("groups", [])]

    # ----------------------------------------------------------------- rules
    def requirement_key(self, req):
        return "|".join([str(req.get("verb", "")).lower(), str(req.get("api_group", "")), str(req.get("resource", "")),
                         str(req.get("subresource", ""))])

    def requirement_template(self, req):
        ns = req.get("namespace", "*")
        name = req.get("resource_name")
        resource = str(req.get("resource", ""))
        res_tpl = resource if "{" in resource else ""
        if ns in (None, "*") and not name and not res_tpl:
            return None
        return SEP.join([str(ns or "*"), str(name or ""), res_tpl])

    def localizable(self, req):
        # namespace "*" means a cluster-wide grant; only an omitted namespace is evaluated in the target's namespace.
        return req.get("namespace") is None and str(req.get("resource")) not in CLUSTER_SCOPED

    def _rules(self, principal):
        cluster = principal.attrs["cluster"]
        for ns, role_key, evidence in principal.attrs.get("bound", ()):
            role = self.roles.get(role_key)
            if role is None:
                yield ns, None, dict(evidence)
                continue
            for rule in role["rules"]:
                yield ns, rule, dict(evidence)
        del cluster

    def possible(self, principal):
        key = ("possible", principal.perm_key)
        if key in self._check_cache:
            return self._check_cache[key]
        keys, universal = set(), False
        for ns, rule, ev in self._rules(principal):
            if rule is None:
                continue
            verbs, groups, resources = (as_list(rule.get(k)) for k in ("verbs", "apiGroups", "resources"))
            if "*" in verbs and "*" in resources and "*" in groups:
                universal = True
                continue
            for k in self.catalog_keys:
                verb, group, resource, sub = k.split("|")
                if _rule_matches(rule, verb, group, resource, sub, None, partial=True):
                    keys.add(k)
        self._check_cache[key] = (frozenset(keys), universal)
        return self._check_cache[key]

    def check(self, principal, req, ref):
        verb = str(req.get("verb", "")).lower()
        group = str(req.get("api_group", "") or "")
        resource = str(req.get("resource", ""))
        sub = str(req.get("subresource", "") or "")
        if isinstance(ref, tuple):
            ns, name, res_override = ref
            if res_override:
                resource = res_override
        else:
            ns, name = ANY, None
        # namespace: "*" = cluster-wide: only ClusterRoleBindings count.
        cluster_scoped = resource in CLUSTER_SCOPED or (ns is ANY and req.get("namespace") == "*")
        best_grant = None
        for bind_ns, rule, evidence in self._rules(principal):
            if rule is None:
                continue
            if bind_ns is not None:
                if cluster_scoped:
                    continue
                if ns is not ANY and ns != "*" and ns != bind_ns:
                    continue
                if ns == "*":
                    # cluster-wide requirement ('*' = in every namespace) needs a ClusterRoleBinding
                    pass
            match = _rule_matches(rule, verb, group, resource, sub, name)
            if not match:
                continue
            conf = "derived" if match is True else "conditional"
            conditions = [] if match is True else [match]
            grant = Grant(conf, [{**evidence, "namespace": bind_ns or "*"}], conditions)
            if best_grant is None or (best_grant.confidence != "derived" and conf == "derived"):
                best_grant = grant
                if conf == "derived" and bind_ns is None:
                    break
        return best_grant

    def scope_only(self, req, template, localized):
        # Node / SA scopes are "<cluster>" / "<cluster>/<ns>", so namespace-only templates are scope-only.
        if localized:
            return True
        if template is None:
            return False
        ns_tpl, name_tpl, res_tpl = template.split(SEP)
        refs = set(_PH.findall(template))
        return not name_tpl and not res_tpl and {n for n in refs if n.startswith("target.")} <= {"target.namespace"}

    def check_targets(self, principal, req, template, candidates, localized=False):
        # Most templates depend on the target only through its namespace: evaluate once per namespace.
        by_ns = localized
        if not localized and template is not None:
            ns_tpl, name_tpl, res_tpl = template.split(SEP)
            target_refs = set(_PH.findall(template))
            by_ns = {n for n in target_refs if n.startswith("target.")} <= {"target.namespace"}
            if not name_tpl and not res_tpl and self.cached_check(principal, req, (ANY, None, "")) is None:
                return {}  # not held in any namespace
        memo, result = {}, {}
        for target in candidates:
            key = (target.attrs.get("namespace"), target.attrs.get("cluster")) if by_ns else target.id
            if key not in memo:
                if localized:
                    refs, floor = [(target.attrs.get("namespace") or ANY, None, "")], None
                else:
                    refs, floor = self.resolve(template, principal, target)
                grant = None
                for ref in refs:
                    got = self.cached_check(principal, req, ref)
                    if got is not None and (grant is None or got.confidence == "derived"):
                        grant = got
                memo[key] = None if grant is None else (downgrade(grant, floor[0], floor[1]) if floor else grant)
            if memo[key] is not None:
                result[target.id] = memo[key]
        return result

    # ----------------------------------------------------------- placeholders
    def placeholder_values(self, name, source, target, pivot=None):
        if name.startswith("pivot"):
            return [pivot[name]] if pivot and name in pivot else None
        if name == "cluster":
            node = target or source
            return [node.attrs.get("cluster")] if node is not None else None
        if name in ("source_bound_clusterrole", "source_bound_role"):
            wanted = "ClusterRole" if name == "source_bound_clusterrole" else "Role"
            return sorted({role[2] for ns, role, ev in source.attrs.get("bound", ()) if self.roles.get(role, {}).get("kind") == wanted})
        if name == "admin_equivalent_clusterrole":
            cluster = source.attrs["cluster"]
            return sorted(k[2] for k, r in self.roles.items() if k[0] == cluster and k[1] is None and any(
                "*" in as_list(x.get("verbs")) and "*" in as_list(x.get("resources")) for x in r["rules"]))
        owner, _, attr = name.partition(".")
        if not attr:
            owner, attr = "source", owner
        node = target if owner == "target" else source
        if node is None:
            return None
        if attr == "namespace":
            value = node.attrs.get("namespace")
            return [value] if value else None
        if attr == "name":
            return [node.attrs.get("name") or node.label]
        if attr == "node":
            if node.kind == "k8s_node":
                return [node.attrs["name"]]
            if node.kind == "k8s_service_account":
                return sorted({p["node"] for p in self.pods if p["cluster"] == node.attrs["cluster"] and p["ns"] == node.attrs["namespace"]
                               and p["sa"] == node.attrs["name"] and p["node"]})
            return None
        if attr == "client_id":
            return None
        return None

    def _sub(self, text, source, target, pivot):
        if not text:
            return [""], None
        names = re.findall(r"(?<!\$)\{([^{}]+)\}", text)
        values = [text]
        for name in names:
            got = self.placeholder_values(name, source, target, pivot)
            if got is None:
                return None, ("unknown", f"placeholder_{name}_not_in_snapshot")
            values = [v.replace("{" + name + "}", g) for v in values for g in got]
        return values, None

    def resolve(self, template, source, target, pivot=None):
        if template is None:
            return [ANY], None
        ns_tpl, name_tpl, res_tpl = template.split(SEP)
        if ns_tpl == "*":
            namespaces, floor = [ANY], None
        else:
            namespaces, floor = self._sub(ns_tpl, source, target, pivot)
            if namespaces is None:
                return [ANY], floor
        names, floor2 = self._sub(name_tpl, source, target, pivot)
        if names is None:
            return [ANY], floor2
        resources, floor3 = self._sub(res_tpl, source, target, pivot)
        if resources is None:
            return [ANY], floor3
        refs = [(ns, name or None, res) for ns in namespaces for name in names for res in resources][:200]
        return refs, None

    def pivot_candidates(self, source):
        cluster = source.attrs["cluster"]
        namespaces = {ns for ns, role, ev in source.attrs.get("bound", ()) if ns}
        if any(ns is None for ns, role, ev in source.attrs.get("bound", ())):
            namespaces |= {n for n in self.namespaces.get(cluster, ()) if n}
        return [{"pivot.namespace": ns} for ns in sorted(namespaces)]

    pivot_is_conditional = False

    def covered_by_requirement(self, key, action, template, kind):
        if key != "resource_permission_covers_target" or not isinstance(action, str):
            return None
        resource, _, verb = action.partition(":")
        if not verb:
            return None
        name = "{target.name}" if kind in ("k8s_user", "k8s_group", "k8s_service_account") else None
        if resource == "serviceaccounts" and verb == "impersonate":
            return {"verb": verb, "resource": resource, "namespace": "{target.namespace}", "resource_name": name}
        req = {"verb": verb, "resource": resource, "namespace": "*"}
        if name:
            req["resource_name"] = name
        return req

    # --------------------------------------------------------------- targets
    def targets(self, kind):
        if kind == "k8s_service_account":
            return list(self.sas.values())
        if kind == "k8s_node":
            return list(self.nodes.values())
        if kind in ("k8s_user", "k8s_group"):
            return [n for n in self.principals.values() if n.kind == kind]
        if kind == "k8s_cluster_admin":
            return [self.entity(c) for c in sorted(self.clusters)]
        if kind == "cloud_identity":
            return [n for n in self._cloud_identities().values() if n.attrs.get("variant") is None]
        return []

    def target_variant(self, kind, selector):
        if kind != "cloud_identity":
            return None
        if "kube2iam_namespace_permits_role" in selector:
            return "kube2iam"
        if "trust_allows_oidc_subject_wildcard" in selector:
            return "oidc_wildcard"
        return None

    def targets_for(self, kind, selector):
        variant = self.target_variant(kind, selector)
        if variant is None:
            return self.targets(kind)
        nodes = self._cloud_identities().values()
        if variant == "kube2iam":
            return [n for n in nodes if n.attrs["binding"] == "kube2iam"]
        return [n for n in nodes if n.attrs["binding"] == "irsa"]

    def set_related(self, snapshots):
        self.related = RelatedClouds(snapshots)
        self.cloud, self._cloud_built = {}, False

    def _cloud_node(self, binding, external, cluster, label, variant=None):
        nid = f"cloud:{binding}:{external}"
        node = self.cloud.get(nid)
        if node is None:
            node = self.cloud[nid] = Node(nid, "cloud_identity", "k8s", cluster, f"{label} {external}",
                                          attrs={"cluster": cluster, "binding": binding, "external_id": external,
                                                 "bound_sas": [], "variant": variant})
        return node

    def _cloud_identities(self):
        if not self.__dict__.get("_cloud_built"):
            self._cloud_built = True
            for sa in self.sas.values():
                ann = sa.attrs.get("annotations") or {}
                for key, binding, label in (("eks.amazonaws.com/role-arn", "irsa", "IAM role"),
                                            ("iam.gke.io/gcp-service-account", "gke_workload_identity", "GCP SA"),
                                            ("azure.workload.identity/client-id", "azure_workload_identity", "Entra app")):
                    if ann.get(key):
                        node = self._cloud_node(binding, ann[key], sa.attrs["cluster"], label)
                        node.attrs["bound_sas"].append(sa.id)
            clusters = sorted(self.clusters) or ["cluster"]
            # Roles any SA could federate into (IRSA trust on an OIDC provider), from related AWS snapshots.
            for arn, (model, role) in sorted(self.related.aws_roles.items()):
                if self.related.oidc_subjects(model, role):
                    for cluster in clusters:
                        if f"cloud:irsa:{arn}" not in self.cloud:
                            self._cloud_node("irsa", arn, cluster, "IAM role", variant="oidc_wildcard")
            # kiam/kube2iam: roles requestable through pod annotations.
            for cluster in clusters:
                if not self.ns_annotations.get(cluster):
                    continue
                refs = set(self.related.aws_roles) | self.pod_roles.get(cluster, set())
                for ref in sorted(refs):
                    found = self.related.aws_role(ref)
                    external = found[1].id if found else ref
                    node = self._cloud_node("kube2iam", external, cluster, "IAM role", variant="kube2iam")
                    node.attrs["role_name"] = found[1].label if found else str(ref).rsplit("/", 1)[-1]
        return self.cloud

    def join(self, node):
        """(public dict of the joined cloud principal, Grant) or None."""
        binding, external = node.attrs.get("binding"), node.attrs.get("external_id")
        if BINDING_PROVIDER.get(binding) == "aws":
            found = self.related.aws_role(external)
        elif binding == "gke_workload_identity":
            found = self.related.gcp_sa(external)
        elif binding in ("azure_workload_identity", "aks_identity_binding"):
            found = self.related.azure_principal(external)
        else:
            found = None
        if not found:
            return None
        model, principal = found
        data = principal.public()
        data["attrs"] = {"related_snapshot": True, "provider": model.provider}
        return data, Grant("derived", [{"join": binding, "external_id": external, "related_provider": model.provider}])

    def cross_edges(self):
        out = []
        for node in self._cloud_identities().values():
            joined = self.join(node)
            if joined:
                out.append((node, joined[0], joined[1]))
        return out

    def entity(self, cluster):
        cache = self.__dict__.setdefault("_entities", {})
        if cluster not in cache:
            cache[cluster] = Node(f"k8s_cluster_admin:{cluster}", "k8s_cluster_admin", "k8s", cluster,
                                  f"cluster-admin of {cluster}", attrs={"cluster": cluster}, entity=True)
        return cache[cluster]

    def unknown_target_scopes(self, kind):
        if kind == "k8s_service_account":
            return unavailable(inventory_status(self.snapshot, "serviceaccount"))
        if kind == "k8s_node":
            status = inventory_status(self.snapshot, "node")
            return unavailable(status) if status else {c: "not_collected" for c in sorted(self.clusters)}
        return {}

    def allowed_scopes(self, rule, source):
        # RBAC never crosses clusters, whatever the entry's scope rule says.
        cluster = source.attrs.get("cluster")
        cache = self.__dict__.setdefault("_allowed_cache", {})
        if cluster not in cache:
            cache[cluster] = {s for s in self._all_scopes() if s == cluster or s.startswith(f"{cluster}/")}
        return cache[cluster]

    def _all_scopes(self):
        if not hasattr(self, "_scopes_cache"):
            self._scopes_cache = {n.scope for n in self.principals.values()} | set(self.clusters)
        return self._scopes_cache

    def source_matches(self, source, kinds, selector):
        if kinds and source.kind not in as_list(kinds):
            return False
        role = (selector or {}).get("k8s_node_role")
        if role:
            labels = source.attrs.get("labels") or {}
            if f"node-role.kubernetes.io/{role}" not in labels and not (role == "control-plane" and "node-role.kubernetes.io/master" in labels):
                return False
        return True

    def _pods_for_sa(self, sa):
        return [p for p in self.pods if p["cluster"] == sa.attrs["cluster"] and p["ns"] == sa.attrs["namespace"] and p["sa"] == sa.attrs["name"]]

    def selector(self, key, value, candidates, source, pivot=None):
        pods_known = bool(inventory_status(self.snapshot, "pod"))
        if key == "k8s_sa_in_namespace":
            if value in ("*", "{target.namespace}"):
                return dict.fromkeys(candidates)
            wanted = source.attrs.get("namespace") if value == "{source.namespace}" else value
            return {tid: None for tid, n in candidates.items() if n.attrs.get("namespace") == wanted}
        if key == "any_principal_in_scope":
            return dict.fromkeys(candidates)
        if key == "same_as_source":
            return {source.id: None} if source.id in candidates else {}
        if key == "exclude_names":
            names = set(as_list(value))
            return {tid: None for tid, n in candidates.items() if n.attrs.get("name") not in names}
        if key == "k8s_sa_absent_but_bound":
            statuses = inventory_status(self.snapshot, "serviceaccount")
            out = {}
            for tid, n in candidates.items():
                if n.kind != "k8s_service_account" or n.attrs.get("inventoried"):
                    continue
                complete = statuses and all(st in ("collected", "empty") for st in statuses.values())
                out[tid] = None if complete else ("unknown", "serviceaccount_inventory_incomplete")
            return out
        if key == "kube2iam_namespace_permits_role":
            annotations = self.ns_annotations.get(source.attrs.get("cluster") if source else None, {})
            if not annotations:
                return None  # annotations not collected: unknown
            namespaces = [p["pivot.namespace"] for p in pivot or [] if "pivot.namespace" in p] if pivot else list(annotations)
            rules = [annotations[ns] for ns in namespaces if ns in annotations]
            if not rules:
                return {}
            out = {}
            for tid, n in candidates.items():
                verdict = _kube2iam_permits(rules, n.attrs.get("external_id"), n.attrs.get("role_name"))
                if verdict is False:
                    continue
                if verdict == "invalid_regex":
                    out[tid] = ("conditional", "kube2iam_permitted_regex_invalid")
                elif self.related.aws_role(n.attrs.get("external_id")) is None:
                    out[tid] = ("conditional", "kube2iam_role_not_in_related_snapshot")
                else:
                    out[tid] = None
            return out
        if key == "trust_allows_k8s_sa_oidc_subject":
            if source is None or source.kind != "k8s_service_account":
                return {}
            out = {}
            for tid, n in candidates.items():
                arn = n.attrs.get("external_id")
                found = self.related.aws_role(arn)
                if found is None:
                    if self.related.aws_account_covered(arn):
                        continue  # the annotated role does not exist in the related account snapshot
                    out[tid] = ("conditional", "cloud_side_trust_not_verified")
                    continue
                subjects = self.related.oidc_subjects(*found)
                if any(_subject_matches(p, source.attrs["namespace"], source.attrs["name"]) for p in subjects):
                    out[tid] = None if "*" not in subjects else ("conditional", "trust_has_no_sub_condition")
            return out
        if key == "trust_allows_oidc_subject_wildcard":
            if not self.related.has("aws"):
                return None
            namespaces = [p["pivot.namespace"] for p in pivot or [] if "pivot.namespace" in p]
            out = {}
            for tid, n in candidates.items():
                found = self.related.aws_role(n.attrs.get("external_id"))
                if found is None:
                    continue
                subjects = self.related.oidc_subjects(*found)
                if any(_subject_matches(p, ns) for p in subjects for ns in namespaces):
                    out[tid] = None
            return out
        if key == "gcp_workload_identity_user_granted_to_k8s_sa":
            if source is None or source.kind != "k8s_service_account":
                return {}
            if not self.related.has("gcp"):
                return None
            out = {}
            for tid, n in candidates.items():
                email = n.attrs.get("external_id")
                verdict = self.related.gcp_wi_grant(email, source.attrs["namespace"], source.attrs["name"])
                if verdict is None:
                    if not self.related.gcp_project_covered(email):
                        out[tid] = ("conditional", "cloud_side_trust_not_verified")
                elif verdict is not False:
                    out[tid] = None if verdict.confidence == "derived" else ("conditional", "binding_condition")
            return out
        if key == "azure_fic_matches_k8s_sa":
            if not self.related.has("azure"):
                return None
            out = {}
            for tid, n in candidates.items():
                found = self.related.azure_principal(n.attrs.get("external_id"))
                creds = found[1].attrs.get("federated_credentials") if found else None
                if creds is None:
                    out[tid] = ("conditional", "federated_identity_credential_not_collected")
                    continue
                subject = f"system:serviceaccount:{source.attrs.get('namespace')}:{source.attrs.get('name')}"
                if any(str((c or {}).get("subject")) == subject for c in as_list(creds)):
                    out[tid] = None
            return out
        if key == "k8s_node_schedulable":
            return {tid: None for tid, n in candidates.items() if not n.attrs.get("unschedulable")}
        if key in ("k8s_node_hosting_pods_with_sa", "k8s_sa_used_by_running_pod", "k8s_sa_used_by_controller_managed_pod"):
            if not pods_known:
                return None
            out = {}
            for tid, n in candidates.items():
                if n.kind == "k8s_node":
                    if any(p["node"] == n.attrs["name"] and p["cluster"] == n.attrs["cluster"] for p in self.pods):
                        out[tid] = None
                    continue
                pods = self._pods_for_sa(n)
                if key == "k8s_node_hosting_pods_with_sa" and source is not None and source.kind == "k8s_node":
                    pods = [p for p in pods if p["node"] == source.attrs["name"]]
                elif key == "k8s_node_hosting_pods_with_sa":
                    pods = [p for p in pods if p["node"]]
                elif key == "k8s_sa_used_by_running_pod":
                    pods = [p for p in pods if p["running"]]
                else:
                    pods = [p for p in pods if p["owned"]]
                if pods:
                    out[tid] = None
            return out
        if key in ("k8s_node_hosting_pods_in_namespace", "k8s_node_hosting_privileged_pod_in_namespace"):
            if not pods_known:
                return None
            if value == "{pivot.namespace}":
                namespaces = {p["pivot.namespace"] for p in pivot or []} if pivot else None
            elif value == "*":
                namespaces = None
            else:
                namespaces = {value}
            out = {}
            for tid, n in candidates.items():
                for p in self.pods:
                    if p["node"] != n.attrs.get("name") or p["cluster"] != n.attrs.get("cluster"):
                        continue
                    if namespaces is not None and p["ns"] not in namespaces:
                        continue
                    if key.endswith("privileged_pod_in_namespace") and not p["privileged"]:
                        continue
                    out[tid] = None
                    break
            return out
        if key == "k8s_sa_cloud_binding":
            if source is None or source.kind != "k8s_service_account":
                return {}
            out = {}
            for tid, n in candidates.items():
                if n.attrs.get("binding") == value and source.id in n.attrs.get("bound_sas", []):
                    # With the related cloud snapshot the companion selector verifies the cloud side.
                    verified = self.related.has(BINDING_PROVIDER.get(value)) and value in (
                        "irsa", "gke_workload_identity", "azure_workload_identity")
                    out[tid] = None if verified else ("conditional", "cloud_side_trust_not_verified")
            return out
        return None

    def admin_targets(self, principal):
        for ns, rule, evidence in self._rules(principal):
            if rule is None or ns is not None:
                continue
            if "*" in as_list(rule.get("verbs")) and "*" in as_list(rule.get("resources")) and "*" in as_list(rule.get("apiGroups")) \
                    and not rule.get("resourceNames"):
                return [(self.entity(principal.attrs["cluster"]), Grant("derived", [evidence]))]
        return []

    def scope_within(self, inner, outer):
        return inner == outer or inner.startswith(outer + "/")


def _kube2iam_permits(rules, arn, name):
    """True / False / 'invalid_regex' for a role against namespace annotations (kiam regex, kube2iam globs)."""
    values = [v for v in (str(arn or ""), str(name or "")) if v]
    invalid = False
    for rule in rules:
        regex = rule.get("permitted")
        if regex:
            try:
                compiled = re.compile(regex)
            except re.error:
                invalid = True
            else:
                if any(compiled.fullmatch(v) for v in values):
                    return True
        for pattern in rule.get("allowed_roles", ()):
            if any(fnmatch.fnmatchcase(v, pattern) for v in values):
                return True
    return "invalid_regex" if invalid else False


def _rule_matches(rule, verb, group, resource, sub, name, partial=False):
    """True, a condition string (partial match) or False."""
    verbs = [str(v).lower() for v in as_list(rule.get("verbs"))]
    if "*" not in verbs and verb not in verbs:
        return False
    groups = as_list(rule.get("apiGroups"))
    if "*" not in groups and group not in groups:
        return False
    combined = f"{resource}/{sub}" if sub else resource
    ok = False
    for res in as_list(rule.get("resources")):
        res = str(res)
        if res == "*" or res == combined or (sub and res == f"*/{sub}"):
            ok = True
            break
        if partial and "{" in resource:
            ok = True
            break
    if not ok:
        return False
    names = as_list(rule.get("resourceNames"))
    if not names:
        return True
    if verb in NO_NAME_VERBS:
        return False
    if partial:
        return True
    if name is None or name is ANY:
        return "restricted_by_resourceNames"
    return True if name in names else False
