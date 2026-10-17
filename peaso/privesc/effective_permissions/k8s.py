"""Kubernetes RBAC effective permissions.

  * Role/ClusterRole rules bound by RoleBinding (namespace-limited) and
    ClusterRoleBinding (cluster-wide, incl. cluster-scoped resources),
  * ClusterRole aggregation (aggregationRule.clusterRoleSelectors.matchLabels),
  * resource matching per the apiserver: '*' covers subresources, 'res/sub' and
    '*/sub' forms; resourceNames restrict (create/list/watch/deletecollection never
    match a rule restricted by resourceNames, except create on a subresource, which names the parent),
  * service accounts implicitly belong to system:serviceaccounts,
    system:serviceaccounts:<ns> and system:authenticated,
  * cloud identities from SA annotations (IRSA, GKE Workload Identity, Azure
    Workload Identity) and kiam/kube2iam namespace annotations; with related cloud
    snapshots (analyze(..., related_snapshots=[...])) the cloud side is verified
    (IAM role trust / workloadIdentityUser bindings / kube2iam role regexes) and each
    cloud identity is joined to its IAM principal by a cross-snapshot edge,
  * node cloud identities (GKE node-pool service account, EKS node instance role, AKS kubelet identity) from
    related cloud snapshots,
  * provider / control-plane managed subjects (managed_source) are never escalation sources but stay targets.
"""
from __future__ import annotations

import fnmatch
import json
import re

from . import ANY, Grant, Model, Node, as_list, best, combine, downgrade, glob_match, inventory_status, items, unavailable
from .exact_evidence import ExactEvidenceMixin

CLUSTER_SCOPED = {
    "nodes", "namespaces", "clusterroles", "clusterrolebindings", "certificatesigningrequests", "persistentvolumes",
    "mutatingwebhookconfigurations", "validatingwebhookconfigurations", "customresourcedefinitions", "storageclasses",
    "priorityclasses", "apiservices", "tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews", "users", "groups",
    "userextras", "uids", "signers", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings",
    "validatingadmissionpolicies", "validatingadmissionpolicybindings", "runtimeclasses", "csidrivers", "volumeattachments",
    "ingressclasses", "securitycontextconstraints", "clusterissuers",
}
NO_NAME_VERBS = {"create", "list", "watch", "deletecollection"}
# Provider / control-plane managed subjects (see K8sModel.managed_source).
MANAGED_SUBJECT_PREFIXES = ("system:", "eks:")
# Reserved "system:" subjects any customer workload or person can act as: never managed.
ATTACKER_REACHABLE = {"system:authenticated", "system:unauthenticated", "system:anonymous", "system:serviceaccounts",
                      "system:nodes"}
CONTROL_PLANE_USERS = {"kube-apiserver", "kube-apiserver-kubelet-client", "kubelet", "kubelet-bootstrap",
                       "kubelet-nodepool-bootstrap", "kube-controller-manager", "kube-scheduler", "kube-proxy",
                       "aksService", "aks-support", "konnectivity-agent"}
MANAGED_NAMESPACES = {"gmp-system", "gmp-public", "gke-gmp-system", "gke-connect", "gke-mcs", "aks-command",
                      "amazon-guardduty", "amazon-network-flow-monitor"}
MANAGED_NAMESPACE_PREFIXES = ("gke-managed-", "aks-istio-")
MANAGED_LABELS = {"kubernetes.io/bootstrapping": None, "addonmanager.kubernetes.io/mode": None,
                  "kubernetes.azure.com/managedby": None, "eks.amazonaws.com/component": None}
MANAGED_ANNOTATION_PREFIXES = ("components.gke.io/",)
SEP = "\x1f"
PREFIX = "\x1eprefix:"     # requirement-key verb marker for verb_prefix
ANY_MATCH = "\x1eany"      # requirement-key group / resource marker for resource_match: any
# Secret metadata hints (name / label / annotation tokens) of static cloud credentials; data is never collected.
SECRET_CLOUD_HINTS = {
    "gcp": ("gcp", "gcloud", "google", "gcs", "service-account-key", "sa-key", "clouddns", "credentials-json"),
    "aws": ("aws", "access-key", "s3", "route53", "awscreds"),
    "azure": ("azure", "aad", "entra", "client-secret", "azuredns"),
}
NON_CLOUD_SECRET_TYPES = {"kubernetes.io/service-account-token", "kubernetes.io/tls", "kubernetes.io/dockerconfigjson",
                          "kubernetes.io/dockercfg", "helm.sh/release.v1", "bootstrap.kubernetes.io/token"}
REMOTE_CLUSTER_MARKERS = ("argocd.argoproj.io/secret-type=cluster", "cluster.x-k8s.io/cluster-name")
# OpenShift SCC fields that make an SCC host-level (node access from a pod admitted under it).
HOST_SCC_FIELDS = ("allowPrivilegedContainer", "allowHostPID", "allowHostNetwork", "allowHostIPC", "allowHostDirVolumePlugin")


def _managed_meta(meta):
    """True when object metadata carries a provider / addon-manager ownership marker."""
    labels = meta.get("labels") or {}
    annotations = meta.get("annotations") or {}
    return any(k in labels for k in MANAGED_LABELS) or any(
        str(k).startswith(MANAGED_ANNOTATION_PREFIXES) for k in list(labels) + list(annotations))


def _cluster(item, scope=None):
    prov = item.get("provenance") or {}
    meta = item.get("metadata") or {}
    return str(prov.get("cluster_id") or meta.get("cluster_id") or "cluster")


_PH = re.compile(r"(?<!\$)\{([^{}]+)\}")


BINDING_PROVIDER = {"irsa": "aws", "kube2iam": "aws", "eks_pod_identity": "aws", "gke_workload_identity": "gcp",
                    "azure_workload_identity": "azure", "aks_identity_binding": "azure",
                    "gke_node": "gcp", "eks_node": "aws", "aks_kubelet": "azure"}
NODE_BINDINGS = ("gke_node", "eks_node", "aks_kubelet")
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
                if str(node.attrs.get("client_id") or node.attrs.get("app_id") or "").lower() == low or str(node.id).lower() == low:
                    return model, node
        return None

    # ---------------------------------------------------------------- node cloud identities
    def gke_pool(self, cluster_ids, pool_name, project):
        """(email of the node-pool SA, metadata mode 'open' / 'concealed' / None) for a GKE node pool, or None.
        `cluster_ids` are the K8s cluster id and kubeconfig context; unset / "default" SA = the project's default
        compute SA. Mode: GCE_METADATA -> open, GKE_METADATA (Workload Identity) / SECURE -> concealed."""
        for model in self.models["gcp"]:
            resource = next((r for r in (model._match_gke(c) for c in cluster_ids if c) if r), None)
            if resource is None and project:
                named = [r for r, it in model.gke.items() if r.startswith(f"projects/{project}/") and any(
                    (p or {}).get("name") == pool_name for p in as_list(it.get("nodePools")))]
                resource = named[0] if len(named) == 1 else None
            if resource is None:
                continue
            item = model.gke[resource]
            pool = next((p for p in as_list(item.get("nodePools")) if (p or {}).get("name") == pool_name), None)
            if pool is None:
                return None
            config = pool.get("config") or {}
            email = config.get("serviceAccount")
            if email in (None, "", "default"):
                pid = resource.split("/")[1]
                number = next((n for n, p in model.project_alias.items() if p == pid), None)
                if number is None:
                    return None
                email = f"{number}-compute@developer.gserviceaccount.com"
            mode = str((config.get("workloadMetadataConfig") or {}).get("mode") or (
                config.get("workloadMetadataConfig") or {}).get("nodeMetadata") or "").upper()
            state = {"GCE_METADATA": "open", "EXPOSE": "open", "GKE_METADATA": "concealed", "GKE_METADATA_SERVER": "concealed",
                     "SECURE": "concealed"}.get(mode)
            return email, state
        return None

    def aws_instance(self, instance_id):
        """([role arns of the instance profile], metadata 'open' / 'concealed' / None) for an EC2 instance, or None.
        IMDS reachable from a pod: endpoint enabled and (IMDSv1 allowed or a PUT response hop limit >= 2)."""
        for model in self.models["aws"]:
            arn = next((a for a, v in model.instances.items() if v[2] == instance_id), None)
            if arn is None:
                continue
            roles = sorted(r for r, hosts in model.hosts.items() if arn in hosts.get("ec2_instance", []))
            options = next(((it.get("MetadataOptions") or {}) for _, it in items(model.snapshot, "instance")
                            if it.get("InstanceId") == instance_id), {})
            state = None
            if options:
                if str(options.get("HttpEndpoint") or "enabled") == "disabled":
                    state = "blocked"
                elif str(options.get("HttpTokens") or "") == "optional" or int(options.get("HttpPutResponseHopLimit") or 1) >= 2:
                    state = "open"
                else:
                    state = "concealed"
            return roles, state
        return None

    def eks_facts(self, cluster_ids):
        """EKS API facts of the EKS cluster a K8s cluster id / kubeconfig context names (EKS ARN, eksctl context,
        `k8s-cluster:<sha256(origin)>` of the eks_cluster endpoint, or the bare cluster name), from related AWS
        snapshots: {"entries": [eks_access_entry], "associations": [eks_pod_identity_association],
        "entries_state" / "associations_state": "collected" | None, "auth_mode": str | None}; None when no related
        AWS snapshot carries that cluster."""
        import hashlib
        names, account = set(), None
        for cid in cluster_ids:
            cid = str(cid or "")
            arn = re.match(r"arn:aws[\w-]*:eks:[^:]*:(\d{12}):cluster/(.+)$", cid)
            eksctl = re.match(r"^[^@]+@([^.]+)\.[a-z0-9-]+\.eksctl\.io$", cid)
            if arn:
                account = arn.group(1)
                names.add(arn.group(2))
            elif eksctl:
                names.add(eksctl.group(1))
            elif cid and not cid.startswith("k8s-cluster:"):
                names.add(cid.rsplit("/", 1)[-1])
        digests = {str(c) for c in cluster_ids if str(c or "").startswith("k8s-cluster:")}
        for model in self.models["aws"]:
            if account and account not in model.accounts:
                continue
            clusters = {}
            for _, it in items(model.snapshot, "eks_cluster"):
                body = it.get("cluster") if isinstance(it.get("cluster"), dict) else it
                name = body.get("name") or it.get("name")
                if not isinstance(name, str):
                    continue
                endpoint = str(body.get("endpoint") or "").lower().rstrip("/")
                digest = "k8s-cluster:" + hashlib.sha256(endpoint.encode()).hexdigest() if endpoint else None
                clusters[name] = (digest, str(((body.get("accessConfig") or {}).get("authenticationMode")) or "") or None)
            wanted = {n for n in names} | {n for n, (d, _) in clusters.items() if d and d in digests}
            entries = [it for _, it in items(model.snapshot, "eks_access_entry") if it.get("clusterName") in wanted]
            assoc = [it for _, it in items(model.snapshot, "eks_pod_identity_association") if it.get("clusterName") in wanted]
            if not (entries or assoc or wanted & set(clusters)):
                continue

            def state(kind):
                statuses = inventory_status(model.snapshot, kind)
                return "collected" if statuses and not unavailable(statuses) else None
            mode = next((clusters[n][1] for n in sorted(wanted) if n in clusters and clusters[n][1]), None)
            return {"entries": entries, "associations": assoc, "entries_state": state("eks_access_entry"),
                    "associations_state": state("eks_pod_identity_association"), "auth_mode": mode}
        return None

    def pods_trust(self, ref):
        """True / False / None: the role trust admits the EKS Pod Identity service (pods.eks.amazonaws.com)."""
        found = self.aws_role(ref)
        if not found:
            return None
        model, role = found
        return any(st.effect == "allow" and st.action_matches("sts:AssumeRole") and "pods.eks.amazonaws.com" in as_list(
            (st.principals if isinstance(st.principals, dict) else {}).get("Service")) for st in model.trust.get(role.id, []))

    def aks_kubelet(self, node_resource_group):
        """Kubelet identity id (client id, else object id) of the AKS cluster owning a node resource group, or None."""
        low = str(node_resource_group).lower()
        for model in self.models["azure"]:
            for _, item in items(model.snapshot, "aks_cluster"):
                props = item.get("properties") or {}
                if str(props.get("nodeResourceGroup") or "").lower() != low:
                    continue
                kubelet = ((props.get("identityProfile") or {}).get("kubeletidentity") or {})
                return kubelet.get("clientId") or kubelet.get("objectId")
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


class K8sModel(ExactEvidenceMixin, Model):
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
        from .k8s_helm_values_rbac import load as load_helm_values_rbac
        self.helm_values_rbac_targets, self.helm_values_rbac_records = load_helm_values_rbac(self)
        from .k8s_verified_pivots import load as load_verified_pivots
        self.verified_pivot_targets, self.verified_pivot_records = load_verified_pivots(self)
        self.load_exact_evidence("k8s_privesc_challenge_evidence", {"k8s_service_account", "k8s_remote_cluster"})
        self.exact_scopes = set(self.clusters)
        self._load_admission()
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
        # Cluster-flavour and secret facts (metadata only; Secret data is never collected).
        self.api_groups, self.node_providers, self.legacy_tokens, self.configmaps = {}, {}, {}, set()
        for scope, item in items(snap, "api_discovery"):
            self.api_groups.setdefault(_cluster(item), set()).update(
                str((g or {}).get("name")) for g in as_list(item.get("groups")) if isinstance(g, dict))
        self.secrets = []                # (cluster, namespace, name, type, labels, annotations) - metadata only
        self.secret_uids = {}
        self.secret_versions = {}
        for scope, item in items(snap, "secret_metadata"):
            meta = item.get("metadata") or {}
            self.secret_uids.setdefault((_cluster(item), meta.get("namespace"), str(meta.get("name") or "")), []).append(meta.get("uid"))
            self.secret_versions.setdefault((_cluster(item), meta.get("namespace"), str(meta.get("name") or "")), []).append(meta.get("resourceVersion"))
            self.secrets.append((_cluster(item), meta.get("namespace"), str(meta.get("name") or ""), str(item.get("type") or ""),
                                 meta.get("labels") or {}, meta.get("annotations") or {}))
            if str(item.get("type") or "") == "kubernetes.io/service-account-token":
                owner = (meta.get("annotations") or {}).get("kubernetes.io/service-account.name")
                if owner:
                    self.legacy_tokens.setdefault((_cluster(item), meta.get("namespace")), set()).add(str(owner))
        for scope, item in items(snap, "configmap_metadata"):
            meta = item.get("metadata") or {}
            self.configmaps.add((_cluster(item), meta.get("namespace"), meta.get("name")))
        self.ns_annotations = {}
        self.managed_ns = set()          # (cluster, namespace) carrying a provider / addon-manager marker
        self.binding_managed = {}        # (cluster, subject key) -> [binding is provider / control-plane managed]
        self.ns_inventoried = {}         # cluster -> namespaces present in the namespace inventory
        self.ns_labels = {}              # (cluster, namespace) -> labels (kubernetes.io/metadata.name always set)
        for scope, item in items(snap, "namespace"):
            meta = item.get("metadata") or {}
            self.namespaces.setdefault(_cluster(item), set()).add(meta.get("name"))
            self.ns_inventoried.setdefault(_cluster(item), set()).add(meta.get("name"))
            self.ns_labels[(_cluster(item), meta.get("name"))] = {
                "kubernetes.io/metadata.name": str(meta.get("name")), **{str(k): str(v) for k, v in (meta.get("labels") or {}).items()}}
            if _managed_meta(meta):
                self.managed_ns.add((_cluster(item), meta.get("name")))
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
            node.attrs["managed_meta"] = _managed_meta(meta)
            node.attrs["inventoried"] = True
        for scope, item in items(snap, "node"):
            meta = item.get("metadata") or {}
            cluster, name = _cluster(item), meta.get("name")
            provider_id = str((item.get("spec") or {}).get("providerID") or "")
            self.node_providers.setdefault(cluster, set()).add(provider_id.split("://", 1)[0].lower() if "://" in provider_id else "")
            node = Node(f"k8s:{cluster}:node:{name}", "k8s_node", "k8s", cluster, name,
                        attrs={"cluster": cluster, "name": name, "labels": meta.get("labels") or {}, "provider_id": provider_id,
                               "unschedulable": bool((item.get("spec") or {}).get("unschedulable")),
                               "groups": ["system:nodes", "system:authenticated"], "user": f"system:node:{name}"})
            self.nodes[node.id] = node
            self.principals[node.id] = node
            self.clusters.add(cluster)
        for scope, item in items(snap, "pod"):
            meta, spec = item.get("metadata") or {}, item.get("spec") or {}
            cluster, ns = _cluster(item), meta.get("namespace")
            sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
            privileged, host_mount = pod_escape_primitives(spec)
            phase = (item.get("status") or {}).get("phase")
            pod_role = (meta.get("annotations") or {}).get("iam.amazonaws.com/role")
            if pod_role:
                self.pod_roles.setdefault(cluster, set()).add(str(pod_role))
            self.pods.append({"cluster": cluster, "ns": ns, "sa": sa, "node": spec.get("nodeName"), "privileged": privileged,
                              "host_mount": host_mount, "configmaps": pod_configmap_refs(spec),
                              "owned": bool(meta.get("ownerReferences")), "running": phase in (None, "Running", "Pending"),
                              "phase": phase})
            self.namespaces.setdefault(cluster, set()).add(ns)
        self.scc_users = {}              # (cluster, ns, name) -> [SCC names] (OpenShift SCC users[] entries)
        self.host_sccs = {}              # cluster -> {SCC name: {"users": [...], "groups": [...]}} (host-level SCCs)
        for scope, item in items(snap, "securitycontextconstraint"):
            meta = item.get("metadata") or {}
            cluster = _cluster(item)
            if any(item.get(f) is True for f in HOST_SCC_FIELDS):
                self.host_sccs.setdefault(cluster, {})[str(meta.get("name"))] = {
                    "users": [str(u) for u in as_list(item.get("users"))], "groups": [str(g) for g in as_list(item.get("groups"))]}
            for user in as_list(item.get("users")):
                parts = str(user).split(":")
                if len(parts) == 4 and parts[:2] == ["system", "serviceaccount"] and parts[2] and parts[3]:
                    self._sa(cluster, parts[2], parts[3])
                    self.scc_users.setdefault((cluster, parts[2], parts[3]), []).append(str(meta.get("name")))
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
                managed_binding = _managed_meta(meta) or (
                    str(meta.get("name") or "").startswith("system:") and str(ref.get("name") or "").startswith("system:"))
                for subject in as_list(item.get("subjects")):
                    if not isinstance(subject, dict):
                        continue
                    skind, sname = subject.get("kind"), subject.get("name")
                    if skind == "ServiceAccount":
                        sns = subject.get("namespace") or ns
                        key = f"sa:{sns}:{sname}"
                        self._sa(cluster, sns, sname).attrs["binding_ref"] = True
                    elif skind == "Group":
                        key = f"group:{sname}"
                        self._subject(cluster, "k8s_group", sname)
                    else:
                        key = f"user:{sname}"
                        if not str(sname).startswith("system:node:"):
                            self._subject(cluster, "k8s_user", sname)
                    self.bindings.setdefault((cluster, key), []).append((ns, role_key, evidence))
                    self.binding_managed.setdefault((cluster, key), []).append(managed_binding)
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
        verb = PREFIX + str(req["verb_prefix"]).lower() if req.get("verb_prefix") else str(req.get("verb", "")).lower()
        if req.get("resource_match") == "any":
            group = str(req["api_group"]) if "api_group" in req else ANY_MATCH
            return "|".join([verb, group, ANY_MATCH, ""])
        return "|".join([verb, str(req.get("api_group", "")), str(req.get("resource", "")),
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
        verb, group, resource, sub = self.requirement_key(req).split("|")
        if req.get("resource_match") != "any":
            resource = str(req.get("resource", ""))
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
        if isinstance(req, dict) and req.get("resource_name") == "{source_rolebound_clusterrole}":
            result = {}
            for target in candidates:
                ns = target.attrs.get("namespace")
                names = {role[2] for bind_ns, role, _ in principal.attrs.get("bound", ())
                         if bind_ns == ns and self.roles.get(role, {}).get("kind") == "ClusterRole"
                         and role[0] == target.attrs.get("cluster")}
                for name in names:
                    grants = {}
                    for verb in ("escalate", "update", "patch"):
                        for bind_ns, rule, evidence in self._rules(principal):
                            if rule is None or bind_ns is not None:
                                continue
                            match = _rule_matches(rule, verb, "rbac.authorization.k8s.io", "clusterroles", "", name)
                            if match:
                                conf = "derived" if match is True else "conditional"
                                grants[verb] = best(grants.get(verb), Grant(conf, [{**evidence, "namespace": bind_ns or "*"}],
                                                                         [] if match is True else [str(match)]))
                    if grants.get("escalate") and (grants.get("update") or grants.get("patch")) and grants.get(req.get("verb")):
                        # Keep the authorization proof tied to this ClusterRole name.
                        # Returning only the current verb lets the evaluator take a
                        # derived escalate on one name and a derived patch on another,
                        # even when neither name has both permissions derived.
                        companion = (best(grants.get("update"), grants.get("patch"))
                                     if req["verb"] == "escalate" else grants["escalate"])
                        grant = combine(grants[req["verb"]], companion)
                        if self.roles.get((target.attrs.get("cluster"), None, name), {}).get("aggregation"):
                            grant = downgrade(grant, "conditional", "aggregated_clusterrole_rules_may_be_overwritten")
                        result[target.id] = best(result.get(target.id), grant)
            return result
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
            # A ClusterRole only grants cluster-wide power when a ClusterRoleBinding (ns None) binds it to the source;
            # a RoleBinding to a ClusterRole confines it to one namespace, so escalating it does not yield cluster-admin.
            # A Role only helps in its own namespace: with a target, keep only Roles bound in the target's namespace.
            target_ns = target.attrs.get("namespace") if target is not None else None
            return sorted({role[2] for ns, role, ev in source.attrs.get("bound", ())
                           if self.roles.get(role, {}).get("kind") == wanted
                           and (ns is None if wanted == "ClusterRole" else (target_ns is None or ns == target_ns))})
        if name == "source_rolebound_clusterrole":
            ns = target.attrs.get("namespace") if target is not None else None
            return sorted({role[2] for bind_ns, role, _ in source.attrs.get("bound", ())
                           if bind_ns == ns and bind_ns is not None
                           and self.roles.get(role, {}).get("kind") == "ClusterRole"})
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
                return sorted({p["node"] for p in self._pods_for_sa(node) if p["node"]})
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
        # A ServiceAccount (and its token/subresources) lives in its namespace: a namespaced Role there covers it,
        # not only ClusterRoleBindings ("*" would demand a cluster-wide grant).
        namespace = "{target.namespace}" if kind == "k8s_service_account" else "*"
        req = {"verb": verb, "resource": resource, "namespace": namespace}
        if name:
            req["resource_name"] = name
        return req

    # --------------------------------------------------------- preconditions
    EKS_PROVIDER_PREFIXES = ("aws", "eks-hybrid")

    def _complete(self, kind):
        statuses = inventory_status(self.snapshot, kind)
        return bool(statuses) and all(st in ("collected", "empty") for st in statuses.values())

    def _is_openshift(self, cluster):
        """True / False / None (api_discovery not collected for the cluster)."""
        groups = self.api_groups.get(cluster)
        if groups is None:
            return None
        return any(g == "openshift.io" or g.endswith(".openshift.io") for g in groups)

    def _is_eks(self, cluster):
        """True / False / None from node providerIDs, EKS API groups and the aws-auth ConfigMap."""
        providers = self.node_providers.get(cluster, set())
        groups = self.api_groups.get(cluster, set())
        if any(p.startswith(self.EKS_PROVIDER_PREFIXES) for p in providers) \
                or any(g.endswith((".k8s.aws", ".amazonaws.com")) for g in groups) \
                or (cluster, "kube-system", "aws-auth") in self.configmaps:
            return True
        nodes_known = self._complete("node") and bool(providers)
        if nodes_known and "" not in providers:
            return False  # every node reports a non-AWS providerID (kind://, gce://, azure://, ...)
        if nodes_known and cluster in self.api_groups and self._complete("configmap_metadata"):
            return False  # no AWS providerID, no EKS API group and no aws-auth ConfigMap
        return None

    def precondition(self, pid, candidates, source):
        checks = {"k8s_eks_cluster": (self._is_eks, "eks_cluster_not_determined"),
                  "k8s_openshift_cluster": (self._is_openshift, "api_discovery_not_collected")}
        if pid not in checks:
            return None
        check, why = checks[pid]
        out = {}
        for tid, n in candidates.items():
            verdict = check(n.attrs.get("cluster"))
            if verdict is True:
                out[tid] = None
            elif verdict is None:
                out[tid] = ("unknown", why)
        return out

    # -------------------------------------------------------------- blockers
    def _load_admission(self):
        """Workload-admission facts: CEL admission policies + bindings, validating webhooks (failurePolicy, rules,
        namespaceSelector) and their collection states (None: not collected / failed; 'absent': API not served)."""
        snap = self.snapshot
        self.admission_policies, self.admission_bindings, self.validating_webhooks = {}, [], []
        states = inventory_status(snap, "admission_policy")
        absent = any(((c.get("error") or {}).get("code") == "admission_policy_api_absent")
                     for c in snap.get("collections", []) if c.get("type") == "admission_policy")
        self.admission_policy_state = "absent" if absent else (
            "collected" if states and not unavailable(states) else None)
        for scope, item in items(snap, "admission_policy"):
            kind, meta, spec = str(item.get("kind") or ""), item.get("metadata") or {}, item.get("spec") or {}
            cluster = _cluster(item)
            if kind.endswith("PolicyBinding"):
                self.admission_bindings.append((cluster, kind, str(meta.get("name")), spec))
            elif kind.endswith("AdmissionPolicy"):
                self.admission_policies[(cluster, kind, str(meta.get("name")))] = spec
        states = inventory_status(snap, "admission_configuration")
        self.webhook_state = "collected" if states and not unavailable(states) else None
        for scope, item in items(snap, "admission_configuration"):
            if str(item.get("kind") or "") != "ValidatingWebhookConfiguration":
                continue  # mutating webhooks usually inject (sidecars, credentials); only validating ones reject
            meta = item.get("metadata") or {}
            for hook in as_list(item.get("webhooks")):
                if isinstance(hook, dict):
                    self.validating_webhooks.append((_cluster(item), str(meta.get("name")), hook))

    def _blocker_resources(self, compiled):
        """(api group, resource[/subresource]) pairs the technique sends through admission: Pods (controllers create
        them too) plus every requirement resource."""
        out = {("", "pods")}
        for alt in compiled["alternatives"]:
            for req in alt:
                raw = req.raw
                if isinstance(raw, dict) and raw.get("resource"):
                    res = str(raw["resource"]) + ("/" + str(raw["subresource"]) if raw.get("subresource") else "")
                    out.add((str(raw.get("api_group") or ""), res))
                    if raw.get("subresource"):
                        out.add(("", "pods/" + str(raw["subresource"])) if raw["resource"] == "pods" else ("", "pods"))
        return out

    def _workload_namespaces(self, compiled):
        """('pivot', None) | ('target', None) | ('fixed', [namespaces]) | ('all', None): where the workload is created."""
        cache = self.__dict__.setdefault("_wl_ns", {})
        eid = compiled["entry"].get("id")
        if eid not in cache:
            values = [str(r.raw.get("namespace")) for alt in compiled["alternatives"] for r in alt
                      if isinstance(r.raw, dict) and r.raw.get("namespace") is not None]
            if any("{pivot.namespace}" in v for v in values):
                cache[eid] = ("pivot", None)
            elif any("{target.namespace}" in v for v in values):
                cache[eid] = ("target", None)
            elif values and all(v != "*" and "{" not in v for v in values):
                cache[eid] = ("fixed", sorted(set(values)))
            else:
                cache[eid] = ("all", None)
        return cache[eid]

    K8S_BLOCKERS = ("pod_security_admission", "pivot_namespace_psa_enforce_baseline_or_restricted", "admission_policy",
                    "admission_webhook", "kyverno_policy", "gatekeeper_constraint")
    POLICY_ENGINE_GROUPS = {"kyverno_policy": ("Kyverno", ("kyverno.io", "policies.kyverno.io")),
                            "gatekeeper_constraint": ("OPA Gatekeeper", ("templates.gatekeeper.sh", "constraints.gatekeeper.sh",
                                                                         "config.gatekeeper.sh"))}

    def blocker_verdict(self, blocker, source, compiled, pivots=None, reached=None, cset=None):
        if blocker not in self.K8S_BLOCKERS:
            return None
        cluster = source.attrs.get("cluster")
        if blocker in self.POLICY_ENGINE_GROUPS:
            name, wanted = self.POLICY_ENGINE_GROUPS[blocker]
            groups = self.api_groups.get(cluster)
            if groups is None:
                return None
            served = sorted(g for g in groups if g in wanted)
            if not served:
                return "clear"
            return ("possibly_blocked", f"{name} is installed (API groups {', '.join(served)}); its policies are not "
                                        "collected, so whether one rejects this workload is not decided")
        mode, fixed = self._workload_namespaces(compiled)
        resources = self._blocker_resources(compiled)
        if mode == "pivot":
            if not pivots:
                return None
            return self._ns_verdict(blocker, cluster, sorted({p.get("pivot.namespace") for p in pivots if p.get("pivot.namespace")}),
                                    resources)
        if mode == "target":
            if not isinstance(reached, dict) or cset is None:
                return None
            out = {}
            for tid in reached:
                node = cset.members.get(tid)
                if node is not None and node.attrs.get("namespace"):
                    out[tid] = self._ns_verdict(blocker, node.attrs.get("cluster", cluster), [node.attrs["namespace"]], resources)
            return out
        namespaces = fixed if mode == "fixed" else sorted(n for n in self.namespaces.get(cluster, ()) if n)
        return self._ns_verdict(blocker, cluster, namespaces, resources)

    def _ns_verdict(self, blocker, cluster, namespaces, resources):
        """The attacker picks the most permissive namespace: clear < not evaluated < possibly_blocked < blocked."""
        if not namespaces:
            return None
        rank = {"clear": 0, None: 1, "possibly_blocked": 2, "blocked": 3}
        best_state, evidence = "blocked", []
        for ns in namespaces:
            state, why = self._one_ns_verdict(blocker, cluster, ns, resources)
            if rank[state] < rank[best_state]:
                best_state, evidence = state, []
            if state == best_state and why:
                evidence.append(why)
        if best_state in ("clear", None):
            return best_state
        shown = "; ".join(evidence[:3]) + (f"; +{len(evidence) - 3} more" if len(evidence) > 3 else "")
        return (best_state, shown)

    def _one_ns_verdict(self, blocker, cluster, ns, resources):
        labels = self.ns_labels.get((cluster, ns))
        if blocker in ("pod_security_admission", "pivot_namespace_psa_enforce_baseline_or_restricted"):
            if labels is None:
                return None, None
            level = labels.get("pod-security.kubernetes.io/enforce")
            if level in ("baseline", "restricted"):
                # Baseline already rejects privileged containers, host namespaces, hostPath and added capabilities.
                return "blocked", (f"namespace {ns} enforces Pod Security '{level}' (label pod-security.kubernetes.io/enforce; "
                                   "API-server PSA exemptions are not collected)")
            return "clear", None
        if blocker == "admission_policy":
            if self.admission_policy_state == "absent":
                return "clear", None
            if self.admission_policy_state is None:
                return None, None
            hits, undecided = [], False
            for bcluster, kind, name, spec in self.admission_bindings:
                if bcluster != cluster:
                    continue
                validating = kind.startswith("Validating")
                actions = [str(a) for a in as_list(spec.get("validationActions"))]
                if validating and actions and "Deny" not in actions:
                    continue  # Warn / Audit only
                policy_kind = kind[:-len("Binding")]
                policy = self.admission_policies.get((cluster, policy_kind, str(spec.get("policyName"))))
                if policy is None:
                    continue  # a binding without its policy admits everything
                match = _admission_match(policy.get("matchConstraints") or {}, resources, labels)
                bound = _admission_match(spec.get("matchResources") or {}, resources, labels, default=True)
                if match is False or bound is False:
                    continue
                if match is None or bound is None:
                    undecided = True
                hits.append(f"{policy_kind} {spec.get('policyName')} bound by {name}"
                            + (f" (validationActions {','.join(actions)})" if actions else "")
                            + f" matches the workload in namespace {ns}")
            if hits:
                return "possibly_blocked", "; ".join(hits[:3]) + (" (namespace labels unknown)" if undecided else "")
            return "clear", None
        if blocker == "admission_webhook":
            if self.webhook_state is None:
                return None, None
            hits = []
            for wcluster, config, hook in self.validating_webhooks:
                if wcluster != cluster:
                    continue
                match = _webhook_match(hook, resources, labels)
                if match is False:
                    continue
                hits.append(f"ValidatingWebhookConfiguration {config}/{hook.get('name')} "
                            f"(failurePolicy {hook.get('failurePolicy') or 'Fail'}) intercepts the workload in namespace {ns}")
            if hits:
                return "possibly_blocked", "; ".join(hits[:3])
            return "clear", None
        return None, None

    # --------------------------------------------------------------- targets
    def targets(self, kind):
        if kind == "k8s_verified_authority":
            return list(self.helm_values_rbac_targets.values()) + [
                node for node in self.verified_pivot_targets.values() if node.kind == kind]
        if kind == "k8s_service_account":
            return list(self.sas.values())
        if kind == "k8s_node":
            return list(self.nodes.values())
        if kind in ("k8s_user", "k8s_group"):
            return [n for n in self.principals.values() if n.kind == kind]
        if kind == "k8s_cluster_admin":
            return [self.entity(c) for c in sorted(self.clusters)]
        if kind == "cloud_identity":
            return [n for n in self._cloud_identities().values() if n.attrs.get("variant") is None] + [
                node for node in self.verified_pivot_targets.values() if node.kind == kind]
        if kind == "k8s_admission_control":
            return [self.admission_entity(c) for c in sorted(self.clusters)]
        if kind == "k8s_remote_cluster":
            return self._remote_clusters() + [
                node for node in self.verified_pivot_targets.values() if node.kind == kind]
        return []

    def admission_entity(self, cluster):
        cache = self.__dict__.setdefault("_admission", {})
        if cluster not in cache:
            cache[cluster] = Node(f"k8s_admission_control:{cluster}", "k8s_admission_control", "k8s", cluster,
                                  f"Admission enforcement of {cluster}", attrs={"cluster": cluster, "name": cluster}, entity=True)
        return cache[cluster]

    def _secret_nodes(self, kind, prefix, label, wanted):
        out = []
        for cluster, ns, name, stype, labels, annotations in self.secrets:
            if stype == "kubernetes.io/service-account-token":
                continue
            hit = wanted(name, stype, labels, annotations)
            if hit:
                out.append(Node(f"{prefix}:{cluster}/{ns}/{name}", kind, "k8s", f"{cluster}/{ns}", label(ns, name),
                                attrs={"cluster": cluster, "namespace": ns, "name": name, "secret_type": stype,
                                       "labels": labels, "hint": hit, "variant": "secret"}))
        return out

    def _remote_clusters(self):
        cache = self.__dict__.get("_remote_cache")
        if cache is None:
            def marker(name, stype, labels, annotations):
                return ["labelled"] if labels else None  # the selector matches the label markers
            cache = self._remote_cache = self._secret_nodes(
                "k8s_remote_cluster", "k8s_remote_cluster", lambda ns, n: f"Remote cluster credential in Secret {ns}/{n}", marker)
        return cache

    def _secret_credentials(self):
        cache = self.__dict__.get("_secret_cred_cache")
        if cache is None:
            def hint(name, stype, labels, annotations):
                if stype in NON_CLOUD_SECRET_TYPES:
                    return None
                text = " ".join([name] + [f"{k} {v}" for k, v in labels.items()] + list(annotations))
                tokens = set(re.split(r"[^a-z0-9]+", text.lower()))
                found = sorted(p for p, hints in SECRET_CLOUD_HINTS.items()
                               if any((h in tokens) if "-" not in h else (h in text.lower()) for h in hints))
                return found or None
            cache = self._secret_nodes("cloud_identity", "cloud:k8s_secret", lambda ns, n: f"Cloud credential in Secret {ns}/{n}", hint)
            if not self._complete("secret_metadata"):
                # Secret metadata missing: one placeholder per cluster, resolved as an unresolved target by the selector.
                cache = cache + [Node(f"cloud:k8s_secret:{c}/*", "cloud_identity", "k8s", c, f"Cloud credentials in Secrets of {c}",
                                      attrs={"cluster": c, "variant": "secret", "placeholder": True}) for c in sorted(self.clusters)]
            self._secret_cred_cache = cache
        return cache

    def target_variant(self, kind, selector):
        if kind == "k8s_service_account":
            # A ServiceAccount only named by a binding subject does not exist: pods, TokenRequests and token Secrets
            # need it. Only the dangling-reference technique (create it) and impersonation (any name) target it.
            # The variant is part of the evaluator's candidate-set key, so the two sets are never shared.
            if {"k8s_sa_absent_but_bound", "k8s_sa_namespace_absent", "k8s_sa_named_in_scc_users"} & set(selector) \
                    or str(selector.get("resource_permission_covers_target") or "").startswith("serviceaccounts:impersonate"):
                return "with_binding_only_sas"
            return None
        if kind != "cloud_identity":
            return None
        if "k8s_verified_pivot" in selector:
            return "verified_pivot"
        if "k8s_secret_holds_cloud_credential" in selector:
            return "secret_credential"
        if "kube2iam_namespace_permits_role" in selector:
            return "kube2iam"
        if "trust_allows_oidc_subject_wildcard" in selector:
            return "oidc_wildcard"
        return None

    def targets_for(self, kind, selector):
        from .credential_evidence import ARGOCD_MOUNT, LEGACY_SA_TOKEN, CREATED_SA_TOKEN
        if kind == "k8s_remote_cluster" and selector.get("k8s_challenge_fact") == ARGOCD_MOUNT:
            return self._remote_clusters()
        if kind == "k8s_service_account" and selector.get("k8s_challenge_fact") in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
            return [n for n in self.sas.values() if n.attrs.get("inventoried")]
        exact = self.exact_targets_for(kind, selector)
        if exact is not None:
            return exact
        variant = self.target_variant(kind, selector)
        if kind == "k8s_service_account":
            if variant is None and self._complete("serviceaccount"):
                return [n for n in self.sas.values() if n.attrs.get("inventoried")]
            return self.targets(kind)
        if variant is None:
            return self.targets(kind)
        if variant == "secret_credential":
            return self._secret_credentials()
        if variant == "verified_pivot":
            return [node for node in self.verified_pivot_targets.values() if node.kind == kind]
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
                                                 "bound_sas": [], "variant": variant, "bound": ()})
            node.perm_key = (cluster, ())
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
            context = str((self.snapshot.get("metadata") or {}).get("context") or "")
            # EKS Pod Identity associations (eks:DescribePodIdentityAssociation) of the matching EKS cluster.
            for cluster in clusters:
                eks = self.related.eks_facts((cluster, context)) if self.related.has("aws") else None
                for assoc in (eks or {}).get("associations") or ():
                    role = assoc.get("targetRoleArn") or assoc.get("roleArn")
                    if not (role and assoc.get("namespace") and assoc.get("serviceAccount")):
                        continue
                    node = self._cloud_node("eks_pod_identity", role, cluster, "IAM role")
                    sid = f"k8s:{cluster}:sa:{assoc['namespace']}:{assoc['serviceAccount']}"
                    if sid not in node.attrs["bound_sas"]:
                        node.attrs["bound_sas"].append(sid)
                    node.attrs.setdefault("associations", []).append(assoc.get("associationArn") or assoc.get("id"))
            self._node_identities()
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

    def _node_identities(self):
        """Node cloud identities from related cloud snapshots: GKE node-pool SA, EKS node instance role, AKS kubelet
        identity. attrs.nodes lists the K8s nodes carrying it, attrs.imds the metadata reachability per node."""
        context = str((self.snapshot.get("metadata") or {}).get("context") or "")
        self.node_identity_unresolved = set()
        for node in sorted(self.nodes.values(), key=lambda n: n.id):
            provider_id = node.attrs.get("provider_id") or ""
            labels = node.attrs.get("labels") or {}
            found = []  # (binding, external id, label, imds state)
            if provider_id.startswith("gce://") and self.related.has("gcp"):
                project = provider_id[len("gce://"):].split("/", 1)[0]
                pool = self.related.gke_pool((node.attrs["cluster"], context), labels.get("cloud.google.com/gke-nodepool"), project)
                if pool:
                    found.append(("gke_node", pool[0], "GCP SA", pool[1]))
            elif provider_id.startswith("aws://") and self.related.has("aws"):
                instance = self.related.aws_instance(provider_id.rsplit("/", 1)[-1])
                if instance:
                    found += [("eks_node", role, "IAM role", instance[1]) for role in instance[0]]
            elif provider_id.startswith("azure://") and self.related.has("azure"):
                match = re.search(r"/resourcegroups/([^/]+)/", provider_id.lower())
                kubelet = self.related.aks_kubelet(match.group(1)) if match else None
                if kubelet:
                    found.append(("aks_kubelet", kubelet, "AKS kubelet identity", "open"))
            if not found:
                self.node_identity_unresolved.add(node.attrs["cluster"])
            for binding, external, label, state in found:
                ident = self._cloud_node(binding, external, node.attrs["cluster"], label)
                ident.attrs.setdefault("nodes", []).append(node.id)
                ident.attrs.setdefault("imds", {})[node.id] = state
        # EKS access entries (eks:DescribeAccessEntry {type}) of the node roles: k8s_nodes_mapped_to_cloud_identity.
        eks_by_cluster = {}
        for ident in self.cloud.values():
            if ident.attrs.get("binding") != "eks_node":
                continue
            cluster = ident.attrs["cluster"]
            if cluster not in eks_by_cluster:
                eks_by_cluster[cluster] = self.related.eks_facts((cluster, context))
            eks = eks_by_cluster[cluster] or {}
            name = str(ident.attrs["external_id"]).rsplit("/", 1)[-1]
            mine = [e for e in eks.get("entries") or () if str(e.get("principalArn") or "") == ident.attrs["external_id"]
                    or (str(e.get("principalArn") or "").rsplit("/", 1)[-1] == name and ":role/" in str(e.get("principalArn")))]
            typed = [e for e in mine if "type" not in (e.get("_coverage") or {})]
            ident.attrs["access_entry_types"] = sorted({str(e.get("type")) for e in typed if e.get("type")})
            ident.attrs["access_entry_state"] = "collected" if eks.get("entries_state") == "collected" and len(typed) == len(mine) else None
            ident.attrs["auth_mode"] = eks.get("auth_mode")

    def _node_identity_verdict(self, ident, source):
        """None (derived) / (confidence, why) / False for a node cloud identity and a technique source."""
        nodes = ident.attrs.get("nodes") or []
        if source is not None and source.kind == "k8s_node":
            return None if source.id in nodes else False
        if source is not None and source.attrs.get("cluster") not in (None, ident.attrs.get("cluster")):
            return False
        states = [ident.attrs.get("imds", {}).get(n) for n in nodes]
        if "hostnetwork" in str((self.current_entry or {}).get("id") or "") or "host_network" in str(
                (self.current_entry or {}).get("id") or ""):
            # hostNetwork pods are not intercepted by the GKE metadata server nor limited by the IMDS hop limit.
            return None if any(s != "blocked" for s in states) else False
        if "open" in states:
            return None  # a pod can be scheduled (nodeSelector) onto a node whose metadata is reachable
        if None in states:
            return ("conditional", "node_metadata_access_not_verified")
        if "concealed" in states:
            return ("conditional", "node_metadata_concealed")  # GKE_METADATA / IMDSv2 hop limit 1
        return False

    def join(self, node):
        """(public dict of the joined cloud principal, Grant) or None."""
        binding, external = node.attrs.get("binding"), node.attrs.get("external_id")
        if BINDING_PROVIDER.get(binding) == "aws":
            found = self.related.aws_role(external)
        elif binding == "gke_workload_identity":
            found = self.related.gcp_sa(external)
        elif binding == "gke_node":
            found = self.related.gcp_sa(external)
        elif binding in ("azure_workload_identity", "aks_identity_binding", "aks_kubelet"):
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
        from .credential_evidence import LEGACY_SA_TOKEN, CREATED_SA_TOKEN
        if (self.current_selector or {}).get("k8s_challenge_fact") in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
            return {}
        if kind == "k8s_verified_authority":
            return {}
        if (self.current_selector or {}).get("k8s_challenge_fact"):
            return self.exact_unknown_target_scopes()
        if kind == "k8s_service_account":
            return unavailable(inventory_status(self.snapshot, "serviceaccount"))
        if kind == "k8s_node":
            status = inventory_status(self.snapshot, "node")
            return unavailable(status) if status else {c: "not_collected" for c in sorted(self.clusters)}
        if kind == "k8s_remote_cluster":
            status = inventory_status(self.snapshot, "secret_metadata")
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
            self._scopes_cache = {n.scope for n in self.principals.values()} | set(self.clusters) | {
                f"{cluster}/{ns}" for cluster, ns, *_ in self.secrets}
        return self._scopes_cache

    def sources(self):
        out = list(self.principals.values())
        if self.related.has("aws"):
            out += [n for n in sorted(self._cloud_identities().values(), key=lambda n: n.id) if n.attrs.get("binding") == "eks_node"]
        return out

    def source_matches(self, source, kinds, selector):
        technique = (self.current_selector or {}).get("k8s_challenge_fact")
        if technique and not self.exact_source_matches(technique, source):
            return False
        if kinds and source.kind not in as_list(kinds):
            return False
        entry_type = (selector or {}).get("eks_access_entry_type")
        if entry_type:
            if source.kind != "cloud_identity" or source.attrs.get("binding") != "eks_node":
                return False
            types = source.attrs.get("access_entry_types") or ()
            if types and entry_type not in types:
                return False  # access entry of another type; no entry / facts missing: decided by the target selector
        aggregated = (selector or {}).get("source_bound_to_aggregated_clusterrole")
        if aggregated and not any(self.roles.get(role, {}).get("aggregation") and role[1] is None
                                  and (ns is None or aggregated is True)
                                  for ns, role, ev in source.attrs.get("bound", ())):
            return False
        role = (selector or {}).get("k8s_node_role")
        if role:
            labels = source.attrs.get("labels") or {}
            if f"node-role.kubernetes.io/{role}" not in labels and not (role == "control-plane" and "node-role.kubernetes.io/master" in labels):
                return False
        return True

    def _ns_has_sa_with_host_scc(self, cluster, namespaces):
        """An SA of one of the namespaces (None = any) may use a host-level SCC: SCC users[]/groups[] or RBAC `use`."""
        sccs = self.host_sccs.get(cluster) or {}
        if not sccs:
            return False
        for scc in sccs.values():
            for group in scc["groups"]:
                if group in ("system:authenticated", "system:serviceaccounts") or (
                        group.startswith("system:serviceaccounts:") and (namespaces is None or group.split(":", 2)[2] in namespaces)):
                    return True
            for user in scc["users"]:
                parts = user.split(":")
                if len(parts) == 4 and parts[:2] == ["system", "serviceaccount"] and (namespaces is None or parts[2] in namespaces):
                    return True
        for sa in self.sas.values():
            if sa.attrs.get("cluster") != cluster or (namespaces is not None and sa.attrs.get("namespace") not in namespaces):
                continue
            for _ns, rule, _ev in self._rules(sa):
                if rule is not None and any(_rule_matches(rule, "use", "security.openshift.io", "securitycontextconstraints", "", name) is True
                                            for name in sccs):
                    return True
        return False

    def _pod_index(self):
        """({(cluster, ns, sa): [pods]}, {(node, cluster): [pods]}), each list in self.pods order; rebuilt if self.pods grows.
        None when a key value is unhashable (callers then scan self.pods as before)."""
        cached = self.__dict__.get("_pod_index_cache")
        if cached is not None and cached[0] == len(self.pods):
            return cached[1]
        index = None
        try:
            by_sa, by_node = {}, {}
            for p in self.pods:
                by_sa.setdefault((p["cluster"], p["ns"], p["sa"]), []).append(p)
                by_node.setdefault((p["node"], p["cluster"]), []).append(p)
            index = (by_sa, by_node)
        except TypeError:
            index = None
        self._pod_index_cache = (len(self.pods), index)
        return index

    def _pods_for_sa(self, sa):
        index = self._pod_index()
        if index is not None:
            try:
                return list(index[0].get((sa.attrs["cluster"], sa.attrs["namespace"], sa.attrs["name"]), ()))
            except TypeError:
                pass
        return [p for p in self.pods if p["cluster"] == sa.attrs["cluster"] and p["ns"] == sa.attrs["namespace"] and p["sa"] == sa.attrs["name"]]

    def _pods_on_node(self, name, cluster):
        """Pods with p["node"] == name and p["cluster"] == cluster, in self.pods order."""
        index = self._pod_index()
        if index is not None:
            try:
                return index[1].get((name, cluster), ())
            except TypeError:
                pass
        return [p for p in self.pods if p["node"] == name and p["cluster"] == cluster]

    def _node_hosts_pod(self, node):
        index = self._pod_index()
        if index is not None:
            try:
                return (node.attrs["name"], node.attrs["cluster"]) in index[1]
            except TypeError:
                pass
        return any(p["node"] == node.attrs["name"] and p["cluster"] == node.attrs["cluster"] for p in self.pods)

    def selector(self, key, value, candidates, source, pivot=None):
        if key == "k8s_verified_pivot":
            from .k8s_verified_pivots import select
            return select(self, value, candidates, source, pivot)
        if key == "k8s_helm_values_rbac":
            if source is None:
                return None
            return {target_id: ("conditional", "reviewed_helm_values_to_rbac_grant")
                    for target_id in candidates
                    if (record := self.helm_values_rbac_records.get(target_id))
                    and record["SourceId"] == source.id}
        if key == "k8s_challenge_fact":
            from .credential_evidence import (ARGOCD_MOUNT, LEGACY_SA_TOKEN, CREATED_SA_TOKEN,
                                              argocd_credential, legacy_sa_token_credential)
            if value in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
                if source is None:
                    return None
                out = {}
                for target_id, target in candidates.items():
                    cluster = target.attrs.get("cluster")
                    records = self.exact_evidence.get((value, source.id, target.kind, target_id, cluster), ())
                    if (self.exact_status.get(cluster) in ("collected", "empty") and len(records) == 1
                            and legacy_sa_token_credential(self, records[0], source, target,
                                                           created=value == CREATED_SA_TOKEN)):
                        out[target_id] = ("conditional", "reviewed_usable_legacy_service_account_token")
                return out
            if value == ARGOCD_MOUNT:
                if source is None:
                    return None
                out = {}
                for target_id, target in candidates.items():
                    cluster = target.attrs.get("cluster")
                    records = self.exact_evidence.get((value, source.id, target.kind, target_id, cluster), ())
                    if not records:
                        continue
                    if (self.exact_status.get(cluster) in ("collected", "empty") and len(records) == 1
                            and argocd_credential(self, records[0], source, target)):
                        out[target_id] = ("conditional", "exact_admitted_mount_and_remote_credential")
                    elif any(record.get("Status") != "disproven" for record in records):
                        out[target_id] = ("unknown", "remote_credential_or_admission_unverified")
                return out
            return self.exact_selector(value, candidates, source)
        if key == "k8s_nodes_mapped_to_cloud_identity":
            if source is None or source.kind != "cloud_identity" or source.attrs.get("binding") != "eks_node":
                return {}
            mapped = [n for n in source.attrs.get("nodes") or () if n in candidates]
            if source.attrs.get("access_entry_state") != "collected":
                return None  # EKS access entries of the cluster not in a related AWS snapshot
            if any(t in ("EC2_LINUX", "EC2_WINDOWS") for t in source.attrs.get("access_entry_types") or ()):
                return dict.fromkeys(mapped)
            if source.attrs.get("auth_mode") == "API":
                return {}  # API-only authentication ignores aws-auth: without a node access entry the role is not mapped
            return {n: ("conditional", "eks_node_mapping_via_aws_auth_not_collected") for n in mapped}
        if key == "k8s_node_cloud_identity":
            self._cloud_identities()
            cluster = source.attrs.get("cluster") if source is not None else None
            out = {}
            for tid, n in candidates.items():
                if n.attrs.get("binding") not in NODE_BINDINGS:
                    continue
                verdict = self._node_identity_verdict(n, source)
                if verdict is not False:
                    out[tid] = verdict
            if not out and (cluster is None or cluster in getattr(self, "node_identity_unresolved", {cluster})):
                return None  # node identity not resolvable without the related cloud snapshot: unresolved
            return out
        pods_known = bool(inventory_status(self.snapshot, "pod"))
        if key == "k8s_sa_has_legacy_token_secret":
            if not self._complete("secret_metadata"):
                from .credential_evidence import LEGACY_SA_TOKEN, CREATED_SA_TOKEN
                if (self.current_selector or {}).get("k8s_challenge_fact") in (LEGACY_SA_TOKEN, CREATED_SA_TOKEN):
                    return {}
                return None
            return {tid: None for tid, n in candidates.items()
                    if n.attrs.get("name") in self.legacy_tokens.get((n.attrs.get("cluster"), n.attrs.get("namespace")), ())}
        if key == "openshift_namespace_has_sa_with_host_scc":
            clusters = {source.attrs.get("cluster")} if source is not None else {n.attrs.get("cluster") for n in candidates.values()}
            if clusters and all(self._is_openshift(c) is False for c in clusters):
                return {}  # not OpenShift: no SCCs exist, the technique does not apply
            if not self._complete("securitycontextconstraint"):
                return None  # securitycontextconstraints not collected (or incomplete)
            if value == "{pivot.namespace}":
                namespaces = {p["pivot.namespace"] for p in pivot or []} if pivot else None
            else:
                namespaces = None if value in ("*", True) else {value}
            hosting = {c for c in clusters if self._ns_has_sa_with_host_scc(c, namespaces)}
            return {tid: None for tid, n in candidates.items() if n.attrs.get("cluster") in hosting}
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
        if key == "k8s_sa_used_by_pending_pod":
            if not pods_known:
                return None
            return {tid: None for tid, n in candidates.items() if n.kind == "k8s_service_account"
                    and any(p["phase"] == "Pending" and not p["node"] for p in self._pods_for_sa(n))}
        if key == "k8s_node_hosting_pod_of_source":
            if source is None or source.kind != "k8s_service_account":
                return {}
            if not pods_known:
                return None
            hosts = {p["node"] for p in self._pods_for_sa(source) if p["node"] and p["running"]}
            return {tid: None for tid, n in candidates.items() if n.kind == "k8s_node" and n.attrs.get("name") in hosts}
        if key == "k8s_sa_namespace_absent":
            complete = self._complete("namespace")
            out = {}
            for tid, n in candidates.items():
                cluster, ns = n.attrs.get("cluster"), n.attrs.get("namespace")
                if n.kind != "k8s_service_account" or n.attrs.get("inventoried") or not (
                        n.attrs.get("binding_ref") or (cluster, ns, n.attrs.get("name")) in self.scc_users):
                    continue
                if ns in self.ns_inventoried.get(cluster, ()):
                    continue
                out[tid] = None if complete else ("unknown", "namespace_inventory_incomplete")
            return out
        if key == "k8s_sa_named_in_scc_users":
            if self._complete("securitycontextconstraint"):
                return {tid: None for tid, n in candidates.items()
                        if (n.attrs.get("cluster"), n.attrs.get("namespace"), n.attrs.get("name")) in self.scc_users}
            clusters = {n.attrs.get("cluster") for n in candidates.values()}
            if clusters and all(self._is_openshift(c) is False for c in clusters):
                return {}
            return None  # securitycontextconstraint not collected on an OpenShift (or undetermined) cluster
        if key == "k8s_secret_holds_cloud_credential":
            wanted = {"aws", "gcp", "azure"} if value is True or "any" in as_list(value) else set(as_list(value))
            out = {}
            for tid, n in candidates.items():
                if n.attrs.get("placeholder"):
                    out[tid] = ("unknown", "secret_metadata_not_collected")
                elif set(n.attrs.get("hint") or ()) & wanted:
                    out[tid] = ("conditional", "secret_content_not_verified")
            return out
        if key == "k8s_secret_holds_remote_cluster_credential":
            markers = REMOTE_CLUSTER_MARKERS if value is True else tuple(as_list(value))
            out = {}
            for tid, n in candidates.items():
                labels = n.attrs.get("labels") or {}
                for m in markers:
                    if _label_matches(labels, m) and (m != "cluster.x-k8s.io/cluster-name" or str(n.attrs.get("name")).endswith("-kubeconfig")):
                        out[tid] = None
                        break
            return out
        if key == "k8s_sa_absent_but_bound":
            statuses = inventory_status(self.snapshot, "serviceaccount")
            out = {}
            for tid, n in candidates.items():
                if n.kind != "k8s_service_account" or n.attrs.get("inventoried") or not n.attrs.get("binding_ref"):
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
        if key == "k8s_sa_name":
            names = {str(v) for v in as_list(value)}
            return {tid: None for tid, n in candidates.items() if n.attrs.get("name") in names}
        if key == "k8s_sa_used_by_pod_consuming_configmap":
            if not pods_known:
                return None
            return {tid: ("conditional", "configmap_consumer_executes_content_not_verified")
                    for tid, n in candidates.items() if n.kind == "k8s_service_account"
                    and any(p["configmaps"] and p["running"] for p in self._pods_for_sa(n))}
        if key in ("k8s_node_hosting_pods_with_sa", "k8s_sa_used_by_running_pod", "k8s_sa_used_by_controller_managed_pod"):
            if not pods_known:
                return None
            out = {}
            for tid, n in candidates.items():
                if n.kind == "k8s_node":
                    if self._node_hosts_pod(n):
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
        if key in ("k8s_node_hosting_pods_in_namespace", "k8s_node_hosting_privileged_pod_in_namespace",
                   "k8s_node_hosting_host_mount_pod_in_namespace"):
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
                for p in self._pods_on_node(n.attrs.get("name"), n.attrs.get("cluster")):
                    if namespaces is not None and p["ns"] not in namespaces:
                        continue
                    field = {"k8s_node_hosting_privileged_pod_in_namespace": "privileged",
                             "k8s_node_hosting_host_mount_pod_in_namespace": "host_mount"}.get(key)
                    if field is None:
                        out[tid] = None
                        break
                    verdict = p.get(field)
                    if verdict is True:
                        out[tid] = None
                        break
                    if verdict and tid not in out:
                        out[tid] = ("conditional", verdict)
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
                    if value == "eks_pod_identity":
                        # The association itself comes from the EKS API; the role trust must admit pods.eks.amazonaws.com.
                        verified = self.related.pods_trust(n.attrs.get("external_id")) is True
                    out[tid] = None if verified else ("conditional", "cloud_side_trust_not_verified")
            return out
        return None

    def managed_source(self, node):
        """Provider / control-plane managed subjects: reserved `system:` / `eks:` users and groups (except the
        groups and users any workload or person can act as), known control-plane users (kube-apiserver,
        kubelet-bootstrap, ...), and ServiceAccounts of kube-system or a provider-managed namespace (gke-managed-*,
        gmp-system, addon-manager labelled, ...) or carrying a provider marker, when every binding naming them is
        provider-created (`kubernetes.io/bootstrapping`, `addonmanager.kubernetes.io/mode`, `components.gke.io/*`,
        reserved `system:` binding to a `system:` role). A user-created binding naming the subject keeps it a source.
        They are never escalation sources; they stay targets (reaching system:masters is still admin)."""
        cache = self.__dict__.setdefault("_managed_cache", {})
        if node.id in cache:
            return cache[node.id]
        cluster = node.attrs.get("cluster")
        verdict = False
        if node.kind in ("k8s_user", "k8s_group"):
            name = str(node.attrs.get("name") or "")
            if name.startswith(MANAGED_SUBJECT_PREFIXES) and name not in ATTACKER_REACHABLE and \
                    not name.startswith(("system:serviceaccounts:", "system:node:", "system:serviceaccount:")):
                verdict = True
            elif name in CONTROL_PLANE_USERS:
                verdict = True
            if verdict:
                kind = "group" if node.kind == "k8s_group" else "user"
                verdict = all(self.binding_managed.get((cluster, f"{kind}:{name}"), [True])) or name.startswith(
                    MANAGED_SUBJECT_PREFIXES)  # reserved names cannot be held by customer credentials
        elif node.kind == "k8s_service_account":
            ns = str(node.attrs.get("namespace") or "")
            managed_ns = ns == "kube-system" or ns in MANAGED_NAMESPACES or ns.startswith(MANAGED_NAMESPACE_PREFIXES) \
                or (cluster, ns) in self.managed_ns
            if managed_ns or node.attrs.get("managed_meta"):
                flags = [f for key in (f"sa:{ns}:{node.attrs.get('name')}", f"user:{node.attrs.get('user')}")
                         for f in self.binding_managed.get((cluster, key), [])]
                verdict = all(flags) if flags else ns != "kube-system" or bool(node.attrs.get("managed_meta"))
        cache[node.id] = verdict
        return verdict

    def admin_targets(self, principal):
        if self.managed_source(principal):
            return []  # control-plane identities: not escalation sources (system:masters stays an admin target)
        for ns, rule, evidence in self._rules(principal):
            if rule is None or ns is not None:
                continue
            if "*" in as_list(rule.get("verbs")) and "*" in as_list(rule.get("resources")) and "*" in as_list(rule.get("apiGroups")) \
                    and not rule.get("resourceNames"):
                return [(self.entity(principal.attrs["cluster"]), Grant("derived", [evidence]))]
        return []

    def scope_within(self, inner, outer):
        return inner == outer or inner.startswith(outer + "/")

    def scope_containers(self, inner):
        """{outer : scope_within(inner, outer)}: inner itself and every prefix ending right before a '/'."""
        if not isinstance(inner, str):
            return frozenset((inner,))
        return frozenset([inner] + [inner[:i] for i, ch in enumerate(inner) if ch == "/"])


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


def _selector_matches(selector, labels):
    """LabelSelector against labels: True / False / None (labels unknown or unsupported operator)."""
    if not isinstance(selector, dict) or not selector:
        return True
    if labels is None:
        return None
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(str(key)) != str(value):
            return False
    for expr in as_list(selector.get("matchExpressions")):
        if not isinstance(expr, dict):
            return None
        key, op, values = str(expr.get("key")), expr.get("operator"), [str(v) for v in as_list(expr.get("values"))]
        if op == "In":
            ok = labels.get(key) in values
        elif op == "NotIn":
            ok = labels.get(key) not in values
        elif op == "Exists":
            ok = key in labels
        elif op == "DoesNotExist":
            ok = key not in labels
        else:
            return None
        if not ok:
            return False
    return True


def _rule_hits(rule, resources, operations=("CREATE", "UPDATE")):
    """An admission RuleWithOperations / NamedRuleWithOperations covers one of (api group, resource) on CREATE/UPDATE."""
    if not isinstance(rule, dict):
        return False
    ops = [str(o) for o in as_list(rule.get("operations"))]
    if not any(o == "*" or o in operations for o in ops):
        return False
    groups = [str(g) for g in as_list(rule.get("apiGroups"))]
    names = [str(r) for r in as_list(rule.get("resources"))]
    for group, resource in resources:
        if not any(g == "*" or g == group for g in groups):
            continue
        base, _, sub = resource.partition("/")
        for name in names:
            nbase, _, nsub = name.partition("/")
            if (nbase in ("*", base)) and ((not sub and not nsub) or nsub == "*" or (sub and nsub == sub)):
                return True
    return False


def _admission_match(match, resources, labels, default=False):
    """MatchResources of a CEL admission policy / binding: True / False / None (namespace labels unknown). An empty
    binding matchResources defers to the policy (default=True)."""
    rules = as_list(match.get("resourceRules"))
    if rules:
        if not any(_rule_hits(r, resources) for r in rules):
            return False
    elif not default:
        return False  # a policy without resourceRules matches nothing
    if any(_rule_hits(r, resources) for r in as_list(match.get("excludeResourceRules"))):
        return False
    return _selector_matches(match.get("namespaceSelector"), labels)


def _webhook_match(hook, resources, labels):
    if not any(_rule_hits(r, resources) for r in as_list(hook.get("rules"))):
        return False
    return _selector_matches(hook.get("namespaceSelector"), labels)


def _label_matches(labels, selector):
    key, eq, value = str(selector).partition("=")
    return key in labels and (not eq or str(labels[key]) == value)


def _rule_matches(rule, verb, group, resource, sub, name, partial=False):
    """True, a condition string (partial match) or False."""
    verbs = [str(v).lower() for v in as_list(rule.get("verbs"))]
    if verb.startswith(PREFIX):
        prefix = verb[len(PREFIX):]
        if "*" not in verbs and not any(v.startswith(prefix) for v in verbs):
            return False
    elif "*" not in verbs and verb not in verbs:
        return False
    groups = as_list(rule.get("apiGroups"))
    if group != ANY_MATCH and "*" not in groups and group not in groups:
        return False
    if resource == ANY_MATCH:
        # resource_match: any - any resource the rule names (resourceNames only narrow it further).
        return bool(as_list(rule.get("resources")))
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
    if verb in NO_NAME_VERBS and not (verb == "create" and (sub or "/" in str(resource))):
        return False  # a create on a subresource (serviceaccounts/token, pods/exec, ...) carries the parent's name
    if partial:
        return True
    if name is None or name is ANY:
        return "restricted_by_resourceNames"
    return True if name in names else False


# ---- container-escape classification (catalog refresh, see SCHEMA_EXTENSIONS.md) -------------------------
# Verdicts: None = no node-escape primitive, True = derived, str = conditional reason id.
# hostNetwork / hostIPC alone and hostPID without SYS_PTRACE or privileged are NOT node escapes; writable
# /var/log (kubelet log symlink) is version dependent and not counted.
_RUNTIME_SOCKETS = ("/run/containerd/containerd.sock", "/run/docker.sock", "/run/crio/crio.sock", "/run/dockershim.sock",
                    "/run/k3s/containerd/containerd.sock", "/run/podman/podman.sock", "/run/buildkit/buildkitd.sock")
# Read access (even readOnly) exposes node credentials: mounting the path or any ancestor (or a credential subtree).
_CRED_LEAVES = ("/var/lib/kubelet/pki", "/var/lib/kubelet/kubeconfig", "/var/lib/kubelet/pods",
                "/var/lib/rancher/k3s/agent")
_CRED_SUBTREES = ("/var/lib/kubelet/pki", "/var/lib/rancher/k3s/agent")
_CRED_LEAVES_CONDITIONAL = ("/etc/kubernetes", "/etc/rancher/k3s")
# Write access yields code execution as host root (paths the host executes or consumes).
_WRITE_LEAVES = ("/etc/crontab", "/etc/cron.d", "/etc/systemd", "/etc/kubernetes/manifests", "/etc/sudoers.d",
                 "/etc/ld.so.preload", "/etc/passwd", "/etc/shadow", "/etc/profile.d", "/root/.ssh", "/usr/bin",
                 "/usr/sbin", "/usr/local/bin", "/usr/lib", "/bin", "/sbin", "/lib", "/lib64", "/opt/cni/bin",
                 "/var/spool/cron", "/proc/sys/kernel/core_pattern", "/sys/kernel/uevent_helper")
_WRITE_SUBTREES = ("/etc/cron.d", "/etc/systemd", "/etc/kubernetes/manifests", "/etc/sudoers.d", "/etc/profile.d",
                   "/root/.ssh", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/lib", "/bin", "/sbin", "/lib",
                   "/lib64", "/opt/cni/bin", "/var/spool/cron")
_WRITE_LEAVES_CONDITIONAL = ("/home", "/var/lib/docker", "/var/lib/containerd", "/sys/fs/cgroup")
_ESCAPE_CAPS = {"SYS_ADMIN": "cap_sys_admin_constrained_by_seccomp_apparmor", "SYS_MODULE": "kernel_module_loading_restricted",
                "ALL": "cap_sys_admin_constrained_by_seccomp_apparmor", "DAC_READ_SEARCH": "open_by_handle_at_blocked_by_seccomp"}


def _norm_path(path):
    path = "/" + str(path or "").strip().strip("/")
    path = re.sub(r"/+", "/", path)
    return "/run" + path[len("/var/run"):] if path == "/var/run" or path.startswith("/var/run/") else path


def _under(path, roots):
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def _ancestor_of(path, targets):
    return any(t == path or path == "/" or t.startswith(path + "/") for t in targets)


def _pod_containers(spec):
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for c in as_list(spec.get(key)):
            if isinstance(c, dict):
                yield c


def pod_escape_primitives(spec):
    """Return (privileged_verdict, host_mount_verdict) for a pod spec."""
    spec = spec or {}
    priv = None
    for c in _pod_containers(spec):
        sc = c.get("securityContext") or {}
        if sc.get("privileged") is True:
            return True, _host_mount_verdict(spec)
        caps = {str(x).upper().removeprefix("CAP_") for x in as_list((sc.get("capabilities") or {}).get("add"))}
        for cap, reason in _ESCAPE_CAPS.items():
            if cap in caps and priv is None:
                priv = reason
        if "SYS_PTRACE" in caps and spec.get("hostPID") and priv is None:
            priv = "ptrace_restricted_by_apparmor_or_yama"
    return priv, _host_mount_verdict(spec)


def _host_mount_verdict(spec):
    host = {v.get("name"): _norm_path((v.get("hostPath") or {}).get("path"))
            for v in as_list(spec.get("volumes")) if isinstance(v, dict) and isinstance(v.get("hostPath"), dict)}
    if not host:
        return None
    verdict = None
    for c in _pod_containers(spec):
        for m in as_list(c.get("volumeMounts")):
            if not isinstance(m, dict) or m.get("name") not in host:
                continue
            path, writable = host[m["name"]], not m.get("readOnly")
            if m.get("subPath") or m.get("subPathExpr"):
                verdict = verdict or "hostpath_subpath_narrows_mount"
                continue
            if _ancestor_of(path, _RUNTIME_SOCKETS) or _ancestor_of(path, _CRED_LEAVES) or _under(path, _CRED_SUBTREES):
                return True
            if writable and (_ancestor_of(path, _WRITE_LEAVES) or _under(path, _WRITE_SUBTREES)):
                return True
            if _ancestor_of(path, _CRED_LEAVES_CONDITIONAL) or _under(path, _CRED_LEAVES_CONDITIONAL):
                verdict = verdict or "node_credential_location_varies"
            elif writable and (_ancestor_of(path, _WRITE_LEAVES_CONDITIONAL) or _under(path, _WRITE_LEAVES_CONDITIONAL)):
                verdict = verdict or "host_write_needs_host_consumer"
    return verdict


def pod_configmap_refs(spec):
    """Names of ConfigMaps a pod consumes (volumes, projected volumes, envFrom, env valueFrom)."""
    spec, names = spec or {}, set()
    for v in as_list(spec.get("volumes")):
        if not isinstance(v, dict):
            continue
        if isinstance(v.get("configMap"), dict):
            names.add(v["configMap"].get("name"))
        for src in as_list((v.get("projected") or {}).get("sources")):
            if isinstance(src, dict) and isinstance(src.get("configMap"), dict):
                names.add(src["configMap"].get("name"))
    for c in _pod_containers(spec):
        for ef in as_list(c.get("envFrom")):
            if isinstance(ef, dict) and isinstance(ef.get("configMapRef"), dict):
                names.add(ef["configMapRef"].get("name"))
        for e in as_list(c.get("env")):
            ref = ((e or {}).get("valueFrom") or {}).get("configMapKeyRef") if isinstance(e, dict) else None
            if isinstance(ref, dict):
                names.add(ref.get("name"))
    names.discard(None)
    names.discard("kube-root-ca.crt")
    return sorted(names)
