"""HackTricks Cloud Best Practices: Kubernetes checks not covered by Prowler/Powerpipe.

Derived from the HackTricks Kubernetes privilege-escalation and post-exploitation
pages. RBAC predicates read declared Role/ClusterRole rules only (aggregation,
bindings and admission are separate facts); provider/control-plane-managed
objects are re-labelled by peaso.checks.k8s_managed like every k8s check.
"""
from __future__ import annotations

from . import result
from .facts import Unavailable, get, list_of_objects, optional
from .fixtures import CASES
from .hacktricks_bp_common import ht_register

PRIVESC = "pentesting-cloud/kubernetes-security/kubernetes-privilege-escalation/"
POST = "pentesting-cloud/kubernetes-security/kubernetes-post-exploitation/"
RBAC_REMEDIATION = ("Remove the grant or narrow it with resourceNames to the vetted operator/administrator identities "
                    "that need it; bind it only to those subjects.")


def _strings(value, what):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise Unavailable("malformed RBAC rule " + what)
    return value


def _resource_match(declared, wanted):
    if declared in ("*", wanted):
        return True
    if declared.endswith("/*") and "/" in wanted and wanted.split("/", 1)[0] == declared[:-2]:
        return True
    return declared.startswith("*/") and "/" in wanted and wanted.split("/", 1)[1] == declared[2:]


def matching_rules(item, grants):
    """Declared rules matching any (apiGroups, resources, verbs) grant. A rule without
    apiGroups is a nonResourceURLs rule and grants no API resource."""
    hits = []
    for rule in list_of_objects(get(item, "rules", list)):
        groups = _strings(optional(rule, "apiGroups", [], list), "apiGroups")
        resources = _strings(optional(rule, "resources", [], list), "resources")
        verbs = _strings(get(rule, "verbs", list), "verbs")
        names = _strings(optional(rule, "resourceNames", [], list), "resourceNames")
        for api_groups, wanted_resources, wanted_verbs in grants:
            if not ("*" in groups or set(groups) & set(api_groups)):
                continue
            resource_hits = sorted({w for w in wanted_resources for d in resources if _resource_match(d, w)})
            verb_hits = sorted(set(verbs) & set(wanted_verbs)) or (["*"] if "*" in verbs else [])
            if resource_hits and verb_hits:
                hits.append({"apiGroups": groups, "resources": resource_hits, "verbs": verb_hits,
                             **({"resourceNames": names} if names else {})})
    return hits


def rbac_check(slug, title, grants, severity, page, remediation=RBAC_REMEDIATION):
    for kind, label in (("role", "Role"), ("clusterrole", "ClusterRole")):
        cid = "k8s.htbp." + kind + "." + slug

        @ht_register(cid, "k8s", "least_privilege", kind, label + " " + title, severity, "AC-6", remediation, pages=[page])
        def evaluate(item, index, grants=grants):
            hits = matching_rules(item, grants)
            return result(bool(hits), matching_rules=hits,
                          semantics="Declared RBAC rules (resourceNames shown when they narrow the grant); bindings, "
                                    "aggregation and admission are evaluated separately")
        api_groups, resources, verbs = grants[0]
        CASES[cid] = {"pass": {"rules": [{"apiGroups": [""], "resources": ["pods", "configmaps"], "verbs": ["get", "list", "watch"]}]},
                      "fail": {"rules": [{"apiGroups": [api_groups[0]], "resources": [resources[0]], "verbs": [verbs[0]]}]},
                      "missing": {}, "malformed": {"rules": [{"apiGroups": [""], "resources": "pods", "verbs": ["*"]}]}}


rbac_check("no_impersonation", "does not grant impersonation of users or service accounts",
           [(("", "authentication.k8s.io"), ("users", "serviceaccounts"), ("impersonate",))], "high",
           PRIVESC + "rbac-and-identities.md",
           "Remove impersonate on users/serviceaccounts except for vetted break-glass or proxy identities, and pin resourceNames.")
rbac_check("no_pod_interactive_access", "does not grant exec, attach, port-forward or ephemeral containers on pods",
           [(("",), ("pods/exec", "pods/attach", "pods/portforward"), ("create",)),
            (("",), ("pods/ephemeralcontainers",), ("patch", "update"))], "high",
           PRIVESC + "workload-and-pod-access.md",
           "Restrict pods/exec, pods/attach, pods/portforward and pods/ephemeralcontainers to break-glass operators; "
           "regular users should not run commands inside workloads that hold ServiceAccount tokens or secrets.")
rbac_check("no_workload_controller_write", "does not grant create/update/patch on workload controllers",
           [(("apps",), ("deployments", "daemonsets", "statefulsets", "replicasets"), ("create", "update", "patch")),
            (("batch",), ("jobs", "cronjobs"), ("create", "update", "patch")),
            (("",), ("replicationcontrollers",), ("create", "update", "patch"))], "medium",
           PRIVESC + "workload-and-pod-access.md",
           "Controller writes are equivalent to pod creation with any ServiceAccount of the namespace; grant them only to "
           "deployment pipelines/operators and enforce Pod Security Admission on the namespace.")
rbac_check("no_service_status_write", "does not grant update/patch on services/status",
           [(("",), ("services/status",), ("update", "patch"))], "medium",
           PRIVESC + "storage-and-networking.md",
           "Only cloud/load-balancer controllers should write services/status (CVE-2020-8554 interception); remove the grant from other roles.")


@ht_register("k8s.htbp.service.no_external_ips", "k8s", "network", "service", "Service does not declare spec.externalIPs",
             "medium", "SC-7", "Remove spec.externalIPs unless the address is administrator-owned and routed to the cluster; enable "
             "the DenyServiceExternalIPs admission plugin or an admission policy restricting the field (CVE-2020-8554).",
             pages=[POST + "internal-network-attacks.md"])
def service_external_ips(item, index):
    spec = get(item, "spec", dict)
    addresses = optional(spec, "externalIPs", [], list)
    if any(not isinstance(x, str) for x in addresses):
        raise Unavailable("malformed externalIPs")
    return result(bool(addresses), external_ips=addresses,
                  semantics="Declared Service field; kube-proxy captures traffic to these destinations from cluster nodes and pods")


CASES["k8s.htbp.service.no_external_ips"] = {
    "pass": {"metadata": {"name": "api", "namespace": "apps"}, "spec": {"type": "ClusterIP", "ports": [{"port": 443}]}},
    "fail": {"metadata": {"name": "api", "namespace": "apps"}, "spec": {"type": "ClusterIP", "externalIPs": ["203.0.113.10"]}},
    "missing": {"metadata": {"name": "api"}}, "malformed": {"spec": {"externalIPs": "203.0.113.10"}}}


@ht_register("k8s.htbp.secret.no_legacy_service_account_token", "k8s", "hardening", "secret_metadata",
             "Secret is not a long-lived legacy ServiceAccount token", "medium", "IA-5",
             "Delete legacy kubernetes.io/service-account-token Secrets and use short-lived projected tokens "
             "(TokenRequest); legacy tokens never expire and stay valid until the Secret is deleted.",
             pages=[PRIVESC + "secrets-and-configmaps.md"])
def legacy_sa_token(item, index):
    kind = get(item, "type", str)
    return result(kind == "kubernetes.io/service-account-token", secret_type=kind,
                  service_account=optional(optional(item, "metadata", {}, dict), "annotations", {}, dict).get("kubernetes.io/service-account.name"),
                  semantics="Secret type from metadata only; the token value was never read")


CASES["k8s.htbp.secret.no_legacy_service_account_token"] = {
    "pass": {"metadata": {"name": "tls", "namespace": "apps"}, "type": "kubernetes.io/tls"},
    "fail": {"metadata": {"name": "ci-token", "namespace": "apps", "annotations": {"kubernetes.io/service-account.name": "ci"}},
             "type": "kubernetes.io/service-account-token"},
    "missing": {"metadata": {"name": "x", "namespace": "apps"}}, "malformed": {"metadata": {"name": "x"}, "type": 3}}


# kubeadm publishes the cluster-info ConfigMap in kube-public to system:anonymous for node bootstrap discovery.
KUBEADM_CLUSTER_INFO = ("kube-public", "kubeadm:bootstrap-signer-clusterinfo")


def anonymous_binding(kind, label):
    cid = "k8s.htbp." + kind + ".no_anonymous_user"

    @ht_register(cid, "k8s", "iam_graph", kind, label + " does not bind the system:anonymous user", "high", "AC-3",
                 "Remove the system:anonymous subject; unauthenticated callers must not receive RBAC grants. Disable "
                 "anonymous authentication or limit it to health endpoints.",
                 pages=["pentesting-cloud/kubernetes-security/kubernetes-unauthenticated-access/README.md"])
    def evaluate(item, index):
        ref = get(item, "roleRef", dict)
        role = get(ref, "name", str)
        subjects = list_of_objects(optional(item, "subjects", [], list))
        anonymous = [s for s in subjects if get(s, "kind", str) == "User" and get(s, "name", str) == "system:anonymous"]
        metadata = optional(item, "metadata", {}, dict)
        if anonymous and kind == "rolebinding" and (metadata.get("namespace"), role) == KUBEADM_CLUSTER_INFO:
            return "NOT_APPLICABLE", {"reason": "kubeadm cluster-info discovery binding in kube-public", "role_ref": ref}
        return result(bool(anonymous), anonymous_subjects=anonymous, role_ref=ref,
                      semantics="Declared binding; system:unauthenticated groups are covered by k8s.rbac.review_*_subjects")
    binding = {"metadata": {"name": "b", "namespace": "apps"}, "roleRef": {"kind": "ClusterRole", "name": "view"}}
    CASES[cid] = {"pass": {**binding, "subjects": [{"kind": "User", "name": "alice"}]},
                  "fail": {**binding, "subjects": [{"kind": "User", "name": "system:anonymous", "apiGroup": "rbac.authorization.k8s.io"}]},
                  "missing": {"metadata": {"name": "b"}}, "malformed": {**binding, "subjects": [{"kind": "User", "name": 1}]}}


anonymous_binding("rolebinding", "RoleBinding")
anonymous_binding("clusterrolebinding", "ClusterRoleBinding")
