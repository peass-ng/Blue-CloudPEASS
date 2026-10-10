"""Namespace, declared RBAC and legacy admission metadata predicates."""
import copy
from . import register, result, unknown
from .facts import get, optional, complete_items, Unavailable, list_of_objects
from .fixtures import CASES

IDS, REFERENCE_SPECS = [], {}
NAMESPACE_KINDS = {"pod": "pod", "deployment": "deployment", "daemonset": "daemonset", "statefulset": "statefulset",
    "replicaset": "replicaset", "replication_controller": "replicationcontroller", "job": "job", "cronjob": "cronjob",
    "role": "role", "role_binding": "rolebinding", "service": "service", "service_account": "serviceaccount",
    "ingress": "ingress", "config_map": "configmap_metadata", "secret": "secret_metadata"}


def named(kind, query, title, function, good, bad, *, dependencies=None):
    cid = "k8s.ports." + kind + "." + query
    IDS.append(cid)
    register(cid, "k8s", "hardening", kind, title, "medium", "AC-6",
        "Review the declared configuration and its administrative scope; effective admission, authorization and networking need separate evidence.",
        dependencies=dependencies)(function)
    CASES[cid] = {"pass": good, "fail": bad, "missing": {}, "malformed": None}
    REFERENCE_SPECS[query] = cid
    return cid


def namespace_rule(kind, query):
    def evaluate(item, index):
        namespace = get(item, "metadata.namespace", str)
        return result(namespace == "default", namespace=namespace,
            semantics="Administrative placement; namespaces are not network subnets")
    return named(kind, query, kind + " avoids the default namespace", evaluate,
        {"metadata": {"namespace": "apps"}}, {"metadata": {"namespace": "default"}})


for _prefix, _kind in NAMESPACE_KINDS.items():
    namespace_rule(_kind, _prefix + "_default_namespace_used")


def default_subject(item, index):
    subjects = list_of_objects(get(item, "subjects", list))
    defaults = [row for row in subjects if get(row, "kind", str) == "ServiceAccount" and get(row, "name", str) == "default"]
    return result(bool(defaults), default_serviceaccount_subjects=defaults,
        semantics="Declared binding subject, not a calculated effective permission")


named("rolebinding", "role_binding_default_service_account_binding_not_active", "RoleBinding avoids default service-account subjects",
    default_subject, {"subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "apps"}]},
    {"subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "apps"}]})
named("clusterrolebinding", "cluster_role_binding_default_service_account_binding_not_active", "ClusterRoleBinding avoids default service-account subjects",
    default_subject, {"subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "apps"}]},
    {"subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "apps"}]})


def wildcard(item, index):
    rules = list_of_objects(get(item, "rules", list))
    violations = []
    for row in rules:
        for key in ("apiGroups", "resources", "verbs"):
            values = optional(row, key, [], list)
            if any(not isinstance(value, str) for value in values):
                raise Unavailable("malformed RBAC string list")
            if any("*" in value for value in values):
                violations.append({"field": key, "values": values})
    return result(bool(violations), declared_wildcards=violations)


named("clusterrole", "role_with_wildcards_used", "ClusterRole restricts declared wildcard patterns", wildcard,
    {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
    {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]}]})


def rbac_rule(query, group, resources, verbs, kind="clusterrole"):
    def evaluate(item, index):
        violations = []
        for row in list_of_objects(get(item, "rules", list)):
            groups, declared_resources, declared_verbs = [get(row, key, list) for key in ("apiGroups", "resources", "verbs")]
            if any(not isinstance(value, str) for values in (groups, declared_resources, declared_verbs) for value in values):
                raise Unavailable("malformed RBAC string lists")
            # Exact source symbols are preserved; broader wildcard review is a
            # separate predicate and no action/privilege chain is constructed.
            if group in groups and set(declared_resources).intersection(resources) and set(declared_verbs).intersection(verbs):
                violations.append(row)
        return result(bool(violations), declared_sensitive_rules=violations,
            semantics="Declared RBAC capability requiring owner review, not effective authorization")
    cid = named(kind, query, "Review " + query.replace("_", " "), evaluate,
        {"rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
        {"rules": [{"apiGroups": [group], "resources": [resources[0]], "verbs": [verbs[0]]}]})
    return cid


_cluster_escalate = rbac_rule("role_with_rbac_escalate_permissions", "rbac.authorization.k8s.io", ["roles", "clusterroles"], ["escalate"])
_role_escalate = rbac_rule("role_with_rbac_escalate_permissions", "rbac.authorization.k8s.io", ["roles", "clusterroles"], ["escalate"], kind="role")
REFERENCE_SPECS["role_with_rbac_escalate_permissions"] = [_cluster_escalate, _role_escalate]
rbac_rule("cluster_role_with_validating_or_mutating_admission_webhook_configurations", "admissionregistration.k8s.io",
          ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"], ["create", "update", "patch"])
def csr_review(item, index):
    violations = []
    for row in list_of_objects(get(item, "rules", list)):
        groups, resources, verbs = [get(row, key, list) for key in ("apiGroups", "resources", "verbs")]
        if any(not isinstance(value, str) for values in (groups, resources, verbs) for value in values):
            raise Unavailable("malformed RBAC policy symbols")
        if "certificates.k8s.io" in groups and (("certificatesigningrequests/approval" in resources and
            set(verbs).intersection({"update", "patch"})) or ("signers" in resources and "approve" in verbs)):
            violations.append(row)
    return result(bool(violations), declared_csr_approval_rules=violations,
        semantics="Declared permissions requiring review; signer restrictions and bindings remain separate")

named("clusterrole", "role_with_rbac_approve_certificate_signing_requests", "Review declared CSR approval capabilities", csr_review,
    {"rules": [{"apiGroups": ["certificates.k8s.io"], "resources": ["signers"], "verbs": ["get"]}]},
    {"rules": [{"apiGroups": ["certificates.k8s.io"], "resources": ["signers"], "verbs": ["approve"]}]})


def service_type(item, index):
    configured = get(item, "spec.type", str)
    if configured not in ("ClusterIP", "ExternalName", "NodePort", "LoadBalancer"):
        return unknown("unrecognized Service type")
    return result(configured in ("NodePort", "LoadBalancer"), service_type=configured,
        semantics="Publication declaration only; externalIPs and reachability are separate")


named("service", "service_type_forbidden", "Service avoids NodePort/LoadBalancer publication", service_type,
    {"spec": {"type": "ClusterIP"}}, {"spec": {"type": "LoadBalancer"}})


def quota_rule(query, dependency, field, resource, alternate=None):
    def evaluate(item, index):
        namespace = get(item, "metadata.name", str)
        objects = [row for row in complete_items(index, dependency) if get(row, "metadata.namespace", str) == namespace]
        observations = []
        if dependency == "resourcequota":
            for row in objects:
                hard = get(row, "spec.hard", dict)
                if resource in hard or alternate and alternate in hard:
                    observations.append({"name": get(row, "metadata.name", str), "quantity": hard.get(resource, hard.get(alternate)),
                        "scopes": row.get("spec", {}).get("scopes", []), "scopeSelector": row.get("spec", {}).get("scopeSelector")})
        else:
            for row in objects:
                for limit in list_of_objects(get(row, "spec.limits", list)):
                    configured = optional(limit, field, {}, dict)
                    if resource in configured:
                        observations.append({"name": get(row, "metadata.name", str), "quantity": configured[resource], "type": limit.get("type")})
        return result(not observations, namespace=namespace, declarations=observations,
            semantics="Existence of a declared quota/limit; applicability selectors and enforcement are separate")
    entry = {"metadata": {"name": "q", "namespace": "apps"}, "spec": {"hard": {resource: "1"}}} if dependency == "resourcequota" else {
        "metadata": {"name": "l", "namespace": "apps"}, "spec": {"limits": [{"type": "Container", field: {resource: "1"}}]}}
    cid = named("namespace", query, "Namespace declares " + query.replace("_", " "), evaluate,
        {"metadata": {"name": "apps"}}, {"metadata": {"name": "other"}}, dependencies=["namespace", dependency])
    CASES[cid]["index"] = {"collections": {dependency: [{"scope": "*", "status": "collected"}]}, dependency: [{"data": entry}]}


for _resource in ("cpu", "memory"):
    quota_rule(f"namespace_resource_quota_{_resource}_limit", "resourcequota", "hard", "limits." + _resource)
    quota_rule(f"namespace_resource_quota_{_resource}_request", "resourcequota", "hard", "requests." + _resource, alternate=_resource)
    quota_rule(f"namespace_limit_range_default_{_resource}_limit", "limitrange", "default", _resource)
    quota_rule(f"namespace_limit_range_default_{_resource}_request", "limitrange", "defaultRequest", _resource)


def network_namespace(query, direction, requires_deny):
    if not requires_deny:
        def per_policy(item, index):
            spec = get(item, "spec", dict)
            rules = list_of_objects(optional(spec, direction.lower(), [], list))
            return result(any(rule == {} for rule in rules), direction=direction,
                semantics="This policy declares an unrestricted peer/port rule for its selected pods; policy union and CNI enforcement are separate")
        named("networkpolicy", query, "NetworkPolicy avoids an unrestricted " + direction + " rule", per_policy,
            {"spec": {direction.lower(): []}}, {"spec": {direction.lower(): [{}]}})
        return
    def evaluate(item, index):
        namespace = get(item, "metadata.name", str)
        policies = [row for row in complete_items(index, "networkpolicy") if get(row, "metadata.namespace", str) == namespace]
        selected = []
        for row in policies:
            spec = get(row, "spec", dict)
            selector = get(spec, "podSelector", dict)
            types = get(spec, "policyTypes", list)
            if direction not in types or selector != {}:
                continue
            rules = optional(spec, direction.lower(), [], list)
            if requires_deny and not rules:
                selected.append(get(row, "metadata.name", str))
            elif not requires_deny and any(rule == {} for rule in rules):
                selected.append(get(row, "metadata.name", str))
        return result(not selected if requires_deny else bool(selected), namespace=namespace, matched_policies=selected,
            semantics="Namespace-wide policy declarations; additive policy union and observed CNI enforcement are not inferred")
    rule = [] if requires_deny else [{}]
    policy = {"metadata": {"name": "p", "namespace": "apps"}, "spec": {"podSelector": {}, "policyTypes": [direction], direction.lower(): rule}}
    good_ns, bad_ns = ("apps", "other") if requires_deny else ("other", "apps")
    cid = named("namespace", query, "Review " + query.replace("_", " "), evaluate,
        {"metadata": {"name": good_ns}}, {"metadata": {"name": bad_ns}}, dependencies=["namespace", "networkpolicy"])
    CASES[cid]["index"] = {"collections": {"networkpolicy": [{"scope": "*", "status": "collected"}]}, "networkpolicy": [{"data": policy}]}


for _direction in ("Ingress", "Egress"):
    network_namespace("network_policy_default_deny_" + _direction.lower(), _direction, True)
    network_namespace("network_policy_default_dont_allow_" + _direction.lower(), _direction, False)


def admission_legacy(query, field, good, bad):
    def evaluate(item, index):
        version = get(item, "_provenance.kubernetes_version", str)
        values = version.lstrip("v").split(".")
        if len(values) < 2 or not values[0].isdigit() or not values[1].isdigit():
            return unknown("Kubernetes version unavailable for removed PSP API")
        if tuple(map(int, values[:2])) >= (1, 25):
            return "NOT_APPLICABLE", {"reason": "PodSecurityPolicy removed in Kubernetes1.25; review Pod Security Admission/SCC configuration instead"}
        configured = get(item, field, type(good))
        return result(configured != good, field=field, configured=configured,
            semantics="Legacy PSP configuration, not binding or admission enforcement proof")
    entry = lambda value: {"_provenance": {"kubernetes_version": "v1.24.0"}, "spec": {field.split(".")[-1]: value}}
    named("podsecuritypolicy", query, "Legacy PSP " + query.replace("_", " "), evaluate, entry(good), entry(bad))


for _query, _field, _good in (
    ("pod_security_policy_container_privilege_disabled", "privileged", False),
    ("pod_security_policy_hostpid_sharing_disabled", "hostPID", False),
    ("pod_security_policy_hostipc_sharing_disabled", "hostIPC", False),
    ("pod_security_policy_host_network_access_disabled", "hostNetwork", False),
    ("pod_security_policy_container_privilege_escalation_disabled", "allowPrivilegeEscalation", False),
    ("pod_security_policy_immutable_container_filesystem", "readOnlyRootFilesystem", True),
):
    admission_legacy(_query, "spec." + _field, _good, not _good)
