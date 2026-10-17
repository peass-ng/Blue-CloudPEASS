"""Bound least-privilege posture signals, never an authorization/action graph.

Manual CIS minimization requirements remain manual. These signals identify
specific declared assignments needing owner review; they do not certify least
privilege or calculate effective access through other authorizers.
"""
from . import register, result, unknown
from .facts import get, optional, complete_items, list_of_objects, Unavailable
from .fixtures import CASES

IDS = []
SPECS = {
    "secret_read": [("", "secrets", ("get", "list", "watch"))],
    "pod_create": [("", "pods", ("create",))],
    "pod_exec": [("", "pods/exec", ("get", "create"))],
    "impersonation": [("", resource, ("impersonate",)) for resource in ("users", "groups", "serviceaccounts")] + [("authentication.k8s.io", "uids", ("impersonate",))],
    "node_proxy": [("", "nodes/proxy", ("get", "list", "watch", "create", "update", "patch", "delete"))],
    "serviceaccount_token_create": [("", "serviceaccounts/token", ("create",))],
}
RELATED_REQUIREMENTS = {
    "secret_read": {"source_ids": ["prowler.kubernetes.rbac_minimize_secret_access"], "verified_controls": ["5.1.2"]},
    "pod_create": {"source_ids": ["prowler.kubernetes.rbac_minimize_pod_creation_access"], "verified_controls": ["5.1.4"]},
    "node_proxy": {"source_ids": ["prowler.kubernetes.rbac_minimize_node_proxy_subresource_access"], "verified_controls": ["5.1.10"]},
    "serviceaccount_token_create": {"source_ids": ["prowler.kubernetes.rbac_minimize_service_account_token_creation"], "verified_controls": ["5.1.13"]},
    "impersonation": {"source_ids": [], "verified_controls": ["5.1.8"],
        "framework_requirements": [{"source_path": "prowler/compliance/kubernetes/" + filename, "source_revision": "61d2cc55c4539a6b48a3cf9f3729d8f2af300882", "version": version, "control_id": "5.1.8", "upstream_checks": []}
            for filename, version in (("cis_1.8_kubernetes.json", "1.8"), ("cis_1.10_kubernetes.json", "1.10"), ("cis_1.11_kubernetes.json", "1.11.1"), ("cis_1.12_kubernetes.json", "1.12.0"), ("cis_2.0.1_kubernetes.json", "2.0.1"))],
        "relationship": "Verified pinned clause has no scanner check IDs and covers Bind/Escalate as well as impersonation; related signal does not automate the full manual requirement"},
    "pod_exec": {"source_ids": [], "verified_controls": [], "mapping_gap": "Related access minimization only; no exact pinned CIS clause asserted"},
}
SYSTEM_ADDONS = frozenset(("coredns", "kube-dns", "metrics-server", "kube-proxy", "kindnet", "calico-node", "flannel"))
UNIVERSAL_GROUPS = frozenset(("system:authenticated", "system:unauthenticated", "system:serviceaccounts"))


def strings(item, field, default=None):
    values = get(item, field, list) if default is None else optional(item, field, default, list)
    if any(not isinstance(value, str) for value in values):
        raise Unavailable("malformed RBAC string list")
    return values


def same_cluster(item, cluster):
    return get(item, "provenance.cluster_id", str) == cluster


def role_subject(item, index, kind):
    metadata, reference = get(item, "metadata", dict), get(item, "roleRef", dict)
    cluster = get(item, "provenance.cluster_id", str)
    if not cluster:
        raise Unavailable("binding cluster identity is empty")
    context_cluster = index.get("context", {}).get("metadata", {}).get("cluster_id")
    if context_cluster is not None and context_cluster != cluster:
        raise Unavailable("binding cluster does not match snapshot context")
    reference_kind, name = get(reference, "kind", str), get(reference, "name", str)
    if optional(reference, "apiGroup", "rbac.authorization.k8s.io", str) != "rbac.authorization.k8s.io":
        raise Unavailable("unrecognized role reference API group")
    namespace = get(metadata, "namespace", str) if kind == "rolebinding" else None
    if reference_kind == "Role" and namespace is None:
        raise Unavailable("ClusterRoleBinding cannot reference a namespaced Role")
    if reference_kind not in ("Role", "ClusterRole"):
        raise Unavailable("unrecognized role reference kind")
    resource_kind = "role" if reference_kind == "Role" else "clusterrole"
    roles = complete_items(index, resource_kind)
    matches = [role for role in roles if get(role, "metadata.name", str) == name and same_cluster(role, cluster)
        and (resource_kind == "clusterrole" or get(role, "metadata.namespace", str) == namespace)]
    if len(matches) != 1:
        raise Unavailable("exact cluster/namespace/role reference missing or ambiguous")
    return matches[0], namespace, cluster


def selected(labels, selector):
    labels = get({"labels": labels}, "labels", dict)
    match_labels = optional(selector, "matchLabels", {}, dict)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in match_labels.items()):
        raise Unavailable("malformed aggregation matchLabels")
    if any(labels.get(key) != value for key, value in match_labels.items()):
        return False
    for expression in list_of_objects(optional(selector, "matchExpressions", [], list)):
        key, operator = get(expression, "key", str), get(expression, "operator", str)
        values = strings(expression, "values", [])
        if operator in ("In", "NotIn") and not values or operator in ("Exists", "DoesNotExist") and values:
            raise Unavailable("invalid aggregation selector values")
        if operator == "In" and labels.get(key) not in values:
            return False
        if operator == "NotIn" and labels.get(key) in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
        if operator not in ("In", "NotIn", "Exists", "DoesNotExist"):
            raise Unavailable("unknown aggregation selector operator")
    return True


def declared_rules(role, index, cluster, stack=()):
    name = get(role, "metadata.name", str)
    if name in stack:
        raise Unavailable("cyclic aggregated role declarations")
    rules = [(name, rule) for rule in list_of_objects(optional(role, "rules", [], list))]
    aggregation = optional(role, "aggregationRule", None, dict)
    if aggregation is None:
        return rules
    selectors = list_of_objects(get(aggregation, "clusterRoleSelectors", list))
    candidates = complete_items(index, "clusterrole")
    for candidate in candidates:
        if not same_cluster(candidate, cluster):
            continue
        candidate_name = get(candidate, "metadata.name", str)
        if candidate_name == name:
            continue
        labels = optional(get(candidate, "metadata", dict), "labels", {}, dict)
        if any(selected(labels, selector) for selector in selectors):
            rules.extend(declared_rules(candidate, index, cluster, (*stack, name)))
    return rules


def risky_rules(role, index, cluster, mode, namespace=None):
    findings = []
    for origin, rule in declared_rules(role, index, cluster):
        groups, resources, verbs = [strings(rule, key, []) for key in ("apiGroups", "resources", "verbs")]
        names = strings(rule, "resourceNames", [])
        for group, resource, wanted_verbs in SPECS[mode]:
            if namespace is not None and resource in ("users", "groups", "uids", "nodes/proxy"):
                continue  # Namespaced bindings do not grant cluster-scoped requests.
            subresource = resource.split("/", 1)[1] if "/" in resource else None
            resource_match = "*" in resources or resource in resources or subresource is not None and "*/" + subresource in resources
            matched_verbs = sorted(set(wanted_verbs) if "*" in verbs else set(wanted_verbs).intersection(verbs))
            if group not in groups and "*" not in groups or not resource_match or not matched_verbs:
                continue
            # The API cannot restrict top-level create by resource name; a
            # nonempty resourceNames constraint does not authorize that create.
            if mode == "pod_create" and names:
                continue
            findings.append({"declaring_role": origin, "api_group": group, "resource": resource,
                "verbs": matched_verbs, "resource_names": names})
        if mode == "impersonation" and namespace is None and ("authentication.k8s.io" in groups or "*" in groups) and ("impersonate" in verbs or "*" in verbs):
            for resource in resources:
                if resource.startswith("userextras/"):
                    findings.append({"declaring_role": origin, "api_group": "authentication.k8s.io", "resource": resource,
                        "verbs": ["impersonate"], "resource_names": names})
    return findings


def subject_class(subject, namespace, cluster, index):
    kind, name = get(subject, "kind", str), get(subject, "name", str)
    if kind == "User" and name.startswith("system:serviceaccount:"):
        parts = name.split(":")
        if len(parts) != 4:
            raise Unavailable("malformed service-account username")
        kind, namespace, name = "ServiceAccount", parts[2], parts[3]
    if kind == "User":
        from .k8s_managed import control_plane_subject
        return "system" if control_plane_subject({"kind": kind, "name": name}) else "non_system"
    if kind == "Group":
        if name in UNIVERSAL_GROUPS or name.startswith("system:serviceaccounts:"):
            return "non_system"
        return "system" if name.startswith("system:") else "non_system"
    if kind != "ServiceAccount":
        raise Unavailable("unrecognized RBAC subject kind")
    subject_namespace = optional(subject, "namespace", namespace, str)
    if not isinstance(subject_namespace, str) or not subject_namespace:
        raise Unavailable("ServiceAccount subject namespace unavailable")
    if subject_namespace != "kube-system":
        return "non_system"
    accounts = complete_items(index, "serviceaccount")
    matches = [account for account in accounts if get(account, "metadata.name", str) == name
        and get(account, "metadata.namespace", str) == subject_namespace and same_cluster(account, cluster)]
    if len(matches) != 1:
        return "unknown"
    labels = optional(get(matches[0], "metadata", dict), "labels", {}, dict)
    trusted = labels.get("kubernetes.io/cluster-service") == "true" or labels.get("addonmanager.kubernetes.io/mode") in ("Reconcile", "EnsureExists")
    trusted = trusted or name in SYSTEM_ADDONS and labels.get("k8s-app") == name
    return "system" if trusted else "non_system"


def install(kind, mode):
    cid = f"k8s.ports.{kind}.bound_{mode}_review"
    IDS.append(cid)
    @register(cid, "k8s", "least_privilege", kind, "Binding limits declared " + mode.replace("_", " ") + " grants to approved system subjects", "high", "AC-6",
        "Review the demonstrated binding, declared role rules and operational justification; remove unintended grants or restrict them to approved scopes/subjects. No authorization action is performed.",
        dependencies=[kind, "role", "clusterrole", "serviceaccount"])
    def evaluate(item, index):
        role, namespace, cluster = role_subject(item, index, kind)
        subjects = list_of_objects(optional(item, "subjects", [], list))
        if not subjects:
            return "NOT_APPLICABLE", {"reason": "Known binding has no subjects"}
        risks = risky_rules(role, index, cluster, mode, namespace)
        for subject in subjects:
            subject_kind = get(subject, "kind", str)
            if subject_kind not in ("User", "Group", "ServiceAccount") or not get(subject, "name", str):
                raise Unavailable("malformed RBAC subject identity")
            expected_group = "" if subject_kind == "ServiceAccount" else "rbac.authorization.k8s.io"
            if optional(subject, "apiGroup", expected_group, str) != expected_group:
                raise Unavailable("unrecognized RBAC subject API group")
        if not risks:
            return result(False, reason="Referenced role declarations do not contain this risk category")
        classifications = [(subject, subject_class(subject, namespace, cluster, index)) for subject in subjects]
        non_system = [subject for subject, status in classifications if status == "non_system"]
        if non_system:
            return result(True, binding=get(item, "metadata.name", str), namespace=namespace, role_ref=get(item, "roleRef", dict),
                non_system_subjects=non_system, declared_rules_needing_review=risks,
                semantics="Full declared binding/role reference, resourceNames and aggregation metadata; no effective authorizer decision or privilege chain")
        if any(status == "unknown" for _, status in classifications):
            return unknown("Trusted system controller applicability lacks complete identity metadata")
        return "NOT_APPLICABLE", {"reason": "Only configured system principals or metadata-proven kube-system addon ServiceAccounts; universal authenticated/unauthenticated/all-SA groups are never exempt"}
    fixture_spec = SPECS[mode][2] if kind == "rolebinding" and mode == "impersonation" else SPECS[mode][0]
    rule = {"apiGroups": [fixture_spec[0]], "resources": [fixture_spec[1]], "verbs": [fixture_spec[2][0]]}
    role_kind = "Role" if kind == "rolebinding" else "ClusterRole"
    binding = {"metadata": {"name": "b", **({"namespace": "apps"} if kind == "rolebinding" else {})},
        "provenance": {"cluster_id": "c"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind, "name": "r"}, "subjects": [{"kind": "User", "name": "reader@example.com"}]}
    resource_kind = "role" if kind == "rolebinding" else "clusterrole"
    role = {"metadata": {"name": "r", **({"namespace": "apps"} if kind == "rolebinding" else {})}, "provenance": {"cluster_id": "c"}, "rules": [rule]}
    good_index = {"collections": {resource_kind: [{"scope": "*", "status": "collected"}]}, resource_kind: [{"data": {**role, "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]}}]}
    bad_index = {"collections": {resource_kind: [{"scope": "*", "status": "collected"}]}, resource_kind: [{"data": role}]}
    CASES[cid] = {"pass": binding, "fail": binding, "missing": {}, "malformed": None, "pass_index": good_index, "fail_index": bad_index}


for _kind in ("rolebinding", "clusterrolebinding"):
    for _mode in SPECS:
        if _kind == "rolebinding" and _mode == "node_proxy":
            continue
        install(_kind, _mode)
