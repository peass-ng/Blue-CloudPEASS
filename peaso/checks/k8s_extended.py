"""Reviewed native Pod-template and namespace controls, without cloud transports.

Pinned upstream predicates are adapted to native defaults, Pod-level inheritance,
init/ephemeral containers, strict field types and explicit incomplete coverage.
No removed PodSecurityPolicy API or unobservable node/control-plane flags are
claimed audited. Current official Pod Security Standards supply default semantics.
"""
from __future__ import annotations
import copy
import re
from . import register, result, unknown
from .facts import get, list_of_objects, optional
from .fixtures import CASES, nest

PSS = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
SA_DOC = "https://kubernetes.io/docs/concepts/security/service-accounts/"
QUOTA_DOC = "https://kubernetes.io/docs/concepts/policy/resource-quotas/"
CONTROLLERS = ("deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob")
EXTENDED_IDS = []
DEPENDENCIES = {}


def _pod(item):
    spec = get(item, "spec", dict)
    containers = list_of_objects(get(spec, "containers", list))
    if not containers:
        raise ValueError("complete Pod specification requires containers")
    rows = list(containers)
    for key in ("initContainers", "ephemeralContainers"):
        rows += list_of_objects(spec.get(key, []))
    pod_context = optional(spec, "securityContext", {}, dict)
    if not isinstance(pod_context, dict):
        raise ValueError("malformed Pod securityContext")
    for row in rows:
        get(row, "name", str)
        if not isinstance(row.get("securityContext", {}), dict):
            raise ValueError("malformed container securityContext")
    return spec, rows, pod_context


def _flag(value, name, default=False):
    value = optional(value, name, default, bool)
    if type(value) is not bool:
        raise ValueError("malformed boolean " + name)
    return value


def _template(item, kind):
    path = "spec.jobTemplate.spec.template" if kind == "cronjob" else "spec.template"
    template = get(item, path, dict)
    # Copy only the native pod template consumed by the predicate.
    return copy.deepcopy(template), path


def _evaluate_pod(item, predicate):
    spec, containers, pod = _pod(item)
    violations = []
    if predicate == "no_host_network":
        return result(_flag(spec, "hostNetwork"), host_network=spec.get("hostNetwork", False), official_reference=PSS, semantics="Declared Pod network namespace; networking admission and reachability were not assessed.")
    if predicate == "non_root" and spec.get("os", {}).get("name") == "windows":
        return "NOT_APPLICABLE", {"reason": "Linux runAsNonRoot predicate; Windows identity policy is separate."}
    for row in containers:
        context = optional(row, "securityContext", {}, dict)
        if predicate == "no_privileged":
            failed = _flag(context, "privileged")
        elif predicate == "non_root":
            configured = _flag(context, "runAsNonRoot", _flag(pod, "runAsNonRoot", False))
            uid = context.get("runAsUser", pod.get("runAsUser"))
            if uid is not None and (type(uid) is not int or uid < 0):
                raise ValueError("malformed runAsUser")
            failed = not configured or uid == 0
        elif predicate == "no_host_ports":
            ports = list_of_objects(row.get("ports", []))
            configured = [p.get("hostPort", 0) for p in ports]
            if any(type(p) is not int or p < 0 or p > 65535 for p in configured):
                raise ValueError("malformed hostPort")
            failed = any(port != 0 for port in configured)
        else:
            raise ValueError("unknown Pod predicate")
        if failed:
            violations.append(row["name"])
    return result(bool(violations), containers_needing_review=violations, semantics="Observed Pod/template configuration, including init and ephemeral containers; future admission and runtime enforcement are separate.", official_reference=PSS)


GOOD = {
    "no_privileged": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]},
    "non_root": {"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "app"}]},
    "no_host_network": {"hostNetwork": False, "containers": [{"name": "app"}]},
    "no_host_ports": {"containers": [{"name": "app", "ports": [{"containerPort": 443, "hostPort": 0}]}]},
}
BAD = {
    "no_privileged": {"containers": [{"name": "app"}], "initContainers": [{"name": "init", "securityContext": {"privileged": True}}]},
    "non_root": {"containers": [{"name": "app", "securityContext": {"runAsNonRoot": False}}]},
    "no_host_network": {"hostNetwork": True, "containers": [{"name": "app"}]},
    "no_host_ports": {"containers": [{"name": "app", "ports": [{"containerPort": 443, "hostPort": 443}]}]},
}


def _controller_check(kind, predicate):
    cid = f"k8s.{kind}.{predicate}"
    EXTENDED_IDS.append(cid)
    title = {"no_privileged": "Pod template avoids privileged containers", "non_root": "Pod template requires non-root Linux containers",
             "no_host_network": "Pod template avoids the host network namespace", "no_host_ports": "Pod template avoids host port publication"}[predicate]
    @register(cid, "k8s", "hardening", kind, kind.title() + " " + title, "high", "CM-6", "Review the workload owner's operational requirements; configure the Pod template according to the chosen Pod Security profile and verify admission enforcement.")
    def evaluate(item, index):
        template, path = _template(item, kind)
        status, evidence = _evaluate_pod(template, predicate)
        return status, {**evidence, "template_path": path, "kind": kind}
    path = "spec.jobTemplate.spec.template.spec" if kind == "cronjob" else "spec.template.spec"
    CASES[cid] = {"pass": nest(path, copy.deepcopy(GOOD[predicate])), "fail": nest(path, copy.deepcopy(BAD[predicate])),
                  "missing": {}, "malformed": nest(path, {"containers": "malformed"})}


for _kind in CONTROLLERS:
    for _predicate in GOOD:
        _controller_check(_kind, _predicate)


@register("k8s.pod.no_host_ports", "k8s", "hardening", "pod", "Pod avoids host port publication", "high", "SC-7", "Remove hostPort publication unless explicitly approved; use reviewed Services and ingress controls.")
def no_host_ports(item, index):
    return _evaluate_pod(item, "no_host_ports")
EXTENDED_IDS.append("k8s.pod.no_host_ports")
CASES["k8s.pod.no_host_ports"] = {"pass": {"spec": GOOD["no_host_ports"]}, "fail": {"spec": BAD["no_host_ports"]}}


@register("k8s.pod.default_proc_mount", "k8s", "hardening", "pod", "Pod containers preserve default proc filesystem masks", "high", "CM-6", "Use the default procMount setting and enforce the reviewed baseline Pod Security profile.")
def proc_mount(item, index):
    spec, containers, _ = _pod(item)
    if spec.get("os", {}).get("name") == "windows":
        return "NOT_APPLICABLE", {"reason": "Linux proc filesystem control."}
    failures = []
    for container in containers:
        value = container.get("securityContext", {}).get("procMount", "Default")
        if value not in ("Default", "Unmasked"):
            return unknown("unknown procMount enum")
        if value == "Unmasked":
            failures.append(container["name"])
    return result(bool(failures), unmasked_containers=failures, official_reference=PSS)
EXTENDED_IDS.append("k8s.pod.default_proc_mount")
CASES["k8s.pod.default_proc_mount"] = {"pass": {"spec": {"containers": [{"name": "app"}]}}, "fail": {"spec": {"containers": [{"name": "app", "securityContext": {"procMount": "Unmasked"}}]}}}


@register("k8s.pod.restrict_selinux_identity", "k8s", "hardening", "pod", "Pod avoids custom SELinux user and role identities", "high", "CM-6", "Keep SELinux user/role overrides unset and verify the cluster's approved SELinux type/profile policy.")
def selinux_identity(item, index):
    spec, rows, pod = _pod(item)
    if spec.get("os", {}).get("name") == "windows":
        return "NOT_APPLICABLE", {"reason": "Linux SELinux policy control."}
    contexts = [("pod", pod)] + [(r["name"], r.get("securityContext", {})) for r in rows]
    failures = []
    for name, context in contexts:
        options = context.get("seLinuxOptions", {})
        if not isinstance(options, dict) or any(not isinstance(options.get(k, ""), str) for k in ("user", "role")):
            return unknown("malformed SELinux identity")
        if options.get("user") or options.get("role"):
            failures.append(name)
    return result(bool(failures), custom_selinux_identity=failures, official_reference=PSS, semantics="Identity override only; SELinux availability, labels and policy types are separate.")
EXTENDED_IDS.append("k8s.pod.restrict_selinux_identity")
CASES["k8s.pod.restrict_selinux_identity"] = {"pass": {"spec": {"containers": [{"name": "app"}]}}, "fail": {"spec": {"securityContext": {"seLinuxOptions": {"user": "custom_u"}}, "containers": [{"name": "app"}]}}}


@register("k8s.serviceaccount.disable_automount", "k8s", "hardening", "serviceaccount", "ServiceAccount disables default API token automount", "medium", "AC-6", "Set automountServiceAccountToken=false for identities whose workloads do not need Kubernetes API credentials; review Pod-level overrides.")
def serviceaccount_automount(item, index):
    get(item, "metadata.name", str)
    value = _flag(item, "automountServiceAccountToken", True)
    return result(value, automount_service_account_token=value, default_when_omitted=True, official_reference=SA_DOC,
                  semantics="ServiceAccount default only; each Pod may override this value.")
EXTENDED_IDS.append("k8s.serviceaccount.disable_automount")
CASES["k8s.serviceaccount.disable_automount"] = {"pass": {"metadata": {"name": "app"}, "automountServiceAccountToken": False}, "fail": {"metadata": {"name": "app"}, "automountServiceAccountToken": True}}


_QUANTITY = re.compile(r"^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+|[numkKMGTPE]|[KMGTPE]i)?$")


def _quota_check(key):
    cid = "k8s.namespace.quota_" + key.replace(".", "_")
    EXTENDED_IDS.append(cid)
    DEPENDENCIES[cid] = ["namespace", "resourcequota"]
    @register(cid, "k8s", "hardening", "namespace", "Namespace declares a broad " + key + " resource quota", "low", "SC-5", "Define ResourceQuota appropriate to the namespace workloads; scope-specific quotas and cluster admission enforcement require review.")
    def evaluate(item, index):
        name = get(item, "metadata.name", str)
        collections = [c for c in index.get("collections", {}).get("resourcequota", [])
            if c.get("scope") in ("*", name) or str(c.get("scope", "")).endswith("/" + name) or str(c.get("scope", "")).endswith("/*")]
        if not collections or any(c.get("status") not in ("collected", "empty") for c in collections):
            return unknown("resource quota inventory unavailable or incomplete")
        quotas = [r["data"] for r in index.get("resourcequota", []) if r["data"].get("metadata", {}).get("namespace") == name]
        broad, limited = [], []
        for quota in quotas:
            spec = get(quota, "spec", dict)
            hard = get(spec, "hard", dict)
            if key not in hard:
                continue
            value = hard[key]
            if not isinstance(value, str) or not _QUANTITY.fullmatch(value):
                return unknown("malformed resource quota quantity", field=key)
            evidence = {"name": get(quota, "metadata.name", str), "quantity": value, "scopes": spec.get("scopes", []), "scope_selector": spec.get("scopeSelector")}
            if spec.get("scopes") or spec.get("scopeSelector"):
                limited.append(evidence)
            else:
                broad.append(evidence)
        if not broad and limited:
            return "MANUAL", {"field": key, "scoped_quotas": limited, "reason": "Scoped quota does not establish namespace-wide workload coverage."}
        return result(not broad, field=key, namespace=name, broad_quotas=broad, official_reference=QUOTA_DOC,
                      semantics="Declared quota configuration only; availability, capacity sizing and admission enforcement are not inferred.")
    row = {"metadata": {"name": "quota", "namespace": "apps"}, "spec": {"hard": {key: "1Gi" if "memory" in key else "2"}}}
    CASES[cid] = {"pass": {"metadata": {"name": "apps"}}, "fail": {"metadata": {"name": "empty"}},
        "index": {"collections": {"resourcequota": [{"scope": "cluster/*", "status": "collected"}]}, "resourcequota": [{"data": row}]}}


for _quota_key in ("limits.cpu", "requests.cpu", "limits.memory", "requests.memory"):
    _quota_check(_quota_key)
