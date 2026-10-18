"""Kubernetes defaults are interpreted only after a complete native Pod spec."""
from . import register, result, unknown
from .facts import get, list_of_objects, optional
from .fixtures import CASES


def containers(item):
    spec = get(item, "spec", dict)
    if spec.get("os", {}).get("name") == "windows":
        return spec, None
    rows = list(list_of_objects(get(spec, "containers", list)))
    if not rows:
        raise ValueError("pod requires containers")
    for key in ("initContainers", "ephemeralContainers"):
        rows += list_of_objects(spec.get(key, []))
    for row in rows:
        if not isinstance(row.get("name"), str):
            raise ValueError("container name unavailable")
    return spec, rows


def container_check(cid, title, predicate, good_context, bad_context, severity="medium"):
    @register(cid, "k8s", "hardening", "pod", title, severity, "CM-6", "Configure workload securityContext and enforce reviewed Pod Security Admission controls.")
    def evaluate(item, index):
        spec, rows = containers(item)
        if rows is None:
            return "NOT_APPLICABLE", {"reason": "Linux container control; Windows pod requires its own policy"}
        pod = optional(spec, "securityContext", {}, dict)
        if not isinstance(pod, dict):
            return unknown("malformed pod securityContext")
        failed = []
        for row in rows:
            context = optional(row, "securityContext", {}, dict)
            if not isinstance(context, dict):
                return unknown("malformed container securityContext")
            if not predicate(context, pod):
                failed.append(row["name"])
        return result(bool(failed), containers_needing_review=failed, semantics="Native pod configuration; admission policy and runtime enforcement are separate")
    CASES[cid] = {"pass": {"spec": {"containers": [{"name": "app", "securityContext": good_context}]}}, "fail": {"spec": {"containers": [{"name": "app", "securityContext": bad_context}]}}}


def flag(context, key, default=None):
    value = optional(context, key, default, bool)
    if value is not None and type(value) is not bool:
        raise ValueError("malformed security flag")
    return value


container_check("k8s.pod.no_privilege_escalation", "Pod containers disable privilege escalation", lambda c, p: flag(c, "allowPrivilegeEscalation", True) is False, {"allowPrivilegeEscalation": False}, {}, "high")
container_check("k8s.pod.read_only_root", "Pod containers use read-only root filesystems", lambda c, p: flag(c, "readOnlyRootFilesystem", False) is True, {"readOnlyRootFilesystem": True}, {})


def nonroot(context, pod):
    value = flag(context, "runAsNonRoot", flag(pod, "runAsNonRoot"))
    uid = context.get("runAsUser", pod.get("runAsUser"))
    if uid is not None and (type(uid) is not int or uid < 0):
        raise ValueError("malformed runAsUser")
    return uid != 0 and (value is True or (uid is not None and uid > 0))
container_check("k8s.pod.non_root", "Pod containers require a non-root identity", nonroot, {"runAsNonRoot": True}, {"runAsUser": 0}, "high")


def drop_all(context, pod):
    caps = optional(context, "capabilities", {}, dict)
    if not isinstance(caps, dict) or not isinstance(caps.get("drop", []), list):
        raise ValueError("malformed capabilities")
    return "ALL" in caps.get("drop", [])
container_check("k8s.pod.drop_capabilities", "Pod containers drop all Linux capabilities", drop_all, {"capabilities": {"drop": ["ALL"]}}, {}, "high")


def safe_capabilities(context, pod):
    caps = optional(context, "capabilities", {}, dict)
    if not isinstance(caps, dict) or not isinstance(caps.get("add", []), list) or any(not isinstance(x, str) for x in caps.get("add", [])):
        raise ValueError("malformed capabilities")
    return not set(caps.get("add", [])) - {"NET_BIND_SERVICE"}
container_check("k8s.pod.restrict_added_capabilities", "Pod containers add only restricted-policy Linux capabilities", safe_capabilities, {"capabilities": {"add": ["NET_BIND_SERVICE"]}}, {"capabilities": {"add": ["SYS_ADMIN"]}}, "high")


def seccomp(context, pod):
    profile = context.get("seccompProfile", pod.get("seccompProfile", {}))
    if not isinstance(profile, dict):
        raise ValueError("malformed seccomp profile")
    kind = profile.get("type")
    if kind not in (None, "RuntimeDefault", "Localhost", "Unconfined"):
        raise ValueError("unrecognized seccomp profile")
    if kind == "Localhost" and not isinstance(profile.get("localhostProfile"), str):
        raise ValueError("localhost seccomp profile missing")
    return kind in ("RuntimeDefault", "Localhost")
container_check("k8s.pod.seccomp", "Pod containers specify a restrictive seccomp profile", seccomp, {"seccompProfile": {"type": "RuntimeDefault"}}, {"seccompProfile": {"type": "Unconfined"}}, "high")


@register("k8s.pod.no_hostpath", "k8s", "hardening", "pod", "Pod avoids hostPath volumes", "high", "CM-6", "Replace hostPath volumes with appropriate managed storage or document tightly constrained operational requirements.")
def hostpath(item, index):
    spec = get(item, "spec", dict)
    # An absent volumes field is the documented empty list default.
    rows = list_of_objects(spec.get("volumes", []))
    paths = [get(row, "hostPath", dict) for row in rows if "hostPath" in row]
    return result(bool(paths), host_path_volumes=paths)
CASES["k8s.pod.no_hostpath"] = {"pass": {"spec": {"containers": [{"name": "app"}]}}, "fail": {"spec": {"volumes": [{"name": "host", "hostPath": {"path": "/var"}}]}}}


@register("k8s.pod.no_default_serviceaccount", "k8s", "hardening", "pod", "Pod uses an explicitly reviewed service account", "medium", "AC-6", "Use a dedicated service account with the permissions required by this workload.")
def default_sa(item, index):
    spec = get(item, "spec", dict)
    name = spec.get("serviceAccountName", "default")
    if not isinstance(name, str):
        return unknown("malformed service account name")
    return result(name in ("default", ""), service_account=name or "default", semantics="Dedicated identity control; RBAC permissions require separate review")
CASES["k8s.pod.no_default_serviceaccount"] = {"pass": {"spec": {"serviceAccountName": "app"}}, "fail": {"spec": {"serviceAccountName": "default"}}}


@register("k8s.pod.restrict_token_automount", "k8s", "hardening", "pod", "Pod explicitly disables automatic service account token mounting", "medium", "AC-6", "Disable automountServiceAccountToken for workloads that do not need Kubernetes API credentials.")
def automount(item, index):
    spec = get(item, "spec", dict)
    if "automountServiceAccountToken" not in spec:
        return unknown("pod token automount inherits the ServiceAccount setting")
    value = get(spec, "automountServiceAccountToken", bool)
    return result(value, automount_service_account_token=value)
CASES["k8s.pod.restrict_token_automount"] = {"pass": {"spec": {"automountServiceAccountToken": False}}, "fail": {"spec": {"automountServiceAccountToken": True}}}


@register("k8s.namespace.restricted_admission", "k8s", "hardening", "namespace", "Namespace explicitly enforces restricted Pod Security Admission", "high", "CM-6", "Set reviewed pod-security.kubernetes.io/enforce and enforce-version labels and verify cluster admission configuration.")
def admission(item, index):
    labels = get(item, "metadata.labels", dict)
    level = labels.get("pod-security.kubernetes.io/enforce")
    if level is None:
        return unknown("namespace enforcement label absent; cluster admission defaults unavailable")
    if level not in ("privileged", "baseline", "restricted"):
        return unknown("unrecognized admission level")
    return result(level != "restricted", enforce_level=level, enforce_version=labels.get("pod-security.kubernetes.io/enforce-version", "latest"), semantics="Namespace admission configuration; exemptions and existing workloads remain separate")
CASES["k8s.namespace.restricted_admission"] = {"pass": {"metadata": {"labels": {"pod-security.kubernetes.io/enforce": "restricted"}}}, "fail": {"metadata": {"labels": {"pod-security.kubernetes.io/enforce": "privileged"}}}}
