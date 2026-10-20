"""claude_gcp_k8s: Kubernetes workload, control-plane, kubelet, RBAC and legacy PSP predicates.

Declarations only: no node command, host-file read, Secret read or admission/runtime enforcement claim.
Missing, redacted or malformed facts are UNKNOWN; absence-based results require complete scoped inventories.
"""
from __future__ import annotations
import copy
import re

from .claude_gcp_k8s_common import (k8s, kid, cases, strings, opt_strings, pod_spec, security_context, pod_case, container,
    KIND_PATHS, result, unknown, get, optional, list_of_objects, complete_items, Unavailable, CASES, nest)
from . import k8s_ports_components as components

K8S_IDS = []
WORKLOAD_PREFIXES = {"cronjob": "cronjob", "daemonset": "daemonset", "deployment": "deployment", "job": "job", "pod": "pod",
                     "pod_template": "podtemplate", "replicaset": "replicaset", "replication_controller": "replicationcontroller",
                     "statefulset": "statefulset"}


def track(cid):
    K8S_IDS.append(cid)
    return cid


def k8s_index(kind_items, scope="*"):
    index = {"collections": {}, "context": {"provider": "k8s", "scope": scope}}
    for kind, items in kind_items.items():
        index["collections"][kind] = [{"scope": scope, "status": "collected" if items else "empty"}]
        index[kind] = [{"data": item} for item in items]
    return index


def bool_field(obj, key):
    return optional(obj, key, False, bool)


def pod_cases(cid, good_containers, bad_containers, kind="pod", good_spec=None, bad_spec=None, **extra):
    good = pod_case(*good_containers, kind=kind, **(good_spec or {}))
    bad = pod_case(*bad_containers, kind=kind, **(bad_spec or {}))
    malformed = pod_case({"name": "c", "securityContext": "x"}, kind=kind)
    return cases(cid, good, bad, malformed=extra.pop("malformed", malformed), **extra)


# --- Pod container predicates (prowler core service: regular Pod containers) -------------------------------------

def pod_rule(slug, title, check, good, bad, *, severity="medium", control="CM-6", remediation=None, good_spec=None, bad_spec=None,
             malformed=None):
    """check(spec, container) -> violation evidence or None for each regular container."""
    @k8s("pod." + slug, "pod", title, severity=severity, control=control, remediation=remediation)
    def evaluate(item, index):
        spec, rows = pod_spec(item, "pod")
        violations = []
        for row in rows:
            hit = check(spec, row)
            if hit:
                violations.append({"container": row["name"], **(hit if isinstance(hit, dict) else {})})
        return result(bool(violations), violations=violations,
                      semantics="Declared regular-container configuration; admission and runtime state are not inferred")
    cid = track(kid("pod." + slug))
    extra = {"malformed": malformed} if malformed is not None else {}
    pod_cases(cid, [container(**good)], [container(**bad)], good_spec=good_spec, bad_spec=bad_spec, **extra)
    return cid


def resource_present(group, name):
    def check(spec, row):
        resources = optional(row, "resources", {}, dict)
        values = optional(resources, group, {}, dict)
        if name not in values:
            return {"missing": group + "." + name}
        if type(values[name]) not in (str, int, float) or isinstance(values[name], bool):
            raise Unavailable("malformed resource quantity")
        return None
    return check


for _group, _name in (("limits", "cpu"), ("requests", "cpu"), ("limits", "memory"), ("requests", "memory")):
    pod_rule(f"{_name}_{_group}_set", f"Pod containers declare {_name} {_group}", resource_present(_group, _name),
             {"resources": {_group: {_name: "1"}}}, {"resources": {}}, control="SC-6",
             remediation=f"Declare resources.{_group}.{_name} for every regular container (or enforce a LimitRange default).",
             malformed=pod_case(container(resources={_group: {_name: True}})))


def probe(key):
    def check(spec, row):
        if key in row:
            get(row, key, dict)
            return None
        return {"missing": key}
    return check


pod_rule("liveness_probe_configured", "Pod containers declare a liveness probe", probe("livenessProbe"),
         {"livenessProbe": {"tcpSocket": {"port": 8080}}}, {}, severity="low", control="CP-10",
         remediation="Declare a livenessProbe for every long-running regular container.",
         malformed=pod_case(container(livenessProbe="tcp")))
pod_rule("readiness_probe_configured", "Pod containers declare a readiness probe", probe("readinessProbe"),
         {"readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}}}, {}, severity="low", control="CP-10",
         remediation="Declare a readinessProbe for every serving regular container.",
         malformed=pod_case(container(readinessProbe="http")))


def host_port(spec, row):
    ports = [get(p, "hostPort", int) for p in list_of_objects(optional(row, "ports", [], list)) if "hostPort" in p]
    if any(not 0 <= port <= 65535 for port in ports):
        raise Unavailable("malformed host port")
    published = [port for port in ports if port != 0]
    return {"host_ports": published} if published else None


pod_rule("no_host_ports", "Pod containers do not declare hostPort", host_port,
         {"ports": [{"containerPort": 8080}]}, {"ports": [{"containerPort": 8080, "hostPort": 8080}]}, control="SC-7",
         remediation="Remove hostPort declarations and publish the workload through a Service.",
         malformed=pod_case(container(ports=[{"hostPort": "80"}])))


def windows_host_process(spec, row):
    options = optional(security_context(row), "windowsOptions", {}, dict)
    pod_options = optional(optional(spec, "securityContext", {}, dict), "windowsOptions", {}, dict)
    value = optional(options, "hostProcess", None, bool)
    if value is None:
        value = optional(pod_options, "hostProcess", False, bool)
    return {"host_process": True} if value else None


pod_rule("no_windows_host_process", "Pod containers do not run as Windows HostProcess", windows_host_process,
         {"securityContext": {"windowsOptions": {"hostProcess": False}}}, {"securityContext": {"windowsOptions": {"hostProcess": True}}},
         severity="high", control="AC-6", remediation="Remove windowsOptions.hostProcess=true unless the node-management workload is approved.",
         malformed=pod_case(container(securityContext={"windowsOptions": {"hostProcess": "true"}})))


def capabilities(row):
    caps = optional(security_context(row), "capabilities", None, dict)
    if caps is None:
        return None, [], []
    return caps, opt_strings(caps, "add"), opt_strings(caps, "drop")


def added_caps(spec, row):
    _, added, _ = capabilities(row)
    return {"added": added} if added else None


def assigned_caps(spec, row):
    caps, added, dropped = capabilities(row)
    if caps is None:
        return None
    return {"added": added, "dropped": dropped} if added or not dropped else None


def net_raw(spec, row):
    _, added, _ = capabilities(row)
    return {"added": added} if set(added) & {"NET_RAW", "CAP_NET_RAW", "ALL"} else None


_caps_bad = pod_case(container(securityContext={"capabilities": {"add": "NET_RAW"}}))
pod_rule("no_added_capabilities", "Pod containers do not add Linux capabilities", added_caps,
         {"securityContext": {"capabilities": {"drop": ["ALL"]}}}, {"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}},
         control="AC-6", remediation="Remove capabilities.add entries unless explicitly approved.", malformed=_caps_bad)
pod_rule("capabilities_dropped", "Pod containers declaring capabilities add none and drop some", assigned_caps,
         {"securityContext": {"capabilities": {"drop": ["ALL"]}}}, {"securityContext": {"capabilities": {"add": [], "drop": []}}},
         control="AC-6", remediation="Declare capabilities.drop: [ALL] and add back only approved capabilities.", malformed=_caps_bad)
pod_rule("no_net_raw_capability", "Pod containers do not add NET_RAW", net_raw,
         {"securityContext": {"capabilities": {"add": ["NET_BIND_SERVICE"]}}}, {"securityContext": {"capabilities": {"add": ["NET_RAW"]}}},
         control="AC-6", remediation="Remove NET_RAW from capabilities.add.", malformed=_caps_bad)


def effective_user(spec, row):
    value = optional(security_context(row), "runAsUser", None, int)
    if value is None:
        value = optional(optional(spec, "securityContext", {}, dict), "runAsUser", None, int)
    return value


def root_user(spec, row):
    value = effective_user(spec, row)
    return {"run_as_user": 0} if value == 0 else None


pod_rule("no_root_user", "Pod containers do not declare runAsUser 0", root_user,
         {"securityContext": {"runAsUser": 1000}}, {"securityContext": {"runAsUser": 0}}, severity="high", control="AC-6",
         remediation="Run containers with a non-zero runAsUser and runAsNonRoot: true.",
         malformed=pod_case(container(securityContext={"runAsUser": "0"})))


def secret_env(spec, row):
    names = []
    for entry in list_of_objects(optional(row, "env", [], list)):
        source = optional(entry, "valueFrom", {}, dict)
        if "secretKeyRef" in source:
            names.append(get(entry, "name", str))
    return {"env": names} if names else None


pod_rule("no_secret_env", "Pod containers do not load Secrets into environment variables", secret_env,
         {"env": [{"name": "MODE", "value_redacted": True}]}, {"env": [{"name": "DB", "valueFrom": {"secretKeyRef": {"name": "db", "key": "p"}}}]},
         control="SC-28", remediation="Mount Secrets as files (or use a CSI secret store) instead of secretKeyRef environment variables.",
         malformed=pod_case(container(env="x")))


# Literal (non-valueFrom) env values whose NAME looks like a credential. The collector keeps only the name and
# the literal's length ({"name", "value_redacted": true, "value_length": n}); the value itself never enters the
# snapshot or this evidence.
_SECRET_TOKENS = ("PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "APIKEY", "PRIVATEKEY", "CREDENTIAL")
_SECRET_PAIRS = (("API", "KEY"), ("PRIVATE", "KEY"), ("ACCESS", "KEY"), ("AUTH", "KEY"), ("SIGNING", "KEY"))
# A trailing token naming a reference to a credential rather than the credential (POSTGRES_PASSWORD_FILE, TOKEN_URL).
_REFERENCE_SUFFIXES = frozenset(("FILE", "PATH", "DIR", "NAME", "REF", "TTL", "URL", "URI", "ENDPOINT", "TYPE", "LENGTH",
                                 "ID", "ENABLED", "EXPIRY", "EXPIRATION", "AUDIENCE", "ISSUER", "HEADER", "LOCATION", "MOUNT"))


def secret_like_env_name(name):
    tokens = [t.upper() for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", name)]
    if not tokens or tokens[-1] in _REFERENCE_SUFFIXES:
        return False
    if any(marker in token for token in tokens for marker in _SECRET_TOKENS):
        return True
    if any(token == "TOKEN" or token.endswith("TOKEN") for token in tokens):
        return True
    return any(pair in _SECRET_PAIRS for pair in zip(tokens, tokens[1:]))


def literal_length(entry):
    """Length of a literal env value, or None when the snapshot cannot tell (redacted without a length)."""
    if "valueFrom" in entry:
        return 0
    if "value_length" in entry:
        length = get(entry, "value_length", int)
        if length < 0:
            raise Unavailable("malformed env value length")
        return length
    if "value" in entry:
        return len(get(entry, "value", str))
    if entry.get("value_redacted") is True:
        return None
    return 0  # an absent value is the documented empty string


@k8s("pod.no_literal_secret_env", "pod", "Pod containers do not set credential-like environment variables to literal values",
     severity="high", control="IA-5",
     remediation="Move the credential into a Secret (mounted as a file, or a CSI secret store) instead of a literal env value, and rotate it.")
def literal_secret_env(item, index):
    _, rows = pod_spec(item, "pod", include_init=True)
    violations, undetermined = [], []
    for row in rows:
        for entry in list_of_objects(optional(row, "env", [], list)):
            name = get(entry, "name", str)
            if not secret_like_env_name(name):
                continue
            length = literal_length(entry)
            if length is None:
                undetermined.append({"container": row["name"], "env": name})
            elif length > 0:
                violations.append({"container": row["name"], "env": name})
    if violations:
        return result(True, literal_credential_env=violations, value_recorded=False,
                      semantics="Declared literal env value under a credential-like name; the value is never collected")
    if undetermined:
        return unknown("literal env value redacted without a length; re-collect with the current collector",
                       env_needing_review=undetermined)
    return result(False, value_recorded=False, literal_credential_env=[])


cases(track(kid("pod.no_literal_secret_env")),
      pod_case(container(env=[{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "p"}}},
                              {"name": "PASSWORD_FILE", "value_redacted": True, "value_length": 20},
                              {"name": "API_TOKEN", "value_redacted": True, "value_length": 0},
                              {"name": "MODE", "value_redacted": True, "value_length": 4}])),
      pod_case(container(env=[{"name": "DB_PASSWORD", "value_redacted": True, "value_length": 12}])),
      unknown=pod_case(container(env=[{"name": "API_KEY", "value_redacted": True}])),
      malformed=pod_case(container(env=[{"name": "API_KEY", "value_length": "12"}])))


def flag_rule(slug, field, title, *, severity="high"):
    @k8s("pod." + slug, "pod", title, severity=severity, control="SC-39",
         remediation="Set " + field + ": false (or remove it) unless the workload is an approved node agent.")
    def evaluate(item, index):
        spec, _ = pod_spec(item, "pod")
        value = bool_field(spec, field)
        return result(value, **{field: value})
    cid = track(kid("pod." + slug))
    cases(cid, pod_case(container(), **{field: False}), pod_case(container(), **{field: True}),
          malformed=pod_case(container(), **{field: "true"}))
    return cid


flag_rule("no_host_ipc", "hostIPC", "Pod does not share the host IPC namespace")
flag_rule("no_host_pid", "hostPID", "Pod does not share the host PID namespace")


@k8s("pod.runtime_default_seccomp", "pod", "Pod or all of its containers use the RuntimeDefault seccomp profile", control="CM-7",
     remediation="Set securityContext.seccompProfile.type: RuntimeDefault at Pod level (or on every container).")
def seccomp(item, index):
    spec, rows = pod_spec(item, "pod", include_init=True)
    profile = lambda obj: optional(optional(obj, "securityContext", {}, dict), "seccompProfile", {}, dict).get("type")
    pod_level = profile(spec)
    containers_level = [profile(row) for row in rows]
    if any(v not in (None, "RuntimeDefault", "Localhost", "Unconfined") for v in [pod_level] + containers_level):
        raise Unavailable("malformed seccomp profile type")
    # A container's explicit profile overrides the Pod default, including
    # init and ephemeral containers; Pod-level RuntimeDefault cannot mask it.
    ok = all((value if value is not None else pod_level) == "RuntimeDefault" for value in containers_level)
    return result(not ok, pod_profile=pod_level, container_profiles=containers_level)


cases(track(kid("pod.runtime_default_seccomp")), pod_case(container(), securityContext={"seccompProfile": {"type": "RuntimeDefault"}}),
      pod_case(container(securityContext={"seccompProfile": {"type": "Unconfined"}})),
      malformed=pod_case(container(), securityContext={"seccompProfile": {"type": 1}}))


# --- kubernetes-compliance workload declarations (every PodSpec carrier) ------------------------------------------

DASHBOARD_LABELS = ("app", "apps", "k8s-app", "app.kubernetes.io/name")


def template_labels(item, kind):
    labels = dict(optional(optional(item, "metadata", {}, dict), "labels", {}, dict))
    if kind != "pod":
        meta_path = KIND_PATHS[kind].rsplit(".", 1)[0]
        template = get(item, meta_path, dict)
        labels.update(optional(optional(template, "metadata", {}, dict), "labels", {}, dict))
    return labels


def workload(prefix, kind, slug, title, evaluate_spec, good, bad, *, severity="medium", control="CM-6", remediation, malformed=None,
             not_applicable=None):
    cid = kid(kind + "." + slug)

    @k8s(kind + "." + slug, kind, title, severity=severity, control=control, remediation=remediation)
    def evaluate(item, index):
        spec, rows = pod_spec(item, kind)
        return evaluate_spec(item, kind, spec, rows)
    track(cid)
    extra = {"not_applicable": pod_case(*not_applicable, kind=kind)} if not_applicable else {}
    cases(cid, pod_case(*good, kind=kind), pod_case(*bad, kind=kind),
          malformed=malformed(kind) if malformed else pod_case({"name": "c", "image": 3}, kind=kind), **extra)
    return cid


def dashboard(item, kind, spec, rows):
    labels = template_labels(item, kind)
    if any(not isinstance(v, str) for v in labels.values()):
        raise Unavailable("malformed labels")
    hits = [row["name"] for row in rows if re.search(r"(^|/)(kubernetes-dashboard|kubernetesui/)",
                                                     get(row, "image", str) if "image" in row else "")]
    labelled = [k for k in DASHBOARD_LABELS if labels.get(k) == "kubernetes-dashboard"]
    return result(bool(hits or labelled), dashboard_containers=hits, dashboard_labels=labelled)


def privileged_port(item, kind, spec, rows):
    ports = []
    for row in rows:
        for port in list_of_objects(optional(row, "ports", [], list)):
            value = get(port, "containerPort", int)
            if value < 1024:
                ports.append({"container": row["name"], "containerPort": value})
    if not any(optional(row, "ports", [], list) for row in rows):
        return "NOT_APPLICABLE", {"reason": "No container ports declared"}
    return result(bool(ports), privileged_ports=ports)


def secrets_files(item, kind, spec, rows):
    hits = []
    for row in rows:
        for entry in list_of_objects(optional(row, "env", [], list)):
            if "secretKeyRef" in optional(entry, "valueFrom", {}, dict):
                hits.append({"container": row["name"], "env": get(entry, "name", str)})
        for entry in list_of_objects(optional(row, "envFrom", [], list)):
            if "secretRef" in entry:
                hits.append({"container": row["name"], "envFrom": "secretRef"})
    return result(bool(hits), secret_environment=hits)


for _prefix, _kind in WORKLOAD_PREFIXES.items():
    workload(_prefix, _kind, "dashboard_not_deployed", _kind + " does not run the Kubernetes Dashboard", dashboard,
             [container()], [container(image="docker.io/kubernetesui/dashboard:v2.7.0")], control="CM-7",
             remediation="Remove the Kubernetes Dashboard or restrict it behind authenticated, non-public access.")
    workload(_prefix, _kind, "secrets_as_files", _kind + " consumes Secrets as files rather than environment variables", secrets_files,
             [container(env=[{"name": "MODE", "value_redacted": True}])], [container(envFrom=[{"secretRef": {"name": "db"}}])],
             control="SC-28", remediation="Mount Secrets as volumes instead of env secretKeyRef/envFrom secretRef.",
             malformed=lambda kind: pod_case(container(env=[{"name": 1, "valueFrom": {"secretKeyRef": {}}}]), kind=kind))
    if _kind != "podtemplate":
        workload(_prefix, _kind, "no_privileged_port", _kind + " containers do not declare privileged (<1024) container ports",
                 privileged_port, [container(ports=[{"containerPort": 8080}])], [container(ports=[{"containerPort": 80}])],
                 severity="low", control="CM-7", remediation="Listen on unprivileged ports (>=1024) inside containers.",
                 malformed=lambda kind: pod_case(container(ports=[{"containerPort": "80"}]), kind=kind), not_applicable=[container()])


@k8s("deployment.replicas_minimum_3", "deployment", "Deployment declares at least three replicas", severity="low", control="CP-10",
     remediation="Run at least three replicas (or an HPA minReplicas of 3) for highly available services.")
def replicas(item, index):
    value = get(item, "spec.replicas", int)
    return result(value < 3, replicas=value)


cases(track(kid("deployment.replicas_minimum_3")), {"spec": {"replicas": 3}}, {"spec": {"replicas": 1}}, malformed={"spec": {"replicas": "3"}})


@k8s("pod.run_as_user_10000", "pod", "Pod containers run with an explicit UID of at least 10000", severity="low", control="AC-6",
     remediation="Set runAsUser >= 10000 at Pod or container level to avoid UID overlap with host accounts.")
def high_uid(item, index):
    spec, rows = pod_spec(item, "pod")
    low = [{"container": row["name"], "run_as_user": effective_user(spec, row)} for row in rows
           if effective_user(spec, row) is None or effective_user(spec, row) < 10000]
    return result(bool(low), containers=low, semantics="Undeclared runAsUser uses the image default and is not accepted")


cases(track(kid("pod.run_as_user_10000")), pod_case(container(), securityContext={"runAsUser": 10001}),
      pod_case(container(securityContext={"runAsUser": 1000})), malformed=pod_case(container(securityContext={"runAsUser": "x"})))


# --- Services, endpoints and ingresses --------------------------------------------------------------------------

def labels_of(item):
    labels = optional(get(item, "metadata", dict), "labels", {}, dict)
    if any(not isinstance(v, str) for v in labels.values()):
        raise Unavailable("malformed labels")
    return labels


@k8s("service.no_tiller_labels", "service", "Service is not labelled as Helm v2 Tiller", control="CM-7",
     remediation="Remove Helm v2 Tiller; migrate to Helm 3, which has no in-cluster server component.")
def tiller_labels(item, index):
    labels = labels_of(item)
    hit = labels.get("app") == "helm" or labels.get("name") == "tiller"
    return result(hit, labels={k: labels[k] for k in ("app", "name") if k in labels})


cases(track(kid("service.no_tiller_labels")), {"metadata": {"name": "web", "labels": {"app": "web"}}},
      {"metadata": {"name": "tiller-deploy", "labels": {"app": "helm", "name": "tiller"}}}, malformed={"metadata": {"labels": {"app": 1}}})


@k8s("service.no_tiller_selector", "service", "Service labels and selector do not reference Tiller", control="CM-7",
     remediation="Remove Helm v2 Tiller services and deployments.")
def tiller_selector(item, index):
    labels = labels_of(item)
    selector = optional(optional(item, "spec", {}, dict), "selector", {}, dict)
    keys = [k for k in list(labels) + list(selector) if "tiller" in str(k).lower()]
    return result(bool(keys), tiller_keys=keys)


cases(track(kid("service.no_tiller_selector")), {"metadata": {"name": "web"}, "spec": {"selector": {"app": "web"}}},
      {"metadata": {"name": "tiller"}, "spec": {"selector": {"tiller": "x"}}}, malformed={"metadata": {"name": "x"}, "spec": {"selector": "x"}})


@k8s("endpointslice.api_secure_port", "endpointslice", "The kubernetes API Service endpoints serve HTTPS on 443 or 6443", control="SC-8",
     remediation="Serve the Kubernetes API only on its secure port (--secure-port) and do not expose an insecure port.")
def api_endpoint(item, index):
    if labels_of(item).get("kubernetes.io/service-name") != "kubernetes" or get(item, "metadata.namespace", str) != "default":
        return "NOT_APPLICABLE", {"reason": "Not the default/kubernetes Service endpoint slice"}
    ports = list_of_objects(get(item, "ports", list))
    bad = [p for p in ports if not (optional(p, "name", "", str) == "https" and get(p, "port", int) in (443, 6443))]
    return result(bool(bad) or not ports, ports=ports)


_api_meta = {"name": "kubernetes", "namespace": "default", "labels": {"kubernetes.io/service-name": "kubernetes"}}
cases(track(kid("endpointslice.api_secure_port")), {"metadata": _api_meta, "ports": [{"name": "https", "port": 6443}]},
      {"metadata": _api_meta, "ports": [{"name": "http", "port": 8080}]},
      not_applicable={"metadata": {"name": "web-x", "namespace": "apps", "labels": {}}, "ports": []},
      malformed={"metadata": _api_meta, "ports": [{"name": "https", "port": "6443"}]})


def complete_annotations(item):
    """The collector keeps only allow-listed annotations; snippet review needs an explicit complete projection."""
    if get(item, "provenance.annotations_complete", bool) is not True:
        raise Unavailable("annotations were filtered by the collector")
    annotations = optional(get(item, "metadata", dict), "annotations", {}, dict)
    if any(not isinstance(v, str) for v in annotations.values()):
        raise Unavailable("malformed annotations")
    return annotations


def snippet_rule(slug, title, value_pattern):
    @k8s("ingress." + slug, "ingress", title, severity="high", control="CM-7",
         remediation="Remove ingress-nginx *-snippet annotations and set allow-snippet-annotations=false on the controller.")
    def evaluate(item, index):
        annotations = complete_annotations(item)
        hits = [k for k, v in annotations.items() if "snippet" in k and (value_pattern is None or re.search(value_pattern, v))]
        return result(bool(hits), snippet_annotations=hits)
    cid = track(kid("ingress." + slug))
    value = "location /x { alias /etc/; content_by_lua_block {} } kubernetes.io"
    cases(cid, {"metadata": {"name": "i", "annotations": {}}, "provenance": {"annotations_complete": True}},
          {"metadata": {"name": "i", "annotations": {"nginx.ingress.kubernetes.io/server-snippet": value}}, "provenance": {"annotations_complete": True}},
          unknown={"metadata": {"name": "i", "annotations": {}}, "provenance": {"annotations_complete": False}},
          malformed={"metadata": {"name": "i", "annotations": {"a-snippet": 1}}, "provenance": {"annotations_complete": True}})
    return cid


snippet_rule("no_nginx_snippets", "Ingress declares no ingress-nginx snippet annotations", None)
snippet_rule("no_nginx_snippet_alias", "Ingress snippet annotations do not use the alias directive", r"alias")
snippet_rule("no_nginx_snippet_lua", "Ingress snippet annotations do not embed Lua code", r"(lua_|_lua|kubernetes\.io)")


# --- Legacy PodSecurityPolicy ---------------------------------------------------------------------------------------

def psp(slug, title, evaluate_policy, good, bad, *, control="CM-7", malformed=None):
    @k8s("podsecuritypolicy." + slug, "podsecuritypolicy", title, control=control,
         remediation="Migrate to Pod Security Admission; while PSP is in use, tighten the policy as described.")
    def evaluate(item, index):
        version = get(item, "_provenance.kubernetes_version", str)
        parts = version.lstrip("v").split(".")
        if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
            return unknown("Kubernetes version unavailable for removed PSP API")
        if tuple(map(int, parts[:2])) >= (1, 25):
            return "NOT_APPLICABLE", {"reason": "PodSecurityPolicy was removed in Kubernetes 1.25"}
        return evaluate_policy(item)
    cid = track(kid("podsecuritypolicy." + slug))
    wrap = lambda body: {"_provenance": {"kubernetes_version": "v1.24.0"}, **body}
    cases(cid, wrap(good), wrap(bad), not_applicable={"_provenance": {"kubernetes_version": "v1.29.0"}, **bad},
          malformed=wrap(malformed or {"spec": "x"}))
    return cid


def host_paths(item):
    spec = get(item, "spec", dict)
    volumes = opt_strings(spec, "volumes")
    allowed = list_of_objects(optional(spec, "allowedHostPaths", [], list))
    host_path_allowed = "hostPath" in volumes or "*" in volumes
    return result(host_path_allowed and not allowed, volumes=volumes, allowed_host_paths=allowed)


psp("allowed_host_path_restricted", "PSP permitting hostPath volumes restricts allowedHostPaths", host_paths,
    {"spec": {"volumes": ["hostPath"], "allowedHostPaths": [{"pathPrefix": "/var/log", "readOnly": True}]}},
    {"spec": {"volumes": ["*"]}}, malformed={"spec": {"volumes": "hostPath"}})


def psp_annotations(item):
    if get(item, "provenance.annotations_complete", bool) is not True:
        raise Unavailable("PSP annotations were filtered by the collector")
    annotations = optional(get(item, "metadata", dict), "annotations", {}, dict)
    if any(not isinstance(v, str) for v in annotations.values()):
        raise Unavailable("malformed annotations")
    return annotations


def services_hardening(item):
    rule = optional(optional(get(item, "spec", dict), "seLinux", {}, dict), "rule", None, str)
    if rule == "MustRunAs":
        return result(False, selinux_rule=rule)
    annotations = psp_annotations(item)
    ok = annotations.get("apparmor.security.beta.kubernetes.io/defaultProfileName") == "runtime/default" or \
        annotations.get("seccomp.security.alpha.kubernetes.io/defaultProfileName") in ("runtime/default", "docker/default")
    return result(not ok, selinux_rule=rule)


psp("security_services_hardening", "PSP enforces SELinux, AppArmor or seccomp defaults", services_hardening,
    {"spec": {"seLinux": {"rule": "MustRunAs"}}},
    {"spec": {"seLinux": {"rule": "RunAsAny"}}, "metadata": {"name": "p", "annotations": {}}, "provenance": {"annotations_complete": True}},
    malformed={"spec": {"seLinux": {"rule": 1}}})


def default_seccomp(item):
    get(item, "spec", dict)
    annotations = psp_annotations(item)
    value = annotations.get("seccomp.security.alpha.kubernetes.io/defaultProfileName")
    return result(value not in ("docker/default", "runtime/default"), default_profile=value)


psp("default_seccomp_profile", "PSP sets a default seccomp profile", default_seccomp,
    {"spec": {}, "metadata": {"name": "p", "annotations": {"seccomp.security.alpha.kubernetes.io/defaultProfileName": "runtime/default"}},
     "provenance": {"annotations_complete": True}},
    {"spec": {}, "metadata": {"name": "p", "annotations": {}}, "provenance": {"annotations_complete": True}})


# --- Control-plane component flags (static Pod declarations) ------------------------------------------------------

def component_flags(item, component):
    _, rows = pod_spec(item, "pod", include_init=True)
    hints, static = components.component_hints(item, "pod")
    found, gaps = [], []
    for row in rows:
        config = row.get("_component_config")
        if config is None:
            if static or component in hints or row["name"] == component:
                gaps.append(row["name"])
            continue
        if not isinstance(config, dict):
            raise Unavailable("malformed component projection")
        captured = config.get("component")
        if captured != component:
            if captured is None and (static or component in hints or row["name"] == component):
                gaps.append(row["name"])
            continue
        if get(config, "flags_complete", bool) is not True:
            raise Unavailable("incomplete component flag projection")
        found.append((row["name"], get(config, "flags", dict)))
    if gaps and not found:
        raise Unavailable("component declarations unavailable")
    return found


def component_case(component, flags):
    return pod_case({"name": component, "_component_config": {"component": component, "flags_complete": True, "flags": flags}})


@k8s("pod.controller_manager_gc_threshold", "pod", "kube-controller-manager sets a non-default terminated-pod GC threshold",
     severity="low", control="SC-6",
     remediation="Set --terminated-pod-gc-threshold to a value appropriate for the cluster size (not the 12500 default).")
def gc_threshold(item, index):
    found = component_flags(item, "kube-controller-manager")
    if not found:
        return "NOT_APPLICABLE", {"reason": "Pod is not a kube-controller-manager declaration"}
    values = []
    for name, flags in found:
        if "terminated-pod-gc-threshold" not in flags:
            raise Unavailable("threshold not declared; default 12500 or a config file may apply")
        value = get(flags, "terminated-pod-gc-threshold", str)
        if not value.isdigit():
            raise Unavailable("malformed threshold")
        values.append(int(value))
    return result(any(v in (0, 12500) for v in values), thresholds=values)


cases(track(kid("pod.controller_manager_gc_threshold")), component_case("kube-controller-manager", {"terminated-pod-gc-threshold": "10"}),
      component_case("kube-controller-manager", {"terminated-pod-gc-threshold": "12500"}),
      not_applicable=pod_case(container(name="app")),
      malformed=component_case("kube-controller-manager", {"terminated-pod-gc-threshold": "x"}))


@k8s("pod.etcd_unique_ca", "pod", "etcd trusts a CA file different from the kube-apiserver client CA", control="SC-12",
     dependencies=["pod"],
     remediation="Use a dedicated CA for etcd (--trusted-ca-file) distinct from the Kubernetes client CA.")
def etcd_ca(item, index):
    found = component_flags(item, "etcd")
    if not found:
        return "NOT_APPLICABLE", {"reason": "Pod is not an etcd declaration"}
    etcd_files = set()
    for _, flags in found:
        etcd_files.add(get(flags, "trusted-ca-file", str))
    apiserver_files = set()
    for pod in complete_items(index, "pod"):
        try:
            rows = component_flags(pod, "kube-apiserver")
        except Unavailable:
            raise Unavailable("kube-apiserver declarations unavailable for the CA comparison")
        for _, flags in rows:
            apiserver_files.add(get(flags, "client-ca-file", str))
    if not apiserver_files:
        raise Unavailable("no kube-apiserver declaration in the complete Pod inventory")
    shared = sorted(etcd_files & apiserver_files)
    if shared:
        return result(True, shared_ca_files=shared)
    return "MANUAL", {"etcd_trusted_ca_files": sorted(etcd_files), "apiserver_client_ca_files": sorted(apiserver_files),
                      "reason": "Paths differ; certificate contents were not read and must be compared by the operator"}


_etcd = component_case("etcd", {"trusted-ca-file": "/etc/kubernetes/pki/ca.crt"})
_api = lambda path: k8s_index({"pod": [component_case("kube-apiserver", {"client-ca-file": path})]})
cases(track(kid("pod.etcd_unique_ca")), None, _etcd, fail_index=_api("/etc/kubernetes/pki/ca.crt"),
      manual=_etcd, manual_index=_api("/etc/kubernetes/pki/other.crt"),
      malformed=component_case("etcd", {"trusted-ca-file": 1}))
CASES[kid("pod.etcd_unique_ca")].pop("pass")


# --- Kubelet configuration metadata and file permissions --------------------------------------------------------------

STRONG_CIPHERS = frozenset(("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"))


def kubelet_rule(slug, title, evaluate_config, good, bad, *, control="CM-6", severity="medium", remediation, malformed):
    @k8s("configuration." + slug, "component_configuration", title, severity=severity, control=control, remediation=remediation)
    def evaluate(item, index):
        if get(item, "component", str) != "kubelet":
            return "NOT_APPLICABLE", {"reason": "Different component configuration"}
        return evaluate_config(get(item, "configuration", dict))
    cid = track(kid("configuration." + slug))
    wrap = lambda cfg: {"component": "kubelet", "configuration": cfg, "provenance": {"source": "operator-supplied metadata"}}
    cases(cid, wrap(good), wrap(bad), manual=wrap({}), not_applicable={"component": "etcd", "configuration": {}},
          malformed=wrap(malformed))
    return cid


def absent(field):
    return "MANUAL", {"reason": field + " not present in the supplied kubelet configuration; verify node arguments"}


def client_ca(cfg):
    if "authentication" not in cfg:
        return absent("authentication")
    x509 = optional(get(cfg, "authentication", dict), "x509", {}, dict)
    value = optional(x509, "clientCAFile", None, str)
    return result(not value, client_ca_file=value)


def streaming(cfg):
    if "streamingConnectionIdleTimeout" not in cfg:
        return absent("streamingConnectionIdleTimeout")
    value = get(cfg, "streamingConnectionIdleTimeout", str)
    numbers = re.findall(r"[0-9]+(?:\.[0-9]+)?", value)
    if not numbers or not re.fullmatch(r"(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|h|m|s))+|0", value):
        raise Unavailable("malformed duration")
    return result(all(float(n) == 0 for n in numbers), streaming_connection_idle_timeout=value)


def ciphers(cfg):
    if "tlsCipherSuites" not in cfg:
        return absent("tlsCipherSuites")
    values = strings(get(cfg, "tlsCipherSuites", list), "cipher suites")
    weak = sorted(set(values) - STRONG_CIPHERS)
    return result(bool(weak) or not values, weak_ciphers=weak)


def tls_files(cfg):
    if optional(cfg, "serverTLSBootstrap", False, bool):
        return result(False, server_tls_bootstrap=True)
    present = [k for k in ("tlsCertFile", "tlsPrivateKeyFile") if optional(cfg, k, "", str)]
    if not present:
        return absent("tlsCertFile/tlsPrivateKeyFile")
    return result(len(present) != 2, declared=present)


kubelet_rule("kubelet_client_ca_file", "Kubelet configuration declares an x509 client CA file", client_ca,
             {"authentication": {"x509": {"clientCAFile": "/etc/kubernetes/pki/ca.crt"}}}, {"authentication": {"anonymous": {"enabled": False}}},
             control="IA-3", remediation="Set authentication.x509.clientCAFile in the kubelet configuration.",
             malformed={"authentication": {"x509": {"clientCAFile": 1}}})
kubelet_rule("kubelet_streaming_timeout", "Kubelet streaming connection idle timeout is not zero", streaming,
             {"streamingConnectionIdleTimeout": "4h0m0s"}, {"streamingConnectionIdleTimeout": "0s"}, control="SC-10",
             remediation="Set streamingConnectionIdleTimeout to a non-zero duration (for example 4h0m0s).",
             malformed={"streamingConnectionIdleTimeout": "forever"})
kubelet_rule("kubelet_strong_ciphers", "Kubelet TLS cipher suites are limited to strong ciphers", ciphers,
             {"tlsCipherSuites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}, {"tlsCipherSuites": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]},
             control="SC-8", remediation="Restrict tlsCipherSuites to the CIS strong-cipher list.",
             malformed={"tlsCipherSuites": "TLS_RSA_WITH_AES_128_GCM_SHA256"})
kubelet_rule("kubelet_tls_cert_and_key", "Kubelet serving certificate and key are declared (or server TLS bootstrap is used)", tls_files,
             {"tlsCertFile": "/var/lib/kubelet/pki/kubelet.crt", "tlsPrivateKeyFile": "/var/lib/kubelet/pki/kubelet.key"},
             {"tlsCertFile": "/var/lib/kubelet/pki/kubelet.crt"}, control="SC-8",
             remediation="Declare tlsCertFile and tlsPrivateKeyFile, or enable serverTLSBootstrap with approved CSR signing.",
             malformed={"tlsCertFile": 1, "tlsPrivateKeyFile": "/x"})


def file_mode(slug, path, title):
    @k8s("file_metadata." + slug, "file_metadata", title, control="AC-3",
         remediation="Set the file mode to 600 or more restrictive (chmod 600 " + path + ").")
    def evaluate(item, index):
        if get(item, "path", str) != path:
            return "NOT_APPLICABLE", {"reason": "Different file metadata subject"}
        raw = get(item, "mode", (int, str))
        if isinstance(raw, bool):
            raise Unavailable("malformed mode")
        if isinstance(raw, str):
            if not re.fullmatch(r"0?o?[0-7]{3,4}", raw):
                raise Unavailable("malformed mode")
            mode = int(raw.lstrip("0o") or "0", 8)
        else:
            mode = raw
        mode &= 0o7777
        return result(bool(mode & ~0o600), path=path, mode=oct(mode), source=item.get("provenance"),
                      semantics="Operator-supplied metadata; host files are never read")
    cid = track(kid("file_metadata." + slug))
    cases(cid, {"path": path, "mode": "600"}, {"path": path, "mode": 0o644}, not_applicable={"path": "/etc/other", "mode": 0o777},
          malformed={"path": path, "mode": "rw-r--r--"})
    return cid


file_mode("kubelet_conf_permissions", "/etc/kubernetes/kubelet.conf", "kubelet.conf permissions are 600 or more restrictive")
file_mode("kubelet_config_yaml_permissions", "/var/lib/kubelet/config.yaml", "Kubelet config.yaml permissions are 600 or more restrictive")
file_mode("kubelet_service_file_permissions", "/etc/systemd/system/kubelet.service.d/kubeadm.conf",
          "Kubelet service file permissions are 600 or more restrictive")


# --- RBAC ------------------------------------------------------------------------------------------------------------

def rule_lists(rule):
    return (strings(optional(rule, "apiGroups", [""], list), "apiGroups") or [""],
            strings(optional(rule, "resources", [], list), "resources"), strings(optional(rule, "verbs", [], list), "verbs"))


def allows(rules, resources, verbs, api_groups=("",)):
    matched = []
    for rule in list_of_objects(rules):
        groups, declared, declared_verbs = rule_lists(rule)
        if not (set(groups) & set(api_groups) or "*" in groups):
            continue
        if declared and (set(declared) & set(resources) or "*" in declared) and declared_verbs and \
                (set(declared_verbs) & set(verbs) or "*" in declared_verbs):
            matched.append(rule)
    return matched


RULE = lambda groups, resources, verbs: {"rules": [{"apiGroups": groups, "resources": resources, "verbs": verbs}]}


def role_rule(slug, title, resources, verbs, api_groups=("",), *, severity="medium", remediation):
    ids = []
    for kind in ("role", "clusterrole"):
        @k8s(kind + "." + slug, kind, ("ClusterRole " if kind == "clusterrole" else "Role ") + title, severity=severity, control="AC-6",
             category="least_privilege", remediation=remediation)
        def evaluate(item, index):
            matched = allows(get(item, "rules", list), resources, verbs, api_groups)
            return result(bool(matched), matching_rules=matched, semantics="Declared RBAC rules, not effective authorization")
        cid = track(kid(kind + "." + slug))
        cases(cid, RULE([""], ["configmaps"], ["get"]), RULE([api_groups[0]], [resources[0]], [verbs[0]]),
              malformed={"rules": [{"apiGroups": [""], "resources": "pods", "verbs": ["*"]}]})
        ids.append(cid)
    return ids


role_rule("no_pod_create", "does not grant create on pods", ["pods"], ["create"],
          remediation="Restrict pod create permissions to the controllers and operators that require them.")
role_rule("no_secret_read", "does not grant get/list/watch on secrets", ["secrets"], ["get", "list", "watch"], severity="high",
          remediation="Limit Secret get/list/watch to the workloads that need specific Secrets (use resourceNames).")
role_rule("no_bind", "does not grant bind on roles or clusterroles", ["roles", "clusterroles"], ["bind"],
          api_groups=("rbac.authorization.k8s.io",), severity="high",
          remediation="Remove the bind verb on roles/clusterroles except for vetted RBAC administrators.")


def wildcard_rule(kind):
    @k8s(kind + ".no_wildcard_resources_or_verbs", kind,
         ("ClusterRole" if kind == "clusterrole" else "Role") + " does not use wildcard resources or verbs", control="AC-6",
         category="least_privilege", remediation="Replace '*' resources and verbs with explicit lists.")
    def evaluate(item, index):
        hits = []
        for rule in list_of_objects(get(item, "rules", list)):
            _, resources, verbs = rule_lists(rule)
            if any("*" in r for r in resources) or "*" in verbs:
                hits.append(rule)
        return result(bool(hits), wildcard_rules=hits)
    cid = track(kid(kind + ".no_wildcard_resources_or_verbs"))
    cases(cid, RULE([""], ["pods"], ["get"]), RULE([""], ["*"], ["get"]),
          malformed={"rules": [{"resources": ["pods"], "verbs": "*"}]})
    return cid


wildcard_rule("role")
wildcard_rule("clusterrole")


_UNIVERSAL_GROUPS = ("system:authenticated", "system:unauthenticated", "system:serviceaccounts")


def _system_subject(subject):
    """Reserved control-plane identities (system:kube-controller-manager, system:masters, GKE system:gke-*):
    the API server reserves the system: prefix, so they are not human users or groups. Groups that cover every
    caller or every ServiceAccount stay in scope. Known control-plane users without the prefix (kube-apiserver,
    EKS eks:*) are shared with every k8s check through peaso.checks.k8s_managed."""
    from .k8s_managed import control_plane_subject
    get(subject, "name", str)
    return control_plane_subject(subject)


def subject_rule(slug, title, resources, verbs, api_groups=("",), *, severity="high", remediation):
    @k8s("clusterrolebinding." + slug, "clusterrolebinding", title, severity=severity, control="AC-6", category="least_privilege",
         dependencies=["clusterrolebinding", "clusterrole"], remediation=remediation)
    def evaluate(item, index):
        humans = [s for s in list_of_objects(optional(item, "subjects", [], list))
                  if get(s, "kind", str) in ("User", "Group") and not _system_subject(s)]
        if not humans:
            return "NOT_APPLICABLE", {"reason": "Binding has no non-system User or Group subjects"}
        ref = get(item, "roleRef", dict)
        if get(ref, "kind", str) != "ClusterRole":
            raise Unavailable("unrecognized roleRef kind")
        name = get(ref, "name", str)
        roles = [r for r in complete_items(index, "clusterrole") if get(r, "metadata.name", str) == name]
        if len(roles) > 1:
            raise Unavailable("ambiguous ClusterRole")
        matched = allows(get(roles[0], "rules", list), resources, verbs, api_groups) if roles else []
        return result(bool(matched), cluster_role=name, role_found=bool(roles),
                      subjects=[{"kind": s["kind"], "name": s.get("name")} for s in humans], matching_rules=matched,
                      semantics="Declared User/Group binding; aggregation and RoleBinding paths are separate")
    cid = track(kid("clusterrolebinding." + slug))
    binding = {"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "r"},
               "subjects": [{"kind": "User", "name": "alice"}]}
    role = lambda body: k8s_index({"clusterrole": [{"metadata": {"name": "r"}, **body}]})
    cases(cid, binding, binding, pass_index=role(RULE([""], ["configmaps"], ["get"])),
          fail_index=role(RULE([api_groups[0]], [resources[0]], [verbs[0]])),
          not_applicable={**binding, "subjects": [{"kind": "ServiceAccount", "name": "x", "namespace": "y"}]},
          not_applicable_index=role({"rules": []}), malformed={**binding, "subjects": [{"kind": 1}]})
    return cid


subject_rule("no_human_csr_approval", "Users and groups are not bound to CSR approval permissions", ["certificatesigningrequests/approval"],
             ["update", "patch"], ("certificates.k8s.io",), remediation="Remove CSR approval rights from human users and groups.")
subject_rule("no_human_node_proxy", "Users and groups are not bound to nodes/proxy access", ["nodes/proxy"], ["get", "list", "watch"],
             remediation="Remove nodes/proxy access from human users and groups.")
subject_rule("no_human_pv_create", "Users and groups are not bound to PersistentVolume create", ["persistentvolumes"], ["create"],
             severity="medium", remediation="Restrict PersistentVolume creation to storage administrators.")
subject_rule("no_human_serviceaccount_token_create", "Users and groups are not bound to serviceaccounts/token create",
             ["serviceaccounts/token"], ["create"], remediation="Remove serviceaccounts/token create from human users and groups.")
subject_rule("no_human_webhook_config_write", "Users and groups are not bound to admission webhook configuration writes",
             ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"], ["create", "update", "delete"],
             ("admissionregistration.k8s.io",), remediation="Restrict admission webhook configuration changes to cluster administrators.")


@k8s("clusterrolebinding.cluster_admin_review", "clusterrolebinding", "ClusterRoleBinding to cluster-admin is reviewed", severity="high",
     control="AC-6", category="least_privilege",
     remediation="Confirm each cluster-admin binding is required; replace it with narrower roles where possible.")
def cluster_admin(item, index):
    ref = get(item, "roleRef", dict)
    if get(ref, "name", str) != "cluster-admin":
        return "NOT_APPLICABLE", {"reason": "Binding does not reference cluster-admin"}
    subjects = list_of_objects(optional(item, "subjects", [], list))
    return "MANUAL", {"subjects": [{"kind": get(s, "kind", str), "name": s.get("name")} for s in subjects],
                      "reason": "Use of cluster-admin requires owner justification"}


cases(track(kid("clusterrolebinding.cluster_admin_review")), None, None,
      manual={"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "User", "name": "a"}]},
      not_applicable={"metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "view"}},
      malformed={"roleRef": {"name": 1}})
CASES[kid("clusterrolebinding.cluster_admin_review")].pop("pass")
CASES[kid("clusterrolebinding.cluster_admin_review")].pop("fail")
