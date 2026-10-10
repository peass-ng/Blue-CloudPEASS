"""Pure component-argument declarations from safely projected Pod metadata.

No evaluator reads a node filesystem, executes a command or fetches a Secret.
Captured declarations do not prove that a running host uses those parameters.
"""
from __future__ import annotations
import copy
import re
from . import register, result, unknown
from .facts import get, guard, Unavailable
from .fixtures import CASES, nest
from .k8s_ports_workloads import KIND_PATHS, PREFIXES, pod_spec

IDS, REFERENCE_SPECS = [], {}
CANONICAL_SPECS = {}
CIPHERS = frozenset(("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"))

# suffix -> component, fields, operation, expected, modeled unsafe value.
SPECS = {
    "container_encryption_providers_configured": ("kube-apiserver", ["encryption-provider-config"], "present", None, ""),
    "container_rotate_certificate_enabled": ("kubelet", ["rotate-certificates"], "equal", "true", "false"),
    "container_argument_event_qps_less_than_5": ("kubelet", ["event-qps"], "le", 5, "6"),
    "container_argument_anonymous_auth_disabled": ("kubelet", ["anonymous-auth"], "equal", "false", "true"),
    "container_argument_api_server_anonymous_auth_disabled": ("kube-apiserver", ["anonymous-auth"], "equal", "false", "true"),
    "container_argument_kubelet_anonymous_auth_disabled": ("kubelet", ["anonymous-auth"], "equal", "false", "true"),
    "container_no_argument_basic_auth_file": ("kube-apiserver", ["basic-auth-file"], "absent", None, "/etc/auth.csv"),
    "container_argument_etcd_cafile_configured": ("kube-apiserver", ["etcd-cafile"], "present", None, ""),
    "container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured": ("kube-apiserver", ["etcd-certfile", "etcd-keyfile"], "present", None, ""),
    "container_argument_api_server_etcd_certfile_and_keyfile_configured": ("kube-apiserver", ["etcd-certfile", "etcd-keyfile"], "present", None, ""),
    "container_argument_audit_log_path_configured": ("kube-apiserver", ["audit-log-path"], "present", None, ""),
    "container_argument_audit_log_maxage_greater_than_30": ("kube-apiserver", ["audit-log-maxage"], "ge", 30, "29"),
    "container_argument_audit_log_maxbackup_greater_than_10": ("kube-apiserver", ["audit-log-maxbackup"], "ge", 10, "9"),
    "container_argument_audit_log_maxsize_greater_than_100": ("kube-apiserver", ["audit-log-maxsize"], "ge", 100, "99"),
    "container_argument_authorization_mode_node": ("kube-apiserver", ["authorization-mode"], "contains", "Node", "RBAC"),
    "container_argument_authorization_mode_rbac": ("kube-apiserver", ["authorization-mode"], "contains", "RBAC", "Node"),
    "container_argument_authorization_mode_no_always_allow": ("kube-apiserver", ["authorization-mode"], "excludes", "AlwaysAllow", "AlwaysAllow"),
    "container_no_argument_insecure_bind_address": ("kube-apiserver", ["insecure-bind-address"], "absent", None, "0.0.0.0"),
    "container_argument_kubelet_https_enabled": ("kube-apiserver", ["kubelet-https"], "equal", "true", "false"),
    "container_argument_insecure_port_0": ("kube-apiserver", ["insecure-port"], "equal", "0", "8080"),
    "container_argument_secure_port_not_0": ("kube-apiserver", ["secure-port"], "gt", 0, "0"),
    "container_argument_kubelet_client_certificate_and_key_configured": ("kube-apiserver", ["kubelet-client-certificate", "kubelet-client-key"], "present", None, ""),
    "container_admission_control_plugin_always_pull_images": ("kube-apiserver", ["enable-admission-plugins"], "contains", "AlwaysPullImages", "NodeRestriction"),
    "container_admission_control_plugin_no_always_admit": ("kube-apiserver", ["enable-admission-plugins"], "excludes", "AlwaysAdmit", "AlwaysAdmit"),
    "container_argument_kube_scheduler_profiling_disabled": ("kube-scheduler", ["profiling"], "equal", "false", "true"),
    "container_argument_kube_scheduler_bind_address_127_0_0_1": ("kube-scheduler", ["bind-address"], "equal", "127.0.0.1", "0.0.0.0"),
    "container_argument_bind_address_127_0_0_1": ("kube-scheduler", ["bind-address"], "equal", "127.0.0.1", "0.0.0.0"),
    "container_argument_protect_kernel_defaults_enabled": ("kubelet", ["protect-kernel-defaults"], "equal", "true", "false"),
    "container_argument_make_iptables_util_chains_enabled": ("kubelet", ["make-iptables-util-chains"], "equal", "true", "false"),
    "container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured": ("kubelet", ["tls-cert-file", "tls-private-key-file"], "present", None, ""),
    "container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured": ("kube-apiserver", ["tls-cert-file", "tls-private-key-file"], "present", None, ""),
    "container_argument_tls_cert_file_and_tls_private_key_file_configured": ("kubelet", ["tls-cert-file", "tls-private-key-file"], "present", None, ""),
    "container_no_argument_hostname_override_configured": ("kubelet", ["hostname-override"], "absent", None, "node"),
    "container_argument_kube_controller_manager_profiling_disabled": ("kube-controller-manager", ["profiling"], "equal", "false", "true"),
    "container_argument_kube_controller_manager_bind_address_127_0_0_1": ("kube-controller-manager", ["bind-address"], "equal", "127.0.0.1", "0.0.0.0"),
    "container_argument_etcd_auto_tls_disabled": ("etcd", ["auto-tls"], "equal", "false", "true"),
    "container_argument_kube_controller_manager_service_account_credentials_enabled": ("kube-controller-manager", ["use-service-account-credentials"], "equal", "true", "false"),
    "container_argument_kubelet_authorization_mode_no_always_allow": ("kubelet", ["authorization-mode"], "excludes", "AlwaysAllow", "AlwaysAllow"),
    "container_argument_kube_controller_manager_service_account_private_key_file_configured": ("kube-controller-manager", ["service-account-private-key-file"], "present", None, ""),
    "container_argument_kubelet_read_only_port_0": ("kubelet", ["read-only-port"], "equal", "0", "10255"),
    "container_argument_kube_controller_manager_root_ca_file_configured": ("kube-controller-manager", ["root-ca-file"], "present", None, ""),
    "container_argument_etcd_client_cert_auth_enabled": ("etcd", ["client-cert-auth"], "equal", "true", "false"),
    "container_argument_namespace_lifecycle_enabled": ("kube-apiserver", ["enable-admission-plugins"], "contains", "NamespaceLifecycle", "NodeRestriction"),
    "container_argument_service_account_lookup_enabled": ("kube-apiserver", ["service-account-lookup"], "equal", "true", "false"),
    "container_token_auth_file_not_configured": ("kube-apiserver", ["token-auth-file"], "absent", None, "/etc/tokens.csv"),
    "container_kubelet_certificate_authority_configured": ("kube-apiserver", ["kubelet-certificate-authority"], "present", None, ""),
    "container_argument_node_restriction_enabled": ("kube-apiserver", ["enable-admission-plugins"], "contains", "NodeRestriction", "NamespaceLifecycle"),
    "container_argument_pod_security_policy_enabled": ("kube-apiserver", ["enable-admission-plugins"], "contains", "PodSecurityPolicy", "NamespaceLifecycle"),
    "container_argument_security_context_deny_enabled": ("kube-apiserver", ["enable-admission-plugins"], "contains_any", ("PodSecurityPolicy", "SecurityContextDeny"), "NamespaceLifecycle"),
    "container_argument_kube_apiserver_profiling_disabled": ("kube-apiserver", ["profiling"], "equal", "false", "true"),
    "container_argument_service_account_key_file_appropriate": ("kube-apiserver", ["service-account-key-file"], "present", None, ""),
    "container_strong_kubelet_cryptographic_ciphers": ("kubelet", ["tls-cipher-suites"], "subset", CIPHERS, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    "container_strong_kube_apiserver_cryptographic_ciphers": ("kube-apiserver", ["tls-cipher-suites"], "subset", CIPHERS, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    "container_argument_rotate_kubelet_server_certificate_enabled": (("kube-controller-manager", "kubelet"), ["feature-gates"], "contains", "RotateKubeletServerCertificate=true", "RotateKubeletServerCertificate=false"),
    "container_argument_etcd_certfile_and_keyfile_configured": ("etcd", ["cert-file", "key-file"], "present", None, ""),
    "container_argument_etcd_peer_certfile_and_peer_keyfile_configured": ("etcd", ["peer-cert-file", "peer-key-file"], "present", None, ""),
    "container_argument_service_account_enabled": ("kube-apiserver", ["enable-admission-plugins"], "contains", "ServiceAccount", "NamespaceLifecycle"),
    "container_argument_kubelet_terminated_pod_gc_threshold_configured": ("kubelet", ["terminated-pod-gc-threshold"], "gt", 0, "0"),
    "container_argument_kubelet_client_ca_file_configured": ("kubelet", ["client-ca-file"], "present", None, ""),
    "container_arg_peer_client_cert_auth_enabled": ("etcd", ["peer-client-cert-auth"], "equal", "true", "false"),
    "container_streaming_connection_idle_timeout_not_zero": ("kubelet", ["streaming-connection-idle-timeout"], "nonzero_duration", None, "0"),
    "container_kubelet_streaming_connection_idle_timeout_not_zero": ("kubelet", ["streaming-connection-idle-timeout"], "nonzero_duration", None, "0"),
}

LEGACY_MAX = {"insecure-port": (1, 19), "insecure-bind-address": (1, 19), "basic-auth-file": (1, 18)}


def compare(flags, fields, operation, expected):
    if operation == "absent":
        return all(field not in flags for field in fields)
    if any(field not in flags for field in fields):
        # A field omitted from projected declarations is not a captured effective
        # default; no running component configuration is inferred.
        raise Unavailable("component setting absent; effective defaults or external configuration unknown")
    values = [get(flags, field, str) for field in fields]
    if operation == "present":
        return all(bool(value) for value in values)
    value = values[0]
    if operation == "equal":
        return value == expected
    if operation in ("ge", "gt", "le"):
        if not re.fullmatch(r"[0-9]+", value):
            raise Unavailable("malformed integer component setting")
        integer = int(value)
        return {"ge": integer >= expected, "gt": integer > expected, "le": integer <= expected}[operation]
    if operation in ("contains", "contains_any", "excludes", "subset"):
        members = set(value.split(","))
        if operation == "contains":
            return expected in members
        if operation == "contains_any":
            return bool(members.intersection(expected))
        if operation == "excludes":
            return expected not in members
        return bool(value) and members <= expected
    if operation in ("duration", "nonzero_duration"):
        valid = bool(re.fullmatch(r"(?:[0-9]+(?:\.[0-9]+)?[hms])+|0", value))
        if not valid:
            raise Unavailable("malformed component duration")
        return operation == "duration" or value not in ("0", "0s", "0m", "0h")
    raise ValueError("unreviewed component comparison")


def evaluate_component(item, kind, spec):
    _, containers = pod_spec(item, kind)
    component, fields, operation, expected, _ = spec
    components = (component,) if isinstance(component, str) else component
    observations, bad, gaps = [], [], []
    for container in containers:
        if "_component_config" not in container:
            gaps.append(container["name"])
            continue
        configuration = get(container, "_component_config", dict)
        captured = configuration.get("component")
        if captured is None:
            gaps.append(container["name"])
            continue
        if captured not in components:
            continue
        if get(configuration, "flags_complete", bool) is not True:
            raise Unavailable("incomplete component flag projection")
        version = configuration.get("version")
        max_version = next((LEGACY_MAX[field] for field in fields if field in LEGACY_MAX), None)
        if expected in ("PodSecurityPolicy", ("PodSecurityPolicy", "SecurityContextDeny")):
            max_version = (1, 24)
        if max_version:
            if not isinstance(version, str) or not re.match(r"^v?[0-9]+\.[0-9]+", version):
                return unknown("component version required for removed legacy control")
            current = tuple(int(x) for x in version.lstrip("v").split(".")[:2])
            if current > max_version:
                continue
        flags = get(configuration, "flags", dict)
        safe = compare(flags, fields, operation, expected)
        observations.append({"container": container["name"], "component": captured, "settings": {field: flags.get(field) for field in fields}})
        if not safe:
            bad.append(container["name"])
    if bad:
        return result(True, observations=observations, containers_needing_review=bad,
            semantics="Explicit declarations, not evidence of host/runtime enforcement")
    if gaps:
        return unknown("component applicability/configuration declarations unavailable", containers=gaps)
    if not observations:
        return "NOT_APPLICABLE", {"reason": "Captured components or explicit component versions are outside this control's applicability"}
    return result(False, observations=observations, semantics="Explicit captured declarations only")


def register_component(kind, suffix, spec):
    components, fields, operation, expected, _ = spec
    # Equality includes component applicability, fields, operation and threshold;
    # aliases are not inferred from a normalized source hash or title.
    canonical = (kind, components, tuple(fields), operation,
                 tuple(sorted(expected)) if isinstance(expected, frozenset) else expected)
    if canonical in CANONICAL_SPECS:
        return CANONICAL_SPECS[canonical]
    cid = f"k8s.ports.{kind}.{suffix}"
    CANONICAL_SPECS[canonical] = cid
    IDS.append(cid)
    @register(cid, "k8s", "hardening", kind, kind + " reviewed " + suffix.replace("_", " "), "medium", "CM-6",
        "Review approved component metadata and the version-specific configuration; do not infer host settings from unrelated workload declarations.")
    def evaluate(item, index):
        return evaluate_component(item, kind, spec)
    component, fields, operation, expected, bad = spec
    good = "configured" if operation == "present" else str(expected) if operation in ("equal", "ge", "le") else "1"
    if operation in ("contains", "contains_any"):
        good = expected[0] if isinstance(expected, tuple) else expected
    elif operation == "excludes":
        good = "RBAC" if fields[0] == "authorization-mode" else "NodeRestriction"
    elif operation == "subset":
        good = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    elif operation in ("duration", "nonzero_duration"):
        good = "60s"
    def fixture(value, is_good):
        flags = {} if is_good and operation == "absent" else {field: value for field in fields}
        row = {"name": "component", "_component_config": {"component": component if isinstance(component, str) else component[0],
            "flags_complete": True, "flags": flags, "version": "v1.18.0"}}
        return nest(KIND_PATHS[kind], {"containers": [row]})
    CASES[cid] = {"pass": fixture(good, True), "fail": fixture(bad, False), "missing": {}, "malformed": None}
    return cid


for _prefix, _kind in PREFIXES.items():
    for _suffix, _spec in SPECS.items():
        REFERENCE_SPECS[_prefix + "_" + _suffix] = register_component(_kind, _suffix, _spec)
