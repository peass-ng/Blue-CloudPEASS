"""Reviewed independent reference thresholds and safe supplied config facts."""
import copy
from . import register, result, unknown
from .facts import get, Unavailable
from .fixtures import CASES, nest
from . import k8s_ports_components as components

IDS, REFERENCE_SPECS = [], {}

# Existing declaration predicates reuse identical component/field/operator
# semantics. Exact-equality audit thresholds differ from the SQL >= controls.
ALIASES = {
    "apiserver_always_pull_images_plugin": "container_admission_control_plugin_always_pull_images",
    "apiserver_auth_mode_include_node": "container_argument_authorization_mode_node",
    "apiserver_auth_mode_include_rbac": "container_argument_authorization_mode_rbac",
    "apiserver_auth_mode_not_always_allow": "container_argument_authorization_mode_no_always_allow",
    "apiserver_disable_profiling": "container_argument_kube_apiserver_profiling_disabled",
    "apiserver_encryption_provider_config_set": "container_encryption_providers_configured",
    "apiserver_etcd_cafile_set": "container_argument_etcd_cafile_configured",
    "apiserver_kubelet_cert_auth": "container_kubelet_certificate_authority_configured",
    "apiserver_no_always_admit_plugin": "container_admission_control_plugin_no_always_admit",
    "apiserver_no_token_auth_file": "container_token_auth_file_not_configured",
    "apiserver_node_restriction_plugin": "container_argument_node_restriction_enabled",
    "apiserver_service_account_key_file_set": "container_argument_service_account_key_file_appropriate",
    "apiserver_service_account_lookup_true": "container_argument_service_account_lookup_enabled",
    "apiserver_tls_config": "container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured",
    "controllermanager_disable_profiling": "container_argument_kube_controller_manager_profiling_disabled",
    "controllermanager_root_ca_file_set": "container_argument_kube_controller_manager_root_ca_file_configured",
    "controllermanager_rotate_kubelet_server_cert": "container_argument_rotate_kubelet_server_certificate_enabled",
    "controllermanager_service_account_credentials": "container_argument_kube_controller_manager_service_account_credentials_enabled",
    "controllermanager_service_account_private_key_file": "container_argument_kube_controller_manager_service_account_private_key_file_configured",
    "scheduler_profiling": "container_argument_kube_scheduler_profiling_disabled",
    "scheduler_bind_address": "container_argument_kube_scheduler_bind_address_127_0_0_1",
}
for _name, _suffix in ALIASES.items():
    REFERENCE_SPECS[_name] = components.REFERENCE_SPECS["pod_" + _suffix]


def declaration(name, spec):
    cid = components.register_component("pod", "reference_" + name, spec)
    IDS.append(cid)
    REFERENCE_SPECS[name] = cid


for _name, _field, _expected in (("apiserver_audit_log_maxage_set", "audit-log-maxage", "30"),
    ("apiserver_audit_log_maxbackup_set", "audit-log-maxbackup", "10"), ("apiserver_audit_log_maxsize_set", "audit-log-maxsize", "100")):
    declaration(_name, ("kube-apiserver", [_field], "equal", _expected, str(int(_expected) + 1)))
declaration("apiserver_client_ca_file_set", ("kube-apiserver", ["client-ca-file"], "present", None, ""))
declaration("apiserver_audit_log_path_set", ("kube-apiserver", ["audit-log-path"], "present", None, ""))
declaration("apiserver_namespace_lifecycle_plugin", ("kube-apiserver", ["enable-admission-plugins"], "contains", "NamespaceLifecycle", "NodeRestriction"))
declaration("apiserver_service_account_plugin", ("kube-apiserver", ["enable-admission-plugins"], "contains", "ServiceAccount", "NodeRestriction"))
declaration("controllermanager_bind_address", ("kube-controller-manager", ["bind-address"], "equal", "127.0.0.1", "0.0.0.0"))
declaration("etcd_no_peer_auto_tls", ("etcd", ["peer-auto-tls"], "equal", "false", "true"))


def configuration(name, path, good, bad, *, expected=None):
    cid = "k8s.ports.configuration." + name
    IDS.append(cid)
    @register(cid, "k8s", "hardening", "component_configuration", "Review supplied " + name.replace("_", " "), "medium", "CM-6",
        "Obtain approved read-only configuration metadata or an explicitly identified operator attestation; no node execution or host-file reads are performed.")
    def evaluate(item, index):
        if get(item, "component", str) != "kubelet":
            return "NOT_APPLICABLE", {"reason": "Different component configuration"}
        value = get(item, "configuration." + path, expected or type(good))
        return result(value != good, field=path, configured=value,
            source=item.get("provenance"), semantics="Supplied configuration metadata; collection provenance must be reviewed separately")
    fixture = lambda value: {"component": "kubelet", "configuration": nest(path, value),
        "provenance": {"source": "modeled/operator-supplied metadata", "runtime_verified": False}}
    CASES[cid] = {"pass": fixture(good), "fail": fixture(bad), "missing": {}, "malformed": None}
    REFERENCE_SPECS[name] = cid


configuration("kubelet_authorization_mode", "authorization.mode", "Webhook", "AlwaysAllow")
configuration("kubelet_disable_anonymous_auth", "authentication.anonymous.enabled", False, True)
configuration("kubelet_disable_read_only_port", "readOnlyPort", 0, 10255)
configuration("kubelet_manage_iptables", "makeIPTablesUtilChains", True, False)
configuration("kubelet_rotate_certificates", "rotateCertificates", True, False)


def file_owner(name, path):
    cid = "k8s.ports.file_metadata." + name
    IDS.append(cid)
    @register(cid, "k8s", "hardening", "file_metadata", "Review supplied ownership for " + path, "medium", "CM-6",
        "Have the node operator attest file ownership through an approved metadata source; the scanner never reads host files or executes node commands.")
    def evaluate(item, index):
        configured_path = get(item, "path", str)
        if configured_path != path:
            return "NOT_APPLICABLE", {"reason": "Different file metadata subject"}
        uid, gid = get(item, "uid", int), get(item, "gid", int)
        if uid < 0 or gid < 0:
            return unknown("invalid POSIX ownership")
        return result(uid != 0 or gid != 0, path=path, uid=uid, gid=gid, source=item.get("provenance"),
            semantics="Operator-supplied metadata; no host file contents or credential values are collected")
    CASES[cid] = {"pass": {"path": path, "uid": 0, "gid": 0}, "fail": {"path": path, "uid": 1000, "gid": 1000},
        "missing": {}, "malformed": None}
    REFERENCE_SPECS[name] = cid


file_owner("kubelet_conf_file_ownership", "/etc/kubernetes/kubelet.conf")
file_owner("kubelet_config_yaml_ownership", "/var/lib/kubelet/config.yaml")
file_owner("kubelet_service_file_ownership_root", "/etc/systemd/system/kubelet.service.d/kubeadm.conf")
