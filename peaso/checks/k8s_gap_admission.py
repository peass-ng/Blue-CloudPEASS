"""Kubernetes API server admission-plugin gaps (CIS Kubernetes 1.2.3 / 1.2.9).

The upstream Prowler evaluators for these controls are inverted (see the
reviewed manifest rows ``prowler.kubernetes.apiserver_deny_service_external_ips``
and ``prowler.kubernetes.apiserver_event_rate_limit``). These natives implement
the documented requirement instead: the plugin is listed in the kube-apiserver
``--enable-admission-plugins`` declaration. They reuse the projected
``_component_config`` facts the Kubernetes collector already captures for
kube-apiserver static Pods; no host file, admission configuration file or
running process is read, so a PASS is declaration evidence only.
kube-apiserver refuses to start when one plugin is both enabled and disabled,
so an enabled declaration is not contradicted by ``--disable-admission-plugins``.
"""
from __future__ import annotations
from . import register
from .fixtures import CASES, nest
from .k8s_ports_components import evaluate_component
from .k8s_ports_workloads import KIND_PATHS

DOCS = "https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/"

# id suffix -> (spec for evaluate_component, title, remediation)
GAPS = {
    "deny_service_external_ips": (
        ("kube-apiserver", ["enable-admission-plugins"], "contains", "DenyServiceExternalIPs", "NodeRestriction"),
        "API server enables the DenyServiceExternalIPs admission plugin",
        "Append DenyServiceExternalIPs to the kube-apiserver --enable-admission-plugins flag so new Services "
        "cannot set spec.externalIPs (CVE-2020-8554 traffic interception); see " + DOCS + "#denyserviceexternalips",
    ),
    "event_rate_limit": (
        ("kube-apiserver", ["enable-admission-plugins"], "contains", "EventRateLimit", "NodeRestriction"),
        "API server enables the EventRateLimit admission plugin",
        "Append EventRateLimit to the kube-apiserver --enable-admission-plugins flag and provide its "
        "--admission-control-config-file limits so Event floods cannot exhaust the API server; see " + DOCS + "#eventratelimit",
    ),
}
IDS = []


def _register(suffix, spec, title, remediation):
    cid = "k8s.gap.apiserver." + suffix
    IDS.append(cid)

    @register(cid, "k8s", "hardening", "pod", title, "medium", "CM-6", remediation, dependencies=["pod"])
    def evaluate(item, index):
        return evaluate_component(item, "pod", spec)

    def fixture(plugins):
        row = {"name": "kube-apiserver", "_component_config": {"component": "kube-apiserver", "flags_complete": True,
            "flags": {"enable-admission-plugins": plugins}, "version": "v1.30.0"}}
        return nest(KIND_PATHS["pod"], {"containers": [row]})
    CASES[cid] = {"pass": fixture("NodeRestriction," + spec[3]), "fail": fixture("NodeRestriction"), "missing": {}, "malformed": None}


for _suffix, (_spec, _title, _remediation) in GAPS.items():
    _register(_suffix, _spec, _title, _remediation)
