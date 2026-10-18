"""Signed Kubernetes checks over operator-supplied component metadata.

These verdicts describe one observed component record. They never imply that
every kubelet or node in the cluster was represented by the supplied evidence.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import quote

from . import register, result, unknown
from .facts import get, memoized
from .fixtures import CASES

IDS = [
    "k8s.cis.a_limit_is_set_on_pod_pids",
    "k8s.cis.the_seccomp_default_parameter_is_set_to_true",
    "k8s.cis.kubelet_rotate_kubelet_server_certificate_true",
]

_FIXTURE_CLUSTER = "fixture"
_FIXTURE_UID = "uid-a"
_FIXTURE_NODE = "node-a"


def _fixture_declaration(configuration):
    return {"id": f"k8s://{_FIXTURE_CLUSTER}/component_configuration/kubelet/node/{_FIXTURE_UID}",
            "component": "kubelet", "node_name": _FIXTURE_NODE, "node_uid": _FIXTURE_UID,
            "observed_at": "2026-01-01T00:00:00+00:00", "configuration": configuration,
            "provenance": {"cluster_id": _FIXTURE_CLUSTER,
                           "source": "operator-supplied metadata", "runtime_verified": False,
                           "namespace": "_cluster"}}


_FIXTURE_INDEX = {"context": {"metadata": {"cluster_id": _FIXTURE_CLUSTER}},
                  "collections": {"node": [{"status": "collected"}]},
                  "node": [{"data": {"metadata": {"name": _FIXTURE_NODE, "uid": _FIXTURE_UID}}}]}


def _observed_nodes(index):
    def compute():
        pages = index.get("collections", {}).get("node", [])
        if len(pages) != 1 or pages[0].get("status") not in ("collected", "empty"):
            return None
        identities = set()
        for row in index.get("node", []):
            data = row.get("data")
            meta = data.get("metadata") if isinstance(data, Mapping) else None
            if not isinstance(meta, Mapping) or not all(
                    isinstance(meta.get(key), str) and meta[key] for key in ("name", "uid")):
                return None
            identity = (meta["name"], meta["uid"])
            if identity in identities:
                return None
            identities.add(identity)
        return identities
    return memoized(index, ("signed_kubelet_component_nodes",), compute)


def _observed_declaration(item, index, verdict):
    status, evidence = verdict
    if status not in ("PASS", "FAIL"):
        return verdict
    provenance = item.get("provenance")
    context = index.get("context", {})
    metadata = context.get("metadata", {}) if isinstance(context, Mapping) else {}
    cluster = metadata.get("cluster_id") if isinstance(metadata, Mapping) else None
    node_name, node_uid = item.get("node_name"), item.get("node_uid")
    if (not isinstance(provenance, Mapping) or not isinstance(cluster, str) or not cluster or
            provenance.get("cluster_id") != cluster or
            provenance.get("source") != "operator-supplied metadata" or
            provenance.get("runtime_verified") is not False or
            not isinstance(node_name, str) or not node_name or
            not isinstance(node_uid, str) or not node_uid or
            not isinstance(item.get("observed_at"), str) or not item["observed_at"] or
            item.get("id") != (f"k8s://{quote(cluster, safe='')}/component_configuration/"
                               f"kubelet/node/{quote(node_uid, safe='')}")):
        return unknown("kubelet source or node identity is unavailable or foreign")
    nodes = _observed_nodes(index)
    if nodes is not None and (node_name, node_uid) not in nodes:
        return unknown("kubelet node is absent from complete observed Node inventory")
    coverage = metadata.get("component_configuration_coverage") if isinstance(metadata, Mapping) else None
    complete = (isinstance(coverage, Mapping) and coverage.get("status") == "attested_complete" and
                coverage.get("cluster_id") == cluster and nodes is not None)
    return status, {**evidence, "observed_component": "kubelet", "observed_node": node_name,
                    "observed_node_uid": node_uid, "observed_at": item["observed_at"],
                    "source": provenance["source"], "runtime_verified": False,
                    "cluster_declaration_coverage": "attested_complete" if complete else "unknown",
                    "scope_claim": "one observed kubelet declaration"}


def _applicability(item, introduced_minor):
    # Historical offline snapshots may include a kubelet version. The current
    # operator-supplied metadata path does not: its verdict is a declaration
    # only, never proof that the running kubelet accepted the setting.
    if "kubeletVersion" not in item:
        return None
    raw = get(item, "kubeletVersion", str)
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.\d+)?(?:[-+][A-Za-z0-9_.-]+)?", raw)
    if not match:
        return unknown("unrecognized kubelet version", observed_version=raw)
    major, minor = map(int, match.groups())
    if major != 1 or minor > 37:
        return unknown("kubelet version outside reviewed feature range", observed_version=raw)
    if minor < introduced_minor:
        return "NOT_APPLICABLE", {"reason": "feature was not supported by this documented kubelet release", "observed_version": raw}
    return None


@register(IDS[0], "k8s", "hardening", "component_configuration",
          "Observed kubelet configuration declares a positive Pod PID limit", "medium", "CM-6",
          "With the node owner, set a capacity-tested positive podPidsLimit in the kubelet's owned configuration and verify the effective per-node configuration after rollout.",
          dependencies=["component_configuration"])
def kubelet_pod_pid_limit(item, index):
    component = get(item, "component", str)
    if component != "kubelet":
        return "NOT_APPLICABLE", {"reason": "Pod PID limit applies to kubelet configuration", "observed_component": component}
    limit = get(item, "configuration.podPidsLimit", int)
    return _observed_declaration(item, index, result(limit <= 0, observed_pod_pids_limit=limit,
                  semantics="One operator-supplied kubelet configuration declaration; all-node coverage and effective runtime configuration are unproved"))


CASES[IDS[0]] = {
    "pass": _fixture_declaration({"podPidsLimit": 4096}),
    "fail": _fixture_declaration({"podPidsLimit": -1}),
    "index": _FIXTURE_INDEX,
    "missing": {"component": "kubelet", "configuration": {}},
    "malformed": {"component": "kubelet", "configuration": {"podPidsLimit": True}},
}


@register(IDS[1], "k8s", "hardening", "component_configuration",
          "Observed kubelet configuration declares seccompDefault enabled", "medium", "CM-6",
          "Review kubelet version and workload compatibility, then set seccompDefault=true in the owned kubelet configuration and verify effective behavior per node after a staged rollout.",
          dependencies=["component_configuration"])
def kubelet_seccomp_default(item, index):
    component = get(item, "component", str)
    if component != "kubelet":
        return "NOT_APPLICABLE", {"reason": "seccompDefault applies to kubelet configuration", "observed_component": component}
    applicability = _applicability(item, 22)
    if applicability is not None:
        return applicability
    enabled = get(item, "configuration.seccompDefault", bool)
    return _observed_declaration(item, index, result(not enabled, configured_seccomp_default=enabled,
                  semantics="One operator-attested kubelet configuration declaration; runtime enforcement, overrides and all-node coverage are unproved"))


CASES[IDS[1]] = {
    "pass": _fixture_declaration({"seccompDefault": True}),
    "fail": _fixture_declaration({"seccompDefault": False}),
    "index": _FIXTURE_INDEX,
    "missing": {"component": "kubelet", "configuration": {}},
    "malformed": {"component": "kubelet", "configuration": {"seccompDefault": "true"}},
}


def kubelet_server_certificate_gate(item, index):
    """Held proposal only: a true feature gate cannot prove serving-certificate rotation."""
    component = get(item, "component", str)
    if component != "kubelet":
        return "NOT_APPLICABLE", {"reason": "server-certificate rotation gate applies to kubelet", "observed_component": component}
    applicability = _applicability(item, 7)
    if applicability is not None:
        return applicability
    enabled = get(item, "configuration.featureGates.RotateKubeletServerCertificate", bool)
    return result(not enabled, configured_rotation_gate=enabled,
                  semantics="One operator-attested feature-gate declaration; serverTLSBootstrap, CSR approval, issued certificates and all-node coverage are unproved")


CASES[IDS[2]] = {
    "pass": {"component": "kubelet", "configuration": {"featureGates": {"RotateKubeletServerCertificate": True}}},
    "fail": {"component": "kubelet", "configuration": {"featureGates": {"RotateKubeletServerCertificate": False}}},
    "missing": {"component": "kubelet", "configuration": {}},
    "malformed": {"component": "kubelet", "configuration": {"featureGates": {"RotateKubeletServerCertificate": "true"}}},
}
