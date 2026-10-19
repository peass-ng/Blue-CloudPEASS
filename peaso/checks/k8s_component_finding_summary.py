"""Brief observations from reviewed Kubernetes component declarations.

No runtime setting, certificate property or encryption state is inferred.
Missing evidence falls back to the report's existing UNKNOWN/error presentation.
"""
from __future__ import annotations

from .k8s_finding_clarity_reviewed import ROWS

_FLAG_LABELS = {
    "encryption-provider-config": "encryption provider configuration path",
    "tls-cert-file": "TLS certificate path",
    "tls-private-key-file": "TLS private-key path",
    "cert-file": "serving certificate path",
    "key-file": "serving private-key path",
    "peer-cert-file": "peer certificate path",
    "peer-key-file": "peer private-key path",
    "client-ca-file": "client CA path",
    "etcd-cafile": "etcd CA path",
    "etcd-certfile": "etcd client certificate path",
    "etcd-keyfile": "etcd client private-key path",
    "kubelet-client-certificate": "kubelet client certificate path",
    "kubelet-client-key": "kubelet client private-key path",
    "kubelet-certificate-authority": "kubelet certificate CA path",
    "service-account-key-file": "ServiceAccount verification-key path",
    "service-account-private-key-file": "ServiceAccount signing-key path",
    "root-ca-file": "root CA path",
    "audit-log-path": "audit log path",
}


def _short_text(value, maximum=100):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        return None
    return value


def component_evidence_summary(finding):
    """Describe one actual flagged container; retain other containers in details."""
    if not isinstance(finding, dict) or finding.get("provider") != "k8s" or finding.get("status") != "FAIL":
        return None
    check_id = finding.get("check_id")
    if not isinstance(check_id, str):
        return None
    row = ROWS.get(check_id)
    if row is None:
        return None
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        return None
    observations = evidence.get("observations")
    flagged = evidence.get("containers_needing_review")
    if not isinstance(observations, list) or not isinstance(flagged, list) or not flagged:
        return None
    binding = row["reviewed_binding"]
    components = binding["component"]
    components = [components] if isinstance(components, str) else components
    for observed in observations[:100]:
        if not isinstance(observed, dict):
            continue
        name = _short_text(observed.get("container"))
        component = observed.get("component")
        settings = observed.get("settings")
        if name not in flagged or not name or component not in components or not isinstance(settings, dict):
            continue
        values = {field: _short_text(settings.get(field), 160) for field in binding["fields"]}
        if any(value is None for value in values.values()):
            continue
        empty = [field for field, value in values.items() if not value]
        if empty and binding["operation"] == "present":
            labels = [_FLAG_LABELS.get(field, field.replace("-", " ")) for field in empty]
            detail = "an empty " + " and ".join(labels)
        else:
            # Flag spellings describe an exact component setting; they are not
            # internal evidence keys or assumptions about live defaults.
            detail = ", ".join(field.replace("-", " ") + "=" + value for field, value in values.items())
        return "Container “" + name + "” declares " + component + " with " + detail + "."
    return None
