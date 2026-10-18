"""Signed GKE public-IP endpoint predicate over the cached cluster inventory."""
from __future__ import annotations

from . import register, result, unknown
from .facts import complete_items, get


@register(
    "gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d",
    "gcp", "exposure", "gke_cluster",
    "GKE clusters explicitly disable the public IP control-plane endpoint",
    "high", "SC-7",
    "Review control-plane access, then disable the public IP endpoint after an alternative access path is ready.",
    target="scope", dependencies=["gke_cluster"],
)
def gke_public_ip_endpoint_disabled(item, index):
    clusters = complete_items(index, "gke_cluster")
    if not clusters:
        return "NOT_APPLICABLE", {"reason": "no GKE clusters in the complete scoped inventory"}

    public = []
    for cluster in clusters:
        name = get(cluster, "name", str)
        # The signed requirement demands an observed false value. Proto3
        # omission, denied coverage, and malformed booleans remain UNKNOWN.
        enabled = get(cluster, "controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint", bool)
        if enabled:
            public.append(name)

    return result(bool(public), cluster_count=len(clusters), public_ip_endpoint_clusters=public,
                  field="controlPlaneEndpointsConfig.ipEndpointsConfig.enablePublicEndpoint",
                  semantics="Public IP endpoint declaration only; DNS endpoint exposure is separate")
