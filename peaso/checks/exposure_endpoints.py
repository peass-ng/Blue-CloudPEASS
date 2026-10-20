"""Managed Kubernetes control-plane endpoints: public only when not CIDR-restricted.

The literal hardening checks (azure.aks.private_cluster, gcp.gke.private_endpoint)
stay unchanged; these exposure checks honour authorized source ranges so a public
endpoint restricted to approved CIDRs is not reported as internet-reachable.
"""
from __future__ import annotations
from ipaddress import ip_network

from . import register, result, unknown
from .facts import get, optional
from .fixtures import CASES

OPEN = ("0.0.0.0/0", "::/0", "*")


def _open(cidrs):
    # Canonical parsing also catches alternative IPv6 spellings of ::/0.
    # Invalid strings never count as proof of configured restrictions.
    return [c for c in cidrs if ip_network(c.strip(), strict=False).prefixlen == 0]


@register("azure.aks.api_server_restricted", "azure", "exposure", "aks_cluster", "AKS API server is private or restricted to authorized IP ranges", "high", "SC-7",
          "Enable a private cluster or set apiServerAccessProfile.authorizedIPRanges to approved administrative CIDRs.")
def aks_api_server(item, index):
    from ipaddress import collapse_addresses
    props = get(item, "properties", dict)
    profile = optional(props, "apiServerAccessProfile", {}, dict)
    if not isinstance(profile, dict):
        return unknown("malformed apiServerAccessProfile")
    if optional(profile, "enablePrivateCluster", False, bool):
        return result(False, private_cluster=True)
    ranges = optional(profile, "authorizedIPRanges", [], list)
    if not isinstance(ranges, list) or any(not isinstance(r, str) for r in ranges):
        return unknown("malformed authorizedIPRanges")
    networks = [ip_network(value.strip(), strict=False) for value in ranges]
    universal = any(network.prefixlen == 0 for version in (4, 6)
                    for network in collapse_addresses(n for n in networks if n.version == version))
    return result(not ranges or universal, private_cluster=False, authorized_ip_ranges=ranges,
                  semantics="Public API server without authorized IP ranges is reachable from 0.0.0.0/0; Entra/Kubernetes authentication still applies.")


@register("gcp.gke.control_plane_restricted", "gcp", "exposure", "gke_cluster", "GKE control plane is private or restricted to authorized networks", "high", "SC-7",
          "Enable the private endpoint or master authorized networks with approved CIDRs only.")
def gke_control_plane(item, index):
    if not isinstance(item, dict) or not item or "name" not in item:
        return unknown("cluster facts missing")
    private = optional(item, "privateClusterConfig", {}, dict)
    control = optional(item, "controlPlaneEndpointsConfig", {}, dict)
    endpoints = optional(control, "ipEndpointsConfig", {}, dict)
    if not isinstance(private, dict) or not isinstance(endpoints, dict):
        return unknown("malformed private cluster configuration")
    if "enabled" in endpoints and get(endpoints, "enabled", bool) is False:
        dns = optional(control, "dnsEndpointConfig", {}, dict)
        return "NOT_APPLICABLE", {"reason": "IP-based control-plane endpoints are disabled; DNS endpoint authorization needs separate review.",
            "ip_endpoints_enabled": False, "dns_endpoint_present": bool(dns.get("endpoint")),
            "dns_external_traffic": dns.get("allowExternalTraffic")}
    if optional(private, "enablePrivateEndpoint", False, bool) or ("enablePublicEndpoint" in endpoints and get(endpoints, "enablePublicEndpoint", bool) is False):
        return result(False, private_endpoint=True)
    legacy = optional(item, "masterAuthorizedNetworksConfig", None, dict) if "masterAuthorizedNetworksConfig" in item or "masterAuthorizedNetworksConfig" in item.get("_coverage", {}) else None
    modern = optional(endpoints, "authorizedNetworksConfig", None, dict) if "authorizedNetworksConfig" in endpoints or "authorizedNetworksConfig" in endpoints.get("_coverage", {}) else None
    # The live API mirrors one setting in both fields (both `{}` when disabled);
    # only differing declarations are a conflict.
    if legacy is not None and modern is not None and legacy != modern:
        return unknown("conflicting legacy and modern authorized network configurations")
    authorized = modern if modern is not None else legacy if legacy is not None else {}
    if not isinstance(authorized, dict):
        return unknown("malformed masterAuthorizedNetworksConfig")
    blocks = optional(authorized, "cidrBlocks", [], list)
    if not isinstance(blocks, list) or any(not isinstance(b, dict) for b in blocks):
        return unknown("malformed authorized network blocks")
    cidrs = [get(b, "cidrBlock", str) for b in blocks]
    enabled = optional(authorized, "enabled", False, bool)
    cloud_access = optional(authorized, "gcpPublicCidrsAccessEnabled", False, bool)
    open_ranges = _open(cidrs)
    if enabled and not open_ranges and cloud_access:
        return "MANUAL", {"reason": "Google Cloud public IPs are allowed in addition to the configured CIDRs; review whether that broad source population is intended.",
            "authorized_networks": cidrs, "gcp_public_cidrs_access": True,
            "authentication": "IAM/RBAC still applies; network source access is not anonymous Kubernetes authorization."}
    return result(not enabled or bool(open_ranges), private_endpoint=False,
                  authorized_networks_enabled=enabled, authorized_networks=cidrs,
                  gcp_public_cidrs_access=cloud_access,
                  semantics="Public endpoint without authorized networks is reachable from 0.0.0.0/0; IAM/RBAC authentication still applies.")


CASES["azure.aks.api_server_restricted"] = {
    "pass": {"properties": {"apiServerAccessProfile": {"authorizedIPRanges": ["203.0.113.0/24"]}}},
    "fail": {"properties": {"apiServerAccessProfile": {"authorizedIPRanges": []}}},
    "unknown": {"properties": {"apiServerAccessProfile": {"authorizedIPRanges": "0.0.0.0/0"}}},
    "missing": {}, "malformed": None}
CASES["gcp.gke.control_plane_restricted"] = {
    "pass": {"name": "c", "masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": "203.0.113.0/24"}]}},
    "fail": {"name": "c", "masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": [{"cidrBlock": "0.0.0.0/0"}]}},
    "unknown": {"name": "c", "masterAuthorizedNetworksConfig": {"enabled": True, "cidrBlocks": "0.0.0.0/0"}},
    "missing": {}, "malformed": None}
