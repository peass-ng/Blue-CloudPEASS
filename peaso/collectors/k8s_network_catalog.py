"""Core network inventories and version-negotiated Gateway API discovery."""
ENDPOINTS = {
    "servicecidr": ("/apis/networking.k8s.io/v1/servicecidrs", False),
    "ipaddress": ("/apis/networking.k8s.io/v1/ipaddresses", False),
    "endpoint": ("/api/v1/endpoints", True),
    "storageclass": ("/apis/storage.k8s.io/v1/storageclasses", False),
    "csidriver": ("/apis/storage.k8s.io/v1/csidrivers", False),
    "csinode": ("/apis/storage.k8s.io/v1/csinodes", False),
    "volumeattachment": ("/apis/storage.k8s.io/v1/volumeattachments", False),
}
GATEWAYS = {
    "gatewayclass": ("gatewayclasses", False), "gateway": ("gateways", True),
    "httproute": ("httproutes", True), "grpcroute": ("grpcroutes", True),
    "tlsroute": ("tlsroutes", True), "tcproute": ("tcproutes", True),
    "udproute": ("udproutes", True), "referencegrant": ("referencegrants", True),
    "backendtlspolicy": ("backendtlspolicies", True),
}
GROUP = "gateway.networking.k8s.io"
from . import k8s_network_route_extensions as route_extensions
ENDPOINTS.update({kind: route_extensions.endpoint(kind) for kind in route_extensions.RESOURCES})


def allowed_path(path):
    import re
    if route_extensions.match(path):
        return True
    plurals = "|".join(plural for plural, _ in GATEWAYS.values())
    return bool(re.fullmatch(r"/apis/gateway\.networking\.k8s\.io/(?:v1|v1beta1|v1alpha2|v1alpha3)(?:/namespaces/[a-z0-9-]+)?/(?:" + plurals + ")", path))


def read(reader, native_call, operation, path, *args, **kwargs):
    """Negotiate the served resource version before its first list request.

    This uses the ordinary scheduler and normalization path, including page,
    resource and credential budgets. The shared annotation producer is unchanged.
    """
    from .k8s import K8sReadError
    if route_extensions.match(path):
        return route_extensions.read(reader, native_call, operation, path, *args, **kwargs)
    with reader.gateway_discovery_lock:
        if reader.gateway_discovery is None:
            groups = native_call(operation, "/apis")
            if not isinstance(groups, dict) or not isinstance(groups.get("groups"), list):
                raise ValueError("malformed Gateway API discovery")
            group = [g for g in groups["groups"] if isinstance(g, dict) and g.get("name") == GROUP]
            resources = {}
            versions = {v.get("version") for g in group for v in g.get("versions", []) if isinstance(v, dict)}
            for version in ("v1", "v1beta1", "v1alpha3", "v1alpha2"):
                if version not in versions:
                    continue
                doc = native_call(operation, f"/apis/{GROUP}/{version}")
                if not isinstance(doc, dict) or not isinstance(doc.get("resources"), list):
                    raise ValueError("malformed Gateway API resource discovery")
                for row in doc["resources"]:
                    if isinstance(row, dict) and isinstance(row.get("name"), str) and "list" in row.get("verbs", []):
                        resources.setdefault(row["name"], (version, row.get("namespaced")))
            reader.gateway_discovery = {"absent": not group, "resources": resources}
        discovery = reader.gateway_discovery
    if discovery["absent"]:
        return {"items": [], "metadata": {}, "kind": "List"}
    plural = path.rsplit("/", 1)[-1]
    resource = discovery["resources"].get(plural)
    if resource is None:
        raise K8sReadError("gateway_resource_not_advertised")
    version, namespaced = resource
    expected_namespaced = next(ns for name, ns in GATEWAYS.values() if name == plural)
    if namespaced is not expected_namespaced:
        raise ValueError("Gateway API resource scope mismatch")
    target = path.replace(f"/apis/{GROUP}/v1/", f"/apis/{GROUP}/{version}/", 1)
    return native_call(operation, target, *args, **kwargs)
