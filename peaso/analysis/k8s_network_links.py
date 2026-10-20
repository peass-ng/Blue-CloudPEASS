"""Cluster-scoped ownership and declared routing/storage references."""
from .common import as_list, node_id, relationship, source, stable_id


def add_links(snapshot, resources, nodes, edges, context):
    lookup = {}
    cluster_kinds = {"node", "persistentvolume", "storageclass", "csidriver", "csinode", "volumeattachment", "gatewayclass", "ingressclass", "servicecidr", "ipaddress"}
    from .network_catalog import _K8S_NETWORK_EXTENSIONS
    cluster_kinds |= {kind for kind, (_, _, namespaced) in _K8S_NETWORK_EXTENSIONS.items() if not namespaced}
    kinds = {"Pod": "pod", "Service": "service", "Gateway": "gateway", "Deployment": "deployment", "ReplicaSet": "replicaset",
        "StatefulSet": "statefulset", "DaemonSet": "daemonset", "Job": "job", "CronJob": "cronjob", "ReplicationController": "replicationcontroller"}
    for row in resources:
        if row["provider"] != "k8s":
            continue
        cluster, namespace = context(snapshot, row)
        meta = row["data"].get("metadata") or {}
        if not cluster or not isinstance(meta, dict):
            continue
        ns = "_cluster" if row["type"] in cluster_kinds else namespace
        if isinstance(meta.get("name"), str) and ns:
            lookup.setdefault((cluster, ns, row["type"], meta["name"]), []).append(row)
    for row in resources:
        if row["provider"] != "k8s":
            continue
        cluster, namespace = context(snapshot, row)
        if not cluster:
            continue
        data, kind = row["data"], row["type"]
        meta, spec = data.get("metadata") or {}, data.get("spec") or {}
        if not isinstance(meta, dict) or not isinstance(spec, dict):
            continue

        def link(path, target_kind, name, ns=None, uid=None, relation="declared_backend"):
            if not isinstance(name, str) or not name or not target_kind:
                return
            ns = "_cluster" if target_kind in cluster_kinds else ns or namespace
            if not ns:
                return
            matches = lookup.get((cluster, ns, target_kind, name), [])
            if uid:
                matches = [m for m in matches if (m["data"].get("metadata") or {}).get("uid") == uid]
            if len(matches) == 1:
                target = node_id(matches[0])
            else:
                rid = f"k8s://{cluster}/{target_kind}/{ns}/{name}"
                target = stable_id("k8s", row["scope"], target_kind, rid)
                nodes.setdefault(target, {"id": target, "resource_id": None, "native_id": rid, "label": name,
                    "type": target_kind, "provider": "k8s", "scope": row["scope"],
                    "evidence": {"inventory_status": "reference_only", "uncertainty": "Target missing, ambiguous or UID does not match"}})
            if target != node_id(row):
                edges.append(relationship(node_id(row), target, relation, source(snapshot, row, path)))

        for i, owner in enumerate(as_list(meta.get("ownerReferences"))):
            if isinstance(owner, dict) and owner.get("uid"):
                link(f"metadata.ownerReferences[{i}]", kinds.get(owner.get("kind")), owner.get("name"), uid=owner["uid"], relation="owned_by")
        if kind == 'pod':
            from .network_observations import multus_networks
            for network in multus_networks(data):
                link('metadata.annotations.' + network['_annotation'], 'network_attachment_definition',
                     network['name'], network['namespace'], relation='declared_additional_network')
        if kind == "gateway":
            link("spec.gatewayClassName", "gatewayclass", spec.get("gatewayClassName"), relation="gateway_class")
        if kind == "backendtlspolicy":
            for i, ref in enumerate(as_list(spec.get("targetRefs"))):
                if isinstance(ref, dict) and ref.get("group", "") == "" and ref.get("kind") == "Service":
                    link(f"spec.targetRefs[{i}]", "service", ref.get("name"), relation="backend_tls_policy_target")
        if kind == "ipaddress":
            ref = spec.get("parentRef") or {}
            if isinstance(ref, dict) and ref.get("group", "") == "" and ref.get("resource") == "services":
                link("spec.parentRef", "service", ref.get("name"), ref.get("namespace"), relation="allocated_service_address")
        if kind == "ingress":
            link("spec.ingressClassName", "ingressclass", spec.get("ingressClassName"), relation="ingress_class")
        if kind in {"persistentvolume", "persistentvolumeclaim"}:
            link("spec.storageClassName", "storageclass", spec.get("storageClassName"), relation="storage_class")
        if kind == "volumeattachment":
            link("spec.nodeName", "node", spec.get("nodeName"), relation="attached_to_node")
            link("spec.attacher", "csidriver", spec.get("attacher"), relation="storage_driver")
            src = spec.get("source") or {}
            if isinstance(src, dict):
                link("spec.source.persistentVolumeName", "persistentvolume", src.get("persistentVolumeName"), relation="storage_attachment")
        if kind == "storageclass":
            link("provisioner", "csidriver", data.get("provisioner"), relation="storage_driver")
        if kind == "csinode":
            link("metadata.name", "node", meta.get("name"), relation="node_driver_configuration")
        if kind == "endpointslice":
            labels = meta.get("labels") or {}
            if isinstance(labels, dict):
                link("metadata.labels.kubernetes.io/service-name", "service", labels.get("kubernetes.io/service-name"), relation="service_endpoints")
        if kind == "endpoint":
            link("metadata.name", "service", meta.get("name"), relation="service_endpoints")

        def visit(value, path):
            if isinstance(value, dict):
                for key, val in value.items():
                    p = f"{path}.{key}"
                    if key == 'k8sService' and isinstance(val, dict):
                        link(p, 'service', val.get('serviceName'), val.get('namespace'))
                    if key in {'services', 'upstreams'} and isinstance(val, list) and kind.startswith(('traefik_', 'contour_', 'nginx_')):
                        for i, ref in enumerate(val):
                            if not isinstance(ref, dict):
                                continue
                            target = 'traefik_service' if ref.get('kind') == 'TraefikService' else 'service'
                            name = ref.get('service') if key == 'upstreams' else ref.get('name')
                            link(f'{p}[{i}]', target, name, ref.get('namespace'))
                    if key == 'to' and isinstance(val, dict) and kind == 'openshift_route' and val.get('kind', 'Service') == 'Service':
                        link(p, 'service', val.get('name'))
                    if key == 'server' and isinstance(val, dict) and kind == 'linkerd_server_authorization':
                        link(p, 'linkerd_server', val.get('name'), relation='declared_authorization_target')
                    if key == 'host' and isinstance(val, str) and kind.startswith('istio_') and ('destination' in path or kind == 'istio_destination_rule'):
                        parts = val.rstrip('.').split('.')
                        if len(parts) >= 3 and parts[2] == 'svc':
                            link(p, 'service', parts[0], parts[1])
                    if key == "targetRef" and isinstance(val, dict) and val.get("kind") in kinds:
                        link(p, kinds[val["kind"]], val.get("name"), val.get("namespace"), val.get("uid"), "endpoint_target")
                    if key in {"backendRefs", "parentRefs"} and isinstance(val, list):
                        for i, ref in enumerate(val):
                            if not isinstance(ref, dict):
                                continue
                            default = "Gateway" if key == "parentRefs" else "Service"
                            target_kind = kinds.get(ref.get("kind", default))
                            group = ref.get("group", "gateway.networking.k8s.io" if key == "parentRefs" else "")
                            if group not in {"", "gateway.networking.k8s.io", "core"}:
                                continue
                            link(f"{p}[{i}]", target_kind, ref.get("name"), ref.get("namespace"), relation="declared_parent" if key == "parentRefs" else "declared_backend")
                    if key in {"backend", "defaultBackend"} and isinstance(val, dict) and kind == "ingress":
                        service = val.get("service") or {}
                        if isinstance(service, dict):
                            link(p + ".service.name", "service", service.get("name") or val.get("serviceName"))
                    if isinstance(val, (dict, list)):
                        visit(val, p)
            elif isinstance(value, list):
                for i, val in enumerate(value):
                    visit(val, f"{path}[{i}]")
        visit(data, "data")
