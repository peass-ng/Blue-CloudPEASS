"""Resolve stored resource limits from a bound admitted Pod; no node/runtime claims."""
from copy import deepcopy


def project(pod, cluster_id, cluster_uid):
    from .azure_aks_workloads_native import _arm, _identity
    from peaso.checks.compliance_new_sw25_pods import _quantity
    rid = _arm(cluster_id)
    meta = _identity(pod, 'Pod')
    provenance = pod.get('_provenance', {})
    if (provenance.get('cluster_id') != rid or provenance.get('cluster_uid') != cluster_uid
            or not isinstance(cluster_uid, str) or not cluster_uid
            or provenance.get('source_operation') != 'list_pods'
            or provenance.get('representation') != 'full' or provenance.get('read_only') is not True
            or not isinstance(meta.get('namespace'), str) or not meta['namespace']
            or not isinstance(pod.get('id'), str) or not pod['id']):
        raise ValueError('AKS admitted Pod provenance unavailable')
    spec = pod.get('spec')
    if not isinstance(spec, dict):raise ValueError('AKS admitted Pod spec unavailable')
    explicit = True
    names = set()
    for kind in ('containers', 'initContainers', 'ephemeralContainers'):
        containers = spec.get(kind, [])
        if not isinstance(containers, list) or kind == 'containers' and not containers:
            raise ValueError('AKS admitted container universe unavailable')
        for container in containers:
            if not isinstance(container, dict):raise ValueError('AKS admitted container malformed')
            name = container.get('name')
            if not isinstance(name, str) or not name or name in names:
                raise ValueError('AKS admitted container identity ambiguous')
            names.add(name)
            resources = container.get('resources', {})
            limits = resources.get('limits', {}) if isinstance(resources, dict) else None
            if not isinstance(limits, dict):
                explicit = False
                continue
            for resource in ('cpu', 'memory'):
                try:_quantity(limits[resource])
                except Exception:explicit = False
    result = {'id': pod['id'] + '/stored-resource-limits', 'clusterId': rid,
              'podUid': meta['uid'], 'admissionEffectsResolved': explicit,
              '_provenance': {'source_operation': 'list_pods', 'cluster_uid': cluster_uid,
                              'pod_resource_version': meta['resourceVersion'], 'read_only': True,
                              'projection': 'persisted post-admission CPU/memory limits only'}}
    if explicit:
        # This is an empty dependency set: no historical LimitRange is used.
        # It does not assert that no LimitRange existed during Pod admission.
        result['limitRangeBindings'] = []
        result['_coverage'] = {'limitRangeBindings': {'status': 'collected'}}
    else:
        result['_coverage'] = {'limitRangeBindings': {'status': 'not_collected'}}
    return deepcopy(result)
