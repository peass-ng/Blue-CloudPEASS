"""Check a cluster policy self-grant followed by job execution as its VM SA."""

from __future__ import annotations

import re

from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_create import _api, _script


def _cloud_platform_scope(cluster):
    config = cluster.get('config') or {}
    gce = config.get('gceClusterConfig') or {}
    scopes = gce.get('serviceAccountScopes') or []
    if 'https://www.googleapis.com/auth/cloud-platform' in scopes:
        return 'derived'
    image = (config.get('softwareConfig') or {}).get('imageVersion')
    version = re.match(r'^(\d+)\.(\d+)(?:\.|-|$)', image or '')
    if version and (int(version.group(1)), int(version.group(2))) >= (2, 1):
        return 'derived'  # Added to every node in image 2.1 and later.
    return 'uncertain'


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    for target_id, target in candidates.items():
        if target_id == source.id or target.kind != 'gcp_service_account' or target.attrs.get('disabled'):
            continue
        email = target.attrs.get('email')
        if not isinstance(email, str):
            continue
        unresolved = False
        for resource in model.hosts.get(email, {}).get('dataproc_cluster', ()):
            cluster = model.dataproc_clusters_by_resource.get(resource)
            if not cluster:
                unresolved = True
                continue
            project = resource.split('/regions/', 1)[0]
            write = _rights(model, source, resource, ('dataproc.clusters.setIamPolicy',))
            jobs = _rights(model, source, project, ('dataproc.jobs.create',))
            if write == 'denied' or jobs == 'denied':
                continue
            if write != 'derived' or jobs != 'derived':
                unresolved = True
                continue
            policy_read = _rights(model, source, resource,
                                  ('dataproc.clusters.getIamPolicy',))
            if policy_read != 'derived':
                unresolved = True  # An existing policy's etag cannot be preserved reliably.
                continue
            # A source that can already use the cluster has the direct job path.
            use = _rights(model, source, resource, ('dataproc.clusters.use',))
            if use == 'derived':
                continue
            if _api(model, project) == 'denied':
                continue
            if _api(model, project) != 'derived':
                unresolved = True
                continue
            state = (cluster.get('status') or {}).get('state')
            if state != 'RUNNING':
                unresolved = True
                continue
            if _cloud_platform_scope(cluster) != 'derived':
                unresolved = True
                continue
            if _script(model, source, target) != 'derived':
                unresolved = True
                continue
            out[target_id] = ('conditional', 'cluster_policy_self_grant_and_readable_job_script')
            break
        if target_id not in out and unresolved:
            out[target_id] = ('unknown', 'cluster_policy_job_path_unresolved')
    return out
