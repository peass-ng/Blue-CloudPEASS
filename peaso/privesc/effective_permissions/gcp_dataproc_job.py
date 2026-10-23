"""Resolve an existing Dataproc job path to its effective service account."""

from __future__ import annotations

from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_cluster_selfgrant import _cloud_platform_scope
from .gcp_dataproc_create import _api, _script
from .gcp_dataproc_gateway import _identity_unresolved, _mapped_email, _mapping, _personal


def select(model, candidates, source):
    if source is None:
        return {}
    out = {}
    for target_id, target in candidates.items():
        if (target_id == source.id or target.kind != 'gcp_service_account'
                or target.attrs.get('disabled')):
            continue
        email = target.attrs.get('email')
        if not isinstance(email, str):
            continue
        unresolved = False
        for resource, cluster in model.dataproc_clusters_by_resource.items():
            project = resource.split('/regions/', 1)[0]
            vm_email = model.dataproc_cluster_service_accounts.get(resource)
            mapping = _mapping(cluster)
            if mapping:
                mapped = _mapped_email(mapping, source)
                if mapped != email and email != vm_email:
                    continue
            elif vm_email != email:
                continue
            jobs = _rights(model, source, project, ('dataproc.jobs.create',))
            use = _rights(model, source, resource, ('dataproc.clusters.use',))
            if jobs == 'denied' or use == 'denied':
                continue
            if jobs != 'derived' or use != 'derived':
                unresolved = True
                continue
            if _api(model, project) == 'denied':
                continue
            if _api(model, project) != 'derived':
                unresolved = True
                continue
            if (cluster.get('status') or {}).get('state') != 'RUNNING':
                unresolved = True
                continue
            if _personal(cluster) or _identity_unresolved(cluster):
                unresolved = True
                continue
            if mapping:
                if mapped != email:
                    unresolved = True
                    continue
                vm = model.principals.get('serviceAccount:' + str(vm_email))
                if (vm is None or _rights(model, vm, target.attrs.get('resource'),
                                          ('iam.serviceAccounts.getAccessToken',)) != 'derived'):
                    unresolved = True
                    continue
                scopes = ((cluster.get('config') or {}).get('gceClusterConfig') or {}).get(
                    'serviceAccountScopes') or []
                if (_cloud_platform_scope(cluster) != 'derived' and
                        'https://www.googleapis.com/auth/iam' not in scopes):
                    unresolved = True
                    continue
            elif _cloud_platform_scope(cluster) != 'derived':
                unresolved = True
                continue
            if _script(model, source, target) != 'derived':
                unresolved = True
                continue
            out[target_id] = ('conditional', 'runnable_dataproc_job_with_verified_identity')
            break
        if target_id not in out and unresolved:
            out[target_id] = ('unknown', 'dataproc_job_identity_or_payload_unresolved')
    return out
