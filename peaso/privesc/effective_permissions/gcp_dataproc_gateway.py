"""Resolve Component Gateway notebook access to the account that runs code."""

from __future__ import annotations

from urllib.parse import urlsplit

from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_cluster_selfgrant import _cloud_platform_scope
from .gcp_dataproc_create import _api


_COMPONENTS = {'JUPYTER', 'ZEPPELIN', 'JUPYTER_KERNEL_GATEWAY'}


def _gateway(cluster):
    config = cluster.get('config') or {}
    endpoint = config.get('endpointConfig') or {}
    if endpoint.get('enableHttpPortAccess') is not True:
        return False
    components = set((config.get('softwareConfig') or {}).get('optionalComponents') or ())
    if not components & _COMPONENTS:
        return False
    ports = endpoint.get('httpPorts') or {}
    if not isinstance(ports, dict):
        return False
    for name, url in ports.items():
        if not isinstance(name, str) or not isinstance(url, str):
            continue
        label = name.lower()
        if not (('jupyter' in label and components & {'JUPYTER', 'JUPYTER_KERNEL_GATEWAY'})
                or ('zeppelin' in label and 'ZEPPELIN' in components)):
            continue
        parsed = urlsplit(url)
        if parsed.scheme == 'https' and (parsed.hostname or '').endswith(
                ('.dataproc.googleusercontent.com', '.dataproc.google.com')):
            return True
    return False


def _mapping(cluster):
    config = cluster.get('config') or {}
    security = config.get('securityConfig') or {}
    identity = security.get('identityConfig') or {}
    mapping = identity.get('userServiceAccountMapping')
    return mapping if isinstance(mapping, dict) and mapping else None


def _identity_unresolved(cluster):
    config = cluster.get('config') or {}
    security = config.get('securityConfig') or {}
    identity = security.get('identityConfig') or {}
    return ('userServiceAccountMapping' in identity and
            not isinstance(identity.get('userServiceAccountMapping'), dict))


def _personal(cluster):
    props = ((cluster.get('config') or {}).get('softwareConfig') or {}).get('properties') or {}
    return any('personal-auth.user' in key and value for key, value in props.items()) if isinstance(props, dict) else False


def _mapped_email(mapping, source):
    if not source.id.startswith('user:'):
        return None
    user = source.id.removeprefix('user:').lower()
    for name, account in mapping.items():
        if isinstance(name, str) and name.lower() == user and isinstance(account, str):
            return account.rsplit('/serviceAccounts/', 1)[-1]
    return None


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
            use = _rights(model, source, resource, ('dataproc.clusters.use',))
            if use == 'denied':
                continue
            get = _rights(model, source, resource, ('dataproc.clusters.get',))
            if get == 'denied':
                unresolved = True
                continue
            if use != 'derived' or get != 'derived':
                unresolved = True
                continue
            if _api(model, project) == 'denied':
                continue
            if (_api(model, project) != 'derived' or
                    (cluster.get('status') or {}).get('state') != 'RUNNING' or
                    not _gateway(cluster)):
                unresolved = True
                continue
            if _personal(cluster):
                unresolved = True  # Direct VM metadata access is not established.
                continue
            if _identity_unresolved(cluster):
                unresolved = True
                continue
            if mapping:
                if mapped != email:
                    unresolved = True  # The VM SA is not the mapped notebook identity.
                    continue
                vm = model.principals.get('serviceAccount:' + str(vm_email))
                if vm is None or _rights(model, vm, target.attrs.get('resource'),
                                         ('iam.serviceAccounts.getAccessToken',)) != 'derived':
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
            out[target_id] = ('conditional', 'enabled_notebook_gateway_with_verified_runtime_identity')
            break
        if target_id not in out and unresolved:
            out[target_id] = ('unknown', 'notebook_gateway_or_runtime_identity_unresolved')
    return out
