"""Resolve a replaceable init action on one existing Dataproc cluster."""

from __future__ import annotations

from datetime import datetime, timezone

from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_cluster_selfgrant import _cloud_platform_scope
from .gcp_dataproc_create import _api
from .gcp_dataproc_gateway import _identity_unresolved, _mapping, _personal


def _replacement(metadata):
    if isinstance(metadata, dict) and metadata.get('status') == 'not_found':
        return 'absent'
    if not isinstance(metadata, dict) or metadata.get('status') != 'collected':
        return 'uncertain'
    value = metadata.get('metadata')
    if not isinstance(value, dict) or not value.get('generation'):
        return 'uncertain'
    if value.get('temporaryHold') or value.get('eventBasedHold'):
        return 'denied'
    for key in ('retentionExpirationTime', 'retainUntilTime'):
        until = value.get(key)
        if not until:
            continue
        try:
            when = datetime.fromisoformat(until.replace('Z', '+00:00'))
            if when.tzinfo is None:
                return 'uncertain'
            if when > datetime.now(timezone.utc):
                return 'denied'
        except (TypeError, ValueError):
            return 'uncertain'
    return 'derived'


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
        for cluster_resource, cluster in model.dataproc_clusters_by_resource.items():
            if model.dataproc_cluster_service_accounts.get(cluster_resource) != email:
                continue
            project = cluster_resource.split('/regions/', 1)[0]
            if _api(model, project) == 'denied':
                continue
            if (_api(model, project) != 'derived' or
                    (cluster.get('status') or {}).get('state') != 'RUNNING' or
                    _cloud_platform_scope(cluster) != 'derived' or
                    _mapping(cluster) or _identity_unresolved(cluster) or _personal(cluster)):
                unresolved = True
                continue
            objects = model.dataproc_init_by_cluster.get(cluster_resource, {})
            if not objects and ((cluster.get('config') or {}).get('initializationActions')):
                unresolved = True
            for resource, metadata in objects.items():
                replacement = _replacement(metadata)
                if replacement == 'denied':
                    continue
                create = _rights(model, source, resource, ('storage.objects.create',))
                delete = (_rights(model, source, resource, ('storage.objects.delete',))
                          if replacement != 'absent' else 'derived')
                if create == 'denied' or delete == 'denied':
                    continue
                read = _rights(model, target, resource, ('storage.objects.get',))
                if read == 'denied':
                    continue
                if (replacement not in ('derived', 'absent') or create != 'derived' or
                        delete != 'derived' or read != 'derived'):
                    unresolved = True
                    continue
                out[target_id] = ('conditional', 'writable_referenced_init_action_for_future_node')
                break
            if target_id in out:
                break
        if target_id not in out and unresolved:
            out[target_id] = ('unknown', 'init_action_replacement_or_execution_unresolved')
    return out
