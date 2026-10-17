"""Read only the admission declaration from an immutable, Pod-bound ConfigMap.

Host files, Secret volumes, kubeconfigs and external plugin configuration files
are intentionally unavailable through this API-only collector.
"""
from __future__ import annotations

import posixpath
import re
from datetime import datetime
from urllib.parse import quote

import yaml


class AdmissionFileUnavailable(ValueError):
    pass


def _timestamp(value):
    if not isinstance(value, str):
        raise AdmissionFileUnavailable('admission_object_timestamp_missing')
    try:
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if value.utcoffset() is None:
            raise ValueError()
        return value
    except ValueError as exc:
        raise AdmissionFileUnavailable('admission_object_timestamp_invalid') from exc


def _path(value):
    return (isinstance(value, str) and len(value) <= 4096 and value.startswith('/')
            and posixpath.normpath(value) == value and '//' not in value)


def _name(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?', value))


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise AdmissionFileUnavailable('admission_yaml_duplicate_or_nonstring_key')
        result[key] = loader.construct_object(value_node)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _plugins(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > 262144:
        raise AdmissionFileUnavailable('admission_configuration_size_or_type')
    # Reject aliases before construction; even valid YAML aliases complicate
    # provenance and permit tiny input to create deeply recursive documents.
    if any(isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for token in yaml.scan(text)):
        raise AdmissionFileUnavailable('admission_yaml_alias_unsupported')
    document = yaml.load(text, Loader=_UniqueLoader)
    if (not isinstance(document, dict) or document.get('kind') != 'AdmissionConfiguration'
            or document.get('apiVersion') not in ('apiserver.config.k8s.io/v1', 'apiserver.config.k8s.io/v1alpha1')):
        raise AdmissionFileUnavailable('admission_configuration_schema')
    plugins = document.get('plugins')
    if not isinstance(plugins, list) or len(plugins) > 128:
        raise AdmissionFileUnavailable('admission_configuration_plugins')
    output, seen = [], set()
    for plugin in plugins:
        if not isinstance(plugin, dict) or not isinstance(plugin.get('name'), str) or plugin['name'] in seen:
            raise AdmissionFileUnavailable('admission_configuration_plugin_identity')
        name = plugin['name']
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,127}', name):
            raise AdmissionFileUnavailable('admission_configuration_plugin_identity')
        seen.add(name)
        kept = {'name': name}
        if name == 'ImagePolicyWebhook':
            if plugin.get('path'):
                raise AdmissionFileUnavailable('admission_external_plugin_file_unavailable')
            config = plugin.get('configuration')
            image = config.get('imagePolicy') if isinstance(config, dict) else None
            if not isinstance(image, dict) or not isinstance(image.get('kubeConfigFile'), str):
                raise AdmissionFileUnavailable('admission_image_policy_schema')
            # The check consumes a normalized plugin-specific configuration.
            # Retain only its path; never read the referenced credential file.
            kept['configuration'] = {'kubeConfigFile': image['kubeConfigFile']}
        output.append(kept)
    return output


def _binding(pod, container, path):
    spec, meta = pod.get('spec', {}), pod.get('metadata', {})
    if pod.get('_static_pod_metadata'):
        raise AdmissionFileUnavailable('static_pod_configmap_mount_unavailable')
    mounts = container.get('volumeMounts', [])
    if not isinstance(mounts, list) or any(not isinstance(mount, dict) for mount in mounts):
        raise AdmissionFileUnavailable('admission_volume_mounts_malformed')
    matches = [mount for mount in mounts if _path(mount.get('mountPath')) and
               (path == mount['mountPath'] or path.startswith(mount['mountPath'].rstrip('/') + '/'))]
    if len(matches) != 1:
        raise AdmissionFileUnavailable('admission_volume_mount_missing_or_ambiguous')
    mount = matches[0]
    if 'subPath' in mount or 'subPathExpr' in mount:
        raise AdmissionFileUnavailable('admission_subpath_snapshot_unverified')
    volumes = spec.get('volumes', [])
    if not isinstance(volumes, list):
        raise AdmissionFileUnavailable('admission_volumes_malformed')
    sources = [volume for volume in volumes if isinstance(volume, dict) and volume.get('name') == mount.get('name')]
    if len(sources) != 1 or not isinstance(sources[0].get('configMap'), dict):
        raise AdmissionFileUnavailable('admission_non_configmap_volume_unavailable')
    volume = sources[0]
    if set(volume) - {'name', 'configMap'}:
        raise AdmissionFileUnavailable('admission_volume_source_ambiguous')
    config = volume['configMap']
    if not _name(config.get('name')) or not _name(meta.get('namespace')) or not meta.get('uid'):
        raise AdmissionFileUnavailable('admission_configmap_binding_identity')
    relative = posixpath.relpath(path, mount['mountPath'])
    if relative == '.' or relative.startswith('../'):
        raise AdmissionFileUnavailable('admission_configmap_file_path')
    items = config.get('items')
    if items is None:
        key = relative
        if '/' in key:
            raise AdmissionFileUnavailable('admission_configmap_key_path_unavailable')
    else:
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise AdmissionFileUnavailable('admission_configmap_items_malformed')
        matching = [item for item in items if item.get('path') == relative]
        if len(matching) != 1:
            raise AdmissionFileUnavailable('admission_configmap_projection_missing_or_ambiguous')
        key = matching[0].get('key')
    if not isinstance(key, str) or not re.fullmatch(r'[-._a-zA-Z0-9]{1,253}', key):
        raise AdmissionFileUnavailable('admission_configmap_key_invalid')
    return meta['namespace'], config['name'], key


def pages(reader, api, collection, cluster):
    """Produce a complete envelope only when every relevant declaration is read."""
    if collection.get('status') not in ('collected', 'empty'):
        raise AdmissionFileUnavailable('admission_pod_inventory_incomplete')
    output = []
    cache = {}
    for pod in collection['items']:
        containers = pod.get('spec', {}).get('containers', [])
        for container in containers:
            config = container.get('_component_config', {})
            if config.get('component') != 'kube-apiserver':
                continue
            if config.get('flags_complete') is not True:
                raise AdmissionFileUnavailable('admission_component_flags_incomplete')
            path = config.get('flags', {}).get('admission-control-config-file')
            if path is None:
                continue
            if not _path(path):
                raise AdmissionFileUnavailable('admission_configuration_path_invalid')
            namespace, name, key = _binding(pod, container, path)
            url = f'/api/v1/namespaces/{quote(namespace, safe="")}/configmaps/{quote(name, safe="")}'
            if url not in cache:
                cache[url] = reader.call(api.get_json, url)
            document = cache[url]
            meta = document.get('metadata', {}) if isinstance(document, dict) else {}
            if (document.get('kind') != 'ConfigMap' or document.get('apiVersion') != 'v1'
                    or meta.get('name') != name or meta.get('namespace') != namespace
                    or not isinstance(meta.get('uid'), str) or not meta['uid']
                    or not isinstance(meta.get('resourceVersion'), str) or not meta['resourceVersion']
                    or document.get('immutable') is not True):
                raise AdmissionFileUnavailable('admission_configmap_identity_or_immutability_unverified')
            # A replacement ConfigMap created after this Pod cannot prove the
            # object mounted at Pod startup. Mutable ConfigMaps may have changed
            # after the admission plugin loaded, so those remain unavailable.
            pod_created = _timestamp(pod['metadata'].get('creationTimestamp'))
            if _timestamp(meta.get('creationTimestamp')) > pod_created:
                raise AdmissionFileUnavailable('admission_configmap_recreated_after_pod')
            # Immutability can itself be enabled after creation. Require the
            # API server's field ownership timestamps for the selected value
            # and immutable flag to predate Pod creation as well.
            managed = meta.get('managedFields')
            if not isinstance(managed, list) or not managed:
                raise AdmissionFileUnavailable('admission_configmap_field_history_unavailable')
            covered = set()
            for owner in managed:
                if not isinstance(owner, dict) or owner.get('fieldsType') != 'FieldsV1':
                    raise AdmissionFileUnavailable('admission_configmap_field_history_malformed')
                fields = owner.get('fieldsV1')
                if not isinstance(fields, dict):
                    raise AdmissionFileUnavailable('admission_configmap_field_history_malformed')
                selected = []
                if 'f:immutable' in fields:
                    selected.append('immutable')
                if isinstance(fields.get('f:data'), dict) and 'f:' + key in fields['f:data']:
                    selected.append('data')
                if selected:
                    if owner.get('subresource') or _timestamp(owner.get('time')) > pod_created:
                        raise AdmissionFileUnavailable('admission_configmap_changed_after_pod')
                    covered.update(selected)
            if covered != {'immutable', 'data'}:
                raise AdmissionFileUnavailable('admission_configmap_field_history_unavailable')
            data = document.get('data')
            if not isinstance(data, dict) or key not in data:
                raise AdmissionFileUnavailable('admission_configmap_data_key_missing')
            plugins = _plugins(data[key])
            output.append({'id': pod['id'] + '/admission-file/' + quote(path, safe=''),
                'pod_uid': pod['metadata']['uid'], 'path': path,
                'verification_status': 'verified', 'plugins': plugins,
                'provenance': {'cluster_id': cluster, 'evidence': 'read-only GET immutable ConfigMap bound to Pod volume',
                    'source_operation': 'GET /api/v1/namespaces/{namespace}/configmaps/{name}',
                    'configmap_uid': meta['uid'], 'configmap_resource_version': meta['resourceVersion'],
                    'configmap_key': key, 'normalization': 'ImagePolicyWebhook.configuration.imagePolicy',
                    'runtime_verified': False, 'credential_material': 'omitted'}})
    yield output
