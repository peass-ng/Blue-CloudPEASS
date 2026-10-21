"""Bound selected GKE image consumers for Secrets and Vulnerabilities."""
from copy import deepcopy
import re

from peaso import gcp_gke_image_selection_20261021 as selection
from peaso.collectors import gcp_gke_selected_pod_image_20261021 as source


def evaluate(item, index, kind):
    marker = item.get('SelectedGkePodImage', {}) if type(item) is dict else {}
    reason = marker.get('reason') if type(marker) is dict else None
    native = marker.get('image') if type(marker) is dict else None
    if type(native) is dict and native.get('reason') not in (None, 'complete'):
        reason = native.get('reason')
    missing = {
        'gke_cluster_identity_unavailable': 'The selected GKE cluster identity was not recorded.',
        'gke_endpoint_or_ca_unavailable': 'The selected GKE cluster endpoint or CA was not recorded.',
        'explicit_kubernetes_context_required': 'The selected GKE cluster has no authorized Kubernetes bearer context.',
        'gke_endpoint_or_ca_changed': 'The selected GKE cluster endpoint or CA changed during the read.',
        'kubernetes_cluster_uid_unavailable': 'The selected Kubernetes cluster namespace UID was not recorded.',
        'kubernetes_cluster_uid_changed': 'The selected Kubernetes cluster namespace UID changed during the read.',
        'gke_cluster_changed': 'The selected GKE cluster identity changed during the read.',
        'pod_image_binding': 'The selected Pod image ID did not match its immutable digest.',
        'pod_image_changed': 'The selected Pod image identity changed during the read.',
        'file_truncated': 'The selected Pod image file bytes were truncated.',
        'registry_not_allowlisted': 'The selected Pod image registry is outside the recorded allowlist.',
    }.get(reason, 'The selected Pod image bytes or their native identity were not fully recorded.')
    unknown = ('UNKNOWN', {'complete': False, 'observed':
        missing + ''})
    try:
        ctx = index['context']; meta = ctx['metadata']; scope = ctx['scope']
        if ctx['provider'] != 'gcp' or meta[kind + '_authorized'] is not True:
            return unknown
        targets = meta[selection.OPTION]
        target, = [t for t in targets if source.identity(t) == item['id']]
        if target['cluster_id'].split('/locations/')[0] != scope:
            return unknown
        collection, = [c for c in index['collections'][kind]
                       if c.get('scope') == scope and item in c.get('items', [])]
        if collection.get('status') not in ('collected', 'partial'):
            return unknown
        marker = item['SelectedGkePodImage']
        before = marker.get('gke_before')
        if (marker.get('schema') != source.SCHEMA or marker.get('identity') != item['id']
                or type(before) is not dict or before != marker.get('gke_after')
                or before.get('name') != target['cluster_id']
                or not isinstance(before.get('cluster_id'), str) or not before['cluster_id']
                or not re.fullmatch('[0-9a-f]{64}', str(before.get('ca_sha256')))
                or not re.fullmatch('[0-9a-f]{64}', str(marker.get('cluster_uid')))):
            return unknown
        refs = marker.get('gke_source_requests')
        if type(refs) is not list or len(refs) != 2 or len(set(refs)) != 2 or not set(refs) <= set(collection.get('source_requests', [])):
            return unknown
        receipts = meta.get('source_requests', [])
        url = 'https://container.googleapis.com/v1/' + target['cluster_id']
        for ref in refs:
            found = [r for r in receipts if type(r) is dict and r.get('id') == ref]
            if (len(found) != 1 or found[0].get('scope') != scope
                    or found[0].get('method') != 'GET' or found[0].get('url') != url
                    or found[0].get('operation') != 'gke-selected-image-cluster-get'
                    or found[0].get('query') != {} or found[0].get('status') != 'collected'
                    or found[0].get('http_status') != 200):
                return unknown
        native = marker.get('image')
        if (type(native) is not dict or native.get('identity') != source.image.identity(target)
                or native.get('manifest_digest') != target['image'].rsplit('@', 1)[1]
                or native.get('native_before') != native.get('native_after')
                or native.get('native_before', {}).get('uid') != target['uid']
                or native.get('native_before', {}).get('resource_version') != target['resource_version']
                or native.get('status_image_id') != target['image']):
            return unknown
        from . import k8s_selected_registry_image_review_20261021 as k8s_review
        k8s_kind = source.image.SECRET_KIND if kind == source.SECRET_KIND else source.image.VULN_KIND
        k8s_item = {'id': source.image.identity(target), 'name': source.image.identity(target),
                    'SelectedRegistryImage': native}
        k8s_index = {'context': {'provider': 'k8s', 'scope': target['namespace'],
                     'metadata': {k8s_kind + '_authorized': True, source.image.OPTION: [target]}},
                     'collections': {k8s_kind: [{'scope': target['namespace'],
                         'status': collection['status'], 'items': [k8s_item]}]}}
        result, evidence = k8s_review.evaluate(k8s_item, k8s_index, k8s_kind)
        if result == 'UNKNOWN':
            return unknown
        if kind == source.SECRET_KIND:
            observed = ('A likely secret was found in the verified image reported by the selected GKE Pod. Its value is hidden.' if result == 'FAIL' else
                        'Both detectors found no supported secret in the verified image reported by the selected GKE Pod.')
        else:
            observed = ('The verified image reported by the selected GKE Pod contains HIGH or CRITICAL package vulnerabilities.' if result == 'FAIL' else
                        'Trivy found no HIGH or CRITICAL package vulnerabilities in the selected GKE Pod image using a fresh database.')
        return result, {**deepcopy(evidence), 'observed': observed}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return unknown


def install():
    import json
    from pathlib import Path
    from .fixtures import CASES
    from . import register
    native_cases = json.loads(Path(__file__).with_name('gcp_gke_selected_pod_image_review_20261021_cases.json').read_text())
    if set(native_cases) != {selection.SECRET_CHECK, selection.VULN_CHECK} or any(key in CASES for key in native_cases):
        raise RuntimeError('GKE selected image native fixture collision or absence')
    CASES.update(native_cases)
    register(selection.SECRET_CHECK, 'gcp', 'exposure', source.SECRET_KIND,
             'Selected GKE Pod image has no detected secrets', 'high', 'security_configuration',
             'Review the selected immutable image and remove confirmed credential values.',
             dependencies=[source.SECRET_KIND], allow_incomplete_failure=True)(
             lambda item, index: evaluate(item, index, source.SECRET_KIND))
    register(selection.VULN_CHECK, 'gcp', 'hardening', source.VULN_KIND,
             'Selected GKE Pod image has no HIGH or CRITICAL package vulnerabilities',
             'high', 'security_configuration',
             'Review the selected immutable image and rebuild a digest with updated packages.',
             dependencies=[source.VULN_KIND], allow_incomplete_failure=True)(
             lambda item, index: evaluate(item, index, source.VULN_KIND))
