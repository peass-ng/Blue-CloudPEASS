"""Exact selected AKS Pod image projection; Arc remains an unavailable capability."""
from copy import deepcopy
import re

from peaso.collectors import azure_selected_aks_image_20261021 as source
from peaso.secret_scanning import merge_leaks


def evaluate(item, index):
    unknown = ('UNKNOWN', {'complete': False, 'observed':
        'The selected Pod lacks a verified cluster, Pod, or image binding.\n'
        'The image contents are therefore unclear.\n'
        'A usable credential in that image could expose data to someone who can read it.'})
    try:
        ctx = index['context']; meta = ctx['metadata']; scope = ctx['scope']
        if ctx['provider'] != 'azure' or meta[source.KIND + '_authorized'] is not True:
            return unknown
        target, = [t for t in meta[source.OPTION] if source.identity(t) == item['id']]
        if target['cluster_id'].casefold().split('/resourcegroups/')[0] != scope.casefold():
            return unknown
        collection, = [c for c in index['collections'][source.KIND]
                       if c.get('scope') == scope and item in c.get('items', [])]
        if collection.get('status') not in ('collected', 'partial'):
            return unknown
        marker = item['SelectedAksImage']
        if (marker.get('schema') != source.SCHEMA or marker.get('identity') != item['id']
                or marker.get('arm_before') != marker.get('arm_after')
                or marker.get('arm_before', {}).get('id') != target['cluster_id'].casefold()
                or not re.fullmatch('[0-9a-f]{64}', str(marker.get('cluster_uid')))):
            return unknown
        native = marker.get('image')
        if (type(native) is not dict or native.get('schema') != source.image.SCHEMA
                or native.get('identity') != source.image.identity(target)
                or native.get('manifest_digest') != target['image'].rsplit('@', 1)[1]
                or native.get('native_before') != native.get('native_after')
                or native.get('native_before', {}).get('uid') != target['uid']
                or native.get('native_before', {}).get('resource_version') != target['resource_version']
                or native.get('status_image_id') != target['image']):
            return unknown
        receipts = native.get('registry_receipts')
        if (type(receipts) is not list or len(receipts) < 3
                or receipts[0].get('category') != 'manifests'
                or receipts[0].get('digest') != native['manifest_digest']
                or any(type(r) is not dict or r.get('status') != 'collected'
                       or r.get('method') != 'GET' for r in receipts)):
            return unknown
        leaks = native.get('leaks')
        if (type(leaks) is not list or len(leaks) > 256 or merge_leaks(leaks) != leaks
                or any(not re.fullmatch('[0-9a-f]{64}', str(l.get('fingerprint')))
                       or not l.get('locations') or not l.get('detectors') for l in leaks)):
            return unknown
        parts = native.get('parts')
        complete_engines = {(p.get('part'), e.get('engine')) for p in parts if type(p) is dict
                            for e in p.get('engines', []) if type(e) is dict and e.get('status') == 'complete'}
        if any((loc.get('path'), detector.get('engine')) not in complete_engines
               for leak in leaks for loc in leak['locations'] for detector in leak['detectors']):
            return unknown
        from . import k8s_selected_registry_image_review_20261021 as k8s_review
        k8s_item = {'id': source.image.identity(target), 'name': source.image.identity(target),
                    'SelectedRegistryImage': native}
        k8s_index = {'context': {'provider': 'k8s', 'scope': target['namespace'],
                     'metadata': {source.image.SECRET_KIND + '_authorized': True, source.image.OPTION: [target]}},
                     'collections': {source.image.SECRET_KIND: [{'scope': target['namespace'],
                         'status': collection['status'], 'items': [k8s_item]}]}}
        trusted, _ = k8s_review.evaluate(k8s_item, k8s_index, source.image.SECRET_KIND)
        if trusted == 'UNKNOWN':
            return unknown
        if leaks:
            if trusted != 'FAIL':
                return unknown
            return 'FAIL', {'complete': marker['complete'], 'secret_leaks': deepcopy(leaks), 'observed':
                'The selected AKS Pod reported an immutable image containing a likely secret.\n'
                'Someone who can read that image may see the value.\n'
                'That could expose credentials or data if the value is usable.'}
        if (trusted == 'PASS' and marker.get('complete') is True and native.get('status') == 'PASS'
                and all(p.get('complete') is True and {e.get('engine') for e in p.get('engines', [])} == {'kingfisher', 'trufflehog'}
                        for p in parts)):
            return 'PASS', {'complete': True, 'observed':
                'The selected AKS Pod reported an immutable image with no recorded secret indicator.\n'
                'Its inspected contents may be less likely to expose a credential.\n'
                'A different image used later could still expose people or their data.'}
        return unknown
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return unknown


def evaluate_vulnerability(item, index):
    unknown = ('UNKNOWN', {'complete': False, 'observed':
        'The selected Pod image lacks a complete package vulnerability record.\n'
        'Its HIGH and CRITICAL package exposure remains unclear.\n'
        'A vulnerable package could affect people or their data if reachable.'})
    try:
        ctx = index['context']; meta = ctx['metadata']; scope = ctx['scope']
        if ctx['provider'] != 'azure' or meta[source.VULN_KIND + '_authorized'] is not True:
            return unknown
        target, = [t for t in meta[source.OPTION] if source.identity(t) == item['id']]
        collection, = [c for c in index['collections'][source.VULN_KIND]
                       if c.get('scope') == scope and item in c.get('items', [])]
        marker = item['SelectedAksImage']; native = marker['image']
        if (target['cluster_id'].casefold().split('/resourcegroups/')[0] != scope.casefold()
                or marker.get('arm_before') != marker.get('arm_after')
                or marker.get('arm_before', {}).get('id') != target['cluster_id'].casefold()
                or not re.fullmatch('[0-9a-f]{64}', str(marker.get('cluster_uid')))
                or native.get('identity') != source.image.identity(target)
                or native.get('manifest_digest') != target['image'].rsplit('@', 1)[1]
                or native.get('native_before') != native.get('native_after')
                or native.get('native_before', {}).get('uid') != target['uid']
                or native.get('native_before', {}).get('resource_version') != target['resource_version']
                or native.get('status_image_id') != target['image']
                or collection.get('status') not in ('collected', 'partial')):
            return unknown
        from . import k8s_selected_registry_image_review_20261021 as k8s_review
        k8s_item = {'id': source.image.identity(target), 'name': source.image.identity(target),
                    'SelectedRegistryImage': native}
        k8s_index = {'context': {'provider': 'k8s', 'scope': target['namespace'],
                     'metadata': {source.image.VULN_KIND + '_authorized': True, source.image.OPTION: [target]}},
                     'collections': {source.image.VULN_KIND: [{'scope': target['namespace'],
                         'status': collection['status'], 'items': [k8s_item]}]}}
        result, evidence = k8s_review.evaluate(k8s_item, k8s_index, source.image.VULN_KIND)
        if result == 'UNKNOWN':
            return unknown
        observed = ('The selected AKS Pod image contains a HIGH or CRITICAL package vulnerability.\n'
                    'That package may allow an attacker to affect the workload if the vulnerable path is reachable.\n'
                    'People or their data could be harmed if that happens.'
                    if result == 'FAIL' else
                    'The selected AKS Pod image has no recorded HIGH or CRITICAL package vulnerability.\n'
                    'Its inspected packages may present less known vulnerability exposure.\n'
                    'A different image used later could still affect people or their data.')
        return result, {**evidence, 'observed': observed}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return unknown


def install():
    from . import register
    from .fixtures import CASES
    from pathlib import Path
    import json
    native_cases=json.loads(Path(__file__).with_name('azure_selected_aks_image_review_20261021_cases.json').read_text())
    if set(native_cases)!={source.CHECK,source.VULN_CHECK} or set(native_cases)&set(CASES):
        raise RuntimeError('Selected AKS image native fixture collision or absence')
    CASES.update(native_cases)
    register(source.CHECK, 'azure', 'exposure', source.KIND,
             'Selected AKS Pod image has no detected secrets', 'high', 'security_configuration',
             'Review the selected immutable image and remove confirmed credential values.',
             dependencies=[source.KIND], allow_incomplete_failure=True)(evaluate)
    register(source.VULN_CHECK, 'azure', 'hardening', source.VULN_KIND,
             'Selected AKS Pod image has no HIGH or CRITICAL package vulnerabilities',
             'high', 'security_configuration',
             'Review the selected immutable image and rebuild a digest with updated packages.',
             dependencies=[source.VULN_KIND], allow_incomplete_failure=True)(evaluate_vulnerability)
