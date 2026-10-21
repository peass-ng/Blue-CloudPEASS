"""Bound selected App Engine Flex version image secret and vulnerability consumers."""
from copy import deepcopy
import hashlib
import json

from peaso import gcp_appengine_flex_image_selection_20261021 as selection
from peaso.collectors import gcp_appengine_flex_image_native_20261021 as source
from peaso.collectors import gcp_appengine_flex_image_runtime_20261021 as runtime
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION


def unknown(reason='The selected Flex version image lacks a complete native identity or image read.'):
    return 'UNKNOWN', {'observed': reason + '', 'complete': False}


def evaluate(item, index, kind):
    try:
        context = index['context']; scope = context['scope']; meta = context['metadata']
        if context['provider'] != 'gcp' or meta[kind + '_authorized'] is not True:
            return unknown()
        targets = selection.selected({selection.OPTION: meta[selection.OPTION]}, [scope])
        marker = item[runtime.MARKER]; row = marker['row']; target = row['selection']
        if target not in targets or marker['scope'] != scope or marker['runtime_image_proven'] is not False:
            return unknown()
        rid = source.identity(target)
        if any(item.get(key) != rid for key in ('name', 'native_id', '_resource_id')):
            return unknown()
        collection, = [c for c in index['collections'][kind] if c.get('scope') == scope and item in c.get('items', [])]
        if collection['status'] not in ('collected', 'partial'):
            return unknown()
        ids = row['source_requests']; ledger = {r['id']: r for r in meta['source_requests']}
        if (type(ids) is not list or len(ids) != len(set(ids)) or not ids
                or not set(ids) <= set(ledger) or set(ids) != set(item['_provenance']['source_requests'])
                or not set(ids) <= set(collection['source_requests'])):
            return unknown()
        version_refs = row['version_source_requests']
        url = 'https://appengine.googleapis.com/v1/' + target['version_name']
        if len(version_refs) != 2 or len(set(version_refs)) != 2:
            return unknown('The selected Flex version has no matching before and after GET records.')
        for ref in version_refs:
            r = ledger[ref]
            if (r.get('scope') != scope or r.get('method') != 'GET' or r.get('url') != url
                    or r.get('query') != {'view': 'FULL', 'fields': source.VERSION_FIELDS}
                    or r.get('operation') != 'appengine_flex_selected_version_get'
                    or r.get('status') != 'collected' or r.get('http_status') != 200):
                return unknown('The selected Flex version full view was not recorded twice.')
        captures = row['metadata_captures']; expected = source.requests_for(target, scope) * 2
        if len(captures) != 6 or not row['association_revalidated']:
            return unknown('The selected Flex version image owners were not revalidated.')
        metadata_receipts = [ledger[r] for r in ids
            if ledger[r].get('operation') == 'cloudrun_worker_pool_selected_image_metadata_get']
        if len(metadata_receipts) != 6:
            return unknown('The selected Flex version image owner GET records are incomplete.')
        bodies = []
        for capture, receipt, (expected_url, fields) in zip(captures, metadata_receipts, expected):
            if capture.get('url') != expected_url or capture.get('fields') != fields:
                return unknown()
            body = capture.get('body')
            if hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest() != capture.get('body_sha256'):
                return unknown()
            if (receipt.get('url') != expected_url or receipt.get('scope') != scope
                    or receipt.get('method') != 'GET' or receipt.get('query') != {'fields': fields}
                    or receipt.get('status') != 'collected' or receipt.get('http_status') != 200
                    or receipt.get('body_sha256') != capture['body_sha256']):
                return unknown()
            bodies.append(body)
        if bodies[:3] != bodies[3:] or source.bind_registry(target, scope, bodies[:3]) != source.bind_registry(target, scope, bodies[3:]):
            return unknown('The selected Flex version registry owner changed during the read.')
        if row['declaration']['name'] != target['version_name'] or row['declaration']['immutable_reference'] != target['immutable_reference']:
            return unknown()
        uri, repo, digest, _ = source.image.parse_image_uri(target['immutable_reference'])
        if kind == selection.SECRET_KIND:
            content = row['content']; leaks = merge_leaks(content.get('leaks', []))
            if leaks != content.get('leaks') or any('raw' in leak or 'value' in leak for leak in leaks):
                return unknown()
            registry = [ledger[r] for r in row['secret_image_source_requests']]
            if (not registry or registry[0].get('category') != 'manifests' or registry[0].get('digest') != digest
                    or registry[0].get('status') != 'collected' or content.get('uri') != uri
                    or content.get('manifest_digest') != digest):
                return unknown('The selected Flex version OCI manifest was not verified.')
            if any(r.get('operation') != 'artifactregistry.registry_content_get' or r.get('scope') != scope
                   or r.get('method') != 'GET' or r.get('category') not in ('manifests', 'blobs')
                   for r in registry):
                return unknown()
            if 'graph' in content:
                from .gcp_image_stream_review_20261021 import evaluate_index_content
                status, evidence = evaluate_index_content(content, uri, repo, digest, scope,
                    receipts=registry)
                if status == 'UNKNOWN' or status != row['status']:
                    return unknown('The selected Flex version image index has incomplete child content.')
                return status, {**evidence, 'runtime_image_proven': False,
                    'source_requests': ids[:]}
            versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
            engines = content.get('engines')
            if type(engines) is not list or {e.get('engine') for e in engines} != set(versions) or any(e.get('version') != versions[e['engine']] for e in engines):
                return unknown('The selected Flex version image lacks both detector records.')
            if content.get('complete') is True and (any(e.get('status') != 'complete' for e in engines)
                    or any(r.get('status') != 'collected' or r.get('http_status') != 200 for r in registry)):
                return unknown('The selected Flex version image bytes or detector coverage were incomplete.')
            status = 'FAIL' if leaks else 'PASS' if content.get('complete') is True else 'UNKNOWN'
            if status == 'UNKNOWN':
                return unknown('The selected Flex version image bytes or detector coverage were incomplete.')
            observed = ('A likely secret was found in the immutable image declared by this App Engine Flex version. Its value is hidden.' if status == 'FAIL' else
                'Both detectors found no supported secret in the inspected image declared by this App Engine Flex version.')
            return status, {'observed': observed, 'complete': status == 'PASS', 'secret_leaks': deepcopy(leaks),
                            'runtime_image_proven': False, 'source_requests': ids[:]}
        vuln = row['vulnerability']
        if type(vuln) is not dict or type(vuln.get('record')) is not dict:
            return unknown('The selected Flex version image has no fresh package scan record.')
        from . import gcp_registry_trivy_review_20261021 as review
        record = vuln['record']
        if record.get('selection') != target['immutable_reference'] or not set(record.get('source_requests', [])) <= set(ids):
            return unknown()
        status, evidence = review.evaluate(record, {'scope': scope,
            'selections': [target['immutable_reference']], 'source_requests': vuln['source_ledger']})
        if status == 'UNKNOWN':
            return unknown('The selected Flex version image lacks a fresh complete package result.')
        observed = ('The immutable image declared by this App Engine Flex version contains HIGH or CRITICAL package vulnerabilities.' if status == 'FAIL' else
            'Trivy found no HIGH or CRITICAL package vulnerabilities in the selected App Engine Flex image using a fresh database.')
        return status, {**deepcopy(evidence), 'observed': observed, 'runtime_image_proven': False}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return unknown()


def install():
    from . import register
    from .fixtures import CASES
    from pathlib import Path
    cases = json.loads(Path(__file__).with_name('gcp_appengine_flex_image_review_20261021_cases.json').read_text())
    if set(cases) != {selection.SECRET_CHECK, selection.VULN_CHECK} or set(cases) & set(CASES):
        raise RuntimeError('selected Flex image native case collision or absence')
    CASES.update(cases)
    register(selection.SECRET_CHECK, 'gcp', 'exposure', selection.SECRET_KIND,
        'Selected App Engine Flex version image has no detected secrets', 'high', 'security_configuration',
        'Review the selected immutable image and remove confirmed credential values.',
        dependencies=[selection.SECRET_KIND], allow_incomplete_failure=True)(
        lambda item, index: evaluate(item, index, selection.SECRET_KIND))
    register(selection.VULN_CHECK, 'gcp', 'hardening', selection.VULN_KIND,
        'Selected App Engine Flex version image has no HIGH or CRITICAL package vulnerabilities',
        'high', 'security_configuration', 'Rebuild the selected image with updated packages.',
        dependencies=[selection.VULN_KIND], allow_incomplete_failure=True)(
        lambda item, index: evaluate(item, index, selection.VULN_KIND))
