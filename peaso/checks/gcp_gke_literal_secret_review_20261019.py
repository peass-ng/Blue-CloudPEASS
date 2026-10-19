"""Pure predicate with explicit registration for returned supported GKE workload literals."""
from copy import deepcopy
from types import SimpleNamespace
from uuid import UUID
import re
from .facts import get, Unavailable
from peaso.collectors.gcp_gke_literal_secret_indicators import (
    KIND, SCHEMA, MARKER, SELECTION, DNS_LABEL, DNS_NAME, MAX_NAMESPACES, MAX_CONTAINERS, MAX_ROW_BYTES, PAGE_SIZE,
    cluster_binding,
)
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID = 'gcp.review.gke_workload.literal_configuration_secret_indicators'
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'dependencies': [KIND, 'gke_cluster'], 'requirements': [],
    'title': 'Returned GKE workload literals have no detected secrets',
    'remediation': 'Remove credential literals from ConfigMaps and Pod environment values, commands and arguments, and rotate confirmed exposed credentials. Prefer workload identity and authorized runtime secret retrieval, or managed secret references, instead of embedding credentials.',
    'evidence_sentences': ['A likely secret was detected in the returned GKE workload configuration.',
                           'The value is hidden; offline detection did not validate the credential.']}


def evaluate(item, index):
    try:
        scope = get(index, 'context.scope', str)
        if get(index, 'context.provider', str) != 'gcp':
            raise Unavailable('provider')
        cluster = get(item, 'cluster', str)
        match = SELECTION.fullmatch(cluster)
        namespace = get(item, 'namespace', str)
        if not match or 'projects/' + match[1] != scope or not DNS_LABEL.fullmatch(namespace):
            raise Unavailable('subject')
        plan = get(index, 'context.metadata.gke_literal_selection', dict)
        if plan.get('status') != 'authorized' or cluster not in get(plan, 'clusters', list):
            raise Unavailable('selection')
        envelopes = get(index, 'collections.' + KIND, list)
        matching = [c for c in envelopes if isinstance(c, dict) and c.get('scope') == scope]
        name = get(item, 'name', str)
        if (len(matching) != 1 or matching[0].get('status') != 'collected' or not isinstance(matching[0].get('items'), list)
                or sum(isinstance(row, dict) and row.get('name') == name for row in matching[0]['items']) != 1
                or item not in matching[0]['items']):
            raise Unavailable('workload collection')
        clusters = [c for c in get(index, 'collections.gke_cluster', list) if isinstance(c, dict) and c.get('scope') == scope]
        if len(clusters) != 1:
            raise Unavailable('cluster collection')
        receipts = get(index, 'context.metadata.source_requests', list)
        try:
            bound = cluster_binding(SimpleNamespace(collections={('gke_cluster', scope): clusters[0]},
                transport=SimpleNamespace(evidence=receipts)), scope, cluster)
        except Exception:
            raise Unavailable('native cluster binding') from None
        if item.get('clusterEndpoint') != bound['endpoint'] or item.get('clusterCaSha256') != bound['ca_sha256']:
            raise Unavailable('cluster endpoint/CA')
        native_kind = get(item, 'nativeKind', str)
        if native_kind not in ('ConfigMap', 'Pod'):
            raise Unavailable('kind')
        suffix = '/configmaps/' if native_kind == 'ConfigMap' else '/pods/'
        native_name = get(item, 'kubernetesName', str)
        uid = get(item, 'uid', str)
        resource_version = get(item, 'resourceVersion', str)
        if (not DNS_NAME.fullmatch(native_name) or name != cluster + '/namespaces/' + namespace + suffix + native_name
                or str(UUID(uid)) != uid or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', resource_version)):
            raise Unavailable('identity')
        refs = get(item, '_provenance.source_requests', list)
        if get(item, '_provenance.scope', str) != scope or not refs:
            raise Unavailable('request provenance')
        by_id = {r.get('id'): r for r in receipts if isinstance(r, dict)}
        if len(by_id) != len(receipts):
            raise Unavailable('ambiguous receipt identities')
        collection_refs = get(matching[0], 'source_requests', list)
        if not collection_refs or not set(refs) <= set(collection_refs):
            raise Unavailable('incomplete collection receipts')
        for ref in collection_refs:
            receipt = by_id.get(ref)
            if (not isinstance(receipt, dict) or receipt.get('scope') not in plan['clusters']
                    or receipt.get('method') != 'GET' or receipt.get('operation') != 'gke-literal-list'
                    or receipt.get('status') != 'collected' or receipt.get('http_status') != 200
                    or receipt.get('query') != {'limit': PAGE_SIZE}):
                raise Unavailable('incomplete selected workload reads')
        expected_url = 'https://' + bound['endpoint'] + '/api/v1/namespaces/' + namespace + ('/configmaps' if native_kind == 'ConfigMap' else '/pods')
        for ref in refs:
            receipt = by_id.get(ref)
            if (not isinstance(receipt, dict) or receipt.get('scope') != cluster or receipt.get('method') != 'GET'
                    or receipt.get('status') != 'collected' or receipt.get('http_status') != 200 or receipt.get('url') != expected_url):
                raise Unavailable('native workload source')
        approval = get(item, 'namespaceAuthorization', dict)
        names = get(approval, 'names', list)
        if (not 1 <= len(names) <= MAX_NAMESPACES or len(names) != len(set(names)) or namespace not in names
                or any(not isinstance(n, str) or not DNS_LABEL.fullmatch(n) for n in names)):
            raise Unavailable('namespace bounds')
        if plan.get('namespaces') is not None:
            if (not isinstance(plan['namespaces'], dict) or approval.get('mode') != 'explicit'
                    or plan['namespaces'].get(cluster) != names or approval.get('source_requests') != []):
                raise Unavailable('explicit namespace')
        else:
            ns_refs = get(approval, 'source_requests', list)
            if approval.get('mode') != 'discovered' or not ns_refs:
                raise Unavailable('namespace discovery')
            for ref in ns_refs:
                row = by_id.get(ref)
                if (not isinstance(row, dict) or row.get('scope') != cluster or row.get('method') != 'GET'
                        or row.get('status') != 'collected' or row.get('http_status') != 200
                        or row.get('url') != 'https://' + bound['endpoint'] + '/api/v1/namespaces'):
                    raise Unavailable('namespace discovery receipt')
        marker = get(item, MARKER, dict)
        if (set(marker) != {'schema', 'complete', 'surfaces', 'leaks', 'verification'} or marker['schema'] != SCHEMA
                or marker['complete'] is not True or marker['verification'] != 'not_attempted'):
            raise Unavailable('scan')
        if native_kind == 'ConfigMap':
            expected = ['data', 'binaryData']
            if item.get('containerNames') != [] or item.get('references') != []:
                raise Unavailable('ConfigMap projection')
        else:
            containers = get(item, 'containerNames', list)
            if not 1 <= len(containers) <= MAX_CONTAINERS * 3:
                raise Unavailable('container coverage')
            expected = []
            seen, counts = set(), {'containers': 0, 'initContainers': 0, 'ephemeralContainers': 0}
            for container in containers:
                if not isinstance(container, dict) or set(container) != {'path', 'name'}:
                    raise Unavailable('container')
                parts = container['path'].split('/')
                if (len(parts) != 2 or parts[0] not in counts or not DNS_LABEL.fullmatch(container['name'])
                        or container['name'] in seen):
                    raise Unavailable('container identity')
                seen.add(container['name'])
                counts[parts[0]] += 1
                if parts[1] != str(counts[parts[0]]) or counts[parts[0]] > MAX_CONTAINERS:
                    raise Unavailable('container ordinal')
                expected.extend(container['path'] + '/' + surface for surface in ('env', 'args', 'command'))
            if counts['containers'] == 0:
                raise Unavailable('missing main containers')
        surfaces = get(marker, 'surfaces', list)
        if [s.get('path') for s in surfaces if isinstance(s, dict)] != expected:
            raise Unavailable('surface coverage')
        engines = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        total = 0
        for surface in surfaces:
            if (set(surface) != {'path', 'bytes', 'complete', 'engines'} or surface['complete'] is not True
                    or type(surface['bytes']) is not int or not 0 <= surface['bytes'] <= MAX_ROW_BYTES
                    or not isinstance(surface['engines'], list) or len(surface['engines']) != 2):
                raise Unavailable('coverage')
            total += surface['bytes']
            pair = surface['engines']
            if (any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                    or e.get('version') != engines.get(e.get('engine')) or e.get('status') != 'complete' for e in pair)
                    or {e['engine'] for e in pair} != set(engines)):
                raise Unavailable('pinned pair')
        if total > MAX_ROW_BYTES or not isinstance(marker['leaks'], list) or len(marker['leaks']) > 256:
            raise Unavailable('bounds')
        leaks = merge_leaks(marker['leaks'])
        if sum(len(row['locations']) for row in leaks) > 512:
            raise Unavailable('location bound')
        for leak in leaks:
            if any(set(loc) - {'path', 'line'} or loc['path'] not in expected for loc in leak['locations']):
                raise Unavailable('location')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
            'native_subject': name, 'cluster': cluster, 'namespace': namespace, 'kubernetes_name': native_name,
            'uid': uid, 'resource_version': resource_version,
            'surfaces': deepcopy(surfaces), 'references': deepcopy(get(item, 'references', list))}
        if leaks:
            return 'FAIL', {**evidence, 'observed': ' '.join(DECLARATION['evidence_sentences'])}
        return 'PASS', {**evidence, 'observed': 'Both offline detectors found no supported secret in the returned supported workload configuration. Other workloads, runtime values and managed secret values were not assessed.'}
    except (Unavailable, ValueError, KeyError, TypeError, AttributeError):
        return 'UNKNOWN', {'observed': 'Workload literal inspection is disabled, denied, incomplete or lacks proven cluster authority; secret absence could not be assessed.'}


def install():
    """Register only when called by the root-owned registry admission hook."""
    import gzip
    import json
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK_ID for c in CHECKS):
        return
    fixtures = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_gke_literal_secret_fixtures.json.gz').read_bytes()))
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high',
             'security_configuration', DECLARATION['remediation'],
             dependencies=DECLARATION['dependencies'])(evaluate)
    CASES[CHECK_ID] = deepcopy(fixtures[CHECK_ID])
