"""Project complete native ACL inventories onto the signed per-bucket fact contract.

Only completed same-scope list traversals can certify absence. Private identities are
already hashed by the native ACL producer; this bridge never reads object content.
"""
from __future__ import annotations

import re

_PUBLIC = frozenset({'allUsers', 'allAuthenticatedUsers'})
_HASH = re.compile(r'sha256:[0-9a-f]{64}\Z')
_OBJECT_REF = re.compile(r'[0-9a-f]{64}\Z')
_GENERATION = re.compile(r'[0-9]{1,20}\Z')


def _guard(value):
    if not isinstance(value, dict):
        return False
    if 'collection_status' in value and value['collection_status'] not in ('collected', 'empty'):
        return False
    coverage = value.get('_coverage', {})
    if not isinstance(coverage, dict):
        return False
    marker = coverage.get('collection_status')
    if 'collection_status' in coverage and (not isinstance(marker, dict)
            or marker.get('status') not in ('collected', 'empty')
            or ('collection_status' in value) != (marker['status'] == 'collected')):
        return False
    return True


def _readable(value, path):
    for part in path.split('.'):
        if not _guard(value) or part not in value:
            return False
        coverage = value.get('_coverage', {})
        if part in coverage:
            marker = coverage[part]
            if (not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty')
                    or marker['status'] == 'empty' and value[part] not in (None, '', [], {})):
                return False
        value = value[part]
    return not isinstance(value, dict) or _guard(value)


def _complete(collection, scope, kind):
    if (not _guard(collection) or collection.get('type') != kind
            or collection.get('scope') != scope or collection.get('error')):
        return False
    status = collection.get('status')
    rows = collection.get('items')
    return (status in ('collected', 'empty') and collection.get('coverage_status') == status
            and isinstance(rows, list) and bool(rows) == (status == 'collected')
            and isinstance(collection.get('source_requests'), list)
            and all(isinstance(x, str) and x for x in collection['source_requests']))


def _unique_names(rows):
    names = [row.get('name') for row in rows if _readable(row, 'name')]
    return len(names) == len(rows) and all(isinstance(n, str) and n for n in names) and len(set(names)) == len(names)


def _proof(collection, names, nonuniform, parent_requests):
    if collection.get('parent_inventory') != 'bucket':
        return None
    # Lists are not compared by order: the parent API order is not a coverage fact.
    covered, disabled = collection.get('covered_parent_ids'), collection.get('acl_disabled_parent_ids')
    if not isinstance(covered, list) or not isinstance(disabled, list):
        return None
    if (len(covered) != len(names) or set(covered) != names
            or len(disabled) != len(names - nonuniform) or set(disabled) != names - nonuniform):
        return None
    proof = collection.get('per_parent_coverage')
    if not isinstance(proof, dict) or set(proof) != nonuniform:
        return None
    all_requests = set(collection['source_requests'])
    page_requests = set()
    for name, value in proof.items():
        if (not isinstance(value, dict) or value.get('all_pages') is not True
                or type(value.get('page_count')) is not int or value['page_count'] < 1
                or not isinstance(value.get('source_requests'), list)
                or len(value['source_requests']) != value['page_count']
                or len(set(value['source_requests'])) != len(value['source_requests'])
                or page_requests.intersection(value['source_requests'])):
            return None
        page_requests.update(value['source_requests'])
    if all_requests != set(parent_requests) | page_requests:
        return None
    return proof


def _rows(collection, proof, scope, object_acl):
    by_bucket = {name: [] for name in proof}
    seen = set()
    for row in collection['items']:
        required = ('bucket', 'entity', 'role', 'name') + (('objectRef', 'generation') if object_acl else ())
        if not all(_readable(row, field) for field in required):
            return None
        bucket, entity, role, name = (row.get(key) for key in ('bucket', 'entity', 'role', 'name'))
        if (bucket not in by_bucket or not isinstance(name, str) or not name
                or not isinstance(entity, str) or entity not in _PUBLIC and not _HASH.fullmatch(entity)
                or role not in (('OWNER', 'READER') if object_acl else ('OWNER', 'READER', 'WRITER'))
                or name in seen):
            return None
        if object_acl:
            ref, generation = row.get('objectRef'), row.get('generation')
            if (not isinstance(ref, str) or not _OBJECT_REF.fullmatch(ref)
                    or not isinstance(generation, str) or not _GENERATION.fullmatch(generation)
                    or not name.startswith(bucket + '/objects/' + ref + '/acl/')):
                return None
        elif 'objectRef' in row or not name.startswith(bucket + '/acl/'):
            return None
        provenance = row.get('_provenance')
        refs = provenance.get('source_requests') if isinstance(provenance, dict) else None
        if (not _readable(row, '_provenance') or not isinstance(provenance, dict)
                or provenance.get('scope') != scope or not isinstance(refs, list) or not refs
                or len(set(refs)) != len(refs)
                or not set(refs) <= set(proof[bucket]['source_requests'])):
            return None
        seen.add(name)
        by_bucket[bucket].append({'bucket': bucket, 'entity': entity, 'role': role})
    return by_bucket


def materialize(collector, scope):
    """Attach both signed ACL envelopes atomically, or leave bucket facts untouched."""
    parent = collector.collections.get(('bucket', scope))
    bucket_acls = collector.collections.get(('bucket_acl', scope))
    object_acls = collector.collections.get(('object_acl', scope))
    if not (_complete(parent, scope, 'bucket')
            and _complete(bucket_acls, scope, 'bucket_acl')
            and _complete(object_acls, scope, 'object_acl')):
        return False
    buckets = parent['items']
    if not _unique_names(buckets):
        return False
    names = {b['name'] for b in buckets}
    nonuniform = set()
    for bucket in buckets:
        if not _readable(bucket, 'iamConfiguration.uniformBucketLevelAccess.enabled'):
            return False
        config = bucket.get('iamConfiguration')
        uniform = config.get('uniformBucketLevelAccess') if isinstance(config, dict) else None
        enabled = uniform.get('enabled') if isinstance(uniform, dict) else None
        if type(enabled) is not bool:
            return False
        if not enabled:
            if 'bucketAccessControls' in bucket or 'objectAccessControls' in bucket:
                return False
            nonuniform.add(bucket['name'])
    if not nonuniform:
        return True  # Uniform buckets retain their existing signed behavior.
    if not parent['source_requests']:
        return False
    bucket_proof = _proof(bucket_acls, names, nonuniform, parent['source_requests'])
    object_proof = _proof(object_acls, names, nonuniform, parent['source_requests'])
    if bucket_proof is None or object_proof is None:
        return False
    for proof in object_proof.values():
        if (proof.get('all_objects') is not True or proof.get('all_versions') is not True
                or proof.get('projection') != 'full' or type(proof.get('object_count')) is not int
                or proof['object_count'] < 0):
            return False
    bucket_rows = _rows(bucket_acls, bucket_proof, scope, False)
    object_rows = _rows(object_acls, object_proof, scope, True)
    if bucket_rows is None or object_rows is None:
        return False
    for name, rows in object_rows.items():
        if len({row['objectRef'] for row in object_acls['items'] if row['bucket'] == name}) > object_proof[name]['object_count']:
            return False
    for bucket in buckets:
        name = bucket['name']
        if name not in nonuniform:
            continue
        bp, op = bucket_proof[name], object_proof[name]
        bucket['bucketAccessControls'] = {
            'status': 'collected', 'all_pages': True, 'items': bucket_rows[name],
            'source_requests': list(bp['source_requests']),
            'parent_source_requests': list(parent['source_requests']),
            'page_count': bp['page_count'], 'source_inventory': 'bucket_acl'}
        bucket['objectAccessControls'] = {
            'status': 'collected', 'all_pages': True, 'all_objects': True,
            'all_versions': True, 'projection': 'full', 'items': object_rows[name],
            'source_requests': list(op['source_requests']),
            'parent_source_requests': list(parent['source_requests']),
            'page_count': op['page_count'], 'object_count': op['object_count'],
            'source_inventory': 'object_acl'}
    return True
