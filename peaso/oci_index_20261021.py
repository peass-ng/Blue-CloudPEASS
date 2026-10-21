"""Pure bounded resolver for digest-selected OCI indexes and Docker manifest lists.

The caller owns the fixed registry transport. This module never selects a host,
forwards credentials, guesses a platform, or reads blobs outside that repository.
"""
from peaso import container_image_archive_20261020 as archive

OCI_INDEX = 'application/vnd.oci.image.index.v1+json'
DOCKER_LIST = 'application/vnd.docker.distribution.manifest.list.v2+json'
INDEX_TYPES = frozenset((OCI_INDEX, DOCKER_LIST))
LEAF_TYPES = frozenset((archive.OCI, archive.DOCKER))
ALL_MANIFEST_TYPES = LEAF_TYPES | INDEX_TYPES
MAX_CHILDREN = 8
MAX_GRAPH_BYTES = (MAX_CHILDREN + 1) * archive.MAX_MANIFEST


def _platform(value):
    archive.require(type(value) is dict and not set(value) -
                    {'os', 'architecture', 'variant'},
                    'unsupported_platform_descriptor')
    for key in ('os', 'architecture'):
        item = value.get(key)
        archive.require(type(item) is str and 1 <= len(item) <= 64 and
                        item != 'unknown' and item.isascii() and
                        all(c.isalnum() or c in '._-' for c in item),
                        'unsupported_platform_descriptor')
    archive.require(value['os'] == 'linux' and value['architecture'] in ('amd64', 'arm64'),
                    'unsupported_platform_descriptor')
    for key in ('variant',):
        if key in value:
            item = value[key]
            archive.require(type(item) is str and 1 <= len(item) <= 64 and item.isascii() and
                            all(c.isalnum() or c in '._-' for c in item),
                            'unsupported_platform_descriptor')
    return {key: value[key] for key in sorted(value)}


def children(parent_raw, parent_digest, fetch, *, check=lambda: None, platform=None):
    """Yield verified leaf (digest, raw, platform) in parent order.

    A later unsupported child raises after earlier leaves have been yielded, so
    callers can preserve a confirmed finding while withholding clean PASS.
    """
    archive.require(type(parent_raw) is bytes and 0 < len(parent_raw) <= archive.MAX_MANIFEST
                    and type(parent_digest) is str and archive.DIGEST.fullmatch(parent_digest)
                    and archive.sha(parent_raw) == parent_digest, 'parent_manifest_digest_or_size')
    archive.require(callable(fetch) and callable(check), 'bounded_manifest_reader_required')
    check()
    parent = archive.decode(parent_raw)
    archive.require(type(parent) is dict and type(parent.get('schemaVersion')) is int and
                    parent['schemaVersion'] == 2, 'unsupported_manifest_schema')
    kind = parent.get('mediaType')
    if kind in LEAF_TYPES:
        yield {'digest': parent_digest, 'size': len(parent_raw), 'mediaType': kind,
               'platform': None, 'raw': parent_raw, 'parent_digest': parent_digest}
        return
    archive.require(kind in INDEX_TYPES and not set(parent)-
                    {'schemaVersion', 'mediaType', 'manifests', 'annotations'} and
                    type(parent.get('manifests')) is list and 1 <= len(parent['manifests']) <= MAX_CHILDREN,
                    'unsupported_image_index')
    if platform is not None:
        _platform(platform)
    seen, total, selected = set(), len(parent_raw), 0
    for item in parent['manifests']:
        check()
        archive.require(type(item) is dict and not set(item)-
                        {'mediaType','digest','size','platform','annotations'} and
                        item.get('mediaType') in LEAF_TYPES and
                        (kind != DOCKER_LIST or item['mediaType'] == archive.DOCKER),
                        'unsupported_index_child')
        desc = archive.descriptor({k:item[k] for k in ('mediaType','digest','size')},
                                  LEAF_TYPES, archive.MAX_MANIFEST)
        child_platform = _platform(item.get('platform'))
        archive.require(desc['digest'] not in seen, 'duplicate_index_child')
        seen.add(desc['digest'])
        if platform is not None and child_platform != platform:
            continue
        selected += 1
        total += desc['size']
        archive.require(total <= MAX_GRAPH_BYTES, 'index_byte_bound')
        raw = fetch(desc['digest'], desc['size'], desc['mediaType'])
        archive.require(type(raw) is bytes and len(raw) == desc['size'] and
                        archive.sha(raw) == desc['digest'], 'child_manifest_digest_or_size')
        document = archive.decode(raw)
        archive.require(type(document) is dict and type(document.get('schemaVersion')) is int and
                        document['schemaVersion'] == 2 and
                        document.get('mediaType') == desc['mediaType'] and
                        'config' in document and 'layers' in document,
                        'unsupported_child_manifest')
        yield {**desc, 'platform': child_platform, 'raw': raw,
               'parent_digest': parent_digest}
    archive.require(selected == 1 if platform is not None else selected == len(parent['manifests']),
                    'index_platform_selection_incomplete')
