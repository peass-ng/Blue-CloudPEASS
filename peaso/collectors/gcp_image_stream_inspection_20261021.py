"""Practical selected GCP image secret inspection using verified streamed layers.

This proposal is not installed into the collector registry yet. It preserves
default-off selection and native project/repository binding via the existing
enricher, while replacing only image download and layer parsing.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
from types import FunctionType

from . import gcp_image_secret_indicators as native
from .gcp_image_stream_reader_20261021 import Reader, MAX_IMAGE, MAX_LAYER
from peaso.container_image_archive_20261020 import visit_files, MAX_LAYERS

WINDOW = 1024 * 1024
OVERLAP = 4096
MAX_FILE = 64 * 1024 * 1024
MAX_SCANNED = 512 * 1024 * 1024


def source_reports(leaks):
    reports = {}
    for leak in leaks:
        for loc in leak['locations']:
            reports[(loc['layer'], loc['path'], leak['fingerprint'])] = {'layer': loc['layer'], 'path': loc['path'],
                'fingerprint': leak['fingerprint'], 'engines': [
                    {'engine': engine, 'status': 'complete'}
                    for engine in sorted({item['engine'] for item in leak['detectors']})]}
    return [reports[key] for key in sorted(reports)]


def inspect_image(row, scope, repositories, projects, reader):
    leaks, engines = [], None
    image_fields, inspected, scanned = None, [], []
    partial_bytes = 0
    files = 0
    try:
        uri, repo, digest = native.bind_image(row, scope, repositories, projects)
        raw = reader.get(uri, 'manifests', digest, native.MAX_MANIFEST)
        manifest = native._json(raw)
        if (type(manifest) is not dict or set(manifest) - {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
                or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2
                or manifest.get('mediaType') not in (native.OCI, native.DOCKER)):
            raise ValueError('single-platform manifest required')
        config = native._descriptor(manifest['config'], native.CONFIG_TYPES, native.MAX_CONFIG)
        layers = manifest.get('layers')
        if type(layers) is not list or not 1 <= len(layers) <= MAX_LAYERS:
            raise ValueError('bounded image layers required')
        layers = [native._descriptor(layer, native.TAR_TYPES, MAX_LAYER) for layer in layers]
        if sum(item['size'] for item in [config] + layers) > MAX_IMAGE:
            raise ValueError('compressed image bound')
        config_raw = reader.get(uri, 'blobs', config['digest'], native.MAX_CONFIG, config['size'])
        decoded = native._json(config_raw)
        if (type(decoded) is not dict or decoded.get('os') != 'linux'
                or decoded.get('architecture') not in ('amd64', 'arm64')
                or type(decoded.get('rootfs')) is not dict or decoded['rootfs'].get('type') != 'layers'
                or type(decoded['rootfs'].get('diff_ids')) is not list
                or len(decoded['rootfs']['diff_ids']) != len(layers)
                or any(type(value) is not str or not native.DIGEST.fullmatch(value)
                       for value in decoded['rootfs']['diff_ids'])):
            raise ValueError('supported platform and rootfs required')

        def scan(payload, path, layer, line_offset=0, document=None):
            nonlocal engines
            native.Deadline(reader).check_deadline()
            outcome = native.scan_with_source(native.scan_content, payload, path,
                source={'resource_id': uri, 'scope': scope, 'image_digest': digest,
                        'layer': layer, 'location_kind': 'configuration' if document is not None else 'file'},
                native=document, timeout=15)
            if engines is None:
                engines = outcome['engines']
            for leak in outcome['leaks']:
                locations = []
                for location in leak['locations']:
                    projected = dict(location, layer=layer)
                    if type(projected.get('line')) is int:
                        projected['line'] += line_offset
                    locations.append(projected)
                leaks.append(dict(leak, locations=locations))
            if len(leaks) > native.MAX_LEAKS or sum(len(item['locations']) for item in leaks) > native.MAX_LOCATIONS:
                raise ValueError('indicator bound')
            if not outcome['complete']:
                raise ValueError('dual detector incomplete')

        image_fields = {'uri': uri, 'repository': repo, 'manifest_digest': digest,
                        'descriptors': deepcopy([config] + layers)}
        partial_bytes = len(config_raw)
        inspected.append(config['digest'])
        scan(config_raw, 'image-config.json', config['digest'], document=decoded)
        files, scanned_bytes, complete = 0, 0, True

        def observe(name, stream, size, layer_index):
            nonlocal files, scanned_bytes, complete, inspected, scanned, partial_bytes
            files += 1
            path = 'member-' + str(files)
            layer = layers[layer_index]['digest']
            scanned = [value['digest'] for value in layers[:layer_index]]
            inspected = [config['digest']] + scanned + [layer]
            partial_bytes += size
            # Scan names as content, never retain provider-controlled filenames
            # in detector caches or public locations.
            with native.source_context(resource_id=uri, scope=scope, image_digest=digest, layer=layer):
                native.alias_path(path, name)
                scan(name.encode('utf-8'), path + '-name', layer)
            if size > MAX_FILE or scanned_bytes + size > MAX_SCANNED:
                complete = False
                return
            overlap, consumed, prior_lines = b'', 0, 0
            while consumed < size:
                reader.check()
                chunk = stream.read(min(WINDOW, size - consumed))
                if type(chunk) is not bytes or not chunk:
                    raise ValueError('truncated verified image file')
                if consumed == 0 and (chunk.startswith((b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ',
                        b'7z\xbc\xaf', b'Rar!', b'\x28\xb5\x2f\xfd')) or chunk[257:262] == b'ustar'):
                    # Scanning the compressed bytes cannot establish absence in
                    # an unexpanded nested archive. Keep any prior positive,
                    # but never label this image complete and clean.
                    complete = False
                    return
                consumed += len(chunk)
                scanned_bytes += len(chunk)
                scan(overlap + chunk, path, layer, prior_lines - overlap.count(b'\n'))
                prior_lines += chunk.count(b'\n')
                overlap = (overlap + chunk)[-OVERLAP:]
            if size == 0:
                scan(b'', path, layer)

        image_identity = {'provider': 'gcp', 'scope': scope,
            'immutable_reference': uri.removeprefix('https://'),
            'manifest_digest': digest, 'config_digest': config['digest']}
        with tempfile.TemporaryDirectory(prefix='peaso-gcp-image-') as directory:
            root, paths = Path(directory), []
            for index, descriptor in enumerate(layers):
                reader.check()
                path = root / ('blob-' + str(index))
                reader.get_layer(uri, descriptor, path)
                paths.append(path)
            result = visit_files(image_identity, raw, config_raw, paths, lambda *args: None,
                                 check=reader.check, partial_callback=observe)
        reader.check()
        if result.get('links_skipped', 0):
            complete = False
        leaks = native.merge_leaks(leaks)
        return {'schema': native.SCHEMA, 'status': 'collected' if complete else 'partial',
            'complete': complete, 'uri': uri, 'repository': repo, 'manifest_digest': digest,
            'descriptors': deepcopy([config] + layers),
            'layers_scanned': [layer['digest'] for layer in layers],
            'expanded_bytes': result['expanded_bytes'], 'members': result['members'],
            'regular_files': files, 'engines': engines, 'leaks': leaks,
            'verification': 'not_attempted', **({} if complete else {
                'inspected_digests': [config['digest']] + [value['digest'] for value in layers],
                'source_reports': source_reports(leaks)})}
    except Exception:
        # A later layer/engine failure cannot erase already observed leaks. Only
        # config/layers whose hashes/rootfs were verified may retain witnesses.
        if image_fields is not None and leaks:
            try:
                safe = native.merge_leaks(leaks)
                if (len(safe) <= native.MAX_LEAKS
                        and sum(len(item['locations']) for item in safe) <= native.MAX_LOCATIONS
                        and all(loc.get('layer') in inspected for leak in safe for loc in leak['locations'])):
                    return {'schema': native.SCHEMA, 'status': 'partial', 'complete': False,
                        **image_fields, 'layers_scanned': scanned, 'inspected_digests': inspected,
                        'expanded_bytes': partial_bytes, 'members': files, 'regular_files': files,
                        'engines': engines or [], 'leaks': safe, 'source_reports': source_reports(safe),
                        'verification': 'not_attempted'}
            except (TypeError, ValueError, KeyError, AttributeError):
                pass
        return {'schema': native.SCHEMA, 'status': 'unavailable', 'complete': False, 'leaks': []}


# Explicit opt-in integration seam for the reviewed collector transaction. No
# predecessor module globals, source, registry entries or callables are patched.
_globals = {**vars(native), 'Reader': Reader, 'inspect_image': inspect_image}
enrich = FunctionType(native.enrich.__code__, _globals, 'enrich', native.enrich.__defaults__)
enrich.__kwdefaults__ = dict(native.enrich.__kwdefaults__ or {})
