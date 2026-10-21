"""Explicit GCS archives: native immutable reads and bounded memory-only parsing.

Uninstalled collection seam. Reuses only audited ZIP/tar parser code, with a
private per-call globals mapping for limits and the GCP detection callback.
Neither AWS globals nor network/context helpers are called or modified.
"""
from peaso.secret_evidence import scan_with_source, source_context, target_source

from copy import deepcopy
import hashlib
import json
import threading
import time
from types import FunctionType

from . import gcp_selected_object_secret_indicators as objects
from .aws_package_content_indicators import scan_zip, scan_tar, PartialArchive
from peaso.secret_scanning import scan_content, merge_leaks

SCHEMA = 'gcp-selected-archive-secrets-v1'
MARKER = 'SelectedArchiveSecretIndicators'
KIND = 'gcs_selected_archive'
OPTION = 'selected_gcs_archives'
MAX_EXPANDED_BYTES = 4194304
MAX_TOTAL_EXPANDED_BYTES = 8388608
MAX_MEMBER_BYTES = 1048576
MAX_MEMBERS = 100
MAX_TOTAL_MEMBERS = 200
MAX_RATIO = 200
MIME_TYPES = {'zip': {'application/zip', 'application/x-zip-compressed'},
              'tar': {'application/x-tar', 'application/tar'},
              'tar.gz': {'application/gzip', 'application/x-gzip'}}


def normalize_selection(options, scopes):
    kinds = options.get('_content_secret_scan_kinds')
    if options.get('content_secret_scans') is not True or not isinstance(kinds, list) or KIND not in kinds:
        return []
    rows = options.get(OPTION)
    if not isinstance(rows, list) or not 1 <= len(rows) <= objects.MAX_OBJECTS:
        raise objects.Incomplete('invalid_archive_selection')
    bases = []
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'project_scope', 'bucket', 'object', 'generation', 'format'}
                or not isinstance(row['format'], str) or row['format'] not in MIME_TYPES):
            raise objects.Incomplete('invalid_archive_selection')
        bases.append({k: v for k, v in row.items() if k != 'format'})
    # Shared native target syntax, exact scope validation and duplicate rejection.
    objects.selected_targets({'content_secret_scans': True,
        '_content_secret_scan_kinds': [objects.KIND], objects.OPTION: bases}, scopes)
    return deepcopy(rows)


def identity(target):
    return 'gcs-selected-archive:' + hashlib.sha256(json.dumps(target, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def _native_metadata(raw, target):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate metadata key')
            result[key] = value
        return result
    try:
        data = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(data, dict) or set(data) - set(objects.FIELDS.split(','))
                or any(data.get(k) != target[k if k != 'name' else 'object'] for k in ('bucket', 'name', 'generation'))
                or not isinstance(data.get('size'), str) or not data['size'].isascii()
                or not data['size'].isdecimal() or len(data['size']) > 20
                or str(int(data['size'])) != data['size']):
            raise ValueError('native metadata mismatch')
        size = int(data['size'])
        mime = data.get('contentType', '').split(';')[0].strip().lower()
        if (not 0 < size <= objects.MAX_OBJECT_BYTES or mime not in MIME_TYPES[target['format']]
                or data.get('contentEncoding', 'identity') != 'identity' or 'customerEncryption' in data):
            raise ValueError('unsupported archive metadata')
        return {'size': size, 'type': mime}
    except Exception:
        raise objects.Incomplete('archive_metadata_unavailable') from None


class Deadline:
    """Only the local deadline method required by memory-only parser functions."""
    def __init__(self, transport, state):
        self.transport, self.state = transport, state

    def check_deadline(self):
        objects._check(self.transport, self.state)


class PartialInspection(objects.Incomplete):
    def __init__(self, parsed):
        super().__init__('partial_archive')
        self.parsed = parsed


def _parse(raw, format_name, transport, state):
    expanded_cap = min(MAX_EXPANDED_BYTES, MAX_TOTAL_EXPANDED_BYTES - state['archive_expanded'])
    member_cap = min(MAX_MEMBERS, MAX_TOTAL_MEMBERS - state['archive_members'])
    if expanded_cap <= 0 or member_cap <= 0:
        raise objects.Incomplete('archive_total_limit')
    facade = Deadline(transport, state)
    files = []
    def inspect_member(payload, name, requests):
        requests.check_deadline()
        if (len(payload) > MAX_MEMBER_BYTES
                or name.lower().endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.xz', '.7z', '.rar',
                                         '.bin', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.exe', '.dll',
                                         '.so', '.class', '.pyc', '.wasm'))
                or bytes(payload).startswith((b'PK\x05\x06', b'PK\x07\x08'))):
            raise objects.Incomplete('nested_or_oversized_member')
        objects._text(bytes(payload))  # strict UTF-8, binary and nested archive rejection
        path = 'archive.member-' + str(len(files) + 1)
        remaining = objects._remaining(transport, state)
        outcome = scan_with_source(scan_content, bytes(payload), path, timeout=min(5, remaining / 2), source={'path': name})
        requests.check_deadline()
        entry = {'path': path, 'bytes': len(payload), 'engines': outcome['engines']}
        files.append(entry)
        if not outcome['complete']:
            if outcome['leaks']:
                raise PartialArchive([{'leaks': outcome['leaks']}], 0, 0)
            raise objects.Incomplete('archive_detector_unavailable')
        return [{'leaks': outcome['leaks']}]
    parser = scan_zip if format_name == 'zip' else scan_tar
    # No global monkeypatch: each parser function has its own immutable bindings.
    globals_for_call = dict(parser.__globals__, _scan=inspect_member,
        EXPANDED_LIMIT=expanded_cap, MEMBER_LIMIT=member_cap,
        ZIP_LIMIT=objects.MAX_OBJECT_BYTES, LAYER_LIMIT=objects.MAX_OBJECT_BYTES)
    if format_name == 'tar.gz':
        globals_for_call['EXPANDED_LIMIT'] = min(expanded_cap, max(1024, len(raw) * MAX_RATIO))
    bounded_parser = FunctionType(parser.__code__, globals_for_call,
                                  parser.__name__, parser.__defaults__, parser.__closure__)
    charged_expanded, charged_members = expanded_cap, member_cap
    try:
        if format_name == 'zip':
            refs, expanded, members = bounded_parser(raw, facade)
        else:
            media = 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if format_name == 'tar.gz' else '')
            refs, expanded, members = bounded_parser(raw, media, facade)
        charged_expanded, charged_members = expanded, members
        if not files:
            raise objects.Incomplete('archive_has_no_regular_text_files')
        leaks = merge_leaks([leak for ref in refs for leak in ref['leaks']])
        if len(leaks) > objects.MAX_LEAKS or sum(len(x['locations']) for x in leaks) > objects.MAX_LOCATIONS:
            raise objects.Incomplete('archive_finding_limit')
        return {'expanded_bytes': expanded, 'members': members, 'files': files, 'leaks': leaks}
    except PartialArchive as exc:
        leaks = merge_leaks([leak for ref in exc.refs for leak in ref['leaks']])
        if (not leaks or len(leaks) > objects.MAX_LEAKS
                or sum(len(x['locations']) for x in leaks) > objects.MAX_LOCATIONS):
            raise objects.Incomplete('archive_incomplete') from None
        raise PartialInspection({'expanded_bytes': max(exc.expanded, sum(f['bytes'] for f in files)),
            'members': max(exc.members, len(files)), 'files': files, 'leaks': leaks}) from None
    finally:
        # Failed parses conservatively consume their whole reserved allowance;
        # repeated malformed archives cannot reset scan-wide expansion budgets.
        state['archive_expanded'] += charged_expanded
        state['archive_members'] += charged_members


def collect_selected_archives(collector, scope):
    targets = normalize_selection(collector.options, collector.scopes)
    if not targets:
        return []
    transport = collector.transport
    with transport.lock:
        if not hasattr(transport, '_selected_object_secret_state'):
            transport._selected_object_secret_state = {'started': time.monotonic(), 'bytes': 0,
                'calls': 0, 'lock': threading.Lock(), 'items': {}}
        state = transport._selected_object_secret_state
    result = []
    with state['lock']:
        state.setdefault('archives', {})
        state.setdefault('archive_expanded', 0)
        state.setdefault('archive_members', 0)
        for target in targets:
            if target['project_scope'] != scope:
                continue
            ident = identity(target)
            if ident not in state['archives']:
                base = {k: v for k, v in target.items() if k != 'format'}
                marker = {'schema': SCHEMA, 'identity': ident, 'scope': scope, 'format': target['format'],
                    'status': 'incomplete', 'complete': False, 'compressed_bytes': 0,
                    'expanded_bytes': 0, 'members': 0, 'files': [], 'leaks': [],
                    'verification': 'not_attempted', 'reason': 'unavailable'}
                try:
                    objects._check(transport, state)
                    objects._bound_bucket(collector, scope, target['bucket'])
                    metadata = _native_metadata(objects._read(transport, state, base), target)
                    if state['bytes'] + metadata['size'] > objects.MAX_TOTAL_BYTES:
                        raise objects.Incomplete('total_byte_limit')
                    if state['archive_expanded'] >= MAX_TOTAL_EXPANDED_BYTES or state['archive_members'] >= MAX_TOTAL_MEMBERS:
                        raise objects.Incomplete('archive_total_limit')
                    payload = objects._read(transport, state, base, media=True, expected=metadata)
                    with source_context(**target_source(target, resource_id=ident, scope=scope)):
                        parsed = _parse(payload, target['format'], transport, state)
                    del payload
                    objects._check(transport, state)
                    marker.update(parsed, compressed_bytes=metadata['size'], complete=True,
                                  status='collected', reason='complete')
                except PartialInspection as exc:
                    marker.update(exc.parsed, compressed_bytes=metadata['size'],
                                  status='partial', reason='partial_positive')
                except Exception:
                    marker['reason'] = 'archive_incomplete'
                state['archives'][ident] = {'name': ident, MARKER: marker}
            result.append(deepcopy(state['archives'][ident]))
    return result


def collection_pages(collector, scope):
    targets = normalize_selection(collector.options, collector.scopes)
    bases = {identity(t): objects.identity({k: v for k, v in t.items() if k != 'format'}) for t in targets}
    for row in collect_selected_archives(collector, scope):
        with collector.transport.lock:
            refs = [e['id'] for e in collector.transport.evidence if e.get('scope') == scope
                    and e.get('resource_id') == bases[row['name']]
                    and e.get('operation') in ('storage.objects.get.metadata', 'storage.objects.get.media')]
        for ref in refs[:-1]:
            yield [], ref
        row.setdefault('_coverage', {})[MARKER] = {'status': 'collected', 'source_requests': refs}
        yield [row], refs[-1] if refs else 'local:gcs_selected_archive'
