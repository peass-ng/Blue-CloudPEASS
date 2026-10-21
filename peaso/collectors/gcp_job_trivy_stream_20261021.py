"""Selected Job CVE capture backed by privately owned streamed layer files.

The native before/after Job metadata proof and Trivy projection are unchanged.
Every verifier invocation freshly hashes retained files; no trust verdict or
content proof is cached. reset() removes this capture's private scratch only.
"""
import hashlib
from pathlib import Path
import tempfile
from types import FunctionType, SimpleNamespace

from . import gcp_image_secret_indicators as native
from . import gcp_job_trivy_capture_20261020 as predecessor
from . import gcp_job_image_vulnerability_native_20261021 as collection
from .gcp_image_stream_reader_20261021 import Reader, MAX_IMAGE, MAX_LAYER, CHUNK
from peaso import container_image_archive_20261020 as archive


def sha256(value, check=lambda: None):
    """Preserve bytes hashing and securely stream owned files on every call."""
    if type(value) is bytes:
        return hashlib.sha256(value)
    archive.require(isinstance(value, Path) and value.is_absolute(), 'owned_capture_required')
    checksum = hashlib.sha256()
    with archive._source(value, value.stat().st_size) as source:
        while True:
            check()
            chunk = source.read(CHUNK)
            if not chunk:
                break
            checksum.update(chunk)
    return checksum


class CaptureReader:
    def __init__(self, reader):
        self.reader = reader
        self._scratch = None
        self.reset()

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def reset(self):
        if self._scratch is not None:
            self._scratch.cleanup()
            self._scratch = None
        self._uri, self._blobs, self._reads, self._total = None, {}, [], 0

    def get(self, uri, category, digest, cap, size=None):
        archive.require(category in ('manifests', 'blobs') and type(uri) is str
                        and self._uri in (None, uri), 'single_native_image_required')
        key = category, digest
        if cap <= native.MAX_CONFIG:
            value = self.reader.get(uri, category, digest, cap, size)
            archive.require(type(value) is bytes and archive.sha(value) == digest,
                            'native_read_digest_mismatch')
            count = len(value)
        else:
            archive.require(category == 'blobs' and type(size) is int
                            and 0 < size <= MAX_LAYER and cap <= MAX_LAYER,
                            'bounded_layer_capture_required')
            manifests = [value for (kind, _), value in self._blobs.items() if kind == 'manifests']
            archive.require(len(manifests) == 1, 'manifest_before_layer_required')
            matches = [item for item in archive.decode(manifests[0])['layers']
                       if item.get('digest') == digest and item.get('size') == size]
            archive.require(bool(matches), 'layer_descriptor_required')
            descriptor = archive.descriptor(matches[0], archive.LAYERS, MAX_LAYER)
            if self._scratch is None:
                self._scratch = tempfile.TemporaryDirectory(prefix='peaso-gcp-trivy-capture-')
            path = Path(self._scratch.name) / ('blob-' + str(len(self._reads)))
            value = self.reader.get_layer(uri, descriptor, path)
            count = size
        self._uri = uri
        if key not in self._blobs:
            self._total += count
            archive.require(self._total <= MAX_IMAGE + archive.MAX_MANIFEST,
                            'retained_image_byte_bound')
            self._blobs[key] = value
        else:
            archive.require(sha256(self._blobs[key], self.check).digest() == sha256(value, self.check).digest(),
                            'duplicate_digest_changed')
        rid = self.reader.request_ids[-1]
        records = [r for r in self.reader.transport.evidence if r.get('id') == rid]
        archive.require(len(records) == 1 and records[0].get('status') == 'collected'
                        and records[0].get('method') == 'GET'
                        and records[0].get('operation') == 'artifactregistry.registry_content_get'
                        and records[0].get('category') == category
                        and records[0].get('digest') == digest,
                        'native_read_receipt_mismatch')
        self._reads.append((rid, key))
        return value

    def close(self):
        try:
            self.reset()
        finally:
            self.reader.close()


def copied(function, replacements):
    result = FunctionType(function.__code__, {**function.__globals__, **replacements},
                          function.__name__, function.__defaults__, function.__closure__)
    result.__kwdefaults__ = dict(function.__kwdefaults__ or {})
    return result


# Only the retained-source hash adapter changes: all native binding, exact read
# sequence, metadata receipts and verifier checks execute the original code.
def scan_captured(selection, scope, before, after, captured, **kwargs):
    scanner = copied(predecessor.scan_captured, {'hashlib': SimpleNamespace(
        sha256=lambda value: sha256(value, captured.check))})
    return scanner(selection, scope, before, after, captured, **kwargs)
_native = SimpleNamespace(**{**vars(native), 'Reader': Reader, 'MAX_LAYER': MAX_LAYER,
                            'MAX_IMAGE': MAX_IMAGE, 'MAX_LAYERS': archive.MAX_LAYERS})
_adapter = SimpleNamespace(CaptureReader=CaptureReader, scan_captured=scan_captured)
_read_image = copied(collection._read_image, {'native': _native})
collect_native = copied(collection.collect_native,
                        {'native': _native, 'adapter': _adapter, '_read_image': _read_image})
