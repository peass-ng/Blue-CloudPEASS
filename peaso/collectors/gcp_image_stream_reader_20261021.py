"""Authenticated immutable GCP registry reads with bounded private scratch files.

Only layer blobs use disk. Manifests/configs remain bounded in memory. The caller
owns a TemporaryDirectory and must remove it after inspection; failed downloads
remove only the file this reader created. No registry discovery or writes occur.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

from . import gcp_image_secret_indicators as native

CHUNK = 64 * 1024
MAX_LAYER = 512 * 1024 * 1024
MAX_IMAGE = 1024 * 1024 * 1024
MAX_CALLS = native.MAX_IMAGES * (64 + 2)  # manifest + config + all 64 layers
MIN_FREE_DISK = 256 * 1024 * 1024


class Reader(native.Reader):
    """Keep native receipts and identity checks while streaming exact layer bytes."""

    def get(self, uri, category, digest, cap, size=None):
        if type(cap) is not int or not 0 < cap <= native.MAX_CONFIG:
            raise ValueError('bounded metadata read required')
        return self._record(uri, category, digest, cap, size, None)

    def get_layer(self, uri, descriptor, destination):
        if (type(descriptor) is not dict or descriptor.get('mediaType') not in native.TAR_TYPES
                or type(descriptor.get('size')) is not int
                or not 0 < descriptor['size'] <= MAX_LAYER
                or type(descriptor.get('digest')) is not str
                or native.DIGEST.fullmatch(descriptor['digest']) is None):
            raise ValueError('bounded immutable layer required')
        if not isinstance(destination, Path) or not destination.is_absolute():
            raise ValueError('owned scratch destination required')
        return self._record(uri, 'blobs', descriptor['digest'], MAX_LAYER,
                            descriptor['size'], destination)

    def _record(self, uri, category, digest, cap, size, destination):
        receipt = {'method': 'GET', 'operation': 'artifactregistry.registry_content_get',
                   'category': category if category in ('manifests', 'blobs') else None,
                   'digest': digest if type(digest) is str and native.DIGEST.fullmatch(digest) else None,
                   'scope': None, 'status': 'unavailable', 'attempts': 0, 'http_attempts': 0}
        self.current_receipt = receipt
        try:
            _, repo, _, _ = native.parse_image_uri(uri)
            receipt['scope'] = '/'.join(repo.split('/')[:2])
            result = self._download(uri, category, digest, cap, size, destination)
            receipt['status'] = 'collected'
            return result
        except Exception:
            if receipt.get('http_status') in (401, 403):
                receipt['status'] = 'denied'
            raise
        finally:
            with self.transport.lock:
                if not hasattr(self.transport, 'evidence'):
                    self.transport.evidence = []
                receipt['id'] = 'request-' + str(len(self.transport.evidence) + 1)
                self.transport.evidence.append(receipt)
                self.request_ids.append(receipt['id'])
            self.current_receipt = None

    def _download(self, uri, category, digest, cap, size, destination):
        self.check()
        canonical, _, _, _ = native.parse_image_uri(uri)
        parsed = urlsplit(canonical)
        if (any(part in ('', '.', '..') for part in parsed.path.lstrip('/').split('/'))
                or category not in ('manifests', 'blobs') or type(digest) is not str
                or native.DIGEST.fullmatch(digest) is None):
            raise ValueError('fixed registry object required')
        image_path = parsed.path.split('@', 1)[0].lstrip('/')
        url = 'https://' + parsed.netloc + '/v2/' + image_path + '/' + category + '/' + digest
        if self.calls >= MAX_CALLS:
            raise ValueError('registry call bound')
        with self.transport.lock:
            self.transport.check_cancelled()
            if self.transport.max_calls is not None and self.transport.calls >= self.transport.max_calls:
                raise ValueError('native call budget')
            self.transport.calls += 1
        self.calls += 1
        self.current_receipt['attempts'] = 1
        authorization = self.transport.credentials.headers().get('Authorization')
        if type(authorization) is not str or not re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', authorization):
            raise ValueError('native access token unavailable')
        basic = base64.b64encode(('oauth2accesstoken:' + authorization[7:]).encode()).decode()
        headers = {'Authorization': 'Basic ' + basic, 'Accept-Encoding': 'identity',
                   'Accept': native.OCI + ', ' + native.DOCKER if category == 'manifests' else 'application/octet-stream'}
        if hasattr(self.session, 'cookies'):
            self.session.cookies.clear()
        self.current_receipt['http_attempts'] = 1
        response = self.session.request('GET', url, headers=headers, stream=True,
            allow_redirects=False, timeout=min(10, self.transport.timeout, max(.001, self.end - native.time.monotonic())))
        output, created = None, False
        try:
            status = response.status_code
            if type(status) is int and 100 <= status <= 599:
                self.current_receipt['http_status'] = status
            if (status != 200 or response.url != url or response.history
                    or response.headers.get('Content-Encoding', 'identity') != 'identity'
                    or response.headers.get('WWW-Authenticate') is not None):
                raise ValueError('registry redirect/challenge/denied/unexpected response')
            length = response.headers.get('Content-Length')
            if length is not None and (type(length) is not str or not length.isdecimal()
                    or int(length) > cap or size is not None and int(length) != size):
                raise ValueError('registry stream size differs')
            header_digest = response.headers.get('Docker-Content-Digest')
            if header_digest is not None and header_digest != digest:
                raise ValueError('registry header digest differs')
            if destination is not None:
                if shutil.disk_usage(destination.parent).free < MIN_FREE_DISK + size:
                    raise ValueError('scratch disk bound')
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                created = True
                output = os.fdopen(fd, 'wb')
            data, count, checksum = bytearray(), 0, hashlib.sha256()
            for chunk in response.iter_content(chunk_size=CHUNK):
                self.check()
                if type(chunk) is not bytes or len(chunk) > CHUNK:
                    raise ValueError('invalid registry stream')
                if not chunk:
                    continue
                count += len(chunk)
                self.bytes += len(chunk)
                if count > cap or size is not None and count > size or self.bytes > native.MAX_IMAGES * MAX_IMAGE:
                    raise ValueError('registry stream bound')
                checksum.update(chunk)
                if output is None:
                    data.extend(chunk)
                else:
                    if shutil.disk_usage(destination.parent).free < MIN_FREE_DISK + len(chunk):
                        raise ValueError('scratch disk bound')
                    output.write(chunk)
            if (size is not None and count != size or length is not None and count != int(length)
                    or 'sha256:' + checksum.hexdigest() != digest):
                raise ValueError('registry descriptor digest/size differs')
            if output is not None:
                output.close()
                output = None
                return destination
            return bytes(data)
        except BaseException:
            if output is not None:
                output.close()
                output = None
            if created:
                destination.unlink(missing_ok=True)
            raise
        finally:
            if output is not None:
                output.close()
            try:
                response.close()
            except BaseException:
                if created:
                    destination.unlink(missing_ok=True)
                raise
