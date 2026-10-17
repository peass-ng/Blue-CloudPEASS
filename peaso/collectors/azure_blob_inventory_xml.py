"""Bounded List Blobs metadata projection; never blob content or user metadata.

The version-pinned API returns EncryptionScope only for scoped encryption:
https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs
"""
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, unquote, urlsplit

API_VERSION = '2023-11-03'
MAX_RESULTS = 500
MAX_BYTES = 8 * 1024 * 1024
INCLUDE = 'snapshots,versions,deleted,deletedwithversions'
CONTAINER = re.compile(r'(?:\$(?:root|web|logs)|[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9]))')


def _invalid():
    raise ValueError('invalid native Blob inventory metadata')


def validate_request(url, allowed_hosts):
    """Return the exact bound origin/container/marker before acquiring a token."""
    parsed = urlsplit(url)
    host = (parsed.hostname or '').lower()
    if (parsed.scheme != 'https' or parsed.netloc.lower() != host or host not in allowed_hosts
            or re.fullmatch(r'[a-z0-9]{3,24}\.blob\.core\.windows\.net', host) is None
            or parsed.username or parsed.password or parsed.fragment or '%' in parsed.path
            or '\\' in parsed.path or not parsed.path.startswith('/')
            or CONTAINER.fullmatch(parsed.path[1:]) is None):
        _invalid()
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        _invalid()
    params = dict(pairs)
    if (len(params) != len(pairs) or set(params) - {'restype', 'comp', 'maxresults', 'include', 'marker'}
            or params.get('restype') != 'container' or params.get('comp') != 'list'
            or params.get('maxresults') != str(MAX_RESULTS) or params.get('include') != INCLUDE):
        _invalid()
    marker = params.get('marker', '')
    if len(marker) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in marker):
        _invalid()
    return {'service_endpoint': 'https://' + host + '/', 'container_name': parsed.path[1:], 'marker': marker}


def _one(parent, tag, *, optional=False):
    nodes = parent.findall(tag)
    if len(nodes) != 1:
        if optional and not nodes: return None
        _invalid()
    return nodes[0]


def _scalar(parent, tag, *, optional=False):
    node = _one(parent, tag, optional=optional)
    if node is None: return None
    if len(node): _invalid()
    return node.text or ''


def project(body, binding):
    """Hash object identity before returning any result to a collector/cache."""
    if (not isinstance(body, bytes) or not body or len(body) > MAX_BYTES or b'\x00' in body
            or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper()):
        _invalid()
    try:
        body.decode('utf-8', errors='strict')
        root = ET.fromstring(body)
    except (ET.ParseError, UnicodeError, ValueError):
        _invalid()
    if (root.tag != 'EnumerationResults' or root.get('ServiceEndpoint') != binding['service_endpoint']
            or root.get('ContainerName') != binding['container_name']
            or _scalar(root, 'Marker') != binding['marker']
            or _scalar(root, 'MaxResults') != str(MAX_RESULTS)
            or _scalar(root, 'Prefix', optional=True) not in (None, '')
            or _scalar(root, 'Delimiter', optional=True) not in (None, '')):
        _invalid()
    marker = _scalar(root, 'NextMarker')
    if len(marker) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in marker): _invalid()
    if marker and marker == binding['marker']: _invalid()
    blobs = _one(root, 'Blobs')
    if len(blobs) > MAX_RESULTS: _invalid()
    result, identities = [], set()
    for blob in blobs:
        if blob.tag != 'Blob': _invalid()  # No delimiter/prefix shortcuts.
        name_node = _one(blob, 'Name')
        if len(name_node) or set(name_node.attrib) - {'Encoded'}: _invalid()
        name = name_node.text
        if not isinstance(name, str) or not name or len(name.encode('utf-8')) > 4096: _invalid()
        encoded = name_node.get('Encoded', 'false')
        if encoded not in {'true', 'false'}: _invalid()
        if encoded == 'true':
            if re.search(r'%(?![0-9a-fA-F]{2})', name): _invalid()
            try:
                name = unquote(name, errors='strict')
            except (UnicodeError, ValueError):
                _invalid()
        parts = [_scalar(blob, key, optional=True) for key in ('Snapshot', 'VersionId')]
        if any(value is not None and (not value or len(value) > 256 or any(ord(c) < 32 for c in value)) for value in parts):
            _invalid()
        properties = _one(blob, 'Properties')
        encrypted = _scalar(properties, 'ServerEncrypted')
        if encrypted not in {'true', 'false'}: _invalid()
        scope = _scalar(properties, 'EncryptionScope', optional=True)
        if scope is not None and (not scope or re.fullmatch(r'(?:\$account-encryption-key|[A-Za-z0-9][A-Za-z0-9._-]{0,255})', scope) is None):
            _invalid()
        cpk = _scalar(properties, 'CustomerProvidedKeySha256', optional=True)
        if cpk is not None and not cpk: _invalid()
        identity = hashlib.sha256(json.dumps([binding['service_endpoint'], binding['container_name'], name, *parts],
            ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest()
        if identity in identities: _invalid()
        identities.add(identity)
        result.append({'identity_sha256': identity, 'server_encrypted': encrypted == 'true',
            'customer_provided_key': cpk is not None, **({'encryption_scope': scope} if scope is not None else {})})
    return {**binding, 'api_version': API_VERSION, 'items': result, 'next_marker': marker}
