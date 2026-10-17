"""Version-pinned Blob metadata projection and real transport admission guards."""
from copy import deepcopy
from urllib.parse import urlencode
import xml.etree.ElementTree as ET

import pytest

from peaso.collectors import azure
from peaso.collectors import azure_blob_inventory_xml as native

ORIGIN = 'https://reviewedaccount.blob.core.windows.net/'
HOST = 'reviewedaccount.blob.core.windows.net'
PRIVATE = 'PRIVATE_OBJECT_NAME_OR_METADATA_SENTINEL'


def url(**changes):
    fields = {'restype': 'container', 'comp': 'list', 'maxresults': '500', 'include': native.INCLUDE}
    fields.update(changes)
    return ORIGIN + 'auditlogs?' + urlencode(fields)


def document():
    root = ET.Element('EnumerationResults', ServiceEndpoint=ORIGIN, ContainerName='auditlogs')
    for name, value in [('Prefix', ''), ('Marker', ''), ('MaxResults', '500'), ('Delimiter', '')]:
        ET.SubElement(root, name).text = value
    blobs = ET.SubElement(root, 'Blobs')
    blob = ET.SubElement(blobs, 'Blob')
    ET.SubElement(blob, 'Name').text = PRIVATE
    props = ET.SubElement(blob, 'Properties')
    ET.SubElement(props, 'ServerEncrypted').text = 'true'
    ET.SubElement(props, 'EncryptionScope').text = 'customer-key'
    ET.SubElement(props, 'CustomerProvidedKeySha256').text = PRIVATE
    ET.SubElement(props, 'CopySource').text = 'https://private.example/data?sig=' + PRIVATE
    ET.SubElement(ET.SubElement(blob, 'Metadata'), 'password').text = PRIVATE
    ET.SubElement(root, 'NextMarker')
    return root


def project(root, request=None):
    binding = native.validate_request(request or url(), {HOST})
    return native.project(ET.tostring(root, encoding='utf-8'), binding)


def test_native_projection_keeps_only_encryption_metadata_and_hashed_identity():
    result = project(document())
    assert PRIVATE not in str(result) and 'CopySource' not in str(result)
    assert len(result['items']) == 1
    item = result['items'][0]
    assert set(item) == {'identity_sha256', 'server_encrypted', 'customer_provided_key', 'encryption_scope'}
    assert len(item['identity_sha256']) == 64 and item['server_encrypted'] is True
    assert item['customer_provided_key'] is True and item['encryption_scope'] == 'customer-key'
    assert result['api_version'] == '2023-11-03' and result['next_marker'] == ''


def test_native_absent_scope_stays_absent_and_cpk_absence_is_distinct():
    root = document(); props = root.find('Blobs/Blob/Properties')
    props.remove(props.find('EncryptionScope')); props.remove(props.find('CustomerProvidedKeySha256'))
    row = project(root)['items'][0]
    assert 'encryption_scope' not in row and row['customer_provided_key'] is False


def test_same_name_versions_and_snapshots_have_distinct_hashed_identity():
    root = document(); blobs = root.find('Blobs'); first = blobs[0]
    version = deepcopy(first); ET.SubElement(version, 'VersionId').text = '2026-10-01T12:00:00.0000000Z'
    snapshot = deepcopy(first); ET.SubElement(snapshot, 'Snapshot').text = '2026-10-01T12:00:00.0000000Z'
    blobs.extend([version, snapshot])
    rows = project(root)['items']
    assert len({r['identity_sha256'] for r in rows}) == 3


def test_encoded_name_has_same_identity_as_its_exact_decoded_native_name():
    first = document(); first.find('Blobs/Blob/Name').text = 'public name'
    second = document(); node = second.find('Blobs/Blob/Name'); node.text = 'public%20name'; node.set('Encoded', 'true')
    assert project(first)['items'] == project(second)['items']


def test_continuation_is_bound_as_opaque_data_without_changing_origin():
    root = document(); root.find('Marker').text = 'opaque+/='; root.find('NextMarker').text = 'next+/='
    result = project(root, url(marker='opaque+/='))
    assert result['marker'] == 'opaque+/=' and result['next_marker'] == 'next+/='


@pytest.mark.parametrize('mutation', ['foreign_endpoint', 'foreign_container', 'prefix', 'delimiter',
    'marker', 'max_results', 'missing_next', 'repeated_marker', 'duplicate_identity',
    'missing_encrypted', 'invalid_encrypted', 'duplicate_scope', 'empty_scope', 'blob_prefix',
    'encoded_invalid', 'missing_name', 'empty_cpk', 'oversized_name'])
def test_ambiguous_or_incomplete_native_xml_is_rejected(mutation):
    root = document(); blob = root.find('Blobs/Blob'); props = blob.find('Properties')
    if mutation == 'foreign_endpoint': root.set('ServiceEndpoint', 'https://foreign.blob.core.windows.net/')
    elif mutation == 'foreign_container': root.set('ContainerName', 'different')
    elif mutation == 'prefix': root.find('Prefix').text = 'filtered/'
    elif mutation == 'delimiter': root.find('Delimiter').text = '/'
    elif mutation == 'marker': root.find('Marker').text = 'wrong-marker'
    elif mutation == 'max_results': root.find('MaxResults').text = '1'
    elif mutation == 'missing_next': root.remove(root.find('NextMarker'))
    elif mutation == 'repeated_marker':
        root.find('Marker').text = 'same'; root.find('NextMarker').text = 'same'
    elif mutation == 'duplicate_identity': root.find('Blobs').append(deepcopy(blob))
    elif mutation == 'missing_encrypted': props.remove(props.find('ServerEncrypted'))
    elif mutation == 'invalid_encrypted': props.find('ServerEncrypted').text = 'unknown'
    elif mutation == 'duplicate_scope': ET.SubElement(props, 'EncryptionScope').text = 'other'
    elif mutation == 'empty_scope': props.find('EncryptionScope').text = ''
    elif mutation == 'blob_prefix': ET.SubElement(root.find('Blobs'), 'BlobPrefix')
    elif mutation == 'encoded_invalid': blob.find('Name').set('Encoded', 'true'); blob.find('Name').text = 'bad%ZZ'
    elif mutation == 'missing_name': blob.remove(blob.find('Name'))
    elif mutation == 'empty_cpk': props.find('CustomerProvidedKeySha256').text = ''
    else: blob.find('Name').text = 'a' * 4097
    with pytest.raises(ValueError, match='invalid native Blob inventory metadata'):
        project(root, url(marker='same') if mutation == 'repeated_marker' else None)


@pytest.mark.parametrize('body', [b'<!DOCTYPE x [<!ENTITY harmless "x">]><x/>',
    '<!DOCTYPE x [<!ENTITY harmless "x">]><x/>'.encode('utf-16'), b'<broken', b'\xff'])
def test_dtd_encoded_xml_and_malformed_bodies_are_rejected(body):
    with pytest.raises(ValueError): native.project(body, native.validate_request(url(), {HOST}))


@pytest.mark.parametrize('change', ['comp', 'endpoint', 'http', 'encoded_path', 'foreign_service',
    'extra_parameter', 'duplicate_parameter', 'metadata', 'sas', 'blob_content', 'port', 'marker_control'])
def test_rejected_urls_never_reach_a_token_or_http_request(monkeypatch, change):
    target = url()
    if change == 'comp': target = url(comp='delete')
    elif change == 'endpoint': target = target.replace('reviewedaccount', 'differentaccount')
    elif change == 'http': target = target.replace('https:', 'http:')
    elif change == 'encoded_path': target = target.replace('/auditlogs?', '/auditlogs%2Fother?')
    elif change == 'foreign_service': target = target.replace('.blob.', '.queue.')
    elif change == 'extra_parameter': target = url(prefix='hidden')
    elif change == 'duplicate_parameter': target += '&comp=list'
    elif change == 'metadata': target = url(include='metadata')
    elif change == 'sas': target += '&sig=private'
    elif change == 'blob_content': target = ORIGIN + 'auditlogs/private-object'
    elif change == 'port': target = target.replace(HOST, HOST + ':443')
    else: target = url(marker='bad\nmarker')
    transport = azure.AzureTransport({'method': 'token', 'storage_token': 'inert'})
    transport.allow_storage(ORIGIN, 'reviewedaccount', 'blob')
    def forbidden(*args): raise AssertionError('URL must be rejected before credentials or network')
    monkeypatch.setattr(transport, 'token', forbidden)
    monkeypatch.setattr(azure, 'build_opener', forbidden)
    with pytest.raises(azure.AzureReadError) as error:
        transport.request_blob_inventory(target)
    assert error.value.code == 'untrusted_storage_inventory_endpoint'


def test_real_transport_uses_only_metadata_get_and_projects_before_return(monkeypatch):
    events = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): events.append('closed')
        def read(self, limit):
            assert limit == native.MAX_BYTES + 1
            return ET.tostring(document(), encoding='utf-8')
    class Opener:
        def open(self, request, timeout):
            assert request.get_method() == 'GET' and request.data is None and timeout == 20
            assert request.get_header('X-ms-version') == native.API_VERSION
            assert request.get_header('Accept') == 'application/xml'
            assert request.full_url == url()
            return Response()
    transport = azure.AzureTransport({'method': 'token', 'storage_token': 'inert'})
    transport.allow_storage(ORIGIN, 'reviewedaccount', 'blob')
    def token(audience):
        assert audience == azure.STORAGE
        events.append('storage-token'); return 'inert'
    monkeypatch.setattr(transport, 'token', token)
    monkeypatch.setattr(azure, 'build_opener', lambda policy: Opener())
    result = transport.request_blob_inventory(url())
    assert events == ['storage-token', 'closed']
    assert PRIVATE not in str(result) and len(result['items']) == 1
