"""Project issuance identifiers from already-collected public X.509 certificates.

No transport is accepted: no secret URI, private key or network read is possible.
This inventory is current Key Vault public certificates, not public TLS coverage.
"""
import base64
import re
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

NATIVE_TYPES = {'certificate_issuance'}
MAX_CERTIFICATES = 50000
MAX_PUBLIC_DER_BASE64 = 131072
SOURCE_KIND = 'key_vault_certificate'
API_VERSION = '2025-07-01'


def required_types(wanted):
    return {SOURCE_KIND, 'vault'} if NATIVE_TYPES.intersection(wanted) else set()


def _project(row, scope):
    if not isinstance(row, dict):
        raise ValueError('certificate source row malformed')
    parent, name, origin = (row.get(k) for k in ('parent_id', 'name', 'vault_uri'))
    if (not isinstance(parent, str) or not re.fullmatch(re.escape(scope) +
            r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft.KeyVault/vaults/[A-Za-z0-9-]{3,24}', parent, re.I)
            or any(segment in ('.', '..') for segment in parent.split('/'))):
        raise ValueError('certificate vault ARM identity malformed or foreign')
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,127}', name):
        raise ValueError('certificate name malformed')
    expected = parent + '/certificates/' + name
    if not isinstance(row.get('id'), str) or row['id'].casefold() != expected.casefold():
        raise ValueError('certificate ARM parent/name mismatch')
    if (not isinstance(origin, str) or not re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net', origin)
            or origin.casefold() != 'https://' + parent.rsplit('/', 1)[1].casefold() + '.vault.azure.net'):
        raise ValueError('certificate native vault endpoint mismatch')
    current = row.get('currentCertificate')
    if not isinstance(current, dict):
        raise ValueError('current public certificate missing')
    native = current.get('id')
    request = origin + '/certificates/' + name
    if not isinstance(native, str) or not re.fullmatch(re.escape(request) + r'/[A-Za-z0-9-]{1,127}', native):
        raise ValueError('certificate native version malformed or foreign')
    provenance = current.get('_provenance')
    if (not isinstance(provenance, dict) or provenance.get('source_operation') != 'certificates_get_current'
            or provenance.get('read_only') is not True or provenance.get('request_uri') != request
            or provenance.get('representation') != 'full' or provenance.get('api_version') != API_VERSION):
        raise ValueError('current public certificate native provenance unavailable')
    encoded = current.get('cer')
    if (not isinstance(encoded, str) or not encoded or len(encoded) > MAX_PUBLIC_DER_BASE64):
        raise ValueError('public certificate DER missing or oversized')
    der = base64.b64decode(encoded, validate=True)
    cert = x509.load_der_x509_certificate(der)
    # Some parsers tolerate trailing ASN.1 bytes; accept exactly one public DER.
    if cert.public_bytes(serialization.Encoding.DER) != der or cert.serial_number <= 0:
        raise ValueError('public certificate DER noncanonical or serial invalid')
    serial = format(cert.serial_number, 'x')
    if len(serial) % 2:
        serial = '0' + serial
    thumbprint = cert.fingerprint(hashes.SHA1()).hex()
    return {'id': expected + '/issuance/' + native.rsplit('/', 1)[1],
            'parent_id': parent, 'native_certificate_id': native,
            'authority': 'x509_not_before', 'issued_at': cert.not_valid_before_utc.astimezone(timezone.utc).isoformat(),
            'serial': serial, 'thumbprint': thumbprint,
            '_provenance': {'source_operation': 'authoritative_certificate_issuance_read',
                'read_only': True, 'request_uri': request, 'api_version': API_VERSION,
                'native_source_operation': 'certificates_get_current', 'native_certificate_id': native,
                'native_field': 'cer', 'der_sha256': cert.fingerprint(hashes.SHA256()).hex(),
                'projection': 'public_x509_not_before', 'private_material_omitted': True}}


def collect(reader, scopes, wanted):
    """Append bounded derived facts after azure_swc.collect_current_certificates.

    Source collection completeness refers only to the current Key Vault inventory.
    A partial source preserves known public facts as partial, never as complete.
    Duplicate identities or thumbprint/serial joins invalidate the projection.
    """
    if not NATIVE_TYPES.intersection(wanted):
        return
    for scope in scopes:
        def fetch(scope=scope):
            if not isinstance(scope, str) or not re.fullmatch(r'/subscriptions/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', scope):
                raise ValueError('certificate subscription scope malformed')
            parents = [c for c in reader.collections if c.get('type') == SOURCE_KIND
                       and isinstance(c.get('scope'), str) and c['scope'].casefold() == scope.casefold()]
            if len(parents) != 1:
                raise ValueError('current certificate source absent or ambiguous')
            parent = parents[0]
            rows, status = parent.get('items'), parent.get('status')
            if (not isinstance(rows, list) or len(rows) > MAX_CERTIFICATES
                    or status not in {'collected', 'empty', 'partial', 'denied', 'timeout', 'malformed', 'unknown'}
                    or (status == 'empty' and rows) or (status == 'collected' and not rows)
                    or (status in {'denied', 'timeout', 'malformed', 'unknown'} and rows)):
                raise ValueError('current certificate source inconsistent or oversized')
            if status in {'collected', 'empty'}:
                coverage = parent.get('scopeCoverage')
                if (not isinstance(coverage, dict) or str(coverage.get('scope', '')).casefold() != scope.casefold()
                        or coverage.get('_provenance', {}).get('source_operation') != 'vault_current_certificate_inventory_read'
                        or coverage.get('_provenance', {}).get('read_only') is not True
                        or coverage.get('resolution') != dict.fromkeys(('vaults', 'certificatePages', 'currentVersions'), 'complete')):
                    raise ValueError('current certificate inventory completeness unavailable')
            facts, identities, current_names, joins = [], set(), set(), set()
            for row in rows:
                fact = _project(row, scope)
                identity = fact['id'].casefold()
                join = (fact['thumbprint'], fact['serial'])
                current_name = row['id'].casefold()
                if identity in identities or current_name in current_names or join in joins:
                    raise ValueError('duplicate or ambiguous public certificate issuance')
                identities.add(identity)
                current_names.add(current_name)
                joins.add(join)
                facts.append(fact)
            if facts:
                yield facts
            if status not in {'collected', 'empty'}:
                if status == 'denied':
                    from .azure import AzureReadError
                    raise AzureReadError('certificate_source_denied', 403)
                if status == 'timeout':
                    raise TimeoutError('certificate_source_timeout')
                raise ValueError('current certificate source incomplete')
        reader.run([('certificate_issuance', scope, 'Microsoft.KeyVault', fetch)])
