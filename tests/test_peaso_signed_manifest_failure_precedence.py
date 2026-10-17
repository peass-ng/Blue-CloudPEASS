"""Independent invalid manifest signatures cannot be hidden by unread blob bytes."""
import base64
import pytest
from peaso.checks import evaluate_check
from tests.compliance_draft_isolation import staged_registry
with staged_registry(("compliance_new_sw23",)):
    from test_peaso_compliance_new_sw23 import fixture, index, signing_key, sw

@pytest.mark.parametrize('damage', ['unread_bytes', 'malformed_bytes', 'missing_blob_name'])
def test_invalid_signature_remains_measured_failure_with_unavailable_blob_bytes(signing_key, damage):
    row, ev = fixture(sw.INTEGRITY, signing_key)
    c = ev['containers']['items'][0]
    c['manifest']['signature_base64'] = base64.b64encode(b'wrong-signature').decode()
    blob = c['blobs']['items'][0]
    if damage == 'unread_bytes': blob['read_complete'] = False
    elif damage == 'malformed_bytes': blob['content_base64'] = '!not-base64'
    else: blob['blobName'] = ''
    status, evidence = evaluate_check(sw.INTEGRITY, row, index(sw.INTEGRITY, row, ev))
    assert status == 'FAIL'
    gap = evidence['manifest_integrity_gaps'][0]
    assert gap['invalid_signature'] is True
    assert gap['missing_or_extra'] == [] and gap['changed'] == []

@pytest.mark.parametrize('damage', ['untrusted_key', 'malformed_signature', 'incomplete_scope', 'incomplete_listing'])
def test_unverified_signature_or_inventory_does_not_establish_failure(signing_key, damage):
    row, ev = fixture(sw.INTEGRITY, signing_key)
    c = ev['containers']['items'][0]
    c['manifest']['signature_base64'] = base64.b64encode(b'wrong-signature').decode()
    if damage == 'untrusted_key': c['trusted_key']['pinned_spki_sha256'] = '0' * 64
    elif damage == 'malformed_signature': c['manifest']['signature_base64'] = '!invalid-base64'
    elif damage == 'incomplete_scope': ev['protected_scope_authoritative'] = False
    else: c['listing_complete'] = False
    assert evaluate_check(sw.INTEGRITY, row, index(sw.INTEGRITY, row, ev))[0] == 'UNKNOWN'

def test_valid_manifest_unavailable_blob_bytes_still_unknown(signing_key):
    row, ev = fixture(sw.INTEGRITY, signing_key)
    ev['containers']['items'][0]['blobs']['items'][0]['read_complete'] = False
    assert evaluate_check(sw.INTEGRITY, row, index(sw.INTEGRITY, row, ev))[0] == 'UNKNOWN'
