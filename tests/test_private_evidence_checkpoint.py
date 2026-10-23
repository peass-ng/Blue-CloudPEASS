from unittest.mock import patch

from peaso.private_evidence_checkpoint import PrivateEvidenceCheckpoint
from peaso.secret_evidence import Capture, EphemeralCipher


def test_unchanged_index_reuses_ciphertext_but_checks_every_mutable_dependency():
    cipher = EphemeralCipher()
    capture = Capture(cipher, 'tenant', 'scan')
    capture.remember('synthetic', 'fingerprint', {'resource_id': 'one', 'scope': 'scope'},
                     'detector', 'rule', ['check'])
    cache = PrivateEvidenceCheckpoint()
    first = cache.document(capture)
    with patch.object(cipher, 'decrypt', wraps=cipher.decrypt) as decrypt:
        second = cache.document(capture)
        assert first == second
        assert decrypt.call_count == 0
    second['records'].clear()
    assert cache.document(capture)['records'] == first['records']
    capture.incomplete = True
    assert cache.document(capture)['incomplete'] is True
    capture.related['fingerprint'] = {'related'}
    changed = cache.document(capture)
    assert cipher.decrypt(changed['index'])['related'] == {'fingerprint': ['related']}
    capture.remember('synthetic', 'fingerprint', {'resource_id': 'two', 'scope': 'other'},
                     'detector', 'rule', ['check'])
    changed = cache.document(capture)
    assert cipher.decrypt(changed['index']) == cipher.decrypt(capture.document()['index'])
    del capture.records['fingerprint']
    assert cipher.decrypt(cache.document(capture)['index'])['resources'] == {}


def test_cache_is_capture_scoped_and_contains_no_plaintext_record():
    cipher = EphemeralCipher()
    one, two = Capture(cipher, 'tenant', 'scan'), Capture(cipher, 'tenant', 'scan')
    one.remember('synthetic-value-unique', 'fp', {}, 'detector', 'rule', [])
    cache = PrivateEvidenceCheckpoint()
    cache.document(one)
    assert 'synthetic-value-unique' not in repr(vars(cache))
    assert not cache.document(two)['records']


def test_custom_capture_remains_authoritative():
    class Custom:
        def document(self):
            return {'custom': True}

    assert PrivateEvidenceCheckpoint().document(Custom()) == {'custom': True}


def test_custom_cipher_and_rotated_key_remain_authoritative():
    class CustomCipher(EphemeralCipher):
        pass

    capture = Capture(CustomCipher(), 'tenant', 'scan')
    cache = PrivateEvidenceCheckpoint()
    with patch.object(capture, 'document', wraps=capture.document) as document:
        cache.document(capture)
        cache.document(capture)
        assert document.call_count == 2
    capture = Capture(EphemeralCipher(), 'tenant', 'scan')
    before = cache.document(capture)
    capture.cipher.fernet = EphemeralCipher().fernet
    after = cache.document(capture)
    assert before['index'] != after['index']
    assert capture.cipher.decrypt(after['index'])['resources'] == {}
