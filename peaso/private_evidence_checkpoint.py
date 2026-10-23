"""Reuse only an unchanged encrypted checkpoint index within one capture.

The admitted capture implementation remains authoritative. No plaintext secret,
decrypted record, or public artifact is retained by this adapter.
"""
import weakref

from cryptography.fernet import Fernet
from peaso.auth.secrets import CredentialCipher
from peaso.secret_evidence import Capture, EphemeralCipher, SCHEMA


class PrivateEvidenceCheckpoint:
    def __init__(self):
        self.signature = self.index = None
        self.capture = lambda: None
        self.fernet = lambda: None

    def document(self, capture):
        if (type(capture) is not Capture
                or type(capture.cipher) not in (CredentialCipher, EphemeralCipher)
                or type(capture.cipher.fernet) is not Fernet):
            return capture.document()
        signature = (id(capture), id(capture.cipher), capture.tenant, capture.scan_id,
                     tuple(capture.records.items()),
                     tuple((key, tuple(sorted(values))) for key, values in capture.related.items()))
        if (self.capture() is not capture or self.signature != signature
                or self.fernet() is not capture.cipher.fernet):
            document = capture.document()
            self.capture = weakref.ref(capture)
            self.fernet = weakref.ref(capture.cipher.fernet)
            self.signature, self.index = signature, document['index']
            return document
        return {'schema': SCHEMA, 'tenant': capture.tenant, 'scan_id': capture.scan_id,
                'incomplete': capture.incomplete, 'records': dict(capture.records),
                'index': self.index}
